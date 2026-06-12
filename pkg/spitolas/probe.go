package spitolas

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// EnvBrowserHeaded is the env var name the autopilot/swarm CLI sets when
// invoked with --headed. ProbeURL honors it as a fallback when
// ProbeConfig.Headed is unset, and agent-browser subprocesses inherit it.
const EnvBrowserHeaded = "VIGOLIUM_BROWSER_HEADED"

// CaptureSourceBrowserProbe is the default `source` label written to records
// captured by ProbeURL. Exposed so callers writing their own ProbeConfig can
// match it (and the browser_probe tool can reuse it).
const CaptureSourceBrowserProbe = "browser-probe"

// CaptureSink persists HTTP request/response pairs observed by the browser
// during ProbeURL. The shape matches database.Repository so callers can pass
// *database.Repository directly. When ProbeConfig.CaptureSink is nil, network
// capture is disabled and only dialog events are recorded — preserving the
// fast XSS-confirm path.
type CaptureSink interface {
	SaveRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse, source, projectUUID string) (string, error)
	SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source, projectUUID string) ([]string, error)
}

// DialogEvent is a JavaScript dialog (alert/confirm/prompt/beforeunload)
// captured during a probe. Recording happens before the page's auto-handler
// accepts it, so the page never blocks waiting for human input.
type DialogEvent struct {
	Type    string    `json:"type"`
	Message string    `json:"message"`
	URL     string    `json:"url"`
	At      time.Time `json:"at"`
}

// ProbeConfig configures a single-page probe used to confirm DOM/reflected
// XSS by observing JavaScript dialogs that fire while the page renders.
type ProbeConfig struct {
	URL           string
	WaitSelector  string
	WaitExtra     time.Duration
	NavTimeout    time.Duration
	BrowserPath   string
	BrowserEngine string

	// Headed disables headless mode. Zero value keeps headless on so a
	// default-config caller can never pop a window on the user's desktop.
	Headed bool

	ProxyURL string

	// ProxyAllowLoopback removes Chrome's implicit proxy bypass for
	// localhost/127.0.0.1 so the proxy also captures traffic to a loopback
	// target. Off by default; set it when the probe's whole point is to route
	// everything through an intercepting proxy (e.g. browser replay to Burp).
	ProxyAllowLoopback bool

	// CaptureSink, when non-nil, enables CDP-level network capture for the
	// probe. Every XHR/fetch/document request the browser makes during the
	// navigation is converted to an HttpRequestResponse and persisted via
	// the sink. Lets a single probe both confirm an XSS dialog AND expand
	// the scanner's input surface with traffic only the browser sees.
	CaptureSink CaptureSink

	// CaptureSource is the `source` label written to captured records.
	// Empty defaults to "browser-probe".
	CaptureSource string

	// CaptureProjectUUID scopes captured records to a project. Required
	// (alongside CaptureSink) for capture to be active; passing only one
	// of the two is treated as "capture disabled".
	CaptureProjectUUID string

	// CollectHTML asks ProbeURL to grab the post-render DOM and return it in
	// ProbeResult.HTML. Off by default — the XSS-dialog path doesn't need
	// it and grabbing HTML adds wall-time on large pages. The autopilot
	// `web_fetch mode=browser` tool flips this on so the model gets the
	// rendered page in the tool result.
	CollectHTML bool

	// Cookies are applied to the page before navigation. Zero value = none, so
	// existing callers are unaffected. Lets the probe replay an authenticated
	// retrieval URL (e.g. stored-XSS confirmation) under the scan's session.
	Cookies []*http.Cookie

	// Headers are extra request headers (key→value) applied to the navigation.
	// Zero value = none.
	Headers map[string]string
}

// ProbeResult carries dialog events that opened during navigation. A non-empty
// Dialogs slice means JavaScript executed and fired alert/confirm/prompt —
// the canonical confirmed-XSS signal.
type ProbeResult struct {
	FinalURL string        `json:"final_url"`
	Title    string        `json:"title,omitempty"`
	Dialogs  []DialogEvent `json:"dialogs"`

	// HTML is the post-JS-render DOM, populated only when ProbeConfig.CollectHTML
	// is true. Kept opt-in because grabbing HTML on every XSS probe doubles the
	// per-call wall time on large pages.
	HTML string `json:"html,omitempty"`
}

// ProbeURL launches a single-page browser session and returns any dialog
// events that fired during navigation. Each call spins up a fresh browser
// process; callers are responsible for budgeting concurrency.
func ProbeURL(ctx context.Context, cfg ProbeConfig) (*ProbeResult, error) {
	if cfg.URL == "" {
		return nil, errors.New("ProbeURL: URL is required")
	}

	crawlerCfg, err := config.New(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ProbeURL: build config: %w", err)
	}

	crawlerCfg.BrowserCount = 1
	crawlerCfg.MaxDepth = 0
	crawlerCfg.MaxStates = 1
	crawlerCfg.Silent = true
	// Env override: when VIGOLIUM_BROWSER_HEADED is set and the caller
	// didn't explicitly set Headed, fall back to headed so the operator
	// can see the window.
	headed := cfg.Headed || utils.EnvTruthy(EnvBrowserHeaded)
	crawlerCfg.Headless = !headed
	if cfg.BrowserPath != "" {
		crawlerCfg.BrowserPath = cfg.BrowserPath
	}
	if cfg.BrowserEngine != "" {
		crawlerCfg.BrowserEngine = cfg.BrowserEngine
	}
	if cfg.ProxyURL != "" {
		crawlerCfg.ProxyURL = cfg.ProxyURL
		crawlerCfg.ProxyAllowLoopback = cfg.ProxyAllowLoopback
	}

	navTimeout := cfg.NavTimeout
	if navTimeout <= 0 {
		navTimeout = 30 * time.Second
	}
	crawlerCfg.PageLoadTimeout = navTimeout

	br, err := browser.New(crawlerCfg)
	if err != nil {
		return nil, fmt.Errorf("ProbeURL: launch browser: %w", err)
	}
	defer func() { _ = br.Close() }()

	// Optional network capture: spin up a CDP-level recorder and let it
	// run for the lifetime of this probe. Records flow through the
	// internal RepositoryWriter into the sink (typically database.Repo).
	if cfg.CaptureSink != nil && cfg.CaptureProjectUUID != "" {
		source := cfg.CaptureSource
		if source == "" {
			source = CaptureSourceBrowserProbe
		}
		targetHost := ""
		if u, perr := url.Parse(cfg.URL); perr == nil && u != nil {
			targetHost = u.Hostname()
		}
		writer := network.NewRepositoryWriter(cfg.CaptureSink, source, cfg.CaptureProjectUUID)
		capture := network.New(writer, true, true, false, false, false, targetHost, "probe")
		if startErr := capture.Start(br.RodBrowser()); startErr != nil {
			zap.L().Debug("ProbeURL: capture start failed", zap.Error(startErr))
		} else {
			defer func() {
				_ = writer.Close()
			}()
		}
	}

	page, err := br.NewPage()
	if err != nil {
		return nil, fmt.Errorf("ProbeURL: open page: %w", err)
	}

	// Apply session context (cookies/headers) before navigation. Failures are
	// non-fatal — an unauthenticated probe still runs, it just won't see
	// behind-login content.
	if len(cfg.Cookies) > 0 {
		if cerr := page.SetCookies(cfg.Cookies); cerr != nil {
			zap.L().Debug("ProbeURL: set cookies failed", zap.Error(cerr))
		}
	}
	if len(cfg.Headers) > 0 {
		dict := make([]string, 0, len(cfg.Headers)*2)
		for k, v := range cfg.Headers {
			dict = append(dict, k, v)
		}
		if cleanup, herr := page.RodPage().SetExtraHeaders(dict); herr != nil {
			zap.L().Debug("ProbeURL: set extra headers failed", zap.Error(herr))
		} else if cleanup != nil {
			defer cleanup()
		}
	}

	if err := page.NavigateCtx(ctx, cfg.URL); err != nil {
		// javascript: URLs and similar return a navigation error but may have
		// already executed JS, so return any captured dialogs alongside the err.
		return &ProbeResult{
			Dialogs: convertDialogs(page.DialogEvents()),
		}, fmt.Errorf("ProbeURL: navigate: %w", err)
	}

	if cfg.WaitSelector != "" {
		_ = page.WaitElement(cfg.WaitSelector, navTimeout)
	}
	if cfg.WaitExtra > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(cfg.WaitExtra):
		}
	}

	finalURL, _ := page.URL()
	title, _ := page.Title()

	html := ""
	if cfg.CollectHTML {
		if h, herr := page.HTML(); herr == nil {
			html = h
		} else {
			zap.L().Debug("ProbeURL: HTML collection failed", zap.Error(herr))
		}
	}

	return &ProbeResult{
		FinalURL: finalURL,
		Title:    title,
		Dialogs:  convertDialogs(page.DialogEvents()),
		HTML:     html,
	}, nil
}

func convertDialogs(in []browser.DialogEvent) []DialogEvent {
	if len(in) == 0 {
		return nil
	}
	out := make([]DialogEvent, len(in))
	for i, ev := range in {
		out[i] = DialogEvent{
			Type:    ev.Type,
			Message: ev.Message,
			URL:     ev.URL,
			At:      ev.At,
		}
	}
	return out
}
