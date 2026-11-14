package spitolas

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
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

// Capture `source` labels written to records a browser run persists. Exposed so
// a caller writing its own ProbeConfig, and anything that later queries those
// records back, name the same string instead of repeating the literal.
const (
	// CaptureSourceBrowserProbe is ProbeURL's default, and the browser_probe
	// tool's.
	CaptureSourceBrowserProbe = "browser-probe"
	// CaptureSourceWebFetchBrowser is what web_fetch labels records with in
	// browser (rendered) mode.
	CaptureSourceWebFetchBrowser = "web-fetch-browser"
)

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
// answers it, so the page never blocks waiting for human input. Answered is
// how the dialog policy answered it ("accepted" or "dismissed"): under the
// default record-dismiss policy a confirm/prompt is dismissed.
type DialogEvent struct {
	Type     string    `json:"type"`
	Message  string    `json:"message"`
	URL      string    `json:"url"`
	At       time.Time `json:"at"`
	Answered string    `json:"answered,omitempty"`
}

// defaultProbeProxy is the proxy a ProbeURL call uses when its config names
// none. See SetDefaultProbeProxy.
var defaultProbeProxy atomic.Pointer[string]

// SetDefaultProbeProxy makes proxyURL the proxy every ProbeURL call uses when
// its ProbeConfig.ProxyURL is empty, and returns a func that restores the
// previous default. An empty proxyURL changes nothing and returns a no-op.
//
// It exists for the browser confirmations active modules run (xss_stored,
// xss_dom_confirm, xss_light_scanner, aem_xss, client_path_traversal_confirm):
// they build their ProbeConfig from a context.Background()-derived context with
// no route back to the scan's options, so a scan run with --proxy confirmed its
// XSS findings around the proxy — traffic the operator's proxy log never saw.
// The runner installs the scan's proxy here for the dynamic-assessment phase.
//
// Process-wide by necessity: two in-process scans with DIFFERENT proxies running
// concurrently share one default (last setter wins until it restores). A caller
// that knows its proxy should still set ProbeConfig.ProxyURL, which always wins.
func SetDefaultProbeProxy(proxyURL string) (restore func()) {
	if proxyURL == "" {
		return func() {}
	}
	prev := defaultProbeProxy.Swap(&proxyURL)
	return func() { defaultProbeProxy.CompareAndSwap(&proxyURL, prev) }
}

// DefaultProbeProxy returns the proxy installed by SetDefaultProbeProxy, or "".
func DefaultProbeProxy() string {
	if p := defaultProbeProxy.Load(); p != nil {
		return *p
	}
	return ""
}

// defaultProbeStealth is the stealth mode a ProbeURL call uses when its config
// names none. See SetDefaultProbeStealth.
var defaultProbeStealth atomic.Pointer[string]

// SetDefaultProbeStealth makes mode the stealth mode every ProbeURL call uses
// when its ProbeConfig.Stealth is empty, and returns a func that restores the
// previous default. An empty mode changes nothing and returns a no-op.
//
// The counterpart of SetDefaultProbeProxy for spidering.stealth: the module
// browser confirmations build their ProbeConfig with no route back to the
// scan's settings, so they ran with the "auto" default whatever the operator
// configured — a crawl with stealth off and confirmations with it on saw two
// different pages. The runner (and the direct scan-url / scan-request paths)
// install the configured mode for the scan. Process-wide, with the same
// last-setter-wins caveat as the proxy default.
func SetDefaultProbeStealth(mode string) (restore func()) {
	if mode == "" {
		return func() {}
	}
	prev := defaultProbeStealth.Swap(&mode)
	return func() { defaultProbeStealth.CompareAndSwap(&mode, prev) }
}

// DefaultProbeStealth returns the mode installed by SetDefaultProbeStealth, or
// "" (auto).
func DefaultProbeStealth() string {
	if p := defaultProbeStealth.Load(); p != nil {
		return *p
	}
	return ""
}

// SetProbeDefaults installs the scan's proxy and stealth mode as the ProbeURL
// defaults (SetDefaultProbeProxy, SetDefaultProbeStealth) and returns one
// restore func for both.
func SetProbeDefaults(proxyURL, stealth string) (restore func()) {
	restoreProxy := SetDefaultProbeProxy(proxyURL)
	restoreStealth := SetDefaultProbeStealth(stealth)
	return func() {
		restoreStealth()
		restoreProxy()
	}
}

// ProbeConfig configures a single-page probe used to confirm DOM/reflected
// XSS by observing JavaScript dialogs that fire while the page renders.
type ProbeConfig struct {
	URL string

	// WaitSelector is a readiness condition: after navigation the probe waits
	// (up to NavTimeout) for it to appear. Whether it did is reported in
	// ProbeResult.Readiness; a timeout is not silently a success.
	WaitSelector string

	// RequireSelector makes a WaitSelector that never appeared an error:
	// ProbeURL returns the partial result together with ErrReadinessFailed.
	// Off by default — callers that only need dialogs or a best-effort DOM
	// keep the result and read Readiness.
	RequireSelector bool

	WaitExtra     time.Duration
	NavTimeout    time.Duration
	BrowserPath   string
	BrowserEngine string

	// Stealth is the stealth mode, as for the crawl: "auto" (or ""), "on" or
	// "off". Auto is on for the default chromium engine, so a module
	// confirmation sees the same page the crawl did.
	Stealth string

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

	// CaptureBodies makes captured records keep their response bodies and
	// headers. Off by default: without it a captured record carries only the
	// request line and status, which keeps the dialog-confirm path fast.
	// ProbeResult.Capture reports which were retained.
	CaptureBodies bool

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

	// Capture is what the probe's network capture retained, read from the
	// writer after it closed. Zero-valued (Enabled false) when no sink was
	// wired; Enabled false with Err set when capture could not start.
	Capture CaptureReceipt `json:"capture"`

	// Readiness is the outcome of ProbeConfig.WaitSelector: ReadinessReady,
	// ReadinessTimeout or ReadinessFailed; empty when no selector was asked
	// for. ReadinessFailed (the bool) is true for either failure, and
	// ReadinessDetail says what was waited for and why it ended.
	Readiness       string `json:"readiness,omitempty"`
	ReadinessFailed bool   `json:"readiness_failed,omitempty"`
	ReadinessDetail string `json:"readiness_detail,omitempty"`
}

// Readiness outcomes (ProbeResult.Readiness).
const (
	ReadinessReady   = "ready"   // the selector appeared
	ReadinessTimeout = "timeout" // it did not appear within the wait
	ReadinessFailed  = "failed"  // the wait itself failed (bad selector, page gone, cancelled)
)

// ErrReadinessFailed is returned (wrapped) by ProbeURL when RequireSelector
// is set and the selector never appeared; the partial result comes with it.
var ErrReadinessFailed = errors.New("readiness condition not met")

// applyReadiness records the outcome of the selector wait on res and returns
// the error ProbeURL must surface (only with RequireSelector).
func applyReadiness(res *ProbeResult, cfg ProbeConfig, waitErr error, waited time.Duration) error {
	if cfg.WaitSelector == "" {
		return nil
	}
	if waitErr == nil {
		res.Readiness = ReadinessReady
		return nil
	}
	res.ReadinessFailed = true
	res.Readiness = ReadinessFailed
	if errors.Is(waitErr, context.DeadlineExceeded) {
		res.Readiness = ReadinessTimeout
		res.ReadinessDetail = fmt.Sprintf("selector %q did not appear within %s", cfg.WaitSelector, waited)
	} else {
		res.ReadinessDetail = fmt.Sprintf("waiting for selector %q failed: %v", cfg.WaitSelector, waitErr)
	}
	if cfg.RequireSelector {
		return fmt.Errorf("ProbeURL: %w: %s", ErrReadinessFailed, res.ReadinessDetail)
	}
	return nil
}

// ProbeURL launches a single-page browser session and returns any dialog
// events that fired during navigation. Each call spins up a fresh browser
// process; callers are responsible for budgeting concurrency.
func ProbeURL(ctx context.Context, cfg ProbeConfig) (res *ProbeResult, err error) {
	if cfg.URL == "" {
		return nil, errors.New("ProbeURL: URL is required")
	}
	if cfg.ProxyURL == "" {
		cfg.ProxyURL = DefaultProbeProxy()
	}
	if cfg.Stealth == "" {
		cfg.Stealth = DefaultProbeStealth()
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
	crawlerCfg.Stealth = cfg.Stealth
	if err := config.ValidateStealth(cfg.Stealth); err != nil {
		return nil, fmt.Errorf("ProbeURL: %w", err)
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

	br, err := browser.NewWithContext(ctx, crawlerCfg)
	if err != nil {
		return nil, fmt.Errorf("ProbeURL: launch browser: %w", err)
	}
	defer func() { _ = br.Close() }()

	// Bind the probe context onto every page this browser creates so the caller's
	// deadline/cancellation reaches rod's per-operation CDP calls — including the
	// raw page.RodPage().SetExtraHeaders escape hatch below and NavigateCtx — not
	// just the loop-level checks. Capture runs on the raw browser (RodBrowser), so
	// it is unaffected and keeps flushing.
	br.SetCrawlContext(ctx)

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
		capture := network.New(writer, true, true, false, cfg.CaptureBodies, cfg.CaptureBodies, targetHost, "probe")
		if startErr := capture.Start(br.RodBrowser()); startErr != nil {
			zap.L().Debug("ProbeURL: capture start failed", zap.Error(startErr))
			// NewRepositoryWriter starts its flush goroutine in the constructor, so
			// the writer owns a goroutine even when the capture never started. The
			// failure path has to close it or every failed start leaks one.
			_ = writer.Close()
			defer func() {
				if res != nil {
					res.Capture = CaptureReceipt{Err: "capture start failed: " + startErr.Error()}
				}
			}()
		} else {
			// Close the CAPTURE, not just the writer. Capture.Close is what sets
			// c.stopped, and c.stopped is the only thing cleanupLoop ever checks —
			// closing the browser ends CDP event delivery but leaves that loop
			// polling every 100ms forever, holding the whole Capture (and its
			// pending/seen/logged maps) live. Each captured probe used to strand
			// one. Capture.Close also closes the writer, so the writer stops
			// admitting only after capture has stopped producing.
			//
			// Registered after the `defer br.Close()` above, so LIFO runs it first:
			// capture down, then the browser.
			//
			// The receipt is read from the writer after that close, so a caller is
			// told what was persisted, not merely that capture was configured.
			defer func() {
				if cerr := capture.Close(); cerr != nil {
					zap.L().Debug("ProbeURL: capture close failed", zap.Error(cerr))
				}
				if res != nil {
					res.Capture = newCaptureReceipt(writer.Receipt(), cfg.CaptureBodies, cfg.CaptureBodies)
				}
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
		// Per-request credential routing (SAFE-3): the headers ride only on
		// requests to the probed host and its subdomains, never on the
		// third-party subresources the page loads.
		probeHost := ""
		if u, perr := url.Parse(cfg.URL); perr == nil {
			probeHost = strings.ToLower(u.Hostname())
		}
		allow := func(raw string) bool {
			u, perr := url.Parse(raw)
			if perr != nil || probeHost == "" {
				return false
			}
			h := strings.ToLower(u.Hostname())
			return h == probeHost || strings.HasSuffix(h, "."+probeHost)
		}
		if herr := page.InstallCredentialRouter(cfg.Headers, allow, nil, browser.CredentialHostPatterns(probeHost)); herr != nil {
			zap.L().Debug("ProbeURL: install credential router failed", zap.Error(herr))
		}
	}

	if err := page.NavigateCtx(ctx, cfg.URL); err != nil {
		// javascript: URLs and similar return a navigation error but may have
		// already executed JS, so return any captured dialogs alongside the err.
		return &ProbeResult{
			Dialogs: convertDialogs(page.DialogEvents()),
		}, fmt.Errorf("ProbeURL: navigate: %w", err)
	}

	var waitErr error
	if cfg.WaitSelector != "" {
		waitErr = page.WaitElement(cfg.WaitSelector, navTimeout)
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

	res = &ProbeResult{
		FinalURL: finalURL,
		Title:    title,
		Dialogs:  convertDialogs(page.DialogEvents()),
		HTML:     html,
	}
	return res, applyReadiness(res, cfg, waitErr, navTimeout)
}

func convertDialogs(in []browser.DialogEvent) []DialogEvent {
	if len(in) == 0 {
		return nil
	}
	out := make([]DialogEvent, len(in))
	for i, ev := range in {
		out[i] = DialogEvent{
			Type:     ev.Type,
			Message:  ev.Message,
			URL:      ev.URL,
			At:       ev.At,
			Answered: ev.Answered,
		}
	}
	return out
}
