package xss_stored

import (
	"context"
	"fmt"
	nethttp "net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/xssbreakout"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// vulnClass is intentionally distinct from reflected "xss" so a reflected
// finding on the same parameter does not suppress stored detection (and vice
// versa) via the cross-module ParameterFindingRegistry.
const vulnClass = "xss-stored"

const (
	probeNavTimeout = 25 * time.Second
	probeWaitExtra  = 700 * time.Millisecond
)

type Module struct {
	modkit.BaseActiveModule
	rhm    dedup.Lazy[dedup.RequestHashManager]
	budget *Budget

	// Probe is overridable so tests don't spawn real browsers.
	Probe func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error)
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.URLParamTypes|modkit.BodyParamTypes,
		),
		rhm:    dedup.LazyDefaultRHM("xss_stored"),
		budget: NewBudget(0, 0),
		Probe:  spitolas.ProbeURL,
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) VulnClass() string { return vulnClass }

// Browser confirmation is expensive — run after the cheaper reflected XSS
// modules (priority 200) so this only does work the others didn't cover.
func (m *Module) Priority() int { return 210 }

func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	hostPath := urlx.Host + urlx.Path
	if reg := scanCtx.ParamFindingsRegistry(); reg != nil && reg.HasFinding(hostPath, ip.Name(), vulnClass) {
		return nil, nil
	}

	if rhm := m.rhm.Get(scanCtx.DedupMgr()); rhm != nil {
		points := rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), []httpmsg.InsertionPoint{ip})
		if len(points) == 0 {
			return nil, nil
		}
	}

	payload, err := NewPayload()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate payload")
	}

	// Write → retrieve → browser-confirm. confirmStored tries the universal
	// HTML-breakout payload first and, only if the value persists and reflects but
	// doesn't execute, retries with operator-chaining JS-string breakouts.
	dialog, probeURL, bodyUsed := m.confirmStored(ctx, ip, httpClient, payload)
	if dialog == nil {
		return nil, nil
	}

	if reg := scanCtx.ParamFindingsRegistry(); reg != nil {
		reg.MarkFound(hostPath, ip.Name(), vulnClass)
	}

	return []*output.ResultEvent{m.buildResult(ctx, ip, payload, bodyUsed, probeURL, *dialog)}, nil
}

// confirmStored stores an executable payload through ip, reloads the page, and
// browser-confirms it. It returns the firing dialog, the navigated URL, and the
// body that worked.
//
// The universal HTML payload breaks out of markup, so it misses a value stored
// into a JS string. When the value persists and reflects but nothing executes,
// confirmStored retries with operator-chaining breakouts ('^alert()^') that run
// even inside a JS expression. The extra writes only happen once the value is
// known to persist — a field that doesn't store at all short-circuits, so we
// never pile mutations onto an unrelated endpoint.
func (m *Module) confirmStored(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payload *Payload,
) (*spitolas.DialogEvent, string, string) {
	dialog, probeURL, stored := m.injectAndConfirm(ctx, ip, httpClient, payload.Body, payload.Canary)
	if !stored {
		return nil, "", "" // nothing persisted/reflected — stop before extra writes
	}
	if dialog != nil {
		return dialog, probeURL, payload.Body
	}

	alert := "alert(`" + payload.Canary + "`)"
	for _, q := range []byte{'\'', '"'} {
		for _, body := range xssbreakout.JSStringPayloads(q, alert) {
			d, pu, ok := m.injectAndConfirm(ctx, ip, httpClient, body, payload.Canary)
			if ok && d != nil {
				return d, pu, body
			}
		}
	}
	return nil, "", ""
}

// injectAndConfirm stores bodyPayload, performs a clean retrieval GET, and (only
// when the canary persisted) browser-confirms it. The bool reports whether the
// value was stored and reflected at all — a clean GET never carries the payload,
// so a canary match means it was persisted, not merely echoed.
func (m *Module) injectAndConfirm(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	bodyPayload, canary string,
) (*spitolas.DialogEvent, string, bool) {
	if err := m.inject(ctx, ip, bodyPayload, httpClient); err != nil {
		return nil, "", false
	}
	body, err := m.retrieve(ctx, httpClient)
	if err != nil || !strings.Contains(body, canary) {
		return nil, "", false
	}
	urlx, _ := ctx.URL()
	dialog, probeURL := m.confirm(ctx, urlx.String(), canary)
	return dialog, probeURL, true
}

// inject sends the write request that stores the payload.
func (m *Module) inject(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	bodyPayload string,
	httpClient *http.Requester,
) error {
	raw := ip.BuildRequest([]byte(bodyPayload))
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return err
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return err
	}
	if resp != nil {
		resp.Close()
	}
	return nil
}

// retrieve performs a clean GET of the original URL, reusing the original
// request's auth headers, and returns the response body.
func (m *Module) retrieve(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) (string, error) {
	req := ctx.Request().Clone().
		WithMethod("GET").
		WithBody(nil).
		WithRemovedHeader("Content-Length").
		WithRemovedHeader("Content-Type").
		WithService(ctx.Service())

	resp, _, err := httpClient.Execute(httpmsg.NewHttpRequestResponse(req, nil), http.Options{})
	if err != nil || resp == nil {
		return "", err
	}
	defer resp.Close()
	return resp.Body().String(), nil
}

// confirm navigates probeURL in a headless browser, replaying the scan session,
// and returns the dialog that carries the canary (or nil).
func (m *Module) confirm(ctx *httpmsg.HttpRequestResponse, probeURL, canary string) (*spitolas.DialogEvent, string) {
	urlx, _ := ctx.URL()
	host := ""
	if urlx != nil {
		host = urlx.Host
	}

	bgCtx, cancel := context.WithTimeout(context.Background(), probeNavTimeout+5*time.Second)
	defer cancel()

	release, ok := m.budget.Reserve(bgCtx, host)
	if !ok {
		return nil, probeURL
	}
	defer release()

	cfg := spitolas.ProbeConfig{
		URL:        probeURL,
		WaitExtra:  probeWaitExtra,
		NavTimeout: probeNavTimeout,
	}
	// Replay the scan session so a behind-login retrieval page renders. Use the
	// cookie jar rather than a bare request header so document.cookie and
	// sub-resource requests see the session too.
	if cookie := ctx.Request().Header("Cookie"); cookie != "" {
		header := nethttp.Header{}
		header.Set("Cookie", cookie)
		cfg.Cookies = (&nethttp.Request{Header: header}).Cookies()
	}

	res, err := m.Probe(bgCtx, cfg)
	if !probeUsable(res, err) {
		return nil, probeURL
	}
	return matchCanary(res.Dialogs, canary), probeURL
}

// probeUsable reports whether a probe result carries enough information to
// proceed. A nav error with captured dialogs is still useful.
func probeUsable(res *spitolas.ProbeResult, err error) bool {
	if res == nil {
		return false
	}
	if err != nil && len(res.Dialogs) == 0 {
		return false
	}
	return true
}

func matchCanary(dialogs []spitolas.DialogEvent, canary string) *spitolas.DialogEvent {
	for i := range dialogs {
		if strings.Contains(dialogs[i].Message, canary) {
			return &dialogs[i]
		}
	}
	return nil
}

func (m *Module) buildResult(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	payload *Payload,
	bodyUsed string,
	probeURL string,
	dialog spitolas.DialogEvent,
) *output.ResultEvent {
	urlx, _ := ctx.URL()
	desc := fmt.Sprintf(
		"Browser-confirmed STORED XSS via %s. Injected payload persisted and triggered %s(%q) on a later load of %s.",
		ip.Name(), dialog.Type, dialog.Message, probeURL,
	)
	if bodyUsed != payload.Body {
		desc += " [js-string-breakout]"
	}
	return &output.ResultEvent{
		URL:              urlx.String(),
		Host:             urlx.Host,
		Request:          string(ip.BuildRequest([]byte(bodyUsed))),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{dialog.Message},
		Info:             output.Info{Description: desc},
	}
}
