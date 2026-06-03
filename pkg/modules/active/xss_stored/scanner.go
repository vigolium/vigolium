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

	// 1. Write: inject the canary through the insertion point. ip.BuildRequest
	// preserves the original method and auth headers.
	if err := m.inject(ctx, ip, payload.Body, httpClient); err != nil {
		return nil, nil
	}

	// 2. Retrieve: a clean GET of the same URL (carrying the scan session). The
	// retrieval request never contains the payload, so a canary match here means
	// the value was stored — not merely reflected.
	body, err := m.retrieve(ctx, httpClient)
	if err != nil || !strings.Contains(body, payload.Canary) {
		return nil, nil
	}

	// 3. Confirm: navigate the retrieval URL in a headless browser and watch for
	// the alert carrying our canary.
	dialog, probeURL := m.confirm(ctx, urlx.String(), payload.Canary)
	if dialog == nil {
		return nil, nil
	}

	if reg := scanCtx.ParamFindingsRegistry(); reg != nil {
		reg.MarkFound(hostPath, ip.Name(), vulnClass)
	}

	return []*output.ResultEvent{m.buildResult(ctx, ip, payload, probeURL, *dialog)}, nil
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
	probeURL string,
	dialog spitolas.DialogEvent,
) *output.ResultEvent {
	urlx, _ := ctx.URL()
	desc := fmt.Sprintf(
		"Browser-confirmed STORED XSS via %s. Injected payload persisted and triggered %s(%q) on a later load of %s.",
		ip.Name(), dialog.Type, dialog.Message, probeURL,
	)
	return &output.ResultEvent{
		URL:              urlx.String(),
		Host:             urlx.Host,
		Request:          string(ip.BuildRequest([]byte(payload.Body))),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{dialog.Message},
		Info:             output.Info{Description: desc},
	}
}
