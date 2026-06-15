package xss_dom_confirm

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/infra/xssencode"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/xssbreakout"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// Cross-module dedup tag — must match xss_scanner / xss_light_scanner so a
// confirmation here suppresses redundant work in the lighter modules.
const vulnClass = "xss"

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

// New returns a module restricted to URL-side insertion points — body and
// header injections aren't navigable via a single browser GET.
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
			modkit.URLParamTypes,
		),
		rhm:    dedup.LazyDefaultRHM("xss_dom_confirm"),
		budget: NewBudget(0, 0),
		Probe:  spitolas.ProbeURL,
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) VulnClass() string { return vulnClass }

// Browser confirmation is much pricier than HTTP-only XSS modules — let them
// run first so cross-module dedup can skip already-confirmed targets here.
func (m *Module) Priority() int { return 200 }

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

	// Plain attempt — same build → send → prefilter → browser-confirm path as
	// before. Factored into attempt() so the fallback can reuse it verbatim. The
	// universal HTML payload (payload.Hash) doubles as a DOM-source navigation.
	evt, plain := m.attempt(ctx, ip, httpClient, urlx.Host, payload, payload.Body, payload.Hash)
	if evt != nil {
		m.markFound(scanCtx, hostPath, ip.Name())
		return []*output.ResultEvent{evt}, nil
	}

	// Fallback (additive): only reached when the plain attempt produced no
	// finding. If a WAF fronts the host — observed on this very response or a
	// prior request — retry with execution-preserving, WAF-tuned mutations.
	// With no WAF detected, MutateForWAF yields nothing and we return as before.
	wafType := scanCtx.DetectedWAF(urlx.Host)
	if wafType == "" && plain != nil {
		if br := waf.ClassifyParts(plain.status, plain.header, []byte(plain.body)); br != nil {
			wafType = br.WAFType
			scanCtx.MarkWAF(urlx.Host, wafType)
		}
	}
	for _, v := range xssencode.MutateForWAF(wafType, payload.Body) {
		mevt, _ := m.attempt(ctx, ip, httpClient, urlx.Host, payload, v.Value, payload.Hash)
		if mevt != nil {
			mevt.Info.Description += fmt.Sprintf(" [waf-bypass: %s/%s]", wafType, v.Name)
			m.markFound(scanCtx, hostPath, ip.Name())
			return []*output.ResultEvent{mevt}, nil
		}
	}

	// Fallback (additive): the universal payload breaks out of HTML markup, so it
	// misses a value reflected inside a JS string. When the canary DID land in the
	// body (so the parameter reflects) but nothing executed, retry with
	// operator-chaining breakouts that run even inside a JS expression — the
	// '^alert()^' class a sibling scanner uses on Salesforce-style pages.
	if plain != nil && strings.Contains(plain.body, payload.Canary) {
		alert := "alert(`" + payload.Canary + "`)"
		for _, q := range []byte{'\'', '"'} {
			for _, body := range xssbreakout.JSStringPayloads(q, alert) {
				jevt, _ := m.attempt(ctx, ip, httpClient, urlx.Host, payload, body, "")
				if jevt != nil {
					jevt.Info.Description += " [js-string-breakout]"
					m.markFound(scanCtx, hostPath, ip.Name())
					return []*output.ResultEvent{jevt}, nil
				}
			}
		}
	}

	return nil, nil
}

func (m *Module) markFound(scanCtx *modkit.ScanContext, hostPath, name string) {
	if reg := scanCtx.ParamFindingsRegistry(); reg != nil {
		reg.MarkFound(hostPath, name, vulnClass)
	}
}

// capturedResp holds the response parts the fallback needs to classify a WAF
// block when an attempt fails the prefilter.
type capturedResp struct {
	status int
	header nethttp.Header
	body   string
}

// attempt injects bodyPayload at ip, prefilters the reflection, and on a pass
// confirms execution in a headless browser. hashPayload is the DOM-source variant
// appended to the navigated URL's fragment (pass "" to navigate the reflection
// alone). It returns the finding on success (else nil) and always returns the
// captured HTTP response so the caller can classify a block on a failed attempt.
func (m *Module) attempt(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	host string,
	payload *Payload,
	bodyPayload string,
	hashPayload string,
) (*output.ResultEvent, *capturedResp) {
	fuzzedRaw := ip.BuildRequest([]byte(bodyPayload))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	plain, err := sendAndCapture(httpClient, fuzzedReq)
	if err != nil || plain == nil {
		return nil, plain
	}

	pass, reason := passesPrefilter(plain.body, payload.Canary)
	if !pass {
		return nil, plain
	}

	probeURL, err := navigableURL(fuzzedReq, hashPayload)
	if err != nil {
		return nil, plain
	}

	bgCtx, cancel := context.WithTimeout(context.Background(), probeNavTimeout+5*time.Second)
	defer cancel()

	release, ok := m.budget.Reserve(bgCtx, host)
	if !ok {
		return nil, plain
	}
	defer release()

	res, err := m.Probe(bgCtx, spitolas.ProbeConfig{
		URL:        probeURL,
		WaitExtra:  probeWaitExtra,
		NavTimeout: probeNavTimeout,
	})
	if !probeUsable(res, err) {
		return nil, plain
	}

	dialog := matchCanary(res.Dialogs, payload.Canary)
	if dialog == nil {
		return nil, plain
	}

	return m.buildResult(ctx, ip, fuzzedRaw, payload, probeURL, reason, *dialog), plain
}

// probeUsable reports whether a probe result carries enough information to
// proceed. A nav error with captured dialogs is still useful (javascript:
// URLs return errors but execute first); a nav error without dialogs is not.
func probeUsable(res *spitolas.ProbeResult, err error) bool {
	if res == nil {
		return false
	}
	if err != nil && len(res.Dialogs) == 0 {
		return false
	}
	return true
}

// sendAndCapture executes req and returns the response status, headers, and
// body. Unlike a body-only read, the status/headers let the caller classify a
// WAF block when the prefilter fails.
func sendAndCapture(httpClient *http.Requester, req *httpmsg.HttpRequestResponse) (*capturedResp, error) {
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil || resp == nil {
		return nil, err
	}
	defer resp.Close()

	cr := &capturedResp{}
	if r := resp.Response(); r != nil {
		cr.status = r.StatusCode
		cr.header = r.Header
	}
	cr.body = resp.Body().String()
	return cr, nil
}

// navigableURL turns a fuzzed request into the URL string a browser can
// navigate to, with the DOM payload variant appended to the fragment.
// Returns an error for non-GET methods which can't be replayed via navigation.
func navigableURL(fuzzedReq *httpmsg.HttpRequestResponse, hashPayload string) (string, error) {
	method := strings.ToUpper(fuzzedReq.Request().Method())
	if method != "GET" && method != "" {
		return "", fmt.Errorf("non-GET method %q is not navigable", method)
	}
	urlx, err := fuzzedReq.Request().URL()
	if err != nil {
		return "", err
	}
	full := urlx.String()
	// No DOM-source variant — navigate the reflected query alone.
	if hashPayload == "" {
		return full, nil
	}
	frag := url.PathEscape(hashPayload)
	if strings.Contains(full, "#") {
		return full + frag, nil
	}
	return full + "#" + frag, nil
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
	fuzzedRaw []byte,
	payload *Payload,
	probeURL string,
	reason PrefilterReason,
	dialog spitolas.DialogEvent,
) *output.ResultEvent {
	urlx, _ := ctx.URL()
	desc := fmt.Sprintf(
		"Browser-confirmed XSS via %s. Payload triggered %s(%q) on %s. Pre-filter signal: %s.",
		ip.Name(), dialog.Type, dialog.Message, probeURL, reason,
	)
	return &output.ResultEvent{
		URL:              urlx.String(),
		Host:             urlx.Host,
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{dialog.Message},
		Info:             output.Info{Description: desc},
	}
}
