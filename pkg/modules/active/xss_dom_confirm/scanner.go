package xss_dom_confirm

import (
	"context"
	"fmt"
	"net/url"
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

	fuzzedRaw := ip.BuildRequest([]byte(payload.Body))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	body, err := sendAndReadBody(httpClient, fuzzedReq)
	if err != nil || body == "" {
		return nil, nil
	}

	pass, reason := passesPrefilter(body, payload.Canary)
	if !pass {
		return nil, nil
	}

	probeURL, err := navigableURL(fuzzedReq, payload.Hash)
	if err != nil {
		return nil, nil
	}

	bgCtx, cancel := context.WithTimeout(context.Background(), probeNavTimeout+5*time.Second)
	defer cancel()

	release, ok := m.budget.Reserve(bgCtx, urlx.Host)
	if !ok {
		return nil, nil
	}
	defer release()

	res, err := m.Probe(bgCtx, spitolas.ProbeConfig{
		URL:        probeURL,
		WaitExtra:  probeWaitExtra,
		NavTimeout: probeNavTimeout,
	})
	if !probeUsable(res, err) {
		return nil, nil
	}

	dialog := matchCanary(res.Dialogs, payload.Canary)
	if dialog == nil {
		return nil, nil
	}

	if reg := scanCtx.ParamFindingsRegistry(); reg != nil {
		reg.MarkFound(hostPath, ip.Name(), vulnClass)
	}

	return []*output.ResultEvent{m.buildResult(ctx, ip, fuzzedRaw, payload, probeURL, reason, *dialog)}, nil
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

func sendAndReadBody(httpClient *http.Requester, req *httpmsg.HttpRequestResponse) (string, error) {
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil || resp == nil {
		return "", err
	}
	defer resp.Close()
	body := resp.Body().Bytes()
	if len(body) == 0 {
		return "", nil
	}
	return string(body), nil
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
