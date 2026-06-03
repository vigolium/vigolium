package reverse_proxy_path_confusion

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// confirmRounds is how many times the WITH-payload shell must reproducibly
	// return 200 + the endpoint fingerprint.
	confirmRounds = 3
	// baselineRounds is how many times the WITHOUT-payload direct request must
	// stay blocked / fingerprint-free.
	baselineRounds = 2
	// limitPerHost gates the (expensive) sweep to effectively once per host.
	limitPerHost = 1
)

// Module implements the reverse-proxy path-confusion active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new reverse-proxy-path-confusion module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("reverse_proxy_path_confusion"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest sweeps the curated restricted endpoints for proxy-vs-backend
// path-confusion, once per host.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
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
	if !m.markAndShouldContinue(urlx, scanCtx) {
		return nil, nil
	}

	// All probes are GETs to root-relative admin endpoints.
	baseRaw := ctx.Request().Raw()
	if ctx.Request().Method() != "GET" {
		baseRaw = infra.SwapToGetMethodRequest(baseRaw)
	}
	service := ctx.Service()

	var results []*output.ResultEvent
	for _, ep := range restrictedEndpoints {
		// (1) WITHOUT-payload baseline: the target fetched directly. If it is
		// openly reachable (200 + fingerprint) there is no proxy-confusion bug.
		directRaw, derr := httpmsg.SetPath(baseRaw, ep.path)
		if derr != nil {
			continue
		}
		dstatus, dbody, ok, fatal := m.fetch(httpClient, service, directRaw)
		if fatal {
			return results, nil
		}
		if ok && dstatus == 200 && hasFingerprint(dbody, ep.fingerprints) {
			continue
		}

		ev, fatal := m.probeShells(ctx, httpClient, service, scanCtx, urlx, baseRaw, ep)
		if fatal {
			return results, nil
		}
		if ev != nil {
			results = append(results, ev)
			return results, nil // one confirmed finding per host is enough
		}
	}
	return results, nil
}

// probeShells tries each confusion shell around the endpoint, confirming any
// candidate through the full multi-round with/without-payload gate. The bool is
// true when the host became unresponsive (caller should stop).
func (m *Module) probeShells(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	service *httpmsg.Service,
	scanCtx *modkit.ScanContext,
	urlx *urlutil.URL,
	baseRaw []byte,
	ep restrictedEndpoint,
) (*output.ResultEvent, bool) {
	for _, sh := range confusionShells {
		realPath := sh.build(ep.path)
		realRaw, err := httpmsg.SetPath(baseRaw, realPath)
		if err != nil {
			continue
		}
		status, body, ok, fatal := m.fetch(httpClient, service, realRaw)
		if fatal {
			return nil, true
		}
		if !ok || status != 200 || !hasFingerprint(body, ep.fingerprints) {
			continue
		}

		// Candidate — run the strengthened confirmation gate.
		if !m.confirm(ctx, httpClient, service, scanCtx, baseRaw, ep, sh, realRaw, body) {
			continue
		}

		return &output.ResultEvent{
			URL:              urlx.Scheme + "://" + urlx.Host + realPath,
			Request:          string(realRaw),
			Response:         body,
			FuzzingParameter: "path",
			ExtractedResults: []string{realPath, ep.label, sh.label},
			Info: output.Info{
				Description: fmt.Sprintf(
					"Reverse-proxy path confusion: reached restricted endpoint %q (%s) via %s shell %q — blocked when requested directly.",
					ep.path, ep.label, sh.label, realPath,
				),
				Severity:   severity.High,
				Confidence: severity.Firm,
			},
		}, false
	}
	return nil, false
}

// confirm runs the with/without-payload, multi-round false-positive gate.
// It fails CLOSED (returns false → no finding) whenever it cannot positively
// prove the bypass — for a High-severity access-control finding, precision is
// preferred over recall, in line with the user's "minimize false positives"
// directive.
func (m *Module) confirm(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	service *httpmsg.Service,
	scanCtx *modkit.ScanContext,
	baseRaw []byte,
	ep restrictedEndpoint,
	sh confusionShell,
	realRaw []byte,
	candidateBody string,
) bool {
	// (2) Decoy-target negative: the SAME shell around a non-existent target must
	// NOT yield the fingerprint. This proves the fingerprint comes from the real
	// target path, not from a catch-all that 200s every shell prefix.
	decoyRaw, err := httpmsg.SetPath(baseRaw, sh.build(decoyTarget))
	if err != nil {
		return false
	}
	ds, db, ok, _ := m.fetch(httpClient, service, decoyRaw)
	if !ok {
		return false // cannot run the decoy-negative → fail closed
	}
	if ds == 200 && hasFingerprint(db, ep.fingerprints) {
		return false // shell prefix 200s every target → catch-all false positive
	}

	// (3) Stable WITHOUT payload: the direct target must STAY blocked /
	// fingerprint-free across rounds (not flapping into reachability).
	directRaw, err := httpmsg.SetPath(baseRaw, ep.path)
	if err != nil {
		return false
	}
	for i := 0; i < baselineRounds; i++ {
		s, b, ok, _ := m.fetch(httpClient, service, directRaw)
		if !ok {
			return false
		}
		if s == 200 && hasFingerprint(b, ep.fingerprints) {
			return false
		}
	}

	// (4) Multi-round with/without-payload introduced-content differential: the
	// shell must reproducibly introduce content absent from the direct (blocked)
	// baseline. This reuses the shared, battle-tested confirmer (which replays the
	// payload PayloadRounds times and diffs against a fresh baseline), giving the
	// "more rounds + compare with vs without payload" gate. Fails closed only on a
	// clean negative; fails open (Ran=false) on transient transport errors.
	diff := modkit.ConfirmBodyDifferential(
		httpClient, service, realRaw, directRaw, "", 0,
		modkit.ReconfirmConfig{PayloadRounds: confirmRounds, NoRedirects: true},
	)
	if diff.Ran && !diff.Confirmed {
		return false
	}

	// (5) Soft-404 / SPA wildcard rejection.
	return modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(candidateBody), "")
}

// fetch issues the request and returns its status and body. The requester
// preserves the encoded shell paths (%23, %2f, ..;) on the wire unchanged, so the
// default client is used (which also keeps replay consistent with ConfirmNotSoft404
// and avoids the raw client's separate transport). ok is false on any
// parse/HTTP/empty-response error; fatal is true only when the host is unresponsive.
func (m *Module) fetch(httpClient *http.Requester, service *httpmsg.Service, raw []byte) (status int, body string, ok bool, fatal bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", false, false
	}
	req = req.WithService(service)

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return 0, "", false, true
		}
		return 0, "", false, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", false, false
	}
	return resp.Response().StatusCode, resp.Body().String(), true, false
}

// hasFingerprint reports whether body contains at least one of the endpoint's
// fingerprint substrings (case-insensitive).
func hasFingerprint(body string, fingerprints []string) bool {
	lower := strings.ToLower(body)
	for _, fp := range fingerprints {
		if strings.Contains(lower, fp) {
			return true
		}
	}
	return false
}

// markAndShouldContinue gates the sweep to effectively once per host.
func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	_, shouldContinue := diskSet.IncrementAndCheck(urlx.Hostname(), limitPerHost)
	return shouldContinue
}
