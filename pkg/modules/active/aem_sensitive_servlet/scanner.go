package aem_sensitive_servlet

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	reproduceRounds = 2
	// maxCandidates bounds the dispatcher-bypass fan-out per servlet path.
	maxCandidates = 8
)

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("aem_sensitive_servlet"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := urlx.Host

	if !modkit.BeginHostProbeKey(scanCtx, httpClient, &m.ds, host) {
		return nil, nil
	}

	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent
	for _, s := range servlets {
		if res := m.probeServlet(ctx, httpClient, scanCtx, s, baseURL); res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// probeServlet sweeps each declared path plus a bounded set of dispatcher-bypass
// variants, and returns the first confirmed disclosure for the servlet.
func (m *Module) probeServlet(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	s servlet,
	baseURL string,
) *output.ResultEvent {
	for _, base := range s.paths {
		for _, path := range candidatePaths(base) {
			res := aem.Get(ctx, httpClient, path, nil)
			if !res.OK {
				continue
			}
			v, ok := s.eval(res)
			if !ok {
				continue
			}
			// Not merely the application's own observed shell echoed back.
			if modkit.ResemblesObservedPage(ctx, res.Body) {
				continue
			}
			// Same-directory catch-all disproof (JSON servlets only).
			if s.siblingGuard && modkit.SiblingPathCatchAll(scanCtx, ctx, httpClient, path, func(b string) bool {
				_, sok := s.eval(aem.ProbeResult{Status: 200, Body: b, ContentType: "application/json", OK: true})
				return sok
			}) {
				continue
			}
			// The disclosure must reproduce across independent rounds.
			if !aem.ReproduceMarker(ctx, httpClient, path, reproduceRounds, func(r aem.ProbeResult) bool {
				_, rok := s.eval(r)
				return rok
			}) {
				continue
			}
			return m.build(s, v, path, base, baseURL)
		}
	}
	return nil
}

// candidatePaths returns the clean path plus a bounded set of content-type-filter
// and traversal dispatcher bypasses. The two builders emit disjoint forms
// (Extension leads with the clean path; Traversal never repeats it), so a plain
// concatenation capped at maxCandidates needs no deduplication.
func candidatePaths(base string) []string {
	out := append(aem.ExtensionBypasses(base), aem.TraversalBypasses(base)...)
	if len(out) > maxCandidates {
		out = out[:maxCandidates]
	}
	return out
}

func (m *Module) build(s servlet, v verdict, requestedPath, base, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + requestedPath

	confidence := severity.Firm
	if v.severity >= severity.High {
		confidence = severity.Certain
	}

	tags := append([]string{"aem", "adobe"}, s.baseTags...)
	evidence := append([]string{"servlet: " + s.id, "path: " + requestedPath}, v.evidence...)

	desc := fmt.Sprintf(
		"AEM servlet disclosure at %s: %s. Confirmed across %d re-fetch rounds and not a catch-all shell.",
		requestedPath, v.name, reproduceRounds,
	)

	res := &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        v.name,
			Description: desc,
			Severity:    v.severity,
			Confidence:  confidence,
			Tags:        tags,
			Reference:   s.ref,
		},
	}

	if requestedPath != base {
		modkit.AnnotatePathBypassFinding(res, requestedPath)
	}
	return res
}
