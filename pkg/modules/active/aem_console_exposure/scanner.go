package aem_console_exposure

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

// reproduceRounds is how many additional times a confirmed panel is re-fetched;
// the panel must serve its identifying markers on every round.
const reproduceRounds = 2

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
		ds: dedup.LazyDiskSet("aem_console_exposure"),
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

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	// Fail-closed AEM gate: never probe consoles on a non-AEM target.
	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent
	for _, p := range panels {
		if res := m.probePanel(ctx, httpClient, scanCtx, p, baseURL); res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// probePanel tries each of a panel's paths directly; when the direct path is
// blocked by a fronting dispatcher (401/403/405), it falls back to the traversal
// path-normalization bypasses. Returns the first confirmed finding, or nil.
func (m *Module) probePanel(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	p panel,
	baseURL string,
) *output.ResultEvent {
	for _, path := range p.paths {
		res := aem.Get(ctx, httpClient, path, nil)
		if !res.OK {
			continue
		}
		if isPanel(ctx, p, path, res) {
			if fin := m.confirm(ctx, httpClient, scanCtx, p, path, baseURL, ""); fin != nil {
				return fin
			}
			continue
		}
		if modkit.IsProxyBlockedStatus(res.Status) {
			for _, bp := range aem.TraversalBypasses(path) {
				bres := aem.Get(ctx, httpClient, bp, nil)
				if bres.OK && isPanel(ctx, p, bp, bres) {
					if fin := m.confirm(ctx, httpClient, scanCtx, p, bp, baseURL, path); fin != nil {
						return fin
					}
				}
			}
		}
	}
	return nil
}

// isPanel reports whether res is the panel: a 200 whose body (with any reflected
// probe path removed) satisfies the panel's marker groups and is not merely the
// application's own observed shell.
func isPanel(ctx *httpmsg.HttpRequestResponse, p panel, path string, res aem.ProbeResult) bool {
	if res.Status != 200 {
		return false
	}
	body := modkit.StripReflectedProbePath(res.Body, path)
	if _, ok := modkit.MatchAllGroups(body, p.markers); !ok {
		return false
	}
	// A catch-all/SPA shell that echoes the same page for any path is not a panel.
	return !modkit.ResemblesObservedPage(ctx, res.Body)
}

// confirm runs the multi-round confirmation (catch-all sibling guard + N stable
// re-fetches) before building the finding. requestedPath is the path that matched
// (a bypass variant when non-empty directPath); directPath is the original blocked
// path when reached via a dispatcher bypass, "" otherwise.
func (m *Module) confirm(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	p panel,
	requestedPath, baseURL, directPath string,
) *output.ResultEvent {
	match := func(r aem.ProbeResult) bool {
		if r.Status != 200 {
			return false
		}
		_, ok := modkit.MatchAllGroups(modkit.StripReflectedProbePath(r.Body, requestedPath), p.markers)
		return ok
	}

	// A guaranteed-nonexistent sibling under the same directory that serves the
	// same markers means a sub-directory catch-all, not a real panel.
	if modkit.SiblingServesAnyMarker(scanCtx, ctx, httpClient, requestedPath, p.markers[0]) {
		return nil
	}
	// The panel must serve its identifying markers on every re-fetch.
	if !aem.ReproduceMarker(ctx, httpClient, requestedPath, reproduceRounds, match) {
		return nil
	}

	return m.buildFinding(p, requestedPath, baseURL, directPath)
}

func (m *Module) buildFinding(p panel, requestedPath, baseURL, directPath string) *output.ResultEvent {
	matchedURL := baseURL + requestedPath

	tags := append([]string{"aem", "adobe"}, p.tags...)
	desc := fmt.Sprintf(
		"An AEM console/admin panel (%s) is reachable at %s. It confirmed across %d re-fetch rounds and is not a catch-all shell.",
		p.name, requestedPath, reproduceRounds,
	)

	evidence := []string{"panel: " + p.id, "path: " + requestedPath}

	res := &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        p.name,
			Description: desc,
			Severity:    p.severity,
			Confidence:  severity.Firm,
			Tags:        tags,
			Reference:   p.ref,
		},
	}

	// Reached via a dispatcher path-normalization bypass: annotate with the bypass
	// path, the ACL-bypass tags/reference, and the explanation.
	if directPath != "" && directPath != requestedPath {
		modkit.AnnotatePathBypassFinding(res, requestedPath)
	}
	return res
}
