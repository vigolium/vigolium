package dependency_confusion

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

const (
	// maxBodySize caps the response body we will parse (15MB). Larger assets are
	// skipped to bound memory.
	maxBodySize = 15 * 1024 * 1024

	// maxObservedURLs caps how many observed URLs are recorded per candidate name
	// in the finding metadata.
	maxObservedURLs = 5

	// maxQueries bounds how many unique names we resolve against the registry in a
	// single scan, so a pathological bundle cannot stall the flush. A breach is
	// logged, never silent.
	maxQueries = 300

	// registryConcurrency bounds concurrent registry lookups.
	registryConcurrency = 8

	// perRequestTimeout and totalFlushTimeout bound a single lookup and the whole
	// resolution phase respectively.
	perRequestTimeout = 8 * time.Second
	totalFlushTimeout = 90 * time.Second
)

// jsPathSuffixes are URL path extensions treated as JavaScript when the
// Content-Type is missing or generic.
var jsPathSuffixes = []string{".js", ".mjs", ".cjs"}

// Module detects dependency-confusion candidates: scoped npm package names
// imported by the target's JavaScript that are unclaimed on the public registry.
// Names are extracted from JavaScript responses during the scan (no network) and
// resolved against the registry once, in bulk, at end-of-scan via BatchFlusher.
type Module struct {
	modkit.BasePassiveModule

	// observed collapses candidates to one entry per package name as responses
	// stream in, so memory is bounded by unique names × maxObservedURLs rather
	// than by total observations. Guarded by mu.
	mu       sync.Mutex
	observed map[string]*aggregatedCandidate

	registry *registryClient
}

// New creates a new dependency-confusion passive module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		registry: newRegistryClient(defaultRegistryBase, perRequestTimeout),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts only JavaScript responses: a JS/ECMAScript Content-Type, or
// a .js/.mjs/.cjs URL path. Manifests, lockfiles, and source maps are out of
// scope — extraction is JavaScript-only.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	body := ctx.Response().Body()
	if len(body) == 0 || len(body) > maxBodySize {
		return false
	}
	if isJSContentType(ctx.Response().Header("Content-Type")) {
		return true
	}
	if u, err := ctx.URL(); err == nil && hasJSPathSuffix(u.Path) {
		return true
	}
	return false
}

// ScanPerRequest extracts scoped package names from a JavaScript response and
// buffers them. No registry traffic happens here — resolution is deferred to
// FlushFindings so each unique name is looked up once for the whole scan.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	resp := ctx.Response()
	// A WAF/CDN edge block is the edge talking, not the application asset.
	if modkit.IsEdgeBlockedResponse(resp) {
		return nil, nil
	}

	names := extractScopedCandidates(resp.BodyToString())
	if len(names) == 0 {
		return nil, nil
	}

	urlStr := urlx.String()
	host := urlx.Host

	m.mu.Lock()
	if m.observed == nil {
		m.observed = make(map[string]*aggregatedCandidate)
	}
	for _, n := range names {
		a := m.observed[n]
		if a == nil {
			a = &aggregatedCandidate{name: n, host: host}
			m.observed[n] = a
		}
		if len(a.urls) < maxObservedURLs && !slices.Contains(a.urls, urlStr) {
			a.urls = append(a.urls, urlStr)
		}
	}
	m.mu.Unlock()

	return nil, nil
}

// FlushFindings resolves every unique candidate name against the npm registry and
// emits a Suspect finding for each that is unclaimed (HTTP 404).
//
// The lookups go to a third party, not the target, and disclose the target's
// internal package names, so they run only through scanCtx.ExternalFetcher —
// the scan's proxy and timeout — and only when the operator enabled
// dynamic_assessment.external_lookups (and not under --offline). Without it
// the buffered names are dropped and nothing is sent.
func (m *Module) FlushFindings(scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	m.mu.Lock()
	observed := m.observed
	m.observed = nil
	m.mu.Unlock()

	if len(observed) == 0 {
		return nil, nil
	}
	if scanCtx == nil || scanCtx.ExternalFetcher == nil {
		zap.L().Debug("dependency-confusion: external lookups disabled; skipping registry resolution",
			zap.Int("candidates", len(observed)))
		return nil, nil
	}
	reg := &registryClient{baseURL: m.registry.baseURL, client: scanCtx.ExternalFetcher}

	names := make([]string, 0, len(observed))
	for name := range observed {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic order and query cap

	if len(names) > maxQueries {
		zap.L().Warn("dependency-confusion: capping registry lookups",
			zap.Int("unique_candidates", len(names)),
			zap.Int("cap", maxQueries))
		names = names[:maxQueries]
	}

	ctx, cancel := context.WithTimeout(context.Background(), totalFlushTimeout)
	defer cancel()

	unclaimed := m.resolveUnclaimed(ctx, reg, names)

	results := make([]*output.ResultEvent, 0, len(unclaimed))
	for _, name := range unclaimed {
		results = append(results, newFinding(observed[name]))
	}
	return results, nil
}

// resolveUnclaimed queries names concurrently (bounded by registryConcurrency)
// and returns those that 404, preserving input order. Each goroutine owns a
// unique index, so it writes its own slot in unclaimedByIdx without a lock;
// wg.Wait establishes the happens-before for the read that follows.
func (m *Module) resolveUnclaimed(ctx context.Context, reg *registryClient, names []string) []string {
	sem := make(chan struct{}, registryConcurrency)
	unclaimedByIdx := make([]bool, len(names))
	var wg sync.WaitGroup

	for i, name := range names {
		wg.Add(1)
		go func(idx int, n string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return // leaves false — same as an indeterminate result
			}
			defer func() { <-sem }()
			unclaimedByIdx[idx] = reg.lookup(ctx, n) == resolutionUnclaimed
		}(i, name)
	}
	wg.Wait()

	var unclaimed []string
	for i, name := range names {
		if unclaimedByIdx[i] {
			unclaimed = append(unclaimed, name)
		}
	}
	return unclaimed
}

// aggregatedCandidate merges every observation of one package name. urls holds up
// to maxObservedURLs distinct locations; urls[0] (always present) is the finding's
// location.
type aggregatedCandidate struct {
	name string
	host string
	urls []string
}

// newFinding builds the ResultEvent for one unclaimed package name.
func newFinding(a *aggregatedCandidate) *output.ResultEvent {
	desc := fmt.Sprintf(
		"The scoped package %q is imported by this target's JavaScript but is not registered on the public npm registry (%s returned 404). "+
			"If the build resolves this dependency from the public registry, an attacker can publish a malicious package under this name to hijack the build (dependency confusion).",
		a.name, defaultRegistryBase)

	return &output.ResultEvent{
		ModuleID: ModuleID,
		Info: output.Info{
			Name:        ModuleName + ": " + a.name,
			Description: desc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Host:             a.host,
		URL:              a.urls[0],
		Matched:          a.urls[0],
		ExtractedResults: []string{a.name},
		Metadata: map[string]any{
			"package":         a.name,
			"registry":        defaultRegistryBase,
			"registry_status": 404,
			"scoped":          true,
			"observed_urls":   a.urls,
		},
	}
}

// hasJSPathSuffix reports whether path ends in a JavaScript file extension.
func hasJSPathSuffix(path string) bool {
	p := strings.ToLower(path)
	for _, suf := range jsPathSuffixes {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

// isJSContentType reports whether ct denotes JavaScript/ECMAScript.
func isJSContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}
