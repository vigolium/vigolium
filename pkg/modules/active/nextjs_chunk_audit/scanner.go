package nextjs_chunk_audit

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/linkfinder"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type hostState struct {
	mu      sync.Mutex
	chunks  map[string]bool
	routes  map[string]bool
	domains map[string]bool
}

func newHostState() *hostState {
	return &hostState{
		chunks:  make(map[string]bool),
		routes:  make(map[string]bool),
		domains: make(map[string]bool),
	}
}

type Module struct {
	modkit.BaseActiveModule
	hostsMu sync.Mutex
	hosts   map[string]*hostState
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		hosts: make(map[string]*hostState),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	ct := ctx.Response().Header("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/html")
}

func (m *Module) stateFor(host string) *hostState {
	m.hostsMu.Lock()
	defer m.hostsMu.Unlock()
	st, ok := m.hosts[host]
	if !ok {
		st = newHostState()
		m.hosts[host] = st
	}
	return st
}

// chunkCtx packs the per-chunk constants threaded through analyzeBody so the
// hot path stays free of long parameter lists.
type chunkCtx struct {
	scanCtx   *modkit.ScanContext
	state     *hostState
	host      string
	scheme    string
	sourceURL string
	fromMap   bool
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	host := urlx.Host

	htmlBody := ctx.Response().Body()
	if !jsframework.LooksLikeNextJS(host, string(htmlBody)) {
		return nil, nil
	}

	chunkPaths := ExtractChunkPaths(htmlBody)
	if len(chunkPaths) == 0 {
		return nil, nil
	}

	state := m.stateFor(host)
	newChunks := pickNewChunks(state, chunkPaths)
	if len(newChunks) == 0 {
		return nil, nil
	}

	scheme := urlx.Scheme
	if scheme == "" {
		scheme = "https"
	}
	baseOrigin := scheme + "://" + host
	cleanRaw, err := modkit.StripCredentialHeaders(ctx.Request().Raw())
	if err != nil {
		return nil, nil
	}
	anonymousClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}
	anonymousCtx := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(ctx.Service(), cleanRaw),
		ctx.Response(),
	)

	var results []*output.ResultEvent
	for _, chunkPath := range newChunks {
		chunkURL := baseOrigin + chunkPath
		chunkBody, ok := m.fetchBytes(anonymousCtx, anonymousClient, chunkPath, MaxChunkBytes)
		if !ok {
			continue
		}
		results = append(results, m.analyzeBody(chunkBody, chunkCtx{
			scanCtx: scanCtx, state: state, host: host, scheme: scheme, sourceURL: chunkURL,
		})...)
		// Re-emit the chunk URL through the feeder so the passive pipeline
		// (notably secret_detect's secret scan) gets coverage.
		m.feedURL(scanCtx, chunkURL)

		mapPath := chunkPath + ".map"
		mapBody, ok := m.fetchBytes(anonymousCtx, anonymousClient, mapPath, MaxMapBytes)
		if !ok {
			continue
		}
		results = append(results, m.analyzeBody(mapBody, chunkCtx{
			scanCtx: scanCtx, state: state, host: host, scheme: scheme,
			sourceURL: baseOrigin + mapPath, fromMap: true,
		})...)
	}

	return results, nil
}

func pickNewChunks(state *hostState, chunkPaths []string) []string {
	state.mu.Lock()
	defer state.mu.Unlock()
	out := make([]string, 0, len(chunkPaths))
	for _, p := range chunkPaths {
		if state.chunks[p] {
			continue
		}
		state.chunks[p] = true
		out = append(out, p)
		if len(out) >= MaxChunksPerHost {
			break
		}
	}
	return out
}

func (m *Module) fetchBytes(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
	maxBytes int64,
) ([]byte, bool) {
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), path)
	if err != nil {
		return nil, false
	}
	raw, _ = httpmsg.SetMethod(raw, "GET")

	// raw is internally built (well-formed), so wrap directly instead of
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, false
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 || infra.IsBlockedResponse(resp) {
		return nil, false
	}

	// Catch-all / echo-server guard: a real Next.js chunk (.js) or its source map
	// (.map) is served as application/javascript, text/javascript, or
	// application/json — NEVER a full HTML document. A 200 text/html body for a
	// chunk path is the host's catch-all / SPA shell served for literally any path
	// (or, under a gzip + bogus `Content-Length: 0` transport quirk, a truncated
	// TAIL fragment of it), whose reflected/echoed text can forge a bogus secret or
	// route-intel match. The Content-Type header survives that truncation, so
	// classify it and drop an HTML document here. A missing/unknown Content-Type
	// fails open so a real bundle served without one is still analysed.
	if modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
		return nil, false
	}

	body := resp.Body().Bytes()
	if int64(len(body)) > maxBytes {
		body = body[:maxBytes]
	}
	// resp.Close() may release/pool the underlying buffer; copy so the
	// returned slice is safe past the defer.
	out := make([]byte, len(body))
	copy(out, body)
	return out, true
}

func (m *Module) analyzeBody(body []byte, cc chunkCtx) []*output.ResultEvent {
	var events []*output.ResultEvent

	if matches := FindSecrets(body, 0); len(matches) > 0 {
		privateCredentials, publicIdentifiers := classifyCredentialMatches(matches)
		if len(privateCredentials) > 0 {
			events = append(events, buildSecretEvent(cc, privateCredentials))
		}
		if len(publicIdentifiers) > 0 {
			events = append(events, buildPublicIdentifierEvent(cc, publicIdentifiers))
		}
	}

	relativeRoutes := linkfinder.ExtractPaths(body)
	absoluteURLs := ExtractAbsoluteURLs(body)

	feedTargets, crossOrigin := classifyExtractions(cc, relativeRoutes, absoluteURLs)

	for _, target := range feedTargets {
		m.feedURL(cc.scanCtx, target)
	}

	if len(relativeRoutes) > 0 || len(absoluteURLs) > 0 || len(crossOrigin) > 0 {
		events = append(events, buildSummaryEvent(cc, len(relativeRoutes), len(absoluteURLs), crossOrigin))
	}

	return events
}

// classifyExtractions partitions extracted routes/URLs into in-scope feed
// targets and cross-origin domain intel. URL parsing happens outside the
// host-state lock; the lock is held only across the dedup map writes.
func classifyExtractions(cc chunkCtx, relativeRoutes, absoluteURLs []string) (feedTargets, crossOrigin []string) {
	type candidate struct {
		target      string
		crossOrigin string
	}
	candidates := make([]candidate, 0, len(relativeRoutes)+len(absoluteURLs))

	for _, p := range relativeRoutes {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		candidates = append(candidates, candidate{target: cc.scheme + "://" + cc.host + p})
	}
	for _, raw := range absoluteURLs {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		if strings.EqualFold(u.Host, cc.host) {
			target := u.Scheme + "://" + u.Host + u.Path
			if u.RawQuery != "" {
				target += "?" + u.RawQuery
			}
			candidates = append(candidates, candidate{target: target})
			continue
		}
		candidates = append(candidates, candidate{crossOrigin: u.Scheme + "://" + u.Host})
	}

	cc.state.mu.Lock()
	defer cc.state.mu.Unlock()
	for _, c := range candidates {
		switch {
		case c.target != "":
			if cc.state.routes[c.target] || len(cc.state.routes) >= MaxRoutesPerHost {
				continue
			}
			cc.state.routes[c.target] = true
			feedTargets = append(feedTargets, c.target)
		case c.crossOrigin != "":
			host := strings.TrimPrefix(strings.TrimPrefix(c.crossOrigin, "https://"), "http://")
			if cc.state.domains[host] || len(cc.state.domains) >= MaxDomainsPerHost {
				continue
			}
			cc.state.domains[host] = true
			if len(crossOrigin) < MaxCrossOriginPerChunk {
				crossOrigin = append(crossOrigin, c.crossOrigin)
			}
		}
	}
	return feedTargets, crossOrigin
}

func buildSecretEvent(cc chunkCtx, secrets []SecretMatch) *output.ResultEvent {
	conf := severity.Tentative
	sev := severity.Medium
	patterns := make([]string, 0, len(secrets))
	extracted := make([]string, 0, len(secrets))
	additional := make([]string, 0, len(secrets))
	for _, s := range secrets {
		patterns = append(patterns, s.Pattern)
		extracted = append(extracted, fmt.Sprintf("[%s] %s", s.Pattern, s.Value))
		additional = append(additional, s.Snippet)
	}
	if containsHighRiskPrivatePattern(secrets) {
		conf = severity.Firm
		sev = severity.High
	}
	desc := fmt.Sprintf("Found %d private-credential-shaped value(s) in %s (patterns: %s). The bundle is anonymously reachable, but provider-side validity and privileges were not tested.",
		len(secrets), cc.sourceURL, strings.Join(lo.Uniq(patterns), ", "))
	return &output.ResultEvent{
		ModuleID:           ModuleID,
		RecordKind:         output.RecordKindCandidate,
		EvidenceGrade:      output.EvidenceGradeCandidate,
		Host:               cc.host,
		URL:                cc.sourceURL,
		Matched:            cc.sourceURL,
		ExtractedResults:   extracted,
		AdditionalEvidence: additional,
		Info: output.Info{
			Name:        "Potential Private Credential in Next.js Bundle",
			Description: desc,
			Severity:    sev,
			Confidence:  conf,
			Tags:        []string{"nextjs", "secret", "info-disclosure"},
		},
		Metadata: map[string]any{
			"source":             cc.sourceURL,
			"from_map":           cc.fromMap,
			"count":              len(secrets),
			"credential_free":    true,
			"provider_validated": false,
		},
	}
}

func buildPublicIdentifierEvent(cc chunkCtx, identifiers []SecretMatch) *output.ResultEvent {
	patterns := make([]string, 0, len(identifiers))
	extracted := make([]string, 0, len(identifiers))
	for _, identifier := range identifiers {
		patterns = append(patterns, identifier.Pattern)
		extracted = append(extracted, fmt.Sprintf("[%s] %s", identifier.Pattern, identifier.Value))
	}
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		Host:             cc.host,
		URL:              cc.sourceURL,
		Matched:          cc.sourceURL,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "Public Client Identifier in Next.js Bundle",
			Description: fmt.Sprintf("Found %d client-visible identifier(s) in %s (%s). These formats are designed to be publishable; review provider restrictions rather than rotate them as leaked secrets.", len(identifiers), cc.sourceURL, strings.Join(lo.Uniq(patterns), ", ")),
			Severity:    severity.Info,
			Confidence:  severity.Firm,
			Tags:        []string{"nextjs", "client-identifier", "intel"},
		},
		Metadata: map[string]any{
			"source":               cc.sourceURL,
			"from_map":             cc.fromMap,
			"count":                len(identifiers),
			"intentionally_public": true,
		},
	}
}

func buildSummaryEvent(cc chunkCtx, routes, urls int, crossOrigin []string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		Host:             cc.host,
		URL:              cc.sourceURL,
		Matched:          cc.sourceURL,
		ExtractedResults: crossOrigin,
		Info: output.Info{
			Name:        "Next.js Static Chunk Analysed",
			Description: fmt.Sprintf("Extracted intel from %s", cc.sourceURL),
			Severity:    severity.Info,
			Confidence:  severity.Certain,
			Tags:        []string{"nextjs", "intel", "info-disclosure"},
		},
		Metadata: map[string]any{
			"source":       cc.sourceURL,
			"from_map":     cc.fromMap,
			"routes":       routes,
			"urls":         urls,
			"cross_origin": len(crossOrigin),
		},
	}
}

func (m *Module) feedURL(scanCtx *modkit.ScanContext, target string) {
	if scanCtx == nil {
		return
	}
	feeder := scanCtx.Feeder()
	if feeder == nil {
		return
	}
	rr, err := httpmsg.GetRawRequestFromURL(target)
	if err != nil {
		return
	}
	feeder.Feed(rr)
}

func distinctPatterns(matches []SecretMatch) int {
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		seen[m.Pattern] = struct{}{}
	}
	return len(seen)
}

var publicClientIdentifierPatterns = map[string]bool{
	"aws-access-key-id":       true,
	"google-api-key":          true,
	"stripe-live-publishable": true,
	"stripe-test-publishable": true,
}

var highRiskPrivateCredentialPatterns = map[string]bool{
	"github-pat":              true,
	"github-fine-grained-pat": true,
	"stripe-live-secret":      true,
	"slack-token":             true,
}

func classifyCredentialMatches(matches []SecretMatch) (privateCredentials, publicIdentifiers []SecretMatch) {
	for _, match := range matches {
		if publicClientIdentifierPatterns[match.Pattern] {
			publicIdentifiers = append(publicIdentifiers, match)
			continue
		}
		privateCredentials = append(privateCredentials, match)
	}
	return privateCredentials, publicIdentifiers
}

func containsHighRiskPrivatePattern(matches []SecretMatch) bool {
	for _, match := range matches {
		if highRiskPrivateCredentialPatterns[match.Pattern] {
			return true
		}
	}
	return false
}
