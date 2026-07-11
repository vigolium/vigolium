package race_interference

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// Module detects race condition vulnerabilities through parallel request analysis.
type Module struct {
	modkit.BaseActiveModule
	rhm     dedup.Lazy[dedup.RequestHashManager]
	options Options
}

// New creates a new race interference detection module.
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
			modkit.InsertionPointTypeSet(httpmsg.INS_PARAM_URL)|
				modkit.InsertionPointTypeSet(httpmsg.INS_PARAM_COOKIE),
		),
		rhm:     dedup.LazyDefaultRHM("race_interference"),
		options: DefaultOptions(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ProbeResult holds the result of a single probe request.
type ProbeResult struct {
	Index      int
	UniqueID   string
	Body       string
	StatusCode int
	Headers    map[string][]string
	Request    string
	Response   string
	HasWrongId bool
	WrongIdVal string
	Err        error
}

// ScanPerInsertionPoint tests a single insertion point for race condition vulnerabilities.
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
	// A race probe issues dozens of requests. Repeating a POST/PUT/PATCH can
	// create duplicate orders, charges, or destructive state, so the generic
	// module is intentionally limited to idempotent GET requests.
	if ctx.Request() == nil || !strings.EqualFold(ctx.Request().Method(), "GET") {
		return nil, nil
	}

	// Check deduplication
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Generate anchor for reflection detection
	anchor := utils.GenerateCanary()

	// Phase 1: Baseline - check if input is reflected
	baseline, reflected, baselineReq, baselineResp := m.buildBaseline(ctx, ip, httpClient, anchor)
	if baseline == nil {
		return nil, nil // Host error or no response
	}

	// Only proceed if anchor is reflected
	if !reflected {
		zap.L().Debug("Anchor not reflected, skipping parameter",
			zap.String("param", ip.Name()),
			zap.String("anchor", anchor))
		return nil, nil
	}

	zap.L().Debug("Anchor reflected, proceeding with race detection",
		zap.String("param", ip.Name()),
		zap.String("anchor", anchor))

	// Phase 2: Parallel probe
	parallelResults := m.sendParallelProbes(ctx, ip, httpClient, anchor)

	// Check for parallel wrongId occurrences
	var parallelWrongIdResults []*ProbeResult
	var parallelDivergent []*ProbeResult
	for _, result := range parallelResults {
		if result.Err != nil {
			continue
		}
		if result.HasWrongId {
			parallelWrongIdResults = append(parallelWrongIdResults, result)
		}
		// Check for divergence from baseline
		if !baseline.Matches(result.StatusCode, result.Body, result.Headers) {
			// A WAF/rate-limit response (notably a 429) to a PARALLEL burst is the
			// edge throttling concurrency, not request interference — exclude it
			// alongside the existing 403->421 filter, or every rate-limited host
			// yields a spurious "request interference" finding.
			serverHeader := ""
			if vals := result.Headers["Server"]; len(vals) > 0 {
				serverHeader = vals[0]
			}
			if !status403To421Filter(baseline.statusCode, result.StatusCode) &&
				!isWafBlocked(result.StatusCode, serverHeader) {
				parallelDivergent = append(parallelDivergent, result)
			}
		}
	}

	// Phase 3: Sequential confirmation
	sequentialResults := m.sendSequentialProbes(ctx, ip, httpClient, anchor)

	var sequentialWrongIdResults []*ProbeResult
	var sequentialDivergent []*ProbeResult
	for _, result := range sequentialResults {
		if result.Err != nil {
			continue
		}
		if result.HasWrongId {
			sequentialWrongIdResults = append(sequentialWrongIdResults, result)
		}
		// Determinism control for the Request Interference leg. A SEQUENTIAL probe
		// (no concurrency) that still diverges from the baseline proves the endpoint
		// is non-deterministic on its own — a per-request CSRF token / nonce /
		// timestamp / SSR shell that the 3-sample baseline under-sampled and marked
		// static. When that is the case, a PARALLEL divergence is that same
		// per-request noise, not a concurrency effect, so it must not be reported.
		// WAF/rate-limit divergence is excluded exactly as in the parallel phase.
		if !baseline.Matches(result.StatusCode, result.Body, result.Headers) {
			serverHeader := ""
			if vals := result.Headers["Server"]; len(vals) > 0 {
				serverHeader = vals[0]
			}
			if !status403To421Filter(baseline.statusCode, result.StatusCode) &&
				!isWafBlocked(result.StatusCode, serverHeader) {
				sequentialDivergent = append(sequentialDivergent, result)
			}
		}
	}

	// Phase 4: Classification
	var results []*output.ResultEvent

	// Input Storage: wrongId persists in sequential (only for URL params)
	if m.options.EnableInputStorageDetection &&
		len(sequentialWrongIdResults) > 0 &&
		ip.Type() == httpmsg.INS_PARAM_URL {

		if confirmation, confirmed := m.reconfirmWrongID(ctx, ip, httpClient, FindingInputStorage); confirmed {
			result := sequentialWrongIdResults[0]
			finding := &Finding{
				Type:        FindingInputStorage,
				Parameter:   ip.Name(),
				Anchor:      anchor,
				WrongIdSeen: result.WrongIdVal,
				Request:     result.Request,
				Response:    result.Response,
			}
			ev := modkit.NewEvidenceCollector()
			ev.Add("baseline", baselineReq, baselineResp)
			ev.Add("sequential-probe", result.Request, result.Response)
			if clean := firstCleanProbe(sequentialResults, baseline, result); clean != nil {
				ev.Add("sequential-control (clean sibling)", clean.Request, clean.Response)
			}
			ev.Add("fresh-canary reproduction", confirmation.Request, confirmation.Response)
			results = append(results, m.buildResult(finding, urlx.String(), ip.Name(), ev.Entries()))
		}
	}

	// Cross-contamination: wrongId only in parallel, not in sequential
	if m.options.EnableCrossContaminationDetection &&
		len(parallelWrongIdResults) > 0 &&
		len(sequentialWrongIdResults) == 0 {

		if confirmation, confirmed := m.reconfirmWrongID(ctx, ip, httpClient, FindingCrossContamination); confirmed {
			result := parallelWrongIdResults[0]
			finding := &Finding{
				Type:        FindingCrossContamination,
				Parameter:   ip.Name(),
				Anchor:      anchor,
				WrongIdSeen: result.WrongIdVal,
				Request:     result.Request,
				Response:    result.Response,
			}
			ev := modkit.NewEvidenceCollector()
			ev.Add("baseline", baselineReq, baselineResp)
			ev.Add("parallel-probe", result.Request, result.Response)
			if clean := firstCleanProbe(parallelResults, baseline, result); clean != nil {
				ev.Add("parallel-control (clean concurrent sibling)", clean.Request, clean.Response)
			}
			ev.Add("fresh-canary reproduction", confirmation.Request, confirmation.Response)
			results = append(results, m.buildResult(finding, urlx.String(), ip.Name(), ev.Entries()))
		}
	}

	// Request Interference: no wrongId but divergent responses in parallel.
	// Divergence alone is a weak signal, so we emit at most one finding per
	// URL (scope-level grouping via ParamFindings) to keep output readable, and
	// only when SEQUENTIAL probes stayed on-baseline — i.e. the divergence is
	// attributable to concurrency, not to an endpoint that varies every response.
	if m.options.EnableRequestInterferenceDetection &&
		len(parallelWrongIdResults) == 0 &&
		len(parallelDivergent) > 0 &&
		len(sequentialDivergent) == 0 &&
		m.reserveInterferenceSlot(scanCtx, urlx.Scheme, urlx.Host, urlx.Path) {

		result := parallelDivergent[0]
		finding := &Finding{
			Type:      FindingRequestInterference,
			Parameter: ip.Name(),
			Anchor:    anchor,
			Request:   result.Request,
			Response:  result.Response,
		}
		ev := modkit.NewEvidenceCollector()
		ev.Add("baseline", baselineReq, baselineResp)
		ev.Add("parallel-probe", result.Request, result.Response)
		if clean := firstCleanProbe(parallelResults, baseline, result); clean != nil {
			ev.Add("parallel-control (baseline-matching sibling)", clean.Request, clean.Response)
		}
		results = append(results, m.buildResult(finding, urlx.String(), ip.Name(), ev.Entries()))
	}

	return results, nil
}

// reconfirmWrongID repeats a storage/cross-contamination classification with a
// completely fresh anchor. A one-burst wrong-id observation can result from a
// stale response, retry, or intermediary; the same class must recur independently.
func (m *Module) reconfirmWrongID(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	client *http.Requester,
	findingType FindingType,
) (*ProbeResult, bool) {
	anchor := utils.GenerateCanary()
	baseline, reflected, _, _ := m.buildBaseline(ctx, ip, client, anchor)
	if baseline == nil || !reflected {
		return nil, false
	}

	switch findingType {
	case FindingInputStorage:
		for _, result := range m.sendSequentialProbes(ctx, ip, client, anchor) {
			if result != nil && result.Err == nil && result.HasWrongId {
				return result, true
			}
		}
	case FindingCrossContamination:
		parallel := m.sendParallelProbes(ctx, ip, client, anchor)
		var wrong *ProbeResult
		for _, result := range parallel {
			if result != nil && result.Err == nil && result.HasWrongId {
				wrong = result
				break
			}
		}
		if wrong == nil {
			return nil, false
		}
		for _, result := range m.sendSequentialProbes(ctx, ip, client, anchor) {
			if result != nil && result.Err == nil && result.HasWrongId {
				return nil, false
			}
		}
		return wrong, true
	}
	return nil, false
}

// firstCleanProbe returns the first probe in results that succeeded, carries no
// wrong id, still matches the baseline group, and is not the divergent probe
// itself — i.e. a concurrent/sequential sibling that came back normal. Attaching
// it gives the finding a contrasting "this one was fine" pair, so the evidence
// shows the interference (one corrupted request next to clean ones) rather than a
// single odd response in isolation. Returns nil when every sibling also diverged
// or errored.
func firstCleanProbe(results []*ProbeResult, baseline *ResponseGroup, exclude *ProbeResult) *ProbeResult {
	for _, r := range results {
		if r == nil || r == exclude || r.Err != nil || r.HasWrongId || r.Request == "" {
			continue
		}
		if baseline != nil && !baseline.Matches(r.StatusCode, r.Body, r.Headers) {
			continue
		}
		return r
	}
	return nil
}

// buildBaseline sends sequential baseline requests and checks reflection. It
// also returns the first valid (non-WAF-blocked) baseline request/response pair
// as raw strings for finding evidence (empty if none was captured); this is
// observation-only and does not affect the baseline grouping or race logic.
func (m *Module) buildBaseline(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	anchor string,
) (*ResponseGroup, bool, string, string) {
	var group *ResponseGroup
	var reflected bool
	var baselineReq, baselineResp string

	for i := 0; i < m.options.BaselineRequestCount; i++ {
		payload := anchor + "BASE"
		fuzzedRaw := ip.BuildRequest([]byte(payload))
		// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		// NoClustering: the baseline loop sends the identical "BASE" request several
		// times to model the endpoint's natural per-request variation. The 500ms
		// request-cluster cache keys on raw request bytes, so clustered samples return
		// the first response's cached copy and the variation model collapses — under-
		// modelling a dynamic endpoint. Each sample must be a genuine round-trip.
		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoClustering: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, false, "", ""
			}
			continue
		}

		body := resp.Body().String()
		statusCode := resp.Response().StatusCode
		headers := resp.Response().Header.Clone()
		// Capture the first valid baseline pair for evidence before Close().
		fullResp := resp.FullResponseString()
		resp.Close()

		// Check WAF blocking
		serverHeader := ""
		if sv := headers.Get("Server"); sv != "" {
			serverHeader = sv
		}
		if isWafBlocked(statusCode, serverHeader) {
			continue
		}

		if baselineReq == "" {
			baselineReq = string(fuzzedRaw)
			baselineResp = fullResp
		}

		// Check reflection on first valid response
		if !reflected && containsAnchor(body, anchor) {
			reflected = true
		}

		// Build or update response group
		if group == nil {
			group = NewResponseGroup(statusCode, body, headers)
		} else {
			group.Update(statusCode, body, headers)
		}
	}

	return group, reflected, baselineReq, baselineResp
}

// sendParallelProbes sends concurrent probe requests.
func (m *Module) sendParallelProbes(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	anchor string,
) []*ProbeResult {
	results := make([]*ProbeResult, m.options.ParallelProbeCount)
	var wg conc.WaitGroup

	for i := 0; i < m.options.ParallelProbeCount; i++ {
		idx := i
		wg.Go(func() {
			results[idx] = m.sendProbe(ctx, ip, httpClient, anchor, idx)
		})
	}

	wg.Wait()
	return results
}

// sendSequentialProbes sends sequential confirmation requests.
func (m *Module) sendSequentialProbes(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	anchor string,
) []*ProbeResult {
	results := make([]*ProbeResult, m.options.ConfirmationRequestCount)

	for i := 0; i < m.options.ConfirmationRequestCount; i++ {
		results[i] = m.sendProbe(ctx, ip, httpClient, anchor, i)
	}

	return results
}

// sendProbe sends a single probe request with indexed payload.
func (m *Module) sendProbe(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	anchor string,
	idx int,
) *ProbeResult {
	result := &ProbeResult{
		Index:    idx,
		UniqueID: utils.RandomString(4),
	}

	// Build payload: anchor + index + uniqueID
	payload := fmt.Sprintf("%s%d%s", anchor, idx, result.UniqueID)
	fuzzedRaw := ip.BuildRequest([]byte(payload))
	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		result.Err = err
		return result
	}

	result.Body = resp.Body().String()
	result.StatusCode = resp.Response().StatusCode
	result.Headers = resp.Response().Header.Clone()
	result.Request = string(fuzzedRaw)
	result.Response = resp.FullResponseString()
	resp.Close()

	// Check for wrong ID
	hasWrongId, wrongIdVal := containsWrongId(result.Body, anchor, idx)
	result.HasWrongId = hasWrongId
	result.WrongIdVal = wrongIdVal

	return result
}

// buildResult creates a ResultEvent from a finding. evidence carries the
// baseline and probe context pairs collected while proving the finding.
func (m *Module) buildResult(finding *Finding, url, param string, evidence []string) *output.ResultEvent {
	kind := output.RecordKindCandidate
	grade := output.EvidenceGradeDifferential
	if finding.Type == FindingRequestInterference {
		kind = output.RecordKindObservation
		grade = output.EvidenceGradeObservation
	}
	return &output.ResultEvent{
		ModuleID:           m.ID(),
		RecordKind:         kind,
		EvidenceGrade:      grade,
		URL:                url,
		Matched:            url,
		FuzzingParameter:   param,
		Request:            finding.Request,
		Response:           finding.Response,
		ExtractedResults:   []string{finding.Anchor, finding.WrongIdSeen},
		AdditionalEvidence: evidence,
		Info: output.Info{
			Name:        m.Name(),
			Severity:    finding.Severity(),
			Confidence:  finding.Confidence(),
			Description: finding.buildDescription(),
			Reference: []string{
				"https://portswigger.net/research/smashing-the-state-machine",
				"https://portswigger.net/research/web-cache-poisoning",
				"https://owasp.org/www-community/attacks/Race_condition_attack",
			},
		},
		Metadata: map[string]any{
			"same_session_only":   finding.Type != FindingRequestInterference,
			"cross_user_proven":   false,
			"fresh_reproduction":  finding.Type != FindingRequestInterference,
			"state_impact_proven": false,
		},
	}
}

// interferenceGroupTag is the sentinel vuln tag used to dedupe Request
// Interference findings per URL via the scan-scoped ParameterFindingRegistry.
const interferenceGroupTag = "race-interference-ri-group"

// reserveInterferenceSlot claims the per-URL slot for a Request Interference
// finding. Returns true on the first caller for a given URL and false for
// every subsequent caller, collapsing noisy per-parameter emissions into one
// finding per endpoint.
func (m *Module) reserveInterferenceSlot(scanCtx *modkit.ScanContext, scheme, host, path string) bool {
	reg := scanCtx.ParamFindingsRegistry()
	if reg == nil {
		return true
	}
	key := normalizeInterferenceKey(scheme, host, path)
	if reg.HasFinding(key, "*", interferenceGroupTag) {
		return false
	}
	reg.MarkFound(key, "*", interferenceGroupTag)
	return true
}

func normalizeInterferenceKey(scheme, host, path string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if scheme == "" {
		return host + path
	}
	return scheme + "://" + host + path
}
