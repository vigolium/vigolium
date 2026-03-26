package race_interference

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
	"github.com/sourcegraph/conc"
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
				modkit.InsertionPointTypeSet(httpmsg.INS_PARAM_BODY)|
				modkit.InsertionPointTypeSet(httpmsg.INS_PARAM_COOKIE)|
				modkit.InsertionPointTypeSet(httpmsg.INS_PARAM_JSON),
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
	baseline, reflected := m.buildBaseline(ctx, ip, httpClient, anchor)
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
			// Filter 403->421 FP
			if !status403To421Filter(baseline.statusCode, result.StatusCode) {
				parallelDivergent = append(parallelDivergent, result)
			}
		}
	}

	// Phase 3: Sequential confirmation
	sequentialResults := m.sendSequentialProbes(ctx, ip, httpClient, anchor)

	var sequentialWrongIdResults []*ProbeResult
	for _, result := range sequentialResults {
		if result.Err != nil {
			continue
		}
		if result.HasWrongId {
			sequentialWrongIdResults = append(sequentialWrongIdResults, result)
		}
	}

	// Phase 4: Classification
	var results []*output.ResultEvent

	// Input Storage: wrongId persists in sequential (only for URL params)
	if m.options.EnableInputStorageDetection &&
		len(sequentialWrongIdResults) > 0 &&
		ip.Type() == httpmsg.INS_PARAM_URL {

		result := sequentialWrongIdResults[0]
		finding := &Finding{
			Type:        FindingInputStorage,
			Parameter:   ip.Name(),
			Anchor:      anchor,
			WrongIdSeen: result.WrongIdVal,
			Request:     result.Request,
			Response:    result.Response,
		}
		results = append(results, m.buildResult(finding, urlx.String(), ip.Name()))
	}

	// Cross-contamination: wrongId only in parallel, not in sequential
	if m.options.EnableCrossContaminationDetection &&
		len(parallelWrongIdResults) > 0 &&
		len(sequentialWrongIdResults) == 0 {

		result := parallelWrongIdResults[0]
		finding := &Finding{
			Type:        FindingCrossContamination,
			Parameter:   ip.Name(),
			Anchor:      anchor,
			WrongIdSeen: result.WrongIdVal,
			Request:     result.Request,
			Response:    result.Response,
		}
		results = append(results, m.buildResult(finding, urlx.String(), ip.Name()))
	}

	// Request Interference: no wrongId but divergent responses in parallel
	if m.options.EnableRequestInterferenceDetection &&
		len(parallelWrongIdResults) == 0 &&
		len(parallelDivergent) > 0 {

		result := parallelDivergent[0]
		finding := &Finding{
			Type:      FindingRequestInterference,
			Parameter: ip.Name(),
			Anchor:    anchor,
			Request:   result.Request,
			Response:  result.Response,
		}
		results = append(results, m.buildResult(finding, urlx.String(), ip.Name()))
	}

	return results, nil
}

// buildBaseline sends sequential baseline requests and checks reflection.
func (m *Module) buildBaseline(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	anchor string,
) (*ResponseGroup, bool) {
	var group *ResponseGroup
	var reflected bool

	for i := 0; i < m.options.BaselineRequestCount; i++ {
		payload := anchor + "BASE"
		fuzzedRaw := ip.BuildRequest([]byte(payload))
		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			return nil, false
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, false
			}
			continue
		}

		body := resp.Body().String()
		statusCode := resp.Response().StatusCode
		headers := resp.Response().Header.Clone()
		resp.Close()

		// Check WAF blocking
		serverHeader := ""
		if sv := resp.Response().Header.Get("Server"); sv != "" {
			serverHeader = sv
		}
		if isWafBlocked(statusCode, serverHeader) {
			continue
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

	return group, reflected
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
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		result.Err = err
		return result
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		result.Err = err
		return result
	}

	result.Body = resp.Body().String()
	result.StatusCode = resp.Response().StatusCode
	result.Headers = resp.Response().Header.Clone()
	result.Request = string(fuzzedRaw)
	result.Response = resp.FullResponse().String()
	resp.Close()

	// Check for wrong ID
	hasWrongId, wrongIdVal := containsWrongId(result.Body, anchor, idx)
	result.HasWrongId = hasWrongId
	result.WrongIdVal = wrongIdVal

	return result
}

// buildResult creates a ResultEvent from a finding.
func (m *Module) buildResult(finding *Finding, url, param string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID:         m.ID(),
		URL:              url,
		Matched:          url,
		FuzzingParameter: param,
		Request:          finding.Request,
		Response:         finding.Response,
		ExtractedResults: []string{finding.Anchor, finding.WrongIdSeen},
		Info: output.Info{
			Name:        m.Name(),
			Severity:    m.Severity(),
			Description: finding.buildDescription(),
			Reference: []string{
				"https://portswigger.net/research/smashing-the-state-machine",
				"https://portswigger.net/research/web-cache-poisoning",
				"https://owasp.org/www-community/attacks/Race_condition_attack",
			},
		},
	}
}
