package idor_detection

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/authzutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// maxProbesPerHost limits the number of IDOR probes per host.
const maxProbesPerHost = 50

// maxBodySize is the upper body size limit (500KB) for response comparison.
const maxBodySize = 500 * 1024

// minBodySize is the minimum body size (50 bytes) for meaningful comparison.
const minBodySize = 50

// Module implements the active IDOR detection scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
	ds  dedup.Lazy[dedup.DiskSet]
}

// New creates a new IDOR Detection module.
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
			modkit.URLParamTypes|modkit.BodyParamTypes|modkit.CookieTypes,
		),
		rhm: dedup.LazyDefaultRHM("idor_detection"),
		ds:  dedup.LazyDiskSet("idor_detection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single parameter for IDOR by substituting neighbor IDs.
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

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by request hash + insertion point
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Per-host rate limit
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil {
		hostKey := utils.Sha1(urlx.Host)
		if _, ok := diskSet.IncrementAndCheck(hostKey, maxProbesPerHost); !ok {
			return nil, nil
		}
	}

	// Classify the parameter
	isPathParam := ip.Type() == httpmsg.INS_URL_PATH_FOLDER || ip.Type() == httpmsg.INS_URL_PATH_FILENAME
	pathSegments := strings.Split(urlx.Path, "/")
	classification := authzutil.ClassifyParam(ip.Name(), ip.BaseValue(), isPathParam, pathSegments)

	if !classification.IsObjectID || classification.Predictability <= authzutil.PredictLow {
		return nil, nil
	}

	// Generate neighbor IDs
	neighbors := authzutil.GenerateNeighborIDs(ip.BaseValue(), classification.IDType, 3)
	if len(neighbors) == 0 {
		return nil, nil
	}

	// Get baseline response
	baseline, err := m.getBaseline(ctx, httpClient, scanCtx)
	if err != nil || baseline == nil {
		return nil, nil
	}

	// Skip if baseline is not a successful response or body is out of range
	if baseline.StatusCode < 200 || baseline.StatusCode >= 300 {
		return nil, nil
	}
	if baseline.BodyLength < minBodySize || baseline.BodyLength > maxBodySize {
		return nil, nil
	}

	compareOpts := authzutil.DefaultCompareOptions()
	host := urlx.Host
	urlStr := urlx.String()

	// Probe each neighbor
	for _, neighborID := range neighbors {
		result, err := m.probeNeighbor(ctx, ip, neighborID, httpClient, baseline, compareOpts, host, urlStr, classification)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}
		if result != nil {
			return []*output.ResultEvent{result}, nil
		}
	}

	return nil, nil
}

// baselineSummary holds baseline response data for comparison.
type baselineSummary struct {
	StatusCode int
	BodyLength int
	Summary    *authzutil.ResponseSummary
}

// getBaseline obtains a baseline response to compare against probes.
func (m *Module) getBaseline(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) (*baselineSummary, error) {
	// Prefer the existing response if available
	if ctx.HasResponse() {
		resp := ctx.Response()
		body := resp.Body()
		summary := authzutil.SummarizeResponse(
			resp.StatusCode(),
			resp.Header("Content-Type"),
			body,
		)
		return &baselineSummary{
			StatusCode: resp.StatusCode(),
			BodyLength: len(body),
			Summary:    summary,
		}, nil
	}

	// Replay the original request
	entry, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Response == nil {
		return nil, nil
	}

	body := entry.Response.Body()
	summary := authzutil.SummarizeResponse(
		entry.StatusCode,
		entry.Response.Header("Content-Type"),
		body,
	)
	return &baselineSummary{
		StatusCode: entry.StatusCode,
		BodyLength: entry.BodyLen,
		Summary:    summary,
	}, nil
}

// probeNeighbor sends a single probe with a neighbor ID and evaluates the response.
func (m *Module) probeNeighbor(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	neighborID string,
	httpClient *http.Requester,
	baseline *baselineSummary,
	compareOpts authzutil.CompareOptions,
	host string,
	urlStr string,
	classification authzutil.IDClassification,
) (*output.ResultEvent, error) {
	// Build the probe request
	fuzzedRaw := ip.BuildRequest([]byte(neighborID))
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}

	// Extract all response data before closing
	probeStatus := 0
	var probeContentType string
	var location string
	if resp.Response() != nil {
		probeStatus = resp.Response().StatusCode
		probeContentType = resp.Response().Header.Get("Content-Type")
		location = resp.Response().Header.Get("Location")
	}
	// Copy the body before Close: resp.Body().Bytes() aliases a buffer that
	// Close() returns to a process-global pool, so reading probeBody afterwards
	// is a use-after-free that races with concurrent module execution.
	probeBody := append([]byte(nil), resp.Body().Bytes()...)
	probeRequest := string(fuzzedRaw)
	probeResponse := resp.FullResponse().String()
	resp.Close()

	// Hard denial: 401, 403 → authorization enforced
	if probeStatus == 401 || probeStatus == 403 {
		return nil, nil
	}

	// Not found: 404 → nonexistent resource
	if probeStatus == 404 {
		return nil, nil
	}

	// Login redirect
	if authzutil.IsLoginRedirect(probeStatus, location) {
		return nil, nil
	}

	// Non-2xx → not a successful access
	if probeStatus < 200 || probeStatus >= 300 {
		return nil, nil
	}

	// Soft-denial check
	if authzutil.ContainsEnforcementString(string(probeBody)) {
		return nil, nil
	}

	// Compare responses
	probeSummary := authzutil.SummarizeResponse(probeStatus, probeContentType, probeBody)
	comparison := authzutil.CompareResponses(baseline.Summary, probeSummary, compareOpts)

	// Content identical → public data, same object
	if comparison.ContentIdentical {
		return nil, nil
	}

	// Not structurally similar → different resource type / error page
	if !comparison.StructurallyIdentical {
		return nil, nil
	}

	// Structurally similar + content differs → potential IDOR
	confidence := severity.Tentative
	if comparison.UserFieldsDiffer {
		confidence = severity.Firm
	}

	desc := fmt.Sprintf(
		"Parameter %s=%s was changed to %s and returned a structurally similar response "+
			"(status=%d, body ratio=%.2f) with different content, suggesting missing authorization.",
		ip.Name(), ip.BaseValue(), neighborID,
		probeStatus, comparison.BodyLengthRatio,
	)
	if len(comparison.DifferingFields) > 0 {
		desc += fmt.Sprintf(" User-specific fields differ: %s.", strings.Join(comparison.DifferingFields, ", "))
	}

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              urlStr,
		Matched:          urlStr,
		Request:          probeRequest,
		Response:         probeResponse,
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{
			fmt.Sprintf("%s=%s → %s", ip.Name(), ip.BaseValue(), neighborID),
		},
		Info: output.Info{
			Name:        "IDOR / Broken Object Level Authorization",
			Description: desc,
			Severity:    severity.High,
			Confidence:  confidence,
			Tags:        []string{"idor", "bola", "access-control", "api-security"},
			Reference: []string{
				"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
				"https://cwe.mitre.org/data/definitions/639.html",
			},
		},
		Metadata: map[string]any{
			"param_name":         ip.Name(),
			"original_value":     ip.BaseValue(),
			"neighbor_value":     neighborID,
			"id_type":            classification.IDType.String(),
			"predictability":     classification.Predictability.String(),
			"name_signal":        classification.NameSignal.String(),
			"total_score":        classification.TotalScore,
			"resource_noun":      classification.ResourceNoun,
			"baseline_status":    baseline.StatusCode,
			"probe_status":       probeStatus,
			"body_length_ratio":  comparison.BodyLengthRatio,
			"content_identical":  comparison.ContentIdentical,
			"user_fields_differ": comparison.UserFieldsDiffer,
			"differing_fields":   comparison.DifferingFields,
		},
	}, nil
}
