package xss_light_scanner

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"go.uber.org/zap"
)

// URLParamsModule implements XSS scanning for URL parameters.
// It tests existing URL parameters and performs POST→GET conversion.
type URLParamsModule struct {
	modkit.BaseActiveModule
	rhm               dedup.Lazy[dedup.RequestHashManager]
	transformAnalyzer *TransformAnalyzer
	jsAnalyzer        *JavaScriptContextAnalyzer

	// Probe runs the headless-browser confirmation step. Overridable so tests
	// never spawn a real browser. Default: spitolas.ProbeURL.
	Probe ProbeFunc
}

// NewURLParamsScanner creates a new URL parameters XSS scanner.
func NewURLParamsScanner() *URLParamsModule {
	m := &URLParamsModule{
		BaseActiveModule: modkit.NewBaseActiveModule(
			URLParamsModuleID,
			URLParamsModuleName,
			URLParamsModuleDesc,
			URLParamsModuleShort,
			URLParamsModuleConfirmation,
			URLParamsModuleSeverity,
			URLParamsModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm:               dedup.LazyDefaultRHM("xss_light_url_params"),
		transformAnalyzer: NewTransformAnalyzer(),
		jsAnalyzer:        NewJavaScriptContextAnalyzer(),
		Probe:             spitolas.ProbeURL,
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest runs the URL parameters XSS scanner for a single request.
func (m *URLParamsModule) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	foundXSS := false

	// 1. Scan converted POST→GET parameters (if non-GET request)
	convertedResults, err := m.scanConvertedRequest(ctx, httpClient, &foundXSS, scanCtx)
	if err != nil && !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		zap.L().Debug("converted request scan error", zap.Error(err))
	}
	results = append(results, convertedResults...)
	if foundXSS {
		return results, nil
	}

	// 2. Scan existing URL parameters
	urlResults, err := m.scanURLParameters(ctx, httpClient, &foundXSS, scanCtx)
	if err != nil && !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		zap.L().Debug("url params scan error", zap.Error(err))
	}
	results = append(results, urlResults...)

	return results, nil
}

// scanConvertedRequest converts POST to GET and scans the converted parameters.
func (m *URLParamsModule) scanConvertedRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	foundXSS *bool,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Check if already GET
	method, err := httpmsg.GetMethod(ctx.Request().Raw())
	if err != nil {
		return nil, err
	}

	if strings.EqualFold(method, "GET") {
		// Already GET, nothing to convert
		return nil, nil
	}

	// Convert to GET
	getRequest, err := httpmsg.ToggleRequestMethod(ctx.Request().Raw())
	if err != nil {
		return nil, err
	}

	// Create insertion points for the converted request
	points, err := httpmsg.CreateAllInsertionPoints(getRequest, true)
	if err != nil {
		return nil, err
	}

	// Filter to only URL parameters
	urlPoints := filterURLParamPoints(points)
	if len(urlPoints) == 0 {
		return nil, nil
	}

	// Apply deduplication
	urlx, _ := ctx.URL()
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		// Create a temporary request info for dedup
		parsedReq, err := httpmsg.ParseRawRequest(string(getRequest))
		if err == nil {
			urlPoints = rhm.GetNotCheckedInsertionPoints(urlx, parsedReq.Request(), urlPoints)
		}
	}

	if len(urlPoints) == 0 {
		return nil, nil
	}

	// Get base response for the converted request
	parsedReq, err := httpmsg.ParseRawRequest(string(getRequest))
	if err != nil {
		return nil, err
	}
	parsedReq = parsedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(parsedReq, http.Options{})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	defer resp.Close()

	baseBody := resp.Body().String()

	// Scan each URL parameter
	for _, ip := range urlPoints {
		result, err := m.scanInsertionPointWithPrefixes(parsedReq, ip, baseBody, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if result != nil && result.HasVulnerability() {
			if evt := confirmXSS(m.Probe, parsedReq, ip, result, httpClient, "[POST→GET] ", nil); evt != nil {
				*foundXSS = true
				results = append(results, evt)
			}
		}
	}

	return results, nil
}

// scanURLParameters scans existing URL parameters in the request.
func (m *URLParamsModule) scanURLParameters(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	foundXSS *bool,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, err
	}

	// Create insertion points
	points, err := httpmsg.CreateAllInsertionPoints(ctx.Request().Raw(), true)
	if err != nil {
		return nil, err
	}

	// Filter to only URL parameters
	urlPoints := filterURLParamPoints(points)
	if len(urlPoints) == 0 {
		return nil, nil
	}

	// Apply deduplication
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		urlPoints = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), urlPoints)
	}

	if len(urlPoints) == 0 {
		return nil, nil
	}

	// Get base body
	baseBody := ""
	if ctx.Response() != nil && len(ctx.Response().Raw()) > 0 {
		baseBody = ctx.Response().BodyToString()
	}

	// Scan each URL parameter
	for _, ip := range urlPoints {
		result, err := m.scanInsertionPointWithPrefixes(ctx, ip, baseBody, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if result != nil && result.HasVulnerability() {
			if evt := confirmXSS(m.Probe, ctx, ip, result, httpClient, "", nil); evt != nil {
				*foundXSS = true
				results = append(results, evt)
			}
		}
	}

	return results, nil
}

// filterURLParamPoints filters insertion points to only URL parameters.
func filterURLParamPoints(points []httpmsg.InsertionPoint) []httpmsg.InsertionPoint {
	filtered := make([]httpmsg.InsertionPoint, 0, len(points))
	for _, ip := range points {
		switch ip.Type() {
		case httpmsg.INS_PARAM_URL, httpmsg.INS_PARAM_NAME_URL:
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

// scanInsertionPointWithPrefixes tries all bypass prefixes sequentially
func (m *URLParamsModule) scanInsertionPointWithPrefixes(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	baseBody string,
	httpClient *http.Requester,
) (*XSSScanResult, error) {
	// Passive check - if base value doesn't reflect, skip entirely
	if !performPassiveCheck(baseBody, ip) {
		return NewXSSScanResult(), nil
	}

	// Try each bypass prefix sequentially
	for _, prefix := range BypassPrefixes {
		result, err := m.scanWithPrefix(ctx, ip, httpClient, prefix)
		if err != nil {
			return nil, err
		}

		// If we found exploitable points, return immediately
		if result != nil && result.HasVulnerability() {
			result.UsedPrefix = prefix.Name
			return result, nil
		}
	}

	// No exploitable points found with any prefix
	return NewXSSScanResult(), nil
}

// scanWithPrefix runs Phase 1 and Phase 2 for a specific prefix
func (m *URLParamsModule) scanWithPrefix(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	prefix BypassPrefix,
) (*XSSScanResult, error) {
	result := NewXSSScanResult()
	result.InsertionPoint = ip.Name()

	// ========== PHASE 1: Primary Payload ==========
	primaryPayload := GeneratePrimaryWithPrefix(prefix)
	result.PrimaryPayload = primaryPayload

	primaryBody, err := sendAndValidatePayload(ctx, ip, primaryPayload, httpClient)
	if err != nil {
		return nil, err
	}
	if primaryBody == nil {
		return result, nil
	}

	result.PrimaryResponse = primaryBody

	// Find all reflections and analyze transforms
	phase1Analyses := m.analyzePhase1(primaryBody, primaryPayload)
	if len(phase1Analyses) == 0 {
		return result, nil
	}

	// Check if any reflection is already exploitable
	for _, ea := range phase1Analyses {
		if ea.IsExploitable() {
			result.ExploitableAnalyses = append(result.ExploitableAnalyses, ea)
		}
	}

	// Early return if exploitable found
	if len(result.ExploitableAnalyses) > 0 {
		return result, nil
	}

	// ========== PHASE 2: Batched Secondary Payload ==========
	nextTests := CollectNextTests(phase1Analyses)
	if !HasAnyTests(nextTests) {
		return result, nil
	}

	// Build batched payload with all needed test sequences
	sequences := GetUniqueSequences(nextTests)
	secondaryPayload := BuildBatchedSecondaryWithPrefix(sequences, prefix)
	if secondaryPayload == nil {
		return result, nil
	}

	result.SecondaryPayload = secondaryPayload

	secondaryBody, err := sendAndValidatePayload(ctx, ip, secondaryPayload, httpClient)
	if err != nil {
		return nil, err
	}
	if secondaryBody == nil {
		return result, nil
	}

	result.SecondaryResponse = secondaryBody

	// Analyze Phase 2 transforms for each test sequence
	phase2Transforms := m.transformAnalyzer.AnalyzeSequenceTransforms(
		secondaryBody,
		secondaryPayload,
		sequences,
	)

	// Check each test to see if it succeeded
	for _, test := range nextTests {
		transform := phase2Transforms[test.TestSequence]
		if transform != nil && transform.Transform == test.SuccessCheck {
			for _, ea := range phase1Analyses {
				if ea.Context == test.Context {
					ea.SetTransform(test.TestSequence, transform)
					if ea.IsExploitable() {
						result.ExploitableAnalyses = append(result.ExploitableAnalyses, ea)
					}
					break
				}
			}
		}
	}

	return result, nil
}

// analyzePhase1 analyzes primary payload reflections
func (m *URLParamsModule) analyzePhase1(responseBody []byte, payload *CanaryPayload) []*EscapeAnalysis {
	var analyses []*EscapeAnalysis

	matches := FindCanaryMatches(responseBody, payload)
	if len(matches) == 0 {
		return analyses
	}

	elements := ParseHTML(responseBody)

	for _, match := range matches {
		containingElement := FindElementAtOffset(elements, match.StartOffset)
		ctx := m.detectContext(elements, containingElement, responseBody, match.StartOffset)
		matchedBytes := match.MatchedBytes

		analysis := m.transformAnalyzer.AnalyzeTransforms(matchedBytes, payload, ctx, match.StartOffset)

		if isURLAttributeContext(ctx) && containingElement != nil {
			attr := containingElement.FindAttributeAtOffset(match.StartOffset)
			if attr != nil {
				analysis.IsAtURLStart = (match.StartOffset == attr.ValueStart)
			}
		}

		analyses = append(analyses, analysis)
	}

	return analyses
}

// detectContext determines the reflection context
func (m *URLParamsModule) detectContext(
	_ []*HtmlElement,
	element *HtmlElement,
	responseBody []byte,
	offset int,
) ReflectionContext {
	if element == nil {
		return HTMLGeneric
	}

	switch element.Type {
	case ElementOpenTag, ElementSelfClosing:
		if element.IsInTagName(offset) {
			return HTMLTagCloseAndInject
		}

		attr := element.FindAttributeAtOffset(offset)
		if attr != nil {
			if attr.ContainsNameOffset(offset) {
				return HTMLAttributeName
			}
			return classifyAttributeContext(element.TagName, attr)
		}
		return HTMLGeneric

	case ElementComment:
		return HTMLCommentBreakout

	case ElementText:
		parentTag := strings.ToLower(element.ParentTag)
		if parentTag == "script" || element.InScript {
			return m.jsAnalyzer.AnalyzeJavaScriptContext(
				responseBody,
				element.StartOffset,
				element.EndOffset,
				offset,
			)
		}
		switch parentTag {
		case "xmp":
			return HTMLAfterXMPClose
		case "noscript":
			return HTMLAfterNoscriptClose
		case "title":
			return HTMLAfterTitleClose
		}
		return HTMLGeneric

	default:
		return HTMLGeneric
	}
}

