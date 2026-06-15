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

// ParamDiscoveryModule implements XSS scanning by discovering hidden echo parameters.
type ParamDiscoveryModule struct {
	modkit.BaseActiveModule
	rhm               dedup.Lazy[dedup.RequestHashManager]
	transformAnalyzer *TransformAnalyzer
	jsAnalyzer        *JavaScriptContextAnalyzer
	paramDiscovery    *ParameterDiscovery

	// Probe runs the headless-browser confirmation step. Overridable so tests
	// never spawn a real browser. Default: spitolas.ProbeURL.
	Probe ProbeFunc
}

// NewParamDiscoveryScanner creates a new parameter discovery XSS scanner.
func NewParamDiscoveryScanner() *ParamDiscoveryModule {
	m := &ParamDiscoveryModule{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ParamDiscoveryModuleID,
			ParamDiscoveryModuleName,
			ParamDiscoveryModuleDesc,
			ParamDiscoveryModuleShort,
			ParamDiscoveryModuleConfirmation,
			ParamDiscoveryModuleSeverity,
			ParamDiscoveryModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm:               dedup.LazyDefaultRHM("xss_light_param_discovery"),
		transformAnalyzer: NewTransformAnalyzer(),
		jsAnalyzer:        NewJavaScriptContextAnalyzer(),
		paramDiscovery:    NewParameterDiscovery(),
		Probe:             spitolas.ProbeURL,
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest runs the parameter discovery XSS scanner for a single request.
func (m *ParamDiscoveryModule) ScanPerRequest(
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

	// Discover and scan hidden parameters
	discoveryResults, err := m.scanDiscoveredParameters(ctx, httpClient, &foundXSS, scanCtx)
	if err != nil && !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		zap.L().Debug("param discovery scan error", zap.Error(err))
	}
	results = append(results, discoveryResults...)

	return results, nil
}

// scanDiscoveredParameters discovers echo params and tests them for XSS.
func (m *ParamDiscoveryModule) scanDiscoveredParameters(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	foundXSS *bool,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Convert to GET if needed for parameter discovery
	workingRequest := ctx.Request().Raw()
	method, err := httpmsg.GetMethod(workingRequest)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(method, "GET") {
		// Convert POST to GET for parameter discovery
		getRequest, err := httpmsg.ToggleRequestMethod(workingRequest)
		if err != nil {
			return nil, err
		}
		workingRequest = getRequest
	}

	// Create context for discovery
	parsedReq, err := httpmsg.ParseRawRequest(string(workingRequest))
	if err != nil {
		return nil, err
	}
	parsedReq = parsedReq.WithService(ctx.Service())

	// Discover parameters that echo in response
	points, modifiedRequest, err := m.paramDiscovery.DiscoverAndCreatePoints(parsedReq, httpClient)
	if err != nil {
		return nil, err
	}

	if len(points) == 0 {
		return nil, nil
	}

	// Apply deduplication
	urlx, _ := ctx.URL()
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		modifiedParsed, err := httpmsg.ParseRawRequest(string(modifiedRequest))
		if err == nil {
			points = rhm.GetNotCheckedInsertionPoints(urlx, modifiedParsed.Request(), points)
		}
	}

	if len(points) == 0 {
		return nil, nil
	}

	// Create new context with modified request
	modifiedParsed, err := httpmsg.ParseRawRequest(string(modifiedRequest))
	if err != nil {
		return nil, err
	}
	modifiedParsed = modifiedParsed.WithService(ctx.Service())

	// Get base response for the modified request
	resp, _, err := httpClient.Execute(modifiedParsed, http.Options{})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	defer resp.Close()

	baseBody := resp.Body().String()

	// Scan each discovered parameter
	for _, ip := range points {
		result, err := m.scanInsertionPointWithPrefixes(modifiedParsed, ip, baseBody, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if result != nil && result.HasVulnerability() {
			// Re-send a real, context-shaped XSS payload and grade the candidate:
			// drop it when the executable breakout never survives in the body,
			// report Low when it survives but no popup fires, and only report
			// High once a headless browser actually pops alert(marker).
			evt := confirmXSS(m.Probe, modifiedParsed, ip, result, httpClient, "[discovered:"+ip.Name()+"] ", nil)
			if evt == nil {
				continue
			}
			*foundXSS = true
			results = append(results, evt)
		}
	}

	return results, nil
}

// scanInsertionPointWithPrefixes tries all bypass prefixes sequentially
func (m *ParamDiscoveryModule) scanInsertionPointWithPrefixes(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	_ string, // baseBody not used - discovered params are known to echo
	httpClient *http.Requester,
) (*XSSScanResult, error) {
	// For discovered params, skip passive check since we already know they echo

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
func (m *ParamDiscoveryModule) scanWithPrefix(
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
func (m *ParamDiscoveryModule) analyzePhase1(responseBody []byte, payload *CanaryPayload) []*EscapeAnalysis {
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
func (m *ParamDiscoveryModule) detectContext(
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


