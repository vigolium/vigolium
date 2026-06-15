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

// PathModule implements XSS scanning for URL path segments.
// It tests path manipulation strategies: recursive, cut, and append.
type PathModule struct {
	modkit.BaseActiveModule
	rhm               dedup.Lazy[dedup.RequestHashManager]
	transformAnalyzer *TransformAnalyzer
	jsAnalyzer        *JavaScriptContextAnalyzer
	pathInjection     *PathInjectionGenerator

	// Probe runs the headless-browser confirmation step. Overridable so tests
	// never spawn a real browser. Default: spitolas.ProbeURL.
	Probe ProbeFunc
}

// NewPathScanner creates a new path injection XSS scanner.
func NewPathScanner() *PathModule {
	m := &PathModule{
		BaseActiveModule: modkit.NewBaseActiveModule(
			PathModuleID,
			PathModuleName,
			PathModuleDesc,
			PathModuleShort,
			PathModuleConfirmation,
			PathModuleSeverity,
			PathModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm:               dedup.LazyDefaultRHM("xss_light_path"),
		transformAnalyzer: NewTransformAnalyzer(),
		jsAnalyzer:        NewJavaScriptContextAnalyzer(),
		pathInjection:     &PathInjectionGenerator{},
		Probe:             spitolas.ProbeURL,
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest runs the path injection XSS scanner for a single request.
func (m *PathModule) ScanPerRequest(
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

	// 1. Scan path segments recursively
	recursiveResults, err := m.scanPathRecursive(ctx, httpClient, &foundXSS, scanCtx)
	if err != nil && !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		zap.L().Debug("path recursive scan error", zap.Error(err))
	}
	results = append(results, recursiveResults...)
	if foundXSS {
		return results, nil
	}

	// 2. Scan with cut strategy
	cutResults, err := m.scanPathCut(ctx, httpClient, &foundXSS, scanCtx)
	if err != nil && !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		zap.L().Debug("path cut scan error", zap.Error(err))
	}
	results = append(results, cutResults...)
	if foundXSS {
		return results, nil
	}

	// 3. Scan with append strategy
	appendResults, err := m.scanPathAppend(ctx, httpClient, &foundXSS, scanCtx)
	if err != nil && !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		zap.L().Debug("path append scan error", zap.Error(err))
	}
	results = append(results, appendResults...)

	return results, nil
}

// scanPathRecursive scans each path segment individually.
func (m *PathModule) scanPathRecursive(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	foundXSS *bool,
	_ *modkit.ScanContext, // scanCtx not used for path dedup yet
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Generate insertion points for each path segment
	points, err := m.pathInjection.GenerateRecursivePathPoints(ctx.Request().Raw())
	if err != nil {
		return nil, err
	}

	if len(points) == 0 {
		return nil, nil
	}

	// Get base body
	baseBody := ""
	if ctx.Response() != nil && len(ctx.Response().Raw()) > 0 {
		baseBody = ctx.Response().BodyToString()
	}

	// Scan each path segment
	for _, ip := range points {
		result, err := m.scanInsertionPointWithPrefixes(ctx, ip, baseBody, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if result != nil && result.HasVulnerability() {
			if evt := confirmXSS(m.Probe, ctx, ip, result, httpClient, "[path:recursive] ", nil); evt != nil {
				*foundXSS = true
				results = append(results, evt)
			}
		}
	}

	return results, nil
}

// scanPathCut scans progressively cut paths.
func (m *PathModule) scanPathCut(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	foundXSS *bool,
	_ *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Generate cut path insertion points
	points, err := m.pathInjection.GenerateCutPathPoints(ctx.Request().Raw())
	if err != nil {
		return nil, err
	}

	if len(points) == 0 {
		return nil, nil
	}

	// For cut paths, we need to send a probe request first to get base response
	for _, ip := range points {
		// Send probe to get base response for this cut path
		probePayload := &CanaryPayload{FullPayload: "test", Canary: "test"}
		probeBody, err := sendAndValidatePayload(ctx, ip, probePayload, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		baseBody := string(probeBody)

		// Now scan
		result, err := m.scanInsertionPointWithPrefixes(ctx, ip, baseBody, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if result != nil && result.HasVulnerability() {
			if evt := confirmXSS(m.Probe, ctx, ip, result, httpClient, "[path:cut] ", nil); evt != nil {
				*foundXSS = true
				results = append(results, evt)
			}
		}
	}

	return results, nil
}

// scanPathAppend scans with appended fake 404 segment.
func (m *PathModule) scanPathAppend(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	foundXSS *bool,
	_ *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Generate append path insertion point
	ip, err := m.pathInjection.GenerateAppendPathPoint(ctx.Request().Raw())
	if err != nil {
		return nil, err
	}

	if ip == nil {
		return nil, nil
	}

	// Send probe to get base response for append path
	probePayload := &CanaryPayload{FullPayload: "nonexistent404", Canary: "nonexistent404"}
	probeBody, err := sendAndValidatePayload(ctx, ip, probePayload, httpClient)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return results, nil
		}
		return nil, nil
	}

	baseBody := string(probeBody)

	// Scan
	result, err := m.scanInsertionPointWithPrefixes(ctx, ip, baseBody, httpClient)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return results, nil
		}
		return nil, nil
	}

	if result != nil && result.HasVulnerability() {
		if evt := confirmXSS(m.Probe, ctx, ip, result, httpClient, "[path:append] ", nil); evt != nil {
			*foundXSS = true
			results = append(results, evt)
		}
	}

	return results, nil
}

// scanInsertionPointWithPrefixes tries all bypass prefixes sequentially
func (m *PathModule) scanInsertionPointWithPrefixes(
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
func (m *PathModule) scanWithPrefix(
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
func (m *PathModule) analyzePhase1(responseBody []byte, payload *CanaryPayload) []*EscapeAnalysis {
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
func (m *PathModule) detectContext(
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

