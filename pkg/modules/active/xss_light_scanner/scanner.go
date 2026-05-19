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
)

// Module implements the XSS Light Scanner module
type Module struct {
	modkit.BaseActiveModule
	rhm               dedup.Lazy[dedup.RequestHashManager]
	transformAnalyzer *TransformAnalyzer
	jsAnalyzer        *JavaScriptContextAnalyzer
}

// New creates a new XSS Light Scanner module
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
		rhm:               dedup.LazyDefaultRHM("xss_light"),
		transformAnalyzer: NewTransformAnalyzer(),
		jsAnalyzer:        NewJavaScriptContextAnalyzer(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest runs the XSS Light Scanner for a single request.
func (m *Module) ScanPerRequest(
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

	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	points = filterXSSRelevantPoints(points)

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

	baseBody := ""
	if ctx.Response() != nil && len(ctx.Response().Raw()) > 0 {
		baseBody = ctx.Response().BodyToString()
	}

	for _, ip := range points {
		result, err := m.scanInsertionPointWithPrefixes(ctx, ip, baseBody, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if result != nil && result.HasVulnerability() {
			results = append(results, m.buildResultEvent(ctx, ip, result))
		}
	}

	return results, nil
}

// scanInsertionPointWithPrefixes tries all bypass prefixes sequentially
// For each prefix: Phase 1 → Phase 2 → if exploitable: done, else: next prefix
func (m *Module) scanInsertionPointWithPrefixes(
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
func (m *Module) scanWithPrefix(
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
			// Found exploitable via double-escape!
			// Update the corresponding Phase 1 analysis
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
func (m *Module) analyzePhase1(responseBody []byte, payload *CanaryPayload) []*EscapeAnalysis {
	var analyses []*EscapeAnalysis

	// Find all reflection points
	matches := FindCanaryMatches(responseBody, payload)
	if len(matches) == 0 {
		return analyses
	}

	// Parse HTML for context detection
	elements := ParseHTML(responseBody)

	for _, match := range matches {
		// Detect context
		containingElement := FindElementAtOffset(elements, match.StartOffset)
		ctx := m.detectContext(elements, containingElement, responseBody, match.StartOffset)

		// Use matchedBytes from canary matcher (already correctly extracted)
		// This is critical for transformed modes where offset mapping was applied
		matchedBytes := match.MatchedBytes

		// Analyze transforms
		analysis := m.transformAnalyzer.AnalyzeTransforms(matchedBytes, payload, ctx, match.StartOffset)

		// For URL attributes, check if reflection is at the start of the value
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

// isURLAttributeContext returns true if context is a URL attribute
func isURLAttributeContext(ctx ReflectionContext) bool {
	switch ctx {
	case JSInURLAttributeDQ, JSInURLAttributeSQ, JSInURLAttributeBT, JSInUnquotedURLAttribute:
		return true
	}
	return false
}

// detectContext determines the reflection context
func (m *Module) detectContext(
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
		// Check if in tag name
		if element.IsInTagName(offset) {
			return HTMLTagCloseAndInject
		}

		// Check if in attribute
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

// buildResultEvent creates a ResultEvent from scan result
func (m *Module) buildResultEvent(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	result *XSSScanResult,
) *output.ResultEvent {
	urlx, _ := ctx.URL()

	// Build evidence from exploitable analyses
	var evidenceParts []string
	for _, ea := range result.ExploitableAnalyses {
		evidenceParts = append(evidenceParts, ea.Context.String())
	}
	description := strings.Join(evidenceParts, " | ")

	if result.UsedPrefix != "" && result.UsedPrefix != "none" {
		description += " [bypass: " + result.UsedPrefix + "]"
	}

	return &output.ResultEvent{
		URL:              urlx.String(),
		Request:          string(ip.BuildRequest([]byte(result.PrimaryPayload.FullPayload))),
		Response:         string(result.PrimaryResponse),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{ip.BaseValue()},
		Info: output.Info{
			Description: description,
		},
	}
}

// filterXSSRelevantPoints removes insertion points not relevant for XSS detection.
func filterXSSRelevantPoints(points []httpmsg.InsertionPoint) []httpmsg.InsertionPoint {
	filtered := make([]httpmsg.InsertionPoint, 0, len(points))
	for _, ip := range points {
		switch ip.Type() {
		case httpmsg.INS_PARAM_COOKIE, httpmsg.INS_HEADER:
			continue
		default:
			filtered = append(filtered, ip)
		}
	}
	return filtered
}
