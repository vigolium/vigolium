// XSS Scanner — reflected XSS detection module.
package xss_scanner

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/core"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/samber/lo"
	"go.uber.org/zap"
)

type Module struct {
	modkit.BaseActiveModule
	rhm            dedup.Lazy[dedup.RequestHashManager]
	moreParams     []string
	paramDiscovery *ParameterDiscovery
	pathInjection  *PathInjectionGenerator
}

// findInsertionPointByName finds an insertion point by parameter name
func findInsertionPointByName(points []httpmsg.InsertionPoint, name string) httpmsg.InsertionPoint {
	for _, ip := range points {
		if ip.Name() == name {
			return ip
		}
	}
	return nil
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
		rhm:            dedup.LazyDefaultRHM("xss_scanner"),
		paramDiscovery: NewParameterDiscovery(),
		pathInjection:  &PathInjectionGenerator{},
	}
	m.ModuleTags = ModuleTags
	return m
}

// createResultCallback creates a callback function that handles XSS findings
func (m *Module) createResultCallback(
	results *[]*output.ResultEvent,
	foundXSS *bool,
) func(core.ReflectionContext, core.PotentialXSSFinding) {
	return func(reflectionContext core.ReflectionContext, result core.PotentialXSSFinding) {
		// Handle ChainedXSSFinding
		if chainedFinding, ok := result.(*core.ChainedXSSFinding); ok {
			contentType := chainedFinding.GetContentType()
			if !strings.Contains(contentType, "html") && !strings.Contains(contentType, "xml") {
				return
			}

			// Map severity to output severity
			sev := severity.Info
			switch chainedFinding.MaxSeverityReached {
			case core.FindingSeverityHigh:
				sev = severity.High
			case core.FindingSeverityMedium:
				sev = severity.Medium
			case core.FindingSeverityLow:
				sev = severity.Low
			}

			*results = append(*results, &output.ResultEvent{
				URL:              chainedFinding.URL,
				Request:          string(chainedFinding.GetRequestRaw()),
				Response:         string(chainedFinding.GetResponseBody()),
				FuzzingParameter: chainedFinding.Parameter,
				Info: output.Info{
					Description: chainedFinding.GetEvidenceSummary(),
					Severity:    sev,
				},
			})
			*foundXSS = true
			return
		}

		// Handle single XSSScanFinding
		finding, ok := result.(*core.XSSScanFinding)
		if !ok {
			return
		}

		contentType := finding.GetContentType()
		if !strings.Contains(contentType, "html") && !strings.Contains(contentType, "xml") {
			return
		}

		description := finding.EvidenceSummary
		if finding.Severity() > 0 {
			description = fmt.Sprintf("[%s] %s", core.SeverityLabel(finding.Severity()), description)
			if finding.TechniqueName() != "" {
				description += fmt.Sprintf("\nTechnique: %s", finding.TechniqueName())
			}
		}

		// Map severity to output severity
		sev := severity.Info
		switch finding.Severity() {
		case core.FindingSeverityHigh:
			sev = severity.High
		case core.FindingSeverityMedium:
			sev = severity.Medium
		case core.FindingSeverityLow:
			sev = severity.Low
		}

		*results = append(*results, &output.ResultEvent{
			URL:              finding.URL,
			Request:          string(finding.GetRequestRaw()),
			Response:         string(finding.GetResponseBody()),
			FuzzingParameter: finding.InjectionPoint.Name(),
			ExtractedResults: []string{finding.InjectionPoint.BaseValue()},
			Info: output.Info{
				Description: description,
				Severity:    sev,
			},
		})
		*foundXSS = true
	}
}

// scanParameter performs XSS scanning on a single insertion point
func (m *Module) scanParameter(
	ip httpmsg.InsertionPoint,
	callback func(core.ReflectionContext, core.PotentialXSSFinding),
	httpService *httpmsg.Service,
	httpClient *protohttp.Requester,
) {
	scanner := core.NewXSSScanningCoordinator(
		ip,
		core.NewNoOpPayloadModifier(),
		callback,
		httpService,
		httpClient,
	)
	scanner.PerformXSSChecks()
}

// scanURLParameters scans all URL parameters in the request
func (m *Module) scanURLParameters(
	urlx *urlutil.URL,
	requestInfo *httpmsg.RequestInfo,
	insertionPoints []httpmsg.InsertionPoint,
	httpService *httpmsg.Service,
	httpClient *protohttp.Requester,
	foundXSS *bool,
	callback func(core.ReflectionContext, core.PotentialXSSFinding),
	scanCtx *modkit.ScanContext,
) {
	urlParams := requestInfo.ParametersByType(httpmsg.ParamURL)
	rhm := m.rhm.Get(scanCtx.DedupMgr())

	for _, param := range urlParams {
		if *foundXSS {
			return
		}

		if m.shouldSkipParameter(param.Name()) {
			continue
		}

		if rhm != nil && !rhm.ShouldCheck3(
			urlx,
			"GET",
			"",
			param.Name(),
			param.Value(),
			"",
		) {
			continue
		}

		ip := findInsertionPointByName(insertionPoints, param.Name())
		if ip != nil {
			m.scanParameter(ip, callback, httpService, httpClient)
		}
	}
}

// scanConvertedRequest converts POST to GET and scans the converted parameters
func (m *Module) scanConvertedRequest(
	ctx *httpmsg.HttpRequestResponse,
	requestInfo *httpmsg.RequestInfo,
	httpService *httpmsg.Service,
	httpClient *protohttp.Requester,
	foundXSS *bool,
	callback func(core.ReflectionContext, core.PotentialXSSFinding),
	scanCtx *modkit.ScanContext,
) {
	// Only convert non-GET requests
	if requestInfo.Method == "GET" {
		return
	}

	swappedRequestBytes, err := httpmsg.ToggleRequestMethod(ctx.Request().Raw())
	if err != nil {
		return
	}

	swappedRequestInfo, err := httpmsg.AnalyzeRequest(swappedRequestBytes)
	if err != nil {
		return
	}

	// Get URL parameters from swapped request
	swappedURLParams := swappedRequestInfo.ParametersByType(httpmsg.ParamURL)
	originalURLParams := requestInfo.ParametersByType(httpmsg.ParamURL)

	// Only proceed if swapped request has more URL parameters
	if len(swappedURLParams) == 0 || len(swappedURLParams) == len(originalURLParams) {
		return
	}

	swappedURLx, err := urlutil.Parse(swappedRequestInfo.URL)
	if err != nil {
		return
	}

	// Create insertion points for the swapped request
	swappedInsertionPoints, err := httpmsg.CreateAllInsertionPoints(swappedRequestBytes, true)
	if err != nil {
		return
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	// Scan each parameter in the swapped request
	for _, param := range swappedURLParams {
		if *foundXSS {
			return
		}

		if m.shouldSkipParameter(param.Name()) {
			continue
		}

		if rhm != nil && !rhm.ShouldCheck3(
			swappedURLx,
			"GET",
			"",
			param.Name(),
			param.Value(),
			"",
		) {
			continue
		}

		ip := findInsertionPointByName(swappedInsertionPoints, param.Name())
		if ip != nil {
			m.scanParameter(ip, callback, httpService, httpClient)
		}
	}
}

// scanDiscoveredParameters discovers and scans additional parameters from the moreParams list
func (m *Module) scanDiscoveredParameters(
	ctx *httpmsg.HttpRequestResponse,
	urlx *urlutil.URL,
	requestInfo *httpmsg.RequestInfo,
	httpService *httpmsg.Service,
	httpClient *protohttp.Requester,
	foundXSS *bool,
	callback func(core.ReflectionContext, core.PotentialXSSFinding),
) {
	// Prepare raw request (convert to GET if needed)
	var rawRequest []byte
	var err error
	if requestInfo.Method != "GET" {
		rawRequest, err = httpmsg.ToggleRequestMethod(ctx.Request().Raw())
		if err != nil {
			rawRequest = ctx.Request().Raw()
		}
	} else {
		rawRequest = ctx.Request().Raw()
	}

	// Get current URL parameters
	moreParamsRequestInfo, err := httpmsg.AnalyzeRequest(rawRequest)
	if err != nil {
		return
	}

	currentQueryParams := moreParamsRequestInfo.ParametersByType(httpmsg.ParamURL)
	var currentQueryParamsStr []string
	if len(currentQueryParams) > 0 {
		currentQueryParamsStr = lo.Map(
			currentQueryParams,
			func(item *httpmsg.Param, _ int) string {
				return item.Name()
			},
		)
	}

	// Use ParameterDiscovery to find and scan echo parameters
	err = m.paramDiscovery.DiscoverAndScanParameters(
		urlx,
		rawRequest,
		m.moreParams,
		currentQueryParamsStr,
		httpService,
		httpClient,
		func(ip httpmsg.InsertionPoint) {
			if *foundXSS {
				return
			}
			m.scanParameter(ip, callback, httpService, httpClient)
		},
	)
	if err != nil {
		zap.L().Debug("parameter discovery failed", zap.Error(err))
	}
}

// scanPathRecursive scans path segments using the recursive injection strategy.
// This leverages httpmsg.ParsePathParameters() which already extracts each segment
// as a separate parameter (e.g., /api/v1/users → 3 parameters).
// Each path segment becomes an insertion point for XSS testing.
func (m *Module) scanPathRecursive(
	urlx *urlutil.URL,
	rawRequest []byte,
	httpService *httpmsg.Service,
	httpClient *protohttp.Requester,
	foundXSS *bool,
	callback func(core.ReflectionContext, core.PotentialXSSFinding),
	scanCtx *modkit.ScanContext,
) {
	// Parse path parameters (e.g., /api/v1/users → [api, v1, users])
	pathParams, err := httpmsg.ParsePathParameters(rawRequest)
	if err != nil || len(pathParams) == 0 {
		return
	}

	// Create insertion points for path parameters
	insertionPoints, err := httpmsg.CreateAllInsertionPoints(rawRequest, true)
	if err != nil {
		return
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	// Scan each path segment individually
	for _, param := range pathParams {
		if *foundXSS {
			return
		}

		if rhm != nil && !rhm.ShouldCheck3(
			urlx,
			"GET",
			"",
			param.Name(),
			param.Value(),
			"",
		) {
			continue
		}

		// Find insertion point for this path parameter
		ip := findInsertionPointByName(insertionPoints, param.Name())
		if ip != nil {
			m.scanParameter(ip, callback, httpService, httpClient)
		}
	}
}

// scanPathCut scans path using the cut injection strategy.
// This progressively cuts path segments from the end and tests each variant.
// Example: /api/v1/users → [/api/v1/PLACEHOLDER, /api/PLACEHOLDER, /PLACEHOLDER]
func (m *Module) scanPathCut(
	urlx *urlutil.URL,
	rawRequest []byte,
	httpService *httpmsg.Service,
	httpClient *protohttp.Requester,
	foundXSS *bool,
	callback func(core.ReflectionContext, core.PotentialXSSFinding),
	scanCtx *modkit.ScanContext,
) {
	// Generate cut path variants (e.g., /api/v1/PLACEHOLDER, /api/PLACEHOLDER, /PLACEHOLDER)
	variants, err := m.pathInjection.GenerateCutPathVariants(rawRequest)
	if err != nil || len(variants) == 0 {
		return
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	// For each variant, parse path parameters and scan
	for _, variant := range variants {
		if *foundXSS {
			return
		}

		// Parse path parameters from the variant
		pathParams, err := httpmsg.ParsePathParameters(variant)
		if err != nil || len(pathParams) == 0 {
			continue
		}

		// Create insertion points for this variant
		insertionPoints, err := httpmsg.CreateAllInsertionPoints(variant, true)
		if err != nil {
			continue
		}

		// The PLACEHOLDER will become a path parameter, scan it
		for _, param := range pathParams {
			if *foundXSS {
				return
			}

			// Only test the PLACEHOLDER parameter
			if param.Value() != "PLACEHOLDER" {
				continue
			}

			if rhm != nil && !rhm.ShouldCheck3(
				urlx,
				"GET",
				"",
				param.Name(),
				param.Value(),
				"",
			) {
				continue
			}

			ip := findInsertionPointByName(insertionPoints, param.Name())
			if ip != nil {
				m.scanParameter(ip, callback, httpService, httpClient)
			}
		}
	}
}

// scanPathAppend scans path by appending a fake 404 path segment.
// This tests error page reflection behavior.
// Example: /api/v1/users → /api/v1/users/thisdoesnotexisted404
func (m *Module) scanPathAppend(
	urlx *urlutil.URL,
	rawRequest []byte,
	httpService *httpmsg.Service,
	httpClient *protohttp.Requester,
	foundXSS *bool,
	callback func(core.ReflectionContext, core.PotentialXSSFinding),
	scanCtx *modkit.ScanContext,
) {
	// Generate variant with appended fake 404 path
	variant, err := m.pathInjection.GenerateAppendPathVariant(rawRequest)
	if err != nil {
		return
	}

	// Parse path parameters from the variant
	pathParams, err := httpmsg.ParsePathParameters(variant)
	if err != nil || len(pathParams) == 0 {
		return
	}

	// Create insertion points for this variant
	insertionPoints, err := httpmsg.CreateAllInsertionPoints(variant, true)
	if err != nil {
		return
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	// Find and scan the appended fake 404 segment
	for _, param := range pathParams {
		if *foundXSS {
			return
		}

		// Only test the fake 404 parameter
		if param.Value() != "thisdoesnotexisted404" {
			continue
		}

		if rhm != nil && !rhm.ShouldCheck3(
			urlx,
			"GET",
			"",
			param.Name(),
			param.Value(),
			"",
		) {
			continue
		}

		ip := findInsertionPointByName(insertionPoints, param.Name())
		if ip != nil {
			m.scanParameter(ip, callback, httpService, httpClient)
		}
	}
}

// shouldSkipParameter checks if the parameter name should be skipped
func (m *Module) shouldSkipParameter(paramName string) bool {
	skipParams := map[string]bool{
		"__eventargument":   true,
		"__eventtarget":     true,
		"__eventvalidation": true,
		"__viewstate":       true,
	}
	return skipParams[strings.ToLower(paramName)]
}

// ScanPerRequest runs the XSS scanner for a single request.
// This module manages its own insertion points internally.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *protohttp.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	// Validate URL
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return []*output.ResultEvent{}, nil
	}

	// Extract HttpService for request execution
	httpService := ctx.Service()
	if httpService == nil {
		return nil, errors.New("httpService is nil in request")
	}

	// Analyze request and create insertion points
	rawRequest := ctx.Request().Raw()
	requestInfo, err := httpmsg.AnalyzeRequest(rawRequest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to analyze request")
	}

	insertionPoints, err := httpmsg.CreateAllInsertionPoints(rawRequest, true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create insertion points")
	}

	// Setup result collection
	var results []*output.ResultEvent
	foundXSS := false
	callback := m.createResultCallback(&results, &foundXSS)

	// Phase 1: Scan converted POST→GET parameters (if applicable)
	m.scanConvertedRequest(ctx, requestInfo, httpService, httpClient, &foundXSS, callback, scanCtx)
	if foundXSS {
		return results, nil
	}

	// Phase 2: Scan existing URL parameters (for GET requests)
	if requestInfo.Method == "GET" {
		m.scanURLParameters(urlx, requestInfo, insertionPoints, httpService, httpClient, &foundXSS, callback, scanCtx)
		if foundXSS {
			return results, nil
		}
	}

	// Phase 2b: Scan path segments using recursive injection
	// Tests each segment individually: /p1/INJECT/p3, /INJECT/p2/p3, etc.
	m.scanPathRecursive(urlx, rawRequest, httpService, httpClient, &foundXSS, callback, scanCtx)
	if foundXSS {
		return results, nil
	}

	// Phase 2c: Scan path using cut injection strategy
	// Progressively cuts from end: /p1/p2/INJECT, /p1/INJECT, /INJECT
	m.scanPathCut(urlx, rawRequest, httpService, httpClient, &foundXSS, callback, scanCtx)
	if foundXSS {
		return results, nil
	}

	// Phase 2d: Scan path using append injection strategy
	// Appends fake 404 path: /p1/p2 → /p1/p2/thisdoesnotexisted404
	m.scanPathAppend(urlx, rawRequest, httpService, httpClient, &foundXSS, callback, scanCtx)
	if foundXSS {
		return results, nil
	}

	// Phase 3: Discover and scan additional parameters
	if len(m.moreParams) > 0 {
		m.scanDiscoveredParameters(ctx, urlx, requestInfo, httpService, httpClient, &foundXSS, callback)
	}

	return results, nil
}
