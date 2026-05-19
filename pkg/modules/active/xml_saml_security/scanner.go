package xml_saml_security

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/anomaly"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

const (
	confirmCount = 2
)

// targetParams - only scan these parameter names (case-insensitive)
var targetParams = []string{"samlrequest", "samlresponse"}

// comparisonAttributes - attribute types for response fingerprinting
// (excluding body content to reduce false positives from dynamic content)
var comparisonAttributes = []anomaly.Type{
	anomaly.STATUS_CODE,
	anomaly.CONTENT_TYPE,
	anomaly.CONTENT_LENGTH,
	anomaly.LINE_COUNT,
	anomaly.WORD_COUNT,
	anomaly.LOCATION,
	anomaly.PAGE_TITLE,
}

// checkConfig holds configuration for each security check
type checkConfig struct {
	name        string
	checkFunc   func(*XMLDocument, *DecodedSAML) (string, error)
	description string
	reference   string
}

// Module implements XML SAML security scanning.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new XML SAML Security scanner module.
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
			modkit.URLParamTypes|modkit.BodyParamTypes, // SAML params only in URL query or POST body
		),
		rhm: dedup.LazyDefaultRHM("xml_saml_security"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint performs scanning for a specific insertion point.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	// Filter: Only process SAMLRequest/SAMLResponse params
	paramName := strings.ToLower(ip.Name())
	if !isSAMLParam(paramName) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Deduplication check
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Step 1: Decode and parse XML from SAML value
	baseValue := ip.BaseValue()
	decoded, err := DecodeSAML(baseValue)
	if err != nil {
		zap.L().Debug("XMLSAMLSecurity: Failed to decode SAML",
			zap.String("param", ip.Name()),
			zap.Error(err))
		return nil, nil
	}

	// Step 2: Parse XML document
	doc, err := ParseXML(decoded.XMLContent)
	if err != nil {
		zap.L().Debug("XMLSAMLSecurity: Failed to parse XML",
			zap.String("param", ip.Name()),
			zap.Error(err))
		return nil, nil
	}

	// Skip if document already has DOCTYPE (don't inject into existing DTD)
	if doc.HasDoctype {
		zap.L().Debug("XMLSAMLSecurity: Document already has DOCTYPE, skipping",
			zap.String("param", ip.Name()))
		return nil, nil
	}

	// Step 3: Send baseline request (empty param value) and get fingerprint
	baselineResp, err := m.sendRequest(ctx, ip, httpClient, "")
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		return nil, nil
	}
	baselineFingerprint := createFingerprint(baselineResp)
	baselineResp.Close()

	// Step 4: Get original response fingerprint
	var originalFingerprint *anomaly.Fingerprint
	if ctx.HasResponse() {
		originalFingerprint = createFingerprintFromCtx(ctx.Response())
	} else {
		origResp, _, err := httpClient.Execute(ctx, http.Options{})
		if err != nil {
			return nil, nil
		}
		originalFingerprint = createFingerprint(origResp)
		origResp.Close()
	}

	// Step 5: Check if fingerprints are valid
	if baselineFingerprint == nil || originalFingerprint == nil {
		zap.L().Debug("XMLSAMLSecurity: Invalid fingerprint, skipping",
			zap.String("param", ip.Name()))
		return nil, nil
	}

	// Check if baseline differs from original (needed for detection)
	// If they're similar, we can't distinguish attack from normal behavior
	if baselineFingerprint.IsSimilar(originalFingerprint) {
		zap.L().Debug("XMLSAMLSecurity: Baseline matches original, skipping",
			zap.String("param", ip.Name()))
		return nil, nil
	}

	// Step 6: Run security checks
	checks := []checkConfig{
		{
			name:        "DOCTYPE",
			checkFunc:   InjectDOCTYPE,
			description: "DOCTYPE injection detected - potential XXE vulnerability",
			reference:   "https://portswigger.net/research/saml-roulette-the-hacker-always-wins",
		},
		{
			name:        "ENTITY",
			checkFunc:   InjectENTITY,
			description: "ENTITY injection detected - potential XXE vulnerability",
			reference:   "https://portswigger.net/research/saml-roulette-the-hacker-always-wins",
		},
	}

	var results []*output.ResultEvent

	for _, check := range checks {
		result := m.runCheck(ctx, ip, httpClient, doc, decoded, originalFingerprint, urlx.String(), check)
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// runCheck executes a single security check with confirmation.
func (m *Module) runCheck(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	doc *XMLDocument,
	decoded *DecodedSAML,
	originalFingerprint *anomaly.Fingerprint,
	urlStr string,
	check checkConfig,
) *output.ResultEvent {
	// Generate payload
	payload, err := check.checkFunc(doc, decoded)
	if err != nil {
		zap.L().Debug("XMLSAMLSecurity: Check payload generation failed",
			zap.String("check", check.name),
			zap.Error(err))
		return nil
	}

	zap.L().Debug("XMLSAMLSecurity: Trying check",
		zap.String("check", check.name),
		zap.String("param", ip.Name()))

	// Require confirmCount successful confirmations
	confirmed := 0
	var lastAttackReq []byte
	var lastAttackRespBody string
	var lastAttackRespFull string

	for attempt := 0; attempt < confirmCount && confirmed < confirmCount; attempt++ {
		attackResp, attackReq, err := m.sendRequestWithPayload(ctx, ip, httpClient, payload)
		if err != nil {
			break
		}

		attackFingerprint := createFingerprint(attackResp)
		attackRespBody := attackResp.Body().String()
		attackRespFull := attackResp.FullResponse().String()
		attackResp.Close()

		// Skip if fingerprint is nil
		if attackFingerprint == nil {
			continue
		}

		// Attack matches original (not baseline) = vulnerability indicator
		if attackFingerprint.IsSimilar(originalFingerprint) {
			confirmed++
			lastAttackReq = attackReq
			lastAttackRespBody = attackRespBody
			lastAttackRespFull = attackRespFull
		}
	}

	if confirmed >= confirmCount {
		return &output.ResultEvent{
			URL:              urlStr,
			Request:          string(lastAttackReq),
			Response:         lastAttackRespFull,
			FuzzingParameter: ip.Name(),
			Info: output.Info{
				Description: check.description,
				Reference:   []string{check.reference},
			},
			Metadata: map[string]interface{}{
				"check_type":      check.name,
				"confirmations":   confirmed,
				"original_value":  ip.BaseValue(),
				"response_sample": truncateString(lastAttackRespBody, 500),
			},
		}
	}

	return nil
}

// sendRequest sends a request with the given payload value.
func (m *Module) sendRequest(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payload string,
) (*httpUtils.ResponseChain, error) {
	modifiedRaw := ip.BuildRequest([]byte(payload))
	modifiedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, err
	}
	modifiedReq = modifiedReq.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(modifiedReq, http.Options{})
	return resp, err
}

// sendRequestWithPayload sends a request and returns both response and raw request.
func (m *Module) sendRequestWithPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payload string,
) (*httpUtils.ResponseChain, []byte, error) {
	modifiedRaw := ip.BuildRequest([]byte(payload))
	modifiedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, nil, err
	}
	modifiedReq = modifiedReq.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(modifiedReq, http.Options{})
	return resp, modifiedRaw, err
}

// isSAMLParam checks if the parameter name is a SAML parameter.
func isSAMLParam(name string) bool {
	name = strings.ToLower(name)
	for _, target := range targetParams {
		if name == target {
			return true
		}
	}
	return false
}

// createFingerprint creates a anomaly.Fingerprint from ResponseChain.
func createFingerprint(respChain *httpUtils.ResponseChain) *anomaly.Fingerprint {
	if respChain == nil || !respChain.Has() {
		return nil
	}
	resp := respChain.Response()
	return anomaly.NewFingerprint2(
		resp.StatusCode,
		respChain.Body().String(),
		resp.Header,
		comparisonAttributes,
	)
}

// createFingerprintFromCtx creates a anomaly.Fingerprint from HttpResponse.
func createFingerprintFromCtx(resp *httpmsg.HttpResponse) *anomaly.Fingerprint {
	headers := make(map[string][]string)
	for _, h := range resp.Headers() {
		headers[h.Name] = append(headers[h.Name], h.Value)
	}
	return anomaly.NewFingerprint2(
		resp.StatusCode(),
		resp.BodyToString(),
		headers,
		comparisonAttributes,
	)
}

// truncateString truncates a string to maxLen characters.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
