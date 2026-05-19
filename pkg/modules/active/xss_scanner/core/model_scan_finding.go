package core

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	localUtils "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

type XSSScanFinding struct {
	URL                string
	InjectionPoint     httpmsg.InsertionPoint
	EffectivePayload   string
	ReflectionTactic   ReflectionTacticType
	ReflectionLocation ReflectionLocation
	EvidenceSummary    string
	// AnalysisResult          *AnalysisResult // from engine_types.go
	ReflectionPointInfo *ReflectionPointCoreInfo // from reflection_point_base.go
	scanFlags           int                      // Flags
	variantCode         byte                     // Variant

	// Copied data from the HTTP transaction for callback access after cleanup.
	RequestRaw         []byte // Raw request bytes
	ResponseBody       []byte
	ResponseHeaders    http.Header
	ResponseStatusCode int
	ContentType        string

	// NEW: Chain reporting support
	severity          int    // FindingSeverityLow/Medium/High (from model_scan_finding_chain.go)
	techniqueName     string // "Character Injection", "Tag Breakout", "Event Handler", etc
	injectionEvidence string // What was successfully injected (e.g., "\"", "</title>", "-->")
	chainPosition     int    // Position in chain (0 = standalone/not part of chain)
}

// IsPotentialXSSFinding is a marker method for the Bgf interface.
func (kb *XSSScanFinding) IsPotentialXSSFinding() {}

// ScanFlags returns the flags.
func (kb *XSSScanFinding) ScanFlags() int {
	return kb.scanFlags
}

// VariantCode returns the variant byte.
func (kb *XSSScanFinding) VariantCode() byte {
	return kb.variantCode
}

// GetResponseBody returns the copied response body, safe to use after cleanup
func (kb *XSSScanFinding) GetResponseBody() []byte {
	return kb.ResponseBody
}

// GetResponseHeaders returns the copied response headers, safe to use after cleanup
func (kb *XSSScanFinding) GetResponseHeaders() http.Header {
	return kb.ResponseHeaders
}

// GetResponseStatusCode returns the copied response status code, safe to use after cleanup
func (kb *XSSScanFinding) GetResponseStatusCode() int {
	return kb.ResponseStatusCode
}

// GetRequestRaw returns the copied raw request bytes, safe to use after cleanup
func (kb *XSSScanFinding) GetRequestRaw() []byte {
	return kb.RequestRaw
}

// GetContentType returns the copied content type, safe to use after cleanup
func (kb *XSSScanFinding) GetContentType() string {
	return kb.ContentType
}

// Severity returns the severity level of this finding
func (kb *XSSScanFinding) Severity() int {
	return kb.severity
}

// SetSeverity sets the severity level
func (kb *XSSScanFinding) SetSeverity(severity int) {
	kb.severity = severity
}

// TechniqueName returns the technique name
func (kb *XSSScanFinding) TechniqueName() string {
	return kb.techniqueName
}

// SetTechniqueName sets the technique name
func (kb *XSSScanFinding) SetTechniqueName(name string) {
	kb.techniqueName = name
}

// InjectionEvidence returns the injection evidence
func (kb *XSSScanFinding) InjectionEvidence() string {
	return kb.injectionEvidence
}

// SetInjectionEvidence sets the injection evidence
func (kb *XSSScanFinding) SetInjectionEvidence(evidence string) {
	kb.injectionEvidence = evidence
}

// ChainPosition returns the position in chain
func (kb *XSSScanFinding) ChainPosition() int {
	return kb.chainPosition
}

// SetChainPosition sets the position in chain
func (kb *XSSScanFinding) SetChainPosition(position int) {
	kb.chainPosition = position
}

func BuildXSSScanFinding(
	injectionPoint httpmsg.InsertionPoint,
	effectivePayloadBytes []byte,
	tactic ReflectionTacticType,
	currentScanFlags int,
	reflectionInfo *ReflectionPointCoreInfo,
	transaction *localUtils.HTTPTransaction,
) *XSSScanFinding {
	// Copy data from transaction before it gets closed
	var requestCopy *http.Request
	var requestRaw []byte
	var responseBody []byte
	var responseHeaders http.Header
	var responseStatusCode int
	var contentType string

	if transaction != nil {
		// Copy request
		if transaction.GetRequest() != nil {
			requestCopy = transaction.GetRequest().Clone(transaction.GetRequest().Context())

			// Extract raw request bytes
			if rawBytes, err := httputil.DumpRequestOut(requestCopy, true); err == nil {
				requestRaw = make([]byte, len(rawBytes))
				copy(requestRaw, rawBytes)
			}
		}

		// Copy response data
		responseBody = make([]byte, len(transaction.GetResponseBody()))
		copy(responseBody, transaction.GetResponseBody())

		// Copy headers
		responseHeaders = make(http.Header)
		for k, v := range transaction.GetResponseHeaders() {
			responseHeaders[k] = make([]string, len(v))
			copy(responseHeaders[k], v)
		}

		responseStatusCode = transaction.GetResponseStatusCode()
		contentType = transaction.GetResponseHeaders().Get("Content-Type")
	}

	// Recalculate offsets based on the full canary (payloadUsedInErwLogic) in the actualBody
	if len(reflectionInfo.canaryBytes) > 0 {
		actualReflectionStartIndex := bytes.Index(
			responseBody, // Use copied response body
			reflectionInfo.canaryBytes,
		)
		if actualReflectionStartIndex != -1 {
			actualReflectionEndIndex := actualReflectionStartIndex + len(reflectionInfo.canaryBytes)

			reflectionInfo.startIndexInInput = actualReflectionStartIndex
			reflectionInfo.endIndexInInput = actualReflectionEndIndex
		}
	}

	evidenceDetails := "Reflection observed."
	if reflectionInfo.canaryBytes != nil {
		evidenceDetails = fmt.Sprintf(
			"Reflected: %s | Context: %s | Location: %s | Content-Type: %s | Status: %d",
			string(reflectionInfo.canaryBytes),
			reflectionInfo.contextType.String(),
			reflectionInfo.location.String(),
			contentType,
			responseStatusCode,
		)

	}

	var url string
	if requestCopy != nil && requestCopy.URL != nil {
		url = requestCopy.URL.String()
	}

	finding := &XSSScanFinding{
		URL:                 url,
		InjectionPoint:      injectionPoint,
		EffectivePayload:    string(effectivePayloadBytes),
		ReflectionTactic:    tactic,
		ReflectionLocation:  reflectionInfo.location,
		EvidenceSummary:     evidenceDetails,
		ReflectionPointInfo: reflectionInfo,
		RequestRaw:          requestRaw,
		ResponseBody:        responseBody,
		ResponseHeaders:     responseHeaders,
		ResponseStatusCode:  responseStatusCode,
		ContentType:         contentType,
		// Chain reporting fields - will be set by strategies
		severity:          0,                                  // FindingSeverityUnknown - strategies should set this
		techniqueName:     "",                                 // Will be set by strategies
		injectionEvidence: string(reflectionInfo.canaryBytes), // Default to canary
		chainPosition:     0,                                  // 0 = standalone/root
	}
	if finding.ReflectionPointInfo != nil {
		zap.L().Debug("BuildFinding: ReflectionPointInfo after recalculation",
			zap.Int("ContextIndicator", int(finding.ReflectionPointInfo.location)),
			zap.Int("ReflectionType", int(finding.ReflectionPointInfo.contextType)),
			zap.Int("ReflectionStartInInput", finding.ReflectionPointInfo.startIndexInInput),
			zap.Int("ReflectionEndInInput", finding.ReflectionPointInfo.endIndexInInput),
			zap.String("Canary", string(finding.ReflectionPointInfo.canaryBytes)))
	} else {
		zap.L().Debug("BuildFinding: ReflectionPointInfo after recalculation: nil")
	}
	return finding
}
