package core

import (
	"net/http"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/formparser"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// HTTPAnalysisResultBuilder corresponds to the Java class burp.i2x.
// It now acts as a builder for AnalysisResult objects.
// In Java, i2x methods mostly return `this` for chaining. In Go, we return *HTTPAnalysisResultBuilder.
type HTTPAnalysisResultBuilder struct {
	// Fields to build AnalysisResult (previously Hkk)
	// Based on AnalysisResult fields in dn_types.go

	// From HTTP Response/Request directly
	requestMethod string
	requestURL    string

	requestProtocol    string
	responseProtocol   string      // For resp.Proto
	responseStatusText string      // For resp.Status (e.g. "200 OK")
	responseStatusCode int16       // Already exists, for resp.StatusCode
	responseHeaders    http.Header // Directly store http.Header (map[string][]string)
	responseCookies    []SimplifiedCookieData
	responseBodyLength int

	// Analysis products
	contentTypeProfile *ContentTypeProfile
	parsedHTMLElements []*htmlparser.HTMLElement
	parsedForms        []*formparser.FormInfo

	responseBodyStartOffset int
}

// newHTTPAnalysisResultBuilder is the private constructor.
// Corresponds to private i2x()
func newHTTPAnalysisResultBuilder() *HTTPAnalysisResultBuilder {
	return &HTTPAnalysisResultBuilder{}
}

// NewAnalysisResultBuilder is a public constructor based on Java's static i2x.b().
// Corresponds to public static i2x b()
func NewAnalysisResultBuilder() *HTTPAnalysisResultBuilder {
	return newHTTPAnalysisResultBuilder()
}

// NewI2xBuilderFromHkk is removed as HKK is being replaced by AnalysisResult.
// If loading from a saved HKK-like structure is needed, a new constructor can be added.

// --- Setters for I2xBuilder, adapted for AnalysisResult fields ---

func (b *HTTPAnalysisResultBuilder) WithRequestLine(
	method, uri, proto string,
) *HTTPAnalysisResultBuilder {
	b.requestMethod = method
	b.requestURL = uri
	b.requestProtocol = proto
	return b
}

func (b *HTTPAnalysisResultBuilder) WithResponseStatus(
	proto, status string,
) *HTTPAnalysisResultBuilder {
	b.responseProtocol = proto
	b.responseStatusText = status // This is the full status string e.g., "200 OK"
	return b
}

func (b *HTTPAnalysisResultBuilder) WithResponseHeaders(
	headers http.Header,
) *HTTPAnalysisResultBuilder {
	b.responseHeaders = headers
	return b
}

// WithResponseBodyLength corresponds to public i2x c(int var1)
func (b *HTTPAnalysisResultBuilder) WithResponseBodyLength(
	length int,
) *HTTPAnalysisResultBuilder { // Used for BodyLength
	b.responseBodyLength = length
	return b
}

// B_setAlternativeCanaryOffsets was for HKK.h. Not directly in AnalysisResult.
// func (b *I2xBuilder) B_setAlternativeCanaryOffsets(altCanaries []int) *I2xBuilder {
// 	return b
// }

// WithParsedHTMLElements corresponds to public i2x e(List<ahe> var1)
func (b *HTTPAnalysisResultBuilder) WithParsedHTMLElements(
	aheList []*htmlparser.HTMLElement,
) *HTTPAnalysisResultBuilder { // Changed to []*HTMLElement
	b.parsedHTMLElements = aheList
	return b
}

// WithResponseBodyStartOffset corresponds to public i2x b(int var1)
func (b *HTTPAnalysisResultBuilder) WithResponseBodyStartOffset(
	bodyOffset int,
) *HTTPAnalysisResultBuilder { // For valBodyStartOffset (original hkk.g)
	b.responseBodyStartOffset = bodyOffset
	return b
}

// WithResponseStatusCode corresponds to public i2x a(short var1)
func (b *HTTPAnalysisResultBuilder) WithResponseStatusCode(
	statusCode int16,
) *HTTPAnalysisResultBuilder {
	b.responseStatusCode = statusCode
	return b
}

// A_setStatusMessage corresponds to public i2x a(String var1)
// func (b *I2xBuilder) A_setStatusMessage(statusMessage string) *I2xBuilder {
// 	b.valStatusMessage = statusMessage
// 	return b
// }

// WithResponseCookies corresponds to public i2x a(List<adq> var1)
func (b *HTTPAnalysisResultBuilder) WithResponseCookies(
	cookies []SimplifiedCookieData,
) *HTTPAnalysisResultBuilder {
	b.responseCookies = cookies
	return b
}

// WithContentTypeProfile corresponds to public i2x a(def var1)
func (b *HTTPAnalysisResultBuilder) WithContentTypeProfile(
	defVal *ContentTypeProfile,
) *HTTPAnalysisResultBuilder { // For ContentTypeInfo
	b.contentTypeProfile = defVal
	return b
}

// D_setH6pList corresponds to public i2x d(List<h6p> var1)
// func (b *I2xBuilder) D_setH6pList(h6pList []H6p) *I2xBuilder {
// 	b.valJsAnalysisResults = h6pList
// 	return b
// }

func (b *HTTPAnalysisResultBuilder) WithParsedForms(
	forms []*formparser.FormInfo,
) *HTTPAnalysisResultBuilder {
	b.parsedForms = forms
	return b
}

// Build builds the AnalysisResult object.
// Renamed from A_buildHkk
func (b *HTTPAnalysisResultBuilder) Build() *HTTPAnalysisReport {
	// Headers are now directly from http.Header, no need to parse from valProcessedHeadersList
	// Request/Status line info is also directly from specific fields

	var reqMethod, reqURL, reqProto string // these should be populated from builder fields
	reqMethod = b.requestMethod
	reqURL = b.requestURL
	reqProto = b.requestProtocol

	return &HTTPAnalysisReport{
		RequestMethod:         reqMethod,
		RequestURL:            reqURL,
		RequestProto:          reqProto,
		ResponseStatusCode:    int(b.responseStatusCode),
		ResponseStatusMessage: b.responseStatusText, // Use the full status string from response
		ResponseProto:         b.responseProtocol,   // Use proto from response
		ResponseHeaders:       b.responseHeaders,    // Directly use the stored http.Header
		ResponseCookies:       b.responseCookies,
		ResponseBodyLength:    b.responseBodyLength,
		ContentTypeInfo:       b.contentTypeProfile,
		ParsedHtmlElements:    b.parsedHTMLElements,
		ParsedForms:           b.parsedForms,
		// ProcessedHeadersList is removed from AnalysisResult, or if kept, b.valProcessedHeadersList (now removed from builder) would be its source.
	}
}
