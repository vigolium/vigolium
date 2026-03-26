package core

import (
	"net/http"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/formparser"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// It now acts as a builder for AnalysisResult objects.
type HTTPAnalysisResultBuilder struct {
	// Fields to build AnalysisResult

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
func newHTTPAnalysisResultBuilder() *HTTPAnalysisResultBuilder {
	return &HTTPAnalysisResultBuilder{}
}

func NewAnalysisResultBuilder() *HTTPAnalysisResultBuilder {
	return newHTTPAnalysisResultBuilder()
}

// --- Setters ---

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

func (b *HTTPAnalysisResultBuilder) WithResponseBodyLength(
	length int,
) *HTTPAnalysisResultBuilder { // Used for BodyLength
	b.responseBodyLength = length
	return b
}

func (b *HTTPAnalysisResultBuilder) WithParsedHTMLElements(
	aheList []*htmlparser.HTMLElement,
) *HTTPAnalysisResultBuilder {
	b.parsedHTMLElements = aheList
	return b
}

func (b *HTTPAnalysisResultBuilder) WithResponseBodyStartOffset(
	bodyOffset int,
) *HTTPAnalysisResultBuilder {
	b.responseBodyStartOffset = bodyOffset
	return b
}

func (b *HTTPAnalysisResultBuilder) WithResponseStatusCode(
	statusCode int16,
) *HTTPAnalysisResultBuilder {
	b.responseStatusCode = statusCode
	return b
}

func (b *HTTPAnalysisResultBuilder) WithResponseCookies(
	cookies []SimplifiedCookieData,
) *HTTPAnalysisResultBuilder {
	b.responseCookies = cookies
	return b
}

func (b *HTTPAnalysisResultBuilder) WithContentTypeProfile(
	defVal *ContentTypeProfile,
) *HTTPAnalysisResultBuilder {
	b.contentTypeProfile = defVal
	return b
}

func (b *HTTPAnalysisResultBuilder) WithParsedForms(
	forms []*formparser.FormInfo,
) *HTTPAnalysisResultBuilder {
	b.parsedForms = forms
	return b
}

// Build builds the HTTPAnalysisReport object.
func (b *HTTPAnalysisResultBuilder) Build() *HTTPAnalysisReport {
	var reqMethod, reqURL, reqProto string
	reqMethod = b.requestMethod
	reqURL = b.requestURL
	reqProto = b.requestProtocol

	return &HTTPAnalysisReport{
		RequestMethod:         reqMethod,
		RequestURL:            reqURL,
		RequestProto:          reqProto,
		ResponseStatusCode:    int(b.responseStatusCode),
		ResponseStatusMessage: b.responseStatusText,
		ResponseProto:         b.responseProtocol,
		ResponseHeaders:       b.responseHeaders,
		ResponseCookies:       b.responseCookies,
		ResponseBodyLength:    b.responseBodyLength,
		ContentTypeInfo:       b.contentTypeProfile,
		ParsedHtmlElements:    b.parsedHTMLElements,
		ParsedForms:           b.parsedForms,
	}
}
