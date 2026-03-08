package core

import (
	"errors"
	"net/http"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/formparser"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
	"go.uber.org/zap"
)

// AnalyzeHTTPTransaction is the new main entry point for analyzing an HTTP response (and optionally request).
func AnalyzeHTTPTransaction(
	transaction *utils.HTTPTransaction,
	parseMode HTMLParseMode,
	shouldStopProcessing func() bool,
) (*HTTPAnalysisReport, error) {
	if transaction == nil || !transaction.IsHasResponse() {
		return nil, errors.New("utils.HTTPTransaction cannot be nil or have no response")
	}

	httpResponse := transaction.GetResponse()
	if httpResponse == nil {
		return nil, errors.New("underlying http.Response in HTTPTransaction is nil")
	}

	responseBodyBytes := transaction.GetResponseBody()
	if responseBodyBytes == nil {
		responseBodyBytes = []byte{}
		zap.L().Debug("[WARN AnalyzeHttpResponse] Received nil or empty body from HTTPTransaction")
	}

	reportBuilder := NewAnalysisResultBuilder()

	// 1. Set basic info from response/request
	reportBuilder.WithResponseBodyLength(len(responseBodyBytes))
	reportBuilder.WithResponseStatusCode(int16(httpResponse.StatusCode))
	// Set response status details (proto and full status string)
	reportBuilder.WithResponseStatus(httpResponse.Proto, httpResponse.Status)

	// Set request line details if request is available
	if transaction.GetRequest() != nil {
		reportBuilder.WithRequestLine(
			transaction.GetRequest().Method,
			transaction.GetRequest().URL.RequestURI(),
			transaction.GetRequest().Proto,
		)
	}

	// Set headers directly from http.Header
	reportBuilder.WithResponseHeaders(httpResponse.Header)

	// 2. Content Type (Def)
	contentTypeInfo := NewContentTypeProfile(httpResponse.Header, responseBodyBytes)
	reportBuilder.WithContentTypeProfile(contentTypeInfo)

	// i2xBuilder.B_setBodyStartOffset(0)
	htmlParserMode := GetHtmlParserInternalMode(parseMode)

	if contentTypeInfo != nil && htmlParserMode != htmlparser.ParseModeNone &&
		(contentTypeInfo.GetStatedTypeCode() == DefTypeHTML || contentTypeInfo.GetInferredTypeCode() == DefTypeHTML) {
		performHTMLAnalysisInternal(
			parseMode,
			reportBuilder,
			transaction.GetRequest(),
			responseBodyBytes,
			0, /*bodyOffset*/
			contentTypeInfo,
			shouldStopProcessing,
		)
	}

	// 4. Cookies
	var simplifiedCookies []SimplifiedCookieData
	for _, cookie := range httpResponse.Cookies() {
		simpleCookie := SimplifiedCookieData{
			Name:  cookie.Name,
			Value: cookie.Value,
		}
		simplifiedCookies = append(simplifiedCookies, simpleCookie)
	}
	reportBuilder.WithResponseCookies(simplifiedCookies)

	// 5. Build AnalysisResult
	analysisReport := reportBuilder.Build()

	return analysisReport, nil
}

// Corresponds to private static void a(h2 var0, i2x var1, hik var2, bi9 var3, c5e var4, int var5, def var6, Supplier<Boolean> var7)
// Refactored: var2Hik and var4C5e replaced/removed. bodyBytes instead of Bi9.
func performHTMLAnalysisInternal(
	parseMode HTMLParseMode,
	reportBuilder *HTTPAnalysisResultBuilder,
	httpRequest *http.Request,
	htmlBodyBytes []byte,
	bodyStartOffset int,
	initialContentType *ContentTypeProfile,
	shouldStop func() bool,
) {
	internalParserMode := GetHtmlParserInternalMode(parseMode)
	parsedElements := parseHTMLElementsForAnalysis(
		bodyStartOffset,
		htmlBodyBytes,
		internalParserMode,
		shouldStop,
	)

	var httpRequestHeaders http.Header
	if httpRequest != nil {
		httpRequestHeaders = httpRequest.Header
	} else {
		httpRequestHeaders = http.Header{}
	}
	refinedContentType := RefineContentTypeWithHTMLMeta(
		initialContentType,
		parsedElements,
		httpRequestHeaders,
		htmlBodyBytes,
		shouldStop,
	)

	// List var10 = cu1.a(var2, var8, var4, var7);
	extractedForms := formparser.ExtractFormsInfo(
		httpRequest,
		parsedElements,
		htmlBodyBytes,
		shouldStop,
	)

	reportBuilder.WithParsedHTMLElements(parsedElements)
	reportBuilder.WithContentTypeProfile(refinedContentType)
	reportBuilder.WithParsedForms(extractedForms) // Use SetForms for []FormInfo
}

// Corresponds to private static List<ahe> a(int var0, bi9 var1, _9 var2)
// Refactored to accept data []byte instead of Bi9 and return []*HTMLElement
func parseHTMLElementsForAnalysis(
	startOffset int,
	htmlData []byte,
	internalMode htmlparser.ParseMode,
	shouldStop func() bool,
) []*htmlparser.HTMLElement { // Return type changed
	if htmlData == nil {
		return []*htmlparser.HTMLElement{}
	}

	limit := len(htmlData)
	contentType := byte(0)

	htmlElements, err := htmlparser.ParseHTMLElements(
		htmlData,
		startOffset,
		limit,
		contentType,
		internalMode,
		shouldStop,
	)
	if err != nil {
		return []*htmlparser.HTMLElement{}
	}

	return htmlElements
}
