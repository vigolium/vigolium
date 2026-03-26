package core

import (
	// For http.Cookie

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/formparser"
	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// SimplifiedCookieData is a simplified representation of a cookie,
// derived from http.Cookie.
type SimplifiedCookieData struct {
	Name  string
	Value string
}

// HTTPAnalysisReport holds analysis results from an *http.Response.
type HTTPAnalysisReport struct {
	// From HTTP Response/Request directly
	RequestMethod         string
	RequestURL            string
	RequestProto          string
	ResponseStatusCode    int
	ResponseStatusMessage string                 // e.g., "200 OK"
	ResponseProto         string                 // e.g., "HTTP/1.1"
	ResponseHeaders       map[string][]string    // Store all headers
	ResponseCookies       []SimplifiedCookieData // Changed to use struct directly
	ResponseBodyLength    int

	// Analysis products
	ContentTypeInfo    *ContentTypeProfile       // Result of content type analysis
	ParsedHtmlElements []*htmlparser.HTMLElement
	ParsedForms        []*formparser.FormInfo
}

