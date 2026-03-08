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

// HTTPAnalysisReport is the refactored version of Hkk,
// designed to hold analysis results from an *http.Response.
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
	ContentTypeInfo    *ContentTypeProfile       // Result of content type analysis (simplified Def)
	ParsedHtmlElements []*htmlparser.HTMLElement // Changed from []Ahe
	ParsedForms        []*formparser.FormInfo    // Thay thế JsAnalysisResults nếu H6p chỉ dùng cho form
	// GqsInfo            *Gqs    // Removed as per new requirement

	// ProcessedHeadersList []string // Removed as I2xBuilder now uses specific fields and http.Header

	// Original HKK fields that might still be relevant or need mapping:
	// D_ValInt        int      // Could be BodyLength or a specific offset. For now, BodyLength is separate.
	// L_ValListString []string // This is now Headers map, but original was List of "Name: Value". Retain for i2x if needed or adapt i2x.
	// H_ValListInt    []int    // Original alternative canary offsets. May not be relevant with http.Response.
	// G_ValInt        int      // Original body offset. With []byte body, this is usually 0.
	// A_ValShort      int16    // StatusCode is now int.
	// F_ValString     string   // StatusMessage is now separate.
}

// --- Adq Interface Implementation for SimplifiedAdqCookie IS REMOVED ---
