package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"

// GetHtmlParserInternalMode corresponds to Java: static _9 h2.b(h2 var0)
func GetHtmlParserInternalMode(mode HTMLParseMode) htmlparser.ParseMode {
	// Logic from h2.java: private final _9 a;
	// private h2(_9 var3, boolean var4) { this.a = var3; ... }
	// This implies H2Type needs to store its corresponding ParseMode.
	// For now, this is a simplified stub.
	switch mode {
	case HTMLParseMode_HTML_HEAD_ANALYSIS:
		return htmlparser.ParseModeHead
	case HTMLParseMode_HTML_ANALYSIS:
		return htmlparser.ParseModeFull
	case HTMLParseMode_HTML_AND_VIEWSTATE_ANALYSIS:
		return htmlparser.ParseModeFull
	case HTMLParseMode_NO_HTML_ANALYSIS:
		return htmlparser.ParseModeNone
	default:
		return htmlparser.ParseModeNone // Or handle error
	}
}

type HTMLParseMode int

// const H2_NO_HTML_ANALYSIS H2Type = 0

// Add new H2Type constants if they are not in stubs.go or defined elsewhere
// These should match the enum constants in h2.java
const (
	HTMLParseMode_NO_HTML_ANALYSIS            HTMLParseMode = 0 // NO_HTML_ANALYSIS(_9.NONE, false)
	HTMLParseMode_HTML_HEAD_ANALYSIS          HTMLParseMode = 1 // HTML_HEAD_ANALYSIS(_9.HEAD, false)
	HTMLParseMode_HTML_ANALYSIS               HTMLParseMode = 2 // HTML_ANALYSIS(_9.FULL, false)
	HTMLParseMode_HTML_AND_VIEWSTATE_ANALYSIS HTMLParseMode = 3 // HTML_AND_VIEWSTATE_ANALYSIS(_9.FULL, true)
)
