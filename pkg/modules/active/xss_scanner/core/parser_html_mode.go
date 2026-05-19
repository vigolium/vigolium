package core

import "github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"

func GetHtmlParserInternalMode(mode HTMLParseMode) htmlparser.ParseMode {
	// This implies H2Type needs to store its corresponding ParseMode.
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

const (
	HTMLParseMode_NO_HTML_ANALYSIS            HTMLParseMode = 0 // NO_HTML_ANALYSIS(_9.NONE, false)
	HTMLParseMode_HTML_HEAD_ANALYSIS          HTMLParseMode = 1 // HTML_HEAD_ANALYSIS(_9.HEAD, false)
	HTMLParseMode_HTML_ANALYSIS               HTMLParseMode = 2 // HTML_ANALYSIS(_9.FULL, false)
	HTMLParseMode_HTML_AND_VIEWSTATE_ANALYSIS HTMLParseMode = 3 // HTML_AND_VIEWSTATE_ANALYSIS(_9.FULL, true)
)
