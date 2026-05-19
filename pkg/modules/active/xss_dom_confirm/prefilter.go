package xss_dom_confirm

import (
	"regexp"
	"strings"
)

// Mirrors heuristics in pkg/modules/passive/dom_xss_detect; kept local because
// the canonical patterns there have known drift (typo around history.pushState
// and missing newer sinks like .src=). Lift to a shared package when both
// modules' patterns are reconciled.
var domSourcePattern = regexp.MustCompile(
	`\b(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer)` +
		`|location\.(?:href|search|hash|pathname)` +
		`|window\.name` +
		`|history\.(?:pushState|replaceState)` +
		`|(?:local|session)Storage)\b`,
)

// Sinks are split across multiple regexes because Go's RE2 can't anchor `\b`
// before a `.` (e.g. `\b\.innerHTML` never matches).
var domSinkPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:eval|Function|setTimeout|setInterval|setImmediate|execScript)\s*\(`),
	regexp.MustCompile(`\.(?:innerHTML|outerHTML|write|writeln)\b`),
	regexp.MustCompile(`\.src\s*=`),
	regexp.MustCompile(`\blocation\.(?:href|assign|replace)\b`),
}

func matchesAnySink(js string) bool {
	for _, re := range domSinkPatterns {
		if re.MatchString(js) {
			return true
		}
	}
	return false
}

var scriptBlockPattern = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)

type PrefilterReason string

const (
	ReasonReflectionInBody PrefilterReason = "reflection-in-body"
	ReasonDOMSourceSink    PrefilterReason = "dom-source-sink"
)

func passesPrefilter(body, canary string) (bool, PrefilterReason) {
	if canary != "" && strings.Contains(body, canary) {
		return true, ReasonReflectionInBody
	}
	if hasDomSourceSink(body) {
		return true, ReasonDOMSourceSink
	}
	return false, ""
}

func hasDomSourceSink(body string) bool {
	if body == "" {
		return false
	}
	for _, idx := range scriptBlockPattern.FindAllStringSubmatchIndex(body, -1) {
		if len(idx) < 4 {
			continue
		}
		js := body[idx[2]:idx[3]]
		if domSourcePattern.MatchString(js) && matchesAnySink(js) {
			return true
		}
	}
	return false
}
