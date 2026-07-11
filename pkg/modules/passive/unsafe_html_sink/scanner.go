package unsafe_html_sink

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// sinkPattern defines a single unsafe HTML sink pattern to detect.
type sinkPattern struct {
	name     string
	pattern  *regexp.Regexp
	severity severity.Severity
	cwe      string
	category string
	// emptyCheck, when set, drops a match whose sink is delivered an empty string
	// literal (el.innerHTML="", document.write("")): a clearing/no-op write that
	// carries no markup and cannot be an injection point.
	emptyCheck bool
}

// Compiled patterns at package level.
var sinkPatterns = []sinkPattern{
	{
		name: "dangerouslySetInnerHTML (React)",
		// Require an actual JSX/object assignment (`dangerouslySetInnerHTML={...}`
		// or minified `dangerouslySetInnerHTML:{__html:x}`), not a bare mention of
		// the prop name. React's own runtime bundle (main-*.js) ships a prop-filter
		// that string-compares the name (`"dangerouslySetInnerHTML"!==a`); a bare
		// pattern matched that on every React site — the dominant false positive.
		pattern:  regexp.MustCompile(`dangerouslySetInnerHTML\s*[:=]`),
		severity: severity.Low,
		cwe:      "CWE-79",
		category: "framework-xss",
	},
	{
		name:     "v-html directive (Vue)",
		pattern:  regexp.MustCompile(`v-html\s*=`),
		severity: severity.Low,
		cwe:      "CWE-79",
		category: "framework-xss",
	},
	{
		name:     "{@html} tag (Svelte)",
		pattern:  regexp.MustCompile(`\{@html\s`),
		severity: severity.Low,
		cwe:      "CWE-79",
		category: "framework-xss",
	},
	{
		name:     "bypassSecurityTrust* (Angular)",
		pattern:  regexp.MustCompile(`bypassSecurityTrust(Html|Url|ResourceUrl|Script|Style)`),
		severity: severity.Low,
		cwe:      "CWE-79",
		category: "framework-xss",
	},
	{
		name:       "innerHTML assignment",
		pattern:    regexp.MustCompile(`\.innerHTML\s*=`),
		severity:   severity.Low,
		cwe:        "CWE-79",
		category:   "dom-xss",
		emptyCheck: true,
	},
	{
		name:       "outerHTML assignment",
		pattern:    regexp.MustCompile(`\.outerHTML\s*=`),
		severity:   severity.Low,
		cwe:        "CWE-79",
		category:   "dom-xss",
		emptyCheck: true,
	},
	{
		name:     "insertAdjacentHTML call",
		pattern:  regexp.MustCompile(`insertAdjacentHTML\s*\(`),
		severity: severity.Low,
		cwe:      "CWE-79",
		category: "dom-xss",
	},
	{
		name:       "document.write call",
		pattern:    regexp.MustCompile(`document\.write\s*\(`),
		severity:   severity.Low,
		cwe:        "CWE-79",
		category:   "dom-xss",
		emptyCheck: true,
	},
	{
		name:     "eval() call",
		pattern:  regexp.MustCompile(`\beval\s*\(`),
		severity: severity.Low,
		cwe:      "CWE-94",
		category: "code-injection",
	},
	{
		name:     "new Function() call",
		pattern:  regexp.MustCompile(`new\s+Function\s*\(`),
		severity: severity.Low,
		cwe:      "CWE-94",
		category: "code-injection",
	},
}

// assignsEmptyLiteral reports whether the text immediately following a sink
// match (the value being assigned to .innerHTML/.outerHTML or passed to
// document.write) is an empty string literal: an empty pair of double quotes,
// single quotes, or backticks. Such writes clear or no-op the target and carry
// no markup, so they are not injection points. The match already consumed the
// = or ( so rest starts at the value.
func assignsEmptyLiteral(rest string) bool {
	rest = strings.TrimLeft(rest, " \t\r\n")
	return strings.HasPrefix(rest, `""`) ||
		strings.HasPrefix(rest, `''`) ||
		strings.HasPrefix(rest, "``")
}

// Module implements the unsafe HTML sink passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Unsafe HTML Sink module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("unsafe_html_sink"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts responses with JS/TS content types, JS/TS/Vue/Svelte URL paths,
// or HTML responses (for inline scripts).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if modkit.IsJSOrTSContentType(ct) || strings.Contains(ct, "text/html") {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		pathLower := strings.ToLower(u.Path)
		for _, ext := range modkit.JSExtensionsExtended {
			if strings.HasSuffix(pathLower, ext) {
				return true
			}
		}
	}

	return false
}

// ScanPerRequest scans response body for unsafe HTML sink patterns.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Dedup by host+path
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	pathLower := strings.ToLower(urlx.Path)
	isTestFile := strings.Contains(pathLower, "test") ||
		strings.Contains(pathLower, "spec") ||
		strings.Contains(pathLower, "mock")

	var results []*output.ResultEvent

	for _, sp := range sinkPatterns {
		// Test/spec/mock code intentionally exercises both eval and Function.
		if sp.category == "code-injection" && isTestFile {
			continue
		}

		matches := sp.pattern.FindAllStringIndex(body, -1)
		if len(matches) == 0 {
			continue
		}

		extracted := make([]string, 0, len(matches))
		for _, loc := range matches {
			start := loc[0]
			end := loc[1]
			// Drop clearing/no-op sink writes that deliver an empty string literal
			// (el.innerHTML="", document.write("")) — they carry no markup and are a
			// common framework pattern, not an injection point.
			if sp.emptyCheck && assignsEmptyLiteral(body[end:]) {
				continue
			}
			// Expand context: up to 40 chars before and after the match
			ctxStart := start - 40
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := end + 40
			if ctxEnd > len(body) {
				ctxEnd = len(body)
			}
			snippet := strings.TrimSpace(body[ctxStart:ctxEnd])
			extracted = append(extracted, modkit.Truncate(snippet, 150))
		}
		// Every match was an inert empty write — nothing to report for this sink.
		if len(extracted) == 0 {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindObservation,
			EvidenceGrade:    output.EvidenceGradeObservation,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("Unsafe HTML Sink: %s", sp.name),
				Description: fmt.Sprintf("Found %d occurrence(s) of %s in %s (%s). Sink presence is retained as an observation; no attacker-controlled source-to-sink flow or sanitizer analysis was established.", len(extracted), sp.name, urlx.Path, sp.cwe),
				Severity:    sp.severity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"xss", "injection", "source-analysis"},
			},
			Metadata: map[string]any{
				"sink":                   sp.name,
				"cwe":                    sp.cwe,
				"category":               sp.category,
				"matchCount":             len(extracted),
				"connected_source":       false,
				"sanitizer_assessed":     false,
				"taint_module_available": true,
			},
		})
	}

	return results, nil
}
