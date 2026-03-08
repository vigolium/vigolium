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
}

// Compiled patterns at package level.
var sinkPatterns = []sinkPattern{
	{
		name:     "dangerouslySetInnerHTML (React)",
		pattern:  regexp.MustCompile(`dangerouslySetInnerHTML`),
		severity: severity.High,
		cwe:      "CWE-79",
		category: "framework-xss",
	},
	{
		name:     "v-html directive (Vue)",
		pattern:  regexp.MustCompile(`v-html\s*=`),
		severity: severity.High,
		cwe:      "CWE-79",
		category: "framework-xss",
	},
	{
		name:     "{@html} tag (Svelte)",
		pattern:  regexp.MustCompile(`\{@html\s`),
		severity: severity.High,
		cwe:      "CWE-79",
		category: "framework-xss",
	},
	{
		name:     "bypassSecurityTrust* (Angular)",
		pattern:  regexp.MustCompile(`bypassSecurityTrust(Html|Url|ResourceUrl|Script|Style)`),
		severity: severity.High,
		cwe:      "CWE-79",
		category: "framework-xss",
	},
	{
		name:     "innerHTML assignment",
		pattern:  regexp.MustCompile(`\.innerHTML\s*=`),
		severity: severity.Medium,
		cwe:      "CWE-79",
		category: "dom-xss",
	},
	{
		name:     "outerHTML assignment",
		pattern:  regexp.MustCompile(`\.outerHTML\s*=`),
		severity: severity.Medium,
		cwe:      "CWE-79",
		category: "dom-xss",
	},
	{
		name:     "insertAdjacentHTML call",
		pattern:  regexp.MustCompile(`insertAdjacentHTML\s*\(`),
		severity: severity.Medium,
		cwe:      "CWE-79",
		category: "dom-xss",
	},
	{
		name:     "document.write call",
		pattern:  regexp.MustCompile(`document\.write\s*\(`),
		severity: severity.Medium,
		cwe:      "CWE-79",
		category: "dom-xss",
	},
	{
		name:     "eval() call",
		pattern:  regexp.MustCompile(`\beval\s*\(`),
		severity: severity.High,
		cwe:      "CWE-94",
		category: "code-injection",
	},
	{
		name:     "new Function() call",
		pattern:  regexp.MustCompile(`new\s+Function\s*\(`),
		severity: severity.High,
		cwe:      "CWE-94",
		category: "code-injection",
	},
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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
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
		// Skip eval() detection for test/spec/mock files
		if sp.category == "code-injection" && sp.name == "eval() call" && isTestFile {
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

		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("Unsafe HTML Sink: %s", sp.name),
				Description: fmt.Sprintf("Found %d occurrence(s) of %s in %s (%s)", len(matches), sp.name, urlx.Path, sp.cwe),
				Severity:    sp.severity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"xss", "injection", "source-analysis"},
			},
			Metadata: map[string]any{
				"sink":       sp.name,
				"cwe":        sp.cwe,
				"category":   sp.category,
				"matchCount": len(matches),
			},
		})
	}

	return results, nil
}

