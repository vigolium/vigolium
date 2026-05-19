package ssr_hydration_xss

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	// Matches inline script tags containing hydration data patterns.
	hydrationScriptRe = regexp.MustCompile(
		`(?is)<script[^>]*>\s*(?:` +
			`(?:self\.__next_f\.push|__NEXT_DATA__|window\.__NEXT_DATA__)\s*=|` +
			`window\.__(?:PRELOADED_STATE|INITIAL_STATE|APOLLO_STATE|NUXT)__\s*=|` +
			`window\.__remixContext\s*=` +
			`)(.+?)</script>`,
	)

	// Detects unescaped </script within a script block — the primary XSS vector.
	scriptBreakoutRe = regexp.MustCompile(`(?i)</script\s*>`)

	// Detects raw < character that isn't properly escaped as \u003c or &lt;
	// within what appears to be JSON content.
	rawAngleBracketRe = regexp.MustCompile(`"[^"]*<[^"]*"`)
)

// Module implements the SSR hydration XSS passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new SSR Hydration XSS Detection module.
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
		ds: dedup.LazyDiskSet("ssr_hydration_xss"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess only accepts HTML responses.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// ScanPerRequest scans HTML responses for unsafe SSR hydration patterns.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	// Find all hydration script blocks
	matches := hydrationScriptRe.FindAllStringSubmatch(body, 10)
	if len(matches) == 0 {
		return nil, nil
	}

	// Extract request parameter values for reflection correlation
	paramValues := extractParamValues(ctx)

	var results []*output.ResultEvent

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		scriptContent := match[1]

		// Check 1: </script> breakout within the hydration block
		if scriptBreakoutRe.MatchString(scriptContent) {
			results = append(results, m.buildResult(
				urlx.Host, urlx.String(),
				"Script tag breakout in hydration data",
				"Unescaped </script> found within SSR hydration script block — allows XSS via script context escape",
				modkit.Truncate(scriptContent, 200),
				severity.High,
				severity.Firm,
				paramValues,
				scriptContent,
			))
			continue
		}

		// Check 2: Raw < characters in JSON string values (not escaped as \u003c)
		rawBrackets := rawAngleBracketRe.FindAllString(scriptContent, 5)
		for _, rb := range rawBrackets {
			// Skip if it's properly escaped
			if strings.Contains(rb, `\u003c`) || strings.Contains(rb, `&lt;`) {
				continue
			}
			// Skip common safe patterns (HTML in legitimate data)
			if strings.Contains(rb, `<br`) || strings.Contains(rb, `<p>`) {
				continue
			}

			conf := severity.Tentative
			// Correlate with request parameters
			for _, val := range paramValues {
				if len(val) >= 4 && strings.Contains(rb, val) {
					conf = severity.Firm
					break
				}
			}

			results = append(results, m.buildResult(
				urlx.Host, urlx.String(),
				"Unescaped HTML in hydration JSON",
				fmt.Sprintf("Raw < character in JSON string value within hydration script — missing \\u003c encoding: %s", modkit.Truncate(rb, 120)),
				modkit.Truncate(rb, 200),
				severity.Medium,
				conf,
				paramValues,
				scriptContent,
			))
			break // One finding per script block is sufficient
		}
	}

	return results, nil
}

// buildResult constructs a ResultEvent for a hydration XSS finding.
func (m *Module) buildResult(
	host, url, name, desc, matched string,
	sev severity.Severity,
	conf severity.Confidence,
	paramValues map[string]string,
	scriptContent string,
) *output.ResultEvent {
	extracted := []string{
		fmt.Sprintf("Pattern: %s", name),
		fmt.Sprintf("Matched: %s", matched),
	}

	// Check for reflected parameters
	var reflectedParam string
	scriptLower := strings.ToLower(scriptContent)
	for param, val := range paramValues {
		if len(val) >= 4 && strings.Contains(scriptLower, strings.ToLower(val)) {
			reflectedParam = param
			extracted = append(extracted, fmt.Sprintf("Reflected parameter: %s", param))
			break
		}
	}

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              url,
		Matched:          url,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        name,
			Description: desc,
			Severity:    sev,
			Confidence:  conf,
			Tags:        []string{"xss", "ssr", "hydration", "json-injection"},
			Reference: []string{
				"https://snyk.io/blog/10-react-security-best-practices/",
				"https://cwe.mitre.org/data/definitions/79.html",
			},
		},
		Metadata: map[string]any{
			"cwe":             "CWE-79",
			"reflected_param": reflectedParam,
		},
	}
}

// extractParamValues collects parameter values from the request URL query.
func extractParamValues(ctx *httpmsg.HttpRequestResponse) map[string]string {
	params := make(map[string]string)

	urlx, err := ctx.URL()
	if err != nil {
		return params
	}

	if urlx.Params != nil {
		urlx.Params.Iterate(func(key string, values []string) bool {
			if len(values) > 0 {
				params[key] = values[0]
			}
			return true
		})
	}

	return params
}
