package nuxt_config_audit

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
	"github.com/pkg/errors"
)

// configPattern defines a single insecure configuration pattern to detect.
type configPattern struct {
	name       string
	re         *regexp.Regexp
	cwe        string
	severity   severity.Severity
	confidence severity.Confidence
	desc       string
}

var configPatterns = []configPattern{
	{
		name:       "Devtools Enabled",
		re:         regexp.MustCompile(`devtools\s*:\s*true`),
		cwe:        "CWE-489",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "Nuxt devtools are enabled, potentially exposing application internals",
	},
	{
		name:       "Runtime Config Secret Exposure",
		re:         regexp.MustCompile(`runtimeConfig.*(?:secret|key|token|password)`),
		cwe:        "CWE-200",
		severity:   severity.High,
		confidence: severity.Firm,
		desc:       "Nuxt runtimeConfig contains references to secrets, keys, tokens, or passwords that may be exposed to the client",
	},
	{
		name:       "Production Source Maps",
		re:         regexp.MustCompile(`productionSourceMap\s*:\s*true`),
		cwe:        "CWE-540",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "Production source maps are enabled, exposing application source code",
	},
	{
		name:       "Debug Mode Enabled",
		re:         regexp.MustCompile(`debug\s*:\s*true`),
		cwe:        "CWE-489",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "Debug mode is enabled in production, potentially exposing verbose error information",
	},
}

// nuxtStateBlob defines where to find Nuxt state data in HTML.
type nuxtStateBlob struct {
	name  string
	start string
	end   string
}

var nuxtStateBlobs = []nuxtStateBlob{
	{
		name:  "__NUXT__",
		start: `window.__NUXT__=`,
		end:   `;</script>`,
	},
	{
		name:  "__NUXT_DATA__",
		start: `<script id="__NUXT_DATA__" type="application/json">`,
		end:   `</script>`,
	},
}

// sensitivePattern defines a pattern to detect in Nuxt state data.
type sensitivePattern struct {
	name    string
	pattern *regexp.Regexp
	desc    string
}

var sensitivePatterns = []sensitivePattern{
	{
		name:    "API Key/Token",
		pattern: regexp.MustCompile(`"(?:api_?key|api_?token|access_?token|secret_?key|auth_?token)"\s*:\s*"([^"]{16,})"`),
		desc:    "API key or token found in Nuxt state",
	},
	{
		name:    "Admin Flag",
		pattern: regexp.MustCompile(`"(?:is_?[Aa]dmin|is_?[Ss]uperuser|is_?[Ss]taff|admin|role)"\s*:\s*(?:true|"admin"|"superuser")`),
		desc:    "Admin/privilege flag found in Nuxt state",
	},
	{
		name:    "Internal URL",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^"]*)?"`),
		desc:    "Internal/private IP address found in Nuxt state",
	},
	{
		name:    "Database URL",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^"]+"`),
		desc:    "Database connection string found in Nuxt state",
	},
	{
		name:    "AWS Key",
		pattern: regexp.MustCompile(`"[^"]*"\s*:\s*"AKIA[0-9A-Z]{16}"`),
		desc:    "AWS access key found in Nuxt state",
	},
}

var (
	nuxtSourceMapRe = regexp.MustCompile(`/_nuxt/[^"'\s]+\.js\.map`)
)

// knownPlaceholders are values to skip as likely non-sensitive (pre-lowercased).
var knownPlaceholders = []string{
	"undefined", "null", "true", "false",
	"change_me", "your_api_key", "xxx",
	"placeholder", "example",
}

// Module implements the Nuxt config audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Nuxt Config Audit module.
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
		ds: dedup.LazyDiskSet("nuxt_config_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts HTML responses or JS/JSON responses with "nuxt" in the URL.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "text/html") {
		return true
	}

	if strings.Contains(ct, "javascript") || strings.Contains(ct, "json") {
		if u, err := ctx.URL(); err == nil {
			pathLower := strings.ToLower(u.Path)
			if strings.Contains(pathLower, "nuxt") {
				return true
			}
		}
	}

	return false
}

// ScanPerRequest scans for insecure Nuxt configuration patterns and sensitive data in Nuxt state.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(urlx.Host)
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var results []*output.ResultEvent

	// Check for sensitive data in Nuxt state blobs
	for _, blob := range nuxtStateBlobs {
		stateData := extractState(body, blob)
		if stateData == "" {
			continue
		}

		for _, sp := range sensitivePatterns {
			matches := sp.pattern.FindAllString(stateData, 3)
			for _, match := range matches {
				if isPlaceholder(match) {
					continue
				}
				results = append(results, &output.ResultEvent{
					ModuleID: ModuleID,
					Host:     urlx.Host,
					URL:      urlx.String(),
					Matched:  urlx.String(),
					ExtractedResults: []string{
						fmt.Sprintf("State blob: %s", blob.name),
						fmt.Sprintf("Pattern: %s", sp.name),
						fmt.Sprintf("Matched: %s", modkit.Truncate(match, 120)),
					},
					Info: output.Info{
						Name:        fmt.Sprintf("Nuxt State Data Exposure: %s", sp.name),
						Description: sp.desc,
						Severity:    ModuleSeverity,
						Confidence:  ModuleConfidence,
						Tags:        []string{"nuxt", "data-exposure", "information-disclosure"},
						Reference:   []string{"https://nuxt.com/docs/api/nuxt-config#runtimeconfig"},
					},
					Metadata: map[string]any{
						"stateBlob": blob.name,
						"pattern":   sp.name,
					},
				})
			}
		}
	}

	// Check each regex-based config pattern
	for _, pat := range configPatterns {
		match := pat.re.FindString(body)
		if match == "" {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				fmt.Sprintf("Pattern: %s", pat.name),
				fmt.Sprintf("Matched: %s", modkit.Truncate(match, 120)),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Nuxt Config: %s", pat.name),
				Description: pat.desc,
				Severity:    pat.severity,
				Confidence:  pat.confidence,
				Tags:        []string{"nuxt", "misconfiguration", "source-analysis"},
				Reference:   []string{fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(pat.cwe, "CWE-"))},
			},
			Metadata: map[string]any{
				"cwe":     pat.cwe,
				"pattern": pat.name,
			},
		})
	}

	// Check for /_nuxt/ source map exposure
	if match := nuxtSourceMapRe.FindString(body); match != "" {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				fmt.Sprintf("Source map reference: %s", modkit.Truncate(match, 120)),
			},
			Info: output.Info{
				Name:        "Nuxt Source Map Exposure",
				Description: "A /_nuxt/ source map file reference was found, potentially exposing application source code",
				Severity:    severity.Medium,
				Confidence:  severity.Firm,
				Tags:        []string{"nuxt", "sourcemap", "information-disclosure"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/540.html"},
			},
			Metadata: map[string]any{
				"cwe":     "CWE-540",
				"pattern": "nuxt-source-map",
			},
		})
	}

	return results, nil
}

// extractState extracts the state data from a blob definition.
func extractState(body string, blob nuxtStateBlob) string {
	idx := strings.Index(body, blob.start)
	if idx == -1 {
		return ""
	}
	start := idx + len(blob.start)
	remaining := body[start:]

	endIdx := strings.Index(remaining, blob.end)
	if endIdx == -1 {
		// Limit extraction to avoid processing huge chunks
		if len(remaining) > 50000 {
			remaining = remaining[:50000]
		}
		return remaining
	}

	return remaining[:endIdx]
}

// isPlaceholder checks if a matched value is a known placeholder.
func isPlaceholder(match string) bool {
	matchLower := strings.ToLower(match)
	for _, ph := range knownPlaceholders {
		if strings.Contains(matchLower, ph) {
			return true
		}
	}
	return false
}
