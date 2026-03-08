package build_misconfig_detect

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

// misconfigPattern defines a single build misconfiguration pattern.
type misconfigPattern struct {
	name     string
	pattern  *regexp.Regexp
	severity severity.Severity
	cwe      string
}

// Compiled patterns at package level.
var misconfigPatterns = []misconfigPattern{
	{
		name:     "Next.js production source maps enabled",
		pattern:  regexp.MustCompile(`productionBrowserSourceMaps\s*:\s*true`),
		severity: severity.Medium,
		cwe:      "CWE-540",
	},
	{
		name:     "Vite/webpack source maps enabled",
		pattern:  regexp.MustCompile(`(?:build\s*:\s*\{[^}]*)?sourcemap\s*:\s*(?:true|['"](?:inline|hidden)['"])`),
		severity: severity.Medium,
		cwe:      "CWE-540",
	},
	{
		name:     "Webpack devtool source-map in production",
		pattern:  regexp.MustCompile(`devtool\s*:\s*['"]source-map['"]`),
		severity: severity.Medium,
		cwe:      "CWE-540",
	},
	{
		name:     "Development mode start script in production",
		pattern:  regexp.MustCompile(`"start"\s*:\s*"(?:next|vite|nuxt)\s+dev"`),
		severity: severity.High,
		cwe:      "CWE-489",
	},
	{
		name:     "Next.js dangerouslyAllowSVG enabled",
		pattern:  regexp.MustCompile(`dangerouslyAllowSVG\s*:\s*true`),
		severity: severity.Medium,
		cwe:      "CWE-79",
	},
	{
		name:     "Next.js broad image remotePatterns wildcard hostname",
		pattern:  regexp.MustCompile(`hostname\s*:\s*['"]\*\*?['"]`),
		severity: severity.High,
		cwe:      "CWE-918",
	},
}

// configFilePatterns are URL path substrings that indicate build config files.
var configFilePatterns = []string{
	"next.config", "vite.config", "webpack.config",
	"package.json", "dockerfile",
}

// Module implements the build misconfiguration detection passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Build Misconfiguration Detect module.
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
		ds: dedup.LazyDiskSet("build_misconfig_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts responses with JS/TS/JSON content types or URLs matching config file patterns.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") ||
		strings.Contains(ct, "typescript") || strings.Contains(ct, "json") {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		pathLower := strings.ToLower(u.Path)
		for _, pat := range configFilePatterns {
			if strings.Contains(pathLower, pat) {
				return true
			}
		}
	}

	return false
}

// ScanPerRequest scans response body for build misconfiguration patterns.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(urlx.Host)
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var results []*output.ResultEvent

	for _, mp := range misconfigPatterns {
		matches := mp.pattern.FindAllStringIndex(body, -1)
		if len(matches) == 0 {
			continue
		}

		extracted := make([]string, 0, len(matches))
		for _, loc := range matches {
			start := loc[0]
			end := loc[1]
			// Expand context: up to 30 chars before and after the match
			ctxStart := start - 30
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := end + 30
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
				Name:        fmt.Sprintf("Build Misconfiguration: %s", mp.name),
				Description: fmt.Sprintf("Found %d occurrence(s) of %s in %s (%s)", len(matches), mp.name, urlx.Path, mp.cwe),
				Severity:    mp.severity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"misconfiguration", "build-config", "source-analysis"},
			},
			Metadata: map[string]any{
				"pattern":    mp.name,
				"cwe":        mp.cwe,
				"matchCount": len(matches),
			},
		})
	}

	return results, nil
}

