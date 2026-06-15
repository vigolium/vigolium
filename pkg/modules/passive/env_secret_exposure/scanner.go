package env_secret_exposure

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

// envPattern defines a single environment secret exposure pattern.
type envPattern struct {
	name    string
	pattern *regexp.Regexp
	cwe     string
}

// Compiled patterns at package level.
var envPatterns = []envPattern{
	{
		name:    "Next.js public secret (NEXT_PUBLIC_*SECRET/KEY/TOKEN*)",
		pattern: regexp.MustCompile(`NEXT_PUBLIC_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)\w*\s*[=:]\s*['"]([^'"]{8,})`),
		cwe:     "CWE-200",
	},
	{
		name:    "Vite public secret (VITE_*SECRET/KEY/TOKEN*)",
		pattern: regexp.MustCompile(`VITE_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)\w*\s*[=:]\s*['"]([^'"]{8,})`),
		cwe:     "CWE-200",
	},
	{
		name:    "Create React App public secret (REACT_APP_*SECRET/KEY/TOKEN*)",
		pattern: regexp.MustCompile(`REACT_APP_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)\w*\s*[=:]\s*['"]([^'"]{8,})`),
		cwe:     "CWE-200",
	},
}

// dotenvSecretIndicators are substrings that indicate a secret value in .env file lines.
var dotenvSecretIndicators = []string{
	"sk_live_", "sk_test_",
	"AKIA",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	"password=", "PASSWORD=",
	"secret=", "SECRET=",
	"private_key=", "PRIVATE_KEY=",
}

// dotenvLinePattern matches raw .env file lines (KEY=VALUE format).
var dotenvLinePattern = regexp.MustCompile(`(?m)^[A-Z_]+=.+`)

// Module implements the environment secret exposure passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Environment Secret Exposure module.
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
		ds: dedup.LazyDiskSet("env_secret_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts text-based responses: JS, HTML, JSON, plain text, or .env/.js/.json URLs.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "json") ||
		strings.Contains(ct, "text/html") || strings.Contains(ct, "text/plain") {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		pathLower := strings.ToLower(u.Path)
		if strings.HasSuffix(pathLower, ".env") || strings.HasSuffix(pathLower, ".js") ||
			strings.HasSuffix(pathLower, ".json") {
			return true
		}
	}

	return false
}

// ScanPerRequest scans response body for exposed environment secrets.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}
	// A WAF/CDN edge block's body is the edge talking, not the application — an
	// env-var-like line in it is not the app exposing a secret.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
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
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))

	var results []*output.ResultEvent

	// Check framework-prefixed env var patterns
	for _, ep := range envPatterns {
		matches := ep.pattern.FindAllStringSubmatch(body, -1)
		if len(matches) == 0 {
			continue
		}

		extracted := make([]string, 0, len(matches))
		seen := make(map[string]struct{})
		for _, match := range matches {
			// Show the full match (match[0]) including the secret value — the
			// point of the finding is to surface the leaked secret to the user.
			full := match[0]
			key := utils.Sha1(full)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			extracted = append(extracted, modkit.Truncate(full, 120))
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("Env Secret Exposure: %s", ep.name),
				Description: fmt.Sprintf("Found %d unique occurrence(s) of %s at %s (%s)", len(extracted), ep.name, urlx.Path, ep.cwe),
				Severity:    severity.High,
				Confidence:  ModuleConfidence,
				Tags:        []string{"secret", "env-exposure", "information-disclosure", "source-analysis"},
			},
			Metadata: map[string]any{
				"pattern":    ep.name,
				"cwe":        ep.cwe,
				"matchCount": len(extracted),
			},
		})
	}

	// Check for .env file content served directly. This targets actual served
	// .env/config files (text/plain, .env URLs), NOT JS bundles — a minified
	// bundle that happens to contain an uppercase KEY=value line is not a leaked
	// .env file. Framework-prefixed patterns above still scan JS. The generic
	// indicators ("password=", "secret=") are also too weak to flag a High
	// without a substantive value behind the assignment.
	if !modkit.IsJSOrTSContentType(ct) {
		dotenvMatches := dotenvLinePattern.FindAllString(body, 50)
		if len(dotenvMatches) > 0 {
			var secretLines []string
			for _, line := range dotenvMatches {
				if !dotenvValueIsSubstantive(line) {
					continue
				}
				for _, indicator := range dotenvSecretIndicators {
					if strings.Contains(line, indicator) {
						secretLines = append(secretLines, modkit.Truncate(line, 120))
						break
					}
				}
			}

			if len(secretLines) > 0 {
				results = append(results, &output.ResultEvent{
					ModuleID:         ModuleID,
					Host:             urlx.Host,
					URL:              urlx.String(),
					Matched:          urlx.String(),
					ExtractedResults: secretLines,
					Info: output.Info{
						Name:        "Env File Secret Exposure",
						Description: fmt.Sprintf("Found %d secret line(s) in .env file content at %s (CWE-200)", len(secretLines), urlx.Path),
						Severity:    severity.High,
						Confidence:  severity.Certain,
						Tags:        []string{"secret", "env-exposure", "information-disclosure", "source-analysis"},
					},
					Metadata: map[string]any{
						"cwe":        "CWE-200",
						"matchCount": len(secretLines),
					},
				})
			}
		}

	}

	return results, nil
}

// dotenvValueIsSubstantive reports whether the value after the first '=' on a
// KEY=VALUE line looks like a real secret rather than an empty or placeholder
// stub. It mirrors the >=8-char value floor used by the framework-prefixed
// patterns so a bare "PASSWORD=" or "SECRET=changeme" cannot raise a High.
func dotenvValueIsSubstantive(line string) bool {
	idx := strings.Index(line, "=")
	if idx < 0 || idx+1 >= len(line) {
		return false
	}
	val := strings.TrimSpace(line[idx+1:])
	val = strings.Trim(val, `"'`)
	if len(val) < 8 {
		return false
	}
	lower := strings.ToLower(val)
	for _, ph := range []string{"changeme", "your_", "yourvalue", "placeholder", "example", "xxxx", "<", "${", "****"} {
		if strings.Contains(lower, ph) {
			return false
		}
	}
	return true
}
