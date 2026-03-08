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

	// Check framework-prefixed env var patterns
	for _, ep := range envPatterns {
		matches := ep.pattern.FindAllStringSubmatch(body, -1)
		if len(matches) == 0 {
			continue
		}

		extracted := make([]string, 0, len(matches))
		seen := make(map[string]struct{})
		for _, match := range matches {
			// Use the full match (match[0]) but redact the secret value
			full := match[0]
			key := utils.Sha1(full)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			extracted = append(extracted, redactValue(modkit.Truncate(full, 120)))
		}

		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
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

	// Check for .env file content served directly
	dotenvMatches := dotenvLinePattern.FindAllString(body, 50)
	if len(dotenvMatches) > 0 {
		var secretLines []string
		for _, line := range dotenvMatches {
			for _, indicator := range dotenvSecretIndicators {
				if strings.Contains(line, indicator) {
					secretLines = append(secretLines, redactValue(modkit.Truncate(line, 120)))
					break
				}
			}
		}

		if len(secretLines) > 0 {
			results = append(results, &output.ResultEvent{
				ModuleID: ModuleID,
				Host:     urlx.Host,
				URL:      urlx.String(),
				Matched:  urlx.String(),
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

	return results, nil
}

// redactValue redacts secret values after the = or : delimiter, keeping the key visible.
func redactValue(s string) string {
	for _, delim := range []string{"=", ":"} {
		idx := strings.Index(s, delim)
		if idx != -1 && idx+1 < len(s) {
			key := s[:idx+1]
			val := s[idx+1:]
			val = strings.TrimLeft(val, " '\"")
			if len(val) > 8 {
				return key + val[:4] + strings.Repeat("*", len(val)-8) + val[len(val)-4:]
			}
			return key + strings.Repeat("*", len(val))
		}
	}
	return s
}

