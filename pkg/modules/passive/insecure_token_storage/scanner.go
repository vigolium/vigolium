package insecure_token_storage

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

// tokenPattern defines a single insecure token storage pattern.
type tokenPattern struct {
	name     string
	pattern  *regexp.Regexp
	severity severity.Severity
	cwe      string
}

// tokenKeyNames is the alternation group for common auth-related key names.
const tokenKeyNames = `(?:token|jwt|auth|session|access_token|refresh_token|id_token|bearer|api_key|apiKey|accessToken|refreshToken|idToken)`

// Compiled patterns at package level.
var tokenPatterns = []tokenPattern{
	{
		name:     "localStorage.setItem with auth token",
		pattern:  regexp.MustCompile(`localStorage\.setItem\s*\(\s*['"]` + tokenKeyNames + `['"]`),
		severity: severity.Medium,
		cwe:      "CWE-922",
	},
	{
		name:     "sessionStorage.setItem with auth token",
		pattern:  regexp.MustCompile(`sessionStorage\.setItem\s*\(\s*['"]` + tokenKeyNames + `['"]`),
		severity: severity.Medium,
		cwe:      "CWE-922",
	},
	{
		name:     "localStorage bracket assignment with auth token",
		pattern:  regexp.MustCompile(`localStorage\[['"]` + `(?:token|jwt|auth|session|access_token|refresh_token|id_token|bearer)` + `['"]`),
		severity: severity.Medium,
		cwe:      "CWE-922",
	},
	{
		name:     "localStorage token used in Authorization header",
		pattern:  regexp.MustCompile(`(?:Authorization|Bearer).*localStorage\.getItem|localStorage\.getItem.*(?:Authorization|Bearer)`),
		severity: severity.High,
		cwe:      "CWE-922",
	},
}

// Module implements the insecure token storage passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Insecure Token Storage module.
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
		ds: dedup.LazyDiskSet("insecure_token_storage"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts responses with JS/TS content types or JS/TS URL paths.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	if modkit.IsJSOrTSContentType(ctx.Response().Header("Content-Type")) {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		if modkit.HasJSExtension(strings.ToLower(u.Path)) {
			return true
		}
	}

	return false
}

// ScanPerRequest scans response body for insecure token storage patterns.
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

	var results []*output.ResultEvent

	for _, tp := range tokenPatterns {
		matches := tp.pattern.FindAllStringIndex(body, -1)
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
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("Insecure Token Storage: %s", tp.name),
				Description: fmt.Sprintf("Found %d occurrence(s) of %s in %s (%s)", len(matches), tp.name, urlx.Path, tp.cwe),
				Severity:    tp.severity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"auth", "token-storage", "xss-amplifier", "source-analysis"},
			},
			Metadata: map[string]any{
				"pattern":    tp.name,
				"cwe":        tp.cwe,
				"matchCount": len(matches),
			},
		})
	}

	return results, nil
}
