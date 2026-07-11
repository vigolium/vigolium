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
	kind     output.RecordKind
	grade    output.EvidenceGrade
	cwe      string
}

const (
	strongTokenKeyNames    = `(?:jwt|access_token|refresh_token|id_token|bearer|accessToken|refreshToken|idToken)`
	ambiguousTokenKeyNames = `(?:token|auth|session|api_key|apiKey)`
	allTokenKeyNames       = `(?:token|jwt|auth|session|access_token|refresh_token|id_token|bearer|api_key|apiKey|accessToken|refreshToken|idToken)`
)

// Compiled patterns at package level.
var tokenPatterns = []tokenPattern{
	{
		name:     "localStorage.setItem with strong auth-token key",
		pattern:  regexp.MustCompile(`localStorage\.setItem\s*\(\s*['"]` + strongTokenKeyNames + `['"]\s*,`),
		severity: severity.Medium,
		kind:     output.RecordKindCandidate,
		grade:    output.EvidenceGradeCandidate,
		cwe:      "CWE-922",
	},
	{
		name:     "localStorage.setItem with ambiguous security key",
		pattern:  regexp.MustCompile(`localStorage\.setItem\s*\(\s*['"]` + ambiguousTokenKeyNames + `['"]\s*,`),
		severity: severity.Info,
		kind:     output.RecordKindObservation,
		grade:    output.EvidenceGradeObservation,
		cwe:      "CWE-922",
	},
	{
		name:     "sessionStorage.setItem with strong auth-token key",
		pattern:  regexp.MustCompile(`sessionStorage\.setItem\s*\(\s*['"]` + strongTokenKeyNames + `['"]\s*,`),
		severity: severity.Low,
		kind:     output.RecordKindCandidate,
		grade:    output.EvidenceGradeCandidate,
		cwe:      "CWE-922",
	},
	{
		name:     "sessionStorage.setItem with ambiguous security key",
		pattern:  regexp.MustCompile(`sessionStorage\.setItem\s*\(\s*['"]` + ambiguousTokenKeyNames + `['"]\s*,`),
		severity: severity.Info,
		kind:     output.RecordKindObservation,
		grade:    output.EvidenceGradeObservation,
		cwe:      "CWE-922",
	},
	{
		name:     "localStorage bracket assignment with strong auth-token key",
		pattern:  regexp.MustCompile(`localStorage\[['"]` + strongTokenKeyNames + `['"]\]\s*=`),
		severity: severity.Medium,
		kind:     output.RecordKindCandidate,
		grade:    output.EvidenceGradeCandidate,
		cwe:      "CWE-922",
	},
	{
		name:     "localStorage bracket assignment with ambiguous security key",
		pattern:  regexp.MustCompile(`localStorage\[['"]` + ambiguousTokenKeyNames + `['"]\]\s*=`),
		severity: severity.Info,
		kind:     output.RecordKindObservation,
		grade:    output.EvidenceGradeObservation,
		cwe:      "CWE-922",
	},
	{
		// The gap between the Authorization/Bearer token and the localStorage
		// read is bounded to a short, statement-local window ([^;\n]{0,40}).
		// Minified bundles are a single line, so an unbounded `.*` would stitch
		// an unrelated `localStorage.getItem('theme')` to a stray `Bearer`
		// literal hundreds of chars away and emit a false positive; the bound
		// keeps the two within one expression/statement.
		name:     "localStorage token used in Authorization header",
		pattern:  regexp.MustCompile(`(?:Authorization|Bearer)[^;\n]{0,80}localStorage\.getItem\s*\(\s*['"]` + allTokenKeyNames + `['"]|localStorage\.getItem\s*\(\s*['"]` + allTokenKeyNames + `['"][^;\n]{0,80}(?:Authorization|Bearer)`),
		severity: severity.Medium,
		kind:     output.RecordKindCandidate,
		grade:    output.EvidenceGradeCandidate,
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

	// A WAF/CDN edge block served with a JS content type is the edge talking,
	// not the application's bundle — any storage pattern in it is noise.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
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
	if strings.Contains(pathLower, ".test.") || strings.Contains(pathLower, ".spec.") || strings.Contains(pathLower, "/test/") || strings.Contains(pathLower, "/tests/") || strings.Contains(pathLower, "/mocks/") {
		return nil, nil
	}

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
			RecordKind:       tp.kind,
			EvidenceGrade:    tp.grade,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        fmt.Sprintf("Insecure Token Storage: %s", tp.name),
				Description: fmt.Sprintf("Found %d occurrence(s) of %s in %s (%s). This establishes a storage/code pattern, not an XSS exploit, token validity, or account takeover.", len(matches), tp.name, urlx.Path, tp.cwe),
				Severity:    tp.severity,
				Confidence:  confidenceForKind(tp.kind),
				Tags:        []string{"auth", "token-storage", "xss-amplifier", "source-analysis"},
			},
			Metadata: map[string]any{
				"pattern":            tp.name,
				"cwe":                tp.cwe,
				"matchCount":         len(matches),
				"xss_confirmed":      false,
				"token_validated":    false,
				"takeover_confirmed": false,
			},
		})
	}

	return results, nil
}

func confidenceForKind(kind output.RecordKind) severity.Confidence {
	if kind == output.RecordKindObservation {
		return severity.Tentative
	}
	return ModuleConfidence
}
