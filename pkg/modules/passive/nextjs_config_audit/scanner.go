package nextjs_config_audit

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
		name:       "dangerouslyAllowSVG",
		re:         regexp.MustCompile(`dangerouslyAllowSVG\s*:\s*true`),
		cwe:        "CWE-79",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "SVG images are allowed, which may enable XSS via malicious SVG content",
	},
	{
		name:       "Wildcard Image Hostname",
		re:         regexp.MustCompile(`hostname\s*:\s*['"]\*\*?['"]`),
		cwe:        "CWE-918",
		severity:   severity.High,
		confidence: severity.Firm,
		desc:       "Wildcard hostname in image remotePatterns allows SSRF via image optimization",
	},
	{
		name:       "HTTP Protocol in Image Config",
		re:         regexp.MustCompile(`protocol\s*:\s*['"]http['"]`),
		cwe:        "CWE-319",
		severity:   severity.Low,
		confidence: severity.Firm,
		desc:       "HTTP (not HTTPS) protocol configured for image loading allows cleartext transport",
	},
	{
		name:       "Production Source Maps",
		re:         regexp.MustCompile(`productionBrowserSourceMaps\s*:\s*true`),
		cwe:        "CWE-540",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "Production browser source maps are enabled, exposing application source code",
	},
	{
		name:       "Internal API Exposure via Rewrites/Redirects",
		re:         regexp.MustCompile(`(?:source|destination)\s*:\s*['"]\/api\/internal`),
		cwe:        "CWE-441",
		severity:   severity.Medium,
		confidence: severity.Firm,
		desc:       "Rewrites or redirects expose internal API routes to external access",
	},
}

var (
	moduleExportRe  = regexp.MustCompile(`module\.exports|export\s+default`)
	imagesConfigRe  = regexp.MustCompile(`images\s*[:\{]`)
	headersConfigRe = regexp.MustCompile(`headers\s*[:\(]`)
)

// Module implements the Next.js config audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Next.js Config Audit module.
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
		ds: dedup.LazyDiskSet("nextjs_config_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts JS/TS/JSON content types, or URLs containing "next.config" or "_next".
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "typescript") ||
		strings.Contains(ct, "ecmascript") || strings.Contains(ct, "json") {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		pathLower := strings.ToLower(u.Path)
		if strings.Contains(pathLower, "next.config") || strings.Contains(pathLower, "_next") {
			return true
		}
	}

	return false
}

// ScanPerRequest scans for insecure Next.js configuration patterns.
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

	// Check each regex-based pattern
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
				Name:        fmt.Sprintf("Next.js Config: %s", pat.name),
				Description: pat.desc,
				Severity:    pat.severity,
				Confidence:  pat.confidence,
				Tags:        []string{"nextjs", "misconfiguration", "source-analysis"},
				Reference:   []string{fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(pat.cwe, "CWE-"))},
			},
			Metadata: map[string]any{
				"cwe":     pat.cwe,
				"pattern": pat.name,
			},
		})
	}

	// Check for missing security headers configuration
	if moduleExportRe.MatchString(body) && imagesConfigRe.MatchString(body) && !headersConfigRe.MatchString(body) {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				"Next.js config defines images but does not configure security headers",
			},
			Info: output.Info{
				Name:        "Next.js Config: Missing Security Headers",
				Description: "Next.js configuration file defines image settings but does not include a headers configuration for security headers (CSP, X-Frame-Options, etc.)",
				Severity:    severity.Info,
				Confidence:  severity.Firm,
				Tags:        []string{"nextjs", "misconfiguration", "source-analysis"},
				Reference:   []string{"https://nextjs.org/docs/app/api-reference/next-config-js/headers"},
			},
			Metadata: map[string]any{
				"pattern": "missing-security-headers",
			},
		})
	}

	return results, nil
}
