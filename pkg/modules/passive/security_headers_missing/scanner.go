package security_headers_missing

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// securityHeader defines a security header to check.
type securityHeader struct {
	name string
	desc string
}

var requiredHeaders = []securityHeader{
	{
		name: "X-Content-Type-Options",
		desc: "Prevents MIME type sniffing attacks. Should be set to 'nosniff'.",
	},
	{
		name: "X-Frame-Options",
		desc: "Prevents clickjacking attacks by controlling iframe embedding. Should be 'DENY' or 'SAMEORIGIN'.",
	},
	{
		name: "Content-Security-Policy",
		desc: "Prevents XSS, data injection, and other code injection attacks by controlling resource loading.",
	},
	{
		name: "Permissions-Policy",
		desc: "Controls browser features and APIs available to the page (formerly Feature-Policy).",
	},
}

// weakReferrerPolicies maps weak Referrer-Policy values to their risk
// description. Safe values (no-referrer, same-origin, strict-origin,
// strict-origin-when-cross-origin, origin) are not flagged.
var weakReferrerPolicies = map[string]string{
	"unsafe-url":                 "sends the full URL as referrer to all origins, leaking path and query parameters",
	"no-referrer-when-downgrade": "sends the full URL on same-protocol requests, may leak sensitive path and query data",
}

// passwordFieldRe matches an HTML password input, used to gate the cacheable
// sensitive-response check.
var passwordFieldRe = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']?password["']?[^>]*>`)

// Module implements the Security Headers Missing passive scanner. It folds the
// related header-hardening checks (Referrer-Policy weaknesses and cacheable
// sensitive HTTPS responses) into a single INFO-severity finding rather than
// emitting them as separate low-severity findings.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Security Headers Missing module.
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
			modkit.ScanScopeHost,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_security_headers_missing"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess prevents an unsuitable JSON/error/static response from claiming
// the host before a representative HTML document arrives.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil || ctx.Request() == nil || ctx.Response().StatusCode() < 200 || ctx.Response().StatusCode() >= 300 {
		return false
	}
	return strings.Contains(strings.ToLower(ctx.Response().Header("Content-Type")), "text/html")
}

// ScanPerHost checks response headers for missing/weak security headers and
// cacheable sensitive content once per host.
func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Only check HTML responses to reduce noise
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	resp := ctx.Response()

	var issues []string
	for _, h := range requiredHeaders {
		val := resp.Header(h.name)
		if val == "" {
			issues = append(issues, fmt.Sprintf("%s: %s", h.name, h.desc))
		}
	}

	// HSTS is only meaningful over HTTPS — browsers ignore the header on an HTTP
	// response — so flag it only on an HTTPS response that omits it.
	if urlx, err := ctx.URL(); err == nil && strings.EqualFold(urlx.Scheme, "https") && resp.Header("Strict-Transport-Security") == "" {
		issues = append(issues, "Strict-Transport-Security: header is missing on HTTPS response.")
	}

	// If CSP contains frame-ancestors, X-Frame-Options is redundant — remove it
	csp := strings.ToLower(resp.Header("Content-Security-Policy"))
	if strings.Contains(csp, "frame-ancestors") {
		filtered := issues[:0]
		for _, entry := range issues {
			if !strings.HasPrefix(entry, "X-Frame-Options:") {
				filtered = append(filtered, entry)
			}
		}
		issues = filtered
	}

	// Folded in from the former referrer-policy-detect module: a missing or weak
	// Referrer-Policy is reported here as an INFO header issue.
	issues = appendReferrerPolicyIssue(issues, resp)

	// Folded in from the former cacheable-https-detect module: a sensitive HTTPS
	// response (sets cookies or renders a password field) that lacks a safe
	// Cache-Control directive is reported here as an INFO caching issue.
	issues = appendCacheableIssue(issues, ctx, resp)

	if len(issues) == 0 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: issues,
			Info: output.Info{
				Description: fmt.Sprintf("%d security header / caching issue(s)", len(issues)),
			},
		},
	}, nil
}

// appendReferrerPolicyIssue flags a missing or weak Referrer-Policy header.
func appendReferrerPolicyIssue(issues []string, resp *httpmsg.HttpResponse) []string {
	policy := strings.TrimSpace(resp.Header("Referrer-Policy"))
	if policy == "" {
		return append(issues, "Referrer-Policy: header is missing; the browser will use its default policy, which may leak URL information to other origins.")
	}
	// Referrer-Policy may carry a comma-separated fallback list; the last value
	// the browser understands is the effective one.
	parts := strings.Split(policy, ",")
	effective := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
	if desc, weak := weakReferrerPolicies[effective]; weak {
		return append(issues, fmt.Sprintf("Referrer-Policy: weak value %q — %s.", effective, desc))
	}
	return issues
}

// appendCacheableIssue flags a sensitive HTTPS response that lacks a safe
// Cache-Control directive, allowing browsers or proxies to cache sensitive data.
func appendCacheableIssue(issues []string, ctx *httpmsg.HttpRequestResponse, resp *httpmsg.HttpResponse) []string {
	urlx, err := ctx.URL()
	if err != nil || !strings.EqualFold(urlx.Scheme, "https") {
		return issues
	}

	// Gate: response must be "sensitive" — sets a cookie or renders a password field.
	hasCookie := false
	for _, h := range resp.Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			hasCookie = true
			break
		}
	}
	hasPasswordField := passwordFieldRe.MatchString(resp.BodyToString())
	if !hasCookie && !hasPasswordField {
		return issues
	}

	// A safe directive means the response is already protected from caching.
	cacheControl := strings.ToLower(resp.Header("Cache-Control"))
	pragma := strings.ToLower(resp.Header("Pragma"))
	if strings.Contains(cacheControl, "no-store") ||
		strings.Contains(cacheControl, "no-cache") ||
		strings.Contains(cacheControl, "private") ||
		strings.Contains(pragma, "no-cache") {
		return issues
	}

	var why string
	switch {
	case hasCookie && hasPasswordField:
		why = "sets cookies and renders a password field"
	case hasCookie:
		why = "sets cookies"
	default:
		why = "renders a password field"
	}
	detail := strings.TrimSpace(resp.Header("Cache-Control"))
	if detail == "" {
		detail = "absent"
	}
	return append(issues, fmt.Sprintf(
		"Cache-Control: sensitive HTTPS response (%s) lacks no-store/no-cache/private (current: %s); browsers or proxies may cache sensitive data.",
		why, detail,
	))
}
