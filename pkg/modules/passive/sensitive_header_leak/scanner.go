package sensitive_header_leak

import (
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// known token patterns -- name-anchored + value-anchored
type tokenPattern struct {
	name             string
	re               *regexp.Regexp
	publicIdentifier bool
}

var tokenPatterns = []tokenPattern{
	{name: "AWS Access Key ID", re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), publicIdentifier: true},
	{name: "AWS Temporary Access Key ID", re: regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`), publicIdentifier: true},
	{name: "Google API Key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), publicIdentifier: true},
	{name: "GitHub Personal Token", re: regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`)},
	{name: "GitHub Server-Server Token", re: regexp.MustCompile(`\bghs_[0-9A-Za-z]{36}\b`)},
	{name: "Slack Bot Token", re: regexp.MustCompile(`\bxox[abp]-[0-9A-Za-z\-]{10,}\b`)},
	{name: "JWT", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\b`)},
	{name: "Stripe Secret Key", re: regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`)},
}

// keyIVRe matches base64:base64 like the nginx-ui X-Backup-Security pattern.
var keyIVRe = regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}:[A-Za-z0-9+/=]{16,}$`)

// suspiciousHeaderNames contains substrings whose presence in the header
// name itself is enough to escalate the value through entropy analysis.
var suspiciousHeaderNames = []string{
	"key", "iv", "secret", "token", "password", "passwd", "auth", "signature",
	"hmac", "private", "session", "credential",
}

// lowSignalHeaderNames are redirect / auth-challenge response headers. A
// token-shaped value here — a JWT embedded in a Location redirect URL, a
// Cloudflare-Access challenge in Www-Authenticate — is a login-flow navigation
// artifact emitted by the framework or edge, far more often than the
// application deliberately leaking a secret in a custom header. We still report
// it (it can occasionally be real), but downgraded to informational/tentative.
var lowSignalHeaderNames = map[string]struct{}{
	"location": {}, "content-location": {}, "refresh": {},
	"www-authenticate": {}, "proxy-authenticate": {},
}

// safeHeaderNames are common response headers we never want to flag (they
// often contain high-entropy looking values that aren't secrets).
var safeHeaderNames = map[string]struct{}{
	"date": {}, "server": {}, "content-type": {}, "content-length": {},
	"content-encoding": {}, "transfer-encoding": {}, "connection": {},
	"vary": {}, "cache-control": {}, "etag": {}, "last-modified": {},
	"expires": {}, "accept-ranges": {}, "x-request-id": {}, "x-trace-id": {},
	"set-cookie":                {},
	"strict-transport-security": {}, "content-security-policy": {},
	"x-content-type-options": {}, "x-frame-options": {}, "x-xss-protection": {},
	"referrer-policy": {}, "permissions-policy": {}, "alt-svc": {},
	"cf-ray": {}, "cf-cache-status": {}, "x-amzn-requestid": {},
	"x-amzn-trace-id": {}, "x-cache": {},
}

// minEntropy below which we don't bother flagging (4.0 bits/char ~ 16 distinct
// chars uniformly).
const minEntropy = 4.0
const minEntropyValueLen = 24

var tokenLikeHeaderValue = regexp.MustCompile(`^[A-Za-z0-9_+/=.,:-]{24,}$`)
var embeddedTokenLikeHeaderValue = regexp.MustCompile(`(?:^|[=\"' ])([A-Za-z0-9_+/.-]{24,})(?:$|[\"' ,])`)

type headerAnalysis struct {
	reason          string
	observationOnly bool
}

type headerHit struct {
	header    string
	evidence  string
	reason    string
	candidate bool
}

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("passive_sensitive_header_leak"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if ctx.Response() == nil {
		return nil, nil
	}
	// A WAF/CDN edge block's headers are the edge's, not the application's, so a
	// high-entropy/token-shaped value in them is not the app leaking a secret.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	if ds := diskSet; ds != nil {
		dk := urlx.Host + urlx.Path
		if ds.IsSeen(dk) {
			return nil, nil
		}
	}

	var hits []headerHit
	for _, h := range ctx.Response().Headers() {
		nameLower := strings.ToLower(h.Name)
		if _, ok := safeHeaderNames[nameLower]; ok {
			continue
		}
		value := h.Value
		if value == "" {
			continue
		}
		if analysis := analyseHeader(nameLower, value); analysis.reason != "" {
			_, lowContext := lowSignalHeaderNames[nameLower]
			hits = append(hits, headerHit{
				header:    h.Name,
				evidence:  fmt.Sprintf("%s: %s", h.Name, maskHeaderValue(value)),
				reason:    analysis.reason,
				candidate: !analysis.observationOnly && !lowContext && !isRedirectStatus(ctx.Response().StatusCode()),
			})
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}

	// A 3xx redirect's headers carry login-flow navigation artifacts — a
	// Location-embedded SSO token, a Www-Authenticate challenge — and so do
	// redirect/auth-challenge headers on any status. In either case the value is
	// very likely not an application secret, so downgrade to informational /
	// tentative rather than reporting a Medium/Firm leak.
	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev, conf := severity.Info, severity.Tentative
	desc := fmt.Sprintf("Response from %s contains %d public-identifier, example, redirect, or authentication-flow header pattern(s). These are retained as observations without claiming secret exposure.", urlx.String(), len(hits))
	var extracted []string
	var reasons []string
	candidateCount := 0
	for _, hit := range hits {
		extracted = append(extracted, hit.evidence+" -> "+hit.reason)
		reasons = append(reasons, hit.header+": "+hit.reason)
		if hit.candidate {
			candidateCount++
		}
	}
	if candidateCount > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev, conf = severity.Medium, severity.Firm
		desc = fmt.Sprintf("Response from %s contains %d private-token-format or constrained high-entropy custom-header candidate(s). Values are masked; validity, ownership, and replay impact were not tested.", urlx.String(), candidateCount)
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: extracted,
			MatcherStatus:    true,
			Info: output.Info{
				Name:        "Sensitive Data in Response Headers",
				Description: desc,
				Severity:    sev,
				Confidence:  conf,
				Tags:        []string{"info-disclosure", "secrets", "headers"},
				Reference:   []string{"https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762"},
			},
			Metadata: map[string]any{
				"candidate_count":                    candidateCount,
				"hit_reasons":                        reasons,
				"credential_validated":               false,
				"set_cookie_owned_by_cookie_modules": true,
			},
		},
	}, nil
}

// isRedirectStatus reports whether code is a 3xx redirect.
func isRedirectStatus(code int) bool {
	return code >= 300 && code < 400
}

// analyseHeader returns a non-empty reason string if the header looks
// like it leaks sensitive data; "" otherwise.
func analyseHeader(name, value string) headerAnalysis {
	trimmed := strings.TrimSpace(value)
	for _, p := range tokenPatterns {
		if p.re.MatchString(trimmed) {
			return headerAnalysis{
				reason:          p.name,
				observationOnly: p.publicIdentifier || looksExampleOrMasked(trimmed),
			}
		}
	}
	if _, lowSignal := lowSignalHeaderNames[name]; lowSignal {
		if match := embeddedTokenLikeHeaderValue.FindStringSubmatch(trimmed); len(match) == 2 && shannonEntropy(match[1]) >= minEntropy {
			return headerAnalysis{reason: "high-entropy authentication-flow value", observationOnly: true}
		}
	}
	if keyIVRe.MatchString(trimmed) {
		// Check both halves are decodable as base64
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			if _, err1 := base64.StdEncoding.DecodeString(parts[0]); err1 == nil {
				if _, err2 := base64.StdEncoding.DecodeString(parts[1]); err2 == nil {
					return headerAnalysis{reason: "base64 key:iv pair", observationOnly: looksExampleOrMasked(trimmed)}
				}
			}
		}
	}
	if isSuspiciousName(name) && len(trimmed) >= minEntropyValueLen && tokenLikeHeaderValue.MatchString(trimmed) {
		ent := shannonEntropy(trimmed)
		if ent >= minEntropy {
			return headerAnalysis{
				reason:          fmt.Sprintf("high-entropy value in suspicious header (entropy=%.2f)", ent),
				observationOnly: looksExampleOrMasked(trimmed),
			}
		}
	}
	return headerAnalysis{}
}

func isSuspiciousName(n string) bool {
	parts := strings.FieldsFunc(strings.ToLower(n), func(r rune) bool {
		return r < 'a' || r > 'z'
	})
	for _, part := range parts {
		for _, s := range suspiciousHeaderNames {
			if part == s {
				return true
			}
		}
	}
	for _, compound := range []string{"api-key", "private-key", "access-token", "session-token", "client-secret", "auth-token"} {
		if strings.Contains(strings.ToLower(n), compound) {
			return true
		}
	}
	return false
}

func looksExampleOrMasked(value string) bool {
	if modkit.IsPlaceholderValue(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"example", "placeholder", "changeme", "dummy", "sample", "redacted", "your_", "your-"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Trim(value, "*xX._- ") == ""
}

func maskHeaderValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 8 {
		return "********"
	}
	return value[:4] + "…" + value[len(value)-4:]
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var ent float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
