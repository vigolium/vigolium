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
	name string
	re   *regexp.Regexp
}

var tokenPatterns = []tokenPattern{
	{name: "AWS Access Key ID", re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{name: "AWS Session Token", re: regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`)},
	{name: "Google API Key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
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

// safeHeaderNames are common response headers we never want to flag (they
// often contain high-entropy looking values that aren't secrets).
var safeHeaderNames = map[string]struct{}{
	"date": {}, "server": {}, "content-type": {}, "content-length": {},
	"content-encoding": {}, "transfer-encoding": {}, "connection": {},
	"vary": {}, "cache-control": {}, "etag": {}, "last-modified": {},
	"expires": {}, "accept-ranges": {}, "x-request-id": {}, "x-trace-id": {},
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

	if ds := m.ds.Get(scanCtx.DedupMgr()); ds != nil {
		dk := urlx.Host + urlx.Path
		if ds.IsSeen(dk) {
			return nil, nil
		}
	}

	var hits []string
	for _, h := range ctx.Response().Headers() {
		nameLower := strings.ToLower(h.Name)
		if _, ok := safeHeaderNames[nameLower]; ok {
			continue
		}
		value := h.Value
		if value == "" {
			continue
		}
		if reason := analyseHeader(nameLower, value); reason != "" {
			hits = append(hits, fmt.Sprintf("%s: %s -> %s", h.Name, truncate(value, 80), reason))
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: hits,
			MatcherStatus:    true,
			Info: output.Info{
				Name:        "Sensitive Data in Response Headers",
				Description: fmt.Sprintf("Response from %s discloses %d sensitive value(s) in custom response headers.", urlx.String(), len(hits)),
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"info-disclosure", "secrets", "headers"},
				Reference:   []string{"https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762"},
			},
		},
	}, nil
}

// analyseHeader returns a non-empty reason string if the header looks
// like it leaks sensitive data; "" otherwise.
func analyseHeader(name, value string) string {
	for _, p := range tokenPatterns {
		if p.re.MatchString(value) {
			return p.name
		}
	}
	if keyIVRe.MatchString(strings.TrimSpace(value)) {
		// Check both halves are decodable as base64
		parts := strings.SplitN(strings.TrimSpace(value), ":", 2)
		if len(parts) == 2 {
			if _, err1 := base64.StdEncoding.DecodeString(parts[0]); err1 == nil {
				if _, err2 := base64.StdEncoding.DecodeString(parts[1]); err2 == nil {
					return "base64 key:iv pair"
				}
			}
		}
	}
	if isSuspiciousName(name) && len(value) >= minEntropyValueLen {
		ent := shannonEntropy(value)
		if ent >= minEntropy {
			return fmt.Sprintf("high-entropy value in suspicious header (entropy=%.2f)", ent)
		}
	}
	return ""
}

func isSuspiciousName(n string) bool {
	for _, s := range suspiciousHeaderNames {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
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
