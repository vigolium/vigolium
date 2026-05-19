// Package waf provides WAF/CDN blocking detection implementation.
package waf

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// Rule defines detection logic for a specific WAF/CDN.
type Rule struct {
	// Name identifies the WAF/CDN (e.g., "cloudflare", "akamai").
	Name string

	// Priority determines check order (lower = checked first).
	Priority int

	// StatusCodes that may indicate blocking (empty = any status).
	StatusCodes []int

	// HeaderChecks are fast header-based detection checks.
	HeaderChecks []HeaderCheck

	// BodyChecks are slower body-based detection checks.
	BodyChecks []BodyCheck
}

// HeaderCheck defines a header-based detection rule.
type HeaderCheck struct {
	// Header name to check (case-insensitive).
	Header string

	// Contains checks if header value contains this substring.
	Contains string

	// Equals checks if header value equals this exactly.
	Equals string

	// Pattern checks if header value matches this regex.
	Pattern *regexp.Regexp

	// Exists checks if header is present (value doesn't matter).
	Exists bool
}

// BodyCheck defines a body-based detection rule.
type BodyCheck struct {
	// Contains checks if body contains this substring.
	Contains string

	// Pattern checks if body matches this regex.
	Pattern *regexp.Regexp
}

// detector implements Detector interface.
// Uses a rule-based approach to detect WAF/CDN blocking responses.
type detector struct {
	rules []Rule
}

// NewDetector creates a new WAF detector with default rules.
func NewDetector() Detector {
	return &detector{
		rules: defaultRules(),
	}
}

// Detect analyzes an HTTP response for WAF/CDN blocking patterns.
// Returns nil if response is not detected as a WAF block.
func (d *detector) Detect(rc *responsechain.ResponseChain) *BlockResult {
	if rc == nil || !rc.Has() {
		return nil
	}

	resp := rc.Response()
	body := rc.BodyBytes()
	statusCode := resp.StatusCode

	// Fast path: skip non-blocking status codes
	if !isBlockingStatusCode(statusCode) {
		return nil
	}

	// Check each rule in priority order
	for _, rule := range d.rules {
		if result := d.matchRule(rule, resp, body, statusCode); result != nil {
			return result
		}
	}

	return nil
}

// matchRule checks if a response matches a specific WAF rule.
func (d *detector) matchRule(rule Rule, resp *http.Response, body []byte, statusCode int) *BlockResult {
	// Check status code if rule has specific codes
	if len(rule.StatusCodes) > 0 && !containsInt(rule.StatusCodes, statusCode) {
		return nil
	}

	var indicators []string

	// Check headers first (faster)
	headerMatched := false
	for _, check := range rule.HeaderChecks {
		if indicator := matchHeader(resp.Header, check); indicator != "" {
			indicators = append(indicators, indicator)
			headerMatched = true
		}
	}

	// Check body patterns
	bodyMatched := false
	for _, check := range rule.BodyChecks {
		if indicator := matchBody(body, check); indicator != "" {
			indicators = append(indicators, indicator)
			bodyMatched = true
		}
	}

	// Rule matches if we have any indicators
	if headerMatched || bodyMatched {
		return &BlockResult{
			IsBlocked:  true,
			WAFType:    rule.Name,
			Indicators: indicators,
		}
	}

	return nil
}

// matchHeader checks if a header matches a HeaderCheck.
func matchHeader(headers http.Header, check HeaderCheck) string {
	value := headers.Get(check.Header)

	if check.Exists {
		if value != "" {
			return "header:" + check.Header
		}
		return ""
	}

	if value == "" {
		return ""
	}

	if check.Equals != "" && strings.EqualFold(value, check.Equals) {
		return "header:" + check.Header + "=" + check.Equals
	}

	if check.Contains != "" && strings.Contains(strings.ToLower(value), strings.ToLower(check.Contains)) {
		return "header:" + check.Header + " contains " + check.Contains
	}

	if check.Pattern != nil && check.Pattern.MatchString(value) {
		return "header:" + check.Header + " matches pattern"
	}

	return ""
}

// matchBody checks if body matches a BodyCheck.
func matchBody(body []byte, check BodyCheck) string {
	if len(body) == 0 {
		return ""
	}

	if check.Contains != "" {
		if bytes.Contains(bytes.ToLower(body), []byte(strings.ToLower(check.Contains))) {
			return "body contains: " + truncate(check.Contains, 50)
		}
	}

	if check.Pattern != nil && check.Pattern.Match(body) {
		return "body matches pattern"
	}

	return ""
}

// isBlockingStatusCode returns true for status codes commonly used by WAFs.
func isBlockingStatusCode(code int) bool {
	switch code {
	case 403, 405, 406, 429, 501, 503:
		return true
	}
	// Cloudflare specific codes
	if code >= 520 && code <= 530 {
		return true
	}
	return false
}

// containsInt checks if slice contains value.
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// truncate shortens a string for display.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// defaultRules returns the built-in WAF detection rules.
func defaultRules() []Rule {
	return []Rule{
		cloudflareRule(),
		akamaiRule(),
		awsWAFRule(),
		f5BigIPRule(),
		impervaRule(),
		sucuriRule(),
		modsecurityRule(),
		genericRule(),
	}
}

func cloudflareRule() Rule {
	return Rule{
		Name:        "cloudflare",
		Priority:    1,
		StatusCodes: []int{403, 429, 503, 520, 521, 522, 523, 524, 525, 526, 527, 530},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "cloudflare"},
			{Header: "Cf-Ray", Exists: true},
			{Header: "Cf-Mitigated", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Attention Required! | Cloudflare"},
			{Contains: "Access denied | Cloudflare"},
			{Contains: "cf-error-code"},
			{Contains: "Just a moment..."},
			{Contains: "challenges.cloudflare.com"},
			{Contains: "Cloudflare Ray ID"},
			{Contains: "_cf_chl_opt"},
			{Pattern: regexp.MustCompile(`(?i)error code:?\s*10[0-9]{2}`)}, // 1010, 1015, 1020, etc.
		},
	}
}

func akamaiRule() Rule {
	return Rule{
		Name:        "akamai",
		Priority:    2,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "AkamaiGHost"},
			{Header: "X-Akamai-Transformed", Exists: true},
			{Header: "Akamai-Origin-Hop", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Access Denied"},
			{Contains: "Your access to this service has been temporarily limited"},
			{Contains: "ak_bmsc"},
			{Contains: "_abck"},
			{Pattern: regexp.MustCompile(`Reference\s*#?\s*[0-9]+\.[0-9a-f]+`)},
		},
	}
}

func awsWAFRule() Rule {
	return Rule{
		Name:        "aws_waf",
		Priority:    3,
		StatusCodes: []int{403, 429, 405},
		HeaderChecks: []HeaderCheck{
			{Header: "X-Amzn-Waf-Action", Exists: true},
			{Header: "X-Amz-Cf-Id", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "awswaf"},
			{Contains: "AWS WAF"},
			{Contains: "Request blocked"},
			{Contains: "captcha.awswaf.com"},
			{Contains: "window.gokuProps"},
		},
	}
}

func f5BigIPRule() Rule {
	return Rule{
		Name:        "f5_bigip",
		Priority:    4,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "BIG-IP"},
			{Header: "Server", Contains: "BigIP"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "The requested URL was rejected"},
			{Contains: "support ID"},
			{Contains: "BIG-IP"},
			{Pattern: regexp.MustCompile(`support ID is:?\s*[0-9]+`)},
		},
	}
}

func impervaRule() Rule {
	return Rule{
		Name:        "imperva",
		Priority:    5,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "X-Iinfo", Exists: true},
			{Header: "X-CDN", Contains: "Incapsula"},
			{Header: "X-CDN", Contains: "Imperva"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Incapsula incident ID"},
			{Contains: "Request unsuccessful"},
			{Contains: "_Incapsula_"},
			{Contains: "visid_incap_"},
			{Contains: "Powered by Incapsula"},
			{Pattern: regexp.MustCompile(`Incapsula incident ID:\s*[0-9]+-[0-9]+`)},
		},
	}
}

func sucuriRule() Rule {
	return Rule{
		Name:        "sucuri",
		Priority:    6,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "Sucuri"},
			{Header: "X-Sucuri-ID", Exists: true},
			{Header: "X-Sucuri-Cache", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Sucuri WebSite Firewall"},
			{Contains: "Access Denied - Sucuri Website Firewall"},
			{Contains: "sucuri.net/privacy-policy"},
			{Contains: "cloudproxy@sucuri.net"},
		},
	}
}

func modsecurityRule() Rule {
	return Rule{
		Name:        "modsecurity",
		Priority:    7,
		StatusCodes: []int{403, 406, 429, 501},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "ModSecurity"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Mod_Security"},
			{Contains: "ModSecurity"},
			{Contains: "NAXSI"},
			{Contains: "This error was generated by Mod_Security"},
			{Pattern: regexp.MustCompile(`(?i)not acceptable.*?security module`)},
		},
	}
}

func genericRule() Rule {
	return Rule{
		Name:         "generic",
		Priority:     99, // Lowest priority - fallback
		StatusCodes:  []int{403, 429},
		HeaderChecks: []HeaderCheck{},
		BodyChecks: []BodyCheck{
			{Contains: "Access Denied"},
			{Contains: "Request Blocked"},
			{Contains: "You have been blocked"},
			{Contains: "Your IP has been blocked"},
			{Contains: "Rate limit exceeded"},
			{Contains: "Too many requests"},
			{Contains: "Forbidden"},
			{Contains: "blocked by"},
		},
	}
}
