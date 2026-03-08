package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// BodySizeAction indicates what to do when body size exceeds limits.
type BodySizeAction int

const (
	BodySizeOK       BodySizeAction = iota // Within limits
	BodySizeTruncate                       // Truncate and continue
	BodySizeDrop                           // Drop entirely
	BodySizeSkipScan                       // Save truncated but skip scan
)

// ScopeMatchInput holds the primitive values needed to evaluate scope rules.
// This avoids coupling the matcher to httpmsg types.
type ScopeMatchInput struct {
	Host                string
	Path                string
	StatusCode          int
	RequestContentType  string
	ResponseContentType string
	RequestRaw          string
	ResponseBody        string
}

// originTarget stores parsed origin data for a single CLI target.
type originTarget struct {
	exactHost string // lowercase hostname (e.g. "www.example.com")
	etldPlus1 string // eTLD+1 (e.g. "example.com"), empty for IPs
	keyword   string // domain label before TLD (e.g. "example"), empty for IPs
	isIP      bool   // true when target is an IP address
}

// ScopeMatcher evaluates whether HTTP records are in scope.
type ScopeMatcher struct {
	cfg           ScopeConfig
	hostCache     sync.Map        // cache: host string -> bool (result of host scope check)
	staticExts    map[string]bool // flattened set of static file extensions (lowercase, with leading dot)
	originMode    string          // "all", "strict", "balanced", "relaxed"
	originTargets []originTarget  // parsed targets for origin matching
}

// NewScopeMatcher creates a new ScopeMatcher from configuration.
// Optional targetHosts are the CLI -t target URLs used for cli_origin_mode filtering.
// Existing call sites that pass no targets continue to work (no origin filtering).
func NewScopeMatcher(cfg ScopeConfig, targetHosts ...string) *ScopeMatcher {
	m := &ScopeMatcher{cfg: cfg}
	if cfg.IgnoreStaticFile && len(cfg.IgnoreStaticContentType) > 0 {
		m.staticExts = make(map[string]bool)
		for _, exts := range cfg.IgnoreStaticContentType {
			for _, ext := range exts {
				ext = strings.ToLower(ext)
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				m.staticExts[ext] = true
			}
		}
	}

	// Set up origin mode filtering
	mode := strings.ToLower(strings.TrimSpace(cfg.CLIOriginMode))
	if mode == "" {
		mode = "relaxed"
	}
	m.originMode = mode
	if mode != "all" && len(targetHosts) > 0 {
		m.originTargets = parseOriginTargets(targetHosts)
	}

	return m
}

// InvalidateCache clears the cached host scope results.
// Call this if scope rules are changed on a live matcher.
func (m *ScopeMatcher) InvalidateCache() {
	m.hostCache = sync.Map{}
}

// hostInScope checks host against the Host scope rule AND origin mode with caching.
// Safe for concurrent use — sync.Map handles its own locking.
func (m *ScopeMatcher) hostInScope(host string) bool {
	if v, ok := m.hostCache.Load(host); ok {
		return v.(bool)
	}
	result := matchGlob(host, m.cfg.Host) && m.hostMatchesOrigin(host)
	m.hostCache.Store(host, result)
	return result
}

// IsStaticFile returns true if the URL path ends with a known static-asset extension.
func (m *ScopeMatcher) IsStaticFile(path string) bool {
	if len(m.staticExts) == 0 {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false
	}
	return m.staticExts[ext]
}

// CheckBodySize evaluates request and response body sizes against configured limits.
// Returns the action to take and the max allowed sizes for truncation.
func (m *ScopeMatcher) CheckBodySize(reqBodyLen, respBodyLen int) (action BodySizeAction, maxReq, maxResp int) {
	maxReqCfg := m.cfg.MaxRequestBodySize
	maxRespCfg := m.cfg.MaxResponseBodySize

	reqExceeds := maxReqCfg > 0 && int64(reqBodyLen) > maxReqCfg
	respExceeds := maxRespCfg > 0 && int64(respBodyLen) > maxRespCfg

	if !reqExceeds && !respExceeds {
		return BodySizeOK, reqBodyLen, respBodyLen
	}

	// Compute truncated sizes
	maxReq = reqBodyLen
	if reqExceeds {
		maxReq = int(maxReqCfg)
	}
	maxResp = respBodyLen
	if respExceeds {
		maxResp = int(maxRespCfg)
	}

	switch m.cfg.BodySizeExceededAction {
	case "drop":
		return BodySizeDrop, maxReq, maxResp
	case "skip-scan":
		return BodySizeSkipScan, maxReq, maxResp
	default:
		return BodySizeTruncate, maxReq, maxResp
	}
}

// InScope checks all scope rules and returns true if the record is in scope.
// All components are AND-ed: every rule must pass.
func (m *ScopeMatcher) InScope(input ScopeMatchInput) bool {
	if !m.hostInScope(input.Host) {
		return false
	}
	if !matchGlob(input.Path, m.cfg.Path) {
		return false
	}
	if m.IsStaticFile(input.Path) {
		return false
	}
	if !matchStatusCode(input.StatusCode, m.cfg.StatusCode) {
		return false
	}
	if !matchGlob(input.RequestContentType, m.cfg.RequestContentType) {
		return false
	}
	if !matchGlob(input.ResponseContentType, m.cfg.ResponseContentType) {
		return false
	}
	if !matchSubstring(input.RequestRaw, m.cfg.RequestString) {
		return false
	}
	if !matchSubstring(input.ResponseBody, m.cfg.ResponseString) {
		return false
	}
	return true
}

// InScopeBytes is like InScope but accepts raw []byte for request/response body
// to avoid string conversion allocations on the hot path.
func (m *ScopeMatcher) InScopeBytes(host, path string, statusCode int,
	reqContentType, respContentType string,
	requestRaw, responseBody []byte) bool {

	if !m.hostInScope(host) {
		return false
	}
	if !matchGlob(path, m.cfg.Path) {
		return false
	}
	if m.IsStaticFile(path) {
		return false
	}
	if !matchStatusCode(statusCode, m.cfg.StatusCode) {
		return false
	}
	if !matchGlob(reqContentType, m.cfg.RequestContentType) {
		return false
	}
	if !matchGlob(respContentType, m.cfg.ResponseContentType) {
		return false
	}
	if !matchSubstringBytes(requestRaw, m.cfg.RequestString) {
		return false
	}
	if !matchSubstringBytes(responseBody, m.cfg.ResponseString) {
		return false
	}
	return true
}

// InScopeRequest checks request-only scope rules (host, path, request content type, request string).
// Use this for pre-HTTP-call filtering to avoid unnecessary requests.
func (m *ScopeMatcher) InScopeRequest(host, path, reqContentType, reqRaw string) bool {
	if !m.hostInScope(host) {
		return false
	}
	if !matchGlob(path, m.cfg.Path) {
		return false
	}
	if m.IsStaticFile(path) {
		return false
	}
	if reqContentType != "" && !matchGlob(reqContentType, m.cfg.RequestContentType) {
		return false
	}
	if reqRaw != "" && !matchSubstring(reqRaw, m.cfg.RequestString) {
		return false
	}
	return true
}

// IsPassAll returns true if all rules are at their default pass-all state.
// Returns false when static file filtering is active (extensions exist),
// when body size limits are configured, or when origin mode filtering is active.
func (m *ScopeMatcher) IsPassAll() bool {
	if len(m.staticExts) > 0 {
		return false
	}
	if m.cfg.MaxRequestBodySize > 0 || m.cfg.MaxResponseBodySize > 0 {
		return false
	}
	if m.originMode != "" && m.originMode != "all" && len(m.originTargets) > 0 {
		return false
	}
	return isDefaultPassAll(m.cfg.Host) &&
		isDefaultPassAll(m.cfg.Path) &&
		isDefaultPassAll(m.cfg.StatusCode) &&
		isDefaultPassAll(m.cfg.RequestContentType) &&
		isDefaultPassAll(m.cfg.ResponseContentType) &&
		isDefaultPassAll(m.cfg.RequestString) &&
		isDefaultPassAll(m.cfg.ResponseString)
}

// matchGlob checks if value matches the glob patterns in the rule.
// Exclude takes priority over include. Empty include = match all.
func matchGlob(value string, rule ScopeRule) bool {
	if isDefaultPassAll(rule) {
		return true
	}

	valueLower := strings.ToLower(value)

	// Check excludes first (higher priority)
	for _, pattern := range rule.Exclude {
		if globMatch(valueLower, strings.ToLower(pattern)) {
			return false
		}
	}

	// If include is empty or only contains "*", match everything
	if len(rule.Include) == 0 || (len(rule.Include) == 1 && rule.Include[0] == "*") {
		return true
	}

	// Check includes
	for _, pattern := range rule.Include {
		if globMatch(valueLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// matchStatusCode checks if the status code matches the rule patterns.
// Supports exact codes ("200"), wildcard patterns ("2xx", "30*"), and ranges ("400-499").
func matchStatusCode(code int, rule ScopeRule) bool {
	if isDefaultPassAll(rule) {
		return true
	}

	codeStr := strconv.Itoa(code)

	// Check excludes first
	for _, pattern := range rule.Exclude {
		if statusCodeMatches(codeStr, code, pattern) {
			return false
		}
	}

	// If include is empty or only contains "*", match everything
	if len(rule.Include) == 0 || (len(rule.Include) == 1 && rule.Include[0] == "*") {
		return true
	}

	// Check includes
	for _, pattern := range rule.Include {
		if statusCodeMatches(codeStr, code, pattern) {
			return true
		}
	}

	return false
}

// matchSubstringBytes is like matchSubstring but operates on []byte to avoid allocation.
func matchSubstringBytes(value []byte, rule ScopeRule) bool {
	if isDefaultPassAll(rule) {
		return true
	}

	valueLower := bytes.ToLower(value)

	for _, pattern := range rule.Exclude {
		if bytes.Contains(valueLower, []byte(strings.ToLower(pattern))) {
			return false
		}
	}

	if len(rule.Include) == 0 {
		return true
	}

	for _, pattern := range rule.Include {
		if bytes.Contains(valueLower, []byte(strings.ToLower(pattern))) {
			return true
		}
	}

	return false
}

// matchSubstring checks if value contains any of the patterns (case-insensitive).
// Empty include = match all (no string filtering).
func matchSubstring(value string, rule ScopeRule) bool {
	if isDefaultPassAll(rule) {
		return true
	}

	valueLower := strings.ToLower(value)

	// Check excludes first
	for _, pattern := range rule.Exclude {
		if strings.Contains(valueLower, strings.ToLower(pattern)) {
			return false
		}
	}

	// Empty include = match all
	if len(rule.Include) == 0 {
		return true
	}

	// Check includes — at least one must match
	for _, pattern := range rule.Include {
		if strings.Contains(valueLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// isDefaultPassAll returns true if the rule is at its default pass-all state.
// A rule passes all when include is empty or ["*"] and exclude is empty.
func isDefaultPassAll(rule ScopeRule) bool {
	if len(rule.Exclude) > 0 {
		return false
	}
	if len(rule.Include) == 0 {
		return true
	}
	return len(rule.Include) == 1 && rule.Include[0] == "*"
}

// globMatch performs glob-style matching using filepath.Match.
// It also handles leading wildcard patterns like "*.example.com".
func globMatch(value, pattern string) bool {
	if pattern == "*" {
		return true
	}
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		return false
	}
	return matched
}

// statusCodeMatches checks if a status code matches a pattern.
// Patterns: exact ("200"), wildcard ("2xx", "2*", "20*"), range ("400-499").
func statusCodeMatches(codeStr string, code int, pattern string) bool {
	pattern = strings.TrimSpace(pattern)

	// Range pattern: "400-499"
	if strings.Contains(pattern, "-") {
		parts := strings.SplitN(pattern, "-", 2)
		if len(parts) == 2 {
			low, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			high, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil {
				return code >= low && code <= high
			}
		}
	}

	// Wildcard patterns: "2xx", "2*", "20*"
	// Replace 'x' with '*' for uniform handling
	normalized := strings.ReplaceAll(strings.ToLower(pattern), "x", "*")
	if strings.Contains(normalized, "*") {
		matched, err := filepath.Match(normalized, codeStr)
		if err == nil && matched {
			return true
		}
		// Also try class matching: "2*" should match "200", "201", etc.
		// filepath.Match("2*", "200") works since * matches any sequence
		// But "2**" from "2xx" won't work, use prefix matching
		prefix := strings.TrimRight(normalized, "*")
		if prefix != "" && strings.HasPrefix(codeStr, prefix) {
			return true
		}
		return false
	}

	// Exact match
	return codeStr == fmt.Sprintf("%d", mustAtoi(pattern, 0))
}

// parseOriginTargets extracts origin data from a list of target URLs/hosts.
// Deduplicates by exactHost.
func parseOriginTargets(targets []string) []originTarget {
	seen := make(map[string]struct{})
	var result []originTarget
	for _, t := range targets {
		host := extractHostFromTarget(t)
		if host == "" {
			continue
		}
		host = strings.ToLower(host)
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}

		ot := originTarget{exactHost: host}

		// Check if the host is an IP address
		if net.ParseIP(host) != nil {
			ot.isIP = true
			result = append(result, ot)
			continue
		}

		// Extract eTLD+1 using publicsuffix
		if etld, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
			ot.etldPlus1 = etld
			// Extract keyword: the label before the TLD portion
			// For "example.com" → "example", for "example.co.uk" → "example"
			tldPart := etld[strings.Index(etld, ".")+1:]
			ot.keyword = strings.TrimSuffix(etld, "."+tldPart)
		}

		result = append(result, ot)
	}
	return result
}

// extractHostFromTarget parses a URL or bare host string, returning the lowercase hostname without port.
func extractHostFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	// Try parsing as URL first
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}

	// Treat as bare host (possibly with port)
	host := target
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// hostMatchesOrigin checks whether a host matches any of the configured origin targets.
// Returns true when origin mode is "all" or no targets are configured.
func (m *ScopeMatcher) hostMatchesOrigin(host string) bool {
	if m.originMode == "all" || len(m.originTargets) == 0 {
		return true
	}
	hostLower := strings.ToLower(host)
	for i := range m.originTargets {
		if m.hostMatchesSingleOrigin(hostLower, &m.originTargets[i]) {
			return true
		}
	}
	return false
}

// hostMatchesSingleOrigin checks if a host matches a single origin target per the current mode.
func (m *ScopeMatcher) hostMatchesSingleOrigin(host string, ot *originTarget) bool {
	// IP targets always require exact match regardless of mode
	if ot.isIP {
		return host == ot.exactHost
	}

	switch m.originMode {
	case "strict":
		return host == ot.exactHost
	case "balanced":
		if ot.etldPlus1 == "" {
			return host == ot.exactHost
		}
		hostETLD, err := publicsuffix.EffectiveTLDPlusOne(host)
		if err != nil {
			return false
		}
		return hostETLD == ot.etldPlus1
	case "relaxed":
		if ot.keyword == "" {
			return host == ot.exactHost
		}
		return strings.Contains(host, ot.keyword)
	default: // "all"
		return true
	}
}

func mustAtoi(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return n
}
