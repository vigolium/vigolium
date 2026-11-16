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
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/pathglob"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
)

// BodySizeAction indicates what to do when body size exceeds limits.
type BodySizeAction int

const (
	BodySizeOK          BodySizeAction = iota // Within limits
	BodySizeTruncate                          // Truncate and continue
	BodySizeDrop                              // Drop entirely
	BodySizeSkipScan                          // Save truncated but skip scan
	BodySizePassiveOnly                       // Run passive modules only, skip active
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
	cfg          ScopeConfig
	hostCache    sync.Map        // cache: host string -> bool (result of host scope check)
	dynamicHosts sync.Map        // hosts allowed at runtime (exact match, lowercased) -> struct{}
	hasDynamic   atomic.Bool     // true once AllowHost is called; gates the dynamicHosts lookup off the hot path
	staticExts   map[string]bool // flattened set of static file extensions (lowercase, with leading dot)
	originMode   string          // "all", "strict", "balanced", "relaxed"
	originIndex  originIndex     // the CLI targets compiled into mode-specific lookups
}

// originIndex is the parsed CLI targets rearranged into what each mode asks.
//
// The membership question used to be answered by walking every origin target per
// candidate host, recomputing the CANDIDATE's registrable domain inside that loop
// for balanced and relaxed mode. On a host sweep that is the worst case in both
// dimensions: every host is distinct, so the repeat-host cache never helps, and
// the work is targets × hosts with a public-suffix lookup in the middle of it. A
// few hundred targets hid it; a list of tens of thousands does not.
//
// The sets answer the identical question — see hostMatchesOrigin for the
// per-mode equivalence — so this is a data-structure change and nothing else. It
// must stay that way: widening what these sets contain widens the scan's scope.
type originIndex struct {
	// exactHosts is every target's hostname. It is the whole answer for strict
	// mode, and the first half of the answer for the other two: an exact hostname
	// hit satisfies balanced and relaxed as well, either through their empty-field
	// fallbacks or because a host is trivially inside its own registrable domain.
	exactHosts map[string]struct{}
	// etldPlus1 are the registrable domains balanced mode accepts.
	etldPlus1 map[string]struct{}
	// keywords are the distinct registrable labels relaxed mode substring-matches
	// against the candidate's own registrable label. A slice because Contains is
	// not a lookup; deduplicated because a target list often repeats one brand.
	keywords []string
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

	// Set up origin mode filtering. Same resolution the banner and the scans row
	// report, so what is applied and what is recorded cannot drift.
	mode := ResolveCLIOriginMode(cfg.CLIOriginMode)
	m.originMode = mode
	if mode != "all" && len(targetHosts) > 0 {
		m.originIndex = buildOriginIndex(parseOriginTargets(targetHosts), mode)
	}

	return m
}

// buildOriginIndex compiles parsed origin targets into the lookups
// hostMatchesOrigin uses for mode.
//
// Only the structures that mode reads are built. Strict mode consults nothing
// but exactHosts, so on a target list of tens of thousands - the size that
// motivated the index - building the softened-match sets too would retain two
// large maps that nothing would ever read.
func buildOriginIndex(targets []originTarget, mode string) originIndex {
	idx := originIndex{exactHosts: make(map[string]struct{}, len(targets))}
	// hostMatchesOrigin reads etldPlus1 only in the balanced arm and keywords only
	// in the relaxed arm — never both — so build strictly the one that mode asks
	// for. Building both would retain a large map nothing reads, which is the very
	// thing this index exists to avoid.
	wantETLD := mode == "balanced"
	wantKeywords := mode == "relaxed"
	if wantETLD {
		idx.etldPlus1 = make(map[string]struct{}, len(targets))
	}
	var seenKeyword map[string]struct{}
	if wantKeywords {
		seenKeyword = make(map[string]struct{}, len(targets))
	}
	for i := range targets {
		ot := &targets[i]
		idx.exactHosts[ot.exactHost] = struct{}{}
		// IPs never soften into a domain: they match exactly in every mode, and
		// parseOriginTargets leaves both derived fields empty for them.
		if ot.isIP {
			continue
		}
		if wantETLD && ot.etldPlus1 != "" {
			idx.etldPlus1[ot.etldPlus1] = struct{}{}
		}
		// Checked separately from etldPlus1 rather than folded into it: a
		// registrable domain can exist while its leading label is empty, and
		// relaxed mode falls back to the exact host in exactly that case.
		if !wantKeywords || ot.keyword == "" {
			continue
		}
		// A short label substring-matches unrelated domains ("a.io" admits
		// banana.com), so relaxed mode keeps only the exact host for it.
		if len(ot.keyword) < minRelaxedKeywordLen {
			warnShortRelaxedKeyword(ot.keyword)
			continue
		}
		if _, dup := seenKeyword[ot.keyword]; !dup {
			seenKeyword[ot.keyword] = struct{}{}
			idx.keywords = append(idx.keywords, ot.keyword)
		}
	}
	return idx
}

// minRelaxedKeywordLen is the shortest registrable label relaxed mode will
// substring-match.
const minRelaxedKeywordLen = 4

var shortKeywordWarned sync.Map

func warnShortRelaxedKeyword(keyword string) {
	if _, dup := shortKeywordWarned.LoadOrStore(keyword, struct{}{}); dup {
		return
	}
	zap.L().Warn("Relaxed scope: target label too short to match as a keyword; only its exact host is in scope",
		zap.String("keyword", keyword), zap.Int("min_length", minRelaxedKeywordLen))
}

// InvalidateCache clears the cached host scope results.
// Call this if scope rules are changed on a live matcher.
func (m *ScopeMatcher) InvalidateCache() {
	m.hostCache = sync.Map{}
}

// AllowHost adds an exact host to the runtime allow-set so it passes the host
// scope check regardless of the configured Host rule or origin mode. Used by the
// subdomain_harvest module under --follow-subdomains to pull specific discovered
// subdomains into scope WITHOUT wildcarding the apex. Safe for concurrent use.
func (m *ScopeMatcher) AllowHost(host string) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return
	}
	m.dynamicHosts.Store(h, struct{}{})
	m.hasDynamic.Store(true)
}

// hostInScope checks host against the Host scope rule AND origin mode with caching.
// Safe for concurrent use — sync.Map handles its own locking.
func (m *ScopeMatcher) hostInScope(host string) bool {
	// Runtime allow-set wins over the configured rule and any cached negative —
	// checked first so a host that was rejected before AllowHost still passes.
	if m.dynamicallyAllowed(host) {
		return true
	}
	if v, ok := m.hostCache.Load(host); ok {
		return v.(bool)
	}
	result := matchGlob(host, m.cfg.Host) && m.hostMatchesOrigin(host)
	m.hostCache.Store(host, result)
	return result
}

// dynamicallyAllowed reports whether host was added through AllowHost. Gated on
// hasDynamic so the default scan (no AllowHost) skips the ToLower + map lookup
// on the hot path entirely.
func (m *ScopeMatcher) dynamicallyAllowed(host string) bool {
	if !m.hasDynamic.Load() {
		return false
	}
	_, ok := m.dynamicHosts.Load(strings.ToLower(host))
	return ok
}

// Scope rejection rules returned by RejectReason. They name the configuration
// key (or filter) that refused the target, so an operator can fix the right one.
const (
	ScopeRuleHostExclude   = "scope.host.exclude"
	ScopeRuleHostInclude   = "scope.host.include"
	ScopeRuleCLIOriginMode = "scope.cli_origin_mode"
	ScopeRulePathExclude   = "scope.path.exclude"
	ScopeRulePathInclude   = "scope.path.include"
	ScopeRuleStaticFile    = "static_file"
)

// RejectReason explains InScopeRequest(host, path, "", ""): it returns "" when
// the pair is in scope, else the first rule that refused it, one of the
// ScopeRule* constants.
//
// It walks the same checks in the same order as InScopeRequest — the runtime
// allow-set, the host rule (exclude before include), the CLI origin mode, the
// path rule, the static-file filter — through the same helpers, so the verdict
// and its explanation cannot disagree. It bypasses the host cache (which stores
// only the boolean) and is meant for per-target explanations, not the per-item
// hot path.
//
// Nil-safe: a scan with no matcher rejects nothing.
func (m *ScopeMatcher) RejectReason(host, path string) string {
	rule, _ := m.RejectDetail(host, path)
	return rule
}

// RejectDetail is RejectReason plus the pattern responsible: the exclude
// pattern that matched, the include list that admitted nothing, the origin
// mode, or the static extension. Both are "" when host/path is in scope.
func (m *ScopeMatcher) RejectDetail(host, path string) (rule, pattern string) {
	if m == nil {
		return "", ""
	}
	if !m.dynamicallyAllowed(host) {
		switch v, p := evalGlobWith(host, m.cfg.Host, globMatch); v {
		case globExcluded:
			return ScopeRuleHostExclude, p
		case globNotIncluded:
			return ScopeRuleHostInclude, strings.Join(m.cfg.Host.Include, ", ")
		}
		if !m.hostMatchesOrigin(host) {
			return ScopeRuleCLIOriginMode, m.cfg.CLIOriginMode
		}
	}
	scopePath := pathglob.ScopePath(path)
	switch v, p := evalGlobWith(scopePath, m.cfg.Path, pathGlobMatch); v {
	case globExcluded:
		return ScopeRulePathExclude, p
	case globNotIncluded:
		return ScopeRulePathInclude, strings.Join(m.cfg.Path.Include, ", ")
	}
	if m.IsStaticFile(path) {
		return ScopeRuleStaticFile, filepath.Ext(scopePath)
	}
	return "", ""
}

// HostInScope reports whether host is within the configured scope (host rule +
// origin mode + runtime allow-set). It is the exported, host-only view of the
// scope used, e.g., to decide whether a known-vendor host is actually the scan
// target (in scope) rather than a third-party resource loaded by the target.
func (m *ScopeMatcher) HostInScope(host string) bool {
	if m == nil {
		return false
	}
	return m.hostInScope(host)
}

// hostIncludeNamesHosts reports whether an include list admits only the
// hosts it names: non-empty, and without a "*" (which admits every host
// whatever else is listed, as globMatch does).
func hostIncludeNamesHosts(include []string) bool {
	named := false
	for _, p := range include {
		switch strings.TrimSpace(p) {
		case "*":
			return false
		case "":
		default:
			named = true
		}
	}
	return named
}

// RestrictsHosts reports whether the scope names which hosts are allowed: a
// scope.host.include other than "*", or CLI targets under an origin mode other
// than "all". An exclude-only or empty host rule admits every host it does not
// name, so it is not a scope a fail-closed caller can rely on (--require-scope).
//
// Nil-safe: no matcher restricts nothing.
func (m *ScopeMatcher) RestrictsHosts() bool {
	if m == nil {
		return false
	}
	if hostIncludeNamesHosts(m.cfg.Host.Include) {
		return true
	}
	return m.originMode != "" && m.originMode != "all" && len(m.originIndex.exactHosts) > 0
}

// ExplicitlyExcluded reports whether host or path matches an operator-written
// exclude pattern — scope.host.exclude or scope.path.exclude — and nothing else.
//
// It is deliberately narrower than InScope. Include lists, origin mode, the
// static-file filter and the runtime allow-set are all ignored, so an
// include-only configuration excludes nothing here. The question it answers is
// "did the operator name this and say no", which is the only scope decision safe
// to enforce BEFORE a request leaves (triage C12): enforcing the include side
// pre-send would silently narrow discovery to the include list, which is not what
// an include list means.
//
// Nil-safe: a scan with no matcher excludes nothing.
func (m *ScopeMatcher) ExplicitlyExcluded(host, path string) bool {
	if m == nil {
		return false
	}
	return matchesExcludeRule(host, m.cfg.Host) ||
		matchesExcludeRuleWith(pathglob.ScopePath(path), m.cfg.Path, pathGlobMatch)
}

// matchesExcludeRule reports whether value matches one of rule's exclude globs.
// Unlike matchGlob it never consults Include and never short-circuits on
// isDefaultPassAll, because a rule with excludes is not pass-all and a rule
// without them is not an exclusion.
func matchesExcludeRule(value string, rule ScopeRule) bool {
	return matchesExcludeRuleWith(value, rule, globMatch)
}

func matchesExcludeRuleWith(value string, rule ScopeRule, match func(value, pattern string) bool) bool {
	_, ok := excludePatternWith(value, rule, match)
	return ok
}

// excludePatternWith is the first of rule's exclude patterns value matches.
func excludePatternWith(value string, rule ScopeRule, match func(value, pattern string) bool) (string, bool) {
	if len(rule.Exclude) == 0 {
		return "", false
	}
	valueLower := strings.ToLower(value)
	for _, pattern := range rule.Exclude {
		if match(valueLower, strings.ToLower(pattern)) {
			return pattern, true
		}
	}
	return "", false
}

// IsStaticFile returns true if the URL path ends with a known static-asset extension.
func (m *ScopeMatcher) IsStaticFile(path string) bool {
	if len(m.staticExts) == 0 {
		return false
	}
	ext := strings.ToLower(filepath.Ext(pathglob.ScopePath(path)))
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
	case "passive-only":
		return BodySizePassiveOnly, maxReq, maxResp
	default:
		return BodySizeTruncate, maxReq, maxResp
	}
}

// Scope rule classes: the component of the scope config that refused a record.
// InScopeWithReason and RejectClassBytes name one of these; the scan document
// counts drops by them (scope_dropped).
const (
	ScopeClassHost                = "host"
	ScopeClassPath                = "path"
	ScopeClassStaticFile          = "static_file"
	ScopeClassStatusCode          = "status_code"
	ScopeClassRequestContentType  = "request_content_type"
	ScopeClassResponseContentType = "response_content_type"
	ScopeClassRequestString       = "request_string"
	ScopeClassResponseString      = "response_string"
)

// InScope checks all scope rules and returns true if the record is in scope.
// All components are AND-ed: every rule must pass.
func (m *ScopeMatcher) InScope(input ScopeMatchInput) bool {
	ok, _ := m.InScopeWithReason(input)
	return ok
}

// InScopeWithReason is InScope that also names the rule class that refused the
// record ("" when it is in scope).
func (m *ScopeMatcher) InScopeWithReason(input ScopeMatchInput) (bool, string) {
	class := m.rejectClass(input.Host, input.Path, input.StatusCode, input.RequestContentType, input.ResponseContentType,
		func() bool { return matchSubstring(input.RequestRaw, m.cfg.RequestString) },
		func() bool { return matchSubstring(input.ResponseBody, m.cfg.ResponseString) })
	return class == "", class
}

// InScopeBytes is like InScope but accepts raw []byte for request/response body
// to avoid string conversion allocations on the hot path.
func (m *ScopeMatcher) InScopeBytes(host, path string, statusCode int,
	reqContentType, respContentType string,
	requestRaw, responseBody []byte) bool {
	return m.RejectClassBytes(host, path, statusCode, reqContentType, respContentType, requestRaw, responseBody) == ""
}

// RejectClassBytes names the rule class that refuses the record, "" when it is
// in scope. The []byte form of InScopeWithReason.
func (m *ScopeMatcher) RejectClassBytes(host, path string, statusCode int,
	reqContentType, respContentType string,
	requestRaw, responseBody []byte) string {
	return m.rejectClass(host, path, statusCode, reqContentType, respContentType,
		func() bool { return matchSubstringBytes(requestRaw, m.cfg.RequestString) },
		func() bool { return matchSubstringBytes(responseBody, m.cfg.ResponseString) })
}

// rejectClass applies every rule in order and names the first that refuses.
// The body rules are closures so each caller keeps its own string/[]byte form.
func (m *ScopeMatcher) rejectClass(host, path string, statusCode int, reqContentType, respContentType string,
	requestOK, responseOK func() bool) string {
	switch {
	case !m.hostInScope(host):
		return ScopeClassHost
	case !matchPathGlob(path, m.cfg.Path):
		return ScopeClassPath
	case m.IsStaticFile(path):
		return ScopeClassStaticFile
	case !matchStatusCode(statusCode, m.cfg.StatusCode):
		return ScopeClassStatusCode
	case !matchGlob(reqContentType, m.cfg.RequestContentType):
		return ScopeClassRequestContentType
	case !matchGlob(respContentType, m.cfg.ResponseContentType):
		return ScopeClassResponseContentType
	case !requestOK():
		return ScopeClassRequestString
	case !responseOK():
		return ScopeClassResponseString
	}
	return ""
}

// RequestRejectClass names the rule class InScopeRequest (static files
// included) or, with targetOnly, InScopeTarget refuses host/path with; "" when
// in scope.
func (m *ScopeMatcher) RequestRejectClass(host, path string, targetOnly bool) string {
	switch {
	case !m.hostInScope(host):
		return ScopeClassHost
	case !matchPathGlob(path, m.cfg.Path):
		return ScopeClassPath
	case !targetOnly && m.IsStaticFile(path):
		return ScopeClassStaticFile
	}
	return ""
}

// InScopeRequest checks request-only scope rules (host, path, request content type, request string).
// Use this for pre-HTTP-call filtering to avoid unnecessary requests.
func (m *ScopeMatcher) InScopeRequest(host, path, reqContentType, reqRaw string) bool {
	if !m.hostInScope(host) {
		return false
	}
	if !matchPathGlob(path, m.cfg.Path) {
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

// InScopeTarget is InScopeRequest without the static-file carve-out: the host
// and path rules only (the query is ignored). For a caller that asks for a
// static asset on purpose (the fingerprint phase's favicon, the senders'
// scope gate), where the carve-out's "never worth a request" does not hold.
// RejectDetail names the rule that refused a pair it rejects.
//
// Nil-safe: no matcher admits every target.
func (m *ScopeMatcher) InScopeTarget(host, path string) bool {
	if m == nil {
		return true
	}
	return m.hostInScope(host) && matchPathGlob(path, m.cfg.Path)
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
	if m.originMode != "" && m.originMode != "all" && len(m.originIndex.exactHosts) > 0 {
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

// globVerdict is evalGlob's answer: pass, or which side of the rule refused.
type globVerdict uint8

const (
	globPass        globVerdict = iota
	globExcluded                // matched an exclude pattern
	globNotIncluded             // matched no include pattern
)

// matchGlob checks if value matches the glob patterns in the rule.
// Exclude takes priority over include. Empty include = match all.
func matchGlob(value string, rule ScopeRule) bool {
	return evalGlob(value, rule) == globPass
}

// matchPathGlob is matchGlob for the path rule: the query and fragment are
// cut off and "*" crosses "/" (pathglob).
func matchPathGlob(path string, rule ScopeRule) bool {
	return evalPathGlob(path, rule) == globPass
}

// pathGlobMatch adapts pathglob.Match to the (value, pattern) order the rule
// evaluators use.
func pathGlobMatch(value, pattern string) bool { return pathglob.Match(pattern, value) }

func evalPathGlob(path string, rule ScopeRule) globVerdict {
	v, _ := evalGlobWith(pathglob.ScopePath(path), rule, pathGlobMatch)
	return v
}

// evalGlob is matchGlob with the reason kept: RejectReason needs to know which
// side of the rule refused, and deriving both from one function is what keeps
// the explanation and the verdict from drifting.
func evalGlob(value string, rule ScopeRule) globVerdict {
	v, _ := evalGlobWith(value, rule, globMatch)
	return v
}

// evalGlobWith is evalGlob with the pattern matcher supplied (match(value,
// pattern), both lowercased) and, for globExcluded, the exclude pattern that
// matched.
func evalGlobWith(value string, rule ScopeRule, match func(value, pattern string) bool) (globVerdict, string) {
	if isDefaultPassAll(rule) {
		return globPass, ""
	}

	// Check excludes first (higher priority). Through the same helper
	// ExplicitlyExcluded uses, so the pre-send exclusion check and the full scope
	// decision cannot disagree about what an exclude pattern matches.
	if p, ok := excludePatternWith(value, rule, match); ok {
		return globExcluded, p
	}

	// If include is empty or only contains "*", match everything
	if len(rule.Include) == 0 || (len(rule.Include) == 1 && rule.Include[0] == "*") {
		return globPass, ""
	}

	// Check includes
	valueLower := strings.ToLower(value)
	for _, pattern := range rule.Include {
		if match(valueLower, strings.ToLower(pattern)) {
			return globPass, ""
		}
	}

	return globNotIncluded, ""
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
			// Keyword is the registrable-domain label (the label before the TLD):
			// "example.com" → "example", "example.co.uk" → "example".
			ot.keyword = leadingLabel(etld)
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
//
// The candidate's registrable domain is derived AT MOST ONCE per call. It used
// to be derived once per origin target, inside a loop over all of them, which
// made first-visit membership cost targets × public-suffix lookups — invisible
// on a handful of targets and quadratic on a host list.
//
// Each mode below answers exactly what the per-target loop answered:
//
//   - strict: literal hostname equality against some target.
//   - balanced: that, or a shared registrable domain. The exact-host set stays
//     in play because a target whose registrable domain could not be derived
//     fell back to comparing hostnames — and for every other target an exact hit
//     implies the domains match anyway.
//   - relaxed: that, or the candidate's registrable label containing some
//     target's. Same reasoning for the exact-host set.
func (m *ScopeMatcher) hostMatchesOrigin(host string) bool {
	if m.originMode == "all" || len(m.originIndex.exactHosts) == 0 {
		return true
	}
	hostLower := strings.ToLower(host)
	if _, ok := m.originIndex.exactHosts[hostLower]; ok {
		return true
	}

	switch m.originMode {
	case "balanced", "relaxed":
	default:
		// strict, and anything unrecognised: only the exact-host set above
		// admits. ResolveCLIOriginMode never yields an unknown mode; failing
		// closed here keeps a hand-built matcher from admitting every host the
		// way the old default arm did.
		return false
	}

	// A host with no registrable domain (a single-label internal name, say) is
	// out of scope in both softened modes: only the exact-host set above could
	// have admitted it. Falling back to a full-host substring here would
	// reintroduce the third-party leak the relaxed-mode comment describes.
	hostETLD, err := publicsuffix.EffectiveTLDPlusOne(hostLower)
	if err != nil {
		return false
	}
	if m.originMode == "balanced" {
		_, ok := m.originIndex.etldPlus1[hostETLD]
		return ok
	}

	// Relaxed. The keyword is matched against the host's registrable-domain
	// leading label, NOT the full hostname. This keeps same-org hosts on other
	// TLDs / brand domains in scope (e.g. keyword "acme" matches acme.io,
	// acmegroup.com) while rejecting unrelated third parties whose subdomain
	// merely contains the keyword — e.g. acmegroup.cloudflareaccess.com, a
	// Cloudflare SSO wall whose registrable label is "cloudflareaccess", not a
	// match. A bare strings.Contains(host, keyword) would wrongly admit it.
	label := leadingLabel(hostETLD)
	for _, keyword := range m.originIndex.keywords {
		if strings.Contains(label, keyword) {
			return true
		}
	}
	return false
}

// leadingLabel returns the registrable-domain label of an eTLD+1 — the label
// before its first dot: "acme.com" → "acme", "example.co.uk" → "example".
// A dotless input (no eTLD+1) is returned unchanged.
func leadingLabel(etldPlus1 string) string {
	label, _, _ := strings.Cut(etldPlus1, ".")
	return label
}

func mustAtoi(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return n
}

// NamedScopeRule is one scope rule with its class (ScopeClass*).
type NamedScopeRule struct {
	Class string
	Rule  ScopeRule
}

// ScopeRuleClasses lists every include/exclude rule of s with its class, in
// evaluation order.
func ScopeRuleClasses(s ScopeConfig) []NamedScopeRule {
	return []NamedScopeRule{
		{ScopeClassHost, s.Host},
		{ScopeClassPath, s.Path},
		{ScopeClassStatusCode, s.StatusCode},
		{ScopeClassRequestContentType, s.RequestContentType},
		{ScopeClassResponseContentType, s.ResponseContentType},
		{ScopeClassRequestString, s.RequestString},
		{ScopeClassResponseString, s.ResponseString},
	}
}

// NonDefaultScopeRules are the rules of s that narrow anything: every rule not
// at its pass-all default.
func NonDefaultScopeRules(s ScopeConfig) []NamedScopeRule {
	var out []NamedScopeRule
	for _, r := range ScopeRuleClasses(s) {
		if !isDefaultPassAll(r.Rule) {
			out = append(out, r)
		}
	}
	return out
}
