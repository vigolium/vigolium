package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/samber/lo"
)

// Issue is one finding of the shared config validator. The same rules run at
// three points — `config set` / `scope set` (refusing a value that introduces
// an error), `config validate`, and doctor's Scope check — so a value is judged
// the same way wherever it is looked at.
type Issue struct {
	// Key is the dotted setting path the issue concerns (scope.host.include).
	Key      string `json:"key"`
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	// Fix is a ready-to-run command (or instruction) that resolves the issue.
	Fix string `json:"fix,omitempty"`
}

// Issue severities. An error means the setting cannot work as written (a scan
// would drop everything, or refuse to start); a warning means it probably does
// not do what was meant.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Issue codes. Stable strings: `config validate -j` consumers branch on them.
const (
	IssueScopePatternInvalid               = "scope_pattern_invalid"
	IssueScopeHostHasSchemeOrPath          = "scope_host_has_scheme_or_path"
	IssueScopeHostHasPort                  = "scope_host_has_port"
	IssueScopeIncludeRestrictive           = "scope_include_restrictive"
	IssueScopePathNoSlash                  = "scope_path_no_slash"
	IssueScopeStatusInvalid                = "scope_status_invalid"
	IssueScopeStatusOutOfRange             = "scope_status_out_of_range"
	IssueScopeExcludesEverything           = "scope_excludes_everything"
	IssueScopeIncludesNothing              = "scope_includes_nothing"
	IssueScopeOriginModeInvalid            = "scope_origin_mode_invalid"
	IssueScopeBodyActionInvalid            = "scope_body_action_invalid"
	IssueScopeIncludeMatchesNoRecentTarget = "scope_include_matches_no_recent_target"
	IssueOASTServerMissing                 = "oast_server_missing"
	IssueOASTServerURLInvalid              = "oast_server_url_invalid"
	IssueOASTIntervalInvalid               = "oast_interval_invalid"
	IssueConfigValueInvalid                = "config_value_invalid"
	IssueConfigUnknownKey                  = "config_unknown_key"
	IssueConfigLoadFailed                  = "config_load_failed"
)

// HasErrors reports whether any issue is error-level.
func HasErrors(issues []Issue) bool {
	for _, is := range issues {
		if is.Severity == SeverityError {
			return true
		}
	}
	return false
}

// validCLIOriginModes and validBodyActions are the values the scope matcher
// acts on (hostMatchesOrigin, CheckBodySize). Anything else silently falls back
// there, which is exactly what validation exists to surface.
var (
	validCLIOriginModes = []string{"all", "relaxed", "balanced", "strict"}
	validBodyActions    = []string{"truncate", "drop", "skip-scan", "passive-only"}
)

// hostPortRe matches a host pattern ending in :port (or :*). Host matching sees
// the hostname only, so such a pattern can never match.
var hostPortRe = regexp.MustCompile(`:(\d+|\*)$`)

// ValidateScope checks a scope section. It is pure: no network, no DB.
func ValidateScope(s ScopeConfig) []Issue {
	var issues []Issue

	globRules := []struct {
		name string
		rule ScopeRule
	}{
		{"host", s.Host},
		{"path", s.Path},
		{"request_content_type", s.RequestContentType},
		{"response_content_type", s.ResponseContentType},
	}
	for _, gr := range globRules {
		for _, side := range []string{"include", "exclude"} {
			patterns := gr.rule.Include
			if side == "exclude" {
				patterns = gr.rule.Exclude
			}
			key := "scope." + gr.name + "." + side
			for i, p := range patterns {
				if problem := globPatternProblem(p); problem != "" {
					issues = append(issues, Issue{
						Key: key, Severity: SeverityError, Code: IssueScopePatternInvalid,
						Message: fmt.Sprintf("%s[%d] = %q: %s", key, i, p, problem),
						Fix:     setListFix(key, cleanPatterns(patterns)),
					})
					continue
				}
				switch gr.name {
				case "host":
					if strings.Contains(p, "://") || strings.Contains(p, "/") {
						issues = append(issues, Issue{
							Key: key, Severity: SeverityError, Code: IssueScopeHostHasSchemeOrPath,
							Message: fmt.Sprintf("%s[%d] = %q: host patterns match the hostname only, so a scheme or path never matches", key, i, p),
							Fix:     setListFix(key, mapPatterns(patterns, hostOnly)),
						})
					} else if hostPortRe.MatchString(p) && !strings.HasPrefix(p, "[") {
						issues = append(issues, Issue{
							Key: key, Severity: SeverityWarning, Code: IssueScopeHostHasPort,
							Message: fmt.Sprintf("%s[%d] = %q: host patterns match the hostname only, so a :port suffix never matches", key, i, p),
							Fix:     setListFix(key, mapPatterns(patterns, hostOnly)),
						})
					}
				case "path":
					if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "*") {
						issues = append(issues, Issue{
							Key: key, Severity: SeverityWarning, Code: IssueScopePathNoSlash,
							Message: fmt.Sprintf("%s[%d] = %q: request paths start with '/', so this pattern never matches", key, i, p),
							Fix:     setListFix(key, mapPatterns(patterns, func(q string) string { return "/" + q })),
						})
					}
				}
			}
		}
	}

	if inc := s.Host.Include; len(inc) > 0 && (len(inc) != 1 || inc[0] != "*") {
		wild := false
		for _, p := range inc {
			if strings.Contains(p, "*") {
				wild = true
				break
			}
		}
		if !wild {
			issues = append(issues, Issue{
				Key: "scope.host.include", Severity: SeverityWarning, Code: IssueScopeIncludeRestrictive,
				Message: fmt.Sprintf("scope.host.include admits only the exact hosts %s; every other host (subdomains included) is dropped from every scan",
					strings.Join(quoteAll(inc), ", ")),
				Fix: "add wildcards (e.g. \"*.example.com\") or reset with `vigolium config set scope.host.include '[\"*\"]'`",
			})
		}
	}

	for _, side := range []string{"include", "exclude"} {
		patterns := s.StatusCode.Include
		if side == "exclude" {
			patterns = s.StatusCode.Exclude
		}
		key := "scope.status_code." + side
		for i, p := range patterns {
			if !validStatusPattern(p) {
				issues = append(issues, Issue{
					Key: key, Severity: SeverityError, Code: IssueScopeStatusInvalid,
					Message: fmt.Sprintf("%s[%d] = %q: not a status code, class (2xx, 30*) or range (400-499)", key, i, p),
					Fix:     setListFix(key, keepPatterns(patterns, validStatusPattern)),
				})
			}
		}
	}

	// Status codes are 100-599: a pattern wholly outside that matches no
	// response, and an include list of only such patterns drops every record.
	inRange := 0
	for i, p := range s.StatusCode.Include {
		if !validStatusPattern(p) {
			continue
		}
		if statusPatternInRange(p) {
			inRange++
			continue
		}
		issues = append(issues, Issue{
			Key: "scope.status_code.include", Severity: SeverityWarning, Code: IssueScopeStatusOutOfRange,
			Message: fmt.Sprintf("scope.status_code.include[%d] = %q: HTTP status codes are 100-599, so this matches no response", i, p),
		})
	}
	if len(s.StatusCode.Include) > 0 && inRange == 0 {
		issues = append(issues, Issue{
			Key: "scope.status_code.include", Severity: SeverityWarning, Code: IssueScopeIncludesNothing,
			Message: "scope.status_code.include matches no HTTP status: every response is dropped from every scan",
			Fix:     "vigolium config set scope.status_code.include '[\"*\"]'",
		})
	}
	for i, p := range s.StatusCode.Exclude {
		if validStatusPattern(p) && p != "*" && !statusPatternInRange(p) {
			issues = append(issues, Issue{
				Key: "scope.status_code.exclude", Severity: SeverityWarning, Code: IssueScopeStatusOutOfRange,
				Message: fmt.Sprintf("scope.status_code.exclude[%d] = %q: HTTP status codes are 100-599, so this excludes nothing", i, p),
			})
		}
	}

	// An exclude of "*" refuses every record for that rule: a scan with it
	// sends its requests and then drops every result.
	for _, r := range ScopeRuleClasses(s) {
		if slices.Contains(r.Rule.Exclude, "*") {
			key := "scope." + r.Class + ".exclude"
			issues = append(issues, Issue{
				Key: key, Severity: SeverityWarning, Code: IssueScopeExcludesEverything,
				Message: fmt.Sprintf("%s contains \"*\": every record is out of scope, so scans drop all their results", key),
				Fix:     setListFix(key, keepPatterns(r.Rule.Exclude, func(q string) bool { return q != "*" })),
			})
		}
	}

	for _, sr := range []struct {
		name string
		rule ScopeRule
	}{{"request_string", s.RequestString}, {"response_string", s.ResponseString}} {
		for _, side := range []string{"include", "exclude"} {
			patterns := sr.rule.Include
			if side == "exclude" {
				patterns = sr.rule.Exclude
			}
			key := "scope." + sr.name + "." + side
			for i, p := range patterns {
				if p == "" {
					issues = append(issues, Issue{
						Key: key, Severity: SeverityError, Code: IssueScopePatternInvalid,
						Message: fmt.Sprintf("%s[%d] is empty: an empty substring matches every request", key, i),
						Fix:     setListFix(key, keepPatterns(patterns, func(q string) bool { return q != "" })),
					})
				}
			}
		}
	}

	if mode := strings.ToLower(strings.TrimSpace(s.CLIOriginMode)); mode != "" && !slices.Contains(validCLIOriginModes, mode) {
		issues = append(issues, Issue{
			Key: "scope.cli_origin_mode", Severity: SeverityError, Code: IssueScopeOriginModeInvalid,
			Message: fmt.Sprintf("scope.cli_origin_mode = %q: must be one of %s", s.CLIOriginMode, strings.Join(validCLIOriginModes, ", ")),
			Fix:     "vigolium config set scope.cli_origin_mode " + DefaultCLIOriginMode,
		})
	}
	if a := s.BodySizeExceededAction; a != "" && !slices.Contains(validBodyActions, a) {
		issues = append(issues, Issue{
			Key: "scope.body_size_exceeded_action", Severity: SeverityError, Code: IssueScopeBodyActionInvalid,
			Message: fmt.Sprintf("scope.body_size_exceeded_action = %q: must be one of %s", a, strings.Join(validBodyActions, ", ")),
			Fix:     "vigolium config set scope.body_size_exceeded_action truncate",
		})
	}
	return issues
}

// ValidateRecentTargets warns when scope.host.include has no wildcard and none
// of targets (the most recent scans' targets) would be admitted by it — the
// shape of a scope left over from another engagement. It is separate from
// ValidateScope because it needs the database, which only the CLI can reach.
func ValidateRecentTargets(s ScopeConfig, targets []string) []Issue {
	inc := s.Host.Include
	if len(inc) == 0 || len(targets) == 0 {
		return nil
	}
	for _, p := range inc {
		if strings.Contains(p, "*") {
			return nil
		}
	}
	var hosts []string
	rule := ScopeRule{Include: inc}
	for _, t := range targets {
		h := extractHostFromTarget(t)
		if h == "" {
			continue
		}
		if evalGlob(h, rule) == globPass {
			return nil
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return nil
	}
	return []Issue{{
		Key: "scope.host.include", Severity: SeverityWarning, Code: IssueScopeIncludeMatchesNoRecentTarget,
		Message: fmt.Sprintf("scope.host.include (%s) admits none of the recent scan targets (%s); a scan of them would drop every request",
			strings.Join(quoteAll(inc), ", "), strings.Join(lo.Uniq(hosts), ", ")),
		Fix: "vigolium config set scope.host.include '[\"*\"]'",
	}}
}

// ValidateSettings runs ValidateScope, the OAST rules and every section's own
// Validate() (wrapped as error-level issues keyed by section).
func ValidateSettings(s *Settings) []Issue {
	if s == nil {
		return nil
	}
	issues := ValidateScope(s.Scope)
	issues = append(issues, validateOAST(s.OAST)...)
	issues = append(issues, validateEnabledModules(s.DynamicAssessment.EnabledModules)...)

	sections := []struct {
		key      string
		validate func() error
	}{
		{"database", s.Database.Validate},
		{"dynamic-assessment.extensions", s.DynamicAssessment.Extensions.Validate},
		{"discovery", s.Discovery.Validate},
		{"known_issue_scan", s.KnownIssueScan.Validate},
		{"external_harvester", s.ExternalHarvester.Validate},
		{"scanning_strategy", s.ScanningStrategy.Validate},
		{"scanning_pace", s.ScanningPace.Validate},
		{"spidering", s.Spidering.Validate},
		{"agent", s.Agent.Validate},
		{"storage", s.Storage.Validate},
		{"notify.webhook", s.Notify.Webhook.Validate},
	}
	for _, sec := range sections {
		if err := sec.validate(); err != nil {
			issues = append(issues, Issue{
				Key: sec.key, Severity: SeverityError, Code: IssueConfigValueInvalid,
				Message: err.Error(),
			})
		}
	}
	return issues
}

func validateOAST(o OASTConfig) []Issue {
	var issues []Issue
	server := strings.TrimSpace(o.ServerURL)
	if o.Enabled && strings.TrimSpace(o.OastURL) == "" && server == "" {
		issues = append(issues, Issue{
			Key: "oast.server_url", Severity: SeverityError, Code: IssueOASTServerMissing,
			Message: "oast is enabled with neither oast.server_url nor oast.oast_url set; blind checks cannot get a callback URL",
			Fix:     "vigolium config set oast.server_url oast.pro (or oast.enabled false)",
		})
	}
	if server != "" && (strings.ContainsAny(o.ServerURL, " \t\"'") || (strings.Contains(server, "://") && !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://"))) {
		issues = append(issues, Issue{
			Key: "oast.server_url", Severity: SeverityError, Code: IssueOASTServerURLInvalid,
			Message: fmt.Sprintf("oast.server_url = %q: expected a host name such as oast.pro", o.ServerURL),
			Fix:     "vigolium config set oast.server_url oast.pro",
		})
	}
	if o.PollInterval < 0 || o.GracePeriod < 0 {
		issues = append(issues, Issue{
			Key: "oast", Severity: SeverityError, Code: IssueOASTIntervalInvalid,
			Message: fmt.Sprintf("oast.poll_interval (%d) and oast.grace_period (%d) must be >= 0", o.PollInterval, o.GracePeriod),
		})
	}
	return issues
}

// UnknownKeyIssues reports every key in content that matches no field of into
// (a *Settings for the global config, a *ProfileSettings for a project or
// profile overlay), as warnings: such a key is silently inert.
func UnknownKeyIssues(path, content string, into any) []Issue {
	var issues []Issue
	for _, e := range unknownKeyErrors(content, into) {
		key := e
		if _, rest, ok := strings.Cut(e, "field "); ok {
			key, _, _ = strings.Cut(rest, " ")
		}
		issues = append(issues, Issue{
			Key: key, Severity: SeverityWarning, Code: IssueConfigUnknownKey,
			Message: fmt.Sprintf("%s: %s (the key has no effect)", ContractPath(path), e),
			Fix:     "remove or rename it; `vigolium config ls` lists the valid keys",
		})
	}
	return issues
}

// ValidateConfigFile reports the problems with a config file that loading
// tolerates: unknown keys. A missing file yields nothing (defaults apply).
func ValidateConfigFile(path string, into any) []Issue {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return []Issue{{
			Key: "", Severity: SeverityError, Code: IssueConfigLoadFailed,
			Message: fmt.Sprintf("%s: %v", ContractPath(path), err),
		}}
	}
	return UnknownKeyIssues(path, ExpandEnvVars(string(data)), into)
}

// globPatternProblem returns why a glob scope pattern is malformed, or "".
func globPatternProblem(p string) string {
	switch {
	case strings.TrimSpace(p) == "":
		return "empty pattern"
	case p != strings.TrimSpace(p):
		return "leading or trailing whitespace"
	case strings.ContainsAny(p, `"'`):
		return "contains a quote (a JSON list split on commas?)"
	case strings.Count(p, "[") != strings.Count(p, "]"):
		return "unbalanced brackets (a JSON list split on commas?)"
	}
	if _, err := filepath.Match(p, ""); errors.Is(err, filepath.ErrBadPattern) {
		return "not a valid glob pattern"
	}
	return ""
}

// validStatusPattern mirrors the shapes statusCodeMatches understands: "*",
// an exact code, a class with x/* wildcards ("2xx", "30*"), or a range
// ("400-499"). Anything else silently never matches there.
// statusPatternInRange reports whether a valid status pattern can match an
// HTTP status (100-599).
func statusPatternInRange(p string) bool {
	p = strings.TrimSpace(p)
	if p == "*" {
		return true
	}
	if lo, hi, ok := strings.Cut(p, "-"); ok {
		a, _ := strconv.Atoi(strings.TrimSpace(lo))
		b, _ := strconv.Atoi(strings.TrimSpace(hi))
		return a <= 599 && b >= 100
	}
	norm := strings.ReplaceAll(strings.ToLower(p), "x", "*")
	if !strings.Contains(norm, "*") {
		n, err := strconv.Atoi(norm)
		return err == nil && n >= 100 && n <= 599
	}
	// A class such as 2xx or 5*: its first digit decides.
	return norm[0] == '*' || (norm[0] >= '1' && norm[0] <= '5')
}

func validStatusPattern(p string) bool {
	p = strings.TrimSpace(p)
	if p == "*" {
		return true
	}
	if lo, hi, ok := strings.Cut(p, "-"); ok {
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b, err2 := strconv.Atoi(strings.TrimSpace(hi))
		return err1 == nil && err2 == nil && a <= b
	}
	norm := strings.ReplaceAll(strings.ToLower(p), "x", "*")
	if norm == "" || len(norm) > 3 {
		return false
	}
	for _, r := range norm {
		if r != '*' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// cleanPatterns is the best-effort repair of a list damaged by comma-splitting
// JSON: trim, strip quotes and brackets, drop empties.
func cleanPatterns(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		q := strings.Trim(strings.TrimSpace(p), `"'[] `)
		if q != "" {
			out = append(out, q)
		}
	}
	return out
}

// hostOnly strips a scheme, path and port from a host pattern.
func hostOnly(p string) string {
	if _, rest, ok := strings.Cut(p, "://"); ok {
		p = rest
	}
	p, _, _ = strings.Cut(p, "/")
	return hostPortRe.ReplaceAllString(p, "")
}

func mapPatterns(patterns []string, f func(string) string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if globPatternProblem(p) != "" {
			continue
		}
		out = append(out, f(p))
	}
	return out
}

func keepPatterns(patterns []string, keep func(string) bool) []string {
	var out []string
	for _, p := range patterns {
		if keep(p) {
			out = append(out, p)
		}
	}
	return out
}

// setListFix renders the `config set` that writes list to key.
func setListFix(key string, list []string) string {
	if list == nil {
		list = []string{}
	}
	b, _ := json.Marshal(list)
	return fmt.Sprintf("vigolium config set %s '%s'", key, b)
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strconv.Quote(s)
	}
	return out
}

// validateEnabledModules reports an explicit empty module allow-list, keyed by
// the list itself so `config set <list> []` is refused.
func validateEnabledModules(c EnabledModulesConfig) []Issue {
	var issues []Issue
	for _, l := range []struct {
		name string
		list []string
	}{
		{"active_modules", c.ActiveModules},
		{"passive_modules", c.PassiveModules},
	} {
		if l.list != nil && len(l.list) == 0 {
			key := "dynamic-assessment.enabled_modules." + l.name
			issues = append(issues, Issue{
				Key: key, Severity: SeverityError, Code: IssueConfigValueInvalid,
				Message: fmt.Sprintf("%s is an empty list, which selects no module", key),
				Fix:     fmt.Sprintf("vigolium config set %s '[all]' (turn single modules off with `vigolium module disable <id> --id`)", key),
			})
		}
	}
	return issues
}
