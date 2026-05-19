package jsext

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/grafana/sobek"
)

// LintSeverity categorizes lint issues.
type LintSeverity string

const (
	LintError   LintSeverity = "error"
	LintWarning LintSeverity = "warning"
)

// LintIssue represents a single lint finding.
type LintIssue struct {
	Severity LintSeverity
	Line     int // 1-based, 0 if unknown
	Col      int // 1-based, 0 if unknown
	Message  string
	Source   string // the offending source snippet
}

// LintResult holds the outcome of linting a single file.
type LintResult struct {
	Path        string
	Issues      []LintIssue
	SourceLines []string // original source split by newline, for context display
}

// HasErrors returns true if any issue is an error.
func (r *LintResult) HasErrors() bool {
	for _, i := range r.Issues {
		if i.Severity == LintError {
			return true
		}
	}
	return false
}

// LintSource validates extension source code and returns any issues found.
// It checks for: syntax errors, unknown vigolium.* API calls, and metadata problems.
func LintSource(source, filename string) *LintResult {
	result := &LintResult{Path: filename, SourceLines: strings.Split(source, "\n")}

	// Phase 1: Compile check — catches syntax errors with line:col info
	_, compileErr := sobek.Compile(filename, source, false)
	if compileErr != nil {
		issue := parseSobekError(compileErr)
		issue.Severity = LintError
		result.Issues = append(result.Issues, issue)
		// Syntax errors prevent further analysis
		return result
	}

	// Phase 2: Check for unknown vigolium.* API calls
	result.Issues = append(result.Issues, checkUnknownAPICalls(source)...)

	// Phase 3: Metadata validation — run in a stub VM to extract module.exports
	result.Issues = append(result.Issues, checkMetadata(source)...)

	return result
}

// Precompiled regexes for lint checks.
var (
	reSobekError  = regexp.MustCompile(`(?:.*): Line (\d+):(\d+) (.+)`)
	reVigoliumAPI = regexp.MustCompile(`\bvigolium\.([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)`)
)

// Cached known API set and namespace list (computed once, read-only after init).
var (
	cachedKnownAPIs  map[string]bool
	cachedNamespaces []string
	knownAPIsOnce    sync.Once
)

func getKnownAPIs() (map[string]bool, []string) {
	knownAPIsOnce.Do(func() {
		cachedKnownAPIs = knownAPIs()
		cachedNamespaces = APINamespaces()
	})
	return cachedKnownAPIs, cachedNamespaces
}

// parseSobekError extracts line/col/message from a sobek compile error.
func parseSobekError(err error) LintIssue {
	// sobek errors look like: "filename: Line 5:12 Unexpected token )"
	// or: "(anonymous): Line 5:12 Unexpected token )"
	msg := err.Error()
	if m := reSobekError.FindStringSubmatch(msg); len(m) == 4 {
		line, _ := strconv.Atoi(m[1])
		col, _ := strconv.Atoi(m[2])
		return LintIssue{
			Line:    line,
			Col:     col,
			Message: m[3],
		}
	}

	return LintIssue{Message: msg}
}

// knownAPIs builds a set of all known vigolium.* fully-qualified function/property names.
func knownAPIs() map[string]bool {
	known := make(map[string]bool)
	for _, def := range allFuncDefs() {
		known[def.FullName()] = true
	}
	// Also register known namespaces themselves (e.g. vigolium.http, vigolium.log)
	for _, ns := range APINamespaces() {
		known[ns] = true
	}
	// Register top-level properties that aren't functions
	known["vigolium.config"] = true
	known["vigolium.record"] = true
	known["vigolium.record.uuid"] = true
	return known
}

// checkUnknownAPICalls scans source for vigolium.* member access patterns
// and reports any that don't match a known API function or namespace.
func checkUnknownAPICalls(source string) []LintIssue {
	known, namespaces := getKnownAPIs()

	var issues []LintIssue
	reported := make(map[string]bool) // deduplicate same unknown call

	lines := strings.Split(source, "\n")
	for lineNum, line := range lines {
		// Skip comment lines
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		matches := reVigoliumAPI.FindAllStringSubmatchIndex(line, -1)
		for _, loc := range matches {
			fullMatch := line[loc[0]:loc[1]]

			// Try to resolve the call: work backwards from longest to shortest prefix
			// to find if any known function or namespace matches.
			if isKnownAPIRef(fullMatch, known, namespaces) {
				continue
			}

			// Unknown API reference
			key := fullMatch
			if reported[key] {
				continue
			}
			reported[key] = true

			col := loc[0] + 1 // 1-based column
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Line:     lineNum + 1,
				Col:      col,
				Message:  fmt.Sprintf("unknown API reference: %s", fullMatch),
				Source:   strings.TrimSpace(line),
			})
		}
	}

	return issues
}

// isKnownAPIRef checks if a vigolium.x.y.z reference resolves to a known
// API function or is a method call on a known namespace.
func isKnownAPIRef(ref string, known map[string]bool, namespaces []string) bool {
	// Direct match (e.g. vigolium.log.info)
	if known[ref] {
		return true
	}

	// Check if it's a known namespace (caller will access a function on it)
	// e.g. "vigolium.http" is a namespace, not directly an error
	parts := strings.Split(ref, ".")
	for i := len(parts); i >= 2; i-- {
		prefix := strings.Join(parts[:i], ".")
		if known[prefix] {
			// If the full ref is longer than the known prefix, the extra parts
			// could be method calls on return values — only flag if the immediate
			// next level is unknown.
			if i == len(parts) {
				return true
			}
			// e.g. vigolium.http.get is known, vigolium.http.get.something is a method on result — OK
			// But vigolium.http.foobar is unknown if vigolium.http.foobar is not in known
			nextLevel := strings.Join(parts[:i+1], ".")
			if known[nextLevel] {
				return true
			}
			// The immediate child is unknown — it's only an error if the prefix is a namespace
			// (not a function). Functions can return objects with arbitrary properties.
			for _, ns := range namespaces {
				if prefix == ns {
					return false // namespace.unknownFunc — flag it
				}
			}
			return true // known function.something — OK (method on return value)
		}
	}

	return false
}

// checkMetadata runs the source in a stub VM and validates module.exports.
func checkMetadata(source string) []LintIssue {
	var issues []LintIssue

	extractor := newMetadataExtractor()
	meta, err := extractor.Extract(source, "lint")
	if err != nil {
		// Not an extension (no module.exports with type) — this is fine for
		// standalone scripts, but warn for files that look like extensions.
		if looksLikeExtension(source) {
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Message:  fmt.Sprintf("metadata extraction failed: %v", err),
			})
		}
		return issues
	}

	// Validate type
	validTypes := map[ScriptType]bool{
		ScriptTypeActive: true, ScriptTypePassive: true,
		ScriptTypePreHook: true, ScriptTypePostHook: true,
	}
	if !validTypes[meta.Type] {
		issues = append(issues, LintIssue{
			Severity: LintError,
			Message:  fmt.Sprintf("invalid extension type %q; must be one of: active, passive, pre_hook, post_hook", meta.Type),
		})
	}

	// Validate severity for active/passive
	if meta.Type == ScriptTypeActive || meta.Type == ScriptTypePassive {
		if meta.Severity == "" {
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Message:  "active/passive extension should declare a severity (critical, high, medium, low, info, suspect)",
			})
		} else if !isValidSeverity(meta.Severity) {
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Message:  fmt.Sprintf("unknown severity %q; expected one of: critical, high, medium, low, info, suspect", meta.Severity),
			})
		}
	}

	// Validate scan types for active modules
	if meta.Type == ScriptTypeActive {
		for _, st := range meta.ScanTypes {
			if !isValidScanType(st) {
				issues = append(issues, LintIssue{
					Severity: LintWarning,
					Message:  fmt.Sprintf("unknown scan type %q; expected: per_insertion_point, per_request, per_host", st),
				})
			}
		}
	}

	// Validate scope for passive modules
	if meta.Type == ScriptTypePassive && meta.Scope != "" {
		if !isValidPassiveScope(meta.Scope) {
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Message:  fmt.Sprintf("unknown passive scope %q; expected: request, response, both", meta.Scope),
			})
		}
	}

	// Check that required handler functions are exported
	issues = append(issues, checkExportedHandlers(source, meta)...)

	return issues
}

// checkExportedHandlers verifies that the script exports the expected handler functions
// for its declared type.
func checkExportedHandlers(source string, meta *ScriptMetadata) []LintIssue {
	var issues []LintIssue

	switch meta.Type {
	case ScriptTypeActive:
		scanTypes := meta.ScanTypes
		if len(scanTypes) == 0 {
			scanTypes = []string{"per_request"} // default
		}
		for _, st := range scanTypes {
			var funcName string
			switch st {
			case "per_insertion_point":
				funcName = "scanPerInsertionPoint"
			case "per_request":
				funcName = "scanPerRequest"
			case "per_host":
				funcName = "scanPerHost"
			}
			if funcName != "" && !exportsFunction(source, funcName) {
				issues = append(issues, LintIssue{
					Severity: LintWarning,
					Message:  fmt.Sprintf("active extension with scan type %q should export %s()", st, funcName),
				})
			}
		}

	case ScriptTypePassive:
		if !exportsFunction(source, "scanPerRequest") {
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Message:  "passive extension should export scanPerRequest()",
			})
		}

	case ScriptTypePreHook, ScriptTypePostHook:
		if !exportsFunction(source, "execute") {
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Message:  fmt.Sprintf("%s extension should export execute()", meta.Type),
			})
		}
	}

	return issues
}

// exportsFunction checks whether the source contains a pattern that exports the given function name.
// This is a heuristic check — it looks for common assignment patterns.
func exportsFunction(source, funcName string) bool {
	patterns := []string{
		funcName + `:`,        // { scanPerRequest: function() ... } or { scanPerRequest: (ctx) => ... }
		funcName + ` :`,       // with space before colon
		`"` + funcName + `"`,  // quoted property name
		`'` + funcName + `'`,  // single-quoted property name
		funcName + `(`,        // method shorthand: scanPerRequest(ctx) { ... }
		`exports.` + funcName, // module.exports.scanPerRequest = ...
	}

	for _, pat := range patterns {
		if strings.Contains(source, pat) {
			return true
		}
	}
	return false
}

// looksLikeExtension returns true if the source appears to be a vigolium extension
// (has module.exports with a type-like field).
func looksLikeExtension(source string) bool {
	return strings.Contains(source, "module.exports") &&
		(strings.Contains(source, `"type"`) || strings.Contains(source, `'type'`) ||
			strings.Contains(source, "type:") || strings.Contains(source, "type :"))
}

// isValidSeverity checks if a severity string is recognized by ParseSeverity.
// ParseSeverity silently defaults unknown values to Info, so we check against
// the known set to detect typos.
func isValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info", "suspect":
		return true
	}
	return false
}

// isValidScanType checks if a scan type string is recognized by ParseScanScopes.
func isValidScanType(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "per_insertion_point", "per_request", "per_host":
		return true
	}
	return false
}

// isValidPassiveScope checks if a passive scope string is recognized by ParsePassiveScope.
func isValidPassiveScope(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "request", "response", "both":
		return true
	}
	return false
}

// SortIssues sorts issues by line number, then column.
func SortIssues(issues []LintIssue) {
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Line != issues[j].Line {
			return issues[i].Line < issues[j].Line
		}
		return issues[i].Col < issues[j].Col
	})
}
