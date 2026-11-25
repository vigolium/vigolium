package jsext

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/yamlext"
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
	// Rule is the stable id of the check that raised the issue (see the
	// Rule* constants), so a caller can filter without matching messages.
	Rule string
}

// Lint rule ids. They are part of the `ext lint -j` contract: add new ones,
// never rename.
const (
	RuleSyntax          = "syntax"             // the source does not parse
	RuleTranspile       = "transpile"          // TypeScript did not transpile
	RuleUnknownAPI      = "unknown-api"        // vigolium.* member that does not exist
	RuleUnknownOASTCls  = "unknown-oast-class" // vigolium.oast.url class literal that does not exist
	RuleMetadata        = "metadata"           // top-level code threw, or module.exports is unusable
	RuleNoExports       = "no-exports"         // the file exports nothing
	RuleInvalidType     = "invalid-type"       // type is not active/passive/pre_hook/post_hook
	RuleMissingSeverity = "missing-severity"   // an active/passive extension declares no severity
	RuleBadSeverity     = "bad-severity"       // severity is not a known level
	RuleBadConfidence   = "bad-confidence"     // confidence is not tentative/firm/certain
	RuleBadScanType     = "bad-scan-type"      // scanTypes holds an unknown value
	RuleBadScope        = "bad-scope"          // passive scope is not request/response/both
	RuleMissingHandler  = "missing-handler"    // the handler a declared scan type needs is not exported
	RuleTopLevelEffect  = "top-level-effect"   // top-level code calls an effectful API (stubbed at load)
)

// LintOptions tunes LintSourceWithOptions.
type LintOptions struct {
	// Extension says the file was named as an extension: a path given to
	// `ext lint`, a file in an extension directory, or --stdin. A file that
	// fails metadata extraction, or exports nothing, is then an error; without
	// it only files that look like an extension are held to that.
	Extension bool
}

// ScriptPragma marks a plain script (for `vigolium js`) that is linted from
// an extension location but is not an extension: it may export nothing.
const ScriptPragma = "// vigolium:script"

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

// LintSource validates source that may or may not be an extension (see
// LintOptions); `ext lint` uses LintSourceWithOptions with Extension set.
func LintSource(source, filename string) *LintResult {
	return LintSourceWithOptions(source, filename, LintOptions{})
}

// LintSourceWithOptions validates extension source code and returns any
// issues found: syntax errors, unknown vigolium.* API calls, and — by running
// the top-level code in the same load-mode VM the scan loader uses — metadata
// problems, missing handlers, and effectful calls made at load time.
func LintSourceWithOptions(source, filename string, opts LintOptions) *LintResult {
	result := &LintResult{Path: filename, SourceLines: strings.Split(source, "\n")}

	// Phase 1: Compile check — catches syntax errors with line:col info
	_, compileErr := sobek.Compile(filename, source, false)
	if compileErr != nil {
		issue := parseSobekError(compileErr)
		issue.Severity = LintError
		issue.Rule = RuleSyntax
		result.Issues = append(result.Issues, issue)
		// Syntax errors prevent further analysis
		return result
	}

	// Phase 2: Check for unknown vigolium.* API calls
	result.Issues = append(result.Issues, checkUnknownAPICalls(source)...)
	oast := checkOASTClassLiterals(source)
	for i := range oast {
		if oast[i].Rule == "" {
			oast[i].Rule = RuleUnknownOASTCls
		}
	}
	result.Issues = append(result.Issues, oast...)

	// Phase 3: Metadata validation — the scan loader's own extractor.
	result.Issues = append(result.Issues, checkMetadata(source, filename, opts)...)

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
	// Prefer the typed error: its rendered text has changed across sobek
	// releases ("SyntaxError: <msg> at file:5:12" today).
	var syn *sobek.CompilerSyntaxError
	if errors.As(err, &syn) && syn.File != nil {
		if pos := syn.File.Position(syn.Offset); pos.Line > 0 {
			return LintIssue{Line: pos.Line, Col: pos.Column, Message: syn.Message}
		}
	}

	// Older sobek errors look like: "filename: Line 5:12 Unexpected token )"
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

			// vigolium.config.<key> is whatever extensions.variables defines.
			if strings.HasPrefix(fullMatch, NsConfig+".") {
				continue
			}

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
				Rule:     RuleUnknownAPI,
			})
		}
	}

	return issues
}

// reOASTURLClass matches a string-literal class in a vigolium.oast.url({...})
// call written on one line; group 2 is the class value.
var reOASTURLClass = regexp.MustCompile("\\bvigolium\\.oast\\.url\\s*\\(\\s*\\{[^}]*?\\bclass\\s*:\\s*([\"'`])([^\"'`]*)[\"'`]")

// checkOASTClassLiterals reports a vigolium.oast.url call whose class literal
// is not a known OAST class. The runtime throws on such a call; lint catches
// the literal case before a scan. Dynamic class values are not checked.
func checkOASTClassLiterals(source string) []LintIssue {
	var issues []LintIssue
	for lineNum, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		for _, m := range reOASTURLClass.FindAllStringSubmatchIndex(line, -1) {
			val := line[m[4]:m[5]]
			if _, ok := oastclass.Parse(val); ok {
				continue
			}
			issues = append(issues, LintIssue{
				Severity: LintError,
				Line:     lineNum + 1,
				Col:      m[4] + 1,
				Message:  fmt.Sprintf("unknown OAST class %q in vigolium.oast.url (valid: %s)", val, strings.Join(oastclass.Names(), ", ")),
				Source:   trimmed,
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

// checkMetadata runs the source's top-level code in the loader's load-mode VM
// and validates what module.exports declares.
func checkMetadata(source, filename string, opts LintOptions) []LintIssue {
	var issues []LintIssue

	res, err := newMetadataExtractor().extract(source, filename)
	if err != nil {
		if errors.Is(err, ErrNoModuleExports) {
			if opts.Extension && !strings.Contains(source, ScriptPragma) {
				issues = append(issues, LintIssue{
					Severity: LintError,
					Rule:     RuleNoExports,
					Message: "no module.exports: an extension must export its metadata and handlers " +
						"(a plain script for `vigolium js` can say so with a `" + ScriptPragma + "` line)",
				})
			}
			return issues
		}
		// A file named as an extension, or one that looks like one, must load.
		if opts.Extension || looksLikeExtension(source) {
			issue := LintIssue{
				Severity: LintError,
				Rule:     RuleMetadata,
				Message:  fmt.Sprintf("metadata extraction failed: %v", err),
			}
			issue.Line, issue.Col = exceptionPosition(err)
			issues = append(issues, issue)
		}
		return issues
	}
	meta := res.Meta

	// Effectful calls made by top-level code: stubbed at load, so the script
	// loads, but they run for real in every scan VM.
	seen := map[string]bool{}
	for _, c := range res.TopLevelEffects {
		key := fmt.Sprintf("%s@%d:%d", c.API, c.Line, c.Col)
		if seen[key] {
			continue
		}
		seen[key] = true
		issues = append(issues, LintIssue{
			Severity: LintWarning,
			Rule:     RuleTopLevelEffect,
			Line:     c.Line,
			Col:      c.Col,
			Message: fmt.Sprintf("top-level %s (%s) runs at load time and is stubbed there; move it into a handler",
				c.API, c.Effect),
		})
	}

	// Validate type
	validTypes := map[ScriptType]bool{
		ScriptTypeActive: true, ScriptTypePassive: true,
		ScriptTypePreHook: true, ScriptTypePostHook: true,
	}
	if !validTypes[meta.Type] {
		issues = append(issues, LintIssue{
			Severity: LintError,
			Rule:     RuleInvalidType,
			Message:  fmt.Sprintf("invalid extension type %q; must be one of: active, passive, pre_hook, post_hook", meta.Type),
		})
	}

	// Validate severity for active/passive
	if meta.Type == ScriptTypeActive || meta.Type == ScriptTypePassive {
		if meta.Severity == "" {
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Rule:     RuleMissingSeverity,
				Message:  "active/passive extension should declare a severity (critical, high, medium, low, info, suspect)",
			})
		} else if !isValidSeverity(meta.Severity) {
			issues = append(issues, LintIssue{
				Severity: LintWarning,
				Rule:     RuleBadSeverity,
				Message:  fmt.Sprintf("unknown severity %q; expected one of: critical, high, medium, low, info, suspect", meta.Severity),
			})
		}
	}

	// Validate confidence: an unknown value would silently fall back to "firm".
	if !yamlext.IsValidConfidence(meta.Confidence) {
		issues = append(issues, LintIssue{
			Severity: LintError,
			Rule:     RuleBadConfidence,
			Message:  fmt.Sprintf("unknown confidence %q; expected one of: tentative, firm, certain", meta.Confidence),
		})
	}

	// Validate scan types for active modules
	if meta.Type == ScriptTypeActive {
		for _, st := range meta.ScanTypes {
			if !isValidScanType(st) {
				issues = append(issues, LintIssue{
					Severity: LintWarning,
					Rule:     RuleBadScanType,
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
				Rule:     RuleBadScope,
				Message:  fmt.Sprintf("unknown passive scope %q; expected: request, response, both", meta.Scope),
			})
		}
	}

	// Check that required handler functions are exported
	issues = append(issues, checkExportedHandlers(meta, res.Handlers)...)

	return issues
}

// exceptionPosition is the source position of a JS exception thrown by
// top-level code, or 0, 0.
func exceptionPosition(err error) (line, col int) {
	var ex *sobek.Exception
	if !errors.As(err, &ex) {
		return 0, 0
	}
	for _, f := range ex.Stack() {
		if pos := f.Position(); pos.Line > 0 {
			return pos.Line, pos.Column
		}
	}
	return 0, 0
}

// scanTypeHandlers maps a scan type to the module.exports function it calls.
var scanTypeHandlers = map[string]string{
	"per_insertion_point": "scanPerInsertionPoint",
	"per_request":         "scanPerRequest",
	"per_host":            "scanPerHost",
}

// checkExportedHandlers verifies that module.exports defines, as a function,
// every handler its declared type and scan types make the runtime call. A
// missing one is an error: the runtime skips it silently, so the extension
// would load and never run.
func checkExportedHandlers(meta *ScriptMetadata, handlers map[string]bool) []LintIssue {
	var issues []LintIssue
	missing := func(format string, args ...any) {
		issues = append(issues, LintIssue{
			Severity: LintError,
			Rule:     RuleMissingHandler,
			Message:  fmt.Sprintf(format, args...),
		})
	}

	switch meta.Type {
	case ScriptTypeActive, ScriptTypePassive:
		scanTypes := meta.ScanTypes
		if len(scanTypes) == 0 {
			scanTypes = []string{"per_request"} // default
		}
		for _, st := range scanTypes {
			st = strings.ToLower(strings.TrimSpace(st))
			fn := scanTypeHandlers[st]
			if fn == "" || (meta.Type == ScriptTypePassive && st == "per_insertion_point") {
				continue
			}
			if !handlers[fn] {
				missing("%s extension with scan type %q must export a %s() function", meta.Type, st, fn)
			}
		}

	case ScriptTypePreHook, ScriptTypePostHook:
		if !handlers["execute"] {
			missing("%s extension must export an execute() function", meta.Type)
		}
	}

	return issues
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
