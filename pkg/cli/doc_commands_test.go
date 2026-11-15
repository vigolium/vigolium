package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/doclex"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/output"
)

// Every documented `vigolium …` command must parse against the real command
// tree. The skill bundle, README, docs/, the --full-example tour and every
// cobra Example/Long are the places an operator or an agent copies a command
// from, and they rotted one renamed flag at a time: `-F` kept appearing after
// it stopped being a shorthand, `server -t` never existed, `project use
// my-project` passed a name where a UUID is required.
//
// The check never runs RunE or PreRunE. It resolves the command path, parses
// the flags against a COPY of the command's flag set, runs the command's own
// positional validator, and then a semantic layer: typed positionals derived
// from Use, enum flags against the canonical tables they are validated with at
// runtime, compatibility shims through their translator, and JS snippets
// through the extension linter. The extraction lives in doc_examples.go, which
// test/e2e also uses to RUN the read-only examples against a seeded store
// (doc_examples_e2e_test.go).
//
// Opt-outs, for synopsis lines and commands that deliberately show a mistake:
//
//	```bash doccheck=skip          the whole fence
//	<!-- doccheck: skip -->        on the line before a fence (or an inline span)
//	vigolium … # doccheck: skip    one line
//	# doccheck: deprecated-ok      a line (or <!-- --> before a fence) that
//	                               documents a deprecated flag on purpose

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// embeddedSkillDocs is skillBundleMarkdown for a test.
func embeddedSkillDocs(t *testing.T) []docSkillFile {
	t.Helper()
	out, err := skillBundleMarkdown()
	if err != nil {
		t.Fatalf("walk embedded skills: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no embedded skill docs found; the walk is broken")
	}
	return out
}

// repoMarkdownDocs returns README.md and docs/**/*.md relative to this
// package, or nil when the checkout does not carry them.
func repoMarkdownDocs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	if data, err := os.ReadFile("../../README.md"); err == nil {
		out["README.md"] = string(data)
	}
	_ = filepath.WalkDir("../../docs", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel("../..", p)
		out[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	return out
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// docArgsAllowlist names commands whose Args validator reads live flag state
// (the real, unset flag values rather than the documented ones), so running it
// against a doc line's positionals would report a correct line as broken. Keep
// it short and say why for each; TestDocArgsAllowlistIsSmall caps it.
var docArgsAllowlist = map[string]string{}

// docScanFamily are the scan-driving commands whose --only/--skip take the
// phase vocabulary and whose --format is the scan output surface.
var docScanFamily = []string{"vigolium scan", "vigolium run", "vigolium scan-url", "vigolium scan-request"}

// docFormatSurfaces maps a command path to the output-format surface its
// --format is validated against at runtime.
var docFormatSurfaces = map[string]output.Surface{
	"vigolium scan":         output.SurfaceScan,
	"vigolium run":          output.SurfaceScan,
	"vigolium scan-url":     output.SurfaceScan,
	"vigolium scan-request": output.SurfaceScan,
	"vigolium export":       output.SurfaceExport,
	"vigolium import":       output.SurfaceImport,
	"vigolium db export":    output.SurfaceDBExport,
}

// docEnumCheck validates one literal value of an enum flag.
type docEnumCheck func(cmdPath, value string) error

func docEachItem(value string, fn func(string) error) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" || strings.Contains(item, doclex.Placeholder) {
			continue
		}
		if err := fn(item); err != nil {
			return err
		}
	}
	return nil
}

func docSeverityCheck(_, value string) error {
	return docEachItem(value, func(s string) error {
		if _, ok := severityRanks[normalizeSeverity(s)]; !ok {
			return fmt.Errorf("unknown severity %q (valid: %s)", s, strings.Join(severityOrder, ", "))
		}
		return nil
	})
}

// docEnumFlags are the enum flags checked against the canonical tables the
// runtime validates them with.
var docEnumFlags = map[string]docEnumCheck{
	"only": func(path, value string) error {
		if !slices.Contains(docScanFamily, path) {
			return nil
		}
		return docEachItem(value, func(p string) error {
			if !runner.IsOnlyPhaseSpelling(p) {
				return fmt.Errorf("--only %q is not a phase (valid: %s)", p, runner.ValidOnlyPhasesDesc)
			}
			return nil
		})
	},
	"skip": func(path, value string) error {
		if !slices.Contains(docScanFamily, path) {
			return nil
		}
		return docEachItem(value, func(p string) error {
			if !runner.IsSkippablePhaseSpelling(p) {
				return fmt.Errorf("--skip %q is not a skippable phase (valid: %s)", p, runner.ValidSkipPhasesDesc)
			}
			return nil
		})
	},
	"input-mode": func(_, value string) error {
		return docEachItem(value, func(v string) error {
			if _, ok := source.LookupFormat(v); !ok {
				return fmt.Errorf("-I %q is not an input format (see --list-input-mode)", v)
			}
			return nil
		})
	},
	"format": func(path, value string) error {
		s, ok := docFormatSurfaces[path]
		if !ok {
			return nil
		}
		return docEachItem(value, func(v string) error {
			_, err := output.Lookup(v, s)
			return err
		})
	},
	"fail-on":      docSeverityCheck,
	"severity":     docSeverityCheck,
	"min-severity": docSeverityCheck,
	"strategy": func(_, value string) error {
		names := (&config.ScanningStrategyConfig{}).StrategyNames()
		return docEachItem(value, func(v string) error {
			if !slices.Contains(names, v) {
				return fmt.Errorf("--strategy %q (valid: %s)", v, strings.Join(names, ", "))
			}
			return nil
		})
	},
	"intensity": func(_, value string) error {
		return docEachItem(value, func(v string) error {
			_, err := agenttypes.ValidateIntensity(v)
			return err
		})
	},
}

// docSpecSuffixes are files that are specs or request exports (-i), never
// target lists (-T). A Burp scope export (`scope.json`) is a target list.
var docSpecSuffixes = []string{".yaml", ".yml", ".json", ".wsdl", ".har", ".xml"}

func docLooksLikeSpec(file string) bool {
	file = strings.ToLower(file)
	if strings.Contains(path.Base(file), "scope") {
		return false
	}
	for _, suffix := range docSpecSuffixes {
		if strings.HasSuffix(file, suffix) {
			return true
		}
	}
	return false
}

// validateDocArgv checks one documented argv (without "vigolium") against the
// command tree, without executing anything. Warnings are worth a log line but
// not a failure.
func validateDocArgv(root *cobra.Command, argv []string, deprecatedOK bool, depth int) (warnings []string, err error) {
	if len(argv) == 2 && argv[0] == "\x00lex" {
		return nil, fmt.Errorf("does not lex: %s", argv[1])
	}
	if len(argv) == 0 {
		return nil, nil
	}
	switch argv[0] {
	// cobra adds `help` and `completion` at Execute time.
	case "help":
		if len(argv) == 1 {
			return nil, nil
		}
		return validateDocArgv(root, append(docDropFlags(argv[1:]), "--help"), deprecatedOK, depth)
	case "completion":
		if len(argv) > 1 && !slices.Contains([]string{"bash", "zsh", "fish", "powershell", "-h", "--help"}, argv[1]) {
			return nil, fmt.Errorf("completion: unknown shell %q", argv[1])
		}
		return nil, nil
	case doclex.Placeholder:
		// `vigolium <command> -h` is the generic "read the help" line.
		if slices.Contains(argv, "-h") || slices.Contains(argv, "--help") {
			return nil, nil
		}
	}

	// -S is a bool on every command, root included (prepareCommandTree injects
	// it), so `vigolium --db x -S finding` resolves to finding.
	cmd, rest, err := root.Find(argv)
	if err != nil {
		return nil, err
	}
	cmdPath := cmd.CommandPath()

	// -h/--help is a meta example; the command path must still exist.
	help := false
	var stripped []string
	for i, a := range rest {
		if a == "--" {
			stripped = append(stripped, rest[i:]...)
			break
		}
		if a == "-h" || a == "--help" {
			help = true
			continue
		}
		stripped = append(stripped, a)
	}

	if cmd.DisableFlagParsing {
		if help {
			return nil, nil
		}
		return validateDocShim(root, cmd, stripped, deprecatedOK, depth)
	}
	if cmd.Deprecated != "" && !deprecatedOK {
		return nil, fmt.Errorf("%s is deprecated: %s (mark the line `doccheck: deprecated-ok` if it documents that)", cmdPath, cmd.Deprecated)
	}

	fset := newParseFlagSet(cmd)
	if err := fset.Parse(stripped); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil, nil
		}
		return nil, err
	}

	// Deprecated and hidden flags.
	var flagErr error
	fset.Visit(func(f *pflag.Flag) {
		orig := cmd.Flag(f.Name)
		if orig == nil {
			return
		}
		if orig.Deprecated != "" && !deprecatedOK && flagErr == nil {
			flagErr = fmt.Errorf("--%s is deprecated: %s (mark the line `doccheck: deprecated-ok` if it documents that)", f.Name, orig.Deprecated)
		}
		if orig.Hidden {
			warnings = append(warnings, fmt.Sprintf("uses hidden flag --%s", f.Name))
		}
	})
	if flagErr != nil {
		return warnings, flagErr
	}

	var positionals []string
	for _, a := range fset.Args() {
		if a != doclex.Ellipsis {
			positionals = append(positionals, a)
		}
	}
	if len(positionals) > 0 && !strings.Contains(positionals[0], doclex.Placeholder) {
		if cmd == root {
			return warnings, fmt.Errorf("unknown command %q for %q", positionals[0], cmdPath)
		}
		if cmd.HasSubCommands() && (!cmd.Runnable() || cmd.Args == nil) {
			return warnings, fmt.Errorf("unknown subcommand %q for %q", positionals[0], cmdPath)
		}
	}
	if help {
		return warnings, nil
	}

	// An elided tail ("vigolium storage get ...") may stand for the
	// positionals themselves, so the arity check only runs without one.
	elided := slices.Contains(fset.Args(), doclex.Ellipsis)
	if cmd.Args != nil && !elided {
		if _, allowed := docArgsAllowlist[cmdPath]; !allowed {
			if err := docRunArgs(cmd, positionals); err != nil {
				return warnings, fmt.Errorf("positional arguments: %w", err)
			}
		}
	}
	if err := docCheckTypedPositionals(cmd, positionals); err != nil {
		return warnings, err
	}

	// Enum flags, against the canonical tables.
	var enumErr error
	fset.Visit(func(f *pflag.Flag) {
		check, ok := docEnumFlags[f.Name]
		if !ok || enumErr != nil {
			return
		}
		for _, v := range docFlagValues(f) {
			if err := check(cmdPath, v); err != nil {
				enumErr = err
				return
			}
		}
	})
	if enumErr != nil {
		return warnings, enumErr
	}

	// `run <phase>`: the positional is the --only vocabulary.
	if cmdPath == "vigolium run" && len(positionals) == 1 && !strings.Contains(positionals[0], doclex.Placeholder) &&
		!runner.IsOnlyPhaseSpelling(positionals[0]) {
		return warnings, fmt.Errorf("run: %q is not a phase (valid: %s)", positionals[0], runner.ValidOnlyPhasesDesc)
	}

	// A spec handed to the target-list flag parses and then reads YAML lines
	// as URLs; only a semantic check finds it.
	if f := fset.Lookup("target-file"); f != nil && f.Shorthand == "T" {
		for _, v := range docFlagValues(f) {
			if docLooksLikeSpec(v) {
				return warnings, fmt.Errorf("-T %q is a spec; -T takes a target list, specs go to -i/--input", v)
			}
		}
	}

	// JS snippets go through the extension linter (compile + vigolium.* API
	// names; effectful calls are stubbed, nothing reaches the network).
	var snippet string
	switch {
	case cmdPath == "vigolium extensions eval" && len(positionals) == 1:
		snippet = positionals[0]
	case cmdPath == "vigolium js":
		if f := fset.Lookup("code"); f != nil {
			if vals := docFlagValues(f); len(vals) > 0 {
				snippet = vals[len(vals)-1]
			}
		}
	}
	if snippet != "" && !strings.Contains(snippet, doclex.Placeholder) {
		if err := docLintSnippet(snippet); err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

// validateDocShim translates a compatibility shim's argv with the shim's own
// translator and validates the native command it would run.
func validateDocShim(root, cmd *cobra.Command, args []string, deprecatedOK bool, depth int) ([]string, error) {
	if depth > 2 {
		return nil, fmt.Errorf("shim translation recursed")
	}
	i := slices.IndexFunc(shimSpecs, func(s shimSpec) bool { return s.name == cmd.Name() })
	if i < 0 {
		// Not a shim: a pass-through command with its own parser.
		return nil, nil
	}
	spec := shimSpecs[i]
	split, err := splitShimGlobals(spec, args, root.PersistentFlags())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", spec.name, err)
	}
	tr, err := spec.translate(split.foreign)
	if err != nil {
		// `vigolium ffuf -j -- <ffuf flags>` is a synopsis of the shim's
		// own argv, not a command to translate.
		if slices.Contains(split.foreign, doclex.Placeholder) || slices.Contains(split.foreign, doclex.Ellipsis) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s shim does not translate: %w", spec.name, err)
	}
	native := append(append([]string{}, split.globals...), tr.argv...)
	w, err := validateDocArgv(root, native, deprecatedOK, depth+1)
	if err != nil {
		return w, fmt.Errorf("%s shim translates to `vigolium %s`, which fails: %w", spec.name, strings.Join(native, " "), err)
	}
	return w, nil
}

// docRunArgs runs a command's positional validator, recovering from a
// validator that assumes runtime state.
func docRunArgs(cmd *cobra.Command, args []string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Args validator panicked: %v", r)
		}
	}()
	return cmd.Args(cmd, args)
}

// docFlagValues returns every literal a parsed flag received.
func docFlagValues(f *pflag.Flag) []string {
	if v, ok := f.Value.(*noopFlagValue); ok {
		return v.all
	}
	return []string{f.Value.String()}
}

func docDropFlags(argv []string) []string {
	var out []string
	for _, a := range argv {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// docPositionalKind is the type a Use string gives a positional.
type docPositionalKind int

const (
	docKindAny docPositionalKind = iota
	docKindUUID
	docKindInt
)

// docUsePositionals derives positional kinds from Use: `[uuid]`,
// `<project-uuid>`, `<scan-uuid>` are UUIDs; `[finding-id]` an integer id. The
// last kind repeats when the Use marks it variadic (`<id>...`).
func docUsePositionals(use string) (kinds []docPositionalKind, variadic bool) {
	fields := strings.Fields(use)
	if len(fields) < 2 {
		return nil, false
	}
	for _, f := range fields[1:] {
		if f == "[flags]" || strings.HasPrefix(f, "--") || strings.HasPrefix(f, "[--") {
			break
		}
		if strings.HasSuffix(f, "...") || strings.HasSuffix(f, "...]") {
			variadic = true
		}
		name := strings.Trim(f, "[]<>.")
		switch {
		case strings.Contains(name, "|"):
			kinds = append(kinds, docKindAny)
		case name == "uuid" || strings.HasSuffix(name, "-uuid"):
			kinds = append(kinds, docKindUUID)
		case name == "finding-id":
			kinds = append(kinds, docKindInt)
		default:
			kinds = append(kinds, docKindAny)
		}
	}
	return kinds, variadic
}

func docCheckTypedPositionals(cmd *cobra.Command, positionals []string) error {
	kinds, variadic := docUsePositionals(cmd.Use)
	for i, p := range positionals {
		if strings.Contains(p, doclex.Placeholder) || p == "-" {
			continue
		}
		var k docPositionalKind
		switch {
		case i < len(kinds):
			k = kinds[i]
		case variadic && len(kinds) > 0:
			k = kinds[len(kinds)-1]
		default:
			continue
		}
		switch k {
		case docKindUUID:
			if _, err := uuid.Parse(p); err != nil {
				return fmt.Errorf("positional %d (%s) must be a UUID, got %q", i+1, cmd.Use, p)
			}
		case docKindInt:
			if _, err := strconv.Atoi(p); err != nil {
				return fmt.Errorf("positional %d (%s) must be an integer id, got %q", i+1, cmd.Use, p)
			}
		}
	}
	return nil
}

func docLintSnippet(code string) error {
	res := jsext.LintSource(code, "doc-snippet.js")
	// unknown-api is only a warning for `ext lint` (a newer binary may know
	// it); a documented snippet must use the API this binary has.
	for _, is := range res.Issues {
		switch is.Rule {
		case jsext.RuleSyntax, jsext.RuleUnknownAPI, jsext.RuleUnknownOASTCls:
			return fmt.Errorf("JS snippet: %s (%s)", is.Message, is.Rule)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func checkDocCommands(t *testing.T, cmds []doclex.Command) {
	t.Helper()
	for _, c := range cmds {
		warnings, err := validateDocArgv(rootCmd, c.Argv, c.DeprecatedOK, 0)
		for _, w := range warnings {
			t.Logf("%s: %s\n  %s", c.Where(), w, c.Text)
		}
		if err != nil {
			t.Errorf("%s: %s\n  -> %v\n  (fix the command, or mark a synopsis with `<!-- doccheck: skip -->` / `# doccheck: skip`)",
				c.Where(), c.Text, err)
		}
	}
}

func TestDocCommandsSkillBundle(t *testing.T) {
	prepareCommandTree(rootCmd)
	total := 0
	for _, f := range embeddedSkillDocs(t) {
		cmds := doclex.Markdown(f.path, f.body)
		total += len(cmds)
		t.Run(f.path, func(t *testing.T) { checkDocCommands(t, cmds) })
	}
	if total < 100 {
		t.Errorf("only %d commands extracted from the skill bundle; the extractor is broken", total)
	}
}

func TestDocCommandsRepoDocs(t *testing.T) {
	prepareCommandTree(rootCmd)
	docs := repoMarkdownDocs(t)
	if len(docs) == 0 {
		t.Skip("README.md and docs/ are not in this checkout")
	}
	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		cmds := doclex.Markdown(n, docs[n])
		if len(cmds) == 0 {
			continue
		}
		t.Run(n, func(t *testing.T) { checkDocCommands(t, cmds) })
	}
}

func TestDocCommandsCobraHelp(t *testing.T) {
	prepareCommandTree(rootCmd)
	cmds := cobraDocCommands(rootCmd)
	if len(cmds) < 300 {
		t.Fatalf("only %d commands extracted from cobra Example/Long; the walk is broken", len(cmds))
	}
	checkDocCommands(t, cmds)
}

// TestDocCommandsInlineSkillSpans checks `vigolium …` code spans in the skill
// files (the router tables carry most of the commands an agent sees, one
// command per cell). A span that is a synopsis rather than a command is
// skipped by docInlineSynopsis; mark anything else with `doccheck: skip`.
func TestDocCommandsInlineSkillSpans(t *testing.T) {
	prepareCommandTree(rootCmd)
	for _, f := range embeddedSkillDocs(t) {
		for _, c := range inlineSkillSpans(f.path, f.body) {
			if _, err := validateDocArgv(rootCmd, c.Argv, c.DeprecatedOK, 0); err != nil {
				if strings.Contains(err.Error(), "flag needs an argument") {
					continue // `--flag` fragment naming a flag, not a command
				}
				t.Errorf("%s: `%s`\n  -> %v\n  (fix the command, or mark a synopsis line with `doccheck: skip`)", c.Where(), c.Text, err)
			}
		}
	}
}

var docInlineSpan = regexp.MustCompile("`((?:\\./bin/)?vigolium [^`]+)`")

// inlineSkillSpans extracts `vigolium …` spans outside fences, skipping the
// ones that read as synopsis rather than a command.
func inlineSkillSpans(src, body string) []doclex.Command {
	_, prose := doclex.Fences(body)
	var out []doclex.Command
	for ln, text := range prose {
		if strings.Contains(text, "doccheck: skip") || strings.Contains(prose[ln-1], "doccheck: skip") {
			continue
		}
		for _, m := range docInlineSpan.FindAllStringSubmatch(text, -1) {
			span := m[1]
			if docInlineSynopsis(span) {
				continue
			}
			for _, argv := range doclex.ShellCommands(span, 0) {
				out = append(out, doclex.Command{Source: src, Line: ln, Text: span, Argv: argv})
			}
		}
	}
	slices.SortFunc(out, func(a, b doclex.Command) int { return a.Line - b.Line })
	return out
}

func docInlineSynopsis(span string) bool {
	if strings.ContainsAny(span, "[|…") || strings.Contains(span, "...") ||
		strings.Contains(span, "<command>") || strings.Contains(span, "<subcommand>") {
		return true
	}
	// `vigolium finding/traffic` names two commands at once.
	for _, w := range strings.Fields(span)[1:] {
		if strings.HasPrefix(w, "-") {
			break
		}
		if strings.Contains(w, "/") && !strings.Contains(w, "://") && !strings.Contains(w, ".") {
			return true
		}
	}
	return false
}

// TestDocArgsAllowlistIsSmall: the allowlist must not become a dumping ground.
func TestDocArgsAllowlistIsSmall(t *testing.T) {
	if len(docArgsAllowlist) > 5 {
		t.Errorf("docArgsAllowlist has %d entries; cap is 5 — move the check into the command's Args instead", len(docArgsAllowlist))
	}
	for path, why := range docArgsAllowlist {
		if strings.TrimSpace(why) == "" {
			t.Errorf("docArgsAllowlist[%q] needs a reason", path)
		}
	}
}

// TestDocEnumTablesNameRealCommands keeps the path-scoped enum tables honest:
// every command they name exists and owns the flag they validate.
func TestDocEnumTablesNameRealCommands(t *testing.T) {
	prepareCommandTree(rootCmd)
	find := func(path string) *cobra.Command {
		cmd, rest, err := rootCmd.Find(strings.Fields(path)[1:])
		if err != nil || len(rest) > 0 || cmd.CommandPath() != path {
			t.Fatalf("%q is not a command", path)
		}
		return cmd
	}
	for _, p := range docScanFamily {
		c := find(p)
		if c.Flags().Lookup("skip") == nil {
			t.Errorf("%s has no --skip", p)
		}
	}
	for p := range docFormatSurfaces {
		if find(p).Flag("format") == nil {
			t.Errorf("%s has no --format", p)
		}
	}
}

func TestDocValidatorCatchesKnownRot(t *testing.T) {
	prepareCommandTree(rootCmd)
	bad := []string{
		"vigolium source ls",                             // removed command
		"vigolium server -t https://x",                   // flag never existed
		"vigolium agent session my-session",              // name where a UUID goes
		"vigolium scan -T openapi.yaml",                  // spec to the target-list flag
		"vigolium scan -t https://x --only crawling-ish", // not a phase
		"vigolium scan -t https://x --format htm",        // not a format
		"vigolium finding --fail-on severe",              // not a severity
		"vigolium ext eval 'vigolium.nosuch.thing()'",    // unknown API
		"vigolium db nosuch",                             // unknown subcommand
		"vigolium agent query --agent x --prompt hi",     // deprecated flag
		"vigolium run crawling-ish -t https://x",         // not a phase
		"vigolium ffuf -u https://t/FUZZ -nosuch",        // shim cannot translate
	}
	for _, line := range bad {
		cmds := doclex.ShellCommands(line, 0)
		if len(cmds) != 1 {
			t.Fatalf("%s: extracted %d commands", line, len(cmds))
		}
		if _, err := validateDocArgv(rootCmd, cmds[0], false, 0); err == nil {
			t.Errorf("validator accepted %q", line)
		}
	}
	cmds := doclex.ShellCommands("vigolium agent query --agent x --prompt hi # doccheck: deprecated-ok", 0)
	if _, err := validateDocArgv(rootCmd, cmds[0], true, 0); err != nil {
		t.Errorf("deprecated-ok line rejected: %v", err)
	}
	good := []string{
		"vigolium scan -t https://x --only dynamic-assessment --format jsonl -o r.jsonl",
		"vigolium finding -h",
		"vigolium help scan",
		"vigolium ffuf -u https://target/FUZZ -w words.txt --dry-run",
	}
	for _, line := range good {
		for _, argv := range doclex.ShellCommands(line, 0) {
			if _, err := validateDocArgv(rootCmd, argv, false, 0); err != nil {
				t.Errorf("validator rejected %q: %v", line, err)
			}
		}
	}
}
