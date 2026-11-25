package cli

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// The most common failure when an LLM drives this engine is not a wrong flag —
// it is a child that was told to map a target, could not picture how, and went
// hunting the operator's host for ffuf / katana / nuclei / gau. It usually FINDS
// them, and then the whole mapping happens outside the engine: outside the
// pinned traffic database, outside the phase model, with flags nobody scoped.
//
// The instinctive response is enforcement — a "instead of X run Y" table, a
// route-rules file, a hook that refuses the binary, prompt-level tool-inventory
// rewriting. That is a lot of machinery to displace muscle memory, and it
// converts a capable action into a refusal.
//
// These shims accept the muscle memory instead. `vigolium ffuf -u URL/FUZZ -w
// list` parses the familiar argv, translates it to the native phase, writes to
// the pinned database, and prints one line saying what actually ran. A refusal
// becomes a redirect that just works.
//
// Three rules keep them honest:
//
//  1. They TRANSLATE, they do not reimplement. Each builds a vigolium command
//     line and runs it through the same cobra tree, so a shim can never drift
//     from the command it fronts.
//  2. They always print the translation, plus a note for every approximation.
//     A silent redirect is a different surprise, not a smaller one — the
//     operator (or the agent reading the output) has to be able to learn the
//     native spelling. `--dry-run` prints it without running anything.
//  3. An argument they do not understand is a hard error naming the native
//     command, never a silent drop. A dropped flag is a scan that ran with a
//     scope nobody chose, which is the failure this exists to prevent.
//
// Vigolium's own global flags (--db, --proxy, -j, --project-name, …) are
// accepted only BEFORE the tool's argv, or before an explicit `--` separator:
//
//	vigolium --db x.sqlite ffuf -u https://t/FUZZ -w list
//	vigolium ffuf --db x.sqlite -u https://t/FUZZ -w list
//	vigolium nuclei -j -- -u https://t        (-j alone would be nuclei's JSONL)
//
// Anywhere else a flag belongs to the foreign tool. Accepting globals in the
// middle would be ambiguous: ffuf -v, nuclei -j and katana -j all collide with
// vigolium spellings, so each tool carries the set of its names that must never
// be read as a vigolium global (shimSpec.collisions plus every name its rule
// table knows).

// shimSpec describes one aliased tool.
type shimSpec struct {
	name    string
	short   string
	example string
	// native names the command(s) this tool is routed to, for help text.
	native string
	// translatesTo lists every native command line translate can produce, as
	// `<command path>` or `run <canonical phase>`: what `schema commands -j`
	// publishes as translates_to. TestShimTranslatesToCoversExamples holds it
	// to translate.
	translatesTo []string
	// longDash is how the tool spells a multi-letter flag in its own docs ("-"
	// for ffuf/nuclei/katana, "--" for gau/arjun), used by the help table.
	longDash string
	// collisions are tool flag names that are also vigolium root flags but are
	// NOT in the rule table (the tool's own meaning differs, and the shim does
	// not translate them). Rule-table names collide implicitly.
	collisions []string
	// rules returns the tool's flag table bound to throwaway state; the help
	// text and the collision set are built from it, so neither can drift from
	// what translate accepts.
	rules func() map[string]shimRule
	// translate turns the tool's argv into a vigolium argv (without the leading
	// "vigolium"). It returns an error naming the native command when it meets an
	// argument it cannot map.
	translate func(args []string) (shimTranslation, error)
}

// shimTranslation is a translated command line plus the approximations it made.
type shimTranslation struct {
	argv  []string
	notes []string
}

// shimSpecs is the registered tool table.
var shimSpecs = []shimSpec{
	{
		name:         "ffuf",
		short:        "Content discovery / fuzzing with ffuf's argv (routed to `vigolium run discovery` or `vigolium fuzz`)",
		example:      "vigolium ffuf -u https://target/FUZZ -w words.txt",
		native:       "fuzz (a -w wordlist run), or run discovery (FUZZ as the whole last path segment with -recursion, or with no -w)",
		translatesTo: []string{"fuzz", "run discovery"},
		longDash:     "-",
		// ffuf -json is JSON-lines result output; -config is ffuf's own file.
		collisions: []string{"json", "config", "debug-log"},
		rules:      func() map[string]shimRule { return ffufRules(&ffufState{}) },
		translate:  translateFFUF,
	},
	{
		name:         "nuclei",
		short:        "Run the known-issue scan using nuclei's argv (routed to `vigolium run known-issue-scan`)",
		example:      "vigolium nuclei -u https://target -severity high,critical",
		native:       "run known-issue-scan",
		translatesTo: []string{"run known-issue-scan"},
		longDash:     "-",
		collisions:   []string{"v", "verbose", "debug", "config"},
		rules:        func() map[string]shimRule { return nucleiRules(&nucleiState{}) },
		translate:    translateNuclei,
	},
	{
		name:         "katana",
		short:        "Crawl using katana's argv (routed to `vigolium run spidering`)",
		example:      "vigolium katana -u https://target -ct 120",
		native:       "run spidering",
		translatesTo: []string{"run spidering"},
		longDash:     "-",
		// katana -j is JSONL output, not vigolium's envelope.
		collisions: []string{"j", "json", "jsonl", "v", "verbose", "debug", "config"},
		rules:      func() map[string]shimRule { return katanaRules(&katanaState{}) },
		translate:  translateKatana,
	},
	{
		name:         "gau",
		short:        "Harvest archived URLs using gau's argv (routed to `vigolium run external-harvest`)",
		example:      "vigolium gau target.example.com",
		native:       "run external-harvest",
		translatesTo: []string{"run external-harvest"},
		longDash:     "--",
		collisions:   []string{"json", "verbose", "config"},
		rules:        func() map[string]shimRule { return gauRules() },
		translate:    translateGau,
	},
	{
		name:         "arjun",
		short:        "Discover parameters using arjun's argv (routed to `vigolium fuzz --fuzz new-param`)",
		example:      "vigolium arjun -u https://target/api",
		native:       "fuzz --fuzz new-param",
		translatesTo: []string{"fuzz"},
		longDash:     "--",
		rules:        func() map[string]shimRule { return arjunRules(&arjunState{}) },
		translate:    translateArjun,
	},
	{
		name:         "dig",
		short:        "Resolve names using dig's argv (routed to `vigolium dns`, which stores the answers)",
		example:      "vigolium dig +short MX example.com @1.1.1.1",
		native:       "dns",
		translatesTo: []string{"dns"},
		longDash:     "-",
		rules:        digRules,
		translate:    translateDig,
	},
	{
		name:         "host",
		short:        "Resolve names using host's argv (routed to `vigolium dns`, which stores the answers)",
		example:      "vigolium host -t mx example.com",
		native:       "dns",
		translatesTo: []string{"dns"},
		longDash:     "-",
		rules:        hostRules,
		translate:    translateHost,
	},
}

func init() {
	for _, spec := range shimSpecs {
		rootCmd.AddCommand(newShimCommand(spec))
	}
}

func newShimCommand(spec shimSpec) *cobra.Command {
	cmd := &cobra.Command{
		Use:   spec.name + " [vigolium globals] [--] [" + spec.name + " flags]",
		Short: spec.short,
		Long: fmt.Sprintf(`Accepts the familiar %[1]s command line and runs the equivalent native vigolium
command: %[2]s.

Results land in the pinned database and the phase model, which is the whole
point: a scan run through the real %[1]s binary happens outside both, with flags
nobody scoped. The translated command is printed before it runs, with a note for
every approximation, so the native spelling is always one invocation away.

Vigolium global flags (--db, --proxy, -j, --project-name, ...) go BEFORE the %[1]s
argv, or before an explicit "--":
  vigolium %[1]s --db scan.sqlite <%[1]s flags>
  vigolium %[1]s -j -- <%[1]s flags>
--dry-run prints the translation (with -j: a JSON envelope) and runs nothing.

Example:
  %[3]s

Flag translation (anything not listed is refused, naming the native command):
%[4]s`, spec.name, spec.native, spec.example, renderShimFlagTable(spec)),
		// Unknown flags must reach translate rather than being rejected by cobra:
		// the whole surface is another tool's, and cobra knows none of it.
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// `--help` on a shim is a request to read this command's own help, not
			// to translate. DisableFlagParsing means cobra will not have handled it.
			for _, a := range args {
				if a == "-h" || a == "--help" {
					return cmd.Help()
				}
			}
			split, err := splitShimGlobals(spec, args, rootCmd.PersistentFlags())
			if err != nil {
				return asUsageError(err)
			}
			// Parse the globals now, not only in the nested Execute, so --no-color,
			// --silent and -j shape this command's own output (the routed-to line
			// and --dry-run). The nested Execute runs the translated argv alone:
			// the values are already set, and parsing a repeatable global (--ext)
			// twice would load it twice.
			if len(split.globals) > 0 {
				if err := rootCmd.PersistentFlags().Parse(split.globals); err != nil {
					return asUsageError(fmt.Errorf("%s: %w", spec.name, err))
				}
				cmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
				if err := applyColorFlag(cmd); err != nil {
					return err
				}
			}
			tr, err := spec.translate(split.foreign)
			if err != nil {
				return asUsageError(err)
			}
			display := append(append([]string{}, split.globals...), tr.argv...)
			if split.dryRun {
				return emitShimDryRun(cmd, spec.name, args, display, tr.notes)
			}
			if !globalSilent {
				printShimRoute(display, tr.notes)
			}
			// Silence the nested Execute's own error print: this RunE returns the
			// error, so the outer ExecuteC prints it. Without this a failing
			// translated command reports "Error: …" twice. Restored afterwards so
			// a later direct invocation is unaffected.
			prior := rootCmd.SilenceErrors
			rootCmd.SilenceErrors = true
			defer func() { rootCmd.SilenceErrors = prior }()
			rootCmd.SetArgs(tr.argv)
			return rootCmd.Execute()
		},
	}
	return cmd
}

// printShimRoute is the always-on translation line (stderr), plus one note per
// approximation.
func printShimRoute(argv, notes []string) {
	fmt.Fprintf(os.Stderr, "%s %s %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("routed to:"),
		terminal.BoldCyan(shimCommandLine(argv)))
	for _, n := range notes {
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Gray("note:"), n)
	}
}

// shimCommandLine renders argv as a pasteable vigolium command.
func shimCommandLine(argv []string) string {
	return quoteArgv(append([]string{"vigolium"}, argv...))
}

// shimDryRun is the --dry-run report: what would run, and every approximation.
type shimDryRun struct {
	Tool          string   `json:"tool"`
	Argv          []string `json:"argv"`
	Translated    []string `json:"translated"`
	NativeCommand string   `json:"native_command"`
	Notes         []string `json:"notes"`
}

func emitShimDryRun(cmd *cobra.Command, tool string, argv, translated, notes []string) error {
	report := shimDryRun{
		Tool:          tool,
		Argv:          append([]string{}, argv...),
		Translated:    translated,
		NativeCommand: shimCommandLine(translated),
		Notes:         notes,
	}
	if report.Notes == nil {
		report.Notes = []string{}
	}
	if globalJSON {
		return emitObject(cmd, ".", report, withDryRun())
	}
	fmt.Println(report.NativeCommand)
	for _, n := range notes {
		fmt.Printf("# note: %s\n", n)
	}
	fmt.Fprintf(os.Stderr, "%s dry run — nothing executed\n", terminal.InfoSymbol())
	return nil
}

// shimSplit is argv separated into vigolium globals and the foreign tool's argv.
type shimSplit struct {
	globals []string
	foreign []string
	dryRun  bool
}

// splitShimGlobals separates leading vigolium global flags from the tool's
// argv. Two forms:
//
//   - explicit: everything before the first `--` must be vigolium globals (or
//     --dry-run); everything after it belongs to the tool. Collisions do not
//     apply — the separator says which side a flag is on.
//   - implicit: leading tokens are consumed as globals while they are root
//     persistent flags whose name the tool does not also use; the first
//     other token starts the tool's argv.
//
// --dry-run is vigolium's wherever it appears (none of these tools has one).
func splitShimGlobals(spec shimSpec, args []string, root *pflag.FlagSet) (shimSplit, error) {
	var out shimSplit
	if sep := slices.Index(args, "--"); sep >= 0 {
		globals, n, dry, err := consumeShimGlobals(spec.name, args[:sep], root, nil)
		if err != nil {
			return out, err
		}
		if n != sep {
			return out, fmt.Errorf("%s: only vigolium global flags may precede \"--\" (found %q); put %s flags after it",
				spec.name, args[n], spec.name)
		}
		out.globals, out.dryRun = globals, dry
		out.foreign = stripDryRun(args[sep+1:], &out.dryRun)
		return out, nil
	}
	globals, n, dry, err := consumeShimGlobals(spec.name, args, root, shimCollisions(spec))
	if err != nil {
		return out, err
	}
	out.globals, out.dryRun = globals, dry
	out.foreign = stripDryRun(args[n:], &out.dryRun)
	return out, nil
}

// consumeShimGlobals reads leading root persistent flags (`--name[=v]` or
// `-x`) from tokens, stopping at the first token that is not one or whose name
// is in collide. It returns the consumed global tokens, how many input tokens
// were used, and whether --dry-run was among them.
func consumeShimGlobals(tool string, tokens []string, root *pflag.FlagSet, collide map[string]bool) (globals []string, n int, dryRun bool, err error) {
	for n < len(tokens) {
		a := tokens[n]
		if a == "--dry-run" {
			dryRun = true
			n++
			continue
		}
		f, name, inline := lookupShimGlobal(root, a)
		if f == nil || collide[name] {
			break
		}
		globals = append(globals, a)
		n++
		if inline || f.NoOptDefVal != "" {
			continue
		}
		if n >= len(tokens) {
			return nil, 0, false, fmt.Errorf("%s: vigolium flag %s needs a value", tool, a)
		}
		globals = append(globals, tokens[n])
		n++
	}
	return globals, n, dryRun, nil
}

// lookupShimGlobal resolves a token to a root persistent flag. Only pflag's
// own spellings count: `--long[=v]` and a one-letter `-x`. A single-dash long
// flag (`-json`) is the foreign tools' style and never a vigolium global.
func lookupShimGlobal(root *pflag.FlagSet, tok string) (f *pflag.Flag, name string, inline bool) {
	switch {
	case strings.HasPrefix(tok, "--") && len(tok) > 2:
		name = tok[2:]
		if i := strings.IndexByte(name, '='); i >= 0 {
			name, inline = name[:i], true
		}
		return root.Lookup(name), name, inline
	case len(tok) == 2 && tok[0] == '-' && tok[1] != '-':
		name = tok[1:]
		return root.ShorthandLookup(name), name, false
	}
	return nil, "", false
}

// shimCollisions is every name the tool owns that a vigolium global must not
// claim: the rule table's keys plus the declared extras.
func shimCollisions(spec shimSpec) map[string]bool {
	set := make(map[string]bool)
	for name := range spec.rules() {
		set[name] = true
	}
	for _, name := range spec.collisions {
		set[name] = true
	}
	return set
}

func stripDryRun(args []string, dry *bool) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--dry-run" {
			*dry = true
			continue
		}
		out = append(out, a)
	}
	return out
}

// renderShimFlagTable renders the tool's rule table for --help: one row per
// distinct rule, aliases joined, sorted by the first spelling.
func renderShimFlagTable(spec shimSpec) string {
	type row struct{ names, desc string }
	groups := map[string][]string{}
	descs := map[string]string{}
	for name, r := range spec.rules() {
		d := r.describe()
		groups[d] = append(groups[d], name)
		descs[d] = d
	}
	rows := make([]row, 0, len(groups))
	for d, names := range groups {
		sort.Slice(names, func(i, j int) bool {
			if len(names[i]) != len(names[j]) {
				return len(names[i]) < len(names[j])
			}
			return names[i] < names[j]
		})
		spelled := make([]string, len(names))
		for i, n := range names {
			if len(n) == 1 {
				spelled[i] = "-" + n
			} else {
				spelled[i] = spec.longDash + n
			}
		}
		rows = append(rows, row{names: strings.Join(spelled, ", "), desc: descs[d]})
	}
	sort.Slice(rows, func(i, j int) bool {
		return strings.TrimLeft(rows[i].names, "-") < strings.TrimLeft(rows[j].names, "-")
	})
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	for _, r := range rows {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\n", r.names, r.desc)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// shimArgs is a tiny scanner over another tool's argv. It exists so each
// translator reads as a table of recognized flags rather than as index
// arithmetic, and so "unknown flag" is one shared error instead of five.
type shimArgs struct {
	tool   string
	native string
	args   []string
	i      int
	notes  []string
}

func newShimArgs(tool, native string, args []string) *shimArgs {
	return &shimArgs{tool: tool, native: native, args: args}
}

func (s *shimArgs) more() bool { return s.i < len(s.args) }
func (s *shimArgs) next() string {
	v := s.args[s.i]
	s.i++
	return v
}

// note records an approximation once.
func (s *shimArgs) note(n string) {
	if !slices.Contains(s.notes, n) {
		s.notes = append(s.notes, n)
	}
}

// value returns the argument belonging to flag, accepting both `-u X` and
// `-u=X`. Returns an error rather than an empty string when the value is
// missing: a flag whose value silently became "" is a scope nobody chose.
func (s *shimArgs) value(flag string) (string, error) {
	if i := strings.IndexByte(flag, '='); i >= 0 {
		return flag[i+1:], nil
	}
	if !s.more() {
		return "", fmt.Errorf("%s: %s needs a value", s.tool, flag)
	}
	return s.next(), nil
}

// unknown is the shared refusal. It names the native command so the operator's
// next move is obvious, which is the difference between a redirect and a wall.
// native may list alternatives separated by "|" (ffuf routes to two commands).
func (s *shimArgs) unknown(flag string) error {
	var helps []string
	for _, n := range strings.Split(s.native, "|") {
		helps = append(helps, "vigolium "+n+" --help")
	}
	return fmt.Errorf("%s: %q has no vigolium equivalent in this shim.\n"+
		"Run the native command directly and pass what you need: %s (flag table: vigolium %s --help)",
		s.tool, flag, strings.Join(helps, " or "), s.tool)
}

// flagName strips a leading dash run and any =value suffix, so `-u`, `--u` and
// `-u=X` all normalize to "u". Both single- and double-dash forms are accepted
// because these tools disagree about which they use (ffuf and nuclei take
// single-dash long flags; katana takes both).
func flagName(arg string) string {
	name := strings.TrimLeft(arg, "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	return name
}

// shimRule is one recognized flag in a tool's argv.
//
// The five translators are one algorithm — scan argv, map a flag to its native
// spelling, emit its value — and writing that out per tool meant the same
// four-line `value(); if err; append` dance appeared thirty-odd times. A missed
// error return in any one of them silently yields "", i.e. the "scope nobody
// chose" failure this whole file exists to prevent. One driver, five tables.
type shimRule struct {
	// to is the native flag to emit. Empty means "recognize and swallow" — the
	// behaviour the tool asks for is already on, so accepting it is honest.
	to string
	// bare marks a flag that takes no value.
	bare bool
	// set records a bare flag's presence (for translators that decide a route
	// after the whole argv is read).
	set *bool
	// xform rewrites the value before it is emitted.
	xform func(string) string
	// parse validates and rewrites the value; an error is a usage error.
	parse func(string) (string, error)
	// capture accumulates the value instead of emitting it (targets, wordlists).
	capture *string
	// appendTo accumulates a repeatable value.
	appendTo *[]string
	// into, when set, receives the `to value` pair instead of the main argv
	// (flags that only apply on one of a tool's routes).
	into *[]string
	// refuse, when non-empty, rejects the flag with this message. It is how a
	// shim says "this concept does not exist here" instead of approximating it —
	// the value is available as %s.
	refuse string
	// note is recorded (once) whenever the flag is used: the approximation the
	// translation makes. The value is available as %s for valued flags.
	note string
	// doc is the --help table's description. Empty derives it from to.
	doc string
}

// describe is the rule's --help table cell.
func (r shimRule) describe() string {
	if r.doc != "" {
		return r.doc
	}
	switch {
	case r.refuse != "":
		return "refused"
	case r.to != "" && r.bare:
		return r.to
	case r.to != "":
		return r.to + " <value>"
	default:
		return "accepted (no-op)"
	}
}

// drive scans argv against rules, appending translated flags to out. A bare
// (non-flag) argument goes to positional when non-nil, otherwise it is an error.
func (s *shimArgs) drive(out []string, rules map[string]shimRule, positional *[]string) ([]string, error) {
	for s.more() {
		arg := s.next()
		if positional != nil && !strings.HasPrefix(arg, "-") {
			*positional = append(*positional, arg)
			continue
		}
		rule, ok := rules[flagName(arg)]
		if !ok {
			return nil, s.unknown(arg)
		}
		if rule.bare {
			if rule.set != nil {
				*rule.set = true
			}
			if rule.note != "" {
				s.note(rule.note)
			}
			if rule.to != "" {
				if rule.into != nil {
					*rule.into = append(*rule.into, rule.to)
				} else {
					out = append(out, rule.to)
				}
			}
			continue
		}
		v, err := s.value(arg)
		if err != nil {
			return nil, err
		}
		if rule.refuse != "" {
			return nil, fmt.Errorf("%s: %s", s.tool, fmt.Sprintf(rule.refuse, v))
		}
		if rule.xform != nil {
			v = rule.xform(v)
		}
		if rule.parse != nil {
			if v, err = rule.parse(v); err != nil {
				return nil, fmt.Errorf("%s: %s: %w", s.tool, arg, err)
			}
		}
		if rule.note != "" {
			s.note(strings.ReplaceAll(rule.note, "%s", v))
		}
		switch {
		case rule.capture != nil:
			*rule.capture = v
		case rule.appendTo != nil:
			*rule.appendTo = append(*rule.appendTo, v)
		case rule.into != nil:
			*rule.into = append(*rule.into, rule.to, v)
		case rule.to != "":
			out = append(out, rule.to, v)
		}
	}
	return out, nil
}

// emitTargets appends one `-t <url>` pair per target.
func emitTargets(out []string, targets []string) []string {
	for _, t := range targets {
		out = append(out, "-t", t)
	}
	return out
}

// secondsToMillis converts a seconds value (integer or decimal, as ffuf -p and
// arjun -d take it) to whole milliseconds.
func secondsToMillis(v string) (string, error) {
	if strings.Contains(v, "-") {
		return "", fmt.Errorf("a delay range (%s) has no equivalent; vigolium fuzz --delay is a fixed delay in ms", v)
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return "", fmt.Errorf("want a non-negative number of seconds, got %q", v)
	}
	return strconv.Itoa(int(f*1000 + 0.5)), nil
}

func nonNegativeInt(v string) (string, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return "", fmt.Errorf("want a non-negative integer, got %q", v)
	}
	return v, nil
}

// ---------------------------------------------------------------- ffuf ----

type ffufState struct {
	target         string
	wordlists      []string
	headers        []string
	method         string
	data           string
	fuzzOnly       []string // matcher/filter pairs: fuzz route only
	delay          string
	exts           string
	recursion      bool
	recursionDepth string
	autoCalibrate  bool
	output         string
	outputFormat   string
}

func ffufRules(st *ffufState) map[string]shimRule {
	fuzzOnly := func(to string) shimRule {
		return shimRule{to: to, into: &st.fuzzOnly, doc: "fuzz " + to + " <value> (routes to fuzz)"}
	}
	r := map[string]shimRule{
		"u": {capture: &st.target, doc: "target URL: with -w → fuzz <url> (marker kept); FUZZ as the whole last path segment with -recursion (or no -w) → run discovery -t <url without /FUZZ>"},
		"w": {appendTo: &st.wordlists, doc: "PATH[:KEYWORD] → --discovery-wordlist PATH, or fuzz -w PATH (+ --keyword KEYWORD)"},
		"H": {appendTo: &st.headers, doc: "-H (FUZZ in a header routes to fuzz)"},
		"X": {capture: &st.method, doc: "fuzz -X (a non-GET method routes to fuzz)"},
		"d": {capture: &st.data, doc: "fuzz -d (a body routes to fuzz)"},

		"mc": fuzzOnly("--match-status-code"),
		"ms": fuzzOnly("--match-size"),
		"mw": fuzzOnly("--match-words"),
		"ml": fuzzOnly("--match-lines"),
		"mr": fuzzOnly("--match-regex"),
		"fc": fuzzOnly("--exclude-status-code"),
		"fs": fuzzOnly("--exclude-size"),
		"fw": fuzzOnly("--exclude-words"),
		"fl": fuzzOnly("--exclude-lines"),
		"fr": fuzzOnly("--exclude-regex"),
		"ac": {bare: true, set: &st.autoCalibrate,
			note: "-ac accepted: discovery (soft-404 fingerprinting) and fuzz (catch-all calibration) both calibrate by default",
			doc:  "accepted (no-op): both routes calibrate against the catch-all by default"},

		"rate":    {to: "--rate-limit", doc: "--rate-limit <req/s> (both routes)"},
		"t":       {to: "--concurrency", doc: "--concurrency <n> (both routes)"},
		"p":       {capture: &st.delay, parse: secondsToMillis, doc: "fuzz --delay <ms> (seconds converted; fuzz route only)"},
		"x":       {to: "--proxy"},
		"timeout": {to: "--timeout", xform: func(v string) string { return v + "s" }, doc: "--timeout <n>s"},
		"s":       {to: "--silent", bare: true},
		"v":       {to: "--verbose", bare: true},
		"o":       {capture: &st.output, doc: "-o (fuzz: the per-payload JSONL stream; discovery: vigolium's scan output)"},
		"of":      {capture: &st.outputFormat, doc: "accepted (no-op, noted): vigolium picks the file format"},
		"e":       {capture: &st.exts, doc: "discovery: --discovery-extensions (dots stripped); fuzz: --suffix (appended literally)"},
		"recursion": {bare: true, set: &st.recursion,
			doc: "routes a last-segment FUZZ to run discovery (which recurses by default); refused on the fuzz route"},
		"recursion-depth": {capture: &st.recursionDepth, parse: nonNegativeInt, doc: "--discovery-max-depth <n> (discovery route only)"},
	}
	for alias, canon := range map[string]string{
		"url": "u", "wordlist": "w", "header": "H", "data": "d",
		"threads": "t", "proxy": "x", "silent": "s",
	} {
		r[alias] = r[canon]
	}
	return r
}

func translateFFUF(args []string) (shimTranslation, error) {
	st := &ffufState{}
	s := newShimArgs("ffuf", "run discovery|fuzz", args)
	common, err := s.drive(nil, ffufRules(st), nil)
	if err != nil {
		return shimTranslation{}, err
	}
	if st.target == "" {
		return shimTranslation{}, usageErrorf("ffuf: -u/--url is required")
	}

	// ffuf allows `-w list:KEYWORD`; one keyword per run is all either route
	// can express (several keywords is ffuf's clusterbomb, which `vigolium fuzz
	// --mode` spells with numbered markers instead).
	keyword := "FUZZ"
	var paths []string
	keywords := map[string]bool{}
	for _, w := range st.wordlists {
		p, kw := splitWordlistKeyword(w)
		paths = append(paths, p)
		if kw != "" {
			keywords[kw] = true
			keyword = kw
		}
	}
	if len(keywords) > 1 {
		return shimTranslation{}, usageErrorf("ffuf: several wordlist keywords (%s) have no shim equivalent — use numbered markers with `vigolium fuzz --mode clusterbomb` (see vigolium fuzz --help)",
			strings.Join(sortedKeywordSet(keywords), ", "))
	}

	inHeaders := slices.ContainsFunc(st.headers, func(h string) bool { return strings.Contains(h, keyword) })
	inData := strings.Contains(st.data, keyword)
	inTarget := strings.Contains(st.target, keyword)
	if !inTarget && !inHeaders && !inData {
		return shimTranslation{}, usageErrorf("ffuf: keyword %s not found in -u, -H or -d", keyword)
	}

	var reasons []string
	switch {
	case inTarget && !fuzzMarkerIsLastSegment(st.target, keyword):
		reasons = append(reasons, keyword+" is not the whole last path segment")
	case inHeaders:
		reasons = append(reasons, keyword+" is in a header")
	case inData:
		reasons = append(reasons, keyword+" is in the body")
	}
	if len(st.fuzzOnly) > 0 {
		reasons = append(reasons, "matchers/filters were given (discovery has none)")
	}
	// A wordlist run of one path segment is what ffuf does: send each word,
	// once. Discovery would crawl, recurse and add its own lists on top, so
	// it takes the run only when -recursion asks for that.
	if len(reasons) == 0 && len(paths) > 0 && !st.recursion && st.recursionDepth == "" {
		reasons = append(reasons, "a wordlist over one path segment is sent word by word (pass -recursion for content discovery, which also crawls and recurses)")
	}
	if st.data != "" && !inData {
		reasons = append(reasons, "-d sets a body (discovery sends none)")
	}
	if st.method != "" && !strings.EqualFold(st.method, "GET") {
		reasons = append(reasons, "-X "+st.method+" (discovery sends GET)")
	}

	tr := shimTranslation{notes: s.notes}
	if len(reasons) == 0 {
		return ffufDiscoveryRoute(st, common, paths, tr)
	}
	return ffufFuzzRoute(st, common, paths, keyword, reasons, tr)
}

func ffufDiscoveryRoute(st *ffufState, common, paths []string, tr shimTranslation) (shimTranslation, error) {
	if st.delay != "" {
		return tr, usageErrorf("ffuf: -p (delay) applies only when routed to `vigolium fuzz`; pace discovery with -rate instead")
	}
	out := []string{"run", "discovery", "-t", stripFuzzMarker(st.target)}
	for _, p := range paths {
		out = append(out, "--discovery-wordlist", p)
	}
	for _, h := range st.headers {
		out = append(out, "-H", h)
	}
	if st.exts != "" {
		out = append(out, "--discovery-extensions", strings.Join(normalizeDiscoveryExtensions(strings.Split(st.exts, ",")), ","))
	}
	if st.recursion {
		tr.notes = append(tr.notes, "-recursion accepted: discovery recurses by default (discovery.recursion.max_depth, default 5)")
	}
	if st.recursionDepth != "" {
		out = append(out, "--discovery-max-depth", st.recursionDepth)
	}
	if st.output != "" {
		out = append(out, "-o", st.output)
		tr.notes = append(tr.notes, "-o receives vigolium's scan output (per --format), not ffuf's result schema; the discovered URLs are in `vigolium traffic`")
	}
	if st.outputFormat != "" {
		tr.notes = append(tr.notes, "-of "+st.outputFormat+" ignored: vigolium picks the output format (--format)")
	}
	tr.argv = append(out, common...)
	return tr, nil
}

func ffufFuzzRoute(st *ffufState, common, paths []string, keyword string, reasons []string, tr shimTranslation) (shimTranslation, error) {
	if len(paths) == 0 {
		return tr, usageErrorf("ffuf: -w is required when routed to `vigolium fuzz` (%s)", strings.Join(reasons, "; "))
	}
	if st.recursion || st.recursionDepth != "" {
		return tr, usageErrorf("ffuf: -recursion has no equivalent on the fuzz route (%s); drop the matchers and put FUZZ as the whole last path segment to route to discovery, which recurses by default",
			strings.Join(reasons, "; "))
	}
	out := []string{"fuzz", st.target}
	for _, p := range paths {
		out = append(out, "-w", p)
	}
	if keyword != "FUZZ" {
		out = append(out, "--keyword", keyword)
	}
	if st.method != "" {
		out = append(out, "-X", st.method)
	}
	if st.data != "" {
		out = append(out, "-d", st.data)
	}
	for _, h := range st.headers {
		out = append(out, "-H", h)
	}
	out = append(out, st.fuzzOnly...)
	if st.delay != "" {
		out = append(out, "--delay", st.delay)
	}
	if st.exts != "" {
		out = append(out, "--suffix", st.exts)
	}
	if st.output != "" {
		out = append(out, "-o", st.output)
	}
	if st.outputFormat != "" {
		tr.notes = append(tr.notes, "-of "+st.outputFormat+" ignored: fuzz writes the per-payload JSONL stream to -o")
	}
	tr.notes = append([]string{"routed to fuzz, not discovery: " + strings.Join(reasons, "; ")}, tr.notes...)
	tr.argv = append(out, common...)
	return tr, nil
}

// fuzzMarkerIsLastSegment reports whether keyword appears exactly once in the
// URL, as the whole last path segment (`/FUZZ` or `/FUZZ/`, no query) — the
// shape content discovery brute-forces by construction.
func fuzzMarkerIsLastSegment(target, keyword string) bool {
	if strings.Count(target, keyword) != 1 {
		return false
	}
	t := strings.TrimSuffix(target, "/")
	return strings.HasSuffix(t, "/"+keyword) && !strings.Contains(t, "?")
}

func stripFuzzMarker(v string) string {
	return strings.TrimSuffix(strings.ReplaceAll(v, "FUZZ", ""), "/")
}

// splitWordlistKeyword splits ffuf's `PATH:KEYWORD`. A colon early in the
// value (a Windows drive letter) is part of the path.
func splitWordlistKeyword(v string) (path, keyword string) {
	if i := strings.LastIndexByte(v, ':'); i > 1 && i < len(v)-1 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func sortedKeywordSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -------------------------------------------------------------- nuclei ----

type nucleiState struct {
	targets   []string
	list      string
	templates []string
}

func nucleiRules(st *nucleiState) map[string]shimRule {
	r := map[string]shimRule{
		"u":           {appendTo: &st.targets, doc: "-t <url> (repeatable)"},
		"l":           {capture: &st.list, doc: "-T <file> (target list)"},
		"severity":    {to: "--known-issue-scan-severities"},
		"tags":        {to: "--known-issue-scan-tags"},
		"etags":       {to: "--known-issue-scan-exclude-tags"},
		"t":           {appendTo: &st.templates, doc: "directory → --known-issue-scan-templates-dir; file or template ID → --known-issue-scan-templates (repeatable)"},
		"rl":          {to: "--rate-limit"},
		"c":           {to: "--concurrency"},
		"H":           {to: "-H"},
		"proxy":       {to: "--proxy"},
		"silent":      {to: "--silent", bare: true},
		"j":           {to: "--json", bare: true},
		"no-color":    {to: "--no-color", bare: true},
		"disable-ust": {bare: true, doc: "accepted (no-op): vigolium never auto-updates templates mid-scan"},
	}
	for alias, canon := range map[string]string{
		"target": "u", "list": "l", "s": "severity", "exclude-tags": "etags",
		"templates": "t", "rate-limit": "rl", "concurrency": "c", "header": "H",
		"jsonl": "j", "json": "j", "nc": "no-color",
	} {
		r[alias] = r[canon]
	}
	return r
}

func translateNuclei(args []string) (shimTranslation, error) {
	st := &nucleiState{}
	s := newShimArgs("nuclei", "run known-issue-scan", args)
	out, err := s.drive([]string{"run", "known-issue-scan"}, nucleiRules(st), nil)
	if err != nil {
		return shimTranslation{}, err
	}
	// No stdin fallback: a shim that silently waits on a pipe nobody connected
	// is a hang, and one that scans whatever happens to be piped is a scope
	// nobody chose.
	if len(st.targets) == 0 && st.list == "" {
		return shimTranslation{}, usageErrorf("nuclei: -u or -l is required")
	}
	tr := shimTranslation{notes: s.notes}
	for _, t := range st.templates {
		if info, err := os.Stat(t); err == nil && info.IsDir() {
			out = append(out, "--known-issue-scan-templates-dir", t)
			continue
		}
		out = append(out, "--known-issue-scan-templates", t)
		if _, err := os.Stat(t); err != nil {
			tr.notes = append(tr.notes, fmt.Sprintf("-t %s is not a local path: passed to nuclei as a template ID/path relative to the templates directory", t))
		}
	}
	if st.list != "" {
		out = append(out, "-T", st.list)
	}
	tr.argv = emitTargets(out, st.targets)
	return tr, nil
}

// -------------------------------------------------------------- katana ----

type katanaState struct {
	targets []string
}

func katanaRules(st *katanaState) map[string]shimRule {
	depthRefusal := "-d/--depth (%s) has no equivalent — vigolium's spider is a state machine, not a depth-limited link follower. Bound the crawl with -ct/--spider-max-time instead"
	r := map[string]shimRule{
		"u":        {appendTo: &st.targets, doc: "URL → -t <url>; an existing file → -T <file> (katana's -u and -list are one flag)"},
		"c":        {to: "--concurrency"},
		"rl":       {to: "--rate-limit"},
		"H":        {to: "-H"},
		"proxy":    {to: "--proxy"},
		"ct":       {to: "--spider-max-time", xform: secondsIfBare, doc: "--spider-max-time (a bare number is seconds, katana's unit)"},
		"silent":   {to: "--silent", bare: true},
		"headless": {bare: true, doc: "accepted (no-op): the spider is always a real browser"},
		"jc": {bare: true,
			note: "-jc accepted: the spider runs every page's JavaScript in a real browser; JS endpoint extraction is discovery's job (vigolium run discovery)",
			doc:  "accepted (no-op): the spider always executes JavaScript"},
		"o": {to: "-o", note: "-o receives vigolium's scan output (per --format), not katana's URL list; crawled URLs are in `vigolium traffic`"},
		"d": {refuse: depthRefusal},
	}
	for alias, canon := range map[string]string{
		"list": "u", "concurrency": "c", "rate-limit": "rl", "headers": "H",
		"crawl-duration": "ct", "hl": "headless", "js-crawl": "jc", "output": "o", "depth": "d",
	} {
		r[alias] = r[canon]
	}
	return r
}

// secondsIfBare appends "s" to a bare number: katana durations default to
// seconds, vigolium's are Go durations that need a unit.
func secondsIfBare(v string) string {
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return v + "s"
	}
	return v
}

func translateKatana(args []string) (shimTranslation, error) {
	st := &katanaState{}
	s := newShimArgs("katana", "run spidering", args)
	out, err := s.drive([]string{"run", "spidering"}, katanaRules(st), nil)
	if err != nil {
		return shimTranslation{}, err
	}
	if len(st.targets) == 0 {
		return shimTranslation{}, usageErrorf("katana: -u or -list is required")
	}
	var urls []string
	for _, t := range st.targets {
		if info, err := os.Stat(t); err == nil && info.Mode().IsRegular() {
			out = append(out, "-T", t)
			continue
		}
		urls = append(urls, t)
	}
	return shimTranslation{argv: emitTargets(out, urls), notes: s.notes}, nil
}

// ----------------------------------------------------------------- gau ----

func gauRules() map[string]shimRule {
	return map[string]shimRule{
		"threads": {to: "--concurrency"},
		"proxy":   {to: "--proxy"},
		// The harvester already queries the *.domain archives, so subdomain
		// URLs are fetched either way; --subs is about keeping them. The
		// relaxed scope origin admits them. --follow-subdomains is NOT the
		// equivalent: it widens the scan itself.
		"subs": {to: "--scope-origin=relaxed", bare: true,
			note: "--subs → --scope-origin relaxed: the harvester already queries *.domain archives; relaxed scope keeps the subdomain URLs (it does not widen the scan the way --follow-subdomains would)"},
	}
}

func translateGau(args []string) (shimTranslation, error) {
	s := newShimArgs("gau", "run external-harvest", args)
	var targets []string
	out, err := s.drive([]string{"run", "external-harvest"}, gauRules(), &targets)
	if err != nil {
		return shimTranslation{}, err
	}
	if len(targets) == 0 {
		return shimTranslation{}, usageErrorf("gau: a target domain is required")
	}
	// gau takes a bare domain; every vigolium phase takes a URL. https rather
	// than the scan default because gau's own callers write bare domains for
	// sites they reach over TLS.
	for i, t := range targets {
		targets[i] = httpmsg.EnsureURLScheme(t, "https")
	}
	return shimTranslation{argv: emitTargets(out, targets), notes: s.notes}, nil
}

// --------------------------------------------------------------- arjun ----

type arjunState struct {
	target   string
	method   string
	wordlist string
	headers  []string
}

func arjunRules(st *arjunState) map[string]shimRule {
	r := map[string]shimRule{
		"u": {capture: &st.target, doc: "target URL (positional)"},
		"m": {capture: &st.method, doc: "GET → --fuzz new-param:query; POST → -X POST --fuzz new-param:body; JSON → -X POST + JSON Content-Type + --fuzz new-param:json; XML refused"},
		"w": {capture: &st.wordlist, doc: "-w <file> (default: the builtin params list)"},
		"t": {to: "-c"},
		"d": {to: "--delay", parse: secondsToMillis, doc: "--delay <ms> (seconds converted)"},
		"stable": {to: "--concurrency=1", bare: true,
			doc: "--concurrency=1 (one request at a time)"},
		"headers":    {appendTo: &st.headers, doc: "-H per header line"},
		"oJ":         {to: "-o", doc: "-o <file> (the per-payload JSONL stream)"},
		"rate-limit": {to: "--rate-limit"},
	}
	for alias, canon := range map[string]string{
		"url": "u", "method": "m", "wordlist": "w", "threads": "t", "delay": "d",
	} {
		r[alias] = r[canon]
	}
	return r
}

func translateArjun(args []string) (shimTranslation, error) {
	st := &arjunState{}
	s := newShimArgs("arjun", "fuzz", args)
	common, err := s.drive(nil, arjunRules(st), nil)
	if err != nil {
		return shimTranslation{}, err
	}
	if st.target == "" {
		return shimTranslation{}, usageErrorf("arjun: -u/--url is required")
	}
	// arjun's -m picks where candidate parameters go, not just the verb: the
	// location is what --fuzz new-param needs.
	out := []string{"fuzz"}
	switch strings.ToUpper(st.method) {
	case "", "GET":
		out = append(out, "--fuzz", "new-param:query")
	case "POST":
		out = append(out, "-X", "POST", "--fuzz", "new-param:body")
	case "JSON":
		out = append(out, "-X", "POST", "-H", "Content-Type: application/json", "--fuzz", "new-param:json")
	case "XML":
		return shimTranslation{}, usageErrorf("arjun: -m XML has no equivalent — fuzz adds query, form and JSON parameters only; mark the position in an XML body with FUZZ and use `vigolium fuzz -d '<xml>…FUZZ…</xml>'`")
	default:
		return shimTranslation{}, usageErrorf("arjun: -m %q: want GET, POST, JSON or XML", st.method)
	}
	wordlist := st.wordlist
	if wordlist == "" {
		wordlist = "params"
	}
	out = append(out, "-w", wordlist)
	for _, block := range st.headers {
		for _, h := range strings.Split(block, "\n") {
			if h = strings.TrimSpace(h); h != "" {
				out = append(out, "-H", h)
			}
		}
	}
	out = append(out, common...)
	// --anomaly, because parameter discovery is exactly the case where the
	// interesting response is not knowable in advance: the caller cannot write a
	// matcher for a parameter they have not found yet.
	out = append(out, "--anomaly", st.target)
	notes := append(s.notes,
		"one candidate parameter per request (arjun batches them), scored with --anomaly against the calibrated baseline",
		"for batched, budgeted mining use `vigolium kit param-mine -t <url>` (or --param-mining on a scan)")
	return shimTranslation{argv: out, notes: notes}, nil
}
