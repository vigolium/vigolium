package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium explain-argv -j -- <argv...>` answers, for one command line, what
// `schema commands` answers per command: the canonical command (a shim's
// translation, `run`'s canonical phase), the targets the line names, its
// reach, and the refusals VIGOLIUM_PINNED would apply. It parses the line
// against the command tree and runs nothing: it sends nothing, opens no store
// and loads no settings beyond what the pinned refusal check reads.

var explainArgvCmd = &cobra.Command{
	Use:   "explain-argv -- <argv...>",
	Short: "Resolve a vigolium command line without running it: command, targets, reach, pinned refusals",
	Long: "Parse a vigolium command line (everything after --, without the binary name) and report what it " +
		"would do without running it: the canonical command (a tool shim's translation, run's canonical phase), " +
		"whether it parses, the targets it names with their kind, its reach (none, line, store, unbounded) and the " +
		"flag that set it, and, under VIGOLIUM_PINNED=1, the refusals the pin applies with the corrected line. " +
		"Sends nothing and opens no store. `vigolium schema commands -j` publishes the same facts per command.",
	Example: "  vigolium explain-argv -j -- scan-url https://app.example.com/login --include-stored\n" +
		"  vigolium explain-argv -j -- r dast -t https://app.example.com",
	Args: cobra.ArbitraryArgs,
	RunE: runExplainArgv,
}

func init() {
	rootCmd.AddCommand(explainArgvCmd)
	registerCommandSchema(contract.Command{Name: "explain-argv", Item: explainArgvView{}, ItemsKind: contract.ItemsObject,
		Description: "One command line resolved without running it: command (canonical path), phase (run's canonical phase), translated_from (a shim), parses and error, sends_traffic, targets {value, kind, from}, reach and reach_by, pinned, refusals and hint."})
}

// explainArgvView is `explain-argv -j`'s object.
type explainArgvView struct {
	// Argv is the line explained; Resolved the line resolved against the tree
	// (a shim's translation, else Argv).
	Argv     []string `json:"argv"`
	Resolved []string `json:"resolved"`
	// TranslatedFrom is the tool shim (ffuf, nuclei, …) the line named.
	TranslatedFrom string `json:"translated_from,omitempty"`
	// Command is the canonical command path, "" when none resolved.
	Command string `json:"command"`
	// Phase is `run`'s canonical phase.
	Phase string `json:"phase,omitempty"`
	// Parses: the line parses (command, flags, positionals). A line that does
	// not exits 2 before anything is sent: reach none.
	Parses bool   `json:"parses"`
	Error  string `json:"error,omitempty"`
	// SendsTraffic is the command's trait (`schema commands`).
	SendsTraffic bool              `json:"sends_traffic"`
	Targets      []explainedTarget `json:"targets"`
	// Reach is none, line, store or unbounded; ReachBy the flag that set it,
	// "" when it is the command's default.
	Reach   string `json:"reach"`
	ReachBy string `json:"reach_by,omitempty"`
	// Pinned: VIGOLIUM_PINNED is on. Refusals are what it refuses on this
	// line (the line exits 2 refused_by_policy when any are listed); Hint is
	// the corrected line, or why there is none.
	Pinned   bool     `json:"pinned"`
	Refusals []string `json:"refusals"`
	Hint     string   `json:"hint,omitempty"`
}

// explainedTarget is one target the line names.
type explainedTarget struct {
	Value string `json:"value"`
	Kind  string `json:"kind"`
	// From is the flag (--target) or "positional".
	From string `json:"from"`
}

func runExplainArgv(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return usageErrorf("explain-argv needs a command line after --, e.g. vigolium explain-argv -j -- scan-url https://app.example.com")
	}
	v := explainArgv(rootCmd, args)
	if globalJSON {
		return emitObject(cmd, "", v)
	}
	fmt.Printf("%s %s\n", terminal.Cyan("command:"), v.Command)
	if !v.Parses {
		fmt.Printf("%s %s\n", terminal.Cyan("error:  "), v.Error)
	}
	fmt.Printf("%s %s %s\n", terminal.Cyan("reach:  "), v.Reach, v.ReachBy)
	for _, t := range v.Targets {
		fmt.Printf("%s %s (%s, %s)\n", terminal.Cyan("target: "), t.Value, t.Kind, t.From)
	}
	for _, r := range v.Refusals {
		fmt.Printf("%s %s\n", terminal.Cyan("refused:"), r)
	}
	if v.Hint != "" {
		fmt.Printf("%s %s\n", terminal.Cyan("hint:   "), v.Hint)
	}
	return nil
}

// explainArgv resolves argv against root's tree. It parses flags into the
// resolved command's flag set and restores every flag it touched before
// returning, so a caller in the same process sees the tree as it was.
func explainArgv(root *cobra.Command, argv []string) explainArgvView {
	v := explainArgvView{Argv: argv, Resolved: argv, Targets: []explainedTarget{}, Refusals: []string{}, Reach: reachNone, Pinned: pinnedEnv()}
	fail := func(err error) explainArgvView {
		v.Parses, v.Error, v.Reach, v.ReachBy = false, err.Error(), reachNone, ""
		return v
	}

	c, rest, err := root.Find(argv)
	if err != nil {
		return fail(err)
	}
	if spec, ok := shimSpecByName(commandPathWithoutRoot(c)); ok {
		v.TranslatedFrom = spec.name
		split, err := splitShimGlobals(spec, rest, root.PersistentFlags())
		if err != nil {
			return fail(err)
		}
		if split.dryRun {
			v.Command, v.Parses = spec.name, true
			v.ReachBy = "--dry-run"
			return v
		}
		tr, err := spec.translate(split.foreign)
		if err != nil {
			return fail(err)
		}
		v.Resolved = append(append([]string{}, split.globals...), tr.argv...)
		if c, rest, err = root.Find(v.Resolved); err != nil {
			return fail(err)
		}
	}
	if c == root {
		return fail(fmt.Errorf("no command in %q", strings.Join(argv, " ")))
	}
	v.Command = commandPathWithoutRoot(c)
	if t, ok := traitOf(c); ok {
		v.SendsTraffic = t.SendsTraffic
	}

	defer snapshotFlags(c)()
	if err := c.ParseFlags(rest); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			v.Parses, v.Reach, v.ReachBy = true, reachNone, "--help"
			return v
		}
		return fail(err)
	}
	positionals := c.Flags().Args()
	if c.Args != nil {
		if err := c.Args(c, positionals); err != nil {
			return fail(err)
		}
	}
	if v.Command == "run" && len(positionals) > 0 {
		if !runner.IsOnlyPhaseSpelling(positionals[0]) {
			return fail(fmt.Errorf("run: %q is not a phase `run` accepts", positionals[0]))
		}
		v.Phase = runner.NormalizeNativePhase(positionals[0])
	}
	v.Parses = true

	trait := commandReach[v.Command]
	v.Reach = trait.Reach
	if v.Reach == "" {
		v.Reach = reachNone
	}
	for _, s := range trait.Targets {
		switch {
		case s.Flag != "":
			for _, val := range flagValues(c.Flags(), s.Flag) {
				v.Targets = append(v.Targets, explainedTarget{Value: val, Kind: s.Kind, From: "--" + s.Flag})
			}
		case s.Positional == positionalFirst && len(positionals) > 0:
			v.Targets = append(v.Targets, explainedTarget{Value: positionals[0], Kind: s.Kind, From: "positional"})
		case s.Positional == positionalEach:
			for _, p := range positionals {
				v.Targets = append(v.Targets, explainedTarget{Value: p, Kind: s.Kind, From: "positional"})
			}
		}
	}
	for _, rf := range trait.ReachFlags {
		if flagSet(c.Flags(), rf.Flag) && (rf.With == "" || flagSet(c.Flags(), rf.With)) {
			v.Reach, v.ReachBy = rf.Reach, "--"+rf.Flag
		}
	}
	for _, rf := range globalReachFlags {
		if flagSet(c.Flags(), rf.Flag) {
			v.Reach, v.ReachBy = rf.Reach, "--"+rf.Flag
		}
	}

	if v.Pinned {
		if refused := pinnedRefusals(c); len(refused) > 0 {
			v.Refusals, v.Hint = pinnedRefusalReport(refused, v.Resolved)
		}
	}
	return v
}

// shimSpecByName is the tool shim registered as path, if it is one.
func shimSpecByName(path string) (shimSpec, bool) {
	for _, s := range shimSpecs {
		if s.name == path {
			return s, true
		}
	}
	return shimSpec{}, false
}

// flagValues are the values a set flag carries (every element of a
// repeatable one); nil when the flag is absent or not set.
func flagValues(fs *pflag.FlagSet, name string) []string {
	f := fs.Lookup(name)
	if f == nil || !f.Changed {
		return nil
	}
	if sv, ok := f.Value.(pflag.SliceValue); ok {
		return sv.GetSlice()
	}
	if s := f.Value.String(); s != "" {
		return []string{s}
	}
	return nil
}

// flagSet reports whether a flag is set on the line: a switch set true, any
// other flag given a non-empty value.
func flagSet(fs *pflag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil || !f.Changed {
		return false
	}
	if f.Value.Type() == "bool" {
		return f.Value.String() == "true"
	}
	return len(flagValues(fs, name)) > 0
}

// snapshotFlags records every flag of c (local, inherited and persistent:
// the inherited set is merged first) and returns the function that puts each
// one back as it was, undoing a ParseFlags of the explained line without
// disturbing what this invocation's own flags set (-j).
func snapshotFlags(c *cobra.Command) (restore func()) {
	_ = c.InheritedFlags()
	type state struct {
		changed bool
		value   string
		slice   []string
	}
	saved := map[*pflag.Flag]state{}
	c.Flags().VisitAll(func(f *pflag.Flag) {
		st := state{changed: f.Changed, value: f.Value.String()}
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			st.slice = append([]string(nil), sv.GetSlice()...)
		}
		saved[f] = st
	})
	return func() {
		for f, st := range saved {
			if f.Changed == st.changed && f.Value.String() == st.value {
				continue
			}
			if sv, ok := f.Value.(pflag.SliceValue); ok {
				_ = sv.Replace(st.slice)
			} else {
				_ = f.Value.Set(st.value)
			}
			f.Changed = st.changed
		}
	}
}
