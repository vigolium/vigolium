package cli

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// Hooks that walk the finished command tree (prepareCommandTree). Each one
// enforces a rule every command must follow, so a command added later gets it
// without remembering to.

// treeHookAnnotation marks a command a hook already processed, so
// prepareCommandTree stays safe to call more than once.
const (
	groupHookAnnotation = "vigolium.group_enforced"
	argsHookAnnotation  = "vigolium.args_wrapped"
)

// enforceGroupSubcommands makes a command group answer an unknown subcommand
// with a usage error instead of its help text and exit 0.
//
// Cobra returns flag.ErrHelp for a command with no RunE before it looks at
// Args at all, and ExecuteC turns that into "print help, return nil". So
// `vigolium config get x -j` printed help text on stdout and exited 0. A group
// therefore gets both an Args validator (rejecting any word as an unknown
// command, with the nearest subcommand) and a RunE (help for a human, a usage
// error under -j, where help text is not a document).
//
// A group whose bare form is a real command (finding, traffic, module, scope,
// scan, …) keeps its positional: there the validator only rejects a word that
// is a near miss of one of its subcommands, then defers to the command's own
// Args.
func enforceGroupSubcommands(root *cobra.Command) {
	walkTree(root, func(c *cobra.Command) {
		if c == root || !c.HasSubCommands() || c.Annotations[groupHookAnnotation] != "" {
			return
		}
		setAnnotation(c, groupHookAnnotation, "1")
		switch {
		case c.RunE == nil && c.Run == nil:
			c.Args = rejectUnknownSubcommand
			c.RunE = groupHelpRunE
		case c.Args == nil:
			// Its own RunE but no positional of its own (agent): any word is a
			// subcommand that does not exist.
			c.Args = rejectUnknownSubcommand
		default:
			own := c.Args
			c.Args = func(cmd *cobra.Command, args []string) error {
				if len(args) > 0 {
					if err := rejectNearMissSubcommand(cmd, args[0]); err != nil {
						return err
					}
				}
				return own(cmd, args)
			}
		}
	})
}

// rejectUnknownSubcommand is the Args of a group with no positional.
func rejectUnknownSubcommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return unknownSubcommandError(cmd, args[0], nearestSubcommand(cmd, args[0], true))
}

// rejectNearMissSubcommand rejects a positional that reads as a mistyped
// subcommand of cmd. A word that cannot be one (a URL, a host, a number, a
// path) is left to the command.
func rejectNearMissSubcommand(cmd *cobra.Command, word string) error {
	if !wordCouldBeSubcommand(word) {
		return nil
	}
	best := nearestSubcommand(cmd, word, false)
	if best == "" {
		return nil
	}
	return unknownSubcommandError(cmd, word, best)
}

// wordCouldBeSubcommand reports whether word has the shape of a command name:
// letters, digits and dashes, starting with a letter.
func wordCouldBeSubcommand(word string) bool {
	if word == "" || !unicode.IsLetter(rune(word[0])) {
		return false
	}
	for _, r := range word {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
			return false
		}
	}
	return true
}

// nearestSubcommand is the visible subcommand of cmd closest to word: by
// cobra's own suggestion rules (edit distance or prefix) when generous, by the
// tighter flag-suggestion budget otherwise, which is what a group that also
// takes a free-form filter word needs.
func nearestSubcommand(cmd *cobra.Command, word string, generous bool) string {
	var names []string
	byName := map[string]string{}
	for _, sub := range cmd.Commands() {
		if !sub.IsAvailableCommand() {
			continue
		}
		for _, n := range append([]string{sub.Name()}, sub.Aliases...) {
			names = append(names, n)
			byName[n] = sub.Name()
		}
	}
	if generous {
		if s := cmd.SuggestionsFor(word); len(s) > 0 {
			return s[0]
		}
	}
	if best := textutil.Closest(word, names); best != "" {
		return byName[best]
	}
	return ""
}

// unknownSubcommandError is the usage error for an unknown subcommand word.
// The message keeps cobra's wording ("unknown command …"), which is what
// scripts and isFlagParseError already recognise.
func unknownSubcommandError(cmd *cobra.Command, word, best string) error {
	path := commandPathWithoutRoot(cmd)
	e := clicommon.CLIError{
		Err:       fmt.Errorf("unknown command %q for %q", word, cmd.CommandPath()),
		Hint:      fmt.Sprintf("Run '%s --help' for its subcommands: %s", cmd.CommandPath(), strings.Join(subcommandNames(cmd), ", ")),
		UsageArgv: clicommon.UsageArgvFor(path),
	}
	if best != "" {
		e.DidYouMean = strings.TrimSpace(path + " " + best)
	}
	return e
}

// subcommandNames lists cmd's visible subcommands.
func subcommandNames(cmd *cobra.Command) []string {
	var out []string
	for _, sub := range cmd.Commands() {
		if sub.IsAvailableCommand() {
			out = append(out, sub.Name())
		}
	}
	return out
}

// groupHelpRunE is the RunE of a pure group: help for a human, and under -j
// (where help text is not a document) a usage error naming the subcommands.
func groupHelpRunE(cmd *cobra.Command, _ []string) error {
	if globalJSON {
		return clicommon.CLIError{
			Err:       fmt.Errorf("%s needs a subcommand", cmd.CommandPath()),
			Hint:      "Subcommands: " + strings.Join(subcommandNames(cmd), ", "),
			UsageArgv: clicommon.UsageArgvFor(commandPathWithoutRoot(cmd)),
		}
	}
	return cmd.Help()
}

// wrapArgsValidators makes every positional-argument error a usage error
// (exit 2). Cobra's validators (MinimumNArgs, ExactArgs, …) return plain
// errors that otherwise classify as a generic failure, exit 1.
func wrapArgsValidators(root *cobra.Command) {
	walkTree(root, func(c *cobra.Command) {
		if c.Args == nil || c.Annotations[argsHookAnnotation] != "" {
			return
		}
		setAnnotation(c, argsHookAnnotation, "1")
		own := c.Args
		c.Args = func(cmd *cobra.Command, args []string) error {
			err := own(cmd, args)
			if err == nil || classifyExitCode(err) != ExitError {
				return err
			}
			// A validator that coded its own condition keeps it.
			var coded codedError
			if errors.As(err, &coded) {
				return err
			}
			return clicommon.CLIError{
				Err:       err,
				Hint:      fmt.Sprintf("Run '%s --help' for its arguments", cmd.CommandPath()),
				UsageArgv: clicommon.UsageArgvFor(commandPathWithoutRoot(cmd)),
			}
		}
	})
}

// walkTree visits c and every descendant.
func walkTree(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, sub := range c.Commands() {
		walkTree(sub, fn)
	}
}

func setAnnotation(c *cobra.Command, key, value string) {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[key] = value
}

// enumAnnotation lists a closed flag's allowed values on the pflag.Flag, so
// `schema flags` (and the guardrail test) can read the set.
const enumAnnotation = "vigolium_enum"

// enumValue validates a flag's value against a closed set while flags are
// parsed, so a typo exits 2 naming the valid values before anything runs. It
// wraps the flag's own Value: the variable, the default, and Type() are
// unchanged. A slice flag is checked element by element.
type enumValue struct {
	inner   pflag.Value
	allowed []string
	// fold matches case-insensitively.
	fold bool
	// allowEmpty accepts "" (a flag whose empty value means "no filter").
	allowEmpty bool
	// commaList checks a plain string flag's comma-separated items one by one.
	commaList bool
	// accept, when set, decides membership instead of an exact match against
	// allowed (aliases, shorthands, prefixes); allowed is still what the error
	// and the schema list.
	accept func(string) bool
}

func (e *enumValue) String() string { return e.inner.String() }
func (e *enumValue) Type() string   { return e.inner.Type() }

func (e *enumValue) Set(s string) error {
	values := []string{s}
	if e.commaList || strings.HasSuffix(e.inner.Type(), "Slice") || strings.HasSuffix(e.inner.Type(), "Array") {
		values = strings.Split(s, ",")
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" && (e.allowEmpty || len(values) > 1) {
			continue
		}
		if !e.accepts(v) {
			return &enumError{value: v, allowed: e.allowed}
		}
	}
	return e.inner.Set(s)
}

func (e *enumValue) accepts(v string) bool {
	if e.accept != nil {
		return e.accept(v)
	}
	for _, a := range e.allowed {
		if a == v || (e.fold && strings.EqualFold(a, v)) {
			return true
		}
	}
	return false
}

// Replace and Append keep slice flags' SliceValue behaviour when the inner
// value has it.
func (e *enumValue) Replace(vals []string) error {
	for _, v := range vals {
		if err := e.Set(v); err != nil {
			return err
		}
	}
	if sv, ok := e.inner.(pflag.SliceValue); ok {
		return sv.Replace(vals)
	}
	return nil
}

// enumError is the cause pflag wraps in its InvalidValueError.
type enumError struct {
	value   string
	allowed []string
}

func (e *enumError) Error() string {
	return "must be one of: " + strings.Join(e.allowed, ", ")
}

// suggestion is the allowed value nearest the typed one, "" when none is close.
func (e *enumError) suggestion() string {
	lower := strings.ToLower(e.value)
	for _, a := range e.allowed {
		if strings.EqualFold(a, e.value) || strings.HasPrefix(strings.ToLower(a), lower) && len(lower) >= 2 {
			return a
		}
	}
	return textutil.Closest(lower, e.allowed)
}

// enumFlag converts an already-registered flag into a closed-set flag. It
// panics on an unknown name: that is a programming error caught by any test
// that builds the tree.
func enumFlag(fs *pflag.FlagSet, name string, allowed []string, opts ...enumOpt) {
	f := fs.Lookup(name)
	if f == nil {
		panic("enumFlag: no flag --" + name)
	}
	if _, done := f.Value.(*enumValue); done {
		return
	}
	ev := &enumValue{inner: f.Value, allowed: slices.Clone(allowed), fold: true}
	for _, o := range opts {
		o(ev)
	}
	f.Value = ev
	if f.Annotations == nil {
		f.Annotations = map[string][]string{}
	}
	f.Annotations[enumAnnotation] = slices.Clone(allowed)
}

type enumOpt func(*enumValue)

// enumAllowEmpty accepts "" as "no filter".
func enumAllowEmpty() enumOpt { return func(e *enumValue) { e.allowEmpty = true } }

// enumCommaList validates each comma-separated item of a plain string flag.
func enumCommaList() enumOpt { return func(e *enumValue) { e.commaList = true } }

// enumAccept decides membership with fn (aliases, shorthands).
func enumAccept(fn func(string) bool) enumOpt { return func(e *enumValue) { e.accept = fn } }

// enumCaseSensitive matches values exactly.
func enumCaseSensitive() enumOpt { return func(e *enumValue) { e.fold = false } }

// flagEnumValues is the allowed set of a closed flag, nil for an open one.
func flagEnumValues(f *pflag.Flag) []string {
	if f == nil || f.Annotations == nil {
		return nil
	}
	return f.Annotations[enumAnnotation]
}

// cobraUnknownCommand matches cobra's own unknown-command error, raised for the
// root before any hook can run.
var cobraUnknownCommand = regexp.MustCompile(`^unknown command "([^"]*)" for "`)

// structureUnknownCommand turns cobra's unknown-command error (whose message
// carries its "Did you mean this?" block as text) into the structured CLIError,
// so the -j envelope's message is the fact and the suggestion is a field.
func structureUnknownCommand(cmd *cobra.Command, err error) error {
	var cli clicommon.CLIError
	if err == nil || cmd == nil || errors.As(err, &cli) {
		return err
	}
	m := cobraUnknownCommand.FindStringSubmatch(err.Error())
	if m == nil {
		return err
	}
	return unknownSubcommandError(cmd, m[1], nearestSubcommand(cmd, m[1], true))
}
