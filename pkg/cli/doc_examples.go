package cli

import (
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/doclex"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
)

// The documentation sources: every `vigolium …` command an operator or an
// agent copies from — the skill bundle, every command's Example and Long and
// the --full-example tour — handed to internal/doclex, which extracts each one
// as an argv (doc_commands_test.go parses each one against the real tree;
// test/e2e runs the read-only ones against a seeded store, see DocExamples).

// cobraDocCommands extracts commands from every command's Example and Long.
// Example lines are shell lines in full (pipes and substitutions included);
// a Long is prose, so only its lines that start with a vigolium invocation
// count.
func cobraDocCommands(root *cobra.Command) []doclex.Command {
	var out []doclex.Command
	walkTree(root, func(c *cobra.Command) {
		if c.Example != "" {
			src := c.CommandPath() + " (Example)"
			lines := strings.Split(terminal.StripANSI(c.Example), "\n")
			out = append(out, doclex.FromLines(src, lines, 1, doclex.LinesShell, false)...)
		}
		if c.Long != "" {
			src := c.CommandPath() + " (Long)"
			lines := strings.Split(terminal.StripANSI(c.Long), "\n")
			out = append(out, doclex.FromLines(src, lines, 1, doclex.LinesProse, false)...)
		}
	})
	return out
}

// fullExampleDocCommands extracts the --full-example tour.
func fullExampleDocCommands() []doclex.Command {
	var out []doclex.Command
	for _, sec := range fullExampleSections() {
		src := "--full-example [" + sec.title + "]"
		out = append(out, doclex.FromLines(src, sec.examples, 1, doclex.LinesShell, false)...)
	}
	return out
}

// docSkillFile is one markdown file of the embedded skill bundle.
type docSkillFile struct {
	path string // path inside public.StaticFS
	body string
}

// skillBundleMarkdown reads the skill bundle from the embed FS, not the working
// tree, so what is checked is exactly what ships. flags.generated.md is a flag
// table generated from the tree itself and is left out.
func skillBundleMarkdown() ([]docSkillFile, error) {
	var out []docSkillFile
	err := fs.WalkDir(public.StaticFS, embedSkillsRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".md") || path.Base(p) == "flags.generated.md" {
			return nil
		}
		data, err := public.StaticFS.ReadFile(p)
		if err != nil {
			return err
		}
		out = append(out, docSkillFile{path: p, body: string(data)})
		return nil
	})
	return out, err
}

// DocExamples returns every documented invocation that lexes in the embedded
// skill bundle, every command's Example and Long, and the --full-example tour,
// for a test that runs the documentation (test/e2e).
func DocExamples() ([]doclex.Command, error) {
	prepareCommandTree(rootCmd)
	cmds := cobraDocCommands(rootCmd)
	cmds = append(cmds, fullExampleDocCommands()...)
	files, err := skillBundleMarkdown()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		cmds = append(cmds, doclex.Markdown(f.path, f.body)...)
	}
	return doclex.Lexed(cmds), nil
}

// docExampleUnsafeFlags turn an invocation of a read command into one that
// writes, sends, streams or waits: such an example is not run unattended.
var docExampleUnsafeFlags = append([]string{
	"replay", "push-to-burp", "to-repeater", "to-organizer", "send-to-burp", "save-to-burp",
	"watch", "follow", "tui", "interactive", "fix", "for", "stdin",
}, dbWriteFlags...)

// ReadOnlyDocExample resolves a documented argv (doclex.Command.Argv) to its
// command and reports whether it can be run against a seeded store with
// nothing on the wire: commandTraits declares the command a read that opens
// the store for reading and sends no traffic, and no flag in the invocation
// changes that. why says why not.
func ReadOnlyDocExample(argv []string) (path, why string) {
	prepareCommandTree(rootCmd)
	cmd, _, err := rootCmd.Find(argv)
	if err != nil || cmd == nil || cmd == rootCmd {
		return "", "names no command"
	}
	path = commandPathWithoutRoot(cmd)
	t, ok := commandTraits[path]
	switch {
	case !ok:
		return path, "not in commandTraits"
	case t.Kind != kindRead:
		return path, "kind " + string(t.Kind)
	case t.DB != dbRead:
		return path, "db intent " + t.DB.String()
	case t.SendsTraffic:
		return path, "sends traffic"
	}
	for _, a := range argv {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "--") && slices.Contains(docExampleUnsafeFlags, name) {
			return path, "--" + name + " writes, sends, streams or waits"
		}
	}
	return path, ""
}
