package cli

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The embedded skill teaches commands in fenced blocks, and every re-sync of
// a downstream driver has found some of them wrong: a flag that was renamed,
// a subcommand that moved. This doctest reads every `vigolium …` line inside a
// fenced shell block of the skill bundle and checks it against the live command
// tree - the subcommand path resolves and every `--flag` it names exists on
// that command (local or inherited). It runs nothing and sends nothing.
//
// Placeholders (`<url>`, `$VAR`, `…`) are values, never flags, so they are
// skipped; a line continued with `\` is joined first.
func TestSkillFencedCommandsParse(t *testing.T) {
	root := rootCmd
	dir := filepath.Join("..", "..", "public", "skills")
	var checked int
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		for _, c := range fencedVigoliumLines(t, path) {
			checked++
			if msg := skillLineProblem(root, c.line); msg != "" {
				t.Errorf("%s:%d: %s\n    %s", path, c.at, msg, c.line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no fenced vigolium command found - the walk read nothing")
	}
}

// The embedded profile is generated, not a file in the bundle, so its fenced
// commands are checked the same way from its rendered text, plain and under
// the pin (where a hidden flag would be a lesson the session cannot use).
func TestEmbeddedProfileFencedCommandsParse(t *testing.T) {
	check := func(t *testing.T, text string) {
		t.Helper()
		lines := fencedVigoliumLinesFrom(t, strings.NewReader(text))
		if len(lines) < len(embeddedProfileVerbs) {
			t.Fatalf("only %d fenced commands in the embedded profile", len(lines))
		}
		for _, c := range lines {
			if msg := skillLineProblem(rootCmd, c.line); msg != "" {
				t.Errorf("embedded profile:%d: %s\n    %s", c.at, msg, c.line)
			}
		}
	}
	check(t, embeddedSkillProfile(rootCmd))
	t.Run("pinned", func(t *testing.T) {
		t.Setenv(pinnedEnvVar, "1")
		restore := applyPinnedHelpView(rootCmd)
		defer restore()
		text := embeddedSkillProfile(rootCmd)
		check(t, text)
		for _, c := range fencedVigoliumLinesFrom(t, strings.NewReader(text)) {
			cmd, _, err := rootCmd.Find(shellWords(strings.TrimPrefix(c.line, "vigolium ")))
			if err == nil && cmd.Hidden {
				t.Errorf("pinned profile teaches hidden command %q", c.line)
			}
		}
	})
}

type skillLine struct {
	at   int
	line string
}

// fencedVigoliumLines returns the `vigolium …` commands inside ```bash/```sh
// (or unlabelled) fences, continuation lines joined, with their line numbers.
func fencedVigoliumLines(t *testing.T, path string) []skillLine {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	return fencedVigoliumLinesFrom(t, f)
}

// fencedVigoliumLinesFrom is fencedVigoliumLines over any markdown text.
func fencedVigoliumLinesFrom(t *testing.T, r io.Reader) []skillLine {
	t.Helper()
	var out []skillLine
	in := false
	shell := false
	pending := ""
	pendingAt := 0
	n := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		n++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "```") {
			if in {
				in, shell, pending = false, false, ""
				continue
			}
			lang := strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			in = true
			shell = lang == "" || lang == "bash" || lang == "sh" || lang == "shell" || lang == "console"
			continue
		}
		if !in || !shell {
			continue
		}
		if pending != "" {
			pending += " " + strings.TrimSuffix(trimmed, "\\")
			if !strings.HasSuffix(trimmed, "\\") {
				out = append(out, skillLine{pendingAt, pending})
				pending = ""
			}
			continue
		}
		line := strings.TrimPrefix(trimmed, "$ ")
		if !strings.HasPrefix(line, "vigolium ") {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			pending, pendingAt = strings.TrimSuffix(line, "\\"), n
			continue
		}
		out = append(out, skillLine{n, line})
	}
	return out
}

// skillLineProblem is why one taught line does not parse against the tree, or "".
func skillLineProblem(root *cobra.Command, line string) string {
	// One command: stop at the first shell operator.
	for _, op := range []string{" | ", " && ", " || ", " ; ", " > ", " 2>", " < ", "#"} {
		if i := strings.Index(line, op); i >= 0 {
			line = line[:i]
		}
	}
	words := shellWords(strings.TrimPrefix(line, "vigolium "))
	// A placeholder for the command itself (`vigolium <command> -h`) names no path to check.
	for _, w := range words {
		if !strings.HasPrefix(w, "-") {
			if strings.ContainsAny(w, "<>") {
				return ""
			}
			break
		}
	}
	cmd, _, err := root.Find(words)
	if err != nil || cmd == nil {
		return "the command path does not resolve"
	}
	// An argv shim (`ffuf`, `arjun`, …) parses its own tool's flags, not cobra's.
	if cmd.DisableFlagParsing {
		return ""
	}
	for _, w := range words {
		if !strings.HasPrefix(w, "--") || w == "--" {
			continue
		}
		name := strings.TrimPrefix(w, "--")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name == "" || strings.ContainsAny(name, "<>$…[]{}") {
			continue
		}
		if cmd.Flags().Lookup(name) == nil && cmd.InheritedFlags().Lookup(name) == nil &&
			root.PersistentFlags().Lookup(name) == nil {
			return "--" + name + " is not a flag of `" + cmd.CommandPath() + "`"
		}
	}
	return ""
}

// shellWords splits on spaces outside single or double quotes.
func shellWords(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
