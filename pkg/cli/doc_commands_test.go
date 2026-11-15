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
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
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
// through the extension linter.
//
// Opt-outs, for synopsis lines and commands that deliberately show a mistake:
//
//	```bash doccheck=skip          the whole fence
//	<!-- doccheck: skip -->        on the line before a fence (or an inline span)
//	vigolium … # doccheck: skip    one line
//	# doccheck: deprecated-ok      a line (or <!-- --> before a fence) that
//	                               documents a deprecated flag on purpose

// docPlaceholder replaces every value the shell would expand or a reader would
// fill in: $VAR, $(…), `…`, <uuid>.
const docPlaceholder = "PLACEHOLDER"

// docEllipsis replaces a bare unquoted "…"/"...": "more of the same". It can
// stand in for a flag's value (`-B …`) and is dropped from positionals.
const docEllipsis = docPlaceholder + "_ELLIPSIS"

// docCommand is one vigolium invocation found in a documentation source.
type docCommand struct {
	source       string
	line         int
	text         string
	argv         []string // without the leading "vigolium"
	deprecatedOK bool
}

func (c docCommand) where() string { return fmt.Sprintf("%s:%d", c.source, c.line) }

// docLine is one logical shell line: continuations joined, prompt stripped.
type docLine struct {
	line         int
	text         string
	deprecatedOK bool
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// docSkillFile is one markdown file of the embedded skill bundle.
type docSkillFile struct {
	path string // path inside public.StaticFS
	body string
}

// embeddedSkillDocs reads the skill bundle from the embed FS, not the working
// tree, so the test checks exactly what ships. flags.generated.md is a flag
// table generated from the tree itself (TestFlagsGeneratedIsCurrent).
func embeddedSkillDocs(t *testing.T) []docSkillFile {
	t.Helper()
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

// cobraDocCommands extracts commands from every command's Example and Long.
// Example lines are shell lines in full (pipes and substitutions included);
// a Long is prose, so only its lines that start with a vigolium invocation
// count.
func cobraDocCommands(root *cobra.Command) []docCommand {
	var out []docCommand
	walkCommandTree(root, func(c *cobra.Command) {
		if c.Example != "" {
			src := c.CommandPath() + " (Example)"
			lines := strings.Split(terminal.StripANSI(c.Example), "\n")
			out = append(out, commandsFromLines(src, lines, 1, docLinesShell, false)...)
		}
		if c.Long != "" {
			src := c.CommandPath() + " (Long)"
			lines := strings.Split(terminal.StripANSI(c.Long), "\n")
			out = append(out, commandsFromLines(src, lines, 1, docLinesProse, false)...)
		}
	})
	return out
}

// fullExampleDocCommands extracts the --full-example tour.
func fullExampleDocCommands() []docCommand {
	var out []docCommand
	for _, sec := range fullExampleSections() {
		src := "--full-example [" + sec.title + "]"
		out = append(out, commandsFromLines(src, sec.examples, 1, docLinesShell, false)...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Markdown extraction
// ---------------------------------------------------------------------------

// docRunnableFences are the info strings whose fences hold commands. Untagged
// and `text` fences are output or synopsis, never runnable.
var docRunnableFences = map[string]bool{"bash": true, "sh": true, "shell": true, "zsh": true, "console": true}

type docFence struct {
	line         int // 1-based line of the first body line
	info         string
	body         []string
	skip         bool
	deprecatedOK bool
}

var docFenceOpen = regexp.MustCompile("^(\\s*)(`{3,}|~{3,})\\s*(.*)$")

// markdownFences splits a markdown document into fenced blocks, following the
// CommonMark closing rule (same character, at least as long, no info string).
// It also returns, for inline-span scanning, every line outside a fence.
func markdownFences(body string) (fences []docFence, prose map[int]string) {
	lines := strings.Split(body, "\n")
	prose = map[int]string{}
	prevNonBlank := ""
	for i := 0; i < len(lines); i++ {
		m := docFenceOpen.FindStringSubmatch(lines[i])
		if m == nil {
			prose[i+1] = lines[i]
			if strings.TrimSpace(lines[i]) != "" {
				prevNonBlank = strings.TrimSpace(lines[i])
			}
			continue
		}
		indent, marker, info := m[1], m[2], strings.TrimSpace(m[3])
		f := docFence{line: i + 2, info: info}
		f.skip = strings.Contains(info, "doccheck=skip") || strings.Contains(prevNonBlank, "doccheck: skip")
		f.deprecatedOK = strings.Contains(info, "doccheck=deprecated-ok") || strings.Contains(prevNonBlank, "doccheck: deprecated-ok")
		j := i + 1
		for ; j < len(lines); j++ {
			t := strings.TrimSpace(lines[j])
			if strings.HasPrefix(t, marker[:3]) && strings.Trim(t, marker[:1]) == "" && len(t) >= len(marker) {
				break
			}
			f.body = append(f.body, strings.TrimPrefix(lines[j], indent))
		}
		fences = append(fences, f)
		i = j
		prevNonBlank = ""
	}
	return fences, prose
}

// markdownDocCommands extracts the commands in a markdown document's runnable
// fences.
func markdownDocCommands(src, body string) []docCommand {
	fences, _ := markdownFences(body)
	var out []docCommand
	for _, f := range fences {
		lang := strings.ToLower(strings.Fields(f.info + " x")[0])
		if f.skip || !docRunnableFences[lang] {
			continue
		}
		mode := docLinesShell
		if lang == "console" {
			mode = docLinesConsole
		}
		out = append(out, commandsFromLines(src, f.body, f.line, mode, f.deprecatedOK)...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Logical lines
// ---------------------------------------------------------------------------

type docLineMode int

const (
	// docLinesShell: every line is shell (a `$ ` prompt is stripped).
	docLinesShell docLineMode = iota
	// docLinesConsole: only `$ `-prompted lines are commands; the rest is output.
	docLinesConsole
	// docLinesProse: only lines that start with a vigolium invocation count.
	docLinesProse
)

var docHeredoc = regexp.MustCompile(`<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// logicalDocLines joins continuations, strips prompts, and drops comments,
// output lines and heredoc bodies.
func logicalDocLines(lines []string, first int, mode docLineMode, deprecatedOK bool) []docLine {
	var out []docLine
	for i := 0; i < len(lines); i++ {
		raw := strings.TrimSpace(lines[i])
		start := i
		switch {
		case strings.HasPrefix(raw, "$ "):
			raw = strings.TrimSpace(raw[2:])
		case raw == "$":
			continue
		case mode == docLinesConsole:
			continue
		}
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "→") {
			continue
		}
		if mode == docLinesProse {
			if !docStartsWithVigolium(raw) {
				continue
			}
			// "vigolium kit wordlist [name]     list the built-in wordlists":
			// a command column followed by a description column.
			if k := strings.Index(raw, "   "); k > 0 {
				raw = raw[:k]
			}
		}
		text := raw
		// Backslash continuation, then a quote left open across lines (an
		// inline JS snippet, a multi-line --prompt).
		for {
			if strings.HasSuffix(text, "\\") && !strings.HasSuffix(text, "\\\\") && i+1 < len(lines) {
				i++
				text = strings.TrimSuffix(text, "\\") + " " + strings.TrimSpace(lines[i])
				continue
			}
			if mode != docLinesProse && docOpenQuote(text) && i+1 < len(lines) && i-start < 60 {
				i++
				text += "\n" + lines[i]
				continue
			}
			break
		}
		// A quote that never closes is a typo on this line, not a multi-line
		// argument: report this line alone rather than swallow the block.
		if strings.Contains(text, "\n") && docOpenQuote(text) {
			i = start
			text = raw
		}
		// Heredoc: the body is data for the command, not commands.
		if m := docHeredoc.FindStringSubmatch(text); m != nil && !strings.Contains(text, "<<<") {
			for i+1 < len(lines) {
				i++
				if strings.TrimSpace(lines[i]) == m[2] {
					break
				}
			}
		}
		lineOK := deprecatedOK || strings.Contains(text, "doccheck: deprecated-ok")
		if strings.Contains(text, "doccheck: skip") {
			continue
		}
		out = append(out, docLine{line: first + start, text: text, deprecatedOK: lineOK})
	}
	return out
}

// docOpenQuote reports whether text ends inside a quote.
func docOpenQuote(text string) bool {
	_, _, err := lexShell(text)
	return errors.Is(err, errDocUnterminated)
}

var docVigoliumWord = regexp.MustCompile(`^(\$\s+)?(\./)?(bin/)?vigolium(\s|$)`)

func docStartsWithVigolium(s string) bool { return docVigoliumWord.MatchString(s) }

// commandsFromLines lexes logical lines and keeps the vigolium invocations.
func commandsFromLines(src string, lines []string, first int, mode docLineMode, deprecatedOK bool) []docCommand {
	var out []docCommand
	for _, l := range logicalDocLines(lines, first, mode, deprecatedOK) {
		for _, argv := range docShellCommands(l.text, 0) {
			out = append(out, docCommand{source: src, line: l.line, text: l.text, argv: argv, deprecatedOK: l.deprecatedOK})
		}
	}
	return out
}

// docShellCommands returns the vigolium argvs (without "vigolium") in one shell
// line, recursing into $(…), backticks and `sh -c`/`watch` command strings.
// A line that does not lex returns a single nil-argv sentinel only when it
// starts with vigolium, so the caller reports it rather than skipping it.
func docShellCommands(text string, depth int) [][]string {
	if depth > 4 {
		return nil
	}
	segs, subs, err := lexShell(text)
	if err != nil {
		if docStartsWithVigolium(strings.TrimSpace(text)) {
			return [][]string{{"\x00lex", err.Error()}}
		}
		return nil
	}
	var out [][]string
	for _, seg := range segs {
		argv, nested := normalizeDocSegment(seg)
		if nested != "" {
			out = append(out, docShellCommands(nested, depth+1)...)
			continue
		}
		if argv != nil {
			out = append(out, argv)
		}
	}
	for _, sub := range subs {
		out = append(out, docShellCommands(sub, depth+1)...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Shell-subset lexer
// ---------------------------------------------------------------------------

var errDocUnterminated = errors.New("unterminated quote or substitution")

// lexShell splits one shell line into command segments (split on |, ||, &&,
// ;, &) of words. Quotes and escapes are honoured; $VAR, ${…}, $(…), backticks
// and <placeholder> become PLACEHOLDER (substitution bodies are returned for
// recursion); redirections are dropped together with their targets; an
// unquoted # starts a comment.
func lexShell(src string) (segs [][]string, subs []string, err error) {
	r := []rune(src)
	var cur []string
	var word strings.Builder
	inWord, dropNext, quoted := false, false, false

	flush := func() {
		if !inWord {
			return
		}
		w := word.String()
		word.Reset()
		inWord = false
		wasQuoted := quoted
		quoted = false
		if dropNext {
			dropNext = false
			return
		}
		switch {
		case (w == "..." || w == "…") && !wasQuoted:
			w = docEllipsis
		case docWholePlaceholder.MatchString(w) || strings.Contains(w, "...") || strings.Contains(w, "…"):
			// A quoted <placeholder>, or an elided value ("9b2f-…", "...").
			w = docPlaceholder
		}
		cur = append(cur, w)
	}
	endSeg := func() {
		flush()
		if len(cur) > 0 {
			segs = append(segs, cur)
		}
		cur = nil
		dropNext = false
	}
	peek := func(i int) rune {
		if i < len(r) {
			return r[i]
		}
		return 0
	}

	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		case c == '#' && !inWord:
			i = len(r)
		case c == '\\':
			if i+1 < len(r) {
				if r[i+1] != '\n' {
					word.WriteRune(r[i+1])
					inWord = true
				}
				i++
			}
		case c == '\'':
			j := slices.Index(r[i+1:], '\'')
			if j < 0 {
				return nil, nil, errDocUnterminated
			}
			word.WriteString(string(r[i+1 : i+1+j]))
			inWord, quoted = true, true
			i += j + 1
		case c == '"':
			j, err := lexDoubleQuoted(r, i+1, &word, &subs)
			if err != nil {
				return nil, nil, err
			}
			inWord, quoted = true, true
			i = j
		case c == '$':
			j, err := lexDollar(r, i, &word, &subs)
			if err != nil {
				return nil, nil, err
			}
			inWord = true
			i = j
		case c == '`':
			j := slices.Index(r[i+1:], '`')
			if j < 0 {
				return nil, nil, errDocUnterminated
			}
			subs = append(subs, string(r[i+1:i+1+j]))
			word.WriteString(docPlaceholder)
			inWord = true
			i += j + 1
		case c == '<':
			// <placeholder> before redirection: `<uuid>` is a value, not two
			// redirections.
			if n := docPlaceholderLen(r, i); n > 0 {
				word.WriteString(docPlaceholder)
				inWord = true
				i += n - 1
				continue
			}
			if peek(i+1) == '(' { // process substitution
				end, err := docMatchParen(r, i+1)
				if err != nil {
					return nil, nil, err
				}
				subs = append(subs, string(r[i+2:end]))
				word.WriteString(docPlaceholder)
				inWord = true
				i = end
				continue
			}
			if inWord && docAllDigits(word.String()) {
				word.Reset()
				inWord = false
			}
			flush()
			for peek(i+1) == '<' || peek(i+1) == '-' || peek(i+1) == '&' || peek(i+1) == '>' {
				i++
			}
			dropNext = true
		case c == '>':
			if inWord && docAllDigits(word.String()) {
				word.Reset()
				inWord = false
			}
			flush()
			if peek(i+1) == '>' || peek(i+1) == '|' {
				i++
			}
			if peek(i+1) == '&' {
				i++
				if peek(i+1) == '-' || (peek(i+1) >= '0' && peek(i+1) <= '9') {
					i++
					continue
				}
			}
			dropNext = true
		case c == '&':
			switch peek(i + 1) {
			case '&':
				endSeg()
				i++
			case '>':
				flush()
				i++
				if peek(i+1) == '>' {
					i++
				}
				dropNext = true
			default:
				endSeg()
			}
		case c == '|':
			endSeg()
			if peek(i+1) == '|' || peek(i+1) == '&' {
				i++
			}
		case c == ';':
			endSeg()
		case (c == '(' || c == ')') && !inWord:
			endSeg()
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	endSeg()
	return segs, subs, nil
}

// docWholePlaceholder is a quoted word that is entirely a <placeholder>.
var docWholePlaceholder = regexp.MustCompile(`^<[A-Za-z_][^<>]*>$`)

// docPlaceholderLen returns the rune length of a <placeholder> at r[i], or 0.
// A placeholder starts with a letter, so `< file` and `<<EOF` stay
// redirections. It may hold spaces only when it is plain words (`<ffuf
// flags>`) closed before the next word, so `<in.txt >out.txt` is still two
// redirections.
func docPlaceholderLen(r []rune, i int) int {
	if i+1 >= len(r) {
		return 0
	}
	if !docIsLetter(r[i+1]) {
		return 0
	}
	spaced := false
	for j := i + 1; j < len(r) && j-i < 80; j++ {
		switch r[j] {
		case '>':
			if spaced && (strings.ContainsRune(string(r[i+1:j]), '.') || r[j-1] == ' ') {
				return 0
			}
			return j - i + 1
		case ' ':
			spaced = true
		case '\t', '\n', '<', '"', '\'', '`', '$', ';', '&', '(', ')':
			return 0
		}
	}
	return 0
}

func lexDoubleQuoted(r []rune, i int, word *strings.Builder, subs *[]string) (int, error) {
	for ; i < len(r); i++ {
		switch r[i] {
		case '"':
			return i, nil
		case '\\':
			if i+1 < len(r) && strings.ContainsRune("$`\"\\\n", r[i+1]) {
				if r[i+1] != '\n' {
					word.WriteRune(r[i+1])
				}
				i++
				continue
			}
			word.WriteRune('\\')
		case '$':
			j, err := lexDollar(r, i, word, subs)
			if err != nil {
				return 0, err
			}
			i = j
		case '`':
			j := slices.Index(r[i+1:], '`')
			if j < 0 {
				return 0, errDocUnterminated
			}
			*subs = append(*subs, string(r[i+1:i+1+j]))
			word.WriteString(docPlaceholder)
			i += j + 1
		default:
			word.WriteRune(r[i])
		}
	}
	return 0, errDocUnterminated
}

// lexDollar handles an expansion starting at r[i] == '$' and returns the index
// of its last rune.
func lexDollar(r []rune, i int, word *strings.Builder, subs *[]string) (int, error) {
	if i+1 >= len(r) {
		word.WriteRune('$')
		return i, nil
	}
	switch n := r[i+1]; {
	case n == '(':
		end, err := docMatchParen(r, i+1)
		if err != nil {
			return 0, err
		}
		inner := string(r[i+2 : end])
		if !strings.HasPrefix(inner, "(") { // $(( … )) is arithmetic
			*subs = append(*subs, inner)
		}
		word.WriteString(docPlaceholder)
		return end, nil
	case n == '{':
		j := slices.Index(r[i+2:], '}')
		if j < 0 {
			return 0, errDocUnterminated
		}
		word.WriteString(docPlaceholder)
		return i + 2 + j, nil
	case n == '\'':
		j := i + 2
		for ; j < len(r) && r[j] != '\''; j++ {
			if r[j] == '\\' {
				j++
			}
		}
		if j >= len(r) {
			return 0, errDocUnterminated
		}
		word.WriteString(docPlaceholder)
		return j, nil
	case n == '_' || n >= 'a' && n <= 'z' || n >= 'A' && n <= 'Z':
		j := i + 1
		for j+1 < len(r) && (r[j+1] == '_' || r[j+1] >= 'a' && r[j+1] <= 'z' || r[j+1] >= 'A' && r[j+1] <= 'Z' || r[j+1] >= '0' && r[j+1] <= '9') {
			j++
		}
		word.WriteString(docPlaceholder)
		return j, nil
	case strings.ContainsRune("0123456789?#@*!$-", n):
		word.WriteString(docPlaceholder)
		return i + 1, nil
	}
	word.WriteRune('$')
	return i, nil
}

// docMatchParen returns the index of the ')' matching the '(' at r[open],
// skipping quoted text.
func docMatchParen(r []rune, open int) (int, error) {
	depth := 0
	for i := open; i < len(r); i++ {
		switch r[i] {
		case '\\':
			i++
		case '\'':
			j := slices.Index(r[i+1:], '\'')
			if j < 0 {
				return 0, errDocUnterminated
			}
			i += j + 1
		case '"':
			for i++; i < len(r) && r[i] != '"'; i++ {
				if r[i] == '\\' {
					i++
				}
			}
			if i >= len(r) {
				return 0, errDocUnterminated
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, errDocUnterminated
}

func docIsLetter(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func docAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Segment normalisation
// ---------------------------------------------------------------------------

var docAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// docPrefixWords are dropped from the front of a segment: shell keywords and
// wrappers that run the rest of the segment as a command.
var docPrefixWords = map[string]bool{
	"eval": true, "time": true, "exec": true, "!": true, "nohup": true, "command": true,
	"builtin": true, "if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "{": true, "}": true, "env": true, "sudo": true,
}

// docWrapperValueOpts are the value-taking options of the wrappers whose tail
// is a command (timeout, watch, xargs).
var docWrapperValueOpts = map[string]map[string]bool{
	"timeout": {"-s": true, "-k": true, "--signal": true, "--kill-after": true},
	"watch":   {"-n": true, "--interval": true, "-q": true, "--equexit": true},
	"xargs":   {"-I": true, "-n": true, "-P": true, "-L": true, "-d": true, "-s": true, "-E": true, "-a": true, "--max-args": true, "--max-procs": true},
}

// normalizeDocSegment strips env prefixes and wrappers and returns the argv
// after "vigolium" (nil when the segment is not a vigolium invocation), or a
// nested command string to lex again (`sh -c '…'`, `watch '…'`).
func normalizeDocSegment(words []string) (argv []string, nested string) {
	for len(words) > 0 {
		w := words[0]
		switch {
		case docAssignment.MatchString(w) || docPrefixWords[w]:
			words = words[1:]
			continue
		case w == "timeout" || w == "watch" || w == "xargs":
			opts := docWrapperValueOpts[w]
			rest := words[1:]
			for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
				if opts[rest[0]] && len(rest) > 1 {
					rest = rest[1:]
				}
				rest = rest[1:]
			}
			if w == "timeout" && len(rest) > 0 {
				rest = rest[1:] // the duration
			}
			if w == "watch" && len(rest) == 1 && strings.ContainsAny(rest[0], " \t") {
				return nil, rest[0]
			}
			words = rest
			continue
		case (w == "sh" || w == "bash" || w == "zsh") && len(words) >= 3 && words[1] == "-c":
			return nil, words[2]
		case w == "go" && len(words) >= 3 && words[1] == "run" && strings.HasSuffix(words[2], "cmd/vigolium"):
			return words[3:], ""
		}
		break
	}
	if len(words) == 0 || !docIsVigoliumBinary(words[0]) {
		return nil, ""
	}
	return words[1:], ""
}

// docIsVigoliumBinary accepts vigolium, ./vigolium, ./bin/vigolium and any
// path ending in /bin/vigolium ($(go env GOPATH)/bin/vigolium).
func docIsVigoliumBinary(w string) bool {
	switch w {
	case "vigolium", "./vigolium", "bin/vigolium", "./bin/vigolium":
		return true
	}
	return strings.HasSuffix(w, "/bin/vigolium")
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
		if item == "" || strings.Contains(item, docPlaceholder) {
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
	case docPlaceholder:
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
		if a != docEllipsis {
			positionals = append(positionals, a)
		}
	}
	if len(positionals) > 0 && !strings.Contains(positionals[0], docPlaceholder) {
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
	elided := slices.Contains(fset.Args(), docEllipsis)
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
	if cmdPath == "vigolium run" && len(positionals) == 1 && !strings.Contains(positionals[0], docPlaceholder) &&
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
	if snippet != "" && !strings.Contains(snippet, docPlaceholder) {
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
		if slices.Contains(split.foreign, docPlaceholder) || slices.Contains(split.foreign, docEllipsis) {
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
		if strings.Contains(p, docPlaceholder) || p == "-" {
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

func checkDocCommands(t *testing.T, cmds []docCommand) {
	t.Helper()
	for _, c := range cmds {
		warnings, err := validateDocArgv(rootCmd, c.argv, c.deprecatedOK, 0)
		for _, w := range warnings {
			t.Logf("%s: %s\n  %s", c.where(), w, c.text)
		}
		if err != nil {
			t.Errorf("%s: %s\n  -> %v\n  (fix the command, or mark a synopsis with `<!-- doccheck: skip -->` / `# doccheck: skip`)",
				c.where(), c.text, err)
		}
	}
}

func TestDocCommandsSkillBundle(t *testing.T) {
	prepareCommandTree(rootCmd)
	total := 0
	for _, f := range embeddedSkillDocs(t) {
		cmds := markdownDocCommands(f.path, f.body)
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
		cmds := markdownDocCommands(n, docs[n])
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
			if _, err := validateDocArgv(rootCmd, c.argv, c.deprecatedOK, 0); err != nil {
				if strings.Contains(err.Error(), "flag needs an argument") {
					continue // `--flag` fragment naming a flag, not a command
				}
				t.Errorf("%s: `%s`\n  -> %v\n  (fix the command, or mark a synopsis line with `doccheck: skip`)", c.where(), c.text, err)
			}
		}
	}
}

var docInlineSpan = regexp.MustCompile("`((?:\\./bin/)?vigolium [^`]+)`")

// inlineSkillSpans extracts `vigolium …` spans outside fences, skipping the
// ones that read as synopsis rather than a command.
func inlineSkillSpans(src, body string) []docCommand {
	_, prose := markdownFences(body)
	var out []docCommand
	for ln, text := range prose {
		if strings.Contains(text, "doccheck: skip") || strings.Contains(prose[ln-1], "doccheck: skip") {
			continue
		}
		for _, m := range docInlineSpan.FindAllStringSubmatch(text, -1) {
			span := m[1]
			if docInlineSynopsis(span) {
				continue
			}
			for _, argv := range docShellCommands(span, 0) {
				out = append(out, docCommand{source: src, line: ln, text: span, argv: argv})
			}
		}
	}
	slices.SortFunc(out, func(a, b docCommand) int { return a.line - b.line })
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

// The lexer and validator are the test's own logic; pin the cases that bit
// the prototype.
func TestDocShellLexer(t *testing.T) {
	cases := []struct {
		line string
		want [][]string
	}{
		{`vigolium finding --id <id> -j`, [][]string{{"finding", "--id", "PLACEHOLDER", "-j"}}},
		{`vigolium scan -t https://x 2>&1 | tee out.log`, [][]string{{"scan", "-t", "https://x"}}},
		{`eval "$(vigolium project use <uuid> --shell)"`, [][]string{{"project", "use", "PLACEHOLDER", "--shell"}}},
		{`VIGOLIUM_DB_PATH=/tmp/x.db timeout 60 vigolium db stats -j > s.json`, [][]string{{"db", "stats", "-j"}}},
		{`cat ids.txt | xargs -I{} vigolium finding --id {}`, [][]string{{"finding", "--id", "{}"}}},
		{`vigolium ext eval 'vigolium.log.info("a # b")' # comment`, [][]string{{"ext", "eval", `vigolium.log.info("a # b")`}}},
		{`./bin/vigolium version && echo ok`, [][]string{{"version"}}},
		{`$(go env GOPATH)/bin/vigolium version`, [][]string{{"version"}}},
		{"watch -n 5 'vigolium scan status <uuid>'", [][]string{{"scan", "status", "PLACEHOLDER"}}},
		{"vigolium ingest -I openapi < spec.yaml", [][]string{{"ingest", "-I", "openapi"}}},
		{"vigolium scan -t \"$TARGET\" --format jsonl", [][]string{{"scan", "-t", "PLACEHOLDER", "--format", "jsonl"}}},
		{"vigolium storage rm a b ...", [][]string{{"storage", "rm", "a", "b", docEllipsis}}},
		{`vigolium olium --prompt "..."`, [][]string{{"olium", "--prompt", "PLACEHOLDER"}}},
		{"vigolium ffuf -j -- <ffuf flags>", [][]string{{"ffuf", "-j", "--", "PLACEHOLDER"}}},
	}
	for _, tc := range cases {
		got := docShellCommands(tc.line, 0)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s\n  got  %q\n  want %q", tc.line, got, tc.want)
		}
	}

	lines := logicalDocLines([]string{
		"$ vigolium scan \\",
		"    -t https://x",
		"vigolium ext eval --stdin <<'EOF'",
		"vigolium.nope()",
		"EOF",
		"→ output line",
		"vigolium version # doccheck: skip",
	}, 1, docLinesShell, false)
	if len(lines) != 2 || lines[0].text != "vigolium scan  -t https://x" || lines[1].line != 3 {
		t.Errorf("logical lines: %+v", lines)
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
		cmds := docShellCommands(line, 0)
		if len(cmds) != 1 {
			t.Fatalf("%s: extracted %d commands", line, len(cmds))
		}
		if _, err := validateDocArgv(rootCmd, cmds[0], false, 0); err == nil {
			t.Errorf("validator accepted %q", line)
		}
	}
	cmds := docShellCommands("vigolium agent query --agent x --prompt hi # doccheck: deprecated-ok", 0)
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
		for _, argv := range docShellCommands(line, 0) {
			if _, err := validateDocArgv(rootCmd, argv, false, 0); err != nil {
				t.Errorf("validator rejected %q: %v", line, err)
			}
		}
	}
}
