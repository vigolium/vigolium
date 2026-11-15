package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
)

// The documentation-example extractor: every `vigolium …` command an operator
// or an agent copies from — the skill bundle, the README and docs/, the
// --full-example tour and every command's Example/Long — is pulled out here as
// an argv (doc_commands_test.go parses each one against the real tree;
// test/e2e runs the read-only ones against a seeded store, see
// DocExamples). It never runs a command.

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
	pipe         [][]string
	deprecatedOK bool
}

func (c docCommand) where() string { return fmt.Sprintf("%s:%d", c.source, c.line) }

// docLine is one logical shell line: continuations joined, prompt stripped.
type docLine struct {
	line         int
	text         string
	deprecatedOK bool
}

// cobraDocCommands extracts commands from every command's Example and Long.
// Example lines are shell lines in full (pipes and substitutions included);
// a Long is prose, so only its lines that start with a vigolium invocation
// count.
func cobraDocCommands(root *cobra.Command) []docCommand {
	var out []docCommand
	walkTree(root, func(c *cobra.Command) {
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
		for _, inv := range docShellInvocations(l.text, 0) {
			out = append(out, docCommand{source: src, line: l.line, text: l.text, argv: inv.argv, pipe: inv.pipe, deprecatedOK: l.deprecatedOK})
		}
	}
	return out
}

// docShellCommands returns the vigolium argvs (without "vigolium") in one shell
// line, recursing into $(…), backticks and `sh -c`/`watch` command strings.
// A line that does not lex returns a single nil-argv sentinel only when it
// starts with vigolium, so the caller reports it rather than skipping it.
func docShellCommands(text string, depth int) [][]string {
	var out [][]string
	for _, inv := range docShellInvocations(text, depth) {
		out = append(out, inv.argv)
	}
	return out
}

// docInvocation is one vigolium argv and the commands its output is piped
// into (`| jq -r '.items[].uuid'`), in order.
type docInvocation struct {
	argv []string
	pipe [][]string
}

// docShellInvocations is docShellCommands with each invocation's pipe tail.
func docShellInvocations(text string, depth int) []docInvocation {
	if depth > 4 {
		return nil
	}
	segs, seps, subs, err := lexShellSeps(text)
	if err != nil {
		if docStartsWithVigolium(strings.TrimSpace(text)) {
			return []docInvocation{{argv: []string{"\x00lex", err.Error()}}}
		}
		return nil
	}
	var out []docInvocation
	for i, seg := range segs {
		argv, nested := normalizeDocSegment(seg)
		if nested != "" {
			out = append(out, docShellInvocations(nested, depth+1)...)
			continue
		}
		if argv == nil {
			continue
		}
		inv := docInvocation{argv: argv}
		for j := i; j < len(seps) && seps[j] == "|" && j+1 < len(segs); j++ {
			inv.pipe = append(inv.pipe, segs[j+1])
		}
		out = append(out, inv)
	}
	for _, sub := range subs {
		out = append(out, docShellInvocations(sub, depth+1)...)
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
	segs, _, subs, err = lexShellSeps(src)
	return segs, subs, err
}

// lexShellSeps is lexShell that also returns, for each segment, the operator
// that ended it ("|", "||", "&&", ";", "&", "(" / ")", or "" at the end).
func lexShellSeps(src string) (segs [][]string, seps []string, subs []string, err error) {
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
	endSeg := func(sep string) {
		flush()
		if len(cur) > 0 {
			segs = append(segs, cur)
			seps = append(seps, sep)
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
				return nil, nil, nil, errDocUnterminated
			}
			word.WriteString(string(r[i+1 : i+1+j]))
			inWord, quoted = true, true
			i += j + 1
		case c == '"':
			j, err := lexDoubleQuoted(r, i+1, &word, &subs)
			if err != nil {
				return nil, nil, nil, err
			}
			inWord, quoted = true, true
			i = j
		case c == '$':
			j, err := lexDollar(r, i, &word, &subs)
			if err != nil {
				return nil, nil, nil, err
			}
			inWord = true
			i = j
		case c == '`':
			j := slices.Index(r[i+1:], '`')
			if j < 0 {
				return nil, nil, nil, errDocUnterminated
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
					return nil, nil, nil, err
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
				endSeg("&&")
				i++
			case '>':
				flush()
				i++
				if peek(i+1) == '>' {
					i++
				}
				dropNext = true
			default:
				endSeg("&")
			}
		case c == '|':
			sep := "|"
			if peek(i+1) == '|' {
				sep = "||"
			}
			endSeg(sep)
			if peek(i+1) == '|' || peek(i+1) == '&' {
				i++
			}
		case c == ';':
			endSeg(";")
		case (c == '(' || c == ')') && !inWord:
			endSeg(string(c))
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	endSeg("")
	return segs, seps, subs, nil
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

// DocExample is one documented vigolium invocation, for a test that runs the
// documentation (test/e2e).
type DocExample struct {
	Source string
	Line   int
	Text   string
	// Argv follows "vigolium". A value the reader fills in ($VAR, <uuid>,
	// $(…)) is DocPlaceholder; an elided one ("…") is DocEllipsis.
	Argv []string
	// Pipe are the commands the invocation's stdout is piped into, in order
	// (`| jq -r '.items[].uuid'` is {{"jq", "-r", ".items[].uuid"}}).
	Pipe [][]string
}

// The placeholder words in DocExample.Argv.
const (
	DocPlaceholder = docPlaceholder
	DocEllipsis    = docEllipsis
)

// DocExamples returns every documented invocation in the embedded skill
// bundle, every command's Example and Long, and the --full-example tour.
func DocExamples() ([]DocExample, error) {
	prepareCommandTree(rootCmd)
	cmds := cobraDocCommands(rootCmd)
	cmds = append(cmds, fullExampleDocCommands()...)
	files, err := skillBundleMarkdown()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		cmds = append(cmds, markdownDocCommands(f.path, f.body)...)
	}
	return exportDocCommands(cmds), nil
}

// MarkdownDocExamples returns the invocations in one markdown document's
// runnable fences (README.md, docs/…).
func MarkdownDocExamples(src, body string) []DocExample {
	return exportDocCommands(markdownDocCommands(src, body))
}

func exportDocCommands(cmds []docCommand) []DocExample {
	out := make([]DocExample, 0, len(cmds))
	for _, c := range cmds {
		if len(c.argv) > 0 && strings.HasPrefix(c.argv[0], "\x00") {
			continue // did not lex; doc_commands_test reports it
		}
		out = append(out, DocExample{Source: c.source, Line: c.line, Text: c.text, Argv: c.argv, Pipe: c.pipe})
	}
	return out
}

// docExampleUnsafeFlags turn an invocation of a read command into one that
// writes, sends, streams or waits: such an example is not run unattended.
var docExampleUnsafeFlags = append([]string{
	"replay", "push-to-burp", "to-repeater", "to-organizer", "send-to-burp", "save-to-burp",
	"watch", "follow", "tui", "interactive", "fix", "for", "stdin",
}, dbWriteFlags...)

// ReadOnlyDocExample resolves ex to its command and reports whether it can be
// run against a seeded store with nothing on the wire: commandTraits declares
// the command a read that opens the store for reading and sends no traffic,
// and no flag in the invocation changes that. why says why not.
func ReadOnlyDocExample(ex DocExample) (path, why string) {
	prepareCommandTree(rootCmd)
	cmd, _, err := rootCmd.Find(ex.Argv)
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
	for _, a := range ex.Argv {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "--") && slices.Contains(docExampleUnsafeFlags, name) {
			return path, "--" + name + " writes, sends, streams or waits"
		}
	}
	return path, ""
}
