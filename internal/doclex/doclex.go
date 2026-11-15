// Package doclex extracts the vigolium invocations from documentation: shell
// lines, markdown fences and prose that starts with a vigolium command. It
// lexes a shell subset into argvs (placeholders for anything the shell or the
// reader would fill in) and never runs anything. pkg/cli's doc tests parse
// every extracted argv against the command tree; test/e2e runs the read-only
// ones against a seeded store.
package doclex

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Placeholder replaces every value the shell would expand or a reader would
// fill in: $VAR, $(…), `…`, <uuid>.
const Placeholder = "PLACEHOLDER"

// Ellipsis replaces a bare unquoted "…"/"...": "more of the same". It can
// stand in for a flag's value (`-B …`) and is dropped from positionals.
const Ellipsis = Placeholder + "_ELLIPSIS"

// Command is one vigolium invocation found in a documentation source.
type Command struct {
	Source string
	Line   int
	Text   string
	// Argv follows "vigolium". A value the reader fills in ($VAR, <uuid>,
	// $(…)) is Placeholder; an elided one ("…") is Ellipsis. A line that does
	// not lex has Argv {"\x00lex", <error>}.
	Argv []string
	// Pipe are the commands the invocation's stdout is piped into, in order
	// (`| jq -r '.items[].uuid'` is {{"jq", "-r", ".items[].uuid"}}).
	Pipe [][]string
	// DeprecatedOK marks an example allowed to use a deprecated spelling
	// (doccheck: deprecated-ok).
	DeprecatedOK bool
}

// Lexed drops the commands whose line did not lex (Argv {"\x00lex", …}),
// which a parse check reports and a runner skips.
func Lexed(cmds []Command) []Command {
	out := make([]Command, 0, len(cmds))
	for _, c := range cmds {
		if len(c.Argv) > 0 && strings.HasPrefix(c.Argv[0], "\x00") {
			continue
		}
		out = append(out, c)
	}
	return out
}

// Where is the source and line, for a report.
func (c Command) Where() string { return fmt.Sprintf("%s:%d", c.Source, c.Line) }

// LogicalLine is one logical shell line: continuations joined, prompt stripped.
type LogicalLine struct {
	Line         int
	Text         string
	DeprecatedOK bool
}

// ---------------------------------------------------------------------------
// Markdown extraction
// ---------------------------------------------------------------------------

// runnableFences are the info strings whose fences hold commands. Untagged
// and `text` fences are output or synopsis, never runnable.
var runnableFences = map[string]bool{"bash": true, "sh": true, "shell": true, "zsh": true, "console": true}

type Fence struct {
	Line         int // 1-based line of the first body line
	Info         string
	Body         []string
	Skip         bool
	DeprecatedOK bool
}

var fenceOpen = regexp.MustCompile("^(\\s*)(`{3,}|~{3,})\\s*(.*)$")

// Fences splits a markdown document into fenced blocks, following the
// CommonMark closing rule (same character, at least as long, no info string).
// It also returns, for inline-span scanning, every line outside a fence.
func Fences(body string) (fences []Fence, prose map[int]string) {
	lines := strings.Split(body, "\n")
	prose = map[int]string{}
	prevNonBlank := ""
	for i := 0; i < len(lines); i++ {
		m := fenceOpen.FindStringSubmatch(lines[i])
		if m == nil {
			prose[i+1] = lines[i]
			if strings.TrimSpace(lines[i]) != "" {
				prevNonBlank = strings.TrimSpace(lines[i])
			}
			continue
		}
		indent, marker, info := m[1], m[2], strings.TrimSpace(m[3])
		f := Fence{Line: i + 2, Info: info}
		f.Skip = strings.Contains(info, "doccheck=skip") || strings.Contains(prevNonBlank, "doccheck: skip")
		f.DeprecatedOK = strings.Contains(info, "doccheck=deprecated-ok") || strings.Contains(prevNonBlank, "doccheck: deprecated-ok")
		j := i + 1
		for ; j < len(lines); j++ {
			t := strings.TrimSpace(lines[j])
			if strings.HasPrefix(t, marker[:3]) && strings.Trim(t, marker[:1]) == "" && len(t) >= len(marker) {
				break
			}
			f.Body = append(f.Body, strings.TrimPrefix(lines[j], indent))
		}
		fences = append(fences, f)
		i = j
		prevNonBlank = ""
	}
	return fences, prose
}

// Markdown extracts the commands in a markdown document's runnable
// fences.
func Markdown(src, body string) []Command {
	fences, _ := Fences(body)
	var out []Command
	for _, f := range fences {
		lang := strings.ToLower(strings.Fields(f.Info + " x")[0])
		if f.Skip || !runnableFences[lang] {
			continue
		}
		mode := LinesShell
		if lang == "console" {
			mode = LinesConsole
		}
		out = append(out, FromLines(src, f.Body, f.Line, mode, f.DeprecatedOK)...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Logical lines
// ---------------------------------------------------------------------------

type LineMode int

const (
	// LinesShell: every line is shell (a `$ ` prompt is stripped).
	LinesShell LineMode = iota
	// LinesConsole: only `$ `-prompted lines are commands; the rest is output.
	LinesConsole
	// LinesProse: only lines that start with a vigolium invocation count.
	LinesProse
)

var heredoc = regexp.MustCompile(`<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// LogicalLines joins continuations, strips prompts, and drops comments,
// output lines and heredoc bodies.
func LogicalLines(lines []string, first int, mode LineMode, deprecatedOK bool) []LogicalLine {
	var out []LogicalLine
	for i := 0; i < len(lines); i++ {
		raw := strings.TrimSpace(lines[i])
		start := i
		switch {
		case strings.HasPrefix(raw, "$ "):
			raw = strings.TrimSpace(raw[2:])
		case raw == "$":
			continue
		case mode == LinesConsole:
			continue
		}
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "→") {
			continue
		}
		if mode == LinesProse {
			if !startsWithVigolium(raw) {
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
			if mode != LinesProse && openQuote(text) && i+1 < len(lines) && i-start < 60 {
				i++
				text += "\n" + lines[i]
				continue
			}
			break
		}
		// A quote that never closes is a typo on this line, not a multi-line
		// argument: report this line alone rather than swallow the block.
		if strings.Contains(text, "\n") && openQuote(text) {
			i = start
			text = raw
		}
		// Heredoc: the body is data for the command, not commands.
		if m := heredoc.FindStringSubmatch(text); m != nil && !strings.Contains(text, "<<<") {
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
		out = append(out, LogicalLine{Line: first + start, Text: text, DeprecatedOK: lineOK})
	}
	return out
}

// openQuote reports whether text ends inside a quote.
func openQuote(text string) bool {
	_, _, err := lexShell(text)
	return errors.Is(err, errUnterminated)
}

var vigoliumWord = regexp.MustCompile(`^(\$\s+)?(\./)?(bin/)?vigolium(\s|$)`)

func startsWithVigolium(s string) bool { return vigoliumWord.MatchString(s) }

// FromLines lexes logical lines and keeps the vigolium invocations.
func FromLines(src string, lines []string, first int, mode LineMode, deprecatedOK bool) []Command {
	var out []Command
	for _, l := range LogicalLines(lines, first, mode, deprecatedOK) {
		for _, inv := range shellInvocations(l.Text, 0) {
			out = append(out, Command{Source: src, Line: l.Line, Text: l.Text, Argv: inv.Argv, Pipe: inv.Pipe, DeprecatedOK: l.DeprecatedOK})
		}
	}
	return out
}

// ShellCommands returns the vigolium argvs (without "vigolium") in one shell
// line, recursing into $(…), backticks and `sh -c`/`watch` command strings.
// A line that does not lex returns a single nil-argv sentinel only when it
// starts with vigolium, so the caller reports it rather than skipping it.
func ShellCommands(text string, depth int) [][]string {
	var out [][]string
	for _, inv := range shellInvocations(text, depth) {
		out = append(out, inv.Argv)
	}
	return out
}

// invocation is one vigolium argv and the commands its output is piped
// into (`| jq -r '.items[].uuid'`), in order.
type invocation struct {
	Argv []string
	Pipe [][]string
}

// shellInvocations is ShellCommands with each invocation's pipe tail.
func shellInvocations(text string, depth int) []invocation {
	if depth > 4 {
		return nil
	}
	segs, seps, subs, err := lexShellSeps(text)
	if err != nil {
		if startsWithVigolium(strings.TrimSpace(text)) {
			return []invocation{{Argv: []string{"\x00lex", err.Error()}}}
		}
		return nil
	}
	var out []invocation
	for i, seg := range segs {
		argv, nested := normalizeSegment(seg)
		if nested != "" {
			out = append(out, shellInvocations(nested, depth+1)...)
			continue
		}
		if argv == nil {
			continue
		}
		inv := invocation{Argv: argv}
		for j := i; j < len(seps) && seps[j] == "|" && j+1 < len(segs); j++ {
			inv.Pipe = append(inv.Pipe, segs[j+1])
		}
		out = append(out, inv)
	}
	for _, sub := range subs {
		out = append(out, shellInvocations(sub, depth+1)...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Shell-subset lexer
// ---------------------------------------------------------------------------

var errUnterminated = errors.New("unterminated quote or substitution")

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
			w = Ellipsis
		case wholePlaceholder.MatchString(w) || strings.Contains(w, "...") || strings.Contains(w, "…"):
			// A quoted <placeholder>, or an elided value ("9b2f-…", "...").
			w = Placeholder
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
				return nil, nil, nil, errUnterminated
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
				return nil, nil, nil, errUnterminated
			}
			subs = append(subs, string(r[i+1:i+1+j]))
			word.WriteString(Placeholder)
			inWord = true
			i += j + 1
		case c == '<':
			// <placeholder> before redirection: `<uuid>` is a value, not two
			// redirections.
			if n := placeholderLen(r, i); n > 0 {
				word.WriteString(Placeholder)
				inWord = true
				i += n - 1
				continue
			}
			if peek(i+1) == '(' { // process substitution
				end, err := matchParen(r, i+1)
				if err != nil {
					return nil, nil, nil, err
				}
				subs = append(subs, string(r[i+2:end]))
				word.WriteString(Placeholder)
				inWord = true
				i = end
				continue
			}
			if inWord && allDigits(word.String()) {
				word.Reset()
				inWord = false
			}
			flush()
			for peek(i+1) == '<' || peek(i+1) == '-' || peek(i+1) == '&' || peek(i+1) == '>' {
				i++
			}
			dropNext = true
		case c == '>':
			if inWord && allDigits(word.String()) {
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

// wholePlaceholder is a quoted word that is entirely a <placeholder>.
var wholePlaceholder = regexp.MustCompile(`^<[A-Za-z_][^<>]*>$`)

// placeholderLen returns the rune length of a <placeholder> at r[i], or 0.
// A placeholder starts with a letter, so `< file` and `<<EOF` stay
// redirections. It may hold spaces only when it is plain words (`<ffuf
// flags>`) closed before the next word, so `<in.txt >out.txt` is still two
// redirections.
func placeholderLen(r []rune, i int) int {
	if i+1 >= len(r) {
		return 0
	}
	if !isLetter(r[i+1]) {
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
				return 0, errUnterminated
			}
			*subs = append(*subs, string(r[i+1:i+1+j]))
			word.WriteString(Placeholder)
			i += j + 1
		default:
			word.WriteRune(r[i])
		}
	}
	return 0, errUnterminated
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
		end, err := matchParen(r, i+1)
		if err != nil {
			return 0, err
		}
		inner := string(r[i+2 : end])
		if !strings.HasPrefix(inner, "(") { // $(( … )) is arithmetic
			*subs = append(*subs, inner)
		}
		word.WriteString(Placeholder)
		return end, nil
	case n == '{':
		j := slices.Index(r[i+2:], '}')
		if j < 0 {
			return 0, errUnterminated
		}
		word.WriteString(Placeholder)
		return i + 2 + j, nil
	case n == '\'':
		j := i + 2
		for ; j < len(r) && r[j] != '\''; j++ {
			if r[j] == '\\' {
				j++
			}
		}
		if j >= len(r) {
			return 0, errUnterminated
		}
		word.WriteString(Placeholder)
		return j, nil
	case n == '_' || n >= 'a' && n <= 'z' || n >= 'A' && n <= 'Z':
		j := i + 1
		for j+1 < len(r) && (r[j+1] == '_' || r[j+1] >= 'a' && r[j+1] <= 'z' || r[j+1] >= 'A' && r[j+1] <= 'Z' || r[j+1] >= '0' && r[j+1] <= '9') {
			j++
		}
		word.WriteString(Placeholder)
		return j, nil
	case strings.ContainsRune("0123456789?#@*!$-", n):
		word.WriteString(Placeholder)
		return i + 1, nil
	}
	word.WriteRune('$')
	return i, nil
}

// matchParen returns the index of the ')' matching the '(' at r[open],
// skipping quoted text.
func matchParen(r []rune, open int) (int, error) {
	depth := 0
	for i := open; i < len(r); i++ {
		switch r[i] {
		case '\\':
			i++
		case '\'':
			j := slices.Index(r[i+1:], '\'')
			if j < 0 {
				return 0, errUnterminated
			}
			i += j + 1
		case '"':
			for i++; i < len(r) && r[i] != '"'; i++ {
				if r[i] == '\\' {
					i++
				}
			}
			if i >= len(r) {
				return 0, errUnterminated
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
	return 0, errUnterminated
}

func isLetter(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func allDigits(s string) bool {
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

var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// prefixWords are dropped from the front of a segment: shell keywords and
// wrappers that run the rest of the segment as a command.
var prefixWords = map[string]bool{
	"eval": true, "time": true, "exec": true, "!": true, "nohup": true, "command": true,
	"builtin": true, "if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "{": true, "}": true, "env": true, "sudo": true,
}

// wrapperValueOpts are the value-taking options of the wrappers whose tail
// is a command (timeout, watch, xargs).
var wrapperValueOpts = map[string]map[string]bool{
	"timeout": {"-s": true, "-k": true, "--signal": true, "--kill-after": true},
	"watch":   {"-n": true, "--interval": true, "-q": true, "--equexit": true},
	"xargs":   {"-I": true, "-n": true, "-P": true, "-L": true, "-d": true, "-s": true, "-E": true, "-a": true, "--max-args": true, "--max-procs": true},
}

// normalizeSegment strips env prefixes and wrappers and returns the argv
// after "vigolium" (nil when the segment is not a vigolium invocation), or a
// nested command string to lex again (`sh -c '…'`, `watch '…'`).
func normalizeSegment(words []string) (argv []string, nested string) {
	for len(words) > 0 {
		w := words[0]
		switch {
		case assignment.MatchString(w) || prefixWords[w]:
			words = words[1:]
			continue
		case w == "timeout" || w == "watch" || w == "xargs":
			opts := wrapperValueOpts[w]
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
	if len(words) == 0 || !isVigoliumBinary(words[0]) {
		return nil, ""
	}
	return words[1:], ""
}

// isVigoliumBinary accepts vigolium, ./vigolium, ./bin/vigolium and any
// path ending in /bin/vigolium ($(go env GOPATH)/bin/vigolium).
func isVigoliumBinary(w string) bool {
	switch w {
	case "vigolium", "./vigolium", "bin/vigolium", "./bin/vigolium":
		return true
	}
	return strings.HasSuffix(w, "/bin/vigolium")
}
