package main

import (
	"regexp"
	"strconv"
	"strings"
)

// re2MaxRepeat is the maximum repeat count Go's RE2 accepts ({1000}). Kingfisher
// patterns occasionally exceed it (e.g. {20,1024}); we clamp to keep compiling.
// Clamping only shortens the maximum acceptable secret length, which is
// irrelevant for detection — real credentials are far shorter than 1000 bytes.
const re2MaxRepeat = 1000

var leadingFlagRe = regexp.MustCompile(`^\(\?([a-zA-Z]+)\)`)

// normalize converts a Rust/PCRE regex (as shipped by kingfisher) into a pattern
// that compiles under Go RE2 / go-re2.
//
// Transforms, in order:
//  1. strip the leading (?x)/(?xi) inline-flag group, dropping only the x flag
//  2. remove insignificant whitespace and #-to-EOL comments (verbose mode)
//  3. remove PCRE inline comment groups (?# ... ) everywhere
//  4. rewrite Rust named groups (?<name> to Go's (?P<name>
//  5. clamp {n}/{n,m} repeat counts above 1000 to 1000
//
// All passes are character-class and backslash-escape aware so payload bytes are
// never altered.
func normalize(pat string) string {
	verbose := false

	if m := leadingFlagRe.FindStringSubmatch(pat); m != nil {
		flags := m[1]
		if strings.ContainsRune(flags, 'x') {
			verbose = true
			kept := strings.ReplaceAll(flags, "x", "")
			if kept == "" {
				pat = pat[len(m[0]):]
			} else {
				pat = "(?" + kept + ")" + pat[len(m[0]):]
			}
		}
	}

	pat = stripComments(pat, verbose)
	pat = rewriteNamedGroups(pat)
	pat = clampRepeats(pat)
	return pat
}

// stripComments removes PCRE inline comment groups (?#...) unconditionally, and
// (in verbose mode) insignificant whitespace plus #-to-end-of-line comments.
func stripComments(pat string, verbose bool) string {
	var b strings.Builder
	b.Grow(len(pat))
	inClass := false
	for i := 0; i < len(pat); i++ {
		c := pat[i]

		// Preserve escape sequences verbatim.
		if c == '\\' && i+1 < len(pat) {
			b.WriteByte(c)
			b.WriteByte(pat[i+1])
			i++
			continue
		}

		if inClass {
			if c == ']' {
				inClass = false
			}
			b.WriteByte(c)
			continue
		}

		// (?# ... ) PCRE comment group — drop to the next unescaped ')'.
		if c == '(' && i+2 < len(pat) && pat[i+1] == '?' && pat[i+2] == '#' {
			j := i + 3
			for j < len(pat) && pat[j] != ')' {
				if pat[j] == '\\' {
					j++
				}
				j++
			}
			i = j // loop ++ moves past the ')'
			continue
		}

		switch c {
		case '[':
			inClass = true
			b.WriteByte(c)
		case ' ', '\t', '\n', '\r', '\f':
			if !verbose {
				b.WriteByte(c)
			}
		case '#':
			if verbose {
				for i < len(pat) && pat[i] != '\n' {
					i++
				}
			} else {
				b.WriteByte(c)
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var namedGroupRe = regexp.MustCompile(`\(\?<([a-zA-Z_][a-zA-Z0-9_]*)>`)

// rewriteNamedGroups converts Rust's (?<name> syntax to Go's (?P<name>. Rust's
// regex crate has no lookbehind, so (?< is always a named group here.
func rewriteNamedGroups(pat string) string {
	if !strings.Contains(pat, "(?<") {
		return pat
	}
	return namedGroupRe.ReplaceAllString(pat, "(?P<$1>")
}

// clampRepeats lowers any {n} / {n,} / {n,m} quantifier bound above re2MaxRepeat
// to re2MaxRepeat. Class- and escape-aware so literal braces are left alone.
func clampRepeats(pat string) string {
	var b strings.Builder
	b.Grow(len(pat))
	inClass := false
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		if c == '\\' && i+1 < len(pat) {
			b.WriteByte(c)
			b.WriteByte(pat[i+1])
			i++
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			b.WriteByte(c)
			continue
		}
		if c == '[' {
			inClass = true
			b.WriteByte(c)
			continue
		}
		if c == '{' {
			if repl, adv, ok := clampBrace(pat[i:]); ok {
				b.WriteString(repl)
				i += adv - 1
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// clampBrace parses a {n} / {n,} / {n,m} quantifier at the start of s and returns
// its clamped textual form and the number of bytes consumed. ok=false if s does
// not begin with a well-formed repeat quantifier (then the '{' is literal).
func clampBrace(s string) (string, int, bool) {
	end := strings.IndexByte(s, '}')
	if end <= 1 {
		return "", 0, false
	}
	inner := s[1:end]
	comma := strings.IndexByte(inner, ',')
	clamp := func(v string) (string, bool) {
		n, err := strconv.Atoi(v)
		if err != nil {
			return "", false
		}
		if n > re2MaxRepeat {
			n = re2MaxRepeat
		}
		return strconv.Itoa(n), true
	}
	if comma < 0 {
		lo, ok := clamp(inner)
		if !ok {
			return "", 0, false
		}
		return "{" + lo + "}", end + 1, true
	}
	loRaw, hiRaw := inner[:comma], inner[comma+1:]
	lo, ok := clamp(loRaw)
	if !ok {
		return "", 0, false
	}
	if hiRaw == "" {
		return "{" + lo + ",}", end + 1, true
	}
	hi, ok := clamp(hiRaw)
	if !ok {
		return "", 0, false
	}
	return "{" + lo + "," + hi + "}", end + 1, true
}
