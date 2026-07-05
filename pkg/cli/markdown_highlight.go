package cli

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// Lightweight Markdown syntax highlighting for the --markdown display mode.
// This is display-only sugar: it is applied to the finished Markdown just
// before it hits an interactive terminal, and is a no-op otherwise, so piping
// to a file or a viewer like `glow` keeps clean, un-escaped Markdown.

var (
	mdHeadingRe = regexp.MustCompile(`^(#{1,6})\s`)
	mdRuleRe    = regexp.MustCompile(`^-{3,}$`)
	mdBoldRe    = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdCodeRe    = regexp.MustCompile("`([^`]+)`")
)

// highlightMarkdown adds ANSI colors to rendered Markdown for interactive
// display: headings, horizontal rules, ``` fence delimiters, **bold** spans and
// `inline code`. It is a no-op unless stdout is an interactive terminal with
// color enabled, so redirected/piped output stays plain Markdown (the fenced
// ```http blocks are meant to be greppable and to feed viewers like `glow`).
// Content inside fenced code blocks — the raw HTTP request/response — is left
// verbatim; only the fence lines themselves are tinted.
func highlightMarkdown(md string) string {
	if !terminal.IsTerminal() || !terminal.IsColorEnabled() {
		return md
	}
	lines := strings.Split(md, "\n")
	inFence := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			lines[i] = terminal.Gray(line)
			inFence = !inFence
			continue
		}
		if inFence {
			continue // raw request/response — leave untouched
		}
		lines[i] = highlightMarkdownLine(line)
	}
	return strings.Join(lines, "\n")
}

// highlightMarkdownLine colorizes a single non-fenced Markdown line: a heading
// or horizontal rule colors the whole line; otherwise inline `code` and **bold**
// spans are tinted in place (their markers dropped for a clean read).
func highlightMarkdownLine(line string) string {
	if mdHeadingRe.MatchString(line) {
		return terminal.BoldOrange(line)
	}
	if mdRuleRe.MatchString(strings.TrimSpace(line)) {
		return terminal.Gray(line)
	}
	line = mdCodeRe.ReplaceAllStringFunc(line, func(s string) string {
		return terminal.Yellow(s[1 : len(s)-1]) // strip the backticks
	})
	line = mdBoldRe.ReplaceAllStringFunc(line, func(s string) string {
		return terminal.BoldYellow(s[2 : len(s)-2]) // strip the ** markers
	})
	return line
}
