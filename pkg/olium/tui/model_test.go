package tui

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/terminal"
)

func TestRenderProseKeepsMarkdownRaw(t *testing.T) {
	input := strings.Join([]string{
		"# Markdown Example",
		"# C# notes",
		"## Closed heading ##",
		"",
		"## Text styles",
		"- **bold**",
		"- *italic*",
		"- ~~strikethrough~~",
		"- `inline code`",
		"",
		"1. First item",
		"  - Nested bullet",
		"",
		"[OpenAI](https://openai.com)",
	}, "\n")

	out := terminal.StripANSI(renderProse(input))
	if out != input {
		t.Fatalf("rendered prose should preserve raw markdown.\nwant:\n%s\n\ngot:\n%s", input, out)
	}
}

func TestRenderProseAppliesMarkdownHighlighting(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"h1", "# Heading one"},
		{"h2", "## Heading two"},
		{"bold", "this is **bold** text"},
		{"italic", "this is *italic* text"},
		{"strikethrough", "this is ~~gone~~ text"},
		{"inline code", "see `func()` for details"},
		{"link", "check [OpenAI](https://openai.com)"},
		{"bullet", "- first item"},
		{"numbered", "1. first item"},
		{"blockquote", "> quoted line"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderProse(tc.in)
			if !strings.Contains(out, "\x1b[") {
				t.Fatalf("expected ANSI escapes in output for %q, got %q", tc.in, out)
			}
			if stripped := terminal.StripANSI(out); stripped != tc.in {
				t.Fatalf("stripped output should match raw input.\nwant: %q\n got: %q", tc.in, stripped)
			}
		})
	}
}

func TestRenderAssistantKeepsMarkdownRawAndHighlightsCodeFenceBody(t *testing.T) {
	text := strings.Join([]string{
		"## Code sample",
		"",
		"```go",
		"package main",
		"",
		"func main() {}",
		"```",
	}, "\n")

	m := Model{width: 80}
	rendered := m.renderAssistant(text)
	out := terminal.StripANSI(rendered)

	for _, wanted := range []string{"## Code sample", "```go", "package main", "func main() {}", "```"} {
		if !strings.Contains(out, wanted) {
			t.Fatalf("rendered assistant output missing %q in:\n%s", wanted, out)
		}
	}
	if rendered == out {
		t.Fatalf("expected fenced Go body to include ANSI syntax highlighting")
	}
}

func TestRenderAssistantKeepsMarkdownFenceWithNestedCodeFenceRaw(t *testing.T) {
	rawFence := strings.Join([]string{
		"```md",
		"## Text styles",
		"**Bold**",
		"*Italic*",
		"~~Strikethrough~~",
		"`Inline code`",
		"",
		"- [OpenAI](https://openai.com)",
		"- <https://example.com>",
		"- [Reference-style link][ref1]",
		"",
		"```js",
		"console.log(\"code block\");",
		"```",
		"",
		"| Column A | Column B |",
		"|----------|----------|",
		"| Value 1  | Value 2  |",
		"```",
	}, "\n")
	text := strings.Join([]string{
		"## Copyable Raw Template",
		"",
		rawFence,
	}, "\n")

	m := Model{width: 80}
	out := terminal.StripANSI(m.renderAssistant(text))
	if !strings.Contains(out, rawFence) {
		t.Fatalf("rendered markdown sample should preserve the full raw fence.\nwant fence:\n%s\n\ngot:\n%s", rawFence, out)
	}
	if strings.Count(out, "```") != 4 {
		t.Fatalf("nested markdown sample should keep all fence markers, got:\n%s", out)
	}
}

func TestSplitScrollbackChunksCapsVisualRows(t *testing.T) {
	lines := make([]string, 0, 55)
	for i := 0; i < 55; i++ {
		lines = append(lines, "line")
	}

	chunks := splitScrollbackChunks(strings.Join(lines, "\n"), 80, 12)
	if len(chunks) < 2 {
		t.Fatalf("expected long scrollback output to be split, got %d chunk", len(chunks))
	}

	for _, chunk := range chunks {
		rows := 0
		for _, line := range strings.Split(chunk, "\n") {
			rows += visualRows(line, 80)
		}
		if rows > 12 {
			t.Fatalf("chunk has %d visual rows, want <= 12:\n%s", rows, terminal.StripANSI(chunk))
		}
	}
}

func TestSplitScrollbackChunksAccountsForWrappedLines(t *testing.T) {
	input := strings.Join([]string{
		strings.Repeat("a", 25),
		strings.Repeat("b", 25),
		"tail",
	}, "\n")

	chunks := splitScrollbackChunks(input, 10, 3)
	if len(chunks) != 3 {
		t.Fatalf("expected each wrapped line to force a chunk, got %d: %#v", len(chunks), chunks)
	}
	if got := strings.Join(chunks, "\n"); got != input {
		t.Fatalf("chunks should preserve content\nwant: %q\ngot:  %q", input, got)
	}
}

// TestStreamingFenceStateMachine drives the per-line fence helpers directly
// (feedFence + finishFence + drainUnclosedFence) so we lock in the streaming
// boundaries without standing up a Bubble Tea program.
func TestStreamingFenceStateMachine(t *testing.T) {
	t.Run("non-markdown fence closes on empty-lang fence", func(t *testing.T) {
		m := &Model{width: 80}
		m.inFence = true
		m.fenceLang = "go"
		m.fenceOpenLine = "```go"
		m.fenceBuf = []string{"package main", "", "func main() {}"}

		// fence-like line carrying a lang inside a non-md fence is content,
		// not a close.
		if _, closed := m.feedFence("```js"); closed {
			t.Fatalf("non-md fence should treat a lang-bearing fence line as content, not a close")
		}
		if !m.inFence {
			t.Fatalf("inFence flipped after content line")
		}

		block, closed := m.feedFence("```")
		if !closed {
			t.Fatalf("non-md fence did not close on empty-lang fence line")
		}
		if m.inFence {
			t.Fatalf("inFence should be false after close")
		}
		raw := terminal.StripANSI(block)
		for _, want := range []string{"```go", "package main", "func main() {}", "```js", "```"} {
			if !strings.Contains(raw, want) {
				t.Fatalf("rendered fence missing %q\nrendered:\n%s", want, raw)
			}
		}
	})

	t.Run("markdown fence respects nested-fence depth", func(t *testing.T) {
		m := &Model{width: 80}
		m.inFence = true
		m.fenceLang = "md"
		m.fenceOpenLine = "```md"

		// open nested
		if _, closed := m.feedFence("```js"); closed {
			t.Fatalf("nested-fence opener should not close outer md fence")
		}
		if !m.mdFenceNested {
			t.Fatalf("expected mdFenceNested=true after entering nested fence")
		}
		if _, closed := m.feedFence("console.log(1);"); closed {
			t.Fatalf("nested fence body should not close outer md fence")
		}
		// close nested
		if _, closed := m.feedFence("```"); closed {
			t.Fatalf("empty-lang fence inside a nested block should only close the nested fence, not the outer md")
		}
		if m.mdFenceNested {
			t.Fatalf("expected mdFenceNested=false after exiting nested fence")
		}
		// now close outer
		block, closed := m.feedFence("```")
		if !closed {
			t.Fatalf("empty-lang fence at depth 0 should close the outer md fence")
		}
		raw := terminal.StripANSI(block)
		if strings.Count(raw, "```") != 4 {
			t.Fatalf("expected all four fence markers preserved, got:\n%s", raw)
		}
	})

	t.Run("drainUnclosedFence emits opener + buffered body raw", func(t *testing.T) {
		m := &Model{width: 80}
		m.inFence = true
		m.fenceLang = "go"
		m.fenceOpenLine = "```go"
		m.fenceBuf = []string{"package main", "func incomplete() {"}

		raw := terminal.StripANSI(m.drainUnclosedFence())
		want := "```go\npackage main\nfunc incomplete() {"
		if raw != want {
			t.Fatalf("drainUnclosedFence mismatch\nwant: %q\n got: %q", want, raw)
		}
		if m.inFence {
			t.Fatalf("drainUnclosedFence should reset inFence")
		}
	})
}

// TestHandleTextDeltaPartialPreservedAcrossDeltas verifies that streamPartial
// accumulates bytes received between newlines, so a token-by-token stream
// like "Hel"+"lo "+"world\n" still reads as one finished line.
func TestHandleTextDeltaPartialPreservedAcrossDeltas(t *testing.T) {
	m := &Model{width: 80}

	m.handleTextDelta("Hel")
	if m.streamPartial != "Hel" {
		t.Fatalf("first partial: want %q got %q", "Hel", m.streamPartial)
	}
	m.handleTextDelta("lo ")
	if m.streamPartial != "Hello " {
		t.Fatalf("second partial: want %q got %q", "Hello ", m.streamPartial)
	}
	m.handleTextDelta("world\n")
	if m.streamPartial != "" {
		t.Fatalf("after newline partial should be empty, got %q", m.streamPartial)
	}
}

// TestFilterSlashItemsPrefixMatch locks in that the chooser keeps every label
// whose prefix matches the typed query — predictable, narrowing-only behavior
// (no fuzzy expansion) so Tab autocomplete always extends what's typed.
func TestFilterSlashItemsPrefixMatch(t *testing.T) {
	items := []slashItem{
		{label: "/clear"},
		{label: "/skill:audit-auth"},
		{label: "/skill:triage-finding"},
	}

	cases := []struct {
		query string
		want  []string
	}{
		{"/", []string{"/clear", "/skill:audit-auth", "/skill:triage-finding"}},
		{"/c", []string{"/clear"}},
		{"/skill:", []string{"/skill:audit-auth", "/skill:triage-finding"}},
		{"/skill:tri", []string{"/skill:triage-finding"}},
		{"/none", nil},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			got := filterSlashItems(items, tc.query)
			gotLabels := make([]string, 0, len(got))
			for _, it := range got {
				gotLabels = append(gotLabels, it.label)
			}
			if len(gotLabels) != len(tc.want) {
				t.Fatalf("len mismatch for %q: want %v got %v", tc.query, tc.want, gotLabels)
			}
			for i := range tc.want {
				if gotLabels[i] != tc.want[i] {
					t.Fatalf("label mismatch for %q: want %v got %v", tc.query, tc.want, gotLabels)
				}
			}
		})
	}
}

// TestBuildSlashItemsHandlesNilRegistry guards against the chooser blowing up
// when no skills are loaded — /clear should still appear as the lone entry.
func TestBuildSlashItemsHandlesNilRegistry(t *testing.T) {
	items := buildSlashItems(nil)
	if len(items) != 1 || items[0].label != "/clear" {
		t.Fatalf("nil registry should yield only /clear, got %#v", items)
	}
}

// TestCompactThinkingBodyDropsAllBlanks verifies that the thinking lane
// collapses every whitespace-only row — including NBSP, tabs, and the
// gnarly GPT-5-style "\n\n\n\n\n\n\n\n" gaps between summary title and
// body — to produce a tight status block with no dead space.
func TestCompactThinkingBodyDropsAllBlanks(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no blanks", "a\nb\nc", "a\nb\nc"},
		{"single blank removed", "a\n\nb", "a\nb"},
		{"huge gap flattens", "**title**\n\n\n\n\n\n\n\nbody", "**title**\nbody"},
		{"whitespace lines removed", "a\n \n\t\n \nb", "a\nb"},
		{"trims each surviving line", "  a  \n\t b \t", "a\nb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := compactThinkingBody(tc.in); got != tc.want {
				t.Fatalf("compactThinkingBody(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRenderThinkingBlockFormatting locks in the ⋈ header and that a
// reasoning stream with a huge newline gap between title and body — the
// exact shape GPT-5 tends to emit — renders as two adjacent indented
// lines with no dead rows between.
func TestRenderThinkingBlockFormatting(t *testing.T) {
	m := &Model{}
	m.thinkingBuf = "\n\n**Responding to greeting**\n\n\n\n\n\n\nThe user typed hoal.\n\n"

	out := terminal.StripANSI(m.renderThinkingBlock())
	wantHeader := "  " + terminal.SymbolBowtie + " thinking"
	if !strings.HasPrefix(out, wantHeader+"\n") {
		t.Fatalf("thinking block should start with %q, got:\n%s", wantHeader, out)
	}
	if strings.Contains(out, "\n\n") {
		t.Fatalf("thinking block should have no blank rows, got:\n%s", out)
	}
	for _, want := range []string{"**Responding to greeting**", "The user typed hoal."} {
		if !strings.Contains(out, want) {
			t.Fatalf("thinking block missing %q in:\n%s", want, out)
		}
	}
}

// TestRenderThinkingBlockEmptyBufferSkips guards against emitting a bare
// header when the reasoning stream was only whitespace — the caller uses
// the empty string to skip the scrollback push entirely.
func TestRenderThinkingBlockEmptyBufferSkips(t *testing.T) {
	m := &Model{}
	m.thinkingBuf = "  \n\t\n"
	if out := m.renderThinkingBlock(); out != "" {
		t.Fatalf("whitespace-only thinking buf should render empty, got %q", out)
	}
}

// TestHandleTextDeltaEntersFenceWithoutFlushingPartial verifies that a fence
// opener flips inFence and stops emitting prose lines until the fence closes.
func TestHandleTextDeltaEntersFenceWithoutFlushingPartial(t *testing.T) {
	m := &Model{width: 80}

	m.handleTextDelta("intro line\n```go\n")
	if !m.inFence {
		t.Fatalf("expected inFence=true after ```go opener")
	}
	if m.fenceLang != "go" {
		t.Fatalf("expected fenceLang=go, got %q", m.fenceLang)
	}
	if m.fenceOpenLine != "```go" {
		t.Fatalf("expected fenceOpenLine=```go, got %q", m.fenceOpenLine)
	}

	m.handleTextDelta("package main\n")
	if len(m.fenceBuf) != 1 || m.fenceBuf[0] != "package main" {
		t.Fatalf("expected fenceBuf=[package main], got %#v", m.fenceBuf)
	}

	m.handleTextDelta("```\n")
	if m.inFence {
		t.Fatalf("expected fence to close after ``` line")
	}
	if len(m.fenceBuf) != 0 {
		t.Fatalf("fenceBuf should be cleared after close, got %#v", m.fenceBuf)
	}
}
