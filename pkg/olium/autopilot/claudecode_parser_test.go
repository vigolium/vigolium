package autopilot

import (
	"strings"
	"testing"
)

func TestClaudeCodeBlockParser_PlainPassthrough(t *testing.T) {
	p := &claudeCodeBlockParser{}
	got := p.Feed("Hello world, no sentinels here.") + p.Flush()
	if got != "Hello world, no sentinels here." {
		t.Fatalf("expected verbatim passthrough; got %q", got)
	}
}

func TestClaudeCodeBlockParser_FindingDispatchedAndStripped(t *testing.T) {
	var got map[string]any
	p := &claudeCodeBlockParser{
		onFinding: func(args map[string]any) { got = args },
	}
	stream := `prefix <<<VIG:FINDING>>>{"title":"x","severity":"high","description":"y"}<<<VIG:END>>> suffix`
	out := p.Feed(stream) + p.Flush()
	if out != "prefix  suffix" {
		t.Fatalf("expected sentinel stripped; got %q", out)
	}
	if got["title"] != "x" || got["severity"] != "high" || got["description"] != "y" {
		t.Fatalf("dispatched args wrong: %#v", got)
	}
}

func TestClaudeCodeBlockParser_HaltDispatched(t *testing.T) {
	var halted string
	p := &claudeCodeBlockParser{
		onHalt: func(r string) { halted = r },
	}
	out := p.Feed("done. <<<VIG:HALT>>>scope covered<<<VIG:END>>>") + p.Flush()
	if out != "done. " {
		t.Fatalf("expected sentinel stripped; got %q", out)
	}
	if halted != "scope covered" {
		t.Fatalf("halt reason wrong: %q", halted)
	}
}

func TestClaudeCodeBlockParser_SplitAcrossDeltas(t *testing.T) {
	var got map[string]any
	p := &claudeCodeBlockParser{
		onFinding: func(args map[string]any) { got = args },
	}
	// Drip the stream one char at a time. Output should be identical to
	// the single-shot case.
	stream := `pre <<<VIG:FINDING>>>{"title":"x","severity":"high","description":"y"}<<<VIG:END>>> post`
	var out strings.Builder
	for _, r := range stream {
		out.WriteString(p.Feed(string(r)))
	}
	out.WriteString(p.Flush())
	if out.String() != "pre  post" {
		t.Fatalf("split-stream output wrong: %q", out.String())
	}
	if got["title"] != "x" {
		t.Fatalf("split-stream dispatch lost: %#v", got)
	}
}

func TestClaudeCodeBlockParser_MultipleBlocksInOneFeed(t *testing.T) {
	var findings []map[string]any
	var halted string
	p := &claudeCodeBlockParser{
		onFinding: func(args map[string]any) { findings = append(findings, args) },
		onHalt:    func(r string) { halted = r },
	}
	stream := `a<<<VIG:FINDING>>>{"title":"one","severity":"low","description":"d1"}<<<VIG:END>>>b<<<VIG:FINDING>>>{"title":"two","severity":"low","description":"d2"}<<<VIG:END>>>c<<<VIG:HALT>>>done<<<VIG:END>>>d`
	got := p.Feed(stream) + p.Flush()
	if got != "abcd" {
		t.Fatalf("expected all sentinels stripped; got %q", got)
	}
	if len(findings) != 2 || findings[0]["title"] != "one" || findings[1]["title"] != "two" {
		t.Fatalf("findings wrong: %#v", findings)
	}
	if halted != "done" {
		t.Fatalf("halt reason wrong: %q", halted)
	}
}

func TestClaudeCodeBlockParser_MalformedBlockDropped(t *testing.T) {
	called := false
	p := &claudeCodeBlockParser{
		onFinding: func(args map[string]any) { called = true },
	}
	// No tag closer ">>>" inside the block — should be silently dropped.
	out := p.Feed("x<<<VIG:nope<<<VIG:END>>>y") + p.Flush()
	if out != "xy" {
		t.Fatalf("expected malformed block dropped; got %q", out)
	}
	if called {
		t.Fatalf("malformed block should not have dispatched")
	}
}

func TestClaudeCodeBlockParser_UnknownTagPassedThrough(t *testing.T) {
	p := &claudeCodeBlockParser{}
	stream := "x<<<VIG:UNKNOWN>>>payload<<<VIG:END>>>y"
	out := p.Feed(stream) + p.Flush()
	if out != stream {
		t.Fatalf("expected unknown tag preserved; got %q", out)
	}
}

func TestClaudeCodeBlockParser_InvalidFindingJSONIgnored(t *testing.T) {
	called := false
	p := &claudeCodeBlockParser{
		onFinding: func(args map[string]any) { called = true },
	}
	out := p.Feed("x<<<VIG:FINDING>>>not json<<<VIG:END>>>y") + p.Flush()
	if out != "xy" {
		t.Fatalf("expected block consumed; got %q", out)
	}
	if called {
		t.Fatalf("invalid JSON should not have dispatched")
	}
}

func TestClaudeCodeBlockParser_PartialStartHeld(t *testing.T) {
	p := &claudeCodeBlockParser{}
	// First delta ends with a partial sentinel start — must be held.
	out1 := p.Feed("hello <<<V")
	if out1 != "hello " {
		t.Fatalf("expected partial start held; got %q", out1)
	}
	// Second delta completes the start but not the block — still held.
	out2 := p.Feed("IG:HALT>>>r")
	if out2 != "" {
		t.Fatalf("expected pending block held; got %q", out2)
	}
	var halted string
	p.onHalt = func(r string) { halted = r }
	// Final delta closes the block.
	out3 := p.Feed("<<<VIG:END>>>tail") + p.Flush()
	if out3 != "tail" {
		t.Fatalf("expected tail after halt; got %q", out3)
	}
	if halted != "r" {
		t.Fatalf("halt reason wrong: %q", halted)
	}
}

func TestSuffixPrefixOverlap(t *testing.T) {
	cases := []struct {
		s, prefix string
		want      int
	}{
		{"foo<<<V", "<<<VIG:", 4},
		{"foo", "<<<VIG:", 0},
		{"<<<VIG", "<<<VIG:", 6},
		{"abc<<<VIG", "<<<VIG:", 6},
		{"", "<<<VIG:", 0},
		{"<", "<<<VIG:", 1},
	}
	for _, c := range cases {
		if got := suffixPrefixOverlap(c.s, c.prefix); got != c.want {
			t.Errorf("suffixPrefixOverlap(%q,%q) = %d, want %d", c.s, c.prefix, got, c.want)
		}
	}
}
