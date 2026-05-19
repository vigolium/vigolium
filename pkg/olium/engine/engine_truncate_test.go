package engine

import (
	"strings"
	"testing"
)

func TestTruncateToolResult_BelowLimit(t *testing.T) {
	got := truncateToolResult("hello", 100)
	if got != "hello" {
		t.Fatalf("expected pass-through, got %q", got)
	}
}

func TestTruncateToolResult_DisabledMax(t *testing.T) {
	big := strings.Repeat("X", 100_000)
	got := truncateToolResult(big, 0)
	if got != big {
		t.Fatalf("max=0 should be no-op, got len=%d want %d", len(got), len(big))
	}
}

func TestTruncateToolResult_KeepsHeadAndTail(t *testing.T) {
	head := strings.Repeat("H", 5000)
	mid := strings.Repeat("M", 50_000)
	tail := strings.Repeat("T", 5000)
	in := head + mid + tail
	got := truncateToolResult(in, 16*1024)

	if len(got) > 16*1024+128 { // small slack for marker
		t.Fatalf("output exceeds budget: %d", len(got))
	}
	if !strings.HasPrefix(got, "HHHH") {
		t.Fatalf("head missing")
	}
	if !strings.HasSuffix(got, "TTTT") {
		t.Fatalf("tail missing")
	}
	if !strings.Contains(got, "truncated") {
		t.Fatalf("no elision marker in output")
	}
}

func TestTruncateToolResult_TinyBudgetHardTruncates(t *testing.T) {
	in := strings.Repeat("X", 1000)
	got := truncateToolResult(in, 200)
	if len(got) != 200 {
		t.Fatalf("expected hard 200-byte truncation, got %d", len(got))
	}
}
