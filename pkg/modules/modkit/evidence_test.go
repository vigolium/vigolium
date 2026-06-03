package modkit

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/output"
)

func TestEvidenceCollector_NilSafe(t *testing.T) {
	var c *EvidenceCollector // nil
	// None of these may panic on a nil collector.
	c.Add("baseline", "req", "resp")
	if got := c.Entries(); got != nil {
		t.Fatalf("nil collector Entries() = %v, want nil", got)
	}
	if got := c.Len(); got != 0 {
		t.Fatalf("nil collector Len() = %d, want 0", got)
	}
}

func TestEvidenceCollector_AddAndEntries(t *testing.T) {
	c := NewEvidenceCollector()
	c.Add("baseline", "GET / HTTP/1.1", "HTTP/1.1 403 Forbidden")
	c.Add("attack", "GET /admin HTTP/1.1", "HTTP/1.1 200 OK")

	entries := c.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if c.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", c.Len())
	}
	if !strings.HasPrefix(entries[0], "# [baseline]\n") {
		t.Fatalf("entry 0 missing baseline marker: %q", entries[0])
	}
	if !strings.HasPrefix(entries[1], "# [attack]\n") {
		t.Fatalf("entry 1 missing attack marker: %q", entries[1])
	}
	if !strings.Contains(entries[0], output.EvidenceSeparator) {
		t.Fatalf("entry 0 missing separator: %q", entries[0])
	}
}

func TestEvidenceCollector_IgnoresEmptyPairs(t *testing.T) {
	c := NewEvidenceCollector()
	c.Add("baseline", "", "") // empty pair — must be ignored
	c.Add("attack", "req", "resp")
	if c.Len() != 1 {
		t.Fatalf("expected empty pair to be ignored, Len() = %d", c.Len())
	}
}

func TestEvidenceCollector_CapsAtMax(t *testing.T) {
	c := NewEvidenceCollector()
	for i := 0; i < MaxEvidencePairs+5; i++ {
		c.Add("confirm", "req", "resp")
	}
	if c.Len() != MaxEvidencePairs {
		t.Fatalf("expected cap at %d, got %d", MaxEvidencePairs, c.Len())
	}
	if got := len(c.Entries()); got != MaxEvidencePairs {
		t.Fatalf("Entries() length = %d, want %d", got, MaxEvidencePairs)
	}
}

func TestEvidenceCollector_EntriesIsCopy(t *testing.T) {
	c := NewEvidenceCollector()
	c.Add("baseline", "req", "resp")
	entries := c.Entries()
	entries[0] = "mutated"
	// Mutating the returned slice must not affect the collector's internal state.
	if again := c.Entries(); again[0] == "mutated" {
		t.Fatalf("Entries() returned a live reference, not a copy")
	}
}
