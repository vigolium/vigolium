package modkit

import (
	"sync"
	"testing"
)

func TestTechRegistry_NilSafe(t *testing.T) {
	var r *TechRegistry
	r.Mark("example.com", "nextjs") // must not panic
	if r.Has("example.com", "nextjs") {
		t.Fatal("nil registry should not report any tech")
	}
	if r.HasAny("example.com", []string{"nextjs"}) {
		t.Fatal("nil registry should not report any tech")
	}
	if r.HostKnown("example.com") {
		t.Fatal("nil registry should report no known hosts")
	}
}

func TestTechRegistry_MarkAndQuery(t *testing.T) {
	r := NewTechRegistry()
	r.Mark("Example.com", " NextJS ")
	r.Mark("example.com", "nodejs")

	if !r.Has("example.com", "nextjs") {
		t.Fatal("expected normalized tag lookup to succeed")
	}
	if !r.HostKnown("EXAMPLE.com") {
		t.Fatal("expected HostKnown to be case-insensitive")
	}
	if !r.HasAny("example.com", []string{"php", "nextjs"}) {
		t.Fatal("HasAny should match one of the candidates")
	}
	if r.HasAny("example.com", []string{"php", "spring"}) {
		t.Fatal("HasAny should return false when no candidate matches")
	}
	if r.Has("other.com", "nextjs") {
		t.Fatal("unknown host should not report any tech")
	}
}

func TestTechRegistry_EmptyInputsAreNoOp(t *testing.T) {
	r := NewTechRegistry()
	r.Mark("", "nextjs")
	r.Mark("example.com", "")
	if r.HostKnown("example.com") {
		t.Fatal("empty inputs must not register a host")
	}
}

func TestTechRegistry_ConcurrentWrites(t *testing.T) {
	r := NewTechRegistry()
	var wg sync.WaitGroup
	tags := []string{"nextjs", "nodejs", "javascript", "react"}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r.Mark("example.com", tags[idx%len(tags)])
		}(i)
	}
	wg.Wait()
	for _, tag := range tags {
		if !r.Has("example.com", tag) {
			t.Fatalf("expected %q to be marked under concurrent writes", tag)
		}
	}
}
