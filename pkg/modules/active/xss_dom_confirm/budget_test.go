package xss_dom_confirm

import (
	"context"
	"testing"
	"time"
)

func TestBudgetGlobalCap(t *testing.T) {
	b := NewBudget(2, 3)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	releases := make([]func(), 0, 3)
	for i := 0; i < 3; i++ {
		// host-A and host-B mixed so per-host doesn't kick in
		host := "a"
		if i%2 == 0 {
			host = "b"
		}
		release, ok := b.Reserve(ctx, host)
		if !ok {
			t.Fatalf("reserve %d: unexpected !ok", i)
		}
		releases = append(releases, release)
	}

	// Fourth call must fail — global cap exhausted.
	if _, ok := b.Reserve(ctx, "c"); ok {
		t.Fatalf("expected fourth reserve to fail (global cap)")
	}

	// Release one and we should be able to reserve again.
	releases[0]()
	if release, ok := b.Reserve(ctx, "c"); !ok {
		t.Fatalf("expected reserve after release to succeed")
	} else {
		release()
	}

	for _, r := range releases[1:] {
		r()
	}
}

func TestBudgetPerHostBlocks(t *testing.T) {
	b := NewBudget(1, 10) // perHost=1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rel1, ok := b.Reserve(ctx, "host-x")
	if !ok {
		t.Fatalf("first reserve failed")
	}

	// Second call to same host should block until ctx times out.
	tightCtx, tightCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer tightCancel()
	if _, ok := b.Reserve(tightCtx, "host-x"); ok {
		t.Fatalf("expected second per-host reserve to time out")
	}

	// Different host still works concurrently.
	rel2, ok := b.Reserve(ctx, "host-y")
	if !ok {
		t.Fatalf("reserve on different host failed")
	}

	rel1()
	rel2()
}

func TestBudgetNilSafe(t *testing.T) {
	var b *Budget
	release, ok := b.Reserve(context.Background(), "h")
	if !ok {
		t.Fatalf("nil budget should be permissive")
	}
	release()
}
