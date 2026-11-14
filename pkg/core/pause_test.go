package core

import (
	"context"
	"testing"
	"time"
)

func TestPauseController_InitialState(t *testing.T) {
	p := NewPauseController()
	if p.IsPaused() {
		t.Fatal("new controller should not be paused")
	}
	if !p.WaitIfPaused(context.Background()) {
		t.Fatal("WaitIfPaused should return true immediately when not paused")
	}
}

func TestPauseController_PauseResume(t *testing.T) {
	p := NewPauseController()

	p.Pause()
	if !p.IsPaused() {
		t.Fatal("expected paused after Pause()")
	}

	p.Resume()
	if p.IsPaused() {
		t.Fatal("expected not paused after Resume()")
	}
}

func TestPauseController_PauseIdempotent(t *testing.T) {
	p := NewPauseController()

	// Second Pause must short-circuit rather than re-acquiring the write lock
	// (which would deadlock). A single Resume then fully unpauses.
	p.Pause()
	p.Pause()
	if !p.IsPaused() {
		t.Fatal("expected paused")
	}

	p.Resume()
	if p.IsPaused() {
		t.Fatal("single Resume should clear the paused state")
	}
}

func TestPauseController_ResumeWhenNotPaused(t *testing.T) {
	p := NewPauseController()
	// Must be a safe no-op (CompareAndSwap fails, no unlock of an unheld lock).
	p.Resume()
	if p.IsPaused() {
		t.Fatal("Resume on an unpaused controller should be a no-op")
	}
}

func TestPauseController_WaitIfPausedBlocksUntilResume(t *testing.T) {
	p := NewPauseController()
	p.Pause()

	done := make(chan bool, 1)
	go func() { done <- p.WaitIfPaused(context.Background()) }()

	select {
	case <-done:
		t.Fatal("WaitIfPaused returned while still paused")
	case <-time.After(50 * time.Millisecond):
	}

	p.Resume()

	select {
	case got := <-done:
		if !got {
			t.Fatal("WaitIfPaused should return true after Resume")
		}
	case <-time.After(time.Second):
		t.Fatal("WaitIfPaused did not unblock after Resume")
	}
}

func TestPauseController_WaitIfPausedContextCancel(t *testing.T) {
	p := NewPauseController()
	p.Pause()
	defer p.Resume()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if p.WaitIfPaused(ctx) {
		t.Fatal("WaitIfPaused should return false when context is cancelled")
	}
}

func TestPauseController_PauseReturnsWithStuckWorker(t *testing.T) {
	p := NewPauseController()

	// A worker is mid-dispatch and stays there. Pause must still return at
	// once (MISS-39); only Quiesced waits for the worker.
	p.AcquireWorker()

	start := time.Now()
	p.Pause()
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("Pause took %s with a stuck worker; must not block", d)
	}
	if !p.IsPaused() {
		t.Fatal("expected paused")
	}
	if p.Quiesced() {
		t.Fatal("Quiesced while a worker is still mid-dispatch")
	}
	qc := p.QuiescedCh()

	// Resume and a second Pause must not block either.
	done := make(chan struct{})
	go func() {
		p.Resume()
		p.Pause()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Resume/Pause blocked behind a stuck worker")
	}
	qc = p.QuiescedCh()

	p.ReleaseWorker()
	select {
	case <-qc:
	case <-time.After(time.Second):
		t.Fatal("quiesced channel not closed after the last worker released")
	}
	if !p.Quiesced() {
		t.Fatal("expected Quiesced after the worker released")
	}
	p.Resume()
	if p.Quiesced() {
		t.Fatal("Quiesced must be false when not paused")
	}
}
