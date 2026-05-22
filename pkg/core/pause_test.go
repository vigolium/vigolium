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

func TestPauseController_PauseWaitsForActiveWorkers(t *testing.T) {
	p := NewPauseController()

	// A worker holds the read lock; Pause must block until it is released.
	p.AcquireWorker()

	paused := make(chan struct{})
	go func() {
		p.Pause()
		close(paused)
	}()

	select {
	case <-paused:
		t.Fatal("Pause returned while a worker was still active")
	case <-time.After(50 * time.Millisecond):
	}

	p.ReleaseWorker()

	select {
	case <-paused:
	case <-time.After(time.Second):
		t.Fatal("Pause did not return after the worker was released")
	}

	p.Resume()
}
