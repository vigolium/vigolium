package core

import (
	"context"
	"sync"
	"sync/atomic"
)

// PauseController provides cooperative pause/resume for worker goroutines.
// Workers call WaitIfPaused between items; Pause blocks until all active
// items finish, then holds future workers until Resume is called.
type PauseController struct {
	mu       sync.RWMutex
	paused   atomic.Bool
	pausedCh chan struct{} // closed when paused, reopened on resume
}

// NewPauseController creates a new PauseController in the unpaused state.
func NewPauseController() *PauseController {
	return &PauseController{}
}

// Pause blocks new workers and waits for in-flight items to finish.
// Safe to call multiple times (idempotent).
func (p *PauseController) Pause() {
	if p.paused.Load() {
		return
	}
	p.paused.Store(true)
	p.pausedCh = make(chan struct{})
	// Acquire write lock — blocks until all RLocks (active workers) release
	p.mu.Lock()
}

// Resume unblocks paused workers. Safe to call when not paused.
func (p *PauseController) Resume() {
	if !p.paused.CompareAndSwap(true, false) {
		return
	}
	close(p.pausedCh)
	p.mu.Unlock()
}

// IsPaused returns the current pause state.
func (p *PauseController) IsPaused() bool {
	return p.paused.Load()
}

// WaitIfPaused blocks the caller if the controller is paused.
// Returns false if the context is cancelled while waiting.
// Workers should call this between processing items.
func (p *PauseController) WaitIfPaused(ctx context.Context) bool {
	if !p.paused.Load() {
		return true
	}
	// Wait for resume or context cancellation
	select {
	case <-ctx.Done():
		return false
	case <-p.pausedCh:
		return true
	}
}

// AcquireWorker acquires a read lock for the duration of item processing.
// Call ReleaseWorker when done. Returns false if paused (caller should
// call WaitIfPaused first).
func (p *PauseController) AcquireWorker() {
	p.mu.RLock()
}

// ReleaseWorker releases the read lock after item processing.
func (p *PauseController) ReleaseWorker() {
	p.mu.RUnlock()
}
