package core

import (
	"context"
	"sync"
	"sync/atomic"
)

// PauseController provides cooperative pause/resume for workers and the
// active-task scheduler.
//
// Pause never blocks: it flips the paused flag and returns. From then on
// workers stop dequeuing (WaitIfPaused between items) and the active-task
// scheduler stops admitting queued tasks. A worker that is mid-dispatch
// finishes its current item; Quiesced reports true once no worker is
// mid-dispatch, which is when a status display should say "paused" rather than
// "pausing". Tasks the scheduler already admitted run to completion — they may
// still send probe traffic, emit findings and acknowledge their item after
// Pause returns.
//
// It used to make Pause wait on an RWMutex every worker held across a whole
// item's dispatch. The server handler called it while holding the server-wide
// scan lock, so one stuck dispatch hung stop and status for every project
// (MISS-39).
//
// stateMu serializes the Pause/Resume transitions and guards the channels, so
// concurrent Pause+Resume — reachable, e.g. a stop-triggered Runner.Close
// resuming while an API pause request is in flight — can never close a nil or
// already-closed channel or leave pausedCh stale relative to the paused flag.
type PauseController struct {
	stateMu    sync.Mutex    // serializes Pause/Resume transitions and guards the channels
	paused     atomic.Bool   // fast-path snapshot for WaitIfPaused/IsPaused
	pausedCh   chan struct{} // non-nil and open while paused; closed on resume
	quiescedCh chan struct{} // non-nil while paused; closed once inDispatch reaches 0
	inDispatch atomic.Int64  // workers currently mid-dispatch
}

// NewPauseController creates a new PauseController in the unpaused state.
func NewPauseController() *PauseController {
	return &PauseController{}
}

// Pause stops new dispatch and admission and returns at once. Safe to call
// multiple times (idempotent) and concurrently with Resume.
func (p *PauseController) Pause() {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.paused.Load() {
		return
	}
	// Create the channels BEFORE flipping the flag so a reader that observes
	// paused==true always sees fresh, open channels.
	p.pausedCh = make(chan struct{})
	p.quiescedCh = make(chan struct{})
	p.paused.Store(true)
	if p.inDispatch.Load() == 0 {
		close(p.quiescedCh)
	}
}

// Resume unblocks paused workers and admission. Safe to call when not paused
// and concurrently with Pause.
func (p *PauseController) Resume() {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if !p.paused.CompareAndSwap(true, false) {
		return
	}
	close(p.pausedCh)
}

// IsPaused returns the current pause state.
func (p *PauseController) IsPaused() bool {
	return p.paused.Load()
}

// Quiesced reports whether the controller is paused AND no worker is still
// mid-dispatch.
func (p *PauseController) Quiesced() bool {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if !p.paused.Load() || p.quiescedCh == nil {
		return false
	}
	select {
	case <-p.quiescedCh:
		return true
	default:
		return false
	}
}

// QuiescedCh returns a channel closed once the current pause is quiesced, or
// nil when not paused.
func (p *PauseController) QuiescedCh() <-chan struct{} {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if !p.paused.Load() {
		return nil
	}
	return p.quiescedCh
}

// WaitIfPaused blocks the caller if the controller is paused.
// Returns false if the context is cancelled while waiting.
// Workers should call this between processing items.
func (p *PauseController) WaitIfPaused(ctx context.Context) bool {
	if !p.paused.Load() {
		return true
	}
	// Read a consistent (paused, channel) snapshot under stateMu so we never
	// select on a nil or stale channel raced in by a concurrent Pause/Resume.
	p.stateMu.Lock()
	paused := p.paused.Load()
	ch := p.pausedCh
	p.stateMu.Unlock()
	if !paused || ch == nil {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-ch:
		return true
	}
}

// AcquireWorker marks a worker as mid-dispatch (fetch, passive stage, task
// dispatch). Never blocks. Call ReleaseWorker when done.
func (p *PauseController) AcquireWorker() {
	p.inDispatch.Add(1)
}

// ReleaseWorker ends a worker's dispatch; the last one out of a pause closes
// the quiesced channel.
func (p *PauseController) ReleaseWorker() {
	if p.inDispatch.Add(-1) != 0 || !p.paused.Load() {
		return
	}
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	if p.paused.Load() && p.quiescedCh != nil && p.inDispatch.Load() == 0 {
		select {
		case <-p.quiescedCh:
		default:
			close(p.quiescedCh)
		}
	}
}
