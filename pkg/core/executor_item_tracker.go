package core

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/work"
)

// itemTracker owns one work item from the end of its dispatch phase until its
// last active-module task finishes. It is what lets a worker hand an item's
// slow tasks off and go back to the queue instead of pinning itself in a
// per-item Wait (head-of-line blocking: one 2-minute module task used to stop
// that worker from fetching any other baseline).
//
// Ownership: the worker owns the item, its pooled response buffer and the
// buffer guard while it fetches, runs the passive stage and dispatches the
// active tasks. From then on the tracker owns them. Every dispatched task holds
// a reference (pending), and so does the dispatcher until it calls done();
// whichever goroutine drops the last reference runs complete(), exactly once.
//
// complete() is the only place an item is finished: the pooled buffer goes
// back to the pool (unless an abandoned module call may still read it), the
// item is acknowledged (or counted unacked on a cancelled phase), Processed()
// advances, inFlight drops and the item's outstanding slot is released.
type itemTracker struct {
	e    *Executor
	ctx  context.Context
	item *work.WorkItem

	// pooledBuf is the baseline response buffer, set by the worker after the
	// fetch. guard records whether an abandoned module call may still read it.
	pooledBuf []byte
	guard     responseBufferGuard
	// releaseBuf hands pooledBuf back (putResponseBuffer); a field so tests can
	// observe exactly when the buffer is returned.
	releaseBuf func([]byte)

	// pending counts outstanding references: one per running task plus the
	// dispatcher's own, which keeps the item open until dispatch is over.
	pending atomic.Int32
	// panicked forces the ack: a poison item that is never acknowledged is
	// re-served on every later run and freezes the durable cursor behind it.
	panicked atomic.Bool
	once     sync.Once
	// holdsSlot is true when the item was dequeued under an outstanding-item
	// slot (the worker path) that complete() must give back.
	holdsSlot bool
	// finished is closed by complete(); processItem waits on it.
	finished chan struct{}
	// prog is the item's coverage-ledger bookkeeping (nil without a ledger).
	prog *itemProgress
}

// newItemTracker opens an item: it counts the item in flight and returns a
// tracker holding the dispatcher's reference. The returned tracker's ctx carries
// the response-buffer guard, so tasks dispatched under it can flag the buffer as
// escaped.
func (e *Executor) newItemTracker(ctx context.Context, item *work.WorkItem, holdsSlot bool) *itemTracker {
	t := &itemTracker{
		e:          e,
		item:       item,
		releaseBuf: putResponseBuffer,
		holdsSlot:  holdsSlot,
		finished:   make(chan struct{}),
	}
	t.ctx = withResponseBufferGuard(ctx, &t.guard)
	if e.cfg.Ledger != nil && item != nil && item.RecordUUID != "" {
		t.prog = newItemProgress()
	}
	t.pending.Store(1)
	e.pool.inFlight.Add(1)
	return t
}

// acquire adds a reference for a task about to start.
func (t *itemTracker) acquire() { t.pending.Add(1) }

// done drops one reference; the last one completes the item.
func (t *itemTracker) done() {
	if t.pending.Add(-1) == 0 {
		t.complete()
	}
}

func (t *itemTracker) complete() {
	t.once.Do(func() {
		e := t.e
		if t.pooledBuf != nil && !t.guard.escaped.Load() {
			t.releaseBuf(t.pooledBuf)
		}
		t.pooledBuf = nil
		e.writeProgress(t)
		e.finishItem(t.ctx, t.item, t.panicked.Load())
		if e.statsTracker != nil {
			e.statsTracker.Increment()
		}
		e.pool.inFlight.Add(-1)
		if t.holdsSlot {
			<-e.pool.itemSlots
		}
		close(t.finished)
	})
}
