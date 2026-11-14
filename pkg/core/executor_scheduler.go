package core

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

// activeScheduler admits detached active-module tasks under two caps: a global
// one (G, the old active-task semaphore size) and a per-host one read from the
// host limiter's current verdict. Tasks queue per host in FIFO order and are
// admitted round-robin across hosts, one per host per turn.
//
// A task only takes a global slot once its own host has room, so a saturated
// host keeps its backlog in its queue, holding nothing. (A plain global
// semaphore taken BEFORE the host gate would let a slow or paced host hold
// every global slot with tasks merely waiting for that host's gate, starving
// every other host behind it.)
//
// There is no dedicated admission goroutine. Admission is a "pump" run by
// whoever changes the scheduler's state: enqueue (a task arrives), release (a
// task finishes), resume (pause lifted), and a context watcher Execute registers
// (cancellation drains the queues). That keeps the scheduler free of a lifecycle
// of its own — nothing to start, nothing to leak when an executor is dropped.
type activeScheduler struct {
	mu sync.Mutex

	// global is G. lowMemory halves it while the memory guardian reports
	// pressure.
	global    int
	lowMemory func() bool
	// capFor is the per-host task cap. Never returns < 1.
	capFor func(host string) int
	// pause, when non-nil, holds admission while paused. Queued tasks stay
	// queued; running ones are untouched.
	pause *PauseController

	queues         map[string]*taskQueue
	ring           []string // hosts with a non-empty queue, round-robin order
	next           int      // ring index the next pump starts from
	running        int
	runningPerHost map[string]int
	// pumps counts pumpLocked runs; a queue's cached host cap is valid for
	// the pump that computed it (taskQueue.capPump).
	pumps uint64

	// resumeWaiter is true while a goroutine waits on the pause controller to
	// re-pump after resume.
	resumeWaiter bool
}

// schedTask is one queued active-module task.
type schedTask struct {
	ctx  context.Context
	host string
	// run starts the admitted task; it must eventually call release (once is
	// enough: further calls are no-ops).
	run func(release func())
	// drop finalises a task that will never run (its context was cancelled
	// while it was queued): it releases the item reference and taskWG.
	drop func()

	sched    *activeScheduler
	released atomic.Bool
}

// release frees the task's running slot. Idempotent, so a stray double call
// can never over-drain the caps.
func (t *schedTask) release() {
	if t.released.CompareAndSwap(false, true) {
		t.sched.release(t.host)
	}
}

type taskQueue struct {
	tasks []*schedTask
	head  int
	// cap / capPump cache the host's cap for one pump (see pumpLocked).
	cap     int
	capPump uint64
}

func (q *taskQueue) len() int { return len(q.tasks) - q.head }

func (q *taskQueue) push(t *schedTask) { q.tasks = append(q.tasks, t) }

func (q *taskQueue) pop() *schedTask {
	t := q.tasks[q.head]
	q.tasks[q.head] = nil
	q.head++
	if q.head == len(q.tasks) {
		q.tasks = q.tasks[:0]
		q.head = 0
	} else if q.head > 64 && q.head*2 > len(q.tasks) {
		n := copy(q.tasks, q.tasks[q.head:])
		clear(q.tasks[n:])
		q.tasks = q.tasks[:n]
		q.head = 0
	}
	return t
}

func newActiveScheduler(global int, capFor func(string) int) *activeScheduler {
	if global < 1 {
		global = 1
	}
	return &activeScheduler{
		global:         global,
		lowMemory:      network.IsLowOnMemory,
		capFor:         capFor,
		queues:         make(map[string]*taskQueue),
		runningPerHost: make(map[string]int),
	}
}

// effectiveGlobal is G, halved under memory pressure.
func (s *activeScheduler) effectiveGlobal() int {
	g := s.global
	if s.lowMemory != nil && s.lowMemory() {
		g /= 2
		if g < 1 {
			g = 1
		}
	}
	return g
}

func (s *activeScheduler) hostCap(host string) int {
	c := 0
	if s.capFor != nil {
		c = s.capFor(host)
	}
	if c < 1 {
		c = 1
	}
	return c
}

// enqueue adds a task to its host's queue and pumps. Never blocks.
//
// Fast path: a live task whose host has nothing queued, under both caps and
// not paused, is admitted at once without the round-robin walk. Any other
// host's queued task is waiting on its own cap or G, which this admission
// does not loosen; a cap that has since grown is picked up by the next pump
// (every admitted task's release pumps).
func (s *activeScheduler) enqueue(t *schedTask) {
	t.sched = s
	s.mu.Lock()
	q := s.queues[t.host]
	if (q == nil || q.len() == 0) && t.ctx.Err() == nil && !s.pausedLocked() &&
		s.running < s.effectiveGlobal() && s.runningPerHost[t.host] < s.hostCap(t.host) {
		s.running++
		s.runningPerHost[t.host]++
		s.mu.Unlock()
		t.run(t.release)
		return
	}
	if q == nil {
		q = &taskQueue{}
		s.queues[t.host] = q
	}
	if q.len() == 0 {
		s.ring = append(s.ring, t.host)
	}
	q.push(t)
	start, dropped := s.pumpLocked()
	s.mu.Unlock()
	s.finish(start, dropped)
}

func (s *activeScheduler) pausedLocked() bool { return s.pause != nil && s.pause.IsPaused() }

// release frees one running slot of host and pumps.
func (s *activeScheduler) release(host string) {
	s.mu.Lock()
	s.running--
	if n := s.runningPerHost[host] - 1; n > 0 {
		s.runningPerHost[host] = n
	} else {
		delete(s.runningPerHost, host)
	}
	start, dropped := s.pumpLocked()
	s.mu.Unlock()
	s.finish(start, dropped)
}

// pump re-runs admission (after resume, or when a context is cancelled).
func (s *activeScheduler) pump() {
	s.mu.Lock()
	start, dropped := s.pumpLocked()
	s.mu.Unlock()
	s.finish(start, dropped)
}

// finish starts admitted tasks and finalises dropped ones, outside the lock.
func (s *activeScheduler) finish(start, dropped []*schedTask) {
	for _, t := range dropped {
		t.drop()
	}
	for _, t := range start {
		t.run(t.release)
	}
}

// pumpLocked admits as many queued tasks as the caps allow, one per host per
// round-robin turn, and collects queued tasks whose context is already
// cancelled. Caller holds s.mu.
func (s *activeScheduler) pumpLocked() (start, dropped []*schedTask) {
	if s.pausedLocked() {
		// Admission waits on the pause; cancelled tasks are still dropped so a
		// stop during a pause never waits on them.
		dropped = s.dropCancelledLocked()
		s.armResumeWaiterLocked()
		return nil, dropped
	}
	g := s.effectiveGlobal()
	s.pumps++
	idle := 0 // consecutive hosts visited without an admission
	for len(s.ring) > 0 && idle < len(s.ring) {
		if s.next >= len(s.ring) {
			s.next = 0
		}
		host := s.ring[s.next]
		q := s.queues[host]
		// Drop cancelled heads first: they cost no slot.
		for q.len() > 0 && q.tasks[q.head].ctx.Err() != nil {
			dropped = append(dropped, q.pop())
		}
		if q.len() == 0 {
			s.removeFromRingLocked(s.next)
			idle = 0
			continue
		}
		if s.running >= g {
			break
		}
		if q.capPump != s.pumps {
			q.cap, q.capPump = s.hostCap(host), s.pumps
		}
		if s.runningPerHost[host] >= q.cap {
			s.next++
			idle++
			continue
		}
		t := q.pop()
		s.running++
		s.runningPerHost[host]++
		start = append(start, t)
		idle = 0
		if q.len() == 0 {
			s.removeFromRingLocked(s.next)
			continue
		}
		s.next++
	}
	return start, dropped
}

func (s *activeScheduler) removeFromRingLocked(i int) {
	host := s.ring[i]
	delete(s.queues, host)
	s.ring = append(s.ring[:i], s.ring[i+1:]...)
	if s.next > i {
		s.next--
	}
}

// dropCancelledLocked removes every queued task whose context is cancelled.
func (s *activeScheduler) dropCancelledLocked() (dropped []*schedTask) {
	for i := 0; i < len(s.ring); {
		host := s.ring[i]
		q := s.queues[host]
		kept := q.tasks[:0]
		for _, t := range q.tasks[q.head:] {
			if t.ctx.Err() != nil {
				dropped = append(dropped, t)
			} else {
				kept = append(kept, t)
			}
		}
		clear(q.tasks[len(kept):])
		q.tasks, q.head = kept, 0
		if q.len() == 0 {
			s.removeFromRingLocked(i)
			continue
		}
		i++
	}
	return dropped
}

// armResumeWaiterLocked starts (once) a goroutine that re-pumps when the pause
// is lifted, or exits when the queued tasks' context ends.
func (s *activeScheduler) armResumeWaiterLocked() {
	if s.resumeWaiter || len(s.ring) == 0 {
		return
	}
	ctx := s.queues[s.ring[0]].tasks[s.queues[s.ring[0]].head].ctx
	s.resumeWaiter = true
	go func() {
		s.pause.WaitIfPaused(ctx)
		s.mu.Lock()
		s.resumeWaiter = false
		s.mu.Unlock()
		s.pump()
	}()
}

// backlog reports queued + running tasks for host.
func (s *activeScheduler) backlog(host string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.runningPerHost[host]
	if q := s.queues[host]; q != nil {
		n += q.len()
	}
	return n
}

// overloaded reports whether host's backlog exceeds factor × its cap — the
// item-fairness threshold at which a worker parks new items for that host.
func (s *activeScheduler) overloaded(host string, factor int) bool {
	if host == "" {
		return false
	}
	return s.backlog(host) > factor*s.hostCap(host)
}

// stats returns (running, queued) for tests and status.
func (s *activeScheduler) stats() (running, queued int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, q := range s.queues {
		queued += q.len()
	}
	return s.running, queued
}

// schedHostKey is the scheduler's per-host key: host:port, the same identity
// the egress gate and host limiter use (egress.HostPort).
func schedHostKey(item *httpmsg.HttpRequestResponse) string {
	if item == nil {
		return ""
	}
	if svc := item.Service(); svc != nil && svc.Host() != "" {
		return net.JoinHostPort(svc.Host(), strconv.Itoa(svc.Port()))
	}
	if u, err := item.URL(); err == nil && u != nil && u.Hostname() != "" {
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		return net.JoinHostPort(u.Hostname(), port)
	}
	return ""
}

// itemFairnessFactor: a worker parks a newly dequeued item whose host already
// has more than this many × its cap tasks queued or running.
const itemFairnessFactor = 4

// maxDeferredItems bounds the parked-item list; past it, items dispatch
// normally (their tasks just queue).
const maxDeferredItems = 1024

// drainCancelled drops every queued task whose context is cancelled, then
// pumps. Execute registers it on its context so a cancelled phase never waits
// on queued tasks that running (possibly stuck) tasks would otherwise have to
// release first.
func (s *activeScheduler) drainCancelled() {
	s.mu.Lock()
	dropped := s.dropCancelledLocked()
	start, more := s.pumpLocked()
	s.mu.Unlock()
	s.finish(start, append(dropped, more...))
}

// hostTaskCapFunc returns the per-host task cap source: the configured
// override, else the host limiter's current verdict for host:port (its ceiling
// while the host is still untracked), else no per-host cap beyond G.
func (e *Executor) hostTaskCapFunc(global int) func(string) int {
	if e.cfg.HostTaskCap != nil {
		return e.cfg.HostTaskCap
	}
	if e.cfg.Services == nil || e.cfg.Services.HostLimiter == nil {
		return func(string) int { return global }
	}
	hl := e.cfg.Services.HostLimiter
	return func(host string) int {
		if limit, _ := hl.CurrentLimit(host); limit > 0 {
			return limit
		}
		if c := hl.CeilingPerHost(); c > 0 {
			return c
		}
		return global
	}
}

// deferredItems is the bounded parked-item list (item fairness).
type deferredItems struct {
	mu    sync.Mutex
	items []deferredItem
}

// deferredItem is a parked item and its scheduler host key.
type deferredItem struct {
	item *work.WorkItem
	host string
}

func (d *deferredItems) park(item *work.WorkItem, host string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.items) >= maxDeferredItems {
		return false
	}
	d.items = append(d.items, deferredItem{item, host})
	return true
}

func (d *deferredItems) len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.items)
}

// takeReady removes and returns the parked items whose host is no longer
// overloaded (all of them when force is set).
func (d *deferredItems) takeReady(overloaded func(host string) bool, force bool) []*work.WorkItem {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.items) == 0 {
		return nil
	}
	var ready []*work.WorkItem
	kept := d.items[:0]
	for _, it := range d.items {
		if force || !overloaded(it.host) {
			ready = append(ready, it.item)
			continue
		}
		kept = append(kept, it)
	}
	clear(d.items[len(kept):])
	d.items = kept
	return ready
}

// parkIfOverloaded parks item when its host already has more than
// itemFairnessFactor × cap tasks queued or running. Returns true if parked.
func (e *Executor) parkIfOverloaded(item *work.WorkItem) bool {
	if item == nil || item.Request == nil {
		return false
	}
	host := schedHostKey(item.Request)
	if !e.pool.sched.overloaded(host, itemFairnessFactor) {
		return false
	}
	return e.pool.deferred.park(item, host)
}

// requeueDeferred sends parked items whose host has drained back to itemCh.
// force sends every parked item (no host left to wait for). Returns false if
// ctx was cancelled mid-send; the unsent items are counted unacked.
func (e *Executor) requeueDeferred(ctx context.Context, itemCh chan<- *work.WorkItem, force bool) bool {
	// Many parked items share a host: ask the scheduler once per host.
	var seen map[string]bool
	ready := e.pool.deferred.takeReady(func(h string) bool {
		over, ok := seen[h]
		if !ok {
			over = e.pool.sched.overloaded(h, itemFairnessFactor)
			if seen == nil {
				seen = make(map[string]bool)
			}
			seen[h] = over
		}
		return over
	}, force)
	for i, it := range ready {
		select {
		case <-ctx.Done():
			e.unacked.Add(int64(len(ready) - i))
			return false
		case itemCh <- it:
		}
	}
	return true
}
