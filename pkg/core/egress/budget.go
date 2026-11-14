package egress

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A request budget caps how many wire attempts a scan may send: --max-requests
// for the whole scan, --max-requests-per-host for each target host.
//
// It is enforced in two strengths, and the difference is reported rather than
// hidden (Inventory / RequestCapEnforcement):
//
//   - HARD, inside Gate.Acquire: an attempt that would go over a limit is
//     refused before a rate token, a host slot or a dial is spent on it. Every
//     gated path (the shared requester, discovery, logins, the port-sweep
//     confirm step, the TLS modules) is held exactly to the number.
//   - SOFT, for engines that bypass the gate but count what they send (the
//     browser crawl): their counters are registered with Track and sampled by
//     Watch every WatchInterval. Once gated plus sampled traffic passes the
//     scan-wide limit the global hook fires and the scan is stopped, so the
//     overshoot is at most what those engines send in one interval. Per-host
//     limits are not applied to soft traffic.
//
// Traffic that is neither gated nor counted (nuclei, own-dialer modules) is
// outside the budget entirely.

// WatchInterval is how often Watch samples the soft (tracked) counters.
const WatchInterval = 500 * time.Millisecond

// BudgetKind says which limit refused an attempt.
type BudgetKind string

const (
	// BudgetGlobal is the scan-wide --max-requests limit.
	BudgetGlobal BudgetKind = "global"
	// BudgetHost is the per-host --max-requests-per-host limit.
	BudgetHost BudgetKind = "host"
	// BudgetPhase is a phase's share of --max-requests (Budget.LimitPhase);
	// Host carries the phase name. It ends the phase's sends, not the scan.
	BudgetPhase BudgetKind = "phase"
)

// ErrBudgetExhausted matches (errors.Is) every *BudgetError.
var ErrBudgetExhausted = errors.New("request budget exhausted")

// BudgetError is returned by Gate.Acquire (and Do, Token) for an attempt the
// request budget refused. Nothing was sent. It is also the cancel cause of a
// scan stopped by the scan-wide limit (see BudgetCause).
type BudgetError struct {
	Kind  BudgetKind
	Host  string // BudgetHost: the host; BudgetPhase: the phase
	Limit int64
}

func (e *BudgetError) Error() string {
	if e.Kind == BudgetHost {
		return fmt.Sprintf("request budget exhausted: host %s used its %d requests (--max-requests-per-host)", e.Host, e.Limit)
	}
	if e.Kind == BudgetPhase {
		return fmt.Sprintf("phase request share exhausted: %s may use requests up to %d of the scan's --max-requests (the rest is reserved for later phases)", e.Host, e.Limit)
	}
	return fmt.Sprintf("request budget exhausted: the scan used its %d requests (--max-requests)", e.Limit)
}

// Is makes errors.Is(err, ErrBudgetExhausted) true for any BudgetError.
func (e *BudgetError) Is(target error) bool { return target == ErrBudgetExhausted }

// Retryable is always false: nothing was sent, and a retry would be refused too.
func (e *BudgetError) Retryable() bool { return false }

// BudgetCause returns the scan-wide budget error ctx was cancelled with, or nil
// when ctx is live or ended for any other reason. Children of the cancelled
// context report the same cause, so a phase context answers it too.
func BudgetCause(ctx context.Context) *BudgetError {
	if ctx == nil || ctx.Err() == nil {
		return nil
	}
	var be *BudgetError
	if errors.As(context.Cause(ctx), &be) {
		return be
	}
	return nil
}

// BudgetHooks are called when a limit is first exhausted. Both run on the
// goroutine whose attempt was refused (or on the watcher), so they must be
// cheap and must not call back into the budget's gate.
type BudgetHooks struct {
	// Global runs once, the first time the scan-wide limit refuses an attempt
	// or the watcher sees tracked traffic pass it.
	Global func(*BudgetError)
	// Host runs once per host, the first time that host's limit refuses one.
	Host func(host string)
}

// Budget is a scan's request budget. A nil *Budget is valid and unlimited.
// Shared by every view of the gate it is attached to (Gate.WithBudget).
type Budget struct {
	max     int64
	perHost int64

	// used counts admitted gated attempts (plus Count'ed dials).
	used atomic.Int64
	// external is the latest sample of the tracked (soft) counters.
	external atomic.Int64

	hosts          sync.Map // lower-cased host → *atomic.Int64
	exhaustedHosts sync.Map // lower-cased host → struct{}

	globalHit  atomic.Bool
	globalOnce sync.Once

	// phaseLimit, when > 0, is the scan-wide count the running phase may not
	// pass (LimitPhase) — a share of --max-requests, so discovery wordlists
	// cannot spend the whole budget before the assessment runs (ECON-5).
	// Refusing at it ends only the phase's sends; the scan carries on.
	phaseLimit atomic.Int64
	phaseName  atomic.Pointer[string]

	hooks atomic.Pointer[BudgetHooks]

	mu sync.Mutex
	// tracked are the soft counters registered with Track. Append-only: an
	// engine that finished keeps its final count, which still counts.
	tracked []trackedCounter
}

type trackedCounter struct {
	read func() int64
	base int64
}

// NewBudget returns a budget of maxRequests for the scan and perHost for each
// host (0 = that limit is off). It returns nil when both are off.
func NewBudget(maxRequests, perHost int64) *Budget {
	if maxRequests <= 0 && perHost <= 0 {
		return nil
	}
	return &Budget{max: max(maxRequests, 0), perHost: max(perHost, 0)}
}

// SetHooks installs the exhaustion callbacks. Call before traffic starts.
func (b *Budget) SetHooks(h BudgetHooks) {
	if b == nil {
		return
	}
	b.hooks.Store(&h)
}

// Used is the number of attempts counted against the scan-wide limit: gated
// attempts plus the last sample of the tracked counters.
func (b *Budget) Used() int64 {
	if b == nil {
		return 0
	}
	return b.used.Load() + b.external.Load()
}

// Exhausted reports whether the scan-wide limit has refused an attempt (or
// tracked traffic went past it).
func (b *Budget) Exhausted() bool {
	return b != nil && b.globalHit.Load()
}

// ExhaustedHosts lists, sorted, the hosts whose per-host limit refused an
// attempt.
func (b *Budget) ExhaustedHosts() []string {
	if b == nil {
		return nil
	}
	var out []string
	b.exhaustedHosts.Range(func(k, _ any) bool {
		out = append(out, k.(string))
		return true
	})
	sort.Strings(out)
	return out
}

func budgetHostKey(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// hostBudget is one host's per-host counter, resolved once per attempt so the
// check, the reservation and a refund share one key and one map lookup. The
// zero value (per-host limit off, or no host) skips the per-host limit.
type hostBudget struct {
	key string
	n   *atomic.Int64
}

// forHost resolves host's per-host counter. host "" (a redirect hop, which has
// no host of its own here) and a budget without a per-host limit give the zero
// hostBudget.
func (b *Budget) forHost(host string) hostBudget {
	if b == nil || b.perHost <= 0 {
		return hostBudget{}
	}
	key := budgetHostKey(host)
	if key == "" {
		return hostBudget{}
	}
	if c, ok := b.hosts.Load(key); ok {
		return hostBudget{key: key, n: c.(*atomic.Int64)}
	}
	c, _ := b.hosts.LoadOrStore(key, &atomic.Int64{})
	return hostBudget{key: key, n: c.(*atomic.Int64)}
}

// LimitPhase caps the running phase at share (0..1) of the scan-wide budget
// still unspent, and returns the func that lifts the cap when the phase ends.
// A no-op without a scan-wide limit.
func (b *Budget) LimitPhase(name string, share float64) (release func()) {
	if b == nil || b.max <= 0 || share <= 0 || share >= 1 {
		return func() {}
	}
	used := b.Used()
	remaining := b.max - used
	if remaining <= 0 {
		return func() {}
	}
	limit := used + int64(float64(remaining)*share)
	if limit <= used {
		limit = used + 1
	}
	b.phaseName.Store(&name)
	b.phaseLimit.Store(limit)
	return func() { b.phaseLimit.CompareAndSwap(limit, 0) }
}

// phaseRefusal returns the phase-cap error when the running phase used its share.
func (b *Budget) phaseRefusal() error {
	pl := b.phaseLimit.Load()
	if pl <= 0 || b.used.Load()+b.external.Load() < pl {
		return nil
	}
	name := ""
	if p := b.phaseName.Load(); p != nil {
		name = *p
	}
	return &BudgetError{Kind: BudgetPhase, Host: name, Limit: pl}
}

// check is the read-only test run before an attempt waits for anything, so a
// request that cannot be admitted never takes a rate token or a host slot.
func (b *Budget) check(hb hostBudget) error {
	if b == nil {
		return nil
	}
	if b.max > 0 && (b.globalHit.Load() || b.used.Load()+b.external.Load() >= b.max) {
		return b.refuseGlobal()
	}
	if err := b.phaseRefusal(); err != nil {
		return err
	}
	if hb.n != nil && hb.n.Load() >= b.perHost {
		return b.refuseHost(hb.key)
	}
	return nil
}

// take reserves one attempt against both limits, or refuses it.
func (b *Budget) take(hb hostBudget) error {
	if b == nil {
		return nil
	}
	if hb.n != nil && !reserve(hb.n, 0, b.perHost) {
		return b.refuseHost(hb.key)
	}
	if err := b.phaseRefusal(); err != nil {
		if hb.n != nil {
			hb.n.Add(-1)
		}
		return err
	}
	if b.max > 0 {
		if b.globalHit.Load() || !reserve(&b.used, b.external.Load(), b.max) {
			if hb.n != nil {
				hb.n.Add(-1)
			}
			return b.refuseGlobal()
		}
	} else {
		b.used.Add(1)
	}
	return nil
}

// refund gives back one attempt take reserved but that was never sent.
func (b *Budget) refund(hb hostBudget) {
	if b == nil {
		return
	}
	b.used.Add(-1)
	if hb.n != nil {
		hb.n.Add(-1)
	}
}

// force counts n attempts that are already on the wire (a bare TCP dial) and
// cannot be refused. Only the scan-wide count moves.
func (b *Budget) force(n int64) {
	if b == nil {
		return
	}
	b.used.Add(n)
}

// reserve increments c when c+offset is below limit. A CAS loop rather than
// add-then-roll-back, so concurrent takers at the boundary never see each
// other's transient over-count and the limit is exact.
func reserve(c *atomic.Int64, offset, limit int64) bool {
	for {
		cur := c.Load()
		if cur+offset >= limit {
			return false
		}
		if c.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (b *Budget) refuseGlobal() error {
	err := &BudgetError{Kind: BudgetGlobal, Limit: b.max}
	b.exhaustGlobal(err)
	return err
}

func (b *Budget) exhaustGlobal(err *BudgetError) {
	b.globalHit.Store(true)
	b.globalOnce.Do(func() {
		if h := b.hooks.Load(); h != nil && h.Global != nil {
			h.Global(err)
		}
	})
}

func (b *Budget) refuseHost(key string) error {
	if _, loaded := b.exhaustedHosts.LoadOrStore(key, struct{}{}); !loaded {
		if h := b.hooks.Load(); h != nil && h.Host != nil {
			h.Host(key)
		}
	}
	return &BudgetError{Kind: BudgetHost, Host: key, Limit: b.perHost}
}

// Track registers the request counter of an engine that bypasses the gate,
// read as a delta from its value now. A counter stays registered for the rest
// of the scan, so what an engine sent still counts after it finishes. Nil-safe
// on both sides.
func (b *Budget) Track(read func() int64) {
	if b == nil || read == nil {
		return
	}
	b.mu.Lock()
	b.tracked = append(b.tracked, trackedCounter{read: read, base: read()})
	b.mu.Unlock()
}

// sample refreshes the tracked-traffic total and fires the global hook when
// gated plus tracked traffic has gone past the scan-wide limit. Strictly past:
// tracked engines are not refused, so reaching the limit exactly is not yet an
// overshoot, while the next gated attempt is refused by take.
func (b *Budget) sample() {
	b.mu.Lock()
	var total int64
	for _, c := range b.tracked {
		total += c.read() - c.base
	}
	b.mu.Unlock()
	b.external.Store(total)
	if b.max > 0 && total > 0 && b.used.Load()+total > b.max {
		b.exhaustGlobal(&BudgetError{Kind: BudgetGlobal, Limit: b.max})
	}
}

// Watch samples the tracked counters every interval (WatchInterval when <= 0)
// until ctx ends or the returned stop is called. It does nothing without a
// scan-wide limit, the only one tracked traffic is held to.
func (b *Budget) Watch(ctx context.Context, interval time.Duration) (stop func()) {
	if b == nil || b.max <= 0 {
		return func() {}
	}
	if interval <= 0 {
		interval = WatchInterval
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				b.sample()
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
}
