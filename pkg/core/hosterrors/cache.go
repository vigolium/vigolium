// Package hosterrors is the scan-wide dead-host circuit breaker.
//
// A host:port that keeps failing at the transport level (refused, reset, DNS,
// i/o timeout) is quarantined so the scan stops spending requests and worker
// time on it. Unlike the cache it replaced, quarantine is not forever: after a
// cooldown one probe request is let through, and its outcome decides whether
// the host recovers or stays quarantined for a longer cooldown. A host whose
// probes keep failing is eventually declared dead for the rest of the scan.
//
//	Closed   --(consecutive errors >= MaxHostError)--> Open(openedAt, cooldown)
//	Open     --(cooldown elapsed; first Admit wins)--> HalfOpen(probeAt)
//	HalfOpen --(MarkSuccess)-->                        Closed (errors=0, cooldown=base)
//	HalfOpen --(MarkFailed)-->                         Open (cooldown=min(2×cooldown, max)), trips++
//	HalfOpen --(probe unreported within ProbeTTL)-->   another probe may be admitted
//	HalfOpen --(MarkFailed, trips >= MaxTrips)-->      Dead (sticky for the scan)
//
// The key is host:port (see httpmsg.HostPortKey), with no method: a host that
// refuses connections refuses them for every method.
//
// The API is split so that looking does not consume the probe:
//   - Quarantined is read-only. The executor uses it to drop work items for a
//     quarantined host before they occupy a worker.
//   - Admit mutates. The requester calls it immediately before a send; it is
//     the call that turns Open into HalfOpen, and it lets exactly one caller
//     through as the probe.
package hosterrors

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bluele/gcache"
	"go.uber.org/zap"
)

// State is a host's breaker state.
type State int32

const (
	// StateClosed — healthy; consecutive transport errors are being counted.
	StateClosed State = iota
	// StateOpen — quarantined until the cooldown elapses.
	StateOpen
	// StateHalfOpen — one probe request is in flight.
	StateHalfOpen
	// StateDead — every probe failed; quarantined for the rest of the scan.
	StateDead
)

// String returns the lower-case state name used in logs and event details.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	case StateDead:
		return "dead"
	default:
		return "unknown"
	}
}

// Defaults for the breaker timings. DefaultProbeTTL is 2 × the default request
// timeout (15s); callers that know the configured timeout pass 2 × that.
const (
	DefaultMaxHostsCount = 10000
	DefaultCooldown      = 30 * time.Second
	DefaultMaxCooldown   = 5 * time.Minute
	DefaultMaxTrips      = 5
	DefaultProbeTTL      = 30 * time.Second
)

// Config configures a Cache. Zero values take the defaults above.
type Config struct {
	// MaxHostError is the consecutive tracked-error count that opens the
	// breaker (--max-host-error). Must be > 0.
	MaxHostError int
	// MaxHostsCount bounds the ARC that holds error counters for healthy
	// (Closed) hosts. Tripped hosts live outside it and are never evicted.
	MaxHostsCount int
	// TrackError lists extra error substrings that count as host errors.
	TrackError []string
	// Cooldown is the first quarantine period; MaxCooldown caps the doubling.
	Cooldown    time.Duration
	MaxCooldown time.Duration
	// MaxTrips is how many failed probes make a host dead. Negative disables
	// the dead state (the host keeps being re-probed at MaxCooldown).
	MaxTrips int
	// ProbeTTL is how long a half-open probe may stay unreported before another
	// probe is admitted (a probe whose caller vanished must not wedge the host).
	ProbeTTL time.Duration
	// Now is the clock; nil means time.Now. Tests inject a fake one.
	Now func() time.Time
}

// Transition describes one breaker state change, delivered to the observer
// installed with SetObserver.
type Transition struct {
	Key      string
	From, To State
	// Errors is the consecutive-error count at the time of the change.
	Errors int32
	// Trips is the number of failed probes so far.
	Trips int32
	// Cooldown is the quarantine period now in force (Open only).
	Cooldown time.Duration
	// Err is the error that caused the change, nil for a recovery.
	Err error
}

// Cache is the host:port circuit breaker. All methods are safe for concurrent
// use; Quarantined, Admit and the healthy-host paths of MarkSuccess take no lock
// beyond a sync.Map load.
type Cache struct {
	MaxHostError int
	TrackError   []string

	cooldown    time.Duration
	maxCooldown time.Duration
	maxTrips    int32
	probeTTL    time.Duration
	now         func() time.Time
	verbose     bool

	// counters holds Closed hosts' error counters. Bounded ARC: evicting a
	// healthy host's counter only forgets a few consecutive errors.
	counters gcache.Cache
	// tripped holds every host that has ever opened. Never evicted, so an Open
	// host cannot silently become healthy by falling out of the ARC; bounded by
	// the number of failing hosts, which is small.
	tripped sync.Map // key → *cacheItem
	// anyTripped is set before the first entry is stored in tripped and never
	// cleared, so a false load proves Quarantined is false for every key.
	anyTripped atomic.Bool
	// createMu serialises counter creation (the first error for a host) so two
	// concurrent first errors share one counter.
	createMu sync.Mutex

	observer atomic.Pointer[func(Transition)]
}

type cacheItem struct {
	state    atomic.Int32
	errors   atomic.Int32
	trips    atomic.Int32
	openedAt atomic.Int64 // unix nanos
	cooldown atomic.Int64 // nanos
	probeAt  atomic.Int64 // unix nanos; 0 = no probe in flight
	lastErr  atomic.Pointer[error]
	// mu serialises state transitions (the slow path). Admit's Open→HalfOpen
	// CAS does not take it.
	mu sync.Mutex
}

// New returns a breaker with the default timings.
func New(maxHostError, maxHostsCount int, trackError []string) *Cache {
	return NewWithConfig(Config{MaxHostError: maxHostError, MaxHostsCount: maxHostsCount, TrackError: trackError})
}

// NewWithConfig returns a breaker for cfg, filling zero fields with defaults.
func NewWithConfig(cfg Config) *Cache {
	if cfg.MaxHostsCount <= 0 {
		cfg.MaxHostsCount = DefaultMaxHostsCount
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = DefaultCooldown
	}
	if cfg.MaxCooldown <= 0 {
		cfg.MaxCooldown = DefaultMaxCooldown
	}
	if cfg.MaxCooldown < cfg.Cooldown {
		cfg.MaxCooldown = cfg.Cooldown
	}
	if cfg.MaxTrips == 0 {
		cfg.MaxTrips = DefaultMaxTrips
	}
	if cfg.ProbeTTL <= 0 {
		cfg.ProbeTTL = DefaultProbeTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Cache{
		MaxHostError: cfg.MaxHostError,
		TrackError:   cfg.TrackError,
		cooldown:     cfg.Cooldown,
		maxCooldown:  cfg.MaxCooldown,
		maxTrips:     int32(cfg.MaxTrips),
		probeTTL:     cfg.ProbeTTL,
		now:          cfg.Now,
		counters:     gcache.New(cfg.MaxHostsCount).ARC().Build(),
	}
}

// SetVerbose sets the cache to log at verbose level
func (c *Cache) SetVerbose(verbose bool) {
	c.verbose = verbose
}

// SetObserver installs fn to receive every state transition. It is called
// outside the breaker's locks, on the goroutine that caused the change, so it
// must not block. Passing nil removes the observer.
func (c *Cache) SetObserver(fn func(Transition)) {
	if fn == nil {
		c.observer.Store(nil)
		return
	}
	c.observer.Store(&fn)
}

// Close releases the cache's entries.
func (c *Cache) Close() {
	c.counters.Purge()
	c.tripped.Range(func(k, _ any) bool {
		c.tripped.Delete(k)
		return true
	})
}

// ErrUnresponsiveHost is returned when a host is unresponsive
var ErrUnresponsiveHost = errors.New("skipping as host is unresponsive")

func (c *Cache) nowNanos() int64 { return c.now().UnixNano() }

func (c *Cache) trippedItem(key string) *cacheItem {
	v, ok := c.tripped.Load(key)
	if !ok {
		return nil
	}
	return v.(*cacheItem)
}

// item returns the host's entry, tripped first, or nil when it has none.
func (c *Cache) item(key string) *cacheItem {
	if it := c.trippedItem(key); it != nil {
		return it
	}
	v, err := c.counters.GetIFPresent(key)
	if err != nil || v == nil {
		return nil
	}
	return v.(*cacheItem)
}

// Quarantined reports whether work for key should be dropped now. Read-only:
// it never consumes the half-open probe. True while Open inside the cooldown,
// while HalfOpen with a probe in flight, and once Dead.
func (c *Cache) Quarantined(key string) bool {
	it := c.trippedItem(key)
	if it == nil {
		return false
	}
	now := c.nowNanos()
	switch State(it.state.Load()) {
	case StateOpen:
		return now < it.openedAt.Load()+it.cooldown.Load()
	case StateHalfOpen:
		return now-it.probeAt.Load() < int64(c.probeTTL)
	case StateDead:
		return true
	default:
		return false
	}
}

// AnyTripped reports whether any host has ever opened. While it is false,
// Quarantined is false for every key, so a caller filtering many items can
// skip building their keys.
func (c *Cache) AnyTripped() bool {
	return c.anyTripped.Load()
}

// Admit reports whether a request to key may be sent now, and whether the
// admission is the half-open recovery probe. Call it immediately before the
// send. For an Open host whose cooldown has elapsed it performs the
// Open→HalfOpen transition, and exactly one concurrent caller gets true — the
// probe. A half-open probe that has not reported within ProbeTTL is treated as
// lost, and one more caller is admitted in its place.
//
// A caller holding the probe can spend it on a request whose outcome actually
// says whether the host is alive — the record's unmodified baseline — instead
// of whatever payload happened to arrive: a WAF that silently drops payloads
// would otherwise fail every probe and get the host declared dead.
func (c *Cache) Admit(key string) (ok, isProbe bool) {
	it := c.trippedItem(key)
	if it == nil {
		return true, false
	}
	now := c.nowNanos()
	switch State(it.state.Load()) {
	case StateClosed:
		return true, false
	case StateOpen:
		if now < it.openedAt.Load()+it.cooldown.Load() {
			return false, false
		}
		// probeAt is written before the CAS so a reader that sees HalfOpen
		// never sees a stale probe time. Losers overwrite it with ~the same
		// instant, which only matters at ProbeTTL granularity.
		it.probeAt.Store(now)
		won := it.state.CompareAndSwap(int32(StateOpen), int32(StateHalfOpen))
		return won, won
	case StateHalfOpen:
		p := it.probeAt.Load()
		if now-p < int64(c.probeTTL) {
			return false, false
		}
		won := it.probeAt.CompareAndSwap(p, now)
		return won, won
	default:
		return false, false
	}
}

// MarkFailed records a failed request to key. Errors that are not host
// errors (see checkError) are ignored, except that one arriving while a probe
// is in flight releases the probe slot: the probe's outcome was inconclusive,
// so the next caller may probe instead of waiting out ProbeTTL.
func (c *Cache) MarkFailed(key string, err error, ignoreTimeout bool) {
	if err == nil || key == "" {
		return
	}
	if !c.checkError(err, ignoreTimeout) {
		if it := c.trippedItem(key); it != nil && State(it.state.Load()) == StateHalfOpen {
			it.probeAt.Store(0)
		}
		return
	}
	it := c.item(key)
	if it == nil {
		it = c.createItem(key)
	}
	it.lastErr.Store(&err)
	switch State(it.state.Load()) {
	case StateClosed:
		if n := it.errors.Add(1); c.MaxHostError > 0 && n >= int32(c.MaxHostError) {
			c.open(key, it, err)
		}
	case StateOpen:
		it.errors.Add(1) // a request sent before the trip; no transition
	case StateHalfOpen:
		it.errors.Add(1)
		c.probeFailed(key, it, err)
	}
}

// MarkSuccess records a successful request to key. A Closed host's error
// counter resets; a HalfOpen host recovers. A success while Open is a request
// that was in flight before the trip and is deliberately ignored: only the
// probe decides recovery.
func (c *Cache) MarkSuccess(key string) {
	if key == "" {
		return
	}
	it := c.item(key)
	if it == nil {
		return
	}
	switch State(it.state.Load()) {
	case StateClosed:
		if it.errors.Load() != 0 {
			it.errors.Store(0)
		}
	case StateHalfOpen:
		c.recover(key, it)
	}
}

func (c *Cache) createItem(key string) *cacheItem {
	c.createMu.Lock()
	defer c.createMu.Unlock()
	if it := c.item(key); it != nil {
		return it
	}
	it := &cacheItem{}
	_ = c.counters.Set(key, it)
	return it
}

// open performs Closed→Open.
func (c *Cache) open(key string, it *cacheItem, err error) {
	it.mu.Lock()
	if State(it.state.Load()) != StateClosed {
		it.mu.Unlock()
		return
	}
	cooldown := c.cooldown
	// Fields before state: a reader that sees Open sees its deadline.
	it.openedAt.Store(c.nowNanos())
	it.cooldown.Store(int64(cooldown))
	it.trips.Store(0)
	c.anyTripped.Store(true)
	c.tripped.LoadOrStore(key, it)
	it.state.Store(int32(StateOpen))
	errs := it.errors.Load()
	it.mu.Unlock()

	if c.verbose {
		zap.L().Warn("Host quarantined after consecutive errors",
			zap.String("host", key), zap.Int32("error_count", errs),
			zap.Duration("cooldown", cooldown), zap.Error(err))
	} else {
		zap.L().Debug("Host quarantined after consecutive errors",
			zap.String("host", key), zap.Int32("error_count", errs),
			zap.Duration("cooldown", cooldown), zap.Error(err))
	}
	c.notify(Transition{Key: key, From: StateClosed, To: StateOpen, Errors: errs, Cooldown: cooldown, Err: err})
}

// probeFailed performs HalfOpen→Open (doubled cooldown) or HalfOpen→Dead.
func (c *Cache) probeFailed(key string, it *cacheItem, err error) {
	it.mu.Lock()
	if State(it.state.Load()) != StateHalfOpen {
		it.mu.Unlock()
		return
	}
	trips := it.trips.Add(1)
	errs := it.errors.Load()
	if c.maxTrips > 0 && trips >= c.maxTrips {
		it.probeAt.Store(0)
		it.state.Store(int32(StateDead))
		it.mu.Unlock()
		zap.L().Warn("Host declared dead after repeated failed probes",
			zap.String("host", key), zap.Int32("trips", trips), zap.Error(err))
		c.notify(Transition{Key: key, From: StateHalfOpen, To: StateDead, Errors: errs, Trips: trips, Err: err})
		return
	}
	cooldown := min(time.Duration(it.cooldown.Load())*2, c.maxCooldown)
	it.openedAt.Store(c.nowNanos())
	it.cooldown.Store(int64(cooldown))
	it.probeAt.Store(0)
	it.state.Store(int32(StateOpen))
	it.mu.Unlock()
	zap.L().Debug("Host probe failed; quarantine extended",
		zap.String("host", key), zap.Int32("trips", trips),
		zap.Duration("cooldown", cooldown), zap.Error(err))
	c.notify(Transition{Key: key, From: StateHalfOpen, To: StateOpen, Errors: errs, Trips: trips, Cooldown: cooldown, Err: err})
}

// recover performs HalfOpen→Closed.
func (c *Cache) recover(key string, it *cacheItem) {
	it.mu.Lock()
	if State(it.state.Load()) != StateHalfOpen {
		it.mu.Unlock()
		return
	}
	trips := it.trips.Load()
	it.errors.Store(0)
	it.trips.Store(0)
	it.cooldown.Store(int64(c.cooldown))
	it.probeAt.Store(0)
	it.state.Store(int32(StateClosed))
	it.mu.Unlock()
	zap.L().Info("Quarantined host recovered", zap.String("host", key))
	c.notify(Transition{Key: key, From: StateHalfOpen, To: StateClosed, Trips: trips})
}

func (c *Cache) notify(t Transition) {
	if fn := c.observer.Load(); fn != nil {
		(*fn)(t)
	}
}

// State returns key's current breaker state (Closed for an unknown host).
func (c *Cache) State(key string) State {
	if it := c.trippedItem(key); it != nil {
		return State(it.state.Load())
	}
	return StateClosed
}

// LastError returns the most recent host error recorded for key, or nil.
func (c *Cache) LastError(key string) error {
	it := c.item(key)
	if it == nil {
		return nil
	}
	if p := it.lastErr.Load(); p != nil {
		return *p
	}
	return nil
}

// QuarantinedCount returns how many hosts are currently not Closed (Open,
// HalfOpen or Dead). Informational, for logging cross-phase propagation.
func (c *Cache) QuarantinedCount() int {
	count := 0
	c.tripped.Range(func(_, v any) bool {
		if State(v.(*cacheItem).state.Load()) != StateClosed {
			count++
		}
		return true
	})
	return count
}

var reCheckError = regexp.MustCompile(`(no address found for host|Client\.Timeout exceeded while awaiting headers|could not resolve host|connection refused|connection reset by peer|i/o timeout|could not connect to any address found for host|timeout awaiting response headers)`)

var reCheckErrorIgnoreTimeout = regexp.MustCompile(`(no address found for host|could not resolve host|connection refused|connection reset by peer|i/o timeout|could not connect to any address found for host)`)

// checkError checks if an error represents a type that should be
// added to the host skipping table.
func (c *Cache) checkError(err error, ignoreTimeout bool) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	errString := err.Error()
	for _, msg := range c.TrackError {
		if strings.Contains(errString, msg) {
			return true
		}
	}
	if ignoreTimeout {
		return reCheckErrorIgnoreTimeout.MatchString(errString)
	}
	return reCheckError.MatchString(errString)
}
