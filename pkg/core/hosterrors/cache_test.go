package hosterrors

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errRefused = errors.New("dial tcp 10.0.0.1:443: connect: connection refused")

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newTestCache returns a breaker with threshold 3, base 30s, max 5m, MaxTrips 3
// and a 10s probe TTL on a fake clock, plus the transitions it reported.
func newTestCache(t *testing.T) (*Cache, *fakeClock, *[]Transition) {
	t.Helper()
	clock := newFakeClock()
	c := NewWithConfig(Config{
		MaxHostError: 3,
		Cooldown:     30 * time.Second,
		MaxCooldown:  5 * time.Minute,
		MaxTrips:     3,
		ProbeTTL:     10 * time.Second,
		Now:          clock.Now,
	})
	var (
		mu  sync.Mutex
		got []Transition
	)
	c.SetObserver(func(tr Transition) {
		mu.Lock()
		got = append(got, tr)
		mu.Unlock()
	})
	t.Cleanup(c.Close)
	return c, clock, &got
}

func trip(c *Cache, key string) {
	for range c.MaxHostError {
		c.MarkFailed(key, errRefused, false)
	}
}

func TestClosedToOpenAtThreshold(t *testing.T) {
	c, _, trs := newTestCache(t)
	const key = "example.com:443"

	c.MarkFailed(key, errRefused, false)
	c.MarkFailed(key, errRefused, false)
	require.False(t, c.Quarantined(key), "below threshold")
	require.Equal(t, StateClosed, c.State(key))

	c.MarkFailed(key, errRefused, false)
	require.True(t, c.Quarantined(key), "at threshold")
	require.Equal(t, StateOpen, c.State(key))
	require.Len(t, *trs, 1)
	require.Equal(t, Transition{Key: key, From: StateClosed, To: StateOpen, Errors: 3, Cooldown: 30 * time.Second, Err: errRefused}, (*trs)[0])
	require.Equal(t, 1, c.QuarantinedCount())
	require.ErrorIs(t, c.LastError(key), errRefused)
}

func TestSuccessResetsConsecutiveCount(t *testing.T) {
	c, _, _ := newTestCache(t)
	const key = "example.com:80"
	c.MarkFailed(key, errRefused, false)
	c.MarkFailed(key, errRefused, false)
	c.MarkSuccess(key)
	c.MarkFailed(key, errRefused, false)
	c.MarkFailed(key, errRefused, false)
	require.False(t, c.Quarantined(key), "errors must be consecutive")
}

func TestUntrackedErrorsIgnored(t *testing.T) {
	c, _, _ := newTestCache(t)
	const key = "example.com:80"
	for range 10 {
		c.MarkFailed(key, errors.New("tls: handshake failure"), false)
		c.MarkFailed(key, context.Canceled, false)
		c.MarkFailed(key, errors.New("Client.Timeout exceeded while awaiting headers"), true)
	}
	require.False(t, c.Quarantined(key))
}

func TestTrackErrorSubstring(t *testing.T) {
	c := New(2, DefaultMaxHostsCount, []string{"custom error"})
	defer c.Close()
	c.MarkFailed("custom.com:80", fmt.Errorf("got: nested: custom error"), true)
	c.MarkFailed("custom.com:80", fmt.Errorf("got: nested: custom error"), true)
	require.True(t, c.Quarantined("custom.com:80"))
}

func TestQuarantinedDuringCooldownAndReadOnly(t *testing.T) {
	c, clock, _ := newTestCache(t)
	const key = "example.com:443"
	trip(c, key)

	clock.Advance(29 * time.Second)
	require.True(t, c.Quarantined(key))
	require.False(t, admit(c, key), "no probe inside the cooldown")

	clock.Advance(2 * time.Second)
	// Cooldown elapsed: Quarantined is false (work may be dispatched) but it is
	// read-only, so however often it is asked the state stays Open and the
	// probe is still available to Admit.
	for range 100 {
		require.False(t, c.Quarantined(key))
	}
	require.Equal(t, StateOpen, c.State(key))
	require.True(t, admit(c, key), "the first Admit after the cooldown is the probe")
	require.Equal(t, StateHalfOpen, c.State(key))
	require.True(t, c.Quarantined(key), "quarantined while the probe is in flight")
	require.False(t, admit(c, key))
}

func TestExactlyOneConcurrentAdmit(t *testing.T) {
	c, clock, _ := newTestCache(t)
	const key = "example.com:443"
	trip(c, key)
	clock.Advance(31 * time.Second)

	var (
		admitted atomic.Int32
		start    = make(chan struct{})
		wg       sync.WaitGroup
	)
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if admit(c, key) {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, admitted.Load())
}

func TestProbeSuccessCloses(t *testing.T) {
	c, clock, trs := newTestCache(t)
	const key = "example.com:443"
	trip(c, key)
	clock.Advance(31 * time.Second)
	require.True(t, admit(c, key))

	c.MarkSuccess(key)
	require.Equal(t, StateClosed, c.State(key))
	require.False(t, c.Quarantined(key))
	require.True(t, admit(c, key))
	require.Equal(t, 0, c.QuarantinedCount())
	last := (*trs)[len(*trs)-1]
	require.Equal(t, StateHalfOpen, last.From)
	require.Equal(t, StateClosed, last.To)

	// The error count restarted: a re-trip needs the full threshold again, and
	// opens with the base cooldown.
	c.MarkFailed(key, errRefused, false)
	c.MarkFailed(key, errRefused, false)
	require.False(t, c.Quarantined(key))
	c.MarkFailed(key, errRefused, false)
	require.True(t, c.Quarantined(key))
	clock.Advance(31 * time.Second)
	require.False(t, c.Quarantined(key), "re-trip uses the base cooldown")
}

func TestProbeFailureDoublesCooldown(t *testing.T) {
	c, clock, trs := newTestCache(t)
	const key = "example.com:443"
	trip(c, key)
	clock.Advance(31 * time.Second)
	require.True(t, admit(c, key))

	c.MarkFailed(key, errRefused, false)
	require.Equal(t, StateOpen, c.State(key))
	last := (*trs)[len(*trs)-1]
	require.Equal(t, Transition{Key: key, From: StateHalfOpen, To: StateOpen, Errors: 4, Trips: 1, Cooldown: time.Minute, Err: errRefused}, last)

	clock.Advance(59 * time.Second)
	require.True(t, c.Quarantined(key))
	require.False(t, admit(c, key))
	clock.Advance(2 * time.Second)
	require.False(t, c.Quarantined(key))
	require.True(t, admit(c, key))
}

func TestCooldownCappedAtMax(t *testing.T) {
	clock := newFakeClock()
	c := NewWithConfig(Config{
		MaxHostError: 1,
		Cooldown:     2 * time.Minute,
		MaxCooldown:  3 * time.Minute,
		MaxTrips:     -1,
		Now:          clock.Now,
	})
	defer c.Close()
	const key = "h:1"
	c.MarkFailed(key, errRefused, false)
	clock.Advance(2*time.Minute + time.Second)
	for range 10 {
		require.True(t, admit(c, key))
		c.MarkFailed(key, errRefused, false)
		require.Equal(t, StateOpen, c.State(key), "MaxTrips<0 never goes dead")
		clock.Advance(3*time.Minute - time.Second)
		require.True(t, c.Quarantined(key), "cooldown is capped at, not below, MaxCooldown")
		clock.Advance(2 * time.Second)
		require.False(t, c.Quarantined(key), "cooldown never exceeds MaxCooldown")
	}
}

func TestStaleProbeReadmitted(t *testing.T) {
	c, clock, _ := newTestCache(t)
	const key = "example.com:443"
	trip(c, key)
	clock.Advance(31 * time.Second)
	require.True(t, admit(c, key))

	// The probe never reports back.
	clock.Advance(9 * time.Second)
	require.True(t, c.Quarantined(key))
	require.False(t, admit(c, key))
	clock.Advance(2 * time.Second)
	require.False(t, c.Quarantined(key), "a probe older than ProbeTTL is lost")
	require.True(t, admit(c, key), "another caller takes over the probe")
	require.False(t, admit(c, key), "but only one")
}

func TestInconclusiveProbeReleasesSlot(t *testing.T) {
	c, clock, _ := newTestCache(t)
	const key = "example.com:443"
	trip(c, key)
	clock.Advance(31 * time.Second)
	require.True(t, admit(c, key))
	c.MarkFailed(key, context.Canceled, false)
	require.Equal(t, StateHalfOpen, c.State(key))
	require.True(t, admit(c, key), "a cancelled probe hands the slot to the next caller")
}

func TestDeadAfterMaxTrips(t *testing.T) {
	c, clock, trs := newTestCache(t)
	const key = "example.com:443"
	trip(c, key)
	cooldown := 30 * time.Second
	for i := range 3 {
		clock.Advance(cooldown + time.Second)
		require.True(t, admit(c, key), "probe %d", i+1)
		c.MarkFailed(key, errRefused, false)
		cooldown *= 2
	}
	require.Equal(t, StateDead, c.State(key))
	last := (*trs)[len(*trs)-1]
	require.Equal(t, StateDead, last.To)
	require.EqualValues(t, 3, last.Trips)

	clock.Advance(time.Hour)
	require.True(t, c.Quarantined(key), "dead is sticky")
	require.False(t, admit(c, key))
	c.MarkSuccess(key)
	require.Equal(t, StateDead, c.State(key))
	require.Equal(t, 1, c.QuarantinedCount())
}

func TestStraySuccessWhileOpenIgnored(t *testing.T) {
	c, _, _ := newTestCache(t)
	const key = "example.com:443"
	trip(c, key)
	c.MarkSuccess(key) // a request sent before the trip
	require.Equal(t, StateOpen, c.State(key))
	require.True(t, c.Quarantined(key))
}

// The key carries no method: a GET failure quarantines a POST to the same
// host:port (callers key with httpmsg.HostPortKey).
func TestKeyIsHostPortOnly(t *testing.T) {
	c, _, _ := newTestCache(t)
	trip(c, "example.com:443")
	require.True(t, c.Quarantined("example.com:443"))
	require.False(t, c.Quarantined("example.com:80"), "a different port is a different service")
}

// An Open host must not become healthy by falling out of the bounded ARC.
func TestOpenSurvivesEviction(t *testing.T) {
	clock := newFakeClock()
	c := NewWithConfig(Config{MaxHostError: 1, MaxHostsCount: 2, Now: clock.Now})
	defer c.Close()
	c.MarkFailed("dead:1", errRefused, false)
	for i := range 50 {
		c.MarkFailed(fmt.Sprintf("noisy-%d:1", i), errors.New("connection reset by peer"), false)
		c.MarkSuccess(fmt.Sprintf("noisy-%d:1", i))
	}
	require.True(t, c.Quarantined("dead:1"))
}

func TestConcurrentMarkFailedCountsEveryError(t *testing.T) {
	c := New(1000, DefaultMaxHostsCount, nil)
	defer c.Close()
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.MarkFailed("example.com:80", errRefused, false)
		}()
	}
	wg.Wait()
	require.EqualValues(t, 100, c.item("example.com:80").errors.Load())
}

func TestTrippedSnapshot(t *testing.T) {
	c, _, _ := newTestCache(t)
	trip(c, "b:1")
	trip(c, "a:1")
	got := c.Tripped()
	require.Len(t, got, 2)
	require.Equal(t, "a:1", got[0].Key)
	require.Equal(t, StateOpen, got[0].State)
	require.ErrorIs(t, got[0].LastErr, errRefused)
}

// AnyTripped stays false until a host opens, and stays true after it recovers.
func TestAnyTripped(t *testing.T) {
	c, clock, _ := newTestCache(t)
	const key = "example.com:443"
	c.MarkFailed(key, errRefused, false)
	require.False(t, c.AnyTripped(), "below threshold")

	trip(c, key)
	require.True(t, c.AnyTripped())

	clock.Advance(31 * time.Second)
	require.True(t, admit(c, key), "probe")
	c.MarkSuccess(key)
	require.Equal(t, StateClosed, c.State(key))
	require.True(t, c.AnyTripped(), "never cleared")
}

// admit is Admit's ok result.
func admit(c *Cache, key string) bool {
	ok, _ := c.Admit(key)
	return ok
}
