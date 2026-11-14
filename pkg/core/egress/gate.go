// Package egress is the single admission point for scan traffic aimed at a
// target: the global request-rate token bucket, the per-host concurrency slot,
// the dead-host breaker and the wire-attempt counter, applied in one order by
// one type.
//
// Before it existed each sender assembled those pieces itself, and most did not:
// the shared requester took one token per LOGICAL request while its retries and
// redirect hops went out free and kept the host slot through every backoff
// sleep; the discovery engine took no host slot and saw no quarantine; the
// port-sweep confirm step and the login flow took nothing at all. A Gate makes
// "what does it cost to send one request to the target" a single answer.
//
// Order inside Acquire, and why:
//
//  1. Quarantined (read-only) — a host already known to be dead must not spend
//     a token or occupy a slot only to be refused. The request budget's
//     read-only check runs here too, for the same reason (see Budget).
//  2. Rate token — taken BEFORE the slot, so a request throttled by the global
//     rate does not sit on scarce per-host concurrency while it waits.
//  3. Host slot — LaneNormal waits for one of the host's normal slots;
//     LanePriority may also take the host's reserved headroom (see
//     ratelimit.HostRateLimiter.AcquirePriority).
//  4. Budget — the request budget's reservation (--max-requests,
//     --max-requests-per-host), refused with a *BudgetError, never dialed.
//  5. Admit — the breaker's mutating check, immediately before the send, so the
//     half-open probe is claimed by a request that is really about to go out.
//  6. Count — one wire attempt.
//
// The returned release feeds the outcome to the breaker and frees the slot.
// Every wire attempt goes through Acquire once: a retry is a new Acquire (Do),
// a redirect hop takes a token (Token), and a bare TCP dial that has nothing
// to rate is still counted (Count).
package egress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/ratelimit"
	"golang.org/x/time/rate"
)

// Lane selects which host slots a request may use.
type Lane int

const (
	// LaneNormal is ordinary scan traffic: one of the host's normal slots.
	LaneNormal Lane = iota
	// LanePriority is traffic the rest of the scan waits on — login, re-login,
	// a reachability preflight. It may use the host's reserved headroom, so it
	// never queues behind the module requests that are waiting for it.
	LanePriority
)

// Config names the shared components a Gate applies. Any of them may be nil,
// which switches that check off.
type Config struct {
	Rate    *rate.Limiter
	Hosts   *ratelimit.HostRateLimiter
	Breaker *hosterrors.Cache
}

// Gate admits target traffic. A nil *Gate is valid and admits everything
// without counting, so a caller holding a possibly-nil gate needs no guard.
type Gate struct {
	cfg Config
	// sent counts wire attempts across the gate and every view derived from it
	// (With / WithRate / WithPhaseCounter share the pointer), so it is the
	// scan-wide total whichever component sent the request.
	sent *atomic.Int64
	// phase, when non-nil, also counts this view's attempts (a phase's own
	// requests_sent).
	phase *atomic.Int64
	// budget, when non-nil, caps the attempts the gate admits. Shared by every
	// view, like sent.
	budget *Budget
}

// New builds a Gate over cfg with a fresh wire-attempt counter.
func New(cfg Config) *Gate {
	return &Gate{cfg: cfg, sent: &atomic.Int64{}}
}

// Matches reports whether g applies exactly cfg's components.
func (g *Gate) Matches(cfg Config) bool {
	return g != nil && g.cfg == cfg
}

// With returns a view of g applying cfg's components instead, still counting
// into g's wire-attempt counter. It is how a phase that runs on its own pace
// (a phase-local rate or host limiter) stays inside the scan's single count.
func (g *Gate) With(cfg Config) *Gate {
	if g == nil {
		return New(cfg)
	}
	view := *g
	view.cfg = cfg
	return &view
}

// WithRate returns a view of g that takes its tokens from l instead (nil =
// unpaced), sharing g's host slots, breaker and counter. Discovery uses it: its
// pace is its own (DiscoveryRateLimit) but its hosts are the scan's.
func (g *Gate) WithRate(l *rate.Limiter) *Gate {
	if g == nil {
		return New(Config{Rate: l})
	}
	cfg := g.cfg
	cfg.Rate = l
	return g.With(cfg)
}

// WithPhaseCounter returns a view of g that also adds every attempt to c.
func (g *Gate) WithPhaseCounter(c *atomic.Int64) *Gate {
	if g == nil {
		g = New(Config{})
	}
	view := *g
	view.phase = c
	return &view
}

// WithBudget returns a view of g that holds every attempt to b (nil = no
// budget). Views derived from it share b. Attach it to the scan's root gate
// before any view is taken, so every sender is held to the same budget.
func (g *Gate) WithBudget(b *Budget) *Gate {
	if g == nil {
		g = New(Config{})
	}
	view := *g
	view.budget = b
	return &view
}

// Sent is the number of wire attempts admitted by g and every view sharing its
// counter.
func (g *Gate) Sent() int64 {
	if g == nil || g.sent == nil {
		return 0
	}
	return g.sent.Load()
}

// Count records n wire attempts that need no admission — a bare TCP dial has
// no request to rate and no slot worth holding, but it still reaches the host,
// so it is charged to the scan-wide request budget (never refused).
func (g *Gate) Count(n int64) {
	if g == nil {
		return
	}
	g.budget.force(n)
	g.count(n)
}

// count adds n to the attempt counters without touching the budget.
func (g *Gate) count(n int64) {
	g.sent.Add(n)
	if g.phase != nil {
		g.phase.Add(n)
	}
}

// Token takes one rate token and counts one attempt, without a host slot. A
// followed redirect hop uses it: the hop is another request on the wire, but
// the original request's slot is still held.
//
// The hop is charged to the scan-wide request budget only: it carries no host
// key here, so a per-host limit does not see it.
func (g *Gate) Token(ctx context.Context) error {
	if g == nil {
		return nil
	}
	if err := g.budget.check(hostBudget{}); err != nil {
		return err
	}
	if g.cfg.Rate != nil {
		if err := g.cfg.Rate.Wait(ctx); err != nil {
			return err
		}
	}
	if err := g.budget.take(hostBudget{}); err != nil {
		return err
	}
	g.count(1)
	return nil
}

// Outcome is what a release reports about the attempt it admitted.
type Outcome struct {
	// Err is the attempt's error; nil is a success.
	Err error
	// IgnoreTimeout keeps a timeout from counting toward quarantine (a
	// deliberately slow probe, Options.IgnoreTimeoutTracking).
	IgnoreTimeout bool
	// Neutral reports nothing to the breaker: the attempt's failure says
	// nothing about the host (a TLS probe offering a cipher the server is
	// expected to refuse).
	Neutral bool
}

// Release ends one admitted attempt. Call it exactly once.
type Release func(Outcome)

func noopRelease(Outcome) {}

// Acquire admits one wire attempt to hostPort ("host:port"; "" skips the host
// slot and the breaker but still takes a token). On success the caller sends
// and then calls the returned Release with the attempt's outcome.
//
// A quarantined host returns hosterrors.ErrUnresponsiveHost; an attempt over
// the request budget returns a *BudgetError (errors.Is ErrBudgetExhausted)
// before anything is waited for or sent; a cancelled ctx, the rate wait or the
// slot wait timing out return that error.
func (g *Gate) Acquire(ctx context.Context, hostPort string, lane Lane) (Release, error) {
	release, _, err := g.acquire(ctx, parseTarget(hostPort), lane)
	return release, err
}

// AcquireHost is Acquire for a host and port the caller holds separately, so
// they are not joined only to be split again.
func (g *Gate) AcquireHost(ctx context.Context, host string, port int, lane Lane) (Release, error) {
	release, _, err := g.acquire(ctx, hostTarget(host, port), lane)
	return release, err
}

// acquire admits one attempt to t, also reporting whether the breaker
// admitted it as its half-open recovery probe.
func (g *Gate) acquire(ctx context.Context, t target, lane Lane) (Release, bool, error) {
	if g == nil {
		return noopRelease, false, nil
	}
	a := admission{host: t.host, key: t.key, breaker: g.cfg.Breaker}
	if t.key == "" {
		a.breaker = nil
	}

	if a.breaker != nil && a.breaker.Quarantined(t.key) {
		return nil, false, hosterrors.ErrUnresponsiveHost
	}
	hb := g.budget.forHost(t.host)
	if err := g.budget.check(hb); err != nil {
		return nil, false, err
	}
	if g.cfg.Rate != nil {
		if err := g.cfg.Rate.Wait(ctx); err != nil {
			return nil, false, err
		}
	}

	if hosts := g.cfg.Hosts; hosts != nil && t.host != "" {
		if lane == LanePriority {
			release, err := hosts.AcquirePriority(ctx, t.host)
			if err != nil {
				return nil, false, err
			}
			a.freePriority = release
		} else {
			// Acquire timeout/cancellation is our own saturation or shutdown,
			// not host distress, so nothing is reported to the breaker.
			if err := hosts.AcquireWithTimeoutContext(ctx, t.host); err != nil {
				return nil, false, err
			}
			a.hosts = hosts
		}
	}

	// Reserved before Admit: a refusal after Admit would leave the breaker's
	// half-open probe claimed by a request that never went out.
	if err := g.budget.take(hb); err != nil {
		a.freeSlot()
		return nil, false, err
	}
	isProbe := false
	if a.breaker != nil {
		ok, probe := a.breaker.Admit(t.key)
		if !ok {
			g.budget.refund(hb)
			a.freeSlot()
			return nil, false, hosterrors.ErrUnresponsiveHost
		}
		isProbe = probe
	}

	g.count(1)
	if a.breaker == nil && a.hosts == nil && a.freePriority == nil {
		return noopRelease, false, nil
	}
	return a.release, isProbe, nil
}

// admission is what an admitted attempt's Release has to undo. Its release
// method value is the Release, one allocation per attempt.
type admission struct {
	host, key string
	breaker   *hosterrors.Cache
	// hosts is set when a normal-lane slot is held; freePriority when a
	// priority-lane slot is.
	hosts        *ratelimit.HostRateLimiter
	freePriority func()
}

func (a admission) release(o Outcome) {
	if a.breaker != nil && !o.Neutral {
		if o.Err != nil {
			a.breaker.MarkFailed(a.key, o.Err, o.IgnoreTimeout)
		} else {
			a.breaker.MarkSuccess(a.key)
		}
	}
	a.freeSlot()
}

func (a admission) freeSlot() {
	switch {
	case a.freePriority != nil:
		a.freePriority()
	case a.hosts != nil:
		a.hosts.Release(a.host)
	}
}

// target is an Acquire destination: the host-limiter key (the host as given,
// so it agrees with the key every other limiter caller uses) and the breaker
// key (lower-cased host:port, as httpmsg.HostPortKey builds it).
type target struct {
	host, key string
}

func parseTarget(hostPort string) target {
	if hostPort == "" {
		return target{}
	}
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return target{host: hostPort, key: strings.ToLower(hostPort)}
	}
	return target{host: h, key: strings.ToLower(hostPort)}
}

// hostTarget is parseTarget(net.JoinHostPort(host, port)) without the split.
// A host carrying a bracket does not survive that round trip unchanged, so it
// takes the parse.
func hostTarget(host string, port int) target {
	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	if strings.ContainsAny(host, "[]") {
		return parseTarget(hostPort)
	}
	return target{host: host, key: strings.ToLower(hostPort)}
}

// HostPort renders u's host:port, defaulting the port from the scheme, in the
// form Acquire takes.
func HostPort(u *url.URL) string {
	if u == nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") || strings.EqualFold(u.Scheme, "wss") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// RetryPolicy says how Do retries a failed attempt.
type RetryPolicy struct {
	// MaxRetries is how many attempts follow the first one (0 = no retry).
	MaxRetries int
	// Retryable decides whether a failed attempt may be retried. nil = never.
	Retryable func(ctx context.Context, err error) bool
	// Backoff is the wait before retry number attempt+1 (attempt counts from
	// 0). nil = DefaultBackoff.
	Backoff func(attempt int) time.Duration
	// IgnoreTimeout is passed to every attempt's Outcome.
	IgnoreTimeout bool
}

// DefaultBackoff doubles from 1s and caps at 10s — the schedule retryablehttp
// applied before retries moved here (RetryWaitMin 1s, RetryWaitMax 10s).
func DefaultBackoff(attempt int) time.Duration {
	const minWait, maxWait = time.Second, 10 * time.Second
	if attempt >= 4 {
		return maxWait
	}
	return min(minWait<<attempt, maxWait)
}

// Do runs send under the gate with retries: acquire → send → release, then a
// backoff sleep WITHOUT the host slot, then a fresh acquire (and so a fresh
// token) for the next attempt. Holding the slot through a 1–10s backoff would
// starve every other request to a host that had merely hiccuped.
//
// send learns whether the attempt was admitted as the breaker's half-open
// recovery probe, so it can send the record's baseline instead of a payload.
//
// It returns the number of attempts made and the final error. If a retry cannot
// be admitted because the host was quarantined by the failures so far, the last
// attempt's own error is returned — it says why the host is down; "skipping"
// does not. A ctx cancelled during a backoff returns ctx's error.
func (g *Gate) Do(ctx context.Context, hostPort string, lane Lane, p RetryPolicy, send func(attempt int, isProbe bool) error) (int, error) {
	backoff := p.Backoff
	if backoff == nil {
		backoff = DefaultBackoff
	}
	t := parseTarget(hostPort) // once, not per attempt
	var lastErr error
	for attempt := 0; ; attempt++ {
		release, isProbe, err := g.acquire(ctx, t, lane)
		if err != nil {
			if lastErr != nil && errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return attempt, lastErr
			}
			return attempt, err
		}
		err = send(attempt, isProbe)
		release(Outcome{Err: err, IgnoreTimeout: p.IgnoreTimeout})
		if err == nil {
			return attempt + 1, nil
		}
		lastErr = err
		if attempt >= p.MaxRetries || p.Retryable == nil || !p.Retryable(ctx, err) {
			return attempt + 1, err
		}
		timer := time.NewTimer(backoff(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return attempt + 1, ctx.Err()
		case <-timer.C:
		}
	}
}

// RefusedError is returned by a gated RoundTripper when the gate refused the
// request before it was sent (quarantine, cancellation, slot or rate wait
// timing out). It reports itself as not retryable so a retry middleware above
// the gate does not turn one refusal into several.
type RefusedError struct{ Err error }

func (e *RefusedError) Error() string { return "egress refused: " + e.Err.Error() }

// Unwrap exposes the cause, so errors.Is(err, hosterrors.ErrUnresponsiveHost)
// and errors.Is(err, context.Canceled) keep working.
func (e *RefusedError) Unwrap() error { return e.Err }

// Retryable is always false: nothing was sent, so there is nothing to retry.
func (e *RefusedError) Retryable() bool { return false }

// RoundTripper wraps next so every round trip is one gated attempt on lane.
// The slot is held until next returns the response headers; the body is read
// outside it. Place it INSIDE any retry middleware, so each retry pays.
func (g *Gate) RoundTripper(next http.RoundTripper, lane Lane) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &roundTripper{g: g, next: next, lane: lane}
}

// BlockClassifier reports whether a response is a WAF/CDN block page. It is
// only consulted for a block-candidate status, with at most blockPeekBytes of
// the body; the body the caller reads is unchanged.
type BlockClassifier interface {
	IsBlockStatus(status int) bool
	IsBlock(status int, header http.Header, body []byte) bool
}

// blockPeekBytes bounds how much of a block-candidate response body is read
// ahead for classification. Block pages are small; the rest still streams.
const blockPeekBytes = 64 << 10

// FeedbackRoundTripper is RoundTripper that also reports every response to the
// host limiter's adaptive control (HostRateLimiter.Feedback) the way the scan
// Requester does: a 429/5xx, a transport error or a classified WAF block backs
// the host off, a healthy completion counts toward its recovery. Without it a
// sender on this wrapper never backed off a throttling host and never let a
// host another phase had pre-armed recover. blocks may be nil (status-only).
func (g *Gate) FeedbackRoundTripper(next http.RoundTripper, lane Lane, blocks BlockClassifier) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &roundTripper{g: g, next: next, lane: lane, feedback: true, blocks: blocks}
}

type roundTripper struct {
	g        *Gate
	next     http.RoundTripper
	lane     Lane
	feedback bool
	blocks   BlockClassifier
}

func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	release, err := t.g.Acquire(req.Context(), HostPort(req.URL), t.lane)
	if err != nil {
		return nil, &RefusedError{Err: err}
	}
	resp, err := t.next.RoundTrip(req)
	release(Outcome{Err: err})
	if t.feedback {
		t.report(req, resp, err)
	}
	return resp, err
}

// hostLimiter is the gate's per-host limiter, nil on a nil gate or one
// configured without host slots.
func (g *Gate) hostLimiter() *ratelimit.HostRateLimiter {
	if g == nil {
		return nil
	}
	return g.cfg.Hosts
}

// report feeds one round trip's outcome to the host limiter. A cancelled
// request says nothing about the host (the run stopped, or a deadline of our
// own expired), so it is not reported.
func (t *roundTripper) report(req *http.Request, resp *http.Response, err error) {
	hosts := t.g.hostLimiter()
	if hosts == nil || requestCancelled(req) {
		return
	}
	// The limiter's key is the bare hostname (what Acquire's parseTarget
	// yields from HostPort), so take it straight from the URL.
	host := req.URL.Hostname()
	if host == "" {
		return
	}
	if err != nil {
		hosts.Feedback(host, ratelimit.FeedbackOutcome{Err: err})
		return
	}
	if resp == nil {
		return
	}
	hosts.Feedback(host, ratelimit.FeedbackOutcome{Status: resp.StatusCode, WAFBlocked: t.isBlock(resp)})
}

// requestCancelled reports whether the CALLER gave up on req (MISS-23). A
// client timeout is not a caller cancellation: it is the host failing to
// answer in time, which the limiter must count as distress.
//
// An http.Client with a Timeout wrapping a RoundTripper it does not know
// (this one) arms two timers: one closes req.Cancel, the other expires req's
// context with DeadlineExceeded. Either firing is the client's timeout, so
// both are treated as distress; only a context that ended with Canceled is
// the caller stopping.
func requestCancelled(req *http.Request) bool {
	return errors.Is(req.Context().Err(), context.Canceled) && !errors.Is(context.Cause(req.Context()), context.DeadlineExceeded)
}

// isBlock classifies a block-candidate response, reading ahead at most
// blockPeekBytes and splicing them back so the caller sees the whole body.
func (t *roundTripper) isBlock(resp *http.Response) bool {
	if t.blocks == nil || !t.blocks.IsBlockStatus(resp.StatusCode) {
		return false
	}
	var body []byte
	if resp.Body != nil && resp.Body != http.NoBody {
		size := int64(blockPeekBytes)
		if resp.ContentLength >= 0 && resp.ContentLength < size {
			size = resp.ContentLength
		}
		buf := bytes.NewBuffer(make([]byte, 0, size))
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, blockPeekBytes))
		peek := buf.Bytes()
		body = peek
		resp.Body = &peekedBody{Reader: io.MultiReader(bytes.NewReader(peek), resp.Body), Closer: resp.Body}
	}
	return t.blocks.IsBlock(resp.StatusCode, resp.Header, body)
}

// peekedBody is a response body whose first bytes were read ahead.
type peekedBody struct {
	io.Reader
	io.Closer
}

// CloseIdleConnections forwards to next, so a client whose Transport is this
// wrapper can still drop its pool.
func (t *roundTripper) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
