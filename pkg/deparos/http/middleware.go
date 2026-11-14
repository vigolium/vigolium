package http

import (
	"context"
	"errors"
	"io"
	"math"
	nethttp "net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrRequestFiltered is returned in place of sending a request the caller's
// policy refuses.
//
// It is deliberately NOT a network error: IsRetryable reports false for it, so a
// refused request is never retried and never reaches the engine's
// consecutive-network-error budget. Without that exemption an excluded host would
// look like a flapping network — *url.Error satisfies net.Error — and enough of
// them in a row would cancel the whole discovery run.
var ErrRequestFiltered = errors.New("request filtered by scope policy")

// FilterMiddleware refuses a request before it reaches the transport.
//
// allow is consulted with the outgoing request (URL and method, SAFE-8) and must
// return true for the request to proceed. This is the egress seam: an operator's explicit exclusion
// has to be enforced HERE rather than by discarding the response, because by then
// the excluded host has already been contacted — which is the whole thing the
// exclusion was asking not to happen.
//
// A nil allow returns next unwrapped, so a run without a policy pays nothing.
// Place it OUTERMOST, ahead of retry: a refused request must not be reattempted.
func FilterMiddleware(allow func(*nethttp.Request) bool) Middleware {
	return func(next nethttp.RoundTripper) nethttp.RoundTripper {
		if allow == nil {
			return next
		}
		return &filterRoundTripper{next: next, allow: allow}
	}
}

type filterRoundTripper struct {
	next  nethttp.RoundTripper
	allow func(*nethttp.Request) bool
}

// CloseIdleConnections forwards the idle-close to the wrapped transport.
// See forwardCloseIdle for why every middleware here needs this method.
func (f *filterRoundTripper) CloseIdleConnections() { forwardCloseIdle(f.next) }

func (f *filterRoundTripper) RoundTrip(req *nethttp.Request) (*nethttp.Response, error) {
	if !f.allow(req) {
		// Returned bare rather than wrapped in RequestError: there was no attempt
		// to attribute. net/http wraps it in a *url.Error on the way out, which
		// keeps errors.Is working for the caller.
		return nil, ErrRequestFiltered
	}
	return f.next.RoundTrip(req)
}

// CountingMiddleware increments n once per physical round trip.
//
// Place it INNERMOST, closest to the transport, so it counts attempts rather than
// logical requests: a request the retry middleware sends three times counts
// three, which is what an operator comparing a scan against a server's access log
// sees. Deparos never follows redirects, so there is no redirect inflation to
// account for.
//
// The counter belongs to the caller — the engine only ever adds to it — so a
// phase can read the real traffic a crawl generated without the engine knowing
// anything about who is reading. A nil counter returns next unwrapped.
func CountingMiddleware(n *atomic.Int64) Middleware {
	return func(next nethttp.RoundTripper) nethttp.RoundTripper {
		if n == nil {
			return next
		}
		return &countingRoundTripper{next: next, n: n}
	}
}

type countingRoundTripper struct {
	next nethttp.RoundTripper
	n    *atomic.Int64
}

// CloseIdleConnections forwards the idle-close to the wrapped transport.
func (c *countingRoundTripper) CloseIdleConnections() { forwardCloseIdle(c.next) }

func (c *countingRoundTripper) RoundTrip(req *nethttp.Request) (*nethttp.Response, error) {
	// Counted before the call, not after: a request that fails or is cancelled was
	// still put on the wire, and a counter that only tallied successes would
	// under-report exactly the runs an operator looks at it for.
	c.n.Add(1)
	return c.next.RoundTrip(req)
}

// RetryConfig configures retry behavior.
type RetryConfig struct {
	// MaxAttempts is the maximum number of attempts (including first request).
	// Default: 3 (1 initial + 2 retries)
	MaxAttempts int

	// InitialBackoff is the initial backoff duration.
	// Default: 100ms
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration.
	// Default: 5 seconds
	MaxBackoff time.Duration

	// BackoffMultiplier is the multiplier for exponential backoff.
	// Default: 2.0
	BackoffMultiplier float64

	// RetryableStatusCodes are HTTP status codes that should trigger retry.
	// Default: 429 (Too Many Requests), 503 (Service Unavailable)
	RetryableStatusCodes []int

	// MinStatusBackoff is the shortest wait before retrying a retryable
	// STATUS that carried no Retry-After. Re-asking a host that just answered
	// "too many requests" 100ms later is the request it refused; the
	// exponential backoff still applies above this floor.
	// Default: 1 second
	MinStatusBackoff time.Duration

	// MaxRetryAfter caps how long a server's Retry-After is honored. A longer
	// Retry-After is not retried at all: the response is returned as it came,
	// rather than parking a discovery worker for minutes (the host limiter's
	// back-off is what slows the rest of the run down).
	// Default: 30 seconds
	MaxRetryAfter time.Duration
}

// DefaultRetryConfig returns default retry configuration.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:          3,
		InitialBackoff:       100 * time.Millisecond,
		MaxBackoff:           5 * time.Second,
		BackoffMultiplier:    2.0,
		RetryableStatusCodes: []int{429, 503},
		MinStatusBackoff:     time.Second,
		MaxRetryAfter:        30 * time.Second,
	}
}

// RetryMiddleware returns a middleware that retries failed requests with exponential backoff.
func RetryMiddleware(config *RetryConfig) Middleware {
	if config == nil {
		config = DefaultRetryConfig()
	}

	return func(next nethttp.RoundTripper) nethttp.RoundTripper {
		return &retryRoundTripper{
			next:   next,
			config: config,
		}
	}
}

type retryRoundTripper struct {
	next   nethttp.RoundTripper
	config *RetryConfig
}

// CloseIdleConnections forwards the idle-close to the wrapped transport.
// See forwardCloseIdle for why every middleware here needs this method.
func (r *retryRoundTripper) CloseIdleConnections() { forwardCloseIdle(r.next) }

// forwardCloseIdle passes an idle-close down to next when it accepts one.
//
// net/http.Client.CloseIdleConnections only calls the method if its Transport
// implements it, and a middleware chain replaces the Transport with the
// outermost wrapper. So a single middleware without this method silently
// swallows every idle-close for the whole chain and the connection pool lives
// until the process exits. Every RoundTripper in this file must forward.
//
// Client.CloseIdleConnections does not rely on this — it holds the transport it
// built and calls it directly. This path is for a caller holding the bare
// *nethttp.Client from Client.HTTPClient().
func forwardCloseIdle(next nethttp.RoundTripper) {
	if c, ok := next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// maxRetryDrainBytes bounds how much of a discarded intermediate response is read
// before closing it. Draining to EOF lets the connection go back to the pool, but
// a large error page must not be read in full just to be thrown away — and an
// unbounded drain on a slow host stalls the retry loop.
const maxRetryDrainBytes = 16 << 10

// drainAndClose consumes a bounded prefix of body so the connection is reusable,
// then closes it exactly once.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxRetryDrainBytes))
	_ = body.Close()
}

func (r *retryRoundTripper) RoundTrip(req *nethttp.Request) (*nethttp.Response, error) {
	var resp *nethttp.Response
	var err error

	// A misconfigured MaxAttempts would skip the loop entirely and return
	// (nil, nil), which every caller of RoundTrip treats as a protocol violation.
	attempts := r.config.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	// A body that cannot be replayed must not be retried: a second attempt would
	// go out empty. Decided once here rather than re-derived per iteration.
	if req.Body != nil && req.GetBody == nil {
		attempts = 1
	}

	for attempt := 1; attempt <= attempts; attempt++ {
		// Attempt 1 sends req untouched; only a RETRY needs its own copy, and a
		// clone is ~1KB and 5 allocations on a path where retries are the
		// exception. Clone does NOT duplicate the body stream, so a retry also has
		// to restore it from GetBody, or it goes out with a consumed (empty) body.
		sendReq := req
		if attempt > 1 {
			sendReq = req.Clone(req.Context())
			if req.Body != nil {
				body, berr := req.GetBody()
				if berr != nil {
					return resp, err
				}
				sendReq.Body = body
			}
		}

		// Execute request
		resp, err = r.next.RoundTrip(sendReq)

		// Check if we should retry
		shouldRetry := false

		// Retry on network errors
		if err != nil && IsRetryable(err) {
			shouldRetry = true
		}

		// Retry on retryable status codes, waiting as long as the server
		// asked (within MaxRetryAfter) and never less than MinStatusBackoff.
		var statusWait time.Duration
		if resp != nil {
			for _, code := range r.config.RetryableStatusCodes {
				if resp.StatusCode == code {
					shouldRetry = true
					break
				}
			}
			if shouldRetry {
				wait, ok := r.statusRetryWait(resp)
				if !ok {
					shouldRetry = false
				}
				statusWait = wait
			}
		}

		// Whether another attempt is permitted MUST be decided before the response
		// is disposed of. Closing on retryable status first meant the final attempt
		// returned a 429/503 whose body was already closed, so the caller read
		// nothing — against a rate-limiting host discovery silently saw empty
		// responses instead of the throttling it was being told about.
		lastAttempt := attempt == attempts
		if shouldRetry && !lastAttempt && resp != nil {
			// Intermediate response we are about to discard: drain a bounded prefix
			// so the connection can be reused, then close.
			drainAndClose(resp.Body)
		}

		// If successful or last attempt, return
		if !shouldRetry || lastAttempt {
			if err != nil {
				return nil, &RequestError{
					URL:     req.URL.String(),
					Attempt: attempt,
					Err:     err,
				}
			}
			return resp, nil
		}

		// Calculate backoff with exponential increase
		backoff := max(r.calculateBackoff(attempt), statusWait)

		// Wait before retry (respect context cancellation)
		select {
		case <-time.After(backoff):
			// Continue to retry
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	// Should not reach here, but return last error
	return resp, err
}

func (r *retryRoundTripper) calculateBackoff(attempt int) time.Duration {
	// Exponential backoff: initialBackoff * (multiplier ^ (attempt - 1))
	backoff := float64(r.config.InitialBackoff) * math.Pow(r.config.BackoffMultiplier, float64(attempt-1))
	duration := time.Duration(backoff)

	// Cap at max backoff
	if duration > r.config.MaxBackoff {
		duration = r.config.MaxBackoff
	}

	return duration
}

// statusRetryWait is the minimum wait before retrying resp's retryable status:
// its Retry-After when present, else MinStatusBackoff. ok is false when the
// server asked for longer than MaxRetryAfter, which is not retried.
func (r *retryRoundTripper) statusRetryWait(resp *nethttp.Response) (wait time.Duration, ok bool) {
	if after, found := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); found {
		if r.config.MaxRetryAfter > 0 && after > r.config.MaxRetryAfter {
			return 0, false
		}
		return after, true
	}
	return r.config.MinStatusBackoff, true
}

// parseRetryAfter reads a Retry-After value (RFC 9110 §10.2.3): delay-seconds
// or an HTTP-date. A date in the past is a zero wait; an unparseable value is
// treated as absent.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		if secs > int64(24*time.Hour/time.Second) {
			secs = int64(24 * time.Hour / time.Second)
		}
		return time.Duration(secs) * time.Second, true
	}
	if at, err := nethttp.ParseTime(v); err == nil {
		return max(at.Sub(now), 0), true
	}
	return 0, false
}

// RateLimitConfig configures rate limiting behavior using token bucket algorithm.
type RateLimitConfig struct {
	// RequestsPerSecond is the maximum number of requests per second.
	// Default: 10
	RequestsPerSecond int

	// BurstSize is the maximum burst size (token bucket capacity).
	// Default: 20
	BurstSize int
}

// DefaultRateLimitConfig returns default rate limit configuration.
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		RequestsPerSecond: 10,
		BurstSize:         20,
	}
}

// RateLimitMiddleware returns a middleware that enforces rate limiting.
// Uses token bucket algorithm for smooth rate limiting.
func RateLimitMiddleware(config *RateLimitConfig) Middleware {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	limiter := newTokenBucket(config.RequestsPerSecond, config.BurstSize)

	return func(next nethttp.RoundTripper) nethttp.RoundTripper {
		return &rateLimitRoundTripper{
			next:    next,
			limiter: limiter,
			config:  config,
		}
	}
}

type rateLimitRoundTripper struct {
	next    nethttp.RoundTripper
	limiter *tokenBucket
	config  *RateLimitConfig
}

// CloseIdleConnections forwards the idle-close to the wrapped transport.
// See forwardCloseIdle: a middleware that omits this breaks the chain for
// everything beneath it.
func (r *rateLimitRoundTripper) CloseIdleConnections() { forwardCloseIdle(r.next) }

func (r *rateLimitRoundTripper) RoundTrip(req *nethttp.Request) (*nethttp.Response, error) {
	// Wait for token (respects context cancellation)
	if err := r.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}

	// Execute request
	return r.next.RoundTrip(req)
}

// tokenBucket implements token bucket rate limiting algorithm.
type tokenBucket struct {
	mu sync.Mutex

	// Configuration
	rate     float64       // Tokens per second
	capacity int           // Maximum tokens
	interval time.Duration // Time between token additions

	// State
	tokens   float64   // Current tokens
	lastFill time.Time // Last time tokens were added
}

func newTokenBucket(requestsPerSecond, burstSize int) *tokenBucket {
	// A zero rate reaches a division by zero below, and a negative one yields a
	// nonsense interval, so clamp to the documented default rather than panicking
	// deep inside a middleware chain.
	if requestsPerSecond < 1 {
		requestsPerSecond = DefaultRateLimitConfig().RequestsPerSecond
	}
	if burstSize < 1 {
		burstSize = requestsPerSecond
	}
	rate := float64(requestsPerSecond)
	interval := time.Second / time.Duration(requestsPerSecond)

	return &tokenBucket{
		rate:     rate,
		capacity: burstSize,
		interval: interval,
		tokens:   float64(burstSize), // Start full
		lastFill: time.Now(),
	}
}

// Wait blocks until a token is available or context is cancelled.
func (tb *tokenBucket) Wait(ctx context.Context) error {
	for {
		// Try to acquire token
		if tb.tryAcquire() {
			return nil
		}

		// Calculate wait time
		waitTime := tb.waitDuration()

		// Wait or respect context cancellation
		select {
		case <-time.After(waitTime):
			// Continue loop to try again
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// tryAcquire attempts to acquire a token.
// Returns true if successful, false if no tokens available.
func (tb *tokenBucket) tryAcquire() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Refill tokens based on elapsed time
	tb.refill()

	// Check if token available
	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}

	return false
}

// refill adds tokens based on elapsed time since last fill.
func (tb *tokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastFill)

	// Calculate tokens to add
	tokensToAdd := elapsed.Seconds() * tb.rate

	// Add tokens (cap at capacity)
	tb.tokens = math.Min(tb.tokens+tokensToAdd, float64(tb.capacity))
	tb.lastFill = now
}

// waitDuration calculates how long to wait until next token is available.
func (tb *tokenBucket) waitDuration() time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Calculate tokens needed
	tokensNeeded := 1.0 - tb.tokens

	if tokensNeeded <= 0 {
		return 0
	}

	// Calculate wait time based on rate
	waitSeconds := tokensNeeded / tb.rate
	return time.Duration(waitSeconds * float64(time.Second))
}

// ChainMiddleware combines multiple middleware into a single middleware.
// Middleware are applied in the order they appear (first middleware wraps subsequent ones).
func ChainMiddleware(middleware ...Middleware) Middleware {
	return func(next nethttp.RoundTripper) nethttp.RoundTripper {
		// Apply middleware in reverse order so they execute in config order
		result := next
		for i := len(middleware) - 1; i >= 0; i-- {
			result = middleware[i](result)
		}
		return result
	}
}
