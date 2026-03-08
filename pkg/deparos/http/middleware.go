package http

import (
	"context"
	"math"
	nethttp "net/http"
	"sync"
	"time"
)

// RetryConfig configures retry behavior.
type RetryConfig struct {
	// MaxAttempts is the maximum number of attempts (including first request).
	// Burp default: 3 (1 initial + 2 retries)
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
}

// DefaultRetryConfig returns default retry configuration matching Burp Suite.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:          3,
		InitialBackoff:       100 * time.Millisecond,
		MaxBackoff:           5 * time.Second,
		BackoffMultiplier:    2.0,
		RetryableStatusCodes: []int{429, 503},
	}
}

// RetryMiddleware returns a middleware that retries failed requests with exponential backoff.
// Matches Burp's retry logic in cq5.java.
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

func (r *retryRoundTripper) RoundTrip(req *nethttp.Request) (*nethttp.Response, error) {
	var resp *nethttp.Response
	var err error

	for attempt := 1; attempt <= r.config.MaxAttempts; attempt++ {
		// Clone request for retry (body may have been consumed)
		reqClone := req.Clone(req.Context())

		// Execute request
		resp, err = r.next.RoundTrip(reqClone)

		// Check if we should retry
		shouldRetry := false

		// Retry on network errors
		if err != nil && IsRetryable(err) {
			shouldRetry = true
		}

		// Retry on retryable status codes
		if resp != nil {
			for _, code := range r.config.RetryableStatusCodes {
				if resp.StatusCode == code {
					shouldRetry = true
					// Close response body before retry
					_ = resp.Body.Close()
					break
				}
			}
		}

		// If successful or last attempt, return
		if !shouldRetry || attempt == r.config.MaxAttempts {
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
		backoff := r.calculateBackoff(attempt)

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
