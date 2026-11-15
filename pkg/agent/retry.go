package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/stream"
	"go.uber.org/zap"
)

// Sentinel errors used to drive retry classification. Wrap a provider
// error with one of these (via fmt.Errorf("...: %w", sentinel)) so
// retryAgentCall can decide whether to back off and retry.
var (
	// errEmptyAgentOutput signals that olium produced no tokens for a
	// prompt — treated as transient so retries can recover.
	errEmptyAgentOutput = errors.New("agent returned empty output (0 tokens)")

	// errProviderRateLimited covers HTTP 429 / quota / rate-limit responses
	// from any olium provider. Always retryable with backoff.
	errProviderRateLimited = errors.New("provider rate limited")

	// errProviderServerError covers HTTP 5xx responses (and equivalent
	// "service unavailable" / "bad gateway" textual messages). Retryable.
	errProviderServerError = errors.New("provider server error")

	// errProviderNetwork covers transient network failures (connection
	// reset, EOF, i/o timeout, DNS lookup failure, TLS handshake). Retryable.
	errProviderNetwork = errors.New("provider network error")
)

// classifyOliumError inspects a raw provider error message (the Err field
// from oengine.EventError, which itself was the provider's HTTP/SSE error
// stringified) and wraps it with a sentinel so retryAgentCall can decide
// whether to retry. Unrecognized strings are returned verbatim — those
// (e.g. 401/403 auth errors, 400 schema errors) are treated as terminal.
//
// Provider error format conventions (see pkg/olium/provider/*.go):
//
//	"anthropic %d: %s"  — e.g. "anthropic 429: rate_limit_exceeded ..."
//	"openai %d: %s"     — e.g. "openai 503: ..."
//	"codex %d: %s"      — e.g. "codex 429: ..."
//
// That text is produced by stream.StatusError.Error(), and stream.StatusOfText
// parses it back, so the two stay in step.
func classifyOliumError(msg string) error {
	lower := strings.ToLower(msg)

	// The engine already decided this provider is not there (a refused or
	// unresolvable endpoint before any call succeeded): terminal, not a blip.
	if strings.Contains(lower, stream.ErrProviderUnreachable.Error()) {
		return fmt.Errorf("%s: %w", msg, stream.ErrProviderUnreachable)
	}

	// Status-carrying errors classify off the status itself. The numeric
	// table lives in pkg/olium/stream so this cross-call classifier and the
	// engine's in-flight one can't drift - they used to keep separate lists,
	// and had: a Cloudflare 520 retried here but not there, a 425 there but
	// not here.
	if se, ok := stream.StatusOfText(msg); ok && se.Retryable() {
		if se.RateLimited() {
			return fmt.Errorf("%s: %w", msg, errProviderRateLimited)
		}
		return fmt.Errorf("%s: %w", msg, errProviderServerError)
	}

	// Bodies that describe the condition without a status we can read.
	if containsAny(lower, "rate limit", "rate_limit", "rate-limit", "too many requests", "quota") {
		return fmt.Errorf("%s: %w", msg, errProviderRateLimited)
	}
	if containsAny(lower,
		"internal server error", "service unavailable", "bad gateway", "gateway timeout", "overloaded",
	) {
		return fmt.Errorf("%s: %w", msg, errProviderServerError)
	}

	// Network-level transient failures from the Go HTTP stack — shared
	// substring list lives in pkg/olium/stream so the engine's in-flight
	// retry classifier and this cross-call one can't drift apart.
	if containsAny(lower, stream.TransientErrSubstrings...) {
		return fmt.Errorf("%s: %w", msg, errProviderNetwork)
	}

	return errors.New(msg)
}

// containsAny returns true if s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// retryAgentCall executes fn with exponential backoff on retryable errors.
// It returns the result of the first successful call, or the last error after all retries.
func retryAgentCall[T any](ctx context.Context, cfg RetryConfig, fn func(ctx context.Context, attempt int) (T, error)) (T, error) {
	maxRetries := cfg.EffectiveMaxRetries()
	delay := cfg.EffectiveInitialDelay()

	var lastResult T
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		lastResult, lastErr = fn(ctx, attempt)
		if lastErr == nil {
			return lastResult, nil
		}

		// Don't retry on last attempt or non-retryable errors
		if attempt >= maxRetries || !isRetryableAgentError(ctx, lastErr) {
			return lastResult, lastErr
		}

		zap.L().Warn("agent call failed (retryable), will retry",
			zap.Int("attempt", attempt+1),
			zap.Int("maxRetries", maxRetries),
			zap.Duration("backoff", delay),
			zap.Error(lastErr))

		select {
		case <-ctx.Done():
			return lastResult, ctx.Err()
		case <-time.After(delay):
		}

		// Exponential backoff
		delay = cfg.BackoffDelay(delay)
	}

	return lastResult, lastErr
}

// retryableSentinels lists all sentinel errors that should trigger a retry.
var retryableSentinels = []error{
	context.DeadlineExceeded,
	errEmptyAgentOutput,
	errProviderRateLimited,
	errProviderServerError,
	errProviderNetwork,
}

// isRetryableAgentError returns true if the error is a transient agent error
// that can be retried (e.g., deadline exceeded, prompt timeout, empty output).
// It does NOT retry when the parent context itself is cancelled.
func isRetryableAgentError(ctx context.Context, err error) bool {
	// If the parent context is done, retrying won't help
	if ctx.Err() != nil {
		return false
	}
	for _, sentinel := range retryableSentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	// Fallback: string matching for backward compatibility with errors
	// that may not yet use sentinel wrapping (e.g., from external libraries).
	msg := err.Error()
	return strings.Contains(msg, "empty output")
}
