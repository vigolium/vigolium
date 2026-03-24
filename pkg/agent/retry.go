package agent

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"go.uber.org/zap"
)

// errEmptyAgentOutput is a sentinel error returned when an agent produces zero output.
var errEmptyAgentOutput = errors.New("agent returned empty output (0 tokens)")

// RetryConfig controls retry behavior for agent calls.
type RetryConfig struct {
	MaxRetries    int           // maximum number of retries (default: 2)
	InitialDelay  time.Duration // initial backoff delay (default: 2s)
	MaxDelay      time.Duration // maximum backoff delay (default: 30s)
	BackoffFactor float64       // exponential backoff multiplier (default: 2.0)
}

// DefaultRetryConfig returns sensible defaults for agent call retries.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:    2,
		InitialDelay:  2 * time.Second,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
	}
}

// effectiveMaxRetries returns MaxRetries or the default if unset.
// Use MaxRetries=-1 to explicitly disable retries (returns 0).
func (rc RetryConfig) effectiveMaxRetries() int {
	if rc.MaxRetries < 0 {
		return 0
	}
	if rc.MaxRetries > 0 {
		return rc.MaxRetries
	}
	return 2
}

// effectiveInitialDelay returns InitialDelay or the default if unset.
func (rc RetryConfig) effectiveInitialDelay() time.Duration {
	if rc.InitialDelay > 0 {
		return rc.InitialDelay
	}
	return 2 * time.Second
}

// effectiveMaxDelay returns MaxDelay or the default if unset.
func (rc RetryConfig) effectiveMaxDelay() time.Duration {
	if rc.MaxDelay > 0 {
		return rc.MaxDelay
	}
	return 30 * time.Second
}

// effectiveBackoffFactor returns BackoffFactor or the default if unset.
func (rc RetryConfig) effectiveBackoffFactor() float64 {
	if rc.BackoffFactor > 0 {
		return rc.BackoffFactor
	}
	return 2.0
}

// retryAgentCall executes fn with exponential backoff on retryable errors.
// It returns the result of the first successful call, or the last error after all retries.
func retryAgentCall[T any](ctx context.Context, cfg RetryConfig, fn func(ctx context.Context, attempt int) (T, error)) (T, error) {
	maxRetries := cfg.effectiveMaxRetries()
	delay := cfg.effectiveInitialDelay()
	maxDelay := cfg.effectiveMaxDelay()
	factor := cfg.effectiveBackoffFactor()

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
		delay = time.Duration(math.Min(float64(delay)*factor, float64(maxDelay)))
	}

	return lastResult, lastErr
}

// isRetryableAgentError returns true if the error is a transient agent error
// that can be retried (e.g., deadline exceeded, prompt timeout, empty output).
// It does NOT retry when the parent context itself is cancelled.
func isRetryableAgentError(ctx context.Context, err error) bool {
	// If the parent context is done, retrying won't help
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, errEmptyAgentOutput) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "ACP prompt timed out") ||
		strings.Contains(msg, "ACP initialize timed out") ||
		strings.Contains(msg, "ACP session creation timed out") ||
		strings.Contains(msg, "ACP prompt failed") ||
		strings.Contains(msg, "SDK query failed") ||
		strings.Contains(msg, "SDK stream error") ||
		strings.Contains(msg, "SDK output collection failed") ||
		strings.Contains(msg, "Codex SDK start failed") ||
		strings.Contains(msg, "Codex SDK initialize failed") ||
		strings.Contains(msg, "Codex SDK turn failed") ||
		strings.Contains(msg, "OpenCode SDK start failed") ||
		strings.Contains(msg, "OpenCode SDK session creation failed") ||
		strings.Contains(msg, "OpenCode SDK prompt failed") ||
		strings.Contains(msg, "empty output")
}
