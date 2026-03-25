package agent

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Sentinel errors for agent backend failures. These enable reliable retry
// classification via errors.Is() instead of fragile string matching.
var (
	errEmptyAgentOutput = errors.New("agent returned empty output (0 tokens)")

	// ACP backend errors
	errACPPromptTimeout  = errors.New("acp prompt timed out")
	errACPInitTimeout    = errors.New("acp initialize timed out")
	errACPSessionTimeout = errors.New("acp session creation timed out")
	errACPPromptFailed   = errors.New("acp prompt failed")

	// SDK backend errors
	errSDKQueryFailed  = errors.New("sdk query failed")
	errSDKStreamError  = errors.New("sdk stream error")
	errSDKOutputFailed = errors.New("sdk output collection failed")

	// Codex backend errors
	errCodexStartFailed = errors.New("codex SDK start failed")
	errCodexInitFailed  = errors.New("codex SDK initialize failed")
	errCodexTurnFailed  = errors.New("codex SDK turn failed")

	// OpenCode backend errors
	errOpenCodeStartFailed   = errors.New("opencode SDK start failed")
	errOpenCodeSessionFailed = errors.New("opencode SDK session creation failed")
	errOpenCodePromptFailed  = errors.New("opencode SDK prompt failed")
)

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

// retryableSentinels lists all sentinel errors that should trigger a retry.
var retryableSentinels = []error{
	context.DeadlineExceeded,
	errEmptyAgentOutput,
	errACPPromptTimeout,
	errACPInitTimeout,
	errACPSessionTimeout,
	errACPPromptFailed,
	errSDKQueryFailed,
	errSDKStreamError,
	errSDKOutputFailed,
	errCodexStartFailed,
	errCodexInitFailed,
	errCodexTurnFailed,
	errOpenCodeStartFailed,
	errOpenCodeSessionFailed,
	errOpenCodePromptFailed,
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
