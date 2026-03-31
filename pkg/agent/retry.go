package agent

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/backend"
	"go.uber.org/zap"
)

// errEmptyAgentOutput is a root-level sentinel for empty agent output (not backend-specific).
var errEmptyAgentOutput = errors.New("agent returned empty output (0 tokens)")

// Backend sentinel errors — aliased from backend package for retry classification.
var (
	errSDKQueryFailed  = backend.ErrSDKQueryFailed
	errSDKStreamError  = backend.ErrSDKStreamError
	errSDKOutputFailed = backend.ErrSDKOutputFailed

	errCodexStartFailed = backend.ErrCodexStartFailed
	errCodexInitFailed  = backend.ErrCodexInitFailed
	errCodexTurnFailed  = backend.ErrCodexTurnFailed

	errOpenCodeStartFailed   = backend.ErrOpenCodeStartFailed
	errOpenCodeSessionFailed = backend.ErrOpenCodeSessionFailed
	errOpenCodePromptFailed  = backend.ErrOpenCodePromptFailed
)

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
