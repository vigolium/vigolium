package agent

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestContainsAny(t *testing.T) {
	if !containsAny("hello world", "xyz", "world") {
		t.Error("should match when one substring is present")
	}
	if containsAny("hello", "x", "y") {
		t.Error("should not match when no substring is present")
	}
	if containsAny("hello") {
		t.Error("no substrings should never match")
	}
}

func TestIsRetryableAgentError_StringFallback(t *testing.T) {
	ctx := context.Background()
	// A non-sentinel error whose message contains "empty output" is retryable
	// via the backward-compat string fallback.
	if !isRetryableAgentError(ctx, errors.New("got empty output from provider")) {
		t.Error("empty output substring should be retryable")
	}
}

func TestIsRetryableAgentError_CancelledParentCtx(t *testing.T) {
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if isRetryableAgentError(cctx, errProviderRateLimited) {
		t.Error("cancelled parent context should disable retry even for a retryable sentinel")
	}
}

func TestRetryAgentCall_SucceedsFirstTry(t *testing.T) {
	calls := 0
	got, err := retryAgentCall(context.Background(),
		RetryConfig{MaxRetries: 3, InitialDelay: time.Millisecond},
		func(_ context.Context, _ int) (string, error) {
			calls++
			return "ok", nil
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ok" || calls != 1 {
		t.Errorf("got=%q calls=%d, want ok/1", got, calls)
	}
}

func TestRetryAgentCall_RetriesThenSucceeds(t *testing.T) {
	calls := 0
	got, err := retryAgentCall(context.Background(),
		RetryConfig{MaxRetries: 3, InitialDelay: time.Millisecond, BackoffFactor: 1.0},
		func(_ context.Context, attempt int) (int, error) {
			calls++
			if attempt < 2 {
				return 0, errProviderRateLimited // retryable
			}
			return 42, nil
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 42 {
		t.Errorf("got = %d, want 42", got)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3 (two retries then success)", calls)
	}
}

func TestRetryAgentCall_NonRetryableStopsImmediately(t *testing.T) {
	calls := 0
	terminal := errors.New("401 unauthorized")
	_, err := retryAgentCall(context.Background(),
		RetryConfig{MaxRetries: 5, InitialDelay: time.Millisecond},
		func(_ context.Context, _ int) (int, error) {
			calls++
			return 0, terminal
		})
	if !errors.Is(err, terminal) {
		t.Errorf("expected terminal error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry on terminal error)", calls)
	}
}

func TestRetryAgentCall_ExhaustsRetries(t *testing.T) {
	calls := 0
	_, err := retryAgentCall(context.Background(),
		RetryConfig{MaxRetries: 2, InitialDelay: time.Millisecond, BackoffFactor: 1.0},
		func(_ context.Context, _ int) (int, error) {
			calls++
			return 0, errProviderServerError
		})
	if !errors.Is(err, errProviderServerError) {
		t.Errorf("expected last error, got %v", err)
	}
	// 1 initial + 2 retries = 3 calls.
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestRetryAgentCall_RespectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := retryAgentCall(ctx,
		RetryConfig{MaxRetries: 5, InitialDelay: 50 * time.Millisecond},
		func(_ context.Context, attempt int) (int, error) {
			calls++
			if attempt == 0 {
				cancel() // cancel before the backoff sleep on the retry path
			}
			return 0, errProviderRateLimited
		})
	if err == nil {
		t.Fatal("expected an error on cancellation")
	}
	if calls > 2 {
		t.Errorf("calls = %d, want <= 2 after cancellation", calls)
	}
}

func TestRetryConfig_Defaults(t *testing.T) {
	// MaxRetries=-1 disables retries entirely.
	calls := 0
	_, _ = retryAgentCall(context.Background(),
		RetryConfig{MaxRetries: -1},
		func(_ context.Context, _ int) (int, error) {
			calls++
			return 0, errProviderRateLimited
		})
	if calls != 1 {
		t.Errorf("MaxRetries=-1 should run exactly once, got %d calls", calls)
	}
}
