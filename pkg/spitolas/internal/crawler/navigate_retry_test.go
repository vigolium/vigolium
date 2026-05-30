package crawler

import (
	"context"
	"errors"
	"testing"
)

// TestNavigateWithRetrySucceedsFirstTry verifies a clean navigation is attempted
// exactly once with no retries.
func TestNavigateWithRetrySucceedsFirstTry(t *testing.T) {
	calls := 0
	err := navigateWithRetry(context.Background(), "https://example.com", 0, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 attempt, got %d", calls)
	}
}

// TestNavigateWithRetryRecoversAfterTransientFailures verifies a transient error
// (e.g. net::ERR_CONNECTION_RESET) is retried and the navigation ultimately
// succeeds within the attempt budget.
func TestNavigateWithRetryRecoversAfterTransientFailures(t *testing.T) {
	calls := 0
	err := navigateWithRetry(context.Background(), "https://example.com", 0, func() error {
		calls++
		if calls < initNavAttempts {
			return errors.New("net::ERR_CONNECTION_RESET")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	if calls != initNavAttempts {
		t.Fatalf("expected %d attempts, got %d", initNavAttempts, calls)
	}
}

// TestNavigateWithRetryExhaustsAttempts verifies that a persistently failing
// navigation is retried up to the attempt cap and returns the last error.
func TestNavigateWithRetryExhaustsAttempts(t *testing.T) {
	calls := 0
	wantErr := errors.New("net::ERR_CONNECTION_RESET")
	err := navigateWithRetry(context.Background(), "https://example.com", 0, func() error {
		calls++
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected last navigation error, got %v", err)
	}
	if calls != initNavAttempts {
		t.Fatalf("expected %d attempts, got %d", initNavAttempts, calls)
	}
}

// TestNavigateWithRetryStopsOnCancelledContext verifies a cancelled context
// aborts before any navigation is attempted.
func TestNavigateWithRetryStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := navigateWithRetry(ctx, "https://example.com", 0, func() error {
		calls++
		return errors.New("boom")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected 0 attempts on cancelled context, got %d", calls)
	}
}

// TestNavigateWithRetryDoesNotRetryContextError verifies that when a navigation
// fails because the context expired mid-flight, the loop returns the context
// error instead of burning the remaining retry budget.
func TestNavigateWithRetryDoesNotRetryContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := navigateWithRetry(ctx, "https://example.com", 0, func() error {
		calls++
		cancel() // context expires during the navigation
		return errors.New("net::ERR_CONNECTION_RESET")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected navigation to stop after context cancel, got %d attempts", calls)
	}
}
