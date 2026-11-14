package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// retryServer answers status (with retryAfter, when set) until the last
// attempt, then 200, counting the attempts.
func retryServer(t *testing.T, status int, retryAfter string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		if n.Add(1) == 1 {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(nethttp.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func retryClient(cfg *RetryConfig) *nethttp.Client {
	return &nethttp.Client{Transport: RetryMiddleware(cfg)(nethttp.DefaultTransport)}
}

func statusRetryConfig() *RetryConfig {
	cfg := DefaultRetryConfig()
	cfg.InitialBackoff = time.Millisecond
	cfg.MinStatusBackoff = 80 * time.Millisecond
	cfg.MaxRetryAfter = 2 * time.Second
	return cfg
}

// Status retries wait as long as the server asked (within MaxRetryAfter) and
// never less than MinStatusBackoff; a Retry-After beyond the cap is returned
// at once rather than retried.
func TestRetryStatusWait(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		retryAfter   string
		wantStatus   int
		wantAttempts int64
		minWait      time.Duration
		maxWait      time.Duration
	}{
		{"429 without Retry-After waits MinStatusBackoff", nethttp.StatusTooManyRequests, "", 200, 2, 80 * time.Millisecond, 0},
		{"Retry-After within the cap is honored", nethttp.StatusServiceUnavailable, "1", 200, 2, time.Second, 0},
		{"Retry-After beyond the cap is not retried", nethttp.StatusTooManyRequests, "120", nethttp.StatusTooManyRequests, 1, 0, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, n := retryServer(t, tc.status, tc.retryAfter)
			start := time.Now()
			resp, err := retryClient(statusRetryConfig()).Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			elapsed := time.Since(start)
			if resp.StatusCode != tc.wantStatus || n.Load() != tc.wantAttempts {
				t.Fatalf("status %d after %d attempts, want %d after %d", resp.StatusCode, n.Load(), tc.wantStatus, tc.wantAttempts)
			}
			if elapsed < tc.minWait {
				t.Errorf("returned after %v, want at least %v", elapsed, tc.minWait)
			}
			if tc.maxWait > 0 && elapsed > tc.maxWait {
				t.Errorf("returned after %v, want under %v", elapsed, tc.maxWait)
			}
		})
	}
}
