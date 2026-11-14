package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// hitCountingServer answers 200 and records every path it was asked for.
func hitCountingServer(t *testing.T, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFilterMiddleware(t *testing.T) {
	t.Run("refused request never reaches the server", func(t *testing.T) {
		var hits atomic.Int64
		srv := hitCountingServer(t, &hits)

		client := NewClient(&ClientConfig{
			Middleware: []Middleware{
				FilterMiddleware(func(r *http.Request) bool { return r.URL.Path != "/admin" }),
				RetryMiddleware(DefaultRetryConfig()),
			},
		})

		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/admin", nil)
		rc, err := client.Send(context.Background(), req)
		if rc != nil {
			rc.Close()
		}
		if err == nil {
			t.Fatal("expected the filtered request to fail")
		}
		if !errors.Is(err, ErrRequestFiltered) {
			t.Fatalf("expected ErrRequestFiltered, got %v", err)
		}
		// The whole point: the excluded path was not contacted at all.
		if got := hits.Load(); got != 0 {
			t.Fatalf("server saw %d hit(s) for an excluded path, want 0", got)
		}
		// A refused request must not look like a flapping network, or enough of
		// them in a row cancels the discovery run.
		if IsRetryable(err) {
			t.Fatal("ErrRequestFiltered must not be retryable")
		}
	})

	t.Run("allowed request passes through", func(t *testing.T) {
		var hits atomic.Int64
		srv := hitCountingServer(t, &hits)

		client := NewClient(&ClientConfig{
			Middleware: []Middleware{
				FilterMiddleware(func(r *http.Request) bool { return r.URL.Path != "/admin" }),
			},
		})

		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/public", nil)
		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("allowed request failed: %v", err)
		}
		rc.Close()
		if got := hits.Load(); got != 1 {
			t.Fatalf("server saw %d hit(s), want 1", got)
		}
	})

	t.Run("nil allow returns the transport unwrapped", func(t *testing.T) {
		base := http.DefaultTransport
		if got := FilterMiddleware(nil)(base); got != base {
			t.Fatal("a nil allow predicate must not wrap the transport")
		}
	})

	t.Run("filtered request is not retried", func(t *testing.T) {
		// Retry INSIDE the filter: proves the filter short-circuits before the
		// retry loop can see anything, whichever order a caller builds.
		var reached atomic.Int64
		client := NewClient(&ClientConfig{
			Middleware: []Middleware{
				FilterMiddleware(func(*http.Request) bool { return false }),
				CountingMiddleware(&reached),
				RetryMiddleware(&RetryConfig{MaxAttempts: 3, InitialBackoff: time.Millisecond}),
			},
		})
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://127.0.0.1:1/x", nil)
		rc, err := client.Send(context.Background(), req)
		if rc != nil {
			rc.Close()
		}
		if !errors.Is(err, ErrRequestFiltered) {
			t.Fatalf("expected ErrRequestFiltered, got %v", err)
		}
		if got := reached.Load(); got != 0 {
			t.Fatalf("%d attempt(s) got past the filter, want 0", got)
		}
	})
}

func TestCountingMiddleware(t *testing.T) {
	t.Run("counts every physical attempt including retries", func(t *testing.T) {
		var served atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if served.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		var sent atomic.Int64
		client := NewClient(&ClientConfig{
			Middleware: []Middleware{
				RetryMiddleware(&RetryConfig{
					MaxAttempts:          3,
					InitialBackoff:       time.Millisecond,
					BackoffMultiplier:    2.0,
					RetryableStatusCodes: []int{503},
				}),
				// Innermost: it must see the retry, not the logical request.
				CountingMiddleware(&sent),
			},
		})

		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
		rc, err := client.Send(context.Background(), req)
		if err != nil {
			t.Fatalf("send failed: %v", err)
		}
		defer rc.Close()
		if rc.Response().StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", rc.Response().StatusCode)
		}
		if got := sent.Load(); got != 2 {
			t.Fatalf("counted %d attempts, want 2 (503 then 200)", got)
		}
	})

	t.Run("counts a failed attempt", func(t *testing.T) {
		var sent atomic.Int64
		client := NewClient(&ClientConfig{
			Middleware:     []Middleware{CountingMiddleware(&sent)},
			RequestTimeout: 200 * time.Millisecond,
		})
		// Port 1 refuses: an attempt was still made.
		req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://127.0.0.1:1/", nil)
		rc, err := client.Send(context.Background(), req)
		if rc != nil {
			rc.Close()
		}
		if err == nil {
			t.Fatal("expected a connection error")
		}
		if got := sent.Load(); got != 1 {
			t.Fatalf("counted %d attempts, want 1", got)
		}
	})

	t.Run("nil counter returns the transport unwrapped", func(t *testing.T) {
		base := http.DefaultTransport
		if got := CountingMiddleware(nil)(base); got != base {
			t.Fatal("a nil counter must not wrap the transport")
		}
	})

	t.Run("concurrent round trips", func(t *testing.T) {
		var hits atomic.Int64
		srv := hitCountingServer(t, &hits)

		var sent atomic.Int64
		client := NewClient(&ClientConfig{
			Middleware: []Middleware{CountingMiddleware(&sent)},
		})

		const n = 32
		done := make(chan struct{}, n)
		for i := 0; i < n; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
				rc, err := client.Send(context.Background(), req)
				if err == nil {
					rc.Close()
				}
			}()
		}
		for i := 0; i < n; i++ {
			<-done
		}
		if got := sent.Load(); got != n {
			t.Fatalf("counted %d attempts, want %d", got, n)
		}
	})
}

func TestEgressMiddlewareForwardsCloseIdle(t *testing.T) {
	// A middleware that swallows CloseIdleConnections leaks the whole chain's
	// connection pool for the life of the process — see forwardCloseIdle.
	var closed atomic.Int64
	base := &closeIdleRecorder{n: &closed}

	var counter atomic.Int64
	for _, mw := range []Middleware{
		FilterMiddleware(func(*http.Request) bool { return true }),
		CountingMiddleware(&counter),
	} {
		rt := mw(base)
		c, ok := rt.(interface{ CloseIdleConnections() })
		if !ok {
			t.Fatalf("%T does not implement CloseIdleConnections", rt)
		}
		c.CloseIdleConnections()
	}
	if got := closed.Load(); got != 2 {
		t.Fatalf("idle-close reached the transport %d times, want 2", got)
	}
}

type closeIdleRecorder struct {
	n *atomic.Int64
}

func (c *closeIdleRecorder) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not used")
}

func (c *closeIdleRecorder) CloseIdleConnections() { c.n.Add(1) }
