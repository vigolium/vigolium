package httpmsg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestBuildRetryableRequestWithContext_AttachesContext verifies the supplied
// context is carried by the built request.
func TestBuildRetryableRequestWithContext_AttachesContext(t *testing.T) {
	rr, err := GetRawRequestFromURL("http://example.com/path")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := rr.BuildRetryableRequestWithContext(ctx)
	if err != nil {
		t.Fatalf("BuildRetryableRequestWithContext: %v", err)
	}
	if req.Context() != ctx {
		t.Error("expected the supplied context to be attached to the request")
	}
}

// TestBuildRetryableRequestWithContext_CancelsInFlight proves that cancelling the
// context aborts an in-flight request promptly instead of waiting out the server.
func TestBuildRetryableRequestWithContext_CancelsInFlight(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	rr, err := GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := rr.BuildRetryableRequestWithContext(ctx)
	if err != nil {
		t.Fatalf("BuildRetryableRequestWithContext: %v", err)
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	resp, err := http.DefaultClient.Do(req.Request)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected a cancellation error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("request did not cancel promptly: took %v", elapsed)
	}
}
