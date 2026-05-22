package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestWithContext_CancelsInFlightExecute proves that a context bound via
// WithContext aborts an in-flight context-less Execute — the mechanism the
// executor relies on to cancel legacy active modules at their per-module
// timeout. Without WithContext, Execute waits for the slow server.
func TestWithContext_CancelsInFlightExecute(t *testing.T) {
	opts := types.DefaultOptions()
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	svc := &services.Services{Options: opts}
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}

	// Server holds the connection open well past the bound below.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(800 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rr, err := httpmsg.GetRawRequestFromURL(srv.URL)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, execErr := r.WithContext(ctx).Execute(rr, Options{NoClustering: true})
	elapsed := time.Since(start)

	if execErr == nil {
		t.Fatal("expected Execute to fail when the bound context is cancelled")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Execute did not honour the bound context: took %s (cancel at 150ms, server sleeps 800ms)", elapsed)
	}
}

func TestWithContext_NilReturnsReceiver(t *testing.T) {
	r := &Requester{}
	// Deliberately exercise the documented nil-context path; use a typed nil so
	// staticcheck (SA1012) doesn't flag the intentional nil literal.
	var nilCtx context.Context
	if r.WithContext(nilCtx) != r {
		t.Error("WithContext(nil) should return the receiver unchanged")
	}
	bound := r.WithContext(context.Background())
	if bound == r {
		t.Error("WithContext(ctx) should return a distinct copy")
	}
	if bound.defaultCtx == nil {
		t.Error("WithContext(ctx) should set defaultCtx")
	}
}
