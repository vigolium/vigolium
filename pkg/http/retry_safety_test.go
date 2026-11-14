package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func newRetryRequester(t *testing.T, retries int, timeout time.Duration) *Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Retries = retries
	opts.Timeout = timeout
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	svc := &services.Services{Options: opts}
	svc.Egress = egress.New(egress.Config{})
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	r.retryBackoff = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(r.CloseIdleConnections)
	return r
}

// A written request that timed out is never re-sent (SAFE-10): a sleep
// payload or a slow POST would otherwise run twice server-side.
func TestRetry_WrittenTimeoutNotRetried(t *testing.T) {
	var hits atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)

	r := newRetryRequester(t, 1, 300*time.Millisecond)
	rr := httpmsg.NewRequestResponseRaw(
		[]byte("POST /slow HTTP/1.1\r\nHost: "+srv.Listener.Addr().String()+"\r\nContent-Length: 1\r\n\r\nx"),
		serviceFor(t, srv.URL))
	if _, _, err := r.Execute(rr, Options{NoClustering: true}); err == nil {
		t.Fatal("want a timeout error")
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("server hits = %d, want 1 (no retry of a written timeout)", n)
	}

	// RetryTimeouts (preflight baselines) opts back in.
	hits.Store(0)
	get, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/slow")
	_, _, _ = r.Execute(get, Options{NoClustering: true, RetryTimeouts: true})
	if n := hits.Load(); n != 2 {
		t.Errorf("RetryTimeouts: server hits = %d, want 2", n)
	}
}

// A written POST whose connection was reset is not retried; a GET is.
func TestRetry_WrittenResetOnlyIdempotent(t *testing.T) {
	var hits atomic.Int64
	srv := flakyServer(t, 1, &hits)
	r := newRetryRequester(t, 1, 3*time.Second)

	post := httpmsg.NewRequestResponseRaw(
		[]byte("POST /x HTTP/1.1\r\nHost: "+srv.Listener.Addr().String()+"\r\nContent-Length: 1\r\n\r\nx"),
		serviceFor(t, srv.URL))
	if _, _, err := r.Execute(post, Options{NoClustering: true}); err == nil {
		t.Fatal("POST: want the reset error, not a retried success")
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("POST hits = %d, want 1", n)
	}

	hits.Store(0)
	get, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/x")
	resp, _, err := r.Execute(get, Options{NoClustering: true})
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Close()
	if n := hits.Load(); n != 2 {
		t.Errorf("GET hits = %d, want 2 (reset GET is retried)", n)
	}
}

// A request that never reached the server is retried whatever its method;
// once written, only idempotent methods are, and a timeout only on opt-in.
// (A refused dial is classified permanent by fastdialer and was never
// retried; the base rule keeps that, so the not-written case is pinned at the
// decision function.)
func TestRetry_SafeToRetryDecision(t *testing.T) {
	ctx := context.Background()
	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("network unreachable")}
	readErr := &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}
	timeoutErr := &url.Error{Op: "Post", URL: "http://x/", Err: context.DeadlineExceeded}
	cases := []struct {
		name          string
		err           error
		wrote         bool
		method        string
		retryTimeouts bool
		want          bool
	}{
		{"unwritten POST", dialErr, false, "POST", false, true},
		{"written POST reset", readErr, true, "POST", false, false},
		{"written GET reset", readErr, true, "GET", false, true},
		{"written OPTIONS reset", readErr, true, "OPTIONS", false, true},
		{"written GET timeout", timeoutErr, true, "GET", false, false},
		{"written GET timeout opt-in", timeoutErr, true, "GET", true, true},
	}
	for _, tc := range cases {
		if got := safeToRetry(ctx, tc.err, tc.wrote, tc.method, tc.retryTimeouts); got != tc.want {
			t.Errorf("%s: safeToRetry = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// NoRetry sends once even when --retries allows more.
func TestRetry_NoRetryOption(t *testing.T) {
	var hits atomic.Int64
	srv := flakyServer(t, 5, &hits)
	r := newRetryRequester(t, 3, 3*time.Second)
	get, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/x")
	_, _, _ = r.Execute(get, Options{NoClustering: true, NoRetry: true})
	if n := hits.Load(); n != 1 {
		t.Errorf("hits = %d, want 1", n)
	}
}

func serviceFor(t *testing.T, rawURL string) *httpmsg.Service {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return rr.Service()
}
