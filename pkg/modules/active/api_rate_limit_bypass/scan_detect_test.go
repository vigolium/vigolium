package api_rate_limit_bypass

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// nonClusteringRequester builds an *http.Requester with request clustering
// disabled. The module's burst phase sends N *identical* requests to provoke a
// 429; modtest.Requester uses DefaultOptions (ClusterRequests=true), which
// collapses identical sequential requests into a single cached round-trip, so
// the server can never count them up to its rate-limit threshold. Disabling
// clustering lets the burst actually reach the test server.
func nonClusteringRequester(t testing.TB) *httpRequester.Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Timeout = 30
	opts.Retries = 1
	opts.MaxHostError = 100
	opts.MaxPerHost = 20
	opts.ClusterRequests = false

	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	svc := &services.Services{
		Options:     opts,
		HostLimiter: hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{MaxPerHost: opts.MaxPerHost}),
		HostErrors:  hosterrors.New(opts.MaxHostError, hosterrors.DefaultMaxHostsCount, nil),
	}
	client, err := httpRequester.NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	return client
}

// TestScanPerHost_DetectsBypassableRateLimit drives the real scan method against
// a backend that enforces a rate limit (429 after a few requests) but trusts an
// IP-spoofing header: any request carrying an X-Forwarded-For / X-Real-IP style
// header is treated as a fresh client and served 200. The module first triggers
// the 429, then circumvents it with a spoofing header.
func TestScanPerHost_DetectsBypassableRateLimit(t *testing.T) {
	t.Parallel()
	var plain int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any IP-spoofing header resets the limiter for the "new" client.
		if hasSpoofHeader(r) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		// Otherwise enforce a limit: 429 after the third unspoofed request.
		if atomic.AddInt64(&plain, 1) > 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := nonClusteringRequester(t)
	// CanProcess requires a captured response, so seed a baseline.
	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/data"), "text/plain", "ok")
	require.True(t, New().CanProcess(rr))

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a bypass finding when a spoofing header circumvents the 429 limit")
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.False(t, res[0].Metadata["bucket_rotation_proven"].(bool))
}

func TestScanPerHost_ConfirmsPerIdentityBucketRotation(t *testing.T) {
	t.Parallel()
	counts := make(map[string]int)
	var plain int
	var requests int64
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		identity := firstSpoofHeader(r)
		mu.Lock()
		defer mu.Unlock()
		if identity == "" {
			plain++
			if plain > 3 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		} else {
			counts[identity]++
			if counts[identity] > 4 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/data"), "text/plain", "ok")
	res, err := New().ScanPerHost(rr, nonClusteringRequester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindFinding, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeBypass, res[0].EvidenceGrade)
	assert.True(t, res[0].Metadata["bucket_rotation_proven"].(bool))
}

func TestScanPerHost_LoopbackAllowlistIsNotRateLimitProof(t *testing.T) {
	t.Parallel()
	var plain int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, value := range r.Header.Values("X-Forwarded-For") {
			if value == "127.0.0.1" {
				_, _ = w.Write([]byte("ok"))
				return
			}
		}
		if atomic.AddInt64(&plain, 1) > 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/data"), "text/plain", "ok")
	res, err := New().ScanPerHost(rr, nonClusteringRequester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

// TestScanPerHost_NoFalsePositive ensures a backend that never rate-limits
// (always 200) yields no finding — there is nothing to bypass.
func TestScanPerHost_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := nonClusteringRequester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/data"), "text/plain", "ok")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a backend with no rate limiting must not yield a bypass finding")
}

// TestScanPerHost_NoFalsePositive_WindowReset reproduces the rate-limit-window
// false positive: the limiter trips a single 429 (4th request) to make the
// module enter its bypass phase, but then the window "resets" and every later
// request — with or without a spoofing header — succeeds. The apparent bypass
// is purely the reset window, not the header. The differential re-confirmation
// (a plain request must STILL be 429) must reject it.
func TestScanPerHost_NoFalsePositive_WindowReset(t *testing.T) {
	t.Parallel()
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 429 exactly once to trip detection during the burst, then the limiter
		// forgets — header-agnostic, so plain requests succeed again too.
		if atomic.AddInt64(&counter, 1) == 4 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := nonClusteringRequester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/api/data"), "text/plain", "ok")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a reset rate-limit window must not be reported as a header bypass")
}

// hasSpoofHeader reports whether r carries any of the IP-spoofing headers the
// module probes with.
func hasSpoofHeader(r *http.Request) bool {
	for _, h := range []string{
		"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
		"X-Client-IP", "True-Client-IP", "X-Custom-IP-Authorization",
	} {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

func firstSpoofHeader(r *http.Request) string {
	for _, h := range []string{
		"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
		"X-Client-IP", "True-Client-IP", "X-Custom-IP-Authorization",
	} {
		if value := r.Header.Get(h); value != "" {
			return value
		}
	}
	return ""
}
