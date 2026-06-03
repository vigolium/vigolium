package authz_compare

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
	"github.com/vigolium/vigolium/pkg/types"
)

// sessionMarkerHeader lets a session-aware test server tell the compare session
// apart from the primary one — mirroring how real compare requesters carry
// per-session auth headers.
const sessionMarkerHeader = "X-Vgn-Session"

// requesterWithMarker builds a requester that stamps the session marker header on
// every request it sends.
func requesterWithMarker(t *testing.T, marker string) *httpRequester.Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Timeout = 30
	opts.Retries = 1
	opts.MaxHostError = 100
	opts.MaxPerHost = 10
	opts.Headers = []string{sessionMarkerHeader + ": " + marker}
	require.NoError(t, network.Init(opts))
	svc := &services.Services{
		Options:     opts,
		HostLimiter: hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{MaxPerHost: opts.MaxPerHost}),
		HostErrors:  hosterrors.New(opts.MaxHostError, hosterrors.DefaultMaxHostsCount, nil),
	}
	client, err := httpRequester.NewRequester(opts, svc)
	require.NoError(t, err)
	return client
}

// primaryBody and compareBody are the two structurally identical (same status,
// near-equal length) but content-different responses two sessions see at the
// same endpoint. primaryBody is seeded as the authenticated baseline; the live
// server returns compareBody to the replaying compare session.
var (
	primaryBody = "{\"owner\":\"alice\",\"email\":\"alice@example.com\",\"pad\":\"" + strings.Repeat("x", 300) + "\"}"
	compareBody = "{\"owner\":\"bobxx\",\"email\":\"bobxx@example.com\",\"pad\":\"" + strings.Repeat("y", 300) + "\"}"
)

// TestScanPerRequest_DetectsCrossSessionIDOR drives the real scan method with a
// configured compare session against a backend that serves a different user's
// (structurally similar) object to the compare session — i.e. it never enforces
// per-session object ownership. The primary baseline is alice's record; the
// replay returns bob's record with a 200, so the module flags missing
// authorization.
func TestScanPerRequest_DetectsCrossSessionIDOR(t *testing.T) {
	t.Parallel()
	// Session-aware backend: the compare session sees a different user's
	// (structurally similar) object, while the primary session — including the
	// determinism gate's self-refetch — consistently sees its own. A real
	// cross-session IDOR looks exactly like this.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get(sessionMarkerHeader) == "session-b" {
			_, _ = w.Write([]byte(compareBody))
			return
		}
		_, _ = w.Write([]byte(primaryBody))
	}))
	defer srv.Close()

	compareClient := requesterWithMarker(t, "session-b")
	mod := New()
	mod.SetCompareClients([]*httpRequester.Requester{compareClient}, []string{"session-b"})
	require.True(t, mod.HasCompareClients())

	primaryClient := modtest.Requester(t)
	// Seed the primary session's authenticated baseline (alice's object).
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/account"),
		"application/json",
		primaryBody,
	)
	require.True(t, mod.CanProcess(rr))

	res, err := mod.ScanPerRequest(rr, primaryClient, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a cross-session IDOR finding when the compare session sees a different object")
}

// TestScanPerRequest_NoFalsePositive ensures a backend that enforces
// authorization for the compare session (403) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	compareClient := modtest.Requester(t)
	mod := New()
	mod.SetCompareClients([]*httpRequester.Requester{compareClient}, []string{"session-b"})

	primaryClient := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/account"),
		"application/json",
		primaryBody,
	)

	res, err := mod.ScanPerRequest(rr, primaryClient, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 403 for the compare session means authorization is enforced — no finding")
}

// TestScanPerRequest_NonDeterministicEndpointNoFalsePositive reproduces the
// classic cross-session-IDOR false positive: an endpoint that serves different
// (structurally similar) content on EVERY request regardless of session — an
// analytics beacon, ad rotator, or randomized bundle. The compare session's
// "different" body looks like another user's object, but the determinism gate's
// primary self-refetch shows the primary session varies just as much, so the
// difference is within the endpoint's own noise and must not be reported.
func TestScanPerRequest_NonDeterministicEndpointNoFalsePositive(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Rotate a non-numeric token every request (digits would be collapsed as
		// dynamic noise by the differential, so vary letters instead). Same shape
		// and length each time → structurally similar, content always different.
		c := atomic.AddInt64(&n, 1)
		tok := strings.Repeat(string(rune('a'+(c%26))), 12)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"owner":"%s","note":"%s","pad":"%s"}`, tok, tok, strings.Repeat("z", 300))
	}))
	defer srv.Close()

	compareClient := requesterWithMarker(t, "session-b")
	mod := New()
	mod.SetCompareClients([]*httpRequester.Requester{compareClient}, []string{"session-b"})

	primaryClient := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/feed"),
		"application/json",
		`{"owner":"aaaaaaaaaaaa","note":"aaaaaaaaaaaa","pad":"`+strings.Repeat("z", 300)+`"}`,
	)

	res, err := mod.ScanPerRequest(rr, primaryClient, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-deterministic endpoint must not be reported as cross-session IDOR")
}

// TestCanProcess_SkipsWithoutCompareClients verifies the module is inert until
// at least one compare session is configured.
func TestCanProcess_SkipsWithoutCompareClients(t *testing.T) {
	t.Parallel()
	mod := New()
	assert.False(t, mod.HasCompareClients())
	rr := modtest.Response(modtest.Request(t, "http://example.com/api/account"), "application/json", primaryBody)
	assert.False(t, mod.CanProcess(rr), "CanProcess must be false without compare sessions")
}
