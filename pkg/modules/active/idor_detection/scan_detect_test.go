package idor_detection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// objectBody renders a fixed-width object body for the given id so that the
// baseline and neighbor responses are structurally identical (same status, near
// identical length) yet have different content — exactly the IDOR signal the
// module looks for. The "email" field guarantees the body is well over the
// module's 50-byte floor.
func objectBody(id string) string {
	return fmt.Sprintf("{\"user_id\":\"%5s\",\"email\":\"user%5s@example.com\",\"pad\":%q}",
		id, id, strings.Repeat("x", 200))
}

// TestScanPerInsertionPoint_DetectsIDOR drives the real scan method against a
// backend that serves a valid object for any neighbor user_id. The module
// classifies user_id=12345 as a predictable object id, probes 12344/12346/...,
// and reports because the neighbor returns a structurally similar 200 with
// different content.
func TestScanPerInsertionPoint_DetectsIDOR(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("user_id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody(id)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		objectBody("12345"),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an IDOR finding when neighbor user_ids return distinct, structurally similar objects")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a backend that enforces
// authorization (403 for any id but the owner's) yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("user_id") != "12345" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(objectBody("12345")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		objectBody("12345"),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "403 for neighbor user_ids means authorization is enforced — no finding")
}

// noiseBody renders a fixed-length body whose only variable part is a 20-digit
// counter token. Two such bodies are always structurally identical (same status,
// identical length) yet byte-different — the shape of an analytics/tracking
// endpoint that returns different content on every request regardless of the id.
func noiseBody(n int64) string {
	return fmt.Sprintf("{\"data\":\"%020d\",\"pad\":%q}", n, strings.Repeat("x", 200))
}

// TestScanPerInsertionPoint_NonDeterministicEndpoint is the regression for the
// classic IDOR false positive: the backend returns different content on every
// request regardless of user_id (a tracking beacon / randomized JS bundle), so a
// neighbor id looks "structurally similar but different" exactly like a real
// BOLA. The determinism gate re-issues the ORIGINAL id, sees the same-id response
// vary just as much, and suppresses the finding.
func TestScanPerInsertionPoint_NonDeterministicEndpoint(t *testing.T) {
	t.Parallel()
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore user_id entirely: every request — same id or not — gets fresh content.
		n := atomic.AddInt64(&counter, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(noiseBody(n)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/profile?user_id=12345"),
		"application/json",
		noiseBody(0),
	)
	ip := modtest.InsertionPoint(t, rr, "user_id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-deterministic endpoint (same id → different content) must not be reported as IDOR")
}
