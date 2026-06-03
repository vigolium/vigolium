package idor_guid

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

// TestScanPerInsertionPoint_DetectsSequentialIDOR drives the real scan method
// against a backend that serves a valid (200, distinct-content) object for any
// numeric id — including the original id's neighbors. The module predicts
// id+/-1, fetches them, and reports because the neighbor returns a 200 whose
// body differs from the baseline.
func TestScanPerInsertionPoint_DetectsSequentialIDOR(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// Each id yields a valid object whose content embeds the id, so neighbor
		// responses are 200 and differ from the baseline body. Padding keeps the
		// body comfortably over the module's 100-byte floor.
		_, _ = fmt.Fprintf(w, "{\"id\":%q,\"owner\":%q,\"secret\":%q,\"pad\":%q}",
			id, "user-"+id, "token-"+id, strings.Repeat("x", 120))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Baseline carries the original object; the module compares neighbors to it.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/objects?id=100"),
		"application/json",
		"{\"id\":\"100\",\"owner\":\"user-100\",\"secret\":\"token-100\",\"pad\":\""+strings.Repeat("x", 120)+"\"}",
	)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an IDOR finding when neighbor ids return valid distinct objects")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a backend that enforces
// authorization (404 for any id but the owner's) yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "100" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		_, _ = w.Write([]byte("{\"id\":\"100\",\"owner\":\"user-100\",\"pad\":\"" + strings.Repeat("x", 120) + "\"}"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/objects?id=100"),
		"application/json",
		"{\"id\":\"100\",\"owner\":\"user-100\",\"pad\":\""+strings.Repeat("x", 120)+"\"}",
	)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "404 for neighbor ids means authorization is enforced — no finding")
}

// noiseBody renders a body (comfortably over the module's 100-byte floor) whose
// only variable part is a 20-digit counter token, so two such bodies are always
// 200/distinct — the shape of a tracking endpoint that returns different content
// on every request regardless of the id.
func noiseBody(n int64) string {
	return fmt.Sprintf("{\"data\":\"%020d\",\"pad\":%q}", n, strings.Repeat("x", 120))
}

// TestScanPerInsertionPoint_NonDeterministicEndpoint is the regression for the
// sequential-id false positive: the backend returns different content on every
// request regardless of the id, so a predicted id+/-1 "returns a valid different
// resource" exactly like a real predictable-reference IDOR. The determinism gate
// re-issues the ORIGINAL id, sees the same-id response vary just as much, and
// suppresses the finding.
func TestScanPerInsertionPoint_NonDeterministicEndpoint(t *testing.T) {
	t.Parallel()
	var counter int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore id entirely: every request gets fresh, distinct content.
		n := atomic.AddInt64(&counter, 1)
		_, _ = w.Write([]byte(noiseBody(n)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/objects?id=100"),
		"application/json",
		noiseBody(0),
	)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-deterministic endpoint (same id → different content) must not be reported as predictable-id IDOR")
}
