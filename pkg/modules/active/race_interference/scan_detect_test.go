package race_interference

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestFirstCleanProbe verifies the contrast-probe selector: it returns the first
// successful, baseline-matching sibling that carries no wrong id and is not the
// divergent probe itself, so a race finding can show a corrupted request next to
// a clean one. Errored, wrong-id, divergent, and the excluded probe are skipped.
func TestFirstCleanProbe(t *testing.T) {
	t.Parallel()
	hdr := http.Header{"Content-Type": {"text/plain"}}
	baseline := NewResponseGroup(200, "hello world", hdr)

	divergent := &ProbeResult{Index: 0, StatusCode: 500, Body: "boom", Headers: hdr, Request: "r0", Response: "resp0"}
	errored := &ProbeResult{Index: 1, Err: assert.AnError}
	withWrong := &ProbeResult{Index: 2, StatusCode: 200, Body: "hello world", Headers: hdr, Request: "r2", HasWrongId: true}
	clean := &ProbeResult{Index: 3, StatusCode: 200, Body: "hello world", Headers: hdr, Request: "r3", Response: "resp3"}

	got := firstCleanProbe([]*ProbeResult{divergent, errored, withWrong, clean}, baseline, divergent)
	require.NotNil(t, got, "expected the clean baseline-matching sibling")
	assert.Equal(t, "r3", got.Request)

	// With no clean sibling available, returns nil rather than the divergent/
	// wrong-id/errored probes.
	assert.Nil(t, firstCleanProbe([]*ProbeResult{divergent, errored, withWrong}, baseline, divergent),
		"no clean sibling → nil")
}

// TestScanPerInsertionPoint_DetectsInputStorage drives the real scan method
// against a backend that exhibits an input-storage race: it echoes the *previous*
// request's parameter value (shared mutable state) alongside the current one.
// Because the canary anchor is reflected and sequential probes see a stored
// value carrying a different probe index than the one they sent, the module
// flags an Input Storage race condition.
func TestScanPerInsertionPoint_DetectsInputStorage(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var prev string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := r.URL.Query().Get("q")
		mu.Lock()
		stored := prev
		prev = cur
		mu.Unlock()
		// Reflect both the previous (stored) and current values. The stored value
		// from an earlier probe carries that probe's index right after the anchor,
		// which is "wrong" relative to the current probe's expected index.
		_, _ = fmt.Fprintf(w, "<html><body>current=%s stored=%s</body></html>", cur, stored)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/search?q=seed")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a race finding when input from one request is stored and served to another")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a stateless backend that
// never reflects the parameter (and serves a stable response) short-circuits
// before any race classification: the module bails when its canary anchor is
// not reflected, so no finding is produced.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Static page — the q value is never echoed, so the anchor is not reflected.
		_, _ = w.Write([]byte("<html><body>static results page, no reflection</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/search?q=seed")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-reflecting backend must not yield a race finding")
}
