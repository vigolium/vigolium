package race_interference

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
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
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, res[0].EvidenceGrade)
	assert.False(t, res[0].Metadata["cross_user_proven"].(bool))
}

func TestBuildResult_DivergenceAloneIsObservation(t *testing.T) {
	t.Parallel()
	finding := &Finding{Type: FindingRequestInterference, Parameter: "q", Anchor: "abc", Request: "GET /", Response: "HTTP/1.1 200 OK"}
	result := New().buildResult(finding, "https://example.com/search", "q", nil)
	assert.Equal(t, output.RecordKindObservation, result.RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, result.EvidenceGrade)
}

// TestScanPerInsertionPoint_NonDeterministicNotInterference reproduces the
// dominant reported false positive: a login/signup-style endpoint that reflects
// the parameter (so the module proceeds) but embeds a per-request nonce (CSRF
// token / SSR shell) so EVERY response diverges — sequentially as well as in
// parallel. The 3-sample baseline under-samples the nonce (it looks stable), so
// the parallel divergence alone would be flagged as a race. The sequential
// determinism control sees the sequential probes diverge too and suppresses it.
func TestScanPerInsertionPoint_NonDeterministicNotInterference(t *testing.T) {
	t.Parallel()
	var count int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		n := atomic.AddInt64(&count, 1)
		// The first 3 hits (the baseline phase) return a STABLE nonce, so the
		// baseline marks the token attributes static. Afterward the endpoint shows
		// its true colours: a per-request token that changes content AND length on
		// every response — with no shared state / cross-contamination.
		token := "stabletoken0"
		if n > 3 {
			token = fmt.Sprintf("t%d%s", n, strings.Repeat("z", int(n%7)))
		}
		_, _ = fmt.Fprintf(w,
			"<html><body>sign in form for query=%s csrf=%s please enter your account credentials to continue now</body></html>",
			q, token)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/login?q=seed")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a page that diverges on sequential probes too (per-request nonce) must not be flagged as request interference")
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
