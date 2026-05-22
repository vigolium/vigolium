package ssti_blind

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const (
	// slowDelay exceeds the module's 6s slowMinDuration.
	slowDelay = 7 * time.Second
	// fastDelay must stay under the 3s fastMaxDuration (and keep the
	// slow-vs-fast separation ≥ 3s) while exceeding the requester's 500ms
	// clustering cache TTL — otherwise the module's repeated slow probes would
	// be served from cache instead of re-stalling on the server.
	fastDelay = 700 * time.Millisecond
)

// queryHasSlowExpr reports whether a query parameter carries one of the heavy
// (long-loop) SSTI expressions. The slow variants all use the literal 50000000
// iteration count; the paired fast probes use 1.
func queryHasSlowExpr(r *http.Request) bool {
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if strings.Contains(v, "50000000") {
				return true
			}
		}
	}
	return false
}

// vulnerableTemplateHandler emulates a server-side template engine that actually
// evaluates the injected expression: the heavy loop stalls the response past the
// slow threshold while the trivial loop returns after a short cache-busting
// delay. Status flushes immediately to satisfy the 5s ResponseHeaderTimeout.
func vulnerableTemplateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slow := queryHasSlowExpr(r)
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if slow {
			time.Sleep(slowDelay)
		} else {
			time.Sleep(fastDelay)
		}
		_, _ = w.Write([]byte("rendered"))
	}
}

// TestScanPerInsertionPoint_DetectsTimeBlindSSTI drives the real scan method's
// time-delay fallback (no OAST) against a vulnerable template engine. The
// interleaved slow/fast probes must confirm a Tentative finding.
func TestScanPerInsertionPoint_DetectsTimeBlindSSTI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	t.Parallel()
	srv := httptest.NewServer(vulnerableTemplateHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/render?name=guest")
	ip := modtest.InsertionPoint(t, rr, "name")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a time-based blind SSTI finding when the slow template expression stalls the response")
	assert.Equal(t, "name", res[0].FuzzingParameter)
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a uniformly fast server (one
// that never evaluates the injected template) yields no finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("rendered"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/render?name=guest")
	ip := modtest.InsertionPoint(t, rr, "name")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never evaluates the template must not yield a blind SSTI finding")
}

// TestMinMaxDuration exercises the pure timing aggregation helpers.
func TestMinMaxDuration(t *testing.T) {
	t.Parallel()
	d := []time.Duration{3 * time.Second, time.Second, 2 * time.Second}
	assert.Equal(t, time.Second, minDuration(d))
	assert.Equal(t, 3*time.Second, maxDuration(d))
	assert.Equal(t, time.Duration(0), minDuration(nil))
	assert.Equal(t, time.Duration(0), maxDuration(nil))
}
