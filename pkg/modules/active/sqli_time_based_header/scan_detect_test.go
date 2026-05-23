package sqli_time_based_header

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

// sleepDelay is just above the module's 12s sleepThreshold so the injected
// sleep payload trips detection while keeping the test as short as possible.
const sleepDelay = 13 * time.Second

// noSleepDelay is applied to the paired no-sleep probe. It must stay well under
// the 12s threshold (so the module sees it as "fast") yet exceed the requester's
// 500ms request-clustering cache TTL — otherwise the module's third probe (a
// byte-identical repeat of the first sleep payload) would be served from the
// clustered cache instantly and never re-trip the timing threshold.
const noSleepDelay = 700 * time.Millisecond

// hasSleepMarker reports whether any of the injected headers carry a SQL sleep
// payload (SLEEP(15)/pg_sleep(15)/the MSSQL heavy-join/the SQLite randomblob),
// as opposed to the paired no-sleep variant (SLEEP(0)/pg_sleep(0)/select 1).
func hasSleepMarker(r *http.Request) bool {
	for _, vals := range r.Header {
		for _, v := range vals {
			if strings.Contains(v, "SLEEP(15)") ||
				strings.Contains(v, "pg_sleep(15)") ||
				strings.Contains(v, "randomblob(150000000)") ||
				strings.Contains(v, "INFORMATION_SCHEMA.tables as sys6)=0") {
				return true
			}
		}
	}
	return false
}

// vulnerableHeaderHandler emulates a backend whose SQL log/query is fed an
// injectable header: the heavy sleep payload stalls the response past the
// detection threshold while the no-sleep payload returns immediately.
//
// The response status/headers are flushed immediately (the requester aborts on
// a 5s ResponseHeaderTimeout) and the delay is applied before the body is
// written, so the module's body-read timing crosses the sleepThreshold.
func vulnerableHeaderHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hasSleepMarker(r) {
			time.Sleep(sleepDelay)
		} else {
			time.Sleep(noSleepDelay)
		}
		_, _ = w.Write([]byte("ok"))
	}
}

// TestScanPerRequest_DetectsHeaderTimeSQLi drives the real scan method against a
// server that honours an injectable header sleep payload. The module's triple
// verification (sleep → no-sleep → sleep) must confirm the finding.
func TestScanPerRequest_DetectsHeaderTimeSQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	// Not parallel: the triple-verify (sleep → no-sleep → sleep) compares
	// wall-clock timings against a fixed threshold, so it must not contend with
	// sibling tests for CPU/the shared dialer.
	srv := httptest.NewServer(vulnerableHeaderHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	// POST: the module skips GET requests entirely.
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/login", "user=admin")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a time-based header SQLi finding when sleep payload stalls the response")
	assert.Equal(t, "Header", res[0].FuzzingParameter)
}

// TestScanPerRequest_SkipsGET ensures GET requests are not probed (the module
// only injects header sleep payloads on body-bearing requests).
func TestScanPerRequest_SkipsGET(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(vulnerableHeaderHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/login")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "GET requests must be skipped by the header time-based SQLi module")
}

// TestScanPerRequest_NoFalsePositive ensures a fast server that ignores the
// injected header payload yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/login", "user=admin")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never stalls must not yield a header time-based SQLi finding")
}
