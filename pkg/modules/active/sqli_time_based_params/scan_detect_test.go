package sqli_time_based_params

import (
	"io"
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
	// sleepDelay is just above the module's 12s sleepThreshold.
	sleepDelay = 13 * time.Second
	// noSleepDelay stays under the threshold but exceeds the requester's 500ms
	// clustering cache TTL, so the module's third (byte-identical) sleep probe
	// is re-executed against the server rather than served from cache.
	noSleepDelay = 700 * time.Millisecond
)

// payloadHasSleep reports whether s carries a heavy SQL sleep payload as opposed
// to its paired no-sleep variant (SLEEP(0)/pg_sleep(0)/select 1).
func payloadHasSleep(s string) bool {
	return strings.Contains(s, "SLEEP(15)") ||
		strings.Contains(s, "pg_sleep(15)") ||
		strings.Contains(s, "randomblob(150000000)") ||
		strings.Contains(s, "INFORMATION_SCHEMA.tables as sys6)")
}

// requestHasSleep scans both query and body params for a sleep marker.
func requestHasSleep(r *http.Request) bool {
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if payloadHasSleep(v) {
				return true
			}
		}
	}
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		if payloadHasSleep(string(body)) {
			return true
		}
	}
	return false
}

// vulnerableParamHandler emulates a backend whose query is fed an injectable
// parameter: the heavy sleep payload stalls the response past the detection
// threshold; the no-sleep variant returns after a short (cache-busting) delay.
// Headers/status flush immediately to satisfy the 5s ResponseHeaderTimeout.
func vulnerableParamHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slow := requestHasSleep(r)
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if slow {
			time.Sleep(sleepDelay)
		} else {
			time.Sleep(noSleepDelay)
		}
		_, _ = w.Write([]byte("ok"))
	}
}

// TestScanPerRequest_DetectsParamTimeSQLi drives the real scan method against a
// server that honours an injectable query-parameter sleep payload. The module's
// triple verification (sleep → no-sleep → sleep) must confirm the finding.
func TestScanPerRequest_DetectsParamTimeSQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	t.Parallel()
	srv := httptest.NewServer(vulnerableParamHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/search?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a time-based param SQLi finding when sleep payload stalls the response")
	assert.Equal(t, "id", res[0].FuzzingParameter)
}

// TestScanPerRequest_NoFalsePositive ensures a uniformly fast server yields no
// finding regardless of the injected payload.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/search?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never stalls must not yield a time-based param SQLi finding")
}
