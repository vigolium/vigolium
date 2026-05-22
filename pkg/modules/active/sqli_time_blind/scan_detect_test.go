package sqli_time_blind

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
	// sleepDelay is just above the module's 8s sleepThreshold.
	sleepDelay = 9 * time.Second
	// noSleepDelay stays under the threshold but exceeds the requester's 500ms
	// clustering cache TTL, so the module's third (byte-identical) sleep probe
	// is re-executed against the server instead of served from cache.
	noSleepDelay = 700 * time.Millisecond
)

// queryHasSleep reports whether any query parameter carries a heavy SQL sleep
// payload (SLEEP(10)/pg_sleep(10)/WAITFOR/RANDOMBLOB/DBMS_PIPE 10) rather than
// its paired no-sleep variant.
func queryHasSleep(r *http.Request) bool {
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if strings.Contains(v, "SLEEP(10)") ||
				strings.Contains(v, "pg_sleep(10)") ||
				strings.Contains(v, "WAITFOR DELAY '0:0:10'") ||
				strings.Contains(v, "RANDOMBLOB") ||
				strings.Contains(v, "RECEIVE_MESSAGE('a',10)") {
				return true
			}
		}
	}
	return false
}

// vulnerableHandler emulates a time-based blind SQLi sink: the sleep payload
// stalls the response past the detection threshold while the no-sleep variant
// returns after a short cache-busting delay. Status flushes immediately to keep
// the response within the requester's 5s ResponseHeaderTimeout.
func vulnerableHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slow := queryHasSleep(r)
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

// TestScanPerRequest_DetectsTimeBlindSQLi drives the real scan method against a
// server that honours an injectable numeric parameter sleep payload. Triple
// verification (sleep → no-sleep → sleep) must confirm the finding.
func TestScanPerRequest_DetectsTimeBlindSQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	t.Parallel()
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a time-based blind SQLi finding when sleep payload stalls the response")
	assert.Equal(t, "id", res[0].FuzzingParameter)
}

// TestScanPerRequest_NoFalsePositive ensures a uniformly fast server never
// yields a finding regardless of the injected payload.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that never stalls must not yield a time-based blind SQLi finding")
}

// TestIsNumericValue exercises the pure numeric-context classifier.
func TestIsNumericValue(t *testing.T) {
	t.Parallel()
	assert.True(t, isNumericValue("123"))
	assert.True(t, isNumericValue("-42"))
	assert.True(t, isNumericValue("3.14"))
	assert.False(t, isNumericValue(""))
	assert.False(t, isNumericValue("abc"))
	assert.False(t, isNumericValue("12a"))
}

// TestGetPayloadsForValue confirms numeric vs string payload selection.
func TestGetPayloadsForValue(t *testing.T) {
	t.Parallel()
	assert.Equal(t, numericPayloads, getPayloadsForValue("42"))
	assert.Equal(t, stringPayloads, getPayloadsForValue("hello"))
}
