package sqli_time_blind

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// baseDelay is the short latency for non-sleeping requests: under the derived
// threshold, but long enough to bust the requester's ~500ms clustering cache so
// byte-identical no-sleep probes are re-executed.
const baseDelay = 600 * time.Millisecond

var sleepArgRe = regexp.MustCompile(`SLEEP\((\d+)\)|pg_sleep\((\d+)\)|0:0:(\d+)|RECEIVE_MESSAGE\('a',(\d+)\)`)

// requestedSleep extracts the sleep seconds encoded in the injected payload, or
// 0 when none is present.
func requestedSleep(r *http.Request) int {
	m := sleepArgRe.FindStringSubmatch(r.URL.Query().Get("id"))
	if m == nil {
		return 0
	}
	for _, g := range m[1:] {
		if g != "" {
			n, _ := strconv.Atoi(g)
			return n
		}
	}
	return 0
}

// flushAndSleep writes a 200, flushes headers (so the body delay stays clear of
// the requester's 5s ResponseHeaderTimeout), sleeps d, then writes the body.
func flushAndSleep(w http.ResponseWriter, d time.Duration) {
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	time.Sleep(d)
	_, _ = w.Write([]byte("ok"))
}

// scalingHandler emulates a genuine time-based blind SQLi sink: the response
// delay equals the requested sleep duration (and is near-instant otherwise).
func scalingHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if n := requestedSleep(r); n > 0 {
			flushAndSleep(w, time.Duration(n)*time.Second)
			return
		}
		flushAndSleep(w, baseDelay)
	}
}

// TestScanPerRequest_DetectsTimeBlindSQLi drives the real scan against a sink
// whose delay scales with the injected sleep value; the multi-round scaling
// confirmation must report a finding.
func TestScanPerRequest_DetectsTimeBlindSQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(scalingHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a time-based blind SQLi finding when the delay scales with the sleep value")
	assert.Equal(t, "id", res[0].FuzzingParameter)
	assert.Equal(t, "mysql", res[0].ExtractedResults[2])
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

// TestScanPerRequest_NoFalsePositive_FixedDelay is the key scaling-factor test:
// a sink that stalls a FIXED amount on any sleep payload (e.g. a timeout/retry
// path) — not proportional to the requested duration — must be rejected because
// the high−low differential does not track the requested factor.
func TestScanPerRequest_NoFalsePositive_FixedDelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestedSleep(r) > 0 {
			flushAndSleep(w, time.Duration(sleepHigh)*time.Second) // fixed, non-scaling
			return
		}
		flushAndSleep(w, baseDelay)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a fixed (non-scaling) delay must not be reported as time-based SQLi")
}

// TestMeanStdev verifies the baseline statistics helper.
func TestMeanStdev(t *testing.T) {
	t.Parallel()
	// Constant samples → zero deviation, mean equals the value.
	mean, stdev := meanStdev([]time.Duration{
		100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond,
	})
	assert.Equal(t, 100*time.Millisecond, mean)
	assert.Equal(t, time.Duration(0), stdev)

	// Empty input is safe.
	mean, stdev = meanStdev(nil)
	assert.Equal(t, time.Duration(0), mean)
	assert.Equal(t, time.Duration(0), stdev)

	// Known spread: values 0ms and 200ms → mean 100ms, population stdev 100ms.
	mean, stdev = meanStdev([]time.Duration{0, 200 * time.Millisecond})
	assert.Equal(t, 100*time.Millisecond, mean)
	assert.Equal(t, 100*time.Millisecond, stdev)
}

// TestPrioritizeByDBMS confirms a recorded backend hint moves matching payloads
// to the front while preserving the rest (no coverage dropped).
func TestPrioritizeByDBMS(t *testing.T) {
	t.Parallel()
	host := "db.example.com"

	// No registry → unchanged.
	assert.Equal(t, numericPayloads, prioritizeByDBMS(numericPayloads, &modkit.ScanContext{}, host))

	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	sc.MarkTech(host, infra.DBMSTechTag("postgres"))

	got := prioritizeByDBMS(numericPayloads, sc, host)
	require.Len(t, got, len(numericPayloads), "reordering must not drop payloads")
	assert.Equal(t, "postgres", got[0].dbType, "matching DBMS payloads must come first")
	// Every original payload is still present.
	counts := map[string]int{}
	for _, p := range got {
		counts[p.template]++
	}
	for _, p := range numericPayloads {
		assert.Equal(t, 1, counts[p.template], "payload %q preserved exactly once", p.template)
	}
}

// TestGetPayloadsForValue confirms numeric vs string payload selection.
func TestGetPayloadsForValue(t *testing.T) {
	t.Parallel()
	assert.Equal(t, numericPayloads, getPayloadsForValue("42"))
	assert.Equal(t, stringPayloads, getPayloadsForValue("hello"))
}
