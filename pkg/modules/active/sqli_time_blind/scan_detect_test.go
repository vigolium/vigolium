package sqli_time_blind

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
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
	f := res[0]
	assert.Equal(t, "id", f.FuzzingParameter)
	assert.Equal(t, "mysql", f.ExtractedResults[2])

	// Time-based blind rides on latency alone, so even a confirmed finding is
	// reported as a lead to verify by hand, never a firmly-confirmed High.
	assert.Equal(t, severity.Suspect, f.Info.Severity, "time-based blind SQLi must report as Suspect")
	assert.Equal(t, severity.Tentative, f.Info.Confidence, "time-based blind SQLi must report as Tentative")

	// The multi-round comparison that proves the finding must be preserved, not
	// discarded: the slow high-sleep probe is the primary pair, and the baseline
	// and fast no-sleep control travel as labeled AdditionalEvidence.
	assert.NotEmpty(t, f.Response, "the slow high-sleep probe response should be the primary response pair")
	require.NotEmpty(t, f.AdditionalEvidence, "finding must carry the baseline/control comparison as evidence")
	joined := strings.Join(f.AdditionalEvidence, "\n")
	assert.Contains(t, joined, "# [baseline", "expected a labeled baseline evidence pair")
	assert.Contains(t, joined, "# [control", "expected the no-sleep control evidence pair")

	require.NotNil(t, f.Metadata, "finding must carry timing metadata")
	assert.Equal(t, timeRounds, f.Metadata["confirmation_rounds"])
	assert.Contains(t, f.Metadata, "threshold_ms")

	var hasRoundLine bool
	for _, e := range f.ExtractedResults {
		if strings.HasPrefix(e, "Round 1:") {
			hasRoundLine = true
		}
	}
	assert.True(t, hasRoundLine, "expected per-round timing lines in extracted results")
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

// TestConfirmTiming_RejectsHighBaselineJitterSpike reproduces the slow-but-constant
// host false positive: every request is slow (~1.2s) and only the LARGE sleep
// coincides with a non-proportional latency spike, while the SMALL sleep adds
// nothing. The old absolute low-latency check missed this (1.2s already clears the
// ~1s bar); crediting each sleep only with the delay it adds over the same round's
// no-sleep control rejects it. Driven through confirmTiming directly to exercise one
// payload instead of the full matrix.
func TestConfirmTiming_RejectsHighBaselineJitterSpike(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestedSleep(r) == sleepHigh {
			flushAndSleep(w, 5*time.Second) // only the large payload spikes, non-proportionally
			return
		}
		flushAndSleep(w, 1200*time.Millisecond) // slow-but-constant baseline (no-sleep AND small sleep)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")
	ip := modtest.InsertionPoint(t, rr, "id")
	pair := numericPayloads[0] // mysql " OR SLEEP(%d)--"

	// Threshold below the spike so the high probe clears it, yet above the slow
	// baseline — the window in which the old absolute low-latency check passed.
	res, err := New().confirmTiming(rr, client, ip, pair, ip.BaseValue(), 4*time.Second)
	require.NoError(t, err)
	assert.Nil(t, res, "a non-scaling spike on a slow-but-constant host must not be reported")
}

// TestScanPerRequest_NoFalsePositive_BlockedBaseline reproduces the CloudFront
// false positive: the edge denies every request — including the unmodified
// baseline — with a 403. A blocked surface has no backend query to time, so the
// insertion point must be skipped outright (no probes wasted per payload).
func TestScanPerRequest_NoFalsePositive_BlockedBaseline(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Request blocked"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a blocked (403) baseline must never be reported as time-based blind SQLi")
}

// TestScanPerRequest_NoFalsePositive_BlockedPayloadScaling is the decisive gate
// test: the clean baseline passes (200), but a WAF answers every SQL payload
// with a 403 whose delay scales with the requested sleep — exactly the timing
// profile that would otherwise confirm. Because the confirming response is a
// block (not a backend query), it must be dropped no matter how the timing looks.
//
// Without the block gate this scan reports a (slow) false positive; with it the
// scan drops at the first blocked probe and returns fast.
func TestScanPerRequest_NoFalsePositive_BlockedPayloadScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := strings.TrimSpace(r.URL.Query().Get("id"))
		// A non-numeric id is an injected SQL payload — block it with a 403 whose
		// delay scales with the requested sleep (what fools a timing-only check).
		if _, err := strconv.Atoi(q); err != nil {
			w.WriteHeader(http.StatusForbidden)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if n := requestedSleep(r); n > 0 {
				time.Sleep(time.Duration(n) * time.Second)
			}
			_, _ = w.Write([]byte("Request blocked"))
			return
		}
		flushAndSleep(w, baseDelay) // clean numeric baseline → fast 200
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/item?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a blocked (403) response must never be reported as time-based SQLi even when its delay scales")
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

// TestGetPayloadsForValue confirms numeric vs string payload selection and the
// risk gate: with risky payloads allowed (deep / --allow-risky-payloads) every
// template is returned; otherwise no OR-per-row or stacked template survives.
func TestGetPayloadsForValue(t *testing.T) {
	t.Parallel()
	assert.Equal(t, numericPayloads, getPayloadsForValue("42", true))
	assert.Equal(t, stringPayloads, getPayloadsForValue("hello", true))

	cases := []struct {
		name      string
		value     string
		wantSafe  []string
		allCount  int
		dbmsGated []string // backends with no time payload left at balanced
	}{
		{
			name:  "string",
			value: "hello",
			wantSafe: []string{"' AND SLEEP(%d)-- -", "' AND SLEEP(%d) AND '1'='1",
				"' OR (SELECT pg_sleep(%d))::text='1'--", "'||(SELECT '' FROM pg_sleep(%d))||'",
				"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)-- -"},
			allCount:  len(stringPayloads),
			dbmsGated: []string{"mssql"},
		},
		{
			name:      "numeric",
			value:     "42",
			wantSafe:  []string{" AND SLEEP(%d)-- -", " AND SLEEP(%d)", " AND 1=(SELECT 1 FROM pg_sleep(%d))"},
			allCount:  len(numericPayloads),
			dbmsGated: []string{"mssql", "oracle"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			safe := getPayloadsForValue(tc.value, false)
			var got []string
			dbms := map[string]bool{}
			for _, p := range safe {
				got = append(got, p.template)
				dbms[p.dbType] = true
				assert.NotRegexp(t, `(?i)\bOR (SLEEP|1=)|;`, p.template,
					"balanced must not send OR-per-row or stacked template %q", p.template)
			}
			assert.Equal(t, tc.wantSafe, got)
			assert.Len(t, getPayloadsForValue(tc.value, true), tc.allCount)
			for _, d := range tc.dbmsGated {
				assert.False(t, dbms[d], "%s time-blind must be deep/--allow-risky-payloads only", d)
			}
		})
	}
}

// TestRiskHighTemplatesExcludedBelowDeep is the contract: every riskHigh template
// is withheld unless the ScanContext allows risky payloads, and every OR-per-row
// or stacked template is marked riskHigh (so a new one can't slip in unmarked).
func TestRiskHighTemplatesExcludedBelowDeep(t *testing.T) {
	t.Parallel()
	perRowOrStacked := regexp.MustCompile(`(?i)(^|')\s*OR (SLEEP|1=)|;`)
	for _, set := range [][]timePair{stringPayloads, numericPayloads} {
		for _, p := range set {
			if perRowOrStacked.MatchString(p.template) {
				assert.Equal(t, riskHigh, p.risk, "OR-per-row/stacked template %q must be riskHigh", p.template)
			}
		}
	}

	for _, sc := range []*modkit.ScanContext{nil, {}, {DeepScan: false}} {
		for _, v := range []string{"hello", "42"} {
			for _, p := range getPayloadsForValue(v, sc.RiskyPayloadsAllowed()) {
				assert.Equal(t, riskNormal, p.risk, "riskHigh template %q sent with DeepScan=false", p.template)
			}
		}
	}
	for _, sc := range []*modkit.ScanContext{{DeepScan: true}, {AllowRiskyPayloads: true}} {
		assert.True(t, sc.RiskyPayloadsAllowed())
		assert.Equal(t, stringPayloads, getPayloadsForValue("hello", sc.RiskyPayloadsAllowed()))
	}
}
