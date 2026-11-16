//go:build e2e

package e2eexpect

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

// Fuzz scenarios drive `vigolium fuzz` against the lab and assert on the -j
// document, the exit code, and what the lab's ledger saw on the wire.

// benignIDs is a payload population large enough for the anomaly detector's
// population signals (it needs 12+ responses) with the one payload that
// breaks the SQL literal hidden in the middle.
func benignIDs(n int, planted ...string) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprint(100+i))
		if i == n/2 {
			out = append(out, planted...)
		}
	}
	return out
}

// The planted SQL error must come out on top of an anomaly run, flagged by
// its error signature, and the run must report exactly what it sent.
func TestFuzz_AnomalyRanksPlantedErrorFirst(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{}))
	c := newCLI(t)
	words := benignIDs(40, "1'")

	r := c.run(t, 2*time.Minute, "fuzz", "-i", app.URL+"/item?id=FUZZ", "-w", writeLines(t, words),
		"--anomaly", "-c", "4", "-j")
	require.Equalf(t, apicontract.ExitSuccess, r.code, "%s", r)
	doc := r.doc(t)

	assert.Equal(t, float64(len(words)), num(doc, "sent"), "sent counts payload sends")
	assert.Zero(t, num(doc, "errors"))
	anomalies, _ := doc["anomalies"].([]any)
	require.NotEmptyf(t, anomalies, "the planted SQL error must be reported as an anomaly\n%s", r)
	top := anomalies[0].(map[string]any)
	assert.Equal(t, "1'", top["payload"], "the planted payload must rank first")
	assert.EqualValues(t, http.StatusInternalServerError, top["status"])
	assert.Contains(t, fmt.Sprint(top["anomaly_reasons"]), "error_signature")
	for _, a := range anomalies[1:] {
		assert.Lessf(t, num(a.(map[string]any), "anomaly_score"), num(top, "anomaly_score"),
			"a benign id must not tie the planted error: %v", a)
	}

	// Wire truth: every payload arrived once, plus baseline/calibration sends.
	hits := l.Ledger.Count("app")
	assert.GreaterOrEqual(t, hits, len(words))
	assert.Equal(t, num(doc, "sent_total"), float64(hits), "sent_total must match what the target received")
}

// -c and -r bound what the target sees: in-flight never exceeds -c, and no
// one-second window carries more than the rate allows (plus one bucket's burst).
func TestFuzz_PaceIsHonoredOnTheWire(t *testing.T) {
	l := newLab(t)
	slow := l.Serve("echo", lab.SlowHost(20*time.Millisecond, 20*time.Millisecond))
	c := newCLI(t)
	const conc, rate, n = 3, 20, 80

	r := c.run(t, 2*time.Minute, "fuzz", "-i", slow.URL+"/search?q=FUZZ", "-w", writeLines(t, benignIDs(n)),
		"-c", fmt.Sprint(conc), "-r", fmt.Sprint(rate), "-j")
	require.Equalf(t, apicontract.ExitSuccess, r.code, "%s", r)

	assert.LessOrEqual(t, l.Ledger.PeakConcurrency("echo"), conc, "in-flight requests exceeded -c")
	burst := l.Ledger.MaxInWindow("echo", time.Second)
	assert.LessOrEqualf(t, burst, rate+conc, "a 1s window carried %d requests at -r %d", burst, rate)
	// n requests at rate r cannot finish faster than (n-burst)/r seconds.
	minWall := time.Duration(float64(n-rate-conc) / rate * float64(time.Second))
	assert.GreaterOrEqualf(t, r.elapsed, minWall, "%d sends finished in %s, faster than -r %d allows", n, r.elapsed, rate)
}

// A target that kills the connection for some payloads: the run finishes,
// counts the failures, and exits partial rather than pretending to be complete.
// (Dropping every nth connection is not enough — net/http transparently
// retries an idempotent GET on a reused connection, which is fine.)
func TestFuzz_FailedSendsArePartialNotSilent(t *testing.T) {
	l := newLab(t)
	app := l.Serve("flaky", lab.DropWhen(lab.SafeEcho(), func(r *http.Request) bool {
		return strings.HasPrefix(r.URL.Query().Get("q"), "11")
	}))
	c := newCLI(t)
	words := benignIDs(30) // 110..119 are dropped

	r := c.run(t, 2*time.Minute, "fuzz", "-i", app.URL+"/search?q=FUZZ", "-w", writeLines(t, words),
		"-c", "2", "--no-calibrate", "-j")
	doc := r.doc(t)
	assert.Equalf(t, apicontract.ExitIncomplete, r.code, "some sends failed: expected the partial exit\n%s", r)
	assert.Equal(t, float64(10), num(doc, "errors"), "every dropped payload must be counted as an error")
	assert.Equal(t, float64(len(words)), num(doc, "sent"))
}

// A target that never answers is bounded by --timeout, not by the test's
// patience: every send times out and the run ends.
func TestFuzz_HangingTargetIsBoundedByTimeout(t *testing.T) {
	l := newLab(t)
	hang := l.Serve("hang", lab.Hang())
	c := newCLI(t)

	r := c.run(t, time.Minute, "fuzz", "-i", hang.URL+"/search?q=FUZZ", "-p", "a", "-p", "b", "-p", "c",
		"--timeout", "2s", "--allow-baseline-error", "-c", "3", "--no-calibrate", "-j")
	assert.Lessf(t, r.elapsed, 20*time.Second, "three 2s-timeout sends took %s\n%s", r.elapsed, r)
	assert.NotEqualf(t, apicontract.ExitSuccess, r.code, "no send got a response; success is a lie\n%s", r)
	assert.Zero(t, l.Ledger.InFlight("hang"), "the client must hang up on the hanging server")
}

// A dead target fails fast with no_targets_reachable instead of retrying
// into the timeout.
func TestFuzz_DeadTargetFailsFast(t *testing.T) {
	c := newCLI(t)
	r := c.run(t, time.Minute, "fuzz", "-i", lab.DeadURL()+"/search?q=FUZZ", "-p", "a", "-j")
	assert.Equalf(t, apicontract.ExitError, r.code, "%s", r)
	assert.Contains(t, r.stdout, string(apicontract.CodeNoTargetsReachable))
	assert.Less(t, r.elapsed, 15*time.Second)
}

// --no-redirects keeps a redirecting payload on the target: the off-site
// sentinel it points at must never be contacted.
func TestFuzz_NoRedirectsStaysOnTarget(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{}))
	sentinel := l.Serve("sentinel", lab.SafeEcho())
	c := newCLI(t)

	r := c.run(t, time.Minute, "fuzz", "-i", app.URL+"/redirect?next=FUZZ",
		"-p", sentinel.URL+"/landing", "-p", "/home", "--no-redirects", "--no-calibrate", "-j")
	require.Equalf(t, apicontract.ExitSuccess, r.code, "%s", r)
	assert.Zero(t, l.Ledger.Count("sentinel"), "--no-redirects followed a redirect off the target")
	assert.Contains(t, r.stdout, "header:Location", "the redirect reflection must still be reported")
}

// Following redirects is bounded: a redirect loop ends after --max-redirs
// hops rather than pinning a worker.
func TestFuzz_RedirectLoopIsBounded(t *testing.T) {
	l := newLab(t)
	loop := l.Serve("loop", lab.RedirectLoop())
	c := newCLI(t)

	r := c.run(t, time.Minute, "fuzz", "-i", loop.URL+"/go?x=FUZZ", "-p", "a",
		"--max-redirs", "3", "--allow-baseline-error", "--no-calibrate", "-j")
	t.Logf("exit %d, %d hops recorded", r.code, l.Ledger.Count("loop"))
	// baseline + one payload, each allowed 1 request + 3 redirects.
	assert.LessOrEqualf(t, l.Ledger.Count("loop"), 2*(1+3),
		"--max-redirs 3 was not honored: the loop server saw %d requests", l.Ledger.Count("loop"))
}
