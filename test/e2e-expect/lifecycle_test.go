//go:build e2e

package e2eexpect

import (
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

// Lifecycle scenarios drive the binary through interruption and resume.

// scanArgs is a hermetic, fast `vigolium scan` over the plants and twins:
// dynamic assessment only, a fixed module set, no tech gate, no heuristics.
func scanArgs(t *testing.T, app *lab.Server, extra ...string) []string {
	t.Helper()
	args := []string{"scan", "-T", writeLines(t, lab.PlantURLs(app.URL, true, true)), "--only", "dynamic-assessment", "--skip-heuristics", "--no-tech-filter",
		"-m", strings.Join(plantModuleSet(), ","), "-c", "4", "--timeout", "5s", "-j"}
	return append(args, extra...)
}

// SIGINT mid-scan: the process exits promptly with the interrupted code, still
// writes exactly one -j document, and that document says the scan is partial
// because it was cancelled. Resuming the scan then finishes it.
func TestLifecycle_InterruptThenResume(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{}))
	c := newCLI(t)
	args := scanArgs(t, app)

	// Baseline: the same scan, uninterrupted, in its own install.
	base := newCLI(t).run(t, 5*time.Minute, args...)
	require.Equalf(t, apicontract.ExitSuccess, base.code, "%s", base)
	full := l.Ledger.Count("app")

	app.Faults.SetLatency(5 * time.Millisecond)
	interruptedFrom := time.Now()
	sentSince := func(t0 time.Time) int { return len(l.Ledger.After("app", t0)) }
	r := c.runInterrupted(t, syscall.SIGINT, 1, time.Minute, func() bool { return sentSince(interruptedFrom) >= full/2 }, 45*time.Second, args...)
	sentBefore := sentSince(interruptedFrom)
	t.Logf("interrupted after %d requests; exit %d", sentBefore, r.code)
	assert.Equalf(t, apicontract.ExitIncomplete, r.code, "SIGINT must exit with the incomplete code\n%s", r)
	doc := r.doc(t)
	assert.Equal(t, database.CompletenessPartial, str(doc, "completeness"))
	assert.Equal(t, database.ReasonCancelled, str(doc, "stop_reason"))
	uuid := str(doc, "scan_uuid")
	require.NotEmptyf(t, uuid, "the interrupted document must name its scan\n%s", r)
	requireQuiesced(t, l)

	// The interrupted run's row is recorded as cancelled.
	st := c.run(t, time.Minute, "scan", "status", uuid, "-j")
	require.Equalf(t, 0, st.code, "%s", st)
	assert.Contains(t, st.stdout, `"`+database.ReasonCancelled+`"`, "scan status must report the interruption")

	// Resume: completes, and does not start over from zero.
	app.Faults.SetLatency(0)
	resumedFrom := time.Now()
	res := c.run(t, 5*time.Minute, append(args, "--resume-scan", uuid)...)
	require.Equalf(t, apicontract.ExitSuccess, res.code, "%s", res)
	rdoc := res.doc(t)
	assert.Equal(t, uuid, str(rdoc, "scan_uuid"), "resume must continue the same scan")
	assert.Equal(t, database.CompletenessComplete, str(rdoc, "completeness"))
	resumed := sentSince(resumedFrom)
	t.Logf("resume sent %d requests (interrupted run sent %d; an uninterrupted run sent %d)", resumed, sentBefore, full)
	// Coverage is tracked per record×module, so units in flight at the
	// interrupt are redone; but what finished must not be.
	assert.Lessf(t, resumed, full, "resume sent %d requests, no fewer than a full run (%d): nothing was skipped", resumed, full)

	// The union of both runs finds every plant the uninterrupted scan does.
	fr := c.run(t, time.Minute, "finding", "--scan-uuid", uuid, "-n", "500", "-j")
	require.Equalf(t, 0, fr.code, "%s", fr)
	got := map[string]bool{}
	for _, it := range items(fr.doc(t)) {
		got[it["module_id"].(string)] = true
	}
	for _, mod := range []string{"sqli-error-based", "lfi-generic", "command-injection-echo", "xss-light-url-params"} {
		assert.Truef(t, got[mod], "interrupt + resume lost the %s finding", mod)
	}
}

// Two SIGINTs while requests are parked on hanging, tarpitting and oversized
// endpoints: the second shortens the shutdown, and the process must still exit
// with the incomplete code, write its document, and never die from the signal.
func TestLifecycle_DoubleInterruptStillExitsCleanly(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.Minefield(lab.VulnAppOptions{}))
	c := newCLI(t)
	var extra []string
	for _, p := range lab.MinePaths() {
		extra = append(extra, "-t", app.URL+p+"?id=1")
	}
	args := scanArgs(t, app, extra...)

	r := c.runInterrupted(t, syscall.SIGINT, 2, 30*time.Second, func() bool {
		return l.Ledger.InFlight("app") > 0 && l.Ledger.Count("app") >= 20
	}, 45*time.Second, args...)
	assert.Equalf(t, apicontract.ExitIncomplete, r.code, "%s", r)
	_ = r.doc(t)
	requireQuiesced(t, l)
}
