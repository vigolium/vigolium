//go:build e2e

package e2eexpect

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

// Probe scenarios: a mixed target list of live, dead, slow and non-HTTP
// endpoints. A probe-only run skips preflight and reports liveness as
// http_records rows with source "probe" — one per answering target, none for
// the rest — so that is what these assert on.

type probeFleet struct {
	lab     *lab.Lab
	alive   map[string]string // target URL → why it must answer
	dead    map[string]string // target URL → why it must not produce a record
	targets []string
	loop    string // the redirect-loop target
}

func newProbeFleet(t *testing.T) *probeFleet {
	t.Helper()
	l := newLab(t)
	f := &probeFleet{lab: l, alive: map[string]string{}, dead: map[string]string{}}
	add := func(m map[string]string, url, why string) {
		m[url] = why
		f.targets = append(f.targets, url)
	}

	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{}))
	landing := l.Serve("landing", lab.SafeEcho())
	tlsSrv := l.ServeTLS("tls", lab.SafeEcho())
	boom := l.Serve("boom", lab.SafeEcho())
	boom.Faults.SetStatus(500)
	loop := l.Serve("loop", lab.RedirectLoop())
	slow := l.Serve("slow", lab.SafeEcho())
	slow.Faults.SetLatency(time.Second)

	add(f.alive, app.URL+"/", "plain HTTP 200")
	add(f.alive, tlsSrv.URL+"/", "self-signed HTTPS (the probe does not verify)")
	add(f.alive, boom.URL+"/", "a 500 is an answer")
	add(f.alive, app.URL+"/redirect?next="+landing.URL+"/landing", "redirect to another port on the same host")
	f.loop = loop.URL + "/go"
	add(f.alive, f.loop, "a redirect loop still answered")
	add(f.alive, slow.URL+"/", "a 1s first byte is under the timeout")

	add(f.dead, lab.DeadURL()+"/", "connection refused")
	add(f.dead, l.ServeRaw("ssh", lab.SSHBanner).URL+"/", "SSH banner, not HTTP")
	add(f.dead, l.ServeRaw("garbage", lab.Garbage).URL+"/", "binary garbage")
	add(f.dead, l.ServeRaw("silent", lab.Silent).URL+"/", "accepts and never writes")
	add(f.dead, l.Serve("hang", lab.Hang()).URL+"/", "HTTP server that never answers")
	return f
}

func TestProbe_MixedFleetIsClassifiedAndBounded(t *testing.T) {
	f := newProbeFleet(t)
	opts := scanOptions(f.targets...)
	opts.OnlyPhase = "probe"
	opts.Timeout = 3 * time.Second
	opts.Retries = 1
	require.NoError(t, runner.ApplyNativePhaseSelection(opts, nil))
	require.True(t, opts.ProbeEnabled)

	sr := runScan(t, opts, 2*time.Minute)
	require.NoError(t, sr.err)
	t.Logf("probed %d targets in %s", len(f.targets), sr.elapsed)
	// Hanging targets run in parallel, each bounded by the timeout; nothing
	// may serialize them.
	assert.Less(t, sr.elapsed, 25*time.Second, "a hanging target stalled the sweep")

	recs, err := database.NewQueryBuilder(sr.db, database.QueryFilters{Source: database.RecordSourceProbe, Limit: 1000}).OmitBodies().Execute(context.Background())
	require.NoError(t, err)
	byTarget := map[string][]*database.HTTPRecord{}
	for _, r := range recs {
		byTarget[r.Target] = append(byTarget[r.Target], r)
	}
	for url, why := range f.alive {
		assert.NotEmptyf(t, byTarget[url], "%s (%s) answered but has no probe record", url, why)
	}
	for url, why := range f.dead {
		assert.Emptyf(t, byTarget[url], "%s (%s) did not answer but has a probe record", url, why)
	}

	// The redirect was followed to the landing page and recorded as a chain.
	assert.Positive(t, f.lab.Ledger.Count("landing"), "same-host redirect was not followed")
	// The loop was cut off, not followed forever.
	assert.LessOrEqual(t, f.lab.Ledger.Count("loop"), 2*11, "redirect loop followed past the hop limit")
	truncated := false
	for _, r := range byTarget[f.loop] {
		t.Logf("  loop record %d %s truncated=%v parent=%q", r.StatusCode, r.URL, r.ChainTruncated, r.ParentUUID)
		truncated = truncated || r.ChainTruncated
	}
	assert.True(t, truncated, "a cut-off redirect loop must be marked chain_truncated")
	// One request per alive target (plus redirect hops) — the probe is a
	// sweep, not a scan: no module traffic.
	assert.LessOrEqual(t, f.lab.Ledger.Count("app"), 2, "probe sent more than the sweep request to the app")
	requireQuiesced(t, f.lab)
}

// The binary: `run probe -T` over the same fleet exits 0 with one -j
// document, keeps human logs off stdout, and names the answered count.
func TestProbe_BinaryMixedFleet(t *testing.T) {
	f := newProbeFleet(t)
	c := newCLI(t)
	r := c.run(t, 2*time.Minute, "run", "probe", "-T", writeLines(t, f.targets), "--timeout", "3s", "-j")
	require.Equalf(t, apicontract.ExitSuccess, r.code, "%s", r)
	doc := r.doc(t)
	assert.Equal(t, true, doc["ok"])
	assert.Equal(t, "scan", str(doc, "kind"))
	t.Logf("stderr:\n%s", r.stderr)
	assert.Less(t, r.elapsed, 40*time.Second, "a hanging target stalled the sweep")
	assert.Containsf(t, r.stderr, "6 of 11 targets answered", "stderr should report the answered count\n%s", r)
}

// Every target dead: the sweep still ends promptly. Today a probe-only run
// skips preflight, so this exits 0 with ok:true and nothing in the document
// says no target answered — only stderr does (tracked in knownDefects).
func TestProbe_BinaryAllDead(t *testing.T) {
	l := newLab(t)
	c := newCLI(t)
	targets := []string{lab.DeadURL() + "/", l.ServeRaw("ssh", lab.SSHBanner).URL + "/", l.ServeRaw("silent", lab.Silent).URL + "/"}
	r := c.run(t, time.Minute, "run", "probe", "-T", writeLines(t, targets), "--timeout", "3s", "-j")
	assert.Less(t, r.elapsed, 30*time.Second)
	assert.Contains(t, r.stderr, "0 of 3 targets answered")
	doc := r.doc(t)
	expectKnown(t, "probe/all-dead-is-ok", r.code == apicontract.ExitSuccess && doc["ok"] == true,
		"an all-dead probe exited %d ok=%v", r.code, doc["ok"])
}
