//go:build e2e

package e2eexpect

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

// In-process scan scenarios: the native runner against the lab, asserting on
// findings, the store, and what each lab server saw on the wire.

// plantModules maps each planted class to the modules expected to catch it;
// any one of them finding the plant's path counts.
var plantModules = map[string][]string{
	"open-redirect":  {"open-redirect"},
	"xss-reflected":  {"xss-light-url-params"},
	"sqli-error":     {"sqli-error-based"},
	"path-traversal": {"lfi-generic", "lfi-path-traversal"},
	// ssti-detection is an Info-level differential lead, not a detection.
	"ssti":              {"reflected-ssti"},
	"command-injection": {"command-injection-echo"},
}

// knownDefects are defects the kit reproduces today, keyed by id, with why.
// Each is a bug to fix. A scenario that observes one calls expectKnown, which
// logs it while it is listed and fails once a deterministic one stops
// reproducing, so a fix also removes its entry (the benign sweep's allow-list
// works the same way). An intermittent defect is only logged when seen.
var knownDefects = map[string]knownDefect{
	"plant-missed/open-redirect": {why: "the seed follows a CLI target's redirect and stores only the destination " +
		"(/redirect?next=account → /account), so the redirecting endpoint itself is never assessed"},
	"plant-missed/ssti": {why: "with ssti-detection in the module set, reflected-ssti never reports /greet (it does " +
		"alone), and ssti-detection's Info lead lands on a different URL each run — often a benign twin " +
		"(/search-safe, /item); looks like the lead is misattributed and the confirmed finding is lost with it"},
	"minefield/heap": {why: "a ≥30 MB response costs ~155 MB of allocations: ResponseChain.Fill grows its buffer by " +
		"doubling (projectdiscovery/utils), then pkg/http.snapshotResponse, Buffer.String and FullResponseBytes " +
		"each copy it; 8 in-flight hostile bodies peak at ~1.8 GiB of heap"},
	// Not checked through expectKnown: goleak in TestMain carries an ignore
	// list for it instead.
	"scan/abandoned-module-goroutines": {why: "a cancelled scan (request budget, Close) returns while module " +
		"goroutines spawned by runActiveWithTimeout keep running; xss-light's browser confirmation goes " +
		"on launching headless Chrome after RunNativeScan has returned"},
	"discovery/jstangle-true-prefix": {why: "JS endpoint extraction resolves Juice Shop's `hostServer + \"/api/...\"` " +
		"base to the literal `true`, so ~25 API endpoints are stored as /true/1/reviews, /true/orders, ... " +
		"and the real /api and /rest routes are never reached by discovery"},
	"discovery/recurses-into-file-stems": {why: "discovery brute-forces under file names as if they were directories " +
		"(/chunk-3CyVWL1v/… from chunk-3CyVWL1v.js, /polyfills/…, /favicon_js/…, Google-font hashes); a 4-minute " +
		"discovery of Juice Shop sends ~14.5k requests"},
	"discovery/ignores-default-rate-limit": {why: "discovery is paced only when --rate-limit is typed: a `run discovery` " +
		"with the default 100/s sent 8,259 requests in one second to Juice Shop"},
	"live/native-scan-misses-search-sqli": {why: "the default native scan (rate 80/s, discovery and spidering capped at 3m, " +
		"--max-time 20m) spends ~14 min in dynamic assessment over ~140 records and hits scan_budget without " +
		"reporting /rest/products/search's SQLi, which a module-scoped scan of that URL finds in seconds"},
	"contract/fingerprint-stack-confidence": {why: "`run fingerprint -j` prints fingerprint.stacks[].confidence " +
		"as a string (\"high\"); the published schema says integer, so the document fails `vigolium schema` validation"},
	"probe/all-dead-is-ok": {why: "a probe-only run skips preflight, so a sweep where no target answered exits 0 " +
		"with ok:true and targets[].reached=null; only stderr says \"0 of N targets answered\""},
	"live/juice-shop-false-edge-block": {intermittent: true, why: "a native scan of Juice Shop (no WAF in front) ends with dynamic-assessment " +
		"partial(edge_blocked): the requester's block detector counts some of the app's own responses as edge blocks " +
		"(unconfirmed which), and block handling slows the phase"},
	"live/juice-shop-exhausted-by-scan": {intermittent: true, why: "Juice Shop grows ~110 MB per 1k requests (per-path metrics); at Node's " +
		"default 4 GB heap an unpaced discovery pass (14–19k requests in 4 min) OOMs it; the kit gives it an 8 GB " +
		"heap, which a full native scan (~40–75k requests) can still exhaust"},
	"discovery/exceeds-max-per-host": {intermittent: true, why: "a discovery-only run held 47 requests in flight against one host under the " +
		"default --max-per-host 40"},
	"budget/persistence-stop-reason": {intermittent: true, why: "about half the runs that exhaust --max-requests report stop_reason " +
		"persistence_incomplete instead of request_budget: the budget's context cancel also cuts in-flight " +
		"writer flushes, so writes are lost and the real stop reason is masked"},
}

type knownDefect struct {
	why          string
	intermittent bool
}

// expectKnown reports whether the scenario observed defect id, tolerating it
// while it is listed in knownDefects. An unlisted observation fails with msg;
// a listed deterministic defect that no longer reproduces fails too.
func expectKnown(t *testing.T, id string, observed bool, msg string, args ...any) bool {
	t.Helper()
	d, known := knownDefects[id]
	switch {
	case observed && known:
		t.Logf("known defect %s reproduces: %s", id, d.why)
	case observed:
		t.Errorf(msg, args...)
	case known && !d.intermittent:
		t.Errorf("known defect %s no longer reproduces — remove it from knownDefects (%s)", id, d.why)
	}
	return observed
}

// leadModules run alongside the detectors so their interaction is exercised:
// heuristic Info-level leads of the same classes.
var leadModules = []string{"ssti-detection"}

func plantModuleSet() []string {
	out := slices.Clone(leadModules)
	for _, ms := range plantModules {
		out = append(out, ms...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Every plant is found by a module that targets it, every benign twin stays
// below Low, and the found set and request count match the golden manifest.
func TestScan_PlantsAndTwins(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{}))
	opts := scanOptions(lab.PlantURLs(app.URL, true, true)...)
	opts.Modules = plantModuleSet()

	sr := runScan(t, opts, 5*time.Minute)
	require.NoError(t, sr.err)
	logFindings(t, sr.findings)
	checkStore(t, sr)
	requireQuiesced(t, l)

	for _, p := range lab.Plants() {
		found := false
		for _, f := range sr.findings {
			if findingPath(f) == p.Path && slices.Contains(plantModules[p.Class], f.ModuleID) {
				found = true
			}
			if findingPath(f) == p.Twin {
				assert.Falsef(t, atLeast(f.Severity, severity.Low),
					"false positive on benign twin %s: [%s] %s", p.Twin, f.Severity, f.ModuleID)
			}
		}
		expectKnown(t, "plant-missed/"+p.Class, !found,
			"planted %s at %s was not found by any of %v", p.Class, p.Path, plantModules[p.Class])
	}
	assert.Equal(t, completeness(sr), database.CompletenessComplete)
	// Info leads vary run to run (which record a heuristic lead attaches to
	// is scheduling-dependent); the golden set holds Low and above.
	checkExpectation(t, "scan/plants", findingKeys(atLeastLow(sr.findings)), l.Ledger.Count("app"))
}

// Discovery and active modules stay on the target: links, forms, scripts and
// redirects that point at another host (the same listener addressed as
// "localhost") never reach it.
func TestScan_ScopeHoldsAgainstOffsiteLinks(t *testing.T) {
	l := newLab(t)
	sentinel := l.Serve("sentinel", lab.SafeEcho())
	offsite := sentinel.Origin("localhost")
	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{OffsiteLinks: []string{offsite + "/partner?ref=lab", offsite + "/signup"}}))

	opts := scanOptions(app.URL + "/")
	opts.DiscoverEnabled = true
	opts.NoDiscoveryFuzz = true
	opts.Modules = append(plantModuleSet(), "ssrf-detection")

	sr := runScan(t, opts, 5*time.Minute)
	require.NoError(t, sr.err)
	t.Logf("app saw %d requests; found %v", l.Ledger.Count("app"), findingKeys(sr.findings))
	requireNoContact(t, l, "sentinel")
	assert.Greater(t, l.Ledger.Count("app"), 20, "discovery should have walked the app")
	checkStore(t, sr)
}

// The configured pace is what the target sees: per-host concurrency never
// exceeds --max-per-host and no one-second window exceeds the token bucket
// (rate plus one bucket of burst).
func TestScan_PaceIsHonoredOnTheWire(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{}))
	app.Faults.SetLatency(15 * time.Millisecond)
	const perHost, rate = 3, 40

	opts := scanOptions(lab.PlantURLs(app.URL, false, true)...)
	opts.Modules = plantModuleSet()
	opts.MaxPerHost, opts.MaxPerHostExplicitlySet = perHost, true
	opts.RateLimit, opts.RateLimitExplicitlySet = rate, true

	sr := runScan(t, opts, 5*time.Minute)
	require.NoError(t, sr.err)
	n := l.Ledger.Count("app")
	t.Logf("%d requests in %s, peak concurrency %d, max 1s window %d", n, sr.elapsed, l.Ledger.PeakConcurrency("app"), l.Ledger.MaxInWindow("app", time.Second))
	require.Greater(t, n, 2*rate, "the scenario must send enough to exercise the limiter")
	assert.LessOrEqual(t, l.Ledger.PeakConcurrency("app"), perHost, "in-flight requests exceeded --max-per-host")
	assert.LessOrEqual(t, l.Ledger.MaxInWindow("app", time.Second), 2*rate, "a 1s window exceeded rate + burst")
	assert.GreaterOrEqualf(t, sr.elapsed, time.Duration(float64(n-rate)/rate*float64(time.Second))*9/10,
		"%d requests finished in %s, faster than %d rps allows", n, sr.elapsed, rate)
}

// A target whose limiter answers 429 + Retry-After once its burst is spent:
// the scan backs off instead of hammering, and still finishes.
func TestScan_ThrottledTargetGetsBackoff(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.Throttled(lab.VulnApp(lab.VulnAppOptions{}), 15, time.Second))
	opts := scanOptions(lab.PlantURLs(app.URL, true, false)[1:4]...)
	opts.Modules = plantModuleSet()

	sr := runScan(t, opts, 5*time.Minute)
	require.NoError(t, sr.err)
	st := l.Ledger.StatusCounts("app")
	total := l.Ledger.Count("app")
	share := float64(st[429]) / float64(max(total, 1))
	t.Logf("%d requests, %d answered 429 (%.0f%%), %s", total, st[429], share*100, sr.elapsed)
	assert.Lessf(t, share, 0.5, "more than half the traffic hit the limiter: the scan is not backing off")
	checkStore(t, sr)
}

// The minefield: the planted app plus endpoints that hang, tarpit, reset,
// lie about Content-Length, send broken chunking, a 64 MiB body and a 512 MiB
// gzip bomb. The scan must finish on time, keep memory bounded, still find
// the plants, and leave no request hanging.
func TestScan_MinefieldIsSurvivable(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.Minefield(lab.VulnAppOptions{}))
	targets := []string{lab.Plants()[2].URL(app.URL), lab.Plants()[1].URL(app.URL)}
	for _, p := range lab.MinePaths() {
		targets = append(targets, app.URL+p+"?id=1")
	}
	opts := scanOptions(targets...)
	opts.Modules = plantModuleSet()
	opts.Timeout = 3 * time.Second

	heap := watchHeap()
	sr := runScan(t, opts, 4*time.Minute)
	peak := heap.Stop()
	t.Logf("finished in %s, %d requests, peak heap %d MiB; found %v", sr.elapsed, l.Ledger.Count("app"), peak>>20, findingKeys(sr.findings))
	require.NoError(t, sr.err)
	expectKnown(t, "minefield/heap", peak >= 1<<30, "peak heap %d MiB is over 1 GiB: hostile bodies are buffered too many times", peak>>20)
	keys := strings.Join(findingKeys(sr.findings), " ")
	assert.Contains(t, keys, "sqli-error-based@/item", "the hostile neighbours must not cost the real finding")
	assert.Contains(t, keys, "xss-light-url-params@/search")
	for _, f := range sr.findings {
		if strings.HasPrefix(findingPath(f), "/mine/") {
			assert.Falsef(t, atLeast(f.Severity, severity.Low), "hostile endpoint reported as a vulnerability: [%s] %s %s", f.Severity, f.ModuleID, f.URL)
		}
	}
	checkStore(t, sr)
	requireQuiesced(t, l)
}

// The host goes away mid-scan (every connection reset). The scan notices,
// stops sending within a bounded number of requests, and ends promptly as
// partial instead of grinding through its queue.
func TestScan_HostDeathEndsTheScanPromptly(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.SlowHost(10*time.Millisecond, 10*time.Millisecond))
	var targets []string
	for i := range 20 {
		targets = append(targets, app.URL+"/search?q=item"+string(rune('a'+i)))
	}
	opts := scanOptions(targets...)
	opts.Modules = plantModuleSet()
	opts.MaxHostError = 5
	opts.Retries = 0

	ps := startScan(t, opts)
	require.Eventually(t, func() bool { return l.Ledger.Count("app") >= 40 }, time.Minute, 20*time.Millisecond)
	died := time.Now()
	app.Faults.SetDown(true)
	sr := ps.wait(t, 2*time.Minute)

	after := len(l.Ledger.After("app", died))
	t.Logf("host died after %d requests; %d more were sent; scan ended %s later (err=%v)",
		l.Ledger.Count("app")-after, after, time.Since(died).Round(time.Millisecond), sr.err)
	assert.Less(t, time.Since(died), 45*time.Second, "the scan kept going long after its only host died")
	assert.LessOrEqual(t, after, 60, "requests kept flowing to a dead host")
	assert.Equal(t, database.CompletenessPartial, completeness(sr), "a scan whose host died is not complete")
}

// --max-requests is a hard ceiling on what the target receives.
func TestScan_RequestBudgetIsAHardCeiling(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.VulnApp(lab.VulnAppOptions{}))
	opts := scanOptions(lab.PlantURLs(app.URL, true, false)...)
	opts.Modules = plantModuleSet()
	opts.MaxRequests = 60

	sr := runScan(t, opts, 2*time.Minute)
	require.NoError(t, sr.err)
	assert.LessOrEqual(t, l.Ledger.Count("app"), 60, "the target received more than --max-requests")
	c := sr.runner.Completion()
	assert.Equal(t, database.CompletenessPartial, c.Completeness)
	if !expectKnown(t, "budget/persistence-stop-reason", c.StopReason == database.ReasonPersistence,
		"stop reason %q", c.StopReason) {
		assert.Equal(t, database.ReasonRequestBudget, c.StopReason)
	}
}

// --max-time bounds the whole scan's wall clock against a slow target.
func TestScan_MaxDurationBoundsWallClock(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.SlowHost(400*time.Millisecond, 200*time.Millisecond))
	opts := scanOptions(lab.PlantURLs(app.URL, true, false)...)
	opts.Modules = plantModuleSet()
	opts.ScanMaxDuration = 4 * time.Second

	sr := runScan(t, opts, 2*time.Minute)
	t.Logf("returned after %s (err=%v)", sr.elapsed, sr.err)
	assert.Less(t, sr.elapsed, 4*time.Second+20*time.Second, "--max-time overran by more than the shutdown grace")
	c := sr.runner.Completion()
	assert.Equal(t, database.CompletenessPartial, c.Completeness)
	assert.Equal(t, database.ReasonScanBudget, c.StopReason)
	requireQuiesced(t, l)
}

// Closing the runner mid-scan (what SIGINT does) returns promptly and leaves
// a consistent store; TestMain's leak check covers the goroutines.
func TestScan_CloseMidScanIsClean(t *testing.T) {
	l := newLab(t)
	app := l.Serve("app", lab.SlowHost(50*time.Millisecond, 50*time.Millisecond))
	opts := scanOptions(lab.PlantURLs(app.URL, true, true)...)
	opts.Modules = plantModuleSet()

	ps := startScan(t, opts)
	require.Eventually(t, func() bool { return l.Ledger.Count("app") >= 30 }, time.Minute, 20*time.Millisecond)
	closed := time.Now()
	ps.runner.Close()
	sr := ps.wait(t, time.Minute)
	t.Logf("Close returned; scan ended %s after it (err=%v)", time.Since(closed).Round(time.Millisecond), sr.err)
	assert.Less(t, time.Since(closed), 35*time.Second)
	assert.Equal(t, database.CompletenessPartial, completeness(sr))
	checkStore(t, sr)
	requireQuiesced(t, l)
}

func atLeastLow(fs []*database.Finding) []*database.Finding {
	var out []*database.Finding
	for _, f := range fs {
		if atLeast(f.Severity, severity.Low) {
			out = append(out, f)
		}
	}
	return out
}

func completeness(sr *scanRun) string { return sr.runner.Completion().Completeness }
