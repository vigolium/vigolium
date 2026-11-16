//go:build e2e

package e2eexpect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/database"
)

// Live scenarios. Each starts a fresh container, runs one vigolium command
// against it, and checks three things: the -j document's contract (exit code,
// ok, completeness), what the run stored (records, paths, findings) against
// the golden entry in testdata/expect.json, and that the target is still up.

// requireDoc asserts a successful run's -j document and returns it with the
// partial reasons it carried. With no allowed reasons the run must be
// complete; a run whose phase is time-capped on purpose (--discover-max-time,
// --spider-max-time) passes the reasons that cap produces, and may then end
// curtailed — any other reason fails.
func requireDoc(t *testing.T, r cliRun, allowed ...string) (map[string]any, map[string]bool) {
	t.Helper()
	require.Equalf(t, apicontract.ExitSuccess, r.code, "%s", r)
	doc := r.doc(t)
	assert.Equal(t, true, doc["ok"])
	reasons := map[string]bool{}
	if rs, isList := doc["reasons"].([]any); isList {
		for _, x := range rs {
			reasons[fmt.Sprint(x)] = true
		}
	}
	if len(allowed) == 0 {
		assert.Equal(t, "completed", str(doc, "status"))
		assert.Equalf(t, database.CompletenessComplete, str(doc, "completeness"), "reasons: %v", doc["reasons"])
		return doc, reasons
	}
	assert.Containsf(t, []string{"completed", "curtailed"}, str(doc, "status"), "reasons: %v", doc["reasons"])
	for x := range reasons {
		assert.Containsf(t, allowed, x, "unexpected partial reason %q (reasons: %v)", x, doc["reasons"])
	}
	return doc, reasons
}

// capped are the partial reasons a deliberately time-capped phase produces.
var capped = []string{database.ReasonPhaseDeadline, database.ReasonInputIncomplete}

// requireTargetSurvived asserts the app still answers after a run, and logs
// its memory so a creeping exhaustion shows up in the test output.
func requireTargetSurvived(t *testing.T, app *liveApp) {
	t.Helper()
	t.Logf("%s: %d requests through the proxy, peak concurrency %d, busiest second %d; memory after the run %d MiB",
		app.spec.Name, app.Lab.Ledger.Count(proxyName), app.Lab.Ledger.PeakConcurrency(proxyName),
		app.Lab.Ledger.MaxInWindow(proxyName, time.Second), app.memMiB())
	require.Truef(t, app.alive(30*time.Second), "%s stopped answering after the run", app.spec.Name)
}

// requireOnlySelectedActive asserts every active-module finding came from a
// module the run selected with -m.
func requireOnlySelectedActive(t *testing.T, fs []*database.Finding, selected []string) {
	t.Helper()
	for _, f := range fs {
		if f.ModuleType == database.ModuleTypeActive {
			assert.Containsf(t, selected, f.ModuleID, "active finding from an unselected module: %s %s", f.ModuleID, f.URL)
		}
	}
}

// --- Juice Shop -------------------------------------------------------------

// `run probe`: one sweep request, one probe record, nothing else.
func TestLive_JuiceShop_RunProbe(t *testing.T) {
	app := startLive(t, juiceShop)
	c := newCLI(t)
	r := c.run(t, 2*time.Minute, "run", "probe", "-t", app.Base+"/", "-j")
	requireDoc(t, r)

	s := openStore(t, c.db)
	recs := s.records(t, database.QueryFilters{})
	require.Len(t, recs, 1, "a probe stores one record per answering target")
	assert.Equal(t, database.RecordSourceProbe, recs[0].Source)
	assert.Equal(t, 200, recs[0].StatusCode)
	assert.Empty(t, s.findings(t), "a probe sweep raises no findings on Juice Shop")
	requireTargetSurvived(t, app)
}

// `run fingerprint`: host facts in the document, plus the fingerprint
// phase's own findings.
func TestLive_JuiceShop_RunFingerprint(t *testing.T) {
	app := startLive(t, juiceShop)
	c := newCLI(t)
	r := c.run(t, 3*time.Minute, "run", "fingerprint", "-t", app.Base+"/", "-j")
	require.Equalf(t, apicontract.ExitSuccess, r.code, "%s", r)
	doc := r.rawDoc(t) // see contract/fingerprint-stack-confidence
	assert.Equal(t, true, doc["ok"])
	assert.Equal(t, database.CompletenessComplete, str(doc, "completeness"))

	facts := items(doc)
	require.Len(t, facts, 1, "fingerprint -j items are one host fact set per origin")
	fp, _ := facts[0]["fingerprint"].(map[string]any)
	require.NotNil(t, fp, "the host facts carry a fingerprint block")
	cors, _ := fp["cors"].(map[string]any)
	assert.Equal(t, true, cors["permissive"], "Juice Shop answers any Origin with ACAO *")
	assert.NotNil(t, facts[0]["favicon"], "the favicon hash is recorded")
	stringConfidence := false
	stacks, _ := fp["stacks"].([]any)
	for _, st := range stacks {
		if m, ok := st.(map[string]any); ok {
			_, isString := m["confidence"].(string)
			stringConfidence = stringConfidence || isString
		}
	}
	if !expectKnown(t, "contract/fingerprint-stack-confidence", stringConfidence,
		"fingerprint.stacks[].confidence is a string; the schema says integer") {
		contracttest.Validate(t, str(doc, "command"), []byte(r.stdout))
	}

	s := openStore(t, c.db)
	recs := s.records(t, database.QueryFilters{})
	checkLiveExpectation(t, "live/juice-shop/run-fingerprint", expectation{
		Found: liveKeys(s.findings(t)), Records: len(recs),
	})
	requireTargetSurvived(t, app)
}

// `run discovery`: the content-discovery phase alone surfaces the known
// Juice Shop paths (/ftp and its files, /metrics, the JS chunks).
func TestLive_JuiceShop_RunDiscovery(t *testing.T) {
	app := startLive(t, juiceShop)
	c := newCLI(t)
	r := c.run(t, 8*time.Minute, "run", "discovery", "-t", app.Base+"/", "--discover-max-time", "4m", "-j")
	requireDoc(t, r, capped...)

	s := openStore(t, c.db)
	recs := s.records(t, database.QueryFilters{})
	paths := answeredPaths(recs)
	t.Logf("discovery stored %d records, %d answered paths", len(recs), len(paths))
	for _, must := range []string{"GET /ftp", "GET /ftp/legal.md", "GET /metrics"} {
		assert.Containsf(t, paths, must, "discovery must surface %s", must)
	}

	bogus := 0
	for _, rec := range recs {
		if strings.HasPrefix(urlPath(rec.URL), "/true/") {
			bogus++
		}
	}
	expectKnown(t, "discovery/jstangle-true-prefix", bogus > 0,
		"%d JS-derived records were stored under a bogus /true/ prefix", bogus)

	// Recursion into file stems: a path stored as a file (/main.js,
	// /chunk-abc.js, /favicon_js.ico, a font) must not be brute-forced as if
	// it were a directory (/main/…, /chunk-abc/…).
	stems := map[string]bool{}
	for _, rec := range recs {
		p := urlPath(rec.URL)
		if base := path.Base(p); path.Dir(p) == "/" && strings.Contains(base, ".") {
			stems["/"+strings.TrimSuffix(base, path.Ext(base))+"/"] = true
		}
	}
	underStems := 0
	for _, h := range app.Lab.Ledger.Hits(proxyName) {
		// Stems are top-level, so the hit's first segment is the only candidate.
		if first, _, nested := strings.Cut(strings.TrimPrefix(h.Path, "/"), "/"); nested && stems["/"+first+"/"] {
			underStems++
		}
	}
	t.Logf("%d of %d requests were brute-forced under %d file stems", underStems, app.Lab.Ledger.Count(proxyName), len(stems))
	expectKnown(t, "discovery/recurses-into-file-stems", underStems > 0,
		"%d discovery requests were sent under file stems treated as directories", underStems)

	// Pace: a phase-only run gets the CLI's default --rate-limit (100/s,
	// a token bucket, so ≤ 200 in any second) and --max-per-host (40).
	busiest, peak := app.Lab.Ledger.MaxInWindow(proxyName, time.Second), app.Lab.Ledger.PeakConcurrency(proxyName)
	t.Logf("discovery sent %d requests; busiest second %d, peak concurrency %d", app.Lab.Ledger.Count(proxyName), busiest, peak)
	expectKnown(t, "discovery/ignores-default-rate-limit", busiest > 200,
		"discovery sent %d requests in one second under the default 100/s rate limit", busiest)
	expectKnown(t, "discovery/exceeds-max-per-host", peak > 40,
		"discovery held %d requests in flight under the default --max-per-host 40", peak)

	// No request budget here: the run is time-capped and unpaced, so its
	// count tracks how fast the target answers, not what discovery decided.
	checkLiveExpectation(t, "live/juice-shop/run-discovery", expectation{
		Found: liveKeys(s.findings(t)), Paths: paths, Records: len(recs),
	})
	alive := app.running() && app.alive(30*time.Second)
	expectKnown(t, "live/juice-shop-exhausted-by-scan", !alive, "Juice Shop stopped answering after discovery")
}

// `run spidering`: the browser crawl reaches the SPA's API calls that no
// static link exposes — above all /rest/products/search.
func TestLive_JuiceShop_RunSpidering(t *testing.T) {
	app := startLive(t, juiceShop)
	c := newCLI(t).withBrowser(t)
	r := c.run(t, 8*time.Minute, "run", "spidering", "-t", app.Base+"/", "--spider-max-time", "3m", "-j")
	requireDoc(t, r, capped...)

	s := openStore(t, c.db)
	recs := s.records(t, database.QueryFilters{})
	paths := answeredPaths(recs)
	t.Logf("spidering stored %d records, %d answered paths", len(recs), len(paths))
	for _, rec := range recs {
		assert.Equalf(t, "spidering", rec.Source, "a spidering-only run stored a %q record: %s", rec.Source, rec.URL)
	}
	assert.Contains(t, paths, "GET /rest/products/search", "the spider must reach the search API")
	checkLiveExpectation(t, "live/juice-shop/run-spidering", expectation{Paths: paths, Records: len(recs)})
	requireTargetSurvived(t, app)
}

var juiceSearchModules = []string{"sqli-error-based", "sqli-boolean-blind", "xss-light-url-params"}

// `run dynamic-assessment -m ...` and `scan --only dynamic-assessment -m ...`
// are the same run: both find the search endpoint's SQL injection, only the
// selected active modules report, and the two agree on what they found.
func TestLive_JuiceShop_DynamicAssessmentWithModules(t *testing.T) {
	app := startLive(t, juiceShop)
	target := app.Base + "/rest/products/search?q=apple"
	mods := strings.Join(juiceSearchModules, ",")

	viaRun := newCLI(t)
	r := viaRun.run(t, 5*time.Minute, "run", "dynamic-assessment", "-t", target, "-m", mods, "-j")
	requireDoc(t, r)
	runFindings := openStore(t, viaRun.db).findings(t)
	requireOnlySelectedActive(t, runFindings, juiceSearchModules)

	viaScan := newCLI(t)
	r = viaScan.run(t, 5*time.Minute, "scan", "-t", target, "--only", "dynamic-assessment", "-m", mods, "-j")
	requireDoc(t, r)
	scanFindings := openStore(t, viaScan.db).findings(t)
	requireOnlySelectedActive(t, scanFindings, juiceSearchModules)

	runKeys, scanKeys := liveKeys(runFindings), liveKeys(scanFindings)
	assert.Contains(t, runKeys, "class:sqli@/rest/products/search")
	assert.Equal(t, runKeys, scanKeys, "`run dynamic-assessment` and `scan --only dynamic-assessment` disagree")
	checkLiveExpectation(t, "live/juice-shop/dynamic-assessment-modules", expectation{Found: runKeys})
	requireTargetSurvived(t, app)
}

// A stateless scan (-S) exports its results and leaves nothing behind: the
// default database is untouched and no scratch database survives in TMPDIR.
func TestLive_JuiceShop_StatelessScan(t *testing.T) {
	app := startLive(t, juiceShop)
	c := newCLI(t).withoutDB()
	out := filepath.Join(t.TempDir(), "results.jsonl")

	// --db is refused with -S: the contract is "no persistent store".
	refused := newCLI(t).run(t, time.Minute, "scan", "-S", "-t", app.Base+"/", "-j")
	assert.Equalf(t, apicontract.ExitUsageError, refused.code, "-S with --db must be a usage error\n%s", refused)

	r := c.run(t, 5*time.Minute, "scan", "-S", "-t", app.Base+"/rest/products/search?q=apple",
		"--only", "dynamic-assessment", "-m", "sqli-error-based", "--format", "jsonl", "-o", out, "-j")
	doc, _ := requireDoc(t, r)
	assert.Equal(t, true, doc["stateless"])
	assert.Equal(t, false, doc["persisted"])

	types, modules := map[string]int{}, map[string]bool{}
	f, err := os.Open(out)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var line struct {
			Type string `json:"type"`
			Data struct {
				ModuleID string `json:"module_id"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(sc.Bytes(), &line))
		types[line.Type]++
		if line.Type == "finding" {
			modules[line.Data.ModuleID] = true
		}
	}
	require.NoError(t, sc.Err())
	assert.Positive(t, types["http_record"], "the export carries the traffic")
	assert.True(t, modules["sqli-error-based"], "the export carries the SQLi finding")

	// Nothing persisted: the install's default database has no scan data.
	dbs, _ := filepath.Glob(filepath.Join(c.home, ".vigolium", "database-*.sqlite"))
	for _, p := range dbs {
		s := openStore(t, p)
		assert.Emptyf(t, s.records(t, database.QueryFilters{}), "stateless scan wrote records into %s", p)
		assert.Emptyf(t, s.findings(t), "stateless scan wrote findings into %s", p)
	}
	// Nothing left in TMPDIR that looks like a database.
	_ = filepath.Walk(c.tmp, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && (strings.Contains(p, ".sqlite") || strings.HasSuffix(p, ".db")) {
			t.Errorf("stateless scan left a scratch database behind: %s", p)
		}
		return nil
	})
	requireTargetSurvived(t, app)
}

// The full native scan: every default phase except the two that leave the
// machine (known-issue-scan needs the nuclei template corpus, external
// harvest queries public archives). Discovery and spidering are time-capped
// and the rate is typed so discovery is paced too (an untyped default leaves
// it unpaced — see discovery/ignores-default-rate-limit — and Juice Shop does
// not survive that). The run must reach dynamic assessment and find the
// search endpoint's SQL injection through the phases alone: no target hint.
func TestLive_JuiceShop_NativeScan(t *testing.T) {
	app := startLive(t, juiceShop)
	c := newCLI(t)
	args := []string{"scan", "-t", app.Base + "/", "--skip", "known-issue-scan,external-harvest",
		"--rate-limit", "80", "--discover-max-time", "3m", "--spider-max-time", "3m", "--max-time", "20m", "-j"}
	if findBrowser() == "" {
		args = append(args, "--skip", "spidering")
	} else {
		c.withBrowser(t)
	}
	r := c.run(t, 25*time.Minute, args...)
	doc, reasons := requireDoc(t, r, append(capped, database.ReasonEdgeBlocked, database.ReasonScanBudget, database.ReasonPersistence)...)
	t.Logf("native scan: status=%s completeness=%s reasons=%v in %vms; %d requests through the proxy",
		str(doc, "status"), str(doc, "completeness"), doc["reasons"], doc["duration_ms"], app.Lab.Ledger.Count(proxyName))
	if phases, ok := doc["phase_outcomes"].([]any); ok {
		for _, p := range phases {
			if m, ok := p.(map[string]any); ok {
				t.Logf("  phase %-20v %-10v %vms %v", m["phase"], m["state"], m["duration_ms"], m["reasons"])
			}
		}
	}
	expectKnown(t, "live/juice-shop-false-edge-block", reasons[database.ReasonEdgeBlocked],
		"dynamic assessment reported edge_blocked against Juice Shop, which has no WAF")
	expectKnown(t, "budget/persistence-stop-reason", reasons[database.ReasonPersistence],
		"the budget-curtailed native scan lost writes (persistence_incomplete)")

	survived := app.running() && app.alive(30*time.Second)
	if expectKnown(t, "live/juice-shop-exhausted-by-scan", !survived, "Juice Shop stopped answering after the native scan") {
		t.Skip("the target died mid-scan; its results say nothing about the scanner")
	}

	s := openStore(t, c.db)
	recs := s.records(t, database.QueryFilters{})
	fs := s.findings(t)
	keys := liveKeys(atLeastLow(fs))
	t.Logf("%d records, %d findings; Low+: %v", len(recs), len(fs), keys)
	if findBrowser() != "" {
		missed := !slices.Contains(keys, "class:sqli@/rest/products/search")
		expectKnown(t, "live/native-scan-misses-search-sqli", missed,
			"the native scan did not find the search SQLi via spidering → dynamic assessment (budget: %v)", reasons[database.ReasonScanBudget])
	}
	checkLiveExpectation(t, "live/juice-shop/native-scan", expectation{
		Found: keys, Paths: answeredPaths(recs), Records: len(recs),
	})
	requireTargetSurvived(t, app)
}

// --- VAmPI --------------------------------------------------------------------

func vampiSpec(t *testing.T, base string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "sample-inputs", "vampi-openapi3.yml"))
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "vampi.yml")
	require.NoError(t, os.WriteFile(p, []byte(strings.ReplaceAll(string(raw), "http://localhost:5000", base)), 0o600))
	return p
}

// `run ingestion` of the OpenAPI spec stores exactly one answered record
// per documented operation, every method, and tests nothing.
func TestLive_VAmPI_RunIngestionSpec(t *testing.T) {
	app := startLive(t, vampi)
	c := newCLI(t)
	r := c.run(t, 3*time.Minute, "run", "ingestion", "-i", vampiSpec(t, app.Base), "-I", "openapi", "--spec-url", "-j")
	requireDoc(t, r)

	s := openStore(t, c.db)
	recs := s.records(t, database.QueryFilters{})
	methods := map[string]int{}
	for _, rec := range recs {
		methods[rec.Method]++
		assert.Positivef(t, rec.StatusCode, "ingested %s %s was never answered", rec.Method, rec.URL)
	}
	assert.Len(t, recs, 14, "VAmPI's spec documents 14 operations")
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		assert.Positivef(t, methods[m], "no %s operation ingested", m)
	}
	assert.Empty(t, s.findings(t), "ingestion alone runs no modules")
	requireTargetSurvived(t, app)
}

var vampiModules = []string{"sqli-error-based", "sqli-boolean-blind"}

// A spec-driven scan with SQLi modules finds VAmPI's injectable username path
// parameter and the Werkzeug debugger it leaks on error.
func TestLive_VAmPI_SpecScanWithModules(t *testing.T) {
	app := startLive(t, vampi)
	c := newCLI(t)
	r := c.run(t, 5*time.Minute, "scan", "-i", vampiSpec(t, app.Base), "-I", "openapi", "--spec-url",
		"--only", "dynamic-assessment", "-m", strings.Join(vampiModules, ","), "-j")
	requireDoc(t, r)

	s := openStore(t, c.db)
	fs := s.findings(t)
	requireOnlySelectedActive(t, fs, vampiModules)
	sqli := false
	for _, k := range liveKeys(fs) {
		sqli = sqli || strings.HasPrefix(k, "class:sqli@/users/v*/")
	}
	assert.True(t, sqli, "the SQL injection in /users/v1/{username} must be found by an sqli module")
	checkLiveExpectation(t, "live/vampi/spec-scan-modules", expectation{
		Found: liveKeys(atLeastLow(fs)), Records: len(s.records(t, database.QueryFilters{})),
	})
	requireTargetSurvived(t, app)
}
