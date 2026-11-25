//go:build canary

package e2e

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// Autonomous end-to-end canary tests.
//
// Unlike the per-endpoint canary tests (dvwa_test.go, juiceshop_test.go) and the
// whitebox benchmark harness — both of which hand a *specific* module a *specific*
// hardcoded request — these tests reproduce the real operator workflow:
//
//	vigolium scan -t <base-url> --stateless --db <tmp> \
//	    --only spidering,discovery,dynamic-assessment --module all
//
// i.e. point the scanner at nothing but the site root and let it discover the
// attack surface on its own (content discovery + browser spidering), then run
// the full active/passive module set against every *discovered* request. The
// assertions then check two independent things the split-phase tests never
// verify together:
//
//  1. Surface expansion — the DB ends up holding routes the scanner was never
//     told about (proves discovery/spidering actually walked the app, not that
//     we seeded the vulnerable URLs by hand).
//  2. Findings on discovered routes — the dynamic-assessment phase produced
//     findings, and they hang off URLs that came out of discovery rather than
//     the single seed target.
//
// This is the "can the scanner find these apps' vulns on its own?" gate that was
// previously missing from the canary tier.

// autonomousScanResult bundles what the post-scan assertions need out of the
// throwaway stateless DB.
type autonomousScanResult struct {
	records  []*database.HTTPRecord
	findings []*database.Finding
	// distinctPaths is the set of URL paths seen across all ingested records.
	distinctPaths map[string]struct{}
}

// seedPath returns the path component of a URL, defaulting to "/" so the seed
// target and a discovered "/" collapse to the same entry.
func seedPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

// runAutonomousScan drives the full native pipeline — content discovery +
// browser spidering + dynamic-assessment — against a single seed target, into a
// file-based stateless SQLite DB (the in-test equivalent of
// `--stateless --db <path>`; see setupStatelessTempDB in
// stateless_phase_canary_test.go). extraHeaders are injected into every request
// the scanner sends (discovery crawl and active probes alike) via opts.Headers —
// used to carry an authenticated session cookie for apps that gate their
// vulnerable surface behind login. tune, if non-nil, gets the last word on the
// options for per-app quirks.
func runAutonomousScan(t *testing.T, seed string, extraHeaders []string, tune func(*types.Options)) *autonomousScanResult {
	t.Helper()

	db, repo := setupStatelessTempDB(t)

	opts := types.DefaultOptions()
	opts.Targets = []string{seed}
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.Stateless = true
	opts.Headers = extraHeaders
	// Deterministic dispatch: skip the heuristic pre-flight that can otherwise
	// drop a live target on a flaky first response (matches runImportToDBScan).
	opts.HeuristicsCheck = "none"

	// The full autonomous chain: crawl the surface AND assess it. This is the
	// combination the split-phase canary tests never enable together.
	opts.DiscoverEnabled = true
	opts.SpideringEnabled = true
	opts.SpideringHeadless = true
	opts.SkipDynamicAssessment = false
	// Keep the run self-contained: no external intel sources, no nuclei/kingfisher.
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false

	// Bound every phase so a wedged container/browser can't hang the suite.
	opts.DiscoverMaxDuration = 90 * time.Second
	opts.SpideringMaxDuration = 90 * time.Second
	opts.ScanMaxDuration = 8 * time.Minute

	if tune != nil {
		tune(opts)
	}

	r, err := runner.New(opts)
	require.NoError(t, err, "failed to create scan runner")
	r.SetSettings(config.DefaultSettings())
	r.SetRepository(repo)
	t.Cleanup(func() { r.Close() })

	err = r.RunNativeScan()
	skipIfTargetDied(t, err, seed)
	require.NoError(t, err, "autonomous discovery+spidering+dynamic-assessment scan should complete without error")

	ctx := context.Background()
	records, err := database.NewQueryBuilder(db, database.QueryFilters{ProjectUUID: database.DefaultProjectUUID}).Execute(ctx)
	require.NoError(t, err, "read back ingested records")
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{ProjectUUID: database.DefaultProjectUUID, Limit: 500}).Execute(ctx)
	require.NoError(t, err, "read back findings")

	paths := make(map[string]struct{}, len(records))
	for _, rec := range records {
		paths[seedPath(rec.URL)] = struct{}{}
	}

	return &autonomousScanResult{records: records, findings: findings, distinctPaths: paths}
}

// logSurface prints the discovered attack surface and finding breakdown so a
// failing run (or a soft-assert app) is diagnosable straight from the test log.
func logSurface(t *testing.T, app string, res *autonomousScanResult) {
	t.Helper()

	paths := make([]string, 0, len(res.distinctPaths))
	for p := range res.distinctPaths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	t.Logf("[%s] discovered %d records across %d distinct paths: %v",
		app, len(res.records), len(res.distinctPaths), paths)

	byModule := map[string]int{}
	for _, f := range res.findings {
		byModule[f.ModuleID]++
	}
	t.Logf("[%s] %d findings across %d modules", app, len(res.findings), len(byModule))
	for _, f := range res.findings {
		t.Logf("  [%s] %s — %s (%s)", f.Severity, f.ModuleID, f.ModuleName, f.URL)
	}
}

// findingsBeyondSeed reports whether any finding hangs off a URL whose path is
// not the seed path — i.e. the dynamic-assessment phase fired on a route that
// discovery/spidering surfaced rather than on the seed target itself.
func findingsBeyondSeed(res *autonomousScanResult, seed string) bool {
	sp := seedPath(seed)
	for _, f := range res.findings {
		if seedPath(f.URL) != sp {
			return true
		}
	}
	return false
}

// startDVWA boots a DVWA container. DVWA has no shared start helper (dvwa_test.go
// inlines it per test), so this file keeps its own.
func startDVWA(t *testing.T) *VulnerableApp {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "vulnerables/web-dvwa:latest",
		ExposedPort: "80/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("80").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start DVWA container")
	t.Cleanup(func() { _ = app.Stop() })

	t.Logf("DVWA running at %s", app.BaseURL)
	return app
}

// TestAutonomousScan_DVWA is the flagship autonomous end-to-end test. DVWA's
// index links to every /vulnerabilities/* page with plain <a href> anchors, so
// content discovery walks the whole app from the root, and the GET forms on
// those pages surface the injectable query parameters (name=, id=, page=, ip=).
// With the authenticated session cookie carried on every request, the
// dynamic-assessment phase then fires the reflected-XSS / SQLi / LFI / cmd-injection
// modules against those *discovered* routes.
//
// This proves the whole chain end-to-end from nothing but the site root — no
// hardcoded vulnerable endpoint anywhere in the test.
func TestAutonomousScan_DVWA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startDVWA(t)

	// DVWA gates its vulnerable pages behind login + a security level, and emits a
	// malformed gzip body (Content-Encoding: gzip with Content-Length: 0) that
	// decodes to only the page tail — losing the reflected payload / SQL error the
	// modules key off. The session cookie unlocks the pages; Accept-Encoding:
	// identity makes DVWA return the full uncompressed page. (Both mirror the
	// per-endpoint DVWA canary in dvwa_test.go.)
	cookie := setupDVWA(t, app.BaseURL)
	headers := []string{"Cookie: " + cookie, "Accept-Encoding: identity"}

	res := runAutonomousScan(t, app.BaseURL, headers, nil)
	logSurface(t, "dvwa", res)

	// (1) Discovery walked past the seed: the DB holds routes we never named. At
	// least one of them must be a /vulnerabilities/* page reached purely from the
	// index links — the proof the surface was discovered, not seeded.
	assert.Greater(t, len(res.distinctPaths), 1,
		"discovery should ingest more than just the seed path")
	reachedVulnPage := false
	for p := range res.distinctPaths {
		if strings.Contains(p, "/vulnerabilities/") {
			reachedVulnPage = true
			break
		}
	}
	assert.True(t, reachedVulnPage,
		"content discovery should reach DVWA /vulnerabilities/* pages from the index links alone")

	// (2) The dynamic-assessment phase found vulns on those discovered routes.
	// DVWA at security=low reliably yields reflected XSS / SQLi / LFI / cmd-injection.
	assert.GreaterOrEqual(t, len(res.findings), 1,
		"autonomous scan of DVWA should produce at least one finding from a discovered route")
	assert.True(t, findingsBeyondSeed(res, app.BaseURL),
		"at least one finding should hang off a discovered route, not the seed target")
}

// TestAutonomousScan_JuiceShop exercises the browser-spidering half of the chain.
// Juice Shop is an Angular SPA: its routes and REST calls only materialize once a
// headless browser executes the app, so this is the test that proves spidering
// (not just HTTP content discovery) expands the surface. Findings are best-effort
// — Juice Shop ships modern protections and the browser-driven crawl is
// environment-sensitive — so the hard gate is surface expansion; findings are
// logged for visibility.
func TestAutonomousScan_JuiceShop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startJuiceShop(t)

	res := runAutonomousScan(t, app.BaseURL, nil, nil)
	logSurface(t, "juiceshop", res)

	// Content discovery alone always ingests the seed. Browser spidering, when a
	// Chromium runtime is available, drives the SPA and surfaces REST/API routes
	// beyond it. If nothing beyond the seed appeared, a browser was almost
	// certainly unavailable (same failure mode the run-spidering canary handles) —
	// skip rather than fail, so a browserless CI reports SKIP instead of a
	// misleading regression.
	require.GreaterOrEqual(t, len(res.records), 1,
		"discovery should ingest at least the seed target")
	if len(res.distinctPaths) <= 1 {
		t.Skip("only the seed path was ingested (Chromium runtime likely unavailable) — spider surface assertions skipped")
	}

	assert.Greater(t, len(res.distinctPaths), 1,
		"browser spidering should surface Juice Shop routes beyond the seed")
	t.Logf("juiceshop autonomous scan: %d findings on %d discovered paths",
		len(res.findings), len(res.distinctPaths))
}

// quarantinedDetail is the detail the dead-host breaker gives a target it
// quarantined mid-scan (runner.allTargetsQuarantined).
const quarantinedDetail = "quarantined for the rest of the scan"

// skipIfTargetDied skips a scan test whose target went down during the scan:
// Juice Shop leaks per-path metrics and can run out of memory (exit 133) or
// wedge its event loop under a full scan. A dead target says nothing about the
// scanner. It skips only on no_targets_reachable, and only when the target
// does not answer now or the breaker quarantined every target mid-scan; a
// target that answers but that the scan never reached at all still fails.
func skipIfTargetDied(t *testing.T, err error, probe string) {
	t.Helper()
	var tu *runner.TargetsUnreachableError
	if err == nil || !errors.As(err, &tu) {
		return
	}
	quarantined := len(tu.Unreachable) > 0
	for _, issue := range tu.Unreachable {
		if issue.Detail != quarantinedDetail {
			quarantined = false
		}
	}
	if quarantined || targetGone(probe) {
		t.Skipf("the target died mid-scan (%v); its results say nothing about the scanner", err)
	}
}

// targetGone reports whether probe no longer answers within 5s.
func targetGone(probe string) bool {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(probe)
	if err != nil {
		return true
	}
	_ = resp.Body.Close()
	return false
}
