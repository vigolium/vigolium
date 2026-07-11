//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// This file holds HERMETIC end-to-end tests for internal/runner's
// RunNativeScan() orchestration. They exercise the same code path the canary
// suite (scan_runner_test.go) drives against Dockerized vulnerable apps, but
// instead point the runner at an in-process httptest.Server with an in-memory
// SQLite DB. No Docker, no network egress — fully deterministic.
//
// The canary-only helpers (setupPipelineDB / newScanRunner) are NOT compiled
// under the `e2e` tag, so this file defines its own self-contained, distinctly
// named equivalents: hermeticDB and hermeticRunner.

// hermeticDB creates a fresh in-memory SQLite database with the schema applied.
// Mirrors setupPipelineDB's SQLite branch (scan_runner_test.go) but is
// self-contained so it compiles under the `e2e` build tag.
func hermeticDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	ctx := context.Background()

	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        ":memory:",
			BusyTimeout: 5000,
			JournalMode: "MEMORY",
			Synchronous: "OFF",
			CacheSize:   10000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(ctx))
	t.Cleanup(func() { db.Close() })
	return db, database.NewRepository(db)
}

// hermeticRunner wires a Runner to an in-memory DB and default settings, then
// registers cleanup. Mirrors newScanRunner (scan_runner_test.go) but with a
// distinct name so both can coexist under different build tags.
func hermeticRunner(t *testing.T, opts *types.Options) (*runner.Runner, *database.DB, *database.Repository) {
	t.Helper()

	db, repo := hermeticDB(t)

	r, err := runner.New(opts)
	require.NoError(t, err)

	r.SetSettings(config.DefaultSettings())
	r.SetRepository(repo)

	t.Cleanup(func() { r.Close() })
	return r, db, repo
}

// hermeticOptions returns options tuned for fast, deterministic in-process
// scans: low concurrency, short retries, and the tech-stack allowlist disabled
// so module selection never depends on fingerprinting a synthetic test server.
func hermeticOptions() *types.Options {
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Concurrency = 4
	opts.MaxPerHost = 4
	opts.Retries = 0
	// Synthetic test servers have no real tech stack to fingerprint; bypass the
	// allowlist gate so the chosen modules always run.
	opts.NoTechFilter = true
	return opts
}

// findingsCount returns the number of findings currently stored in the DB.
func findingsCount(t *testing.T, db *database.DB) int {
	t.Helper()
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 1000}).Execute(context.Background())
	require.NoError(t, err)
	return len(findings)
}

// TestScanRunnerHermetic_DynamicAssessmentFindsVuln drives the dynamic-assessment
// phase against an in-process open-redirect endpoint. The endpoint 302s to
// whatever the `next` query parameter holds, which the open-redirect active
// module reliably flags. Exercises: seed (CLI target ingestion, discovery off) →
// dynamic-assessment (active module dispatch + finding persistence).
func TestScanRunnerHermetic_DynamicAssessmentFindsVuln(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping hermetic e2e test in short mode")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next := r.URL.Query().Get("next"); next != "" {
			w.Header().Set("Location", next) // unvalidated redirect — open redirect
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ctx := context.Background()

	opts := hermeticOptions()
	// The `next` value is deliberately a bare token (not an absolute URL): the
	// scope matcher derives scope from the seed target and treats a query value
	// like "https://attacker.tld" as an additional in-scope host, which then
	// excludes the 127.0.0.1 record from the scan. A plain token avoids that —
	// the open-redirect module brute-forces its own attacker payloads into the
	// `next` parameter (whose name matches the module's redirect-param list)
	// regardless of the original value, and the handler echoes them into the
	// Location header, yielding a deterministic finding.
	opts.Targets = []string{srv.URL + "/redirect?next=account"}
	// Restrict to the single relevant active module so the phase stays fast and
	// the assertion is unambiguous. Passive modules are disabled.
	opts.Modules = []string{"open-redirect"}
	opts.PassiveModules = []string{}
	// --only dynamic-assessment equivalent: seed ingests the CLI target, then
	// dynamic-assessment runs. Discovery / harvest / known-issue all off.
	opts.SkipDynamicAssessment = false
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false

	r, db, _ := hermeticRunner(t, opts)

	require.NoError(t, r.RunNativeScan(), "RunNativeScan should complete without error")

	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 1,
		"expected at least 1 open-redirect finding from the dynamic-assessment phase")

	t.Logf("dynamic-assessment found %d findings", len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
	}
}

// TestScanRunnerHermetic_DiscoveryIngestsRecords drives the discovery phase
// against an in-process HTML site. Deparos content discovery is enabled and
// dynamic-assessment is skipped, so the run ingests HTTP records into the DB but
// produces no findings. Exercises: discovery (input source + deparos ingestion,
// no modules) and the SkipDynamicAssessment short-circuit.
func TestScanRunnerHermetic_DiscoveryIngestsRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping hermetic e2e test in short mode")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/about">about</a>
			<a href="/contact">contact</a>
		</body></html>`)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>about page</body></html>`)
	})
	mux.HandleFunc("/contact", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>contact page</body></html>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx := context.Background()

	opts := hermeticOptions()
	opts.Targets = []string{srv.URL}
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{}
	// --only discovery equivalent.
	opts.DiscoverEnabled = true
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.SkipDynamicAssessment = true

	r, db, repo := hermeticRunner(t, opts)

	require.NoError(t, r.RunNativeScan(), "RunNativeScan should complete without error")

	hosts, err := repo.GetDistinctHosts(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(hosts), 1,
		"expected at least one host in DB after discovery ingested records")
	t.Logf("discovery ingested %d distinct host(s)", len(hosts))

	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, len(findings),
		"expected 0 findings when dynamic-assessment is skipped")
}

// TestScanRunnerHermetic_PassiveOnlyFinding drives a passive-only dynamic
// assessment. The endpoint sets an insecure session cookie (no HttpOnly /
// SameSite), which the cookie-security-detect passive module reliably flags
// without sending any extra traffic. Because a likely session cookie missing a
// material transport/script protection is classified as a *candidate* (the
// module never emits a full record_kind='finding' row — see the module's
// metadata), the assertion checks for a persisted candidate record. No active
// modules run. Exercises: seed ingestion → dynamic-assessment passive-module
// dispatch → finding-table persistence on a stored record.
func TestScanRunnerHermetic_PassiveOnlyFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping hermetic e2e test in short mode")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Insecure session cookie: missing HttpOnly and SameSite. The missing
		// HttpOnly flag on a likely session cookie is a material protection gap,
		// so cookie-security-detect emits a candidate record regardless of scheme
		// (Secure is only required on HTTPS, see cookie_security_detect).
		w.Header().Set("Set-Cookie", "sessionid=abc123; Path=/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>login</body></html>`)
	}))
	t.Cleanup(srv.Close)

	ctx := context.Background()

	opts := hermeticOptions()
	opts.Targets = []string{srv.URL + "/login"}
	// No active modules; a single deterministic passive module.
	opts.Modules = []string{}
	opts.PassiveModules = []string{"cookie-security-detect"}
	opts.SkipDynamicAssessment = false
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false

	r, db, repo := hermeticRunner(t, opts)

	require.NoError(t, r.RunNativeScan(), "RunNativeScan should complete without error")

	// The CLI target must have been ingested (seed phase).
	hosts, err := repo.GetDistinctHosts(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(hosts), 1, "expected the CLI target to be ingested")

	// The module classifies a session cookie missing HttpOnly as a candidate,
	// not a record_kind='finding' row, so the default finding-only query returns
	// nothing.
	assert.Equal(t, 0, findingsCount(t, db),
		"cookie-security-detect emits candidates, not findings, for this cookie")

	// Query the candidate tier: the passive dispatch must have persisted the
	// cookie-security-detect record to the findings table.
	candidates, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{
		Limit:       100,
		RecordKinds: []string{database.RecordKindCandidate},
	}).Execute(ctx)
	require.NoError(t, err)
	t.Logf("passive-only run produced %d candidate record(s)", len(candidates))
	for _, f := range candidates {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
	}
	assert.GreaterOrEqual(t, len(candidates), 1,
		"expected at least 1 passive cookie-security candidate record")
	found := false
	for _, f := range candidates {
		if f.ModuleID == "cookie-security-detect" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected a cookie-security-detect candidate record")
}
