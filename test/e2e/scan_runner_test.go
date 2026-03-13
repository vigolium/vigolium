//go:build canary

package e2e

import (
	"context"
	"os"
	"path/filepath"
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

// --- Helpers ---

// startVAmPI starts a VAmPI container and returns the app.
func startVAmPI(t *testing.T) *VulnerableApp {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "erev0s/vampi:latest",
		ExposedPort: "5000/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("5000").
			WithStartupTimeout(60 * time.Second),
		Env: map[string]string{
			"vulnerable": "1",
		},
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start VAmPI container")
	t.Cleanup(func() { _ = app.Stop() })

	t.Logf("VAmPI running at %s", app.BaseURL)
	return app
}

// vampiVulnerableEndpoints returns VAmPI endpoints known to have SQL injection vulnerabilities.
func vampiVulnerableEndpoints(baseURL string) []string {
	return []string{
		baseURL + "/users/v1/_debug?username=admin",
		baseURL + "/books/v1?book=test",
	}
}

// newScanRunner creates a Runner with an in-memory DB and default settings.
// It returns the runner, the underlying DB (for queries), and the repository.
func newScanRunner(t *testing.T, opts *types.Options) (*runner.Runner, *database.DB, *database.Repository) {
	t.Helper()
	return newScanRunnerWithSettings(t, opts, config.DefaultSettings())
}

// newScanRunnerWithSettings creates a Runner with an in-memory DB and custom settings.
func newScanRunnerWithSettings(t *testing.T, opts *types.Options, settings *config.Settings) (*runner.Runner, *database.DB, *database.Repository) {
	t.Helper()

	db, repo := setupPipelineDB(t)

	r, err := runner.New(opts)
	require.NoError(t, err)

	r.SetSettings(settings)
	r.SetRepository(repo)

	t.Cleanup(func() { r.Close() })
	return r, db, repo
}

// --- Tests ---

// TestScanRunner_VAmPI_OnlyAudit validates --only audit
// flag behavior via the Runner. Discovery, external harvest, and SPA are disabled;
// only the audit phase runs against known vulnerable endpoints.
func TestScanRunner_VAmPI_OnlyAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping canary test in short mode")
	}

	app := startVAmPI(t)
	ctx := context.Background()

	opts := types.DefaultOptions()
	opts.Targets = vampiVulnerableEndpoints(app.BaseURL)
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	// --only audit equivalent
	opts.SkipAudit = false
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SPAEnabled = false

	r, db, _ := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: findings exist in DB
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 1,
		"Expected at least 1 finding from audit against VAmPI")

	t.Logf("Audit found %d findings", len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
	}
}

// TestScanRunner_VAmPI_OnlyDiscover validates --only discovery: discovery runs
// and ingests HTTP records, but audit is skipped (no findings).
func TestScanRunner_VAmPI_OnlyDiscover(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping canary test in short mode")
	}

	app := startVAmPI(t)
	ctx := context.Background()

	opts := types.DefaultOptions()
	opts.Targets = []string{app.BaseURL}
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	// --only discovery equivalent
	opts.DiscoverEnabled = true
	opts.ExternalHarvestEnabled = false
	opts.SPAEnabled = false
	opts.SkipAudit = true

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: HTTP records were ingested
	hosts, err := repo.GetDistinctHosts(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(hosts), 1,
		"Expected at least one host in DB after discovery")
	t.Logf("Discover phase ingested %d distinct hosts", len(hosts))

	// Assert: no findings (audit was skipped)
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, len(findings),
		"Expected 0 findings when audit is skipped")
}

// TestScanRunner_JuiceShop_FullPipeline validates the full pipeline (no --only)
// against Juice Shop. All phases run with their defaults.
func TestScanRunner_JuiceShop_FullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping canary test in short mode")
	}

	app := startJuiceShop(t)
	ctx := context.Background()

	opts := types.DefaultOptions()
	opts.Targets = juiceShopEndpoints(app.BaseURL)
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.SkipAudit = false
	// No OnlyPhase, no strategy override — default audit
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SPAEnabled = false

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: HTTP records were ingested
	hosts, err := repo.GetDistinctHosts(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(hosts), 1,
		"Expected at least one host in DB after full pipeline")

	// Assert: scan completed and produced records
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	// Juice Shop has modern protections, findings not guaranteed — just assert scan ran
	t.Logf("Full pipeline: %d hosts, %d findings", len(hosts), len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
	}
}

// TestScanRunner_VAmPI_StrategyLite validates the "lite" strategy preset:
// audit only, no discovery, no external harvest, no SPA.
func TestScanRunner_VAmPI_StrategyLite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping canary test in short mode")
	}

	app := startVAmPI(t)
	ctx := context.Background()

	opts := types.DefaultOptions()
	opts.Targets = vampiVulnerableEndpoints(app.BaseURL)
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	// Lite strategy fields: audit only
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SPAEnabled = false
	opts.SkipAudit = false

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: findings in DB >= 1
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 1,
		"Expected at least 1 finding with lite strategy against VAmPI")

	// Assert: no deparos discovery records (only the explicit target URLs should exist)
	hosts, err := repo.GetDistinctHosts(ctx)
	require.NoError(t, err)
	// With discovery disabled, only the VAmPI host should appear
	assert.LessOrEqual(t, len(hosts), 1,
		"Expected at most 1 host (no discovery expansion)")

	t.Logf("Lite strategy: %d findings, %d hosts", len(findings), len(hosts))
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
	}
}

// TestScanRunner_VAmPI_OnlyExternalHarvest validates --only external-harvest:
// external intelligence sources are queried, original targets are ingested,
// but discovery/SPA/DA are all skipped. External sources won't find anything
// for a local container, so this also exercises the empty-harvest path.
func TestScanRunner_VAmPI_OnlyExternalHarvest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping canary test in short mode")
	}

	app := startVAmPI(t)
	ctx := context.Background()

	opts := types.DefaultOptions()
	opts.Targets = vampiVulnerableEndpoints(app.BaseURL)
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	// --only external-harvest equivalent
	opts.ExternalHarvestEnabled = true
	opts.DiscoverEnabled = false
	opts.SPAEnabled = false
	opts.SkipAudit = true

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: original targets were ingested into DB (discovery phase always runs the input source)
	hosts, err := repo.GetDistinctHosts(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(hosts), 1,
		"Expected at least one host in DB from original targets")
	t.Logf("External harvest: %d distinct hosts ingested", len(hosts))

	// Assert: no findings (audit was skipped)
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, len(findings),
		"Expected 0 findings when only external-harvest is enabled (DA skipped)")
}

// TestScanRunner_VAmPI_OnlySPA validates --only spa: the SPA phase runs nuclei
// and kingfisher batch scans after ingesting targets, but audit is skipped.
func TestScanRunner_VAmPI_OnlySPA(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping canary test in short mode")
	}

	app := startVAmPI(t)
	ctx := context.Background()

	opts := types.DefaultOptions()
	opts.Targets = vampiVulnerableEndpoints(app.BaseURL)
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	// --only spa equivalent
	opts.SPAEnabled = true
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SkipAudit = true

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: targets were ingested (discovery phase always ingests input)
	hosts, err := repo.GetDistinctHosts(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(hosts), 1,
		"Expected at least one host in DB after SPA pipeline")
	t.Logf("SPA: %d distinct hosts ingested", len(hosts))

	// SPA runs nuclei + kingfisher. Nuclei may or may not find issues in VAmPI
	// depending on available templates. Kingfisher may not be installed.
	// Both sub-phases log errors but don't fail the pipeline.
	// Assert that scan completed and log any SPA findings.
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	t.Logf("SPA: %d findings (nuclei + kingfisher)", len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
	}
}

// TestScanRunner_VAmPI_SourceAwareDA validates source-aware scanning via the
// Runner: a JS extension module reads files from a registered SourceRepo and
// produces findings based on source code analysis during the audit.
func TestScanRunner_VAmPI_SourceAwareDA(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping canary test in short mode")
	}

	app := startVAmPI(t)
	ctx := context.Background()

	// --- Set up mock source repo ---
	sourceDir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(sourceDir, "app.py"),
		[]byte(`from flask import Flask\napp = Flask(__name__)\n# SQL query: SELECT * FROM users\n`),
		0644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(sourceDir, "requirements.txt"),
		[]byte("flask\nsqlalchemy\n"),
		0644,
	))

	// --- Create JS extension script ---
	scriptDir := t.TempDir()
	scriptPath := filepath.Join(scriptDir, "source_check.js")
	require.NoError(t, os.WriteFile(scriptPath, []byte(`
module.exports = {
  id: "source-check",
  name: "Source Code Check",
  description: "Checks source repo for SQL patterns",
  type: "active",
  severity: "info",
  scanTypes: ["per_host"],

  scanPerHost: function(ctx) {
    var host = ctx.request.host;
    if (!host) return [];

    // Strip port from host (e.g. "localhost:55234" -> "localhost")
    var hostname = host.split(":")[0];

    var repos = vigolium.source.getByHostname(hostname);
    if (!repos || repos.length === 0) {
      return [];
    }

    var repo = repos[0];
    var content = vigolium.source.readFile(hostname, "app.py");
    if (!content) return [];

    // Search for SQL patterns in source
    var matches = vigolium.source.searchFiles(hostname, "SQL");
    if (!matches || matches.length === 0) return [];

    return [{
      matched: "source-aware-finding",
      url: ctx.request.url,
      name: "SQL Pattern in Source",
      description: "Found " + matches.length + " SQL patterns in source code of " + repo.name,
      severity: "info"
    }];
  }
};
`), 0644))

	// --- Build custom settings with extensions enabled ---
	settings := config.DefaultSettings()
	settings.Audit.Extensions.Enabled = true
	settings.Audit.Extensions.Scripts = []string{scriptPath}
	settings.Audit.Extensions.Limits = config.ScriptLimits{
		Timeout:     "60s",
		MaxMemoryMB: 128,
	}

	// --- Build runner options ---
	opts := types.DefaultOptions()
	opts.Targets = vampiVulnerableEndpoints(app.BaseURL)
	opts.Modules = []string{"all"}
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.SkipAudit = false
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SPAEnabled = false

	r, db, repo := newScanRunnerWithSettings(t, opts, settings)

	// Register the source repo for the VAmPI container's hostname.
	// The container URL is like http://localhost:XXXXX, extract just "localhost".
	sr := &database.SourceRepo{
		ProjectUUID: database.DefaultProjectUUID,
		Hostname:    "localhost",
		Name:        "vampi-source",
		RootPath:    sourceDir,
		RepoType:    "folder",
		Language:    "python",
	}
	require.NoError(t, repo.CreateSourceRepo(ctx, sr))

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: findings exist from both built-in modules and the JS extension
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 200}).Execute(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 1,
		"Expected at least 1 finding from source-aware DA")

	// Check for source-aware JS module findings specifically
	var jsFindings int
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
		if f.ModuleID == "ext-source-check" {
			jsFindings++
		}
	}
	t.Logf("Source-aware DA: %d total findings, %d from JS extension", len(findings), jsFindings)
	assert.GreaterOrEqual(t, jsFindings, 1,
		"Expected at least 1 finding from the source-aware JS extension module")
}
