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

// setupPipelineDB creates a database for pipeline tests.
//
// Default: in-memory SQLite (fast, isolated per-test).
// When VIGOLIUM_TEST_DB_DRIVER=postgres: connects to the shared PG instance
// configured via VIGOLIUM_PG_* env vars (defaults match test/testdata/postgres/
// docker-compose.yaml) and drops+recreates the schema for per-test isolation.
// Intended for pre-deploy validation of schema compatibility with real PG.
func setupPipelineDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	ctx := context.Background()

	if os.Getenv("VIGOLIUM_TEST_DB_DRIVER") == "postgres" {
		db, err := database.NewDB(pgTestConfigFromEnv())
		if err != nil {
			t.Skipf("PostgreSQL not available (start with 'make postgres-up'): %v", err)
		}
		dropAllVigoliumTables(ctx, db)
		require.NoError(t, db.CreateSchema(ctx))
		require.NoError(t, db.SeedDefaults(ctx))
		t.Cleanup(func() { db.Close() })
		return db, database.NewRepository(db)
	}

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

// startJuiceShop starts a Juice Shop container and returns the app.
func startJuiceShop(t *testing.T) *VulnerableApp {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "bkimminich/juice-shop:latest",
		ExposedPort: "3000/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("3000").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start Juice Shop container")
	t.Cleanup(func() { _ = app.Stop() })

	t.Logf("Juice Shop running at %s", app.BaseURL)
	return app
}

// juiceShopEndpoints returns Juice Shop endpoints for scanning.
func juiceShopEndpoints(baseURL string) []string {
	return []string{
		baseURL + "/rest/products/search?q=test",
		baseURL + "/api/Users/?username=admin",
	}
}

// --- Tests ---

// TestScanRunner_VAmPI_OnlyDynamicAssessment validates --only dynamic-assessment
// flag behavior via the Runner. Discovery, external harvest, and KnownIssueScan are disabled;
// only the dynamic-assessment phase runs against known vulnerable endpoints.
func TestScanRunner_VAmPI_OnlyDynamicAssessment(t *testing.T) {
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
	// --only dynamic-assessment equivalent
	opts.SkipDynamicAssessment = false
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false

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
	opts.KnownIssueScanEnabled = false
	opts.SkipDynamicAssessment = true

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: HTTP records were ingested
	hosts, err := repo.GetDistinctHosts(ctx, database.DefaultProjectUUID)
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
	opts.SkipDynamicAssessment = false
	// No OnlyPhase, no strategy override — default audit
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: HTTP records were ingested
	hosts, err := repo.GetDistinctHosts(ctx, database.DefaultProjectUUID)
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
// audit only, no discovery, no external harvest, no KnownIssueScan.
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
	opts.KnownIssueScanEnabled = false
	opts.SkipDynamicAssessment = false

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: findings in DB >= 1
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 1,
		"Expected at least 1 finding with lite strategy against VAmPI")

	// Assert: no deparos discovery records (only the explicit target URLs should exist)
	hosts, err := repo.GetDistinctHosts(ctx, database.DefaultProjectUUID)
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
// but discovery/KnownIssueScan/DA are all skipped. External sources won't find anything
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
	opts.KnownIssueScanEnabled = false
	opts.SkipDynamicAssessment = true

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: original targets were ingested into DB (discovery phase always runs the input source)
	hosts, err := repo.GetDistinctHosts(ctx, database.DefaultProjectUUID)
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

// TestScanRunner_VAmPI_OnlyKnownIssueScan validates --only known-issue-scan: the KnownIssueScan phase runs nuclei
// and kingfisher batch scans after ingesting targets, but audit is skipped.
func TestScanRunner_VAmPI_OnlyKnownIssueScan(t *testing.T) {
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
	// --only known-issue-scan equivalent
	opts.KnownIssueScanEnabled = true
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.SkipDynamicAssessment = true

	r, db, repo := newScanRunner(t, opts)

	err := r.RunNativeScan()
	require.NoError(t, err, "RunNativeScan should complete without error")

	// Assert: targets were ingested (discovery phase always ingests input)
	hosts, err := repo.GetDistinctHosts(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(hosts), 1,
		"Expected at least one host in DB after KnownIssueScan pipeline")
	t.Logf("KnownIssueScan: %d distinct hosts ingested", len(hosts))

	// KnownIssueScan runs nuclei + kingfisher. Nuclei may or may not find issues in VAmPI
	// depending on available templates. Kingfisher may not be installed.
	// Both sub-phases log errors but don't fail the pipeline.
	// Assert that scan completed and log any KnownIssueScan findings.
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{Limit: 100}).Execute(ctx)
	require.NoError(t, err)
	t.Logf("KnownIssueScan: %d findings (nuclei + kingfisher)", len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Severity, f.ModuleID, f.ModuleName)
	}
}

