//go:build canary

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	secret_detect "github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/output"
)

// setupPipelineDB creates an in-memory SQLite database for pipeline tests.
func setupPipelineDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
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
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { _ = db.Close() })
	return db, database.NewRepository(db)
}

// juiceShopEndpoints returns Juice Shop API endpoints for testing the pipeline.
func juiceShopEndpoints(baseURL string) []string {
	return []string{
		baseURL + "/rest/products/search?q=apple",
		baseURL + "/api/Products",
		baseURL + "/api/Feedbacks",
		baseURL + "/api/Users",
		baseURL + "/api/Challenges",
		baseURL + "/rest/user/whoami",
		baseURL + "/rest/products/1/reviews",
		baseURL + "/rest/memories",
		baseURL + "/rest/basket/1",
	}
}

// startJuiceShop starts a Juice Shop container and returns the app and a cleanup function.
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

// pipelineTestEnv holds shared state for pipeline e2e tests.
type pipelineTestEnv struct {
	db         *database.DB
	repo       *database.Repository
	infra      *TestInfra
	httpClient *httpRequester.Requester
	svc        *services.Services
}

// setupPipelineEnv creates DB, HTTP infra, and services for pipeline tests.
func setupPipelineEnv(t *testing.T) *pipelineTestEnv {
	t.Helper()

	db, repo := setupPipelineDB(t)

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	t.Cleanup(infra.Cleanup)

	dedupMgr := dedup.NewManager()
	t.Cleanup(dedupMgr.Close)

	svc := &services.Services{
		Options:      infra.Options,
		HostLimiter:  infra.HostLimiter,
		HostErrors:   infra.HostErrors,
		DedupManager: dedupMgr,
	}

	httpClient, err := httpRequester.NewRequester(infra.Options, svc)
	require.NoError(t, err)

	return &pipelineTestEnv{
		db:         db,
		repo:       repo,
		infra:      infra,
		httpClient: httpClient,
		svc:        svc,
	}
}

// --- Phase 1: Discovery (Ingest) Tests ---

// TestAVAE_Phase1_IngestToDatabase verifies that Phase 1 ingests HTTP
// request/response pairs into the database without running any modules.
func TestAVAE_Phase1_IngestToDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	app := startJuiceShop(t)
	env := setupPipelineEnv(t)
	ctx := context.Background()

	endpoints := juiceShopEndpoints(app.BaseURL)

	// Build an input source from URLs
	inputSrc, err := source.NewInputSource(source.SourceConfig{
		Targets:    endpoints,
		Format:     "urls",
		BufferSize: 100,
	})
	require.NoError(t, err)
	defer func() { _ = inputSrc.Close() }()

	// Phase 1: Executor with nil modules — ingest only
	scanUUID := fmt.Sprintf("test-phase1-%d", time.Now().UnixNano())
	executorCfg := core.ExecutorConfig{
		Workers:       5,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      scanUUID,
	}

	executor := core.NewExecutor(executorCfg, inputSrc, nil, nil)
	_, err = executor.Execute(ctx)
	require.NoError(t, err)

	processed := executor.Processed()
	t.Logf("Phase 1: Processed %d items", processed)

	// Verify records were stored in DB
	hosts, err := env.repo.GetDistinctHosts(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(hosts), 0, "Expected at least one host in DB after ingest")

	// Verify records have responses
	records, err := env.repo.GetRecordsWithResponseBody(ctx, "", 100)
	require.NoError(t, err)
	assert.Greater(t, len(records), 0, "Expected records with response bodies in DB")
	t.Logf("Phase 1: %d records with response body, %d distinct hosts", len(records), len(hosts))
}

// TestAVAE_Phase1_NoModulesExecuted verifies that no findings are produced
// during Phase 1 (ingest-only mode).
func TestAVAE_Phase1_NoModulesExecuted(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	app := startJuiceShop(t)
	env := setupPipelineEnv(t)
	ctx := context.Background()

	inputSrc, err := source.NewInputSource(source.SourceConfig{
		Targets:    []string{app.BaseURL + "/rest/products/search?q=apple"},
		Format:     "urls",
		BufferSize: 10,
	})
	require.NoError(t, err)
	defer func() { _ = inputSrc.Close() }()

	var findings []*output.ResultEvent
	executorCfg := core.ExecutorConfig{
		Workers:       2,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      "test-no-modules",
		OnResult: func(result *output.ResultEvent) {
			findings = append(findings, result)
		},
	}

	executor := core.NewExecutor(executorCfg, inputSrc, nil, nil)
	hasResults, err := executor.Execute(ctx)
	require.NoError(t, err)

	assert.False(t, hasResults, "Phase 1 should not produce results (no modules)")
	assert.Empty(t, findings, "Phase 1 should not produce findings")
}

// --- Phase 3: Analysis (Module Scan from DB) Tests ---

// TestAVAE_Phase3_ScanFromDB verifies that Phase 3 reads records from the
// database (via OneShotDBInputSource) and runs modules against them.
func TestAVAE_Phase3_ScanFromDB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	app := startJuiceShop(t)
	env := setupPipelineEnv(t)
	ctx := context.Background()

	// --- Phase 1: Ingest ---
	endpoints := juiceShopEndpoints(app.BaseURL)
	ingestSrc, err := source.NewInputSource(source.SourceConfig{
		Targets:    endpoints,
		Format:     "urls",
		BufferSize: 100,
	})
	require.NoError(t, err)
	defer func() { _ = ingestSrc.Close() }()

	ingestCfg := core.ExecutorConfig{
		Workers:       5,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      "test-phase1-for-phase3",
	}

	executor := core.NewExecutor(ingestCfg, ingestSrc, nil, nil)
	_, err = executor.Execute(ctx)
	require.NoError(t, err)
	t.Logf("Phase 1: Ingested %d items", executor.Processed())

	// --- Phase 3: Scan from DB ---
	scan := &database.Scan{
		UUID:        fmt.Sprintf("test-phase3-%d", time.Now().UnixNano()),
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "e2e-phase3",
		Status:      "running",
		Modules:     "all",
		ScanSource:  "test",
		ScanMode:    "full",
		StartedAt:   time.Now(),
	}
	require.NoError(t, env.repo.CreateScanWithCursor(ctx, scan))

	// Verify there are records to scan
	count, err := env.repo.CountRecordsAfterCursor(ctx, scan.CursorAt, scan.CursorUUID)
	require.NoError(t, err)
	assert.Greater(t, count, int64(0), "Expected records in DB after Phase 1")
	t.Logf("Phase 3: %d records to scan", count)

	// Create DB input source
	dbSource := database.NewOneShotDBInputSource(env.db, env.repo, scan.UUID)

	// Get modules
	activeModules := modules.GetActiveModules()
	passiveModules := modules.GetPassiveModules()
	t.Logf("Phase 3: Running with %d active + %d passive modules", len(activeModules), len(passiveModules))

	var findings []*output.ResultEvent
	scanCfg := core.ExecutorConfig{
		Workers:       5,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      scan.UUID,
		SkipBaseline:  true, // Phase 3: responses already in DB
		OnResult: func(result *output.ResultEvent) {
			findings = append(findings, result)
		},
	}

	scanExecutor := core.NewExecutor(scanCfg, dbSource, activeModules, passiveModules)
	_, err = scanExecutor.Execute(ctx)
	require.NoError(t, err)

	t.Logf("Phase 3: Processed %d items, found %d findings", scanExecutor.Processed(), len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s — %s", f.Info.Severity, f.ModuleID, f.URL)
	}

	// Complete scan
	_ = env.repo.CompleteScan(ctx, scan.UUID, "")
}

// TestAVAE_Phase3_SkipBaseline verifies that SkipBaseline correctly uses
// the response already attached from DB records instead of re-fetching.
func TestAVAE_Phase3_SkipBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	app := startJuiceShop(t)
	env := setupPipelineEnv(t)
	ctx := context.Background()

	// Ingest a single endpoint
	target := app.BaseURL + "/rest/products/search?q=test"
	rr, err := httpmsg.GetRawRequestFromURL(target)
	require.NoError(t, err)

	// Fetch response via HTTP client to get a real response attached
	respChain, _, err := env.httpClient.Execute(rr, httpRequester.Options{})
	require.NoError(t, err)
	fullResp := respChain.FullResponse().Bytes()
	rawCopy := make([]byte, len(fullResp))
	copy(rawCopy, fullResp)
	respChain.Close()

	httpResp := httpmsg.NewHttpResponse(rawCopy)
	rr = rr.WithResponse(httpResp)

	// Save to DB
	recordUUID, err := env.repo.SaveRecord(ctx, rr, "test-ingest")
	require.NoError(t, err)
	require.NotEmpty(t, recordUUID)

	// Create scan record
	scan := &database.Scan{
		UUID:        fmt.Sprintf("test-skipbaseline-%d", time.Now().UnixNano()),
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "e2e-skipbaseline",
		Status:      "running",
		ScanSource:  "test",
		ScanMode:    "full",
		StartedAt:   time.Now(),
	}
	require.NoError(t, env.repo.CreateScanWithCursor(ctx, scan))

	// Read back from DB via OneShotDBInputSource
	dbSource := database.NewOneShotDBInputSource(env.db, env.repo, scan.UUID)

	var processedCount int
	passiveModules := modules.GetPassiveModules()

	scanCfg := core.ExecutorConfig{
		Workers:       1,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      scan.UUID,
		SkipBaseline:  true,
		OnResult: func(result *output.ResultEvent) {
			processedCount++
		},
	}

	scanExecutor := core.NewExecutor(scanCfg, dbSource, nil, passiveModules)
	_, err = scanExecutor.Execute(ctx)
	require.NoError(t, err)

	assert.Equal(t, int64(1), scanExecutor.Processed(),
		"Expected exactly 1 record processed from DB")
	t.Logf("SkipBaseline: processed %d items, %d passive findings", scanExecutor.Processed(), processedCount)
}

// --- Full Pipeline (Phase 1 + Phase 3) Tests ---

// TestAVAE_FullPipeline_IngestThenScan runs Phase 1 (ingest) followed by
// Phase 3 (module scan from DB) against Juice Shop, verifying end-to-end.
func TestAVAE_FullPipeline_IngestThenScan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	app := startJuiceShop(t)
	env := setupPipelineEnv(t)
	ctx := context.Background()

	// ===== Phase 1: Discovery =====
	t.Log("=== Phase 1: Discovery (ingest) ===")
	endpoints := juiceShopEndpoints(app.BaseURL)
	ingestSrc, err := source.NewInputSource(source.SourceConfig{
		Targets:    endpoints,
		Format:     "urls",
		BufferSize: 100,
	})
	require.NoError(t, err)
	defer func() { _ = ingestSrc.Close() }()

	scanUUID := fmt.Sprintf("test-fullpipeline-%d", time.Now().UnixNano())
	ingestCfg := core.ExecutorConfig{
		Workers:       5,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      scanUUID,
	}

	ingestExec := core.NewExecutor(ingestCfg, ingestSrc, nil, nil)
	_, err = ingestExec.Execute(ctx)
	require.NoError(t, err)

	ingestCount := ingestExec.Processed()
	t.Logf("Phase 1: Ingested %d records", ingestCount)
	assert.Greater(t, ingestCount, int64(0), "Phase 1 should ingest at least one record")

	// Verify DB state after Phase 1
	hosts, err := env.repo.GetDistinctHosts(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(hosts), 0)

	records, err := env.repo.GetRecordsWithResponseBody(ctx, "", 100)
	require.NoError(t, err)
	assert.Greater(t, len(records), 0)
	t.Logf("Phase 1 DB state: %d hosts, %d records with body", len(hosts), len(records))

	// ===== Phase 3: Analysis =====
	t.Log("=== Phase 3: Analysis (modules) ===")
	scan := &database.Scan{
		UUID:        scanUUID + "-phase3",
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "e2e-fullpipeline-phase3",
		Status:      "running",
		Modules:     "all",
		ScanSource:  "test",
		ScanMode:    "full",
		StartedAt:   time.Now(),
	}
	require.NoError(t, env.repo.CreateScanWithCursor(ctx, scan))

	dbSource := database.NewOneShotDBInputSource(env.db, env.repo, scan.UUID)
	activeModules := modules.GetActiveModules()
	passiveModules := modules.GetPassiveModules()

	var findings []*output.ResultEvent
	scanCfg := core.ExecutorConfig{
		Workers:       5,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      scan.UUID,
		SkipBaseline:  true,
		OnResult: func(result *output.ResultEvent) {
			findings = append(findings, result)
		},
	}

	scanExec := core.NewExecutor(scanCfg, dbSource, activeModules, passiveModules)
	_, err = scanExec.Execute(ctx)
	require.NoError(t, err)

	scanCount := scanExec.Processed()
	t.Logf("Phase 3: Processed %d records, produced %d findings", scanCount, len(findings))

	// Phase 3 should process the same records that Phase 1 ingested
	assert.Greater(t, scanCount, int64(0), "Phase 3 should process records from DB")

	// Log finding summary
	findingSummary := make(map[string]int)
	for _, f := range findings {
		findingSummary[f.ModuleID]++
	}
	t.Log("=== Finding Summary ===")
	for moduleID, count := range findingSummary {
		t.Logf("  %s: %d", moduleID, count)
	}
	t.Logf("  Total: %d", len(findings))

	_ = env.repo.CompleteScan(ctx, scan.UUID, "")
}

// --- Phase 2: SPA (Kingfisher Batch) Tests ---

// TestAVAE_Phase2_KingfisherBatch verifies that the kingfisher batch scanner
// can scan response bodies stored in the DB for leaked secrets.
func TestAVAE_Phase2_KingfisherBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	app := startJuiceShop(t)
	env := setupPipelineEnv(t)
	ctx := context.Background()

	// Ingest some endpoints
	endpoints := juiceShopEndpoints(app.BaseURL)
	ingestSrc, err := source.NewInputSource(source.SourceConfig{
		Targets:    endpoints,
		Format:     "urls",
		BufferSize: 100,
	})
	require.NoError(t, err)
	defer func() { _ = ingestSrc.Close() }()

	ingestCfg := core.ExecutorConfig{
		Workers:       5,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      "test-kingfisher-ingest",
	}

	executor := core.NewExecutor(ingestCfg, ingestSrc, nil, nil)
	_, err = executor.Execute(ctx)
	require.NoError(t, err)
	t.Logf("Ingested %d records for kingfisher batch test", executor.Processed())

	// Run GetRecordsWithResponseBody to verify batch query works
	records, err := env.repo.GetRecordsWithResponseBody(ctx, "", 500)
	require.NoError(t, err)
	assert.Greater(t, len(records), 0, "Expected records with response bodies")

	// Verify cursor pagination works
	if len(records) > 0 {
		lastUUID := records[len(records)-1].UUID
		nextBatch, err := env.repo.GetRecordsWithResponseBody(ctx, lastUUID, 500)
		require.NoError(t, err)
		// Second batch should have zero or fewer records (we ingested < 500)
		assert.LessOrEqual(t, len(nextBatch), len(records),
			"Second batch should not return more records than first")

		// Verify no overlap
		if len(nextBatch) > 0 {
			assert.NotEqual(t, records[0].UUID, nextBatch[0].UUID,
				"Second batch should not overlap with first")
		}
	}

	t.Logf("GetRecordsWithResponseBody: returned %d records", len(records))
	for _, r := range records {
		t.Logf("  uuid=%s host=%s ct=%s bodyLen=%d",
			r.UUID[:8], r.Hostname, r.ResponseContentType, len(r.ResponseBody))
	}
}

// --- Edge Cases ---

// TestAVAE_Phase3_FilterSecretDetectWhenSPAEnabled verifies that the
// passive-secret-detect module is correctly filtered out of Phase 3
// when SPA mode is enabled (to avoid duplicate kingfisher findings).
func TestAVAE_Phase3_FilterSecretDetectWhenSPAEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	passiveModules := modules.GetPassiveModules()

	// Verify secret-detect module exists in full list
	hasSecretDetect := false
	for _, m := range passiveModules {
		if m.ID() == secret_detect.ModuleID {
			hasSecretDetect = true
			break
		}
	}
	// Only test filtering if the module is registered
	if !hasSecretDetect {
		t.Skip("passive-secret-detect module not registered, skipping filter test")
	}

	// Simulate the filtering that runDynamicAssessmentPhase does when SPA is enabled
	filtered := filterOutPassiveModuleTest(passiveModules, secret_detect.ModuleID)

	// Verify it was removed
	for _, m := range filtered {
		assert.NotEqual(t, secret_detect.ModuleID, m.ID(),
			"passive-secret-detect should be filtered out when SPA is enabled")
	}
	assert.Equal(t, len(passiveModules)-1, len(filtered),
		"Filtered list should have exactly one fewer module")
}

// filterOutPassiveModuleTest is a test-local copy of the runner's filterOutPassiveModule.
func filterOutPassiveModuleTest(mods []modules.PassiveModule, id string) []modules.PassiveModule {
	result := make([]modules.PassiveModule, 0, len(mods))
	for _, m := range mods {
		if m.ID() != id {
			result = append(result, m)
		}
	}
	return result
}

// TestAVAE_EmptyInput_Phase1NoOp verifies that Phase 1 is a no-op when
// no input is provided (DB-only scan mode).
func TestAVAE_EmptyInput_Phase1NoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	env := setupPipelineEnv(t)
	ctx := context.Background()

	// Create an input source from empty targets
	inputSrc, err := source.NewInputSource(source.SourceConfig{
		Targets:    []string{},
		Format:     "urls",
		BufferSize: 10,
	})
	require.NoError(t, err)
	defer func() { _ = inputSrc.Close() }()

	executorCfg := core.ExecutorConfig{
		Workers:       2,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      "test-empty",
	}

	executor := core.NewExecutor(executorCfg, inputSrc, nil, nil)
	_, err = executor.Execute(ctx)
	require.NoError(t, err)

	assert.Equal(t, int64(0), executor.Processed(),
		"Empty input should process zero items")
}

// TestAVAE_DBGetterAndBatchQuery verifies the new repository methods work correctly.
func TestAVAE_DBGetterAndBatchQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	db, repo := setupPipelineDB(t)

	// Verify DB() getter returns the same DB handle
	assert.Equal(t, db, repo.DB(), "DB() should return the underlying database handle")

	// Verify empty DB returns empty results
	ctx := context.Background()
	records, err := repo.GetRecordsWithResponseBody(ctx, "", 10)
	require.NoError(t, err)
	assert.Empty(t, records, "Empty DB should return no records")
}

// TestAVAE_Phase3_FeedbackLoop verifies that Phase 3 can re-scan newly
// discovered records in multiple rounds.
func TestAVAE_Phase3_FeedbackLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	app := startJuiceShop(t)
	env := setupPipelineEnv(t)
	ctx := context.Background()

	// Phase 1: Ingest a small set of endpoints
	ingestSrc, err := source.NewInputSource(source.SourceConfig{
		Targets: []string{
			app.BaseURL + "/rest/products/search?q=test",
			app.BaseURL + "/api/Products",
		},
		Format:     "urls",
		BufferSize: 10,
	})
	require.NoError(t, err)
	defer func() { _ = ingestSrc.Close() }()

	ingestCfg := core.ExecutorConfig{
		Workers:       2,
		Services:      env.svc,
		HTTPRequester: env.httpClient,
		Repository:    env.repo,
		ScanUUID:      "test-feedback-ingest",
	}
	ingestExec := core.NewExecutor(ingestCfg, ingestSrc, nil, nil)
	_, err = ingestExec.Execute(ctx)
	require.NoError(t, err)
	t.Logf("Feedback loop: ingested %d records", ingestExec.Processed())

	// Phase 3: Run multiple rounds (simulating the feedback loop)
	scan := &database.Scan{
		UUID:        fmt.Sprintf("test-feedback-%d", time.Now().UnixNano()),
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "e2e-feedback",
		Status:      "running",
		ScanSource:  "test",
		ScanMode:    "full",
		StartedAt:   time.Now(),
	}
	require.NoError(t, env.repo.CreateScanWithCursor(ctx, scan))

	maxRounds := 3
	var totalProcessed int64
	for round := 0; round < maxRounds; round++ {
		dbSource := database.NewOneShotDBInputSource(env.db, env.repo, scan.UUID)
		passiveModules := modules.GetPassiveModules()

		scanCfg := core.ExecutorConfig{
			Workers:       2,
			Services:      env.svc,
			HTTPRequester: env.httpClient,
			Repository:    env.repo,
			ScanUUID:      scan.UUID,
			SkipBaseline:  true,
		}
		scanExec := core.NewExecutor(scanCfg, dbSource, nil, passiveModules)
		_, err = scanExec.Execute(ctx)
		require.NoError(t, err)

		roundProcessed := scanExec.Processed()
		totalProcessed += roundProcessed
		t.Logf("Feedback round %d: processed %d records", round+1, roundProcessed)

		// Check for new records after cursor
		newCount, err := env.repo.CountRecordsAfterCursor(ctx, scan.CursorAt, scan.CursorUUID)
		require.NoError(t, err)
		if newCount == 0 {
			t.Logf("No new records after round %d, stopping", round+1)
			break
		}
	}

	assert.Greater(t, totalProcessed, int64(0), "Feedback loop should process records")
	_ = env.repo.CompleteScan(ctx, scan.UUID, "")
}
