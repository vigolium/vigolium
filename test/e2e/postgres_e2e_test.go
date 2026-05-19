//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// setupPostgresDB connects to the PostgreSQL instance, drops all tables for a
// clean slate, then re-creates the schema. Returns the DB and a Repository.
func setupPostgresDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()

	db, err := database.NewDB(pgTestConfigFromEnv())
	if err != nil {
		t.Skipf("PostgreSQL not available (start with 'make postgres-up'): %v", err)
	}

	ctx := context.Background()
	dropAllVigoliumTables(ctx, db)
	require.NoError(t, db.CreateSchema(ctx))
	require.NoError(t, db.SeedDefaults(ctx))
	t.Cleanup(func() { db.Close() })
	return db, database.NewRepository(db)
}

// saveRecordFromURL is a test helper that creates an HTTPRecord from a URL string.
func saveRecordFromURL(t *testing.T, repo *database.Repository, url, projectUUID string) string {
	t.Helper()
	rr, err := httpmsg.GetRawRequestFromURL(url)
	require.NoError(t, err)
	uuid, err := repo.SaveRecord(context.Background(), rr, "test", projectUUID)
	require.NoError(t, err)
	return uuid
}

// newPgAPITestEnv starts a fiber API server backed by PostgreSQL.
func newPgAPITestEnv(t *testing.T, apiKey string) *apiTestEnv {
	t.Helper()

	db, repo := setupPostgresDB(t)

	tmpDir := t.TempDir()
	taskQueue, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = taskQueue.Close() })

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var keys []string
	noAuth := true
	if apiKey != "" {
		keys = []string{apiKey}
		noAuth = false
	}

	srv := server.NewServer(server.ServerConfig{
		ServiceAddr:          addr,
		APIKeys:              keys,
		NoAuth:               noAuth,
		CORSAllowedOrigins:   "reflect-origin",
		Version:              "test-pg-v0.0.1",
		DisableFetchResponse: true,
	}, taskQueue, db, repo, nil, nil, nil)

	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	apiURL := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(apiURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return &apiTestEnv{
		server: srv,
		url:    apiURL,
		db:     db,
		repo:   repo,
		queue:  taskQueue,
		apiKey: apiKey,
	}
}

// ============================================================
// PostgreSQL: Schema & Connection
// ============================================================

func TestPg_SchemaCreation(t *testing.T) {
	db, _ := setupPostgresDB(t)

	var count int
	err := db.NewSelect().
		TableExpr("information_schema.tables").
		ColumnExpr("COUNT(*)").
		Where("table_schema = 'public'").
		Where("table_type = 'BASE TABLE'").
		Scan(context.Background(), &count)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 10, "expected at least 10 tables")
}

func TestPg_SeedDefaults(t *testing.T) {
	db, _ := setupPostgresDB(t)
	ctx := context.Background()

	var userName string
	err := db.NewSelect().TableExpr("users").Column("name").
		Where("uuid = ?", database.DefaultUserUUID).
		Scan(ctx, &userName)
	require.NoError(t, err)
	assert.Equal(t, "vigolium-admin", userName)

	var projectName string
	err = db.NewSelect().TableExpr("projects").Column("name").
		Where("uuid = ?", database.DefaultProjectUUID).
		Scan(ctx, &projectName)
	require.NoError(t, err)
	assert.Equal(t, "Default Project", projectName)

	// SeedDefaults is idempotent
	require.NoError(t, db.SeedDefaults(ctx))
}

func TestPg_DriverName(t *testing.T) {
	db, _ := setupPostgresDB(t)
	assert.Equal(t, "postgres", db.Driver())
}

// ============================================================
// PostgreSQL: Record CRUD
// ============================================================

func TestPg_RecordCRUD(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	uuid := saveRecordFromURL(t, repo, "http://example.com/test?id=1", database.DefaultProjectUUID)

	rec, err := repo.GetRecordByUUID(ctx, uuid)
	require.NoError(t, err)
	assert.Equal(t, "example.com", rec.Hostname)
	assert.Contains(t, rec.Path, "/test")
	assert.Equal(t, "GET", rec.Method)

	count, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", database.DefaultProjectUUID).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	err = repo.DeleteRecord(ctx, uuid)
	require.NoError(t, err)

	count, err = repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", database.DefaultProjectUUID).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// ============================================================
// PostgreSQL: Finding CRUD
// ============================================================

func TestPg_FindingCRUD(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	recUUID := saveRecordFromURL(t, repo, "http://vuln.example.com/xss?q=test", database.DefaultProjectUUID)

	finding := &database.Finding{
		ProjectUUID:     database.DefaultProjectUUID,
		HTTPRecordUUIDs: []string{recUUID},
		ModuleID:        "xss-reflected",
		ModuleName:      "Reflected XSS",
		ModuleType:      "active",
		Severity:        "high",
		Confidence:      "firm",
		Description:     "Reflected XSS in q parameter",
		FindingHash:     "test-hash-pg-001",
		FoundAt:         time.Now(),
	}
	err := repo.SaveFindingDirect(ctx, finding)
	require.NoError(t, err)
	assert.Greater(t, finding.ID, int64(0))

	got, err := repo.GetFindingByID(ctx, finding.ID)
	require.NoError(t, err)
	assert.Equal(t, "xss-reflected", got.ModuleID)
	assert.Equal(t, "high", got.Severity)

	// Get by record UUID (uses finding_records junction)
	findings, err := repo.GetFindingsByRecordUUID(ctx, recUUID)
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	err = repo.DeleteFinding(ctx, finding.ID)
	require.NoError(t, err)
}

// ============================================================
// PostgreSQL: Scan CRUD
// ============================================================

func TestPg_ScanCRUD(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	scanUUID := "cccccccc-cccc-cccc-cccc-cccccccccccc"
	scan := &database.Scan{
		UUID:        scanUUID,
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "pg-test-scan",
		Status:      "running",
		Target:      "http://example.com",
	}
	err := repo.CreateScan(ctx, scan)
	require.NoError(t, err)

	got, err := repo.GetScanByUUID(ctx, scanUUID)
	require.NoError(t, err)
	assert.Equal(t, "pg-test-scan", got.Name)
	assert.Equal(t, "running", got.Status)

	// Complete the scan
	err = repo.CompleteScan(ctx, scanUUID, "")
	require.NoError(t, err)
	got, err = repo.GetScanByUUID(ctx, scan.UUID)
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status)
}

// ============================================================
// PostgreSQL: Multiple Records & Queries
// ============================================================

func TestPg_MultipleRecords(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	urls := []string{
		"http://example.com/a?x=1",
		"http://example.com/b?y=2",
		"http://other.com/c?z=3",
	}
	for _, u := range urls {
		saveRecordFromURL(t, repo, u, database.DefaultProjectUUID)
	}

	count, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", database.DefaultProjectUUID).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Query by hostname
	qb := database.NewQueryBuilder(repo.DB(), database.QueryFilters{
		ProjectUUID: database.DefaultProjectUUID,
		HostPattern: "example.com",
	})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	assert.Len(t, records, 2)
}

func TestPg_FindingSeverityCounts(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	recUUID := saveRecordFromURL(t, repo, "http://test.com/vuln", database.DefaultProjectUUID)

	severities := []string{"critical", "high", "high", "medium", "low", "info"}
	for i, sev := range severities {
		f := &database.Finding{
			ProjectUUID:     database.DefaultProjectUUID,
			HTTPRecordUUIDs: []string{recUUID},
			ModuleID:        fmt.Sprintf("mod-%d", i),
			ModuleName:      fmt.Sprintf("Module %d", i),
			Severity:        sev,
			Confidence:      "firm",
			FindingHash:     fmt.Sprintf("hash-pg-%d", i),
			FoundAt:         time.Now(),
		}
		err := repo.SaveFindingDirect(ctx, f)
		require.NoError(t, err)
	}

	counts, err := database.CountFindingsBySeverity(ctx, repo.DB(), database.DefaultProjectUUID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), counts["critical"])
	assert.Equal(t, int64(2), counts["high"])
	assert.Equal(t, int64(1), counts["medium"])
	assert.Equal(t, int64(1), counts["low"])
	assert.Equal(t, int64(1), counts["info"])
}

// ============================================================
// PostgreSQL: API Server Integration
// ============================================================

func TestPg_API_Health(t *testing.T) {
	env := newPgAPITestEnv(t, "")

	resp := env.get(t, "/health")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.HealthResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "healthy", body.Status)
}

func TestPg_API_ServerInfo(t *testing.T) {
	env := newPgAPITestEnv(t, "")

	resp := env.get(t, "/server-info")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ServerInfoResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "test-pg-v0.0.1", body.Version)
}

func TestPg_API_IngestAndQuery(t *testing.T) {
	env := newPgAPITestEnv(t, "")

	for _, u := range []string{"http://example.com/a?x=1", "http://example.com/b?y=2"} {
		resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{"input_mode":"url","content":"%s"}`, u))
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	resp := env.get(t, "/api/http-records?limit=10")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(2), body.Total)
}

func TestPg_API_Findings(t *testing.T) {
	env := newPgAPITestEnv(t, "")

	resp := env.get(t, "/api/findings")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Findings []json.RawMessage `json:"findings"`
		Total    int64             `json:"total"`
	}
	readJSON(t, resp, &body)
	assert.Equal(t, int64(0), body.Total)
}

func TestPg_API_Auth(t *testing.T) {
	env := newPgAPITestEnv(t, "pg-secret-key")

	// Unauthenticated request should fail
	req, err := http.NewRequest(http.MethodGet, env.url+"/api/http-records", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Authenticated request should succeed
	resp2 := env.get(t, "/api/http-records")
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestPg_API_Modules(t *testing.T) {
	env := newPgAPITestEnv(t, "")

	resp := env.get(t, "/api/modules")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Modules []server.ModuleInfo `json:"modules"`
		Total   int                 `json:"total"`
	}
	readJSON(t, resp, &body)
	assert.Greater(t, body.Total, 0)
}

// ============================================================
// PostgreSQL: Project Isolation (Multi-Tenancy)
// ============================================================

func TestPg_ProjectIsolation(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	projectA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	projectB := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// Create projects
	require.NoError(t, repo.CreateProject(ctx, &database.Project{
		UUID:      projectA,
		Name:      "Project A",
		OwnerUUID: database.DefaultUserUUID,
	}))
	require.NoError(t, repo.CreateProject(ctx, &database.Project{
		UUID:      projectB,
		Name:      "Project B",
		OwnerUUID: database.DefaultUserUUID,
	}))

	saveRecordFromURL(t, repo, "http://a.example.com/page", projectA)
	saveRecordFromURL(t, repo, "http://b.example.com/page", projectB)

	countA, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", projectA).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, countA)

	countB, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", projectB).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, countB)
}

// ============================================================
// PostgreSQL: Concurrent Access
// ============================================================

func TestPg_ConcurrentInserts(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	const n = 20
	errs := make(chan error, n)

	for i := 0; i < n; i++ {
		go func(i int) {
			rr, err := httpmsg.GetRawRequestFromURL(
				fmt.Sprintf("http://concurrent.example.com/path-%d?i=%d", i, i))
			if err != nil {
				errs <- err
				return
			}
			_, err = repo.SaveRecord(ctx, rr, "test", database.DefaultProjectUUID)
			errs <- err
		}(i)
	}

	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}

	count, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", database.DefaultProjectUUID).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, n, count)
}

// ============================================================
// PostgreSQL: Duplicate Finding (hash uniqueness)
// ============================================================

func TestPg_DuplicateFindingHash(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	recUUID := saveRecordFromURL(t, repo, "http://dup.example.com/test", database.DefaultProjectUUID)

	finding := &database.Finding{
		ProjectUUID:     database.DefaultProjectUUID,
		HTTPRecordUUIDs: []string{recUUID},
		ModuleID:        "xss-test",
		ModuleName:      "XSS Test",
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "duplicate-hash-pg",
		FoundAt:         time.Now(),
	}

	err := repo.SaveFindingDirect(ctx, finding)
	require.NoError(t, err)
	assert.Greater(t, finding.ID, int64(0))

	// Second save with same hash should not error (dedup via ON CONFLICT)
	finding2 := &database.Finding{
		ProjectUUID:     database.DefaultProjectUUID,
		HTTPRecordUUIDs: []string{recUUID},
		ModuleID:        "xss-test",
		ModuleName:      "XSS Test",
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "duplicate-hash-pg",
		FoundAt:         time.Now(),
	}
	err = repo.SaveFindingDirect(ctx, finding2)
	require.NoError(t, err)

	// Should still only have one finding
	findings, err := repo.GetFindingsByRecordUUID(ctx, recUUID)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
}

// ============================================================
// PostgreSQL: Batch Delete Records
// ============================================================

func TestPg_BatchDeleteRecords(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		saveRecordFromURL(t, repo, fmt.Sprintf("http://batch.example.com/path-%d", i), database.DefaultProjectUUID)
	}

	count, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", database.DefaultProjectUUID).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, count)

	db := database.NewDeleteBuilder(repo.DB(), database.QueryFilters{
		ProjectUUID: database.DefaultProjectUUID,
		HostPattern: "batch.example.com",
	})
	deleted, err := db.DeleteRecords(ctx, false)
	require.NoError(t, err)
	assert.Equal(t, int64(5), deleted)

	count, err = repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).
		Where("project_uuid = ?", database.DefaultProjectUUID).Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// ============================================================
// PostgreSQL: Scope Operations
// ============================================================

func TestPg_ScopeOperations(t *testing.T) {
	db, repo := setupPostgresDB(t)
	ctx := context.Background()

	// Insert scope directly
	scope := &database.Scope{
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "test-scope",
		RuleType:    "include",
		HostPattern: "*.example.com",
		Priority:    100,
		Enabled:     true,
	}
	_, err := db.NewInsert().Model(scope).Exec(ctx)
	require.NoError(t, err)

	scopes, err := repo.LoadEnabledScopes(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	assert.Len(t, scopes, 1)
	assert.Equal(t, "*.example.com", scopes[0].HostPattern)
}

// ============================================================
// PostgreSQL: Agentic Scan CRUD
// ============================================================

func TestPg_AgenticScanCRUD(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	parentUUID := "11111111-1111-1111-1111-111111111111"
	now := time.Now().UTC().Truncate(time.Second)

	parent := &database.AgenticScan{
		UUID:        parentUUID,
		ProjectUUID: database.DefaultProjectUUID,
		Mode:        "autopilot",
		AgentName:   "autopilot-master",
		Protocol:    "sdk",
		Model:       "claude-opus-4-7",
		InputType:   "url",
		TargetURL:   "http://vuln.example.com/",
		VulnType:    "xss",
		ModuleNames: []string{"xss-reflected", "sqli-error-based"},
		TemplateID:  "autopilot-default",
		Status:      "running",
		PhasesRun:   []string{"plan", "extension"},
		TokenUsage: map[string]interface{}{
			"plan":      map[string]interface{}{"input": 1200, "output": 350},
			"extension": map[string]interface{}{"input": 4800, "output": 900},
		},
		TotalInputTokens:  6000,
		TotalOutputTokens: 1250,
		EstimatedCostUSD:  0.1234,
		InputRecordCount:  3,
		SourcePath:        "/tmp/src",
		SourceType:        "local",
		SessionID:         "sess-abc",
		SessionDir:        "/tmp/sessions/abc",
		StorageURL:        "gs://vigolium-runs/abc/bundle.tar.gz",
		StartedAt:         now,
	}
	require.NoError(t, repo.CreateAgenticScan(ctx, parent))

	got, err := repo.GetAgenticScan(ctx, parentUUID)
	require.NoError(t, err)
	assert.Equal(t, "autopilot", got.Mode)
	assert.Equal(t, "claude-opus-4-7", got.Model)
	assert.Equal(t, []string{"xss-reflected", "sqli-error-based"}, got.ModuleNames)
	assert.Equal(t, []string{"plan", "extension"}, got.PhasesRun)
	assert.Equal(t, int64(6000), got.TotalInputTokens)
	assert.Equal(t, int64(1250), got.TotalOutputTokens)
	assert.InDelta(t, 0.1234, got.EstimatedCostUSD, 1e-6)
	assert.Equal(t, "gs://vigolium-runs/abc/bundle.tar.gz", got.StorageURL)
	require.Contains(t, got.TokenUsage, "extension")

	// Update: mark completed, bump cost + tokens
	got.Status = "completed"
	got.CurrentPhase = ""
	got.TotalInputTokens = 7500
	got.TotalOutputTokens = 1800
	got.EstimatedCostUSD = 0.2468
	got.FindingCount = 4
	got.RecordCount = 12
	got.SavedCount = 4
	got.CompletedAt = now.Add(5 * time.Minute)
	got.DurationMs = 300_000
	require.NoError(t, repo.UpdateAgenticScan(ctx, got))

	// Update storage URL via focused method
	require.NoError(t, repo.UpdateAgenticScanStorageURL(ctx, parentUUID, "gs://vigolium-runs/abc/final.tar.gz"))

	reread, err := repo.GetAgenticScan(ctx, parentUUID)
	require.NoError(t, err)
	assert.Equal(t, "completed", reread.Status)
	assert.Equal(t, int64(7500), reread.TotalInputTokens)
	assert.InDelta(t, 0.2468, reread.EstimatedCostUSD, 1e-6)
	assert.Equal(t, "gs://vigolium-runs/abc/final.tar.gz", reread.StorageURL)

	// Child run linked via parent_run_uuid (swarm sub-run)
	child := &database.AgenticScan{
		UUID:          "22222222-2222-2222-2222-222222222222",
		ProjectUUID:   database.DefaultProjectUUID,
		ParentAgenticScanUUID: parentUUID,
		Mode:          "autopilot",
		AgentName:     "autopilot-worker",
		Status:        "completed",
		StartedAt:     now,
	}
	require.NoError(t, repo.CreateAgenticScan(ctx, child))

	children, err := repo.GetChildAgenticScans(ctx, parentUUID)
	require.NoError(t, err)
	assert.Len(t, children, 1)
	assert.Equal(t, child.UUID, children[0].UUID)

	// List excludes children (parent_run_uuid IS NULL OR '')
	runs, total, err := repo.ListAgenticScans(ctx, database.DefaultProjectUUID, "", 50, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, runs, 1)
	assert.Equal(t, parentUUID, runs[0].UUID)

	// Filter by mode
	_, totalFiltered, err := repo.ListAgenticScans(ctx, database.DefaultProjectUUID, "autopilot", 50, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), totalFiltered)

	// DeleteOldAgenticScans: mark parent as old + completed, then delete.
	_, err = repo.DB().NewUpdate().Model((*database.AgenticScan)(nil)).
		Set("completed_at = ?", time.Now().Add(-48*time.Hour)).
		Where("uuid = ?", parentUUID).
		Exec(ctx)
	require.NoError(t, err)

	deleted, err := repo.DeleteOldAgenticScans(ctx, 24*time.Hour)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, deleted, 1)
}

// ============================================================
// PostgreSQL: Session Hostname CRUD
// ============================================================

func TestPg_AuthenticationHostnameCRUD(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	hydratedAt := time.Now().UTC().Truncate(time.Second)

	sh := &database.AuthenticationHostname{
		ProjectUUID:  database.DefaultProjectUUID,
		ScanUUID:     "scan-uuid-1",
		Hostname:     "api.example.com",
		SessionName:  "admin",
		SessionRole:  "admin",
		Position:     0,
		SessionToken: "jwt-abc-123",
		Headers: map[string]string{
			"Authorization": "Bearer jwt-abc-123",
			"X-Tenant-ID":   "acme",
		},
		LoginURL:         "https://api.example.com/login",
		LoginMethod:      "POST",
		LoginContentType: "application/json",
		LoginBody:        `{"username":"admin","password":"hunter2"}`,
		ExtractRules:     `[{"name":"token","source":"body","jsonpath":"$.token"}]`,
		Source:           "manual",
		HydratedAt:       &hydratedAt,
	}
	require.NoError(t, repo.SaveAuthenticationHostname(ctx, sh))

	rows, err := repo.GetAuthenticationHostnamesByHostname(ctx, database.DefaultProjectUUID, "api.example.com")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	got := rows[0]
	assert.Equal(t, "admin", got.SessionName)
	assert.Equal(t, "jwt-abc-123", got.SessionToken)
	assert.Equal(t, "Bearer jwt-abc-123", got.Headers["Authorization"])
	assert.Equal(t, "acme", got.Headers["X-Tenant-ID"])
	assert.Contains(t, got.ExtractRules, "$.token")
	require.NotNil(t, got.HydratedAt)
	assert.WithinDuration(t, hydratedAt, *got.HydratedAt, time.Second)

	// Upsert: same (project_uuid, hostname, session_name) updates fields in place.
	sh.SessionToken = "jwt-rotated-456"
	sh.Headers = map[string]string{"Authorization": "Bearer jwt-rotated-456"}
	require.NoError(t, repo.SaveAuthenticationHostname(ctx, sh))

	rows, err = repo.GetAuthenticationHostnamesByHostname(ctx, database.DefaultProjectUUID, "api.example.com")
	require.NoError(t, err)
	require.Len(t, rows, 1, "upsert must not create a duplicate row")
	assert.Equal(t, "jwt-rotated-456", rows[0].SessionToken)
	assert.Equal(t, "Bearer jwt-rotated-456", rows[0].Headers["Authorization"])

	// Batch upsert: two more sessions (different session_name).
	batch := []*database.AuthenticationHostname{
		{
			ProjectUUID: database.DefaultProjectUUID,
			ScanUUID:    "scan-uuid-1",
			Hostname:    "api.example.com",
			SessionName: "user",
			SessionRole: "user",
			Position:    1,
			Source:      "harvester",
		},
		{
			ProjectUUID: database.DefaultProjectUUID,
			ScanUUID:    "scan-uuid-1",
			Hostname:    "web.example.com",
			SessionName: "admin",
			SessionRole: "admin",
			Position:    0,
			Source:      "harvester",
		},
	}
	require.NoError(t, repo.SaveAuthenticationHostnames(ctx, batch))

	// GetByProject returns all three, ordered by hostname, position.
	allRows, err := repo.GetAuthenticationHostnamesByProject(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	assert.Len(t, allRows, 3)

	// GetByScan scopes to a scan_uuid.
	byScan, err := repo.GetAuthenticationHostnamesByScan(ctx, database.DefaultProjectUUID, "scan-uuid-1")
	require.NoError(t, err)
	assert.Len(t, byScan, 3)

	// DeleteByHostname removes only rows for that hostname.
	require.NoError(t, repo.DeleteAuthenticationHostnamesByHostname(ctx, database.DefaultProjectUUID, "api.example.com"))

	rows, err = repo.GetAuthenticationHostnamesByHostname(ctx, database.DefaultProjectUUID, "api.example.com")
	require.NoError(t, err)
	assert.Len(t, rows, 0)

	remaining, err := repo.GetAuthenticationHostnamesByProject(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	require.Len(t, remaining, 1)
	assert.Equal(t, "web.example.com", remaining[0].Hostname)

	// DeleteAuthenticationHostname by id.
	require.NoError(t, repo.DeleteAuthenticationHostname(ctx, remaining[0].ID))
	remaining, err = repo.GetAuthenticationHostnamesByProject(ctx, database.DefaultProjectUUID)
	require.NoError(t, err)
	assert.Len(t, remaining, 0)
}
