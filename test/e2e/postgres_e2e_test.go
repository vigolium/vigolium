//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// pgTestConfig returns a PostgreSQL database config for e2e tests.
// Reads connection details from environment variables with sensible defaults
// matching the docker-compose in test/testdata/postgres/.
func pgTestConfig() *config.DatabaseConfig {
	host := envOr("VIGOLIUM_PG_HOST", "localhost")
	port := envOrInt("VIGOLIUM_PG_PORT", 5433)
	user := envOr("VIGOLIUM_PG_USER", "vigolium_test")
	password := envOr("VIGOLIUM_PG_PASSWORD", "vigolium_test_pass")
	dbName := envOr("VIGOLIUM_PG_DATABASE", "vigolium_test")

	return &config.DatabaseConfig{
		Enabled: true,
		Driver:  "postgres",
		Postgres: config.PostgresConfig{
			Host:            host,
			Port:            port,
			User:            user,
			Password:        password,
			Database:        dbName,
			SSLMode:         "disable",
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: "5m",
		},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

// setupPostgresDB connects to the PostgreSQL instance, drops all tables for a
// clean slate, then re-creates the schema. Returns the DB and a Repository.
func setupPostgresDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()

	cfg := pgTestConfig()
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Skipf("PostgreSQL not available (start with 'make postgres-up'): %v", err)
	}

	ctx := context.Background()

	// Drop all tables for a clean slate
	tables := []string{
		"scan_logs", "oast_interactions", "source_repos", "scopes",
		"finding_records", "findings", "http_records", "scans",
		"projects", "users",
	}
	for _, tbl := range tables {
		_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", tbl))
	}

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
	}, taskQueue, db, repo, nil, nil)

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
	assert.Contains(t, body.DBDriver, "postgres")
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
// PostgreSQL: Source Repo CRUD
// ============================================================

func TestPg_SourceRepoCRUD(t *testing.T) {
	_, repo := setupPostgresDB(t)
	ctx := context.Background()

	sr := &database.SourceRepo{
		ProjectUUID: database.DefaultProjectUUID,
		Hostname:    "example.com",
		Name:        "example-app",
		RootPath:    "/tmp/repos/example",
		RepoType:    "folder",
		Language:    "go",
	}
	err := repo.CreateSourceRepo(ctx, sr)
	require.NoError(t, err)
	assert.Greater(t, sr.ID, int64(0))

	got, err := repo.GetSourceRepoByID(ctx, sr.ID)
	require.NoError(t, err)
	assert.Equal(t, "example.com", got.Hostname)
	assert.Equal(t, "go", got.Language)
}
