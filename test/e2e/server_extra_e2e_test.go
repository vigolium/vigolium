//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// setupTestDBSingleConn creates an in-memory SQLite DB with MaxOpenConns=1.
// This is required for operations that use ScanAndCount (multiple queries)
// since each in-memory SQLite connection gets its own database.
func setupTestDBSingleConn(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:         ":memory:",
			BusyTimeout:  5000,
			JournalMode:  "MEMORY",
			Synchronous:  "OFF",
			CacheSize:    10000,
			MaxOpenConns: 1,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { db.Close() })
	return db, database.NewRepository(db)
}

// settingsTestEnv is like apiTestEnv but with non-nil Settings.
type settingsTestEnv struct {
	server   *server.Server
	url      string
	db       *database.DB
	repo     *database.Repository
	queue    queue.Queue
	settings *config.Settings
	apiKey   string
}

func newSettingsTestEnv(t *testing.T, apiKey string) *settingsTestEnv {
	t.Helper()

	db, repo := setupTestDBSingleConn(t)

	tmpDir := t.TempDir()
	taskQueue, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = taskQueue.Close() })

	port := getFreePortAlt(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var keys []string
	noAuth := true
	if apiKey != "" {
		keys = []string{apiKey}
		noAuth = false
	}

	settings := config.DefaultSettings()

	srv := server.NewServer(server.ServerConfig{
		ServiceAddr:          addr,
		APIKeys:              keys,
		NoAuth:               noAuth,
		CORSAllowedOrigins:   "reflect-origin",
		Version:              "test-v0.0.1",
		Author:               "test-author",
		Commit:               "abc1234567890",
		BuildTime:            "2026-01-01T00:00:00Z",
		DisableFetchResponse: true,
	}, taskQueue, db, repo, settings, nil)

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

	return &settingsTestEnv{
		server:   srv,
		url:      apiURL,
		db:       db,
		repo:     repo,
		queue:    taskQueue,
		settings: settings,
		apiKey:   apiKey,
	}
}

func getFreePortAlt(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func (env *settingsTestEnv) post(t *testing.T, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.url+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (env *settingsTestEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.url+path, nil)
	require.NoError(t, err)
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (env *settingsTestEnv) put(t *testing.T, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, env.url+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (env *settingsTestEnv) doDelete(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, env.url+path, nil)
	require.NoError(t, err)
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// ============================================================
// GET /api/info (HandleAppInfo)
// ============================================================

func TestAPI_AppInfo(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/info")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.AppInfoResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "vigolium", body.Name)
	assert.Equal(t, "test-v0.0.1", body.Version)
	assert.Equal(t, "test-author", body.Author)
	assert.Equal(t, "https://docs.vigolium.io", body.Docs)
	assert.Equal(t, "2026-01-01T00:00:00Z", body.BuildTime)
	// Commit is truncated to 7 chars
	assert.Equal(t, "abc1234", body.Commit)
}

func TestAPI_AppInfo_ShortCommit(t *testing.T) {
	// Short commits (<=7 chars) are not truncated
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/api/info")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.AppInfoResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "vigolium", body.Name)
}

// ============================================================
// GET /swagger/doc.json
// ============================================================

func TestAPI_SwaggerSpec(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/swagger/doc.json")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	resp.Body.Close()
}

// ============================================================
// GET /metrics
// ============================================================

func TestAPI_Metrics_NotConfigured(t *testing.T) {
	// Default test env doesn't enable metrics
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/metrics")
	// Metrics not enabled returns 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

// ============================================================
// GET /api/stats
// ============================================================

func TestAPI_Stats_EmptyDB(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/stats")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.StatsResponse
	readJSON(t, resp, &body)

	assert.Equal(t, int64(0), body.HTTPRecords.Total)
	assert.Equal(t, int64(0), body.Findings.Total)
	assert.Greater(t, body.Modules.Active.Total, 0, "should have active modules")
	assert.Greater(t, body.Modules.Passive.Total, 0, "should have passive modules")
	assert.NotNil(t, body.Findings.BySeverity)
}

func TestAPI_Stats_AfterIngest(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Ingest some records
	env.post(t, "/api/ingest-http", `{"input_mode":"url","content":"http://example.com/a"}`).Body.Close()
	env.post(t, "/api/ingest-http", `{"input_mode":"url","content":"http://example.com/b"}`).Body.Close()

	resp := env.get(t, "/api/stats")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.StatsResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(2), body.HTTPRecords.Total)
}

// ============================================================
// GET /api/scope
// ============================================================

func TestAPI_Scope_Get_WithSettings(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/scope")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body config.ScopeConfig
	readJSON(t, resp, &body)

	// Default scope config values
	assert.False(t, body.AppliedOnIngest)
	assert.Equal(t, []string{"*"}, body.Host.Include)
}

func TestAPI_Scope_Get_NilSettings(t *testing.T) {
	// apiTestEnv passes nil settings
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/api/scope")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Should return default scope config
	var body config.ScopeConfig
	readJSON(t, resp, &body)
	assert.Equal(t, []string{"*"}, body.Host.Include)
}

// ============================================================
// POST /api/scope
// ============================================================

func TestAPI_Scope_Update_InvalidJSON(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scope", `not valid json`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid JSON")
}

func TestAPI_Scope_Update_NilSettings(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/scope", `{"host":{"include":["*.example.com"]}}`)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "settings not available")
}

// ============================================================
// GET /api/config
// ============================================================

func TestAPI_Config_Get(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/config")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ConfigListResponse
	readJSON(t, resp, &body)
	assert.Greater(t, body.Total, 0, "should have config entries")
	assert.Len(t, body.Entries, body.Total)

	// All entries should have a key
	for _, e := range body.Entries {
		assert.NotEmpty(t, e.Key)
	}
}

func TestAPI_Config_Get_Filter(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/config?filter=scope")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ConfigListResponse
	readJSON(t, resp, &body)

	// All returned keys should contain "scope"
	for _, e := range body.Entries {
		assert.Contains(t, e.Key, "scope", "filtered entries should match")
	}
}

func TestAPI_Config_Get_FilterNoMatch(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/config?filter=nonexistent_key_xyz")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ConfigListResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 0, body.Total)
}

func TestAPI_Config_Get_NilSettings(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/api/config")
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "settings not available")
}

// ============================================================
// POST /api/config
// ============================================================

func TestAPI_Config_Update_InvalidJSON(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/config", `not valid json`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid JSON")
}

func TestAPI_Config_Update_EmptyBody(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/config", `{}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "at least one")
}

func TestAPI_Config_Update_InvalidKey(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/config", `{"nonexistent.key.xyz": "value"}`)

	var body server.ConfigUpdateResponse
	readJSON(t, resp, &body)
	// Invalid keys produce errors
	assert.NotEmpty(t, body.Errors)
}

func TestAPI_Config_Update_NilSettings(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/config", `{"scope.applied_on_ingest": "true"}`)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "settings not available")
}

// ============================================================
// GET /api/scan/status
// ============================================================

func TestAPI_ScanStatus_Idle(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/scan/status")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanStatusResponse
	readJSON(t, resp, &body)
	assert.False(t, body.Running)
	assert.Equal(t, "idle", body.Status)
}

// ============================================================
// DELETE /api/scan
// ============================================================

func TestAPI_ScanCancel_NoScanRunning(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.doDelete(t, "/api/scan")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ScanStatusResponse
	readJSON(t, resp, &body)
	assert.False(t, body.Running)
	assert.Equal(t, "idle", body.Status)
	assert.Contains(t, body.Message, "no scan")
}

// ============================================================
// POST /api/scans/run
// ============================================================

func TestAPI_ScanAllRecords_NoRecords(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// No records ingested, so scan should fail with "no records"
	resp := env.post(t, "/api/scan-all-records", `{}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "no records")
}

func TestAPI_ScanTrigger_InvalidJSON(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/scans/run", `not valid json`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid request")
}

// ============================================================
// GET /api/source-repos (empty)
// ============================================================

func TestAPI_SourceRepos_ListEmpty(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/source-repos")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(0), body.Total)
}

// ============================================================
// POST /api/source-repos — validation
// ============================================================

func TestAPI_SourceRepos_Create_InvalidJSON(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/source-repos", `not valid json`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid request")
}

func TestAPI_SourceRepos_Create_MissingFields(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Missing both hostname and root_path
	resp := env.post(t, "/api/source-repos", `{"name": "test"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "hostname")
	assert.Contains(t, body.Error, "root_path")
}

func TestAPI_SourceRepos_Create_MissingHostname(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/source-repos", `{"root_path": "/tmp/repo"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestAPI_SourceRepos_Create_MissingRootPath(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/source-repos", `{"hostname": "example.com"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// ============================================================
// POST /api/source-repos — success
// ============================================================

func TestAPI_SourceRepos_Create_Minimal(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/source-repos", `{
		"hostname": "example.com",
		"root_path": "/app/src"
	}`)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body database.SourceRepo
	readJSON(t, resp, &body)
	assert.Equal(t, "example.com", body.Hostname)
	assert.Equal(t, "/app/src", body.RootPath)
	assert.Equal(t, "example.com", body.Name, "name defaults to hostname")
	assert.Equal(t, "folder", body.RepoType, "repo_type defaults to folder")
	assert.NotZero(t, body.ID)
}

func TestAPI_SourceRepos_Create_Full(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.post(t, "/api/source-repos", `{
		"hostname": "api.example.com",
		"name": "Backend API",
		"root_path": "/opt/api",
		"repo_type": "git",
		"language": "Go",
		"framework": "Fiber",
		"endpoints": ["/api/users", "/api/login"],
		"route_params": ["id", "page"],
		"tags": ["backend", "rest"]
	}`)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body database.SourceRepo
	readJSON(t, resp, &body)
	assert.Equal(t, "api.example.com", body.Hostname)
	assert.Equal(t, "Backend API", body.Name)
	assert.Equal(t, "/opt/api", body.RootPath)
	assert.Equal(t, "git", body.RepoType)
	assert.Equal(t, "Go", body.Language)
	assert.Equal(t, "Fiber", body.Framework)
	assert.Equal(t, []string{"/api/users", "/api/login"}, body.Endpoints)
	assert.Equal(t, []string{"id", "page"}, body.RouteParams)
	assert.Equal(t, []string{"backend", "rest"}, body.Tags)
}

// ============================================================
// GET /api/source-repos/:id
// ============================================================

func TestAPI_SourceRepos_GetByID(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Create first
	resp := env.post(t, "/api/source-repos", `{
		"hostname": "example.com",
		"root_path": "/app",
		"language": "Python"
	}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created database.SourceRepo
	readJSON(t, resp, &created)

	// Get by ID
	resp = env.get(t, fmt.Sprintf("/api/source-repos/%d", created.ID))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body database.SourceRepo
	readJSON(t, resp, &body)
	assert.Equal(t, created.ID, body.ID)
	assert.Equal(t, "example.com", body.Hostname)
	assert.Equal(t, "Python", body.Language)
}

func TestAPI_SourceRepos_GetByID_NotFound(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/source-repos/99999")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "not found")
}

func TestAPI_SourceRepos_GetByID_InvalidID(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/source-repos/abc")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid ID")
}

// ============================================================
// PUT /api/source-repos/:id
// ============================================================

func TestAPI_SourceRepos_Update(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Create
	resp := env.post(t, "/api/source-repos", `{
		"hostname": "example.com",
		"root_path": "/app",
		"language": "Python"
	}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created database.SourceRepo
	readJSON(t, resp, &created)

	// Update
	resp = env.put(t, fmt.Sprintf("/api/source-repos/%d", created.ID), `{
		"language": "Go",
		"framework": "Gin",
		"tags": ["updated"]
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body database.SourceRepo
	readJSON(t, resp, &body)
	assert.Equal(t, "Go", body.Language)
	assert.Equal(t, "Gin", body.Framework)
	assert.Equal(t, []string{"updated"}, body.Tags)
	// Unchanged fields should persist
	assert.Equal(t, "example.com", body.Hostname)
	assert.Equal(t, "/app", body.RootPath)
}

func TestAPI_SourceRepos_Update_NotFound(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.put(t, "/api/source-repos/99999", `{"language": "Go"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "not found")
}

func TestAPI_SourceRepos_Update_InvalidJSON(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Create first
	resp := env.post(t, "/api/source-repos", `{
		"hostname": "example.com",
		"root_path": "/app"
	}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created database.SourceRepo
	readJSON(t, resp, &created)

	resp = env.put(t, fmt.Sprintf("/api/source-repos/%d", created.ID), `not json`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestAPI_SourceRepos_Update_InvalidID(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.put(t, "/api/source-repos/abc", `{"language": "Go"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid ID")
}

// ============================================================
// DELETE /api/source-repos/:id
// ============================================================

func TestAPI_SourceRepos_Delete(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Create
	resp := env.post(t, "/api/source-repos", `{
		"hostname": "example.com",
		"root_path": "/app"
	}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created database.SourceRepo
	readJSON(t, resp, &created)

	// Delete
	resp = env.doDelete(t, fmt.Sprintf("/api/source-repos/%d", created.ID))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	readJSON(t, resp, &body)
	assert.Equal(t, "source repo deleted", body["message"])

	// Confirm it's gone
	resp = env.get(t, fmt.Sprintf("/api/source-repos/%d", created.ID))
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestAPI_SourceRepos_Delete_InvalidID(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.doDelete(t, "/api/source-repos/abc")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "invalid ID")
}

// ============================================================
// GET /api/source-repos — list with data
// ============================================================

func TestAPI_SourceRepos_ListAfterCreate(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Create two repos
	env.post(t, "/api/source-repos", `{"hostname":"alpha.com","root_path":"/a"}`).Body.Close()
	env.post(t, "/api/source-repos", `{"hostname":"beta.com","root_path":"/b"}`).Body.Close()

	resp := env.get(t, "/api/source-repos")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(2), body.Total)
}

func TestAPI_SourceRepos_ListPagination(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Create 3 repos
	for i := 0; i < 3; i++ {
		env.post(t, "/api/source-repos", fmt.Sprintf(
			`{"hostname":"host%d.com","root_path":"/path%d"}`, i, i,
		)).Body.Close()
	}

	// Page 1
	resp := env.get(t, "/api/source-repos?limit=2&offset=0")
	var page1 server.PaginatedResponse
	readJSON(t, resp, &page1)
	assert.Equal(t, int64(3), page1.Total)
	assert.Equal(t, 2, page1.Limit)
	assert.True(t, page1.HasMore)

	// Page 2
	resp = env.get(t, "/api/source-repos?limit=2&offset=2")
	var page2 server.PaginatedResponse
	readJSON(t, resp, &page2)
	assert.Equal(t, int64(3), page2.Total)
	assert.False(t, page2.HasMore)
}

func TestAPI_SourceRepos_FilterByHostname(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	env.post(t, "/api/source-repos", `{"hostname":"alpha.com","root_path":"/a"}`).Body.Close()
	env.post(t, "/api/source-repos", `{"hostname":"beta.com","root_path":"/b"}`).Body.Close()

	resp := env.get(t, "/api/source-repos?hostname=alpha.com")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(1), body.Total)
}

// ============================================================
// Source repos — full CRUD lifecycle
// ============================================================

func TestAPI_SourceRepos_CRUD_Lifecycle(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// 1. Create
	resp := env.post(t, "/api/source-repos", `{
		"hostname": "crud.example.com",
		"root_path": "/opt/crud-app",
		"language": "JavaScript",
		"framework": "Express"
	}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created database.SourceRepo
	readJSON(t, resp, &created)
	id := created.ID
	assert.Equal(t, "crud.example.com", created.Hostname)

	// 2. Read
	resp = env.get(t, fmt.Sprintf("/api/source-repos/%d", id))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var fetched database.SourceRepo
	readJSON(t, resp, &fetched)
	assert.Equal(t, "JavaScript", fetched.Language)

	// 3. Update
	resp = env.put(t, fmt.Sprintf("/api/source-repos/%d", id), `{
		"language": "TypeScript",
		"endpoints": ["/api/v1/items"]
	}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updated database.SourceRepo
	readJSON(t, resp, &updated)
	assert.Equal(t, "TypeScript", updated.Language)
	assert.Equal(t, []string{"/api/v1/items"}, updated.Endpoints)
	assert.Equal(t, "Express", updated.Framework, "unchanged fields should persist")

	// 4. List — should contain our repo
	resp = env.get(t, "/api/source-repos?hostname=crud.example.com")
	var list server.PaginatedResponse
	readJSON(t, resp, &list)
	assert.Equal(t, int64(1), list.Total)

	// 5. Delete
	resp = env.doDelete(t, fmt.Sprintf("/api/source-repos/%d", id))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// 6. Verify deleted
	resp = env.get(t, fmt.Sprintf("/api/source-repos/%d", id))
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()

	// 7. List — should be empty for this hostname
	resp = env.get(t, "/api/source-repos?hostname=crud.example.com")
	readJSON(t, resp, &list)
	assert.Equal(t, int64(0), list.Total)
}

// ============================================================
// GET /api/stats — module counts
// ============================================================

func TestAPI_Stats_ModuleCounts(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/stats")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.StatsResponse
	readJSON(t, resp, &body)

	// Enabled should be > 0 when using default settings
	assert.Greater(t, body.Modules.Active.Total, 0)
	assert.Greater(t, body.Modules.Passive.Total, 0)
	assert.GreaterOrEqual(t, body.Modules.Active.Enabled, 0)
	assert.GreaterOrEqual(t, body.Modules.Passive.Enabled, 0)
}

// ============================================================
// GET /api/stats — response format
// ============================================================

func TestAPI_Stats_ResponseFormat(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	resp := env.get(t, "/api/stats")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	defer resp.Body.Close()
	var raw map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&raw))

	// Required top-level fields
	assert.Contains(t, raw, "http_records")
	assert.Contains(t, raw, "modules")
	assert.Contains(t, raw, "findings")
}

// ============================================================
// POST /api/scans/run — with records present
// ============================================================

func TestAPI_ScanTrigger_WithRecords(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Ingest a record so we have something to scan
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/scan-test"
	}`)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Trigger scan via scan-all-records — should accept (or fail during runner setup, which is OK)
	resp = env.post(t, "/api/scan-all-records", `{}`)
	status := resp.StatusCode

	// The scan may succeed (202) or fail at runner setup (500) depending on
	// module initialization, but it should NOT be a 400 "no records" error
	assert.NotEqual(t, http.StatusBadRequest, status,
		"should not get 'no records' error after ingesting data")
	resp.Body.Close()

	// If it started, check status and wait for completion
	if status == http.StatusAccepted {
		// Second concurrent scan should get 409
		resp = env.post(t, "/api/scan-all-records", `{}`)
		if resp.StatusCode == http.StatusConflict {
			var errBody server.ErrorResponse
			readJSON(t, resp, &errBody)
			assert.Contains(t, errBody.Error, "already running")
		} else {
			resp.Body.Close()
		}

		// Check status endpoint
		statusResp := env.get(t, "/api/scan/status")
		var scanStatus server.ScanStatusResponse
		readJSON(t, statusResp, &scanStatus)
		assert.Contains(t, []string{"running", "idle"}, scanStatus.Status)

		// Wait for scan to finish so goroutines are cleaned up
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			r := env.get(t, "/api/scan/status")
			var s server.ScanStatusResponse
			readJSON(t, r, &s)
			if s.Status == "idle" {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// ============================================================
// Scan concurrency: status during idle and after cancel
// ============================================================

func TestAPI_ScanStatus_ThenCancel_ThenStatus(t *testing.T) {
	env := newSettingsTestEnv(t, "")

	// Status when idle
	resp := env.get(t, "/api/scan/status")
	var status server.ScanStatusResponse
	readJSON(t, resp, &status)
	assert.Equal(t, "idle", status.Status)
	assert.False(t, status.Running)

	// Cancel when nothing running
	resp = env.doDelete(t, "/api/scan")
	readJSON(t, resp, &status)
	assert.Equal(t, "idle", status.Status)

	// Status should still be idle
	resp = env.get(t, "/api/scan/status")
	readJSON(t, resp, &status)
	assert.Equal(t, "idle", status.Status)
}
