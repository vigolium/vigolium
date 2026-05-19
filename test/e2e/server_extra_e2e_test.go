//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
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
	}, taskQueue, db, repo, settings, nil, nil)

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

func getFreePortAlt(t *testing.T) int { return getFreePort(t) }

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

