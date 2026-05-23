package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
)

// newPinnedTestDB is a single-connection variant of newProjectModelTestDB.
//
// A shared in-memory SQLite database (":memory:") is per-connection, so any
// table created on one pooled connection is invisible to the next. The package
// helper happens to work for the http_records/findings tables exercised
// elsewhere, but the scans / scan_logs paths reliably land on a connection that
// never saw CreateSchema. Pinning the pool to a single connection guarantees
// every statement runs against the same in-memory database.
func newPinnedTestDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)
	bunDB := bun.NewDB(sqldb, sqlitedialect.New())
	db := database.NewDBFromBun(bunDB, "sqlite")
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, database.NewRepository(db)
}

// insertScan inserts a minimal Scan row and returns its UUID.
func insertScan(t *testing.T, db *database.DB, repo *database.Repository, projectUUID string) string {
	t.Helper()
	uuid := "scan-" + randSuffix()
	s := &database.Scan{
		UUID:        uuid,
		ProjectUUID: projectUUID,
		Name:        "test-scan",
		Status:      "completed",
		Target:      "https://example.test/",
		Modules:     "mod-a,mod-b",
		ScanSource:  "api",
		StartedAt:   time.Now().UTC(),
	}
	if err := repo.CreateScan(context.Background(), s); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	return uuid
}

// -----------------------------------------------------------------------------
// Projects: list / get / get-stats / delete (success + error paths)
// -----------------------------------------------------------------------------

func TestHandleProjectStatsHandlers(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	// Seed a project plus some data so stats are non-trivial.
	if err := repo.CreateProject(context.Background(), &database.Project{
		UUID: database.DefaultProjectUUID, Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create default project: %v", err)
	}
	insertRecord(t, db, database.DefaultProjectUUID)
	insertFinding(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/projects", h.HandleListProjects)
	app.Get("/api/projects/:uuid", h.HandleGetProject)
	app.Get("/api/projects/:uuid/stats", h.HandleGetProjectStats)

	t.Run("list projects", func(t *testing.T) {
		status, body := doGet(t, app, "/api/projects", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var projects []ProjectWithStats
		if err := json.Unmarshal(body, &projects); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
		if len(projects) == 0 {
			t.Errorf("expected at least the default project")
		}
	})

	t.Run("get default project", func(t *testing.T) {
		status, body := doGet(t, app, "/api/projects/"+database.DefaultProjectUUID, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var pw ProjectWithStats
		if err := json.Unmarshal(body, &pw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if pw.Project == nil || pw.UUID != database.DefaultProjectUUID {
			t.Errorf("unexpected project payload: %+v", pw.Project)
		}
	})

	t.Run("get missing project → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/projects/does-not-exist", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("get project stats", func(t *testing.T) {
		status, body := doGet(t, app, "/api/projects/"+database.DefaultProjectUUID+"/stats", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var ps ProjectStats
		if err := json.Unmarshal(body, &ps); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
	})

	t.Run("get stats for missing project → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/projects/missing/stats", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Get("/api/projects", hn.HandleListProjects)
		app2.Get("/api/projects/:uuid/stats", hn.HandleGetProjectStats)
		if status, _ := doGet(t, app2, "/api/projects", nil); status != http.StatusServiceUnavailable {
			t.Errorf("list status = %d, want 503", status)
		}
		if status, _ := doGet(t, app2, "/api/projects/x/stats", nil); status != http.StatusServiceUnavailable {
			t.Errorf("stats status = %d, want 503", status)
		}
	})
}

func TestHandleDeleteProject(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	const customUUID = "abcd1234-0000-0000-0000-000000000001"
	if err := repo.CreateProject(context.Background(), &database.Project{
		UUID: customUUID, Name: "to-delete", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Delete("/api/projects/:uuid", h.HandleDeleteProject)

	t.Run("cannot delete default project → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/projects/"+database.DefaultProjectUUID, "", nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("delete custom project", func(t *testing.T) {
		if status, body := doReq(t, app, http.MethodDelete, "/api/projects/"+customUUID, "", nil); status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		if _, err := repo.GetProjectByUUID(context.Background(), customUUID); err == nil {
			t.Errorf("project should be deleted")
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Delete("/api/projects/:uuid", hn.HandleDeleteProject)
		if status, _ := doReq(t, app2, http.MethodDelete, "/api/projects/x", "", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
}

// -----------------------------------------------------------------------------
// Scope: get + update validation paths, mergeScopeRule
// -----------------------------------------------------------------------------

func TestHandleGetScope(t *testing.T) {
	t.Run("nil settings returns default scope", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Get("/api/scope", h.HandleGetScope)
		status, body := doGet(t, app, "/api/scope", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		var sc config.ScopeConfig
		if err := json.Unmarshal(body, &sc); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
	})

	t.Run("with settings returns configured scope", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
		app := fiber.New()
		app.Get("/api/scope", h.HandleGetScope)
		if status, _ := doGet(t, app, "/api/scope", nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})
}

func TestHandleUpdateScope_ErrorPaths(t *testing.T) {
	t.Run("nil settings → 500", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Post("/api/scope", h.HandleUpdateScope)
		if status, _ := doReq(t, app, http.MethodPost, "/api/scope", `{"host":{"include":["x"]}}`, nil); status != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", status)
		}
	})

	t.Run("malformed json → 400", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
		app := fiber.New()
		app.Post("/api/scope", h.HandleUpdateScope)
		if status, _ := doReq(t, app, http.MethodPost, "/api/scope", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})
}

func TestMergeScopeRule(t *testing.T) {
	t.Run("nil src leaves dst untouched", func(t *testing.T) {
		dst := &config.ScopeRule{Include: []string{"keep"}, Exclude: []string{"drop"}}
		src := &config.ScopeRule{} // nil slices
		mergeScopeRule(dst, src)
		if len(dst.Include) != 1 || dst.Include[0] != "keep" {
			t.Errorf("include overwritten: %+v", dst.Include)
		}
		if len(dst.Exclude) != 1 || dst.Exclude[0] != "drop" {
			t.Errorf("exclude overwritten: %+v", dst.Exclude)
		}
	})

	t.Run("non-nil src overwrites dst", func(t *testing.T) {
		dst := &config.ScopeRule{Include: []string{"old"}}
		src := &config.ScopeRule{Include: []string{"new"}, Exclude: []string{}}
		mergeScopeRule(dst, src)
		if len(dst.Include) != 1 || dst.Include[0] != "new" {
			t.Errorf("include = %+v, want [new]", dst.Include)
		}
		if dst.Exclude == nil || len(dst.Exclude) != 0 {
			t.Errorf("exclude = %+v, want empty non-nil", dst.Exclude)
		}
	})
}

// -----------------------------------------------------------------------------
// Generic DB API: tables / columns / records CRUD
// -----------------------------------------------------------------------------

func TestHandleDBSchemaAndRecords(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/db/tables", h.HandleListDBTables)
	app.Get("/api/db/tables/:table/columns", h.HandleListDBTableColumns)
	app.Get("/api/db/tables/:table/records", h.HandleListDBRecords)
	app.Get("/api/db/tables/:table/records/:id", h.HandleGetDBRecord)

	t.Run("list tables", func(t *testing.T) {
		status, body := doGet(t, app, "/api/db/tables", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var resp struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal(body, &resp)
		if resp.Total == 0 {
			t.Errorf("expected non-zero tables")
		}
	})

	t.Run("list columns for valid table", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/db/tables/http_records/columns", nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("columns for invalid table → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/db/tables/no_such_table/columns", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("list records (project-scoped auto-filter)", func(t *testing.T) {
		status, body := doGet(t, app, "/api/db/tables/http_records/records?limit=10&offset=0&sort=url&order=asc", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
	})

	t.Run("list records with filter param", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/db/tables/http_records/records?filter.method=GET&all_projects=true&search=ex", nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("list records non-numeric limit → 400", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/db/tables/http_records/records?limit=abc", nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("list records unknown table → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/db/tables/no_such_table/records", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("get record by pk not found → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/db/tables/findings/records/999999", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})
}

func TestHandleDBRecordWrites(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	id := insertFindingReturning(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/db/tables/:table/records", h.HandleCreateDBRecord)
	app.Put("/api/db/tables/:table/records/:id", h.HandleUpdateDBRecord)
	app.Delete("/api/db/tables/:table/records/:id", h.HandleDeleteDBRecord)

	t.Run("create malformed json → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/db/tables/findings/records", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("create invalid column → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPost, "/api/db/tables/findings/records", `{"this_column_does_not_exist":"x"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("update malformed json → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPut, "/api/db/tables/findings/records/1", `{bad`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("update existing finding status field", func(t *testing.T) {
		idStr := intToStr(id)
		if status, body := doReq(t, app, http.MethodPut, "/api/db/tables/findings/records/"+idStr, `{"status":"fixed"}`, nil); status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
	})

	t.Run("delete unknown table → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/db/tables/no_such_table/records/1", "", nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("delete existing finding", func(t *testing.T) {
		idStr := intToStr(id)
		if status, _ := doReq(t, app, http.MethodDelete, "/api/db/tables/findings/records/"+idStr, "", nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestIsProjectScopedTable(t *testing.T) {
	scoped := []string{"scans", "http_records", "findings", "oast_interactions", "scopes", "agentic_scans"}
	for _, tn := range scoped {
		if !isProjectScopedTable(tn) {
			t.Errorf("isProjectScopedTable(%q) = false, want true", tn)
		}
	}
	unscoped := []string{"finding_records", "users", "unknown_table"}
	for _, tn := range unscoped {
		if isProjectScopedTable(tn) {
			t.Errorf("isProjectScopedTable(%q) = true, want false", tn)
		}
	}
}

// -----------------------------------------------------------------------------
// Scans: list / get / delete / status (DB-backed, no live runner)
// -----------------------------------------------------------------------------

func TestHandleScanListGetDelete(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	scanUUID := insertScan(t, db, repo, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/scans", h.HandleListScans)
	app.Get("/api/scans/:uuid", h.HandleGetScan)
	app.Delete("/api/scans/:uuid", h.HandleDeleteScan)

	t.Run("list scans", func(t *testing.T) {
		status, body := doGet(t, app, "/api/scans?limit=600&offset=0", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var resp PaginatedResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
		if resp.Total != 1 {
			t.Errorf("total = %d, want 1", resp.Total)
		}
	})

	t.Run("get scan", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/scans/"+scanUUID, nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("get missing scan → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/scans/no-such-scan", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("delete missing scan → 404", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/scans/no-such-scan", "", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("delete existing scan", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/scans/"+scanUUID, "", nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Get("/api/scans", hn.HandleListScans)
		app2.Get("/api/scans/:uuid", hn.HandleGetScan)
		app2.Delete("/api/scans/:uuid", hn.HandleDeleteScan)
		if status, _ := doGet(t, app2, "/api/scans", nil); status != http.StatusServiceUnavailable {
			t.Errorf("list status = %d, want 503", status)
		}
		if status, _ := doGet(t, app2, "/api/scans/x", nil); status != http.StatusServiceUnavailable {
			t.Errorf("get status = %d, want 503", status)
		}
		if status, _ := doReq(t, app2, http.MethodDelete, "/api/scans/x", "", nil); status != http.StatusServiceUnavailable {
			t.Errorf("delete status = %d, want 503", status)
		}
	})
}

func TestHandleScanStatus(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/api/scan/status", h.HandleScanStatus)

	t.Run("idle when nothing running", func(t *testing.T) {
		status, body := doGet(t, app, "/api/scan/status", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		var resp ScanStatusResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
		if resp.Running || resp.Status != "idle" {
			t.Errorf("expected idle, got running=%v status=%q", resp.Running, resp.Status)
		}
	})

	t.Run("running reflects scan state with explicit project query", func(t *testing.T) {
		h.scanMu.Lock()
		st := h.getProjectScanState("proj-running")
		st.running = true
		st.scanID = "scan-xyz"
		h.scanMu.Unlock()

		status, body := doGet(t, app, "/api/scan/status?project=proj-running", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		var resp ScanStatusResponse
		_ = json.Unmarshal(body, &resp)
		if !resp.Running || resp.ScanUUID != "scan-xyz" {
			t.Errorf("expected running scan-xyz, got %+v", resp)
		}
	})
}

func TestHandleStopPauseResumeScan_NotRunning(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Post("/api/scans/:uuid/stop", h.HandleStopScan)
	app.Post("/api/scans/:uuid/pause", h.HandlePauseScan)
	app.Post("/api/scans/:uuid/resume", h.HandleResumeScan)

	for _, action := range []string{"stop", "pause", "resume"} {
		t.Run(action+" non-running → 409", func(t *testing.T) {
			if status, _ := doReq(t, app, http.MethodPost, "/api/scans/scan-unknown/"+action, "", nil); status != http.StatusConflict {
				t.Errorf("status = %d, want 409", status)
			}
		})
	}
}

func TestHandleGetScanLogs(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	scanUUID := insertScan(t, db, repo, database.DefaultProjectUUID)
	// Seed a structured scan log so the DB-fallback path returns data.
	if err := repo.CreateScanLog(context.Background(), &database.ScanLog{
		ProjectUUID: database.DefaultProjectUUID,
		ScanUUID:    scanUUID,
		Level:       "info",
		Message:     "hello",
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create scan log: %v", err)
	}

	// Point sessions dir at an empty temp dir so resolveRuntimeLogPath misses
	// and the handler falls back to DB logs.
	settings := config.DefaultSettings()
	settings.ScanningStrategy.ScanLogs.SessionsDir = t.TempDir()

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, settings)
	app := fiber.New()
	app.Get("/api/scans/:uuid/logs", h.HandleGetScanLogs)

	t.Run("returns DB logs envelope", func(t *testing.T) {
		status, body := doGet(t, app, "/api/scans/"+scanUUID+"/logs?level=info&limit=10&offset=0", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var resp struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
		if resp.Total != 1 {
			t.Errorf("total = %d, want 1", resp.Total)
		}
	})

	t.Run("missing scan → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/scans/no-such-scan/logs", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Get("/api/scans/:uuid/logs", hn.HandleGetScanLogs)
		if status, _ := doGet(t, app2, "/api/scans/x/logs", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
}

// -----------------------------------------------------------------------------
// Scan helper functions (pure)
// -----------------------------------------------------------------------------

func TestScanHelpers(t *testing.T) {
	t.Run("splitModuleCSV", func(t *testing.T) {
		if got := splitModuleCSV(""); got != nil {
			t.Errorf("empty => %v, want nil", got)
		}
		got := splitModuleCSV(" a , b ,, c ")
		if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
			t.Errorf("got %v, want [a b c]", got)
		}
	})

	t.Run("displayScanTarget", func(t *testing.T) {
		if got := displayScanTarget(&database.Scan{Target: "https://x"}); got != "https://x" {
			t.Errorf("got %q", got)
		}
		if got := displayScanTarget(&database.Scan{ScanSource: "scan-on-receive"}); got != "<grouped-from-ingest-stream>" {
			t.Errorf("got %q", got)
		}
		if got := displayScanTarget(&database.Scan{ScanSource: "server-catchup"}); got != "<grouped-from-ingest-stream>" {
			t.Errorf("got %q", got)
		}
		if got := displayScanTarget(&database.Scan{}); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("buildScanViews collapses the full module set to \"all\"", func(t *testing.T) {
		allIDs := modules.GetActiveModulesID()
		if len(allIDs) == 0 {
			t.Skip("no active modules registered")
		}
		// Selecting every active module collapses to the "all" display.
		full := buildScanViews([]*database.Scan{{UUID: "s1", Modules: strings.Join(allIDs, ",")}})
		if len(full) != 1 {
			t.Fatalf("len = %d, want 1", len(full))
		}
		if full[0].UUID != "s1" {
			t.Errorf("UUID = %q, want s1", full[0].UUID)
		}
		if full[0].Modules != "all" {
			t.Errorf("Modules = %q, want \"all\" when the full active set is selected", full[0].Modules)
		}

		// A partial selection is shown verbatim (not collapsed).
		partial := buildScanViews([]*database.Scan{{UUID: "s2", Modules: "a,b"}})
		if partial[0].UUID != "s2" {
			t.Errorf("partial UUID = %q, want s2", partial[0].UUID)
		}
		if partial[0].Modules != "a,b" {
			t.Errorf("partial Modules = %q, want verbatim \"a,b\"", partial[0].Modules)
		}
	})
}
