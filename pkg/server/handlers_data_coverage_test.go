package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// doReq drives an arbitrary method/path against a Fiber app and returns status +
// body. It mirrors the helpers already used across the package's handler tests
// (doGet in handlers_basic_test.go) but supports a request body and per-call
// headers so the mutating endpoints can be exercised too.
func doReq(t *testing.T, app *fiber.App, method, path, body string, headers map[string]string) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// insertFindingReturning inserts a Finding and returns its autoincrement ID.
func insertFindingReturning(t *testing.T, db *database.DB, projectUUID string) int64 {
	t.Helper()
	f := &database.Finding{
		ProjectUUID:     projectUUID,
		HTTPRecordUUIDs: []string{"rec-x"},
		ModuleID:        "test-module",
		ModuleName:      "Test Module",
		Severity:        "high",
		Confidence:      "firm",
		Status:          "draft",
		FindingHash:     "fhash-" + randSuffix(),
		FoundAt:         time.Now().UTC(),
	}
	if _, err := db.NewInsert().Model(f).Exec(context.Background()); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return f.ID
}

// insertOAST inserts an OAST interaction row and returns its ID.
func insertOAST(t *testing.T, db *database.DB, projectUUID string) int64 {
	t.Helper()
	o := &database.OASTInteraction{
		ProjectUUID:  projectUUID,
		UniqueID:     "uid-" + randSuffix(),
		FullID:       "full-" + randSuffix(),
		Protocol:     "dns",
		InteractedAt: time.Now().UTC(),
	}
	if _, err := db.NewInsert().Model(o).Exec(context.Background()); err != nil {
		t.Fatalf("insert oast: %v", err)
	}
	return o.ID
}

// -----------------------------------------------------------------------------
// Findings: list / get / update-status / delete
// -----------------------------------------------------------------------------

func TestHandleListFindings_DBUnavailable(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/api/findings", h.findingsHandler().HandleListFindings)
	if status, _ := doGet(t, app, "/api/findings", nil); status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", status)
	}
}

func TestHandleListFindings_SuccessAndFilters(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	insertFindingReturning(t, db, database.DefaultProjectUUID)
	insertFindingReturning(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/findings", h.findingsHandler().HandleListFindings)

	t.Run("list returns paginated findings", func(t *testing.T) {
		status, body := doGet(t, app, "/api/findings", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var resp PaginatedResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
		if resp.Total != 2 {
			t.Errorf("total = %d, want 2", resp.Total)
		}
		if resp.ProjectUUID != database.DefaultProjectUUID {
			t.Errorf("project = %q", resp.ProjectUUID)
		}
	})

	t.Run("severity + sort + pagination params accepted", func(t *testing.T) {
		// Exercise the many filter branches in HandleListFindings.
		status, _ := doGet(t, app, "/api/findings?severity=high,low&status=draft&sort=severity&order=asc&limit=600&offset=0&search=test&module_name=Test&module_type=active&finding_source=dast&domain=example&scan_uuid=s1&repo_name=r1", nil)
		if status != http.StatusOK {
			t.Errorf("filtered list status = %d, want 200", status)
		}
	})
}

func TestHandleGetFinding(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	id := insertFindingReturning(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/findings/:id", h.findingsHandler().HandleGetFinding)

	t.Run("found", func(t *testing.T) {
		status, body := doGet(t, app, "/api/findings/"+strconv.FormatInt(id, 10), nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var f database.Finding
		if err := json.Unmarshal(body, &f); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if f.ID != id {
			t.Errorf("id = %d, want %d", f.ID, id)
		}
	})

	t.Run("non-numeric id → 400", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/findings/not-a-number", nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("missing id → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/findings/999999", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Get("/api/findings/:id", hn.findingsHandler().HandleGetFinding)
		if status, _ := doGet(t, app2, "/api/findings/1", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
}

func TestHandleUpdateFindingStatus(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	id := insertFindingReturning(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Patch("/api/findings/:id/status", h.findingsHandler().HandleUpdateFindingStatus)

	t.Run("valid status update", func(t *testing.T) {
		status, body := doReq(t, app, http.MethodPatch, "/api/findings/"+strconv.FormatInt(id, 10)+"/status", `{"status":"triaged"}`, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var f database.Finding
		_ = json.Unmarshal(body, &f)
		if f.Status != "triaged" {
			t.Errorf("status = %q, want triaged", f.Status)
		}
	})

	t.Run("invalid status value → 400", func(t *testing.T) {
		status, _ := doReq(t, app, http.MethodPatch, "/api/findings/"+strconv.FormatInt(id, 10)+"/status", `{"status":"bogus"}`, nil)
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("non-numeric id → 400", func(t *testing.T) {
		status, _ := doReq(t, app, http.MethodPatch, "/api/findings/abc/status", `{"status":"fixed"}`, nil)
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("malformed body → 400", func(t *testing.T) {
		status, _ := doReq(t, app, http.MethodPatch, "/api/findings/"+strconv.FormatInt(id, 10)+"/status", `{not json`, nil)
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("missing finding → 404", func(t *testing.T) {
		status, _ := doReq(t, app, http.MethodPatch, "/api/findings/888888/status", `{"status":"fixed"}`, nil)
		if status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})
}

func TestHandleDeleteFinding(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	id := insertFindingReturning(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Delete("/api/findings/:id", h.findingsHandler().HandleDeleteFinding)

	t.Run("non-numeric id → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/findings/xyz", "", nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("missing id → 404", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/findings/777777", "", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("delete existing", func(t *testing.T) {
		status, body := doReq(t, app, http.MethodDelete, "/api/findings/"+strconv.FormatInt(id, 10), "", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		// Now it's gone.
		if status, _ := doReq(t, app, http.MethodDelete, "/api/findings/"+strconv.FormatInt(id, 10), "", nil); status != http.StatusNotFound {
			t.Errorf("re-delete status = %d, want 404", status)
		}
	})
}

// -----------------------------------------------------------------------------
// HTTP records: list / get / delete
// -----------------------------------------------------------------------------

func TestHandleListRecords(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/http-records", h.HandleListRecords)

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Get("/api/http-records", hn.HandleListRecords)
		if status, _ := doGet(t, app2, "/api/http-records", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})

	t.Run("list with many filters", func(t *testing.T) {
		status, body := doGet(t, app, "/api/http-records?status_code=200,404&content_type=text/html&method=get,post&path=/&search=x&source=api&min_risk=1&remark=a,b&sort=url&order=asc&limit=600&offset=0", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var resp PaginatedResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
	})

	t.Run("single remark (no comma)", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/http-records?remark=single", nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})
}

func TestHandleGetRecord(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)
	// Pull the inserted UUID back out.
	var rec database.HTTPRecord
	if err := db.NewSelect().Model(&rec).Limit(1).Scan(context.Background()); err != nil {
		t.Fatalf("select record: %v", err)
	}

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/http-records/:uuid", h.HandleGetRecord)

	t.Run("found", func(t *testing.T) {
		status, body := doGet(t, app, "/api/http-records/"+rec.UUID, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var got database.HTTPRecord
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.UUID != rec.UUID {
			t.Errorf("uuid = %q, want %q", got.UUID, rec.UUID)
		}
	})

	t.Run("missing uuid → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/http-records/no-such-uuid", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Get("/api/http-records/:uuid", hn.HandleGetRecord)
		if status, _ := doGet(t, app2, "/api/http-records/x", nil); status != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", status)
		}
	})
}

func TestHandleDeleteRecord(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)
	var rec database.HTTPRecord
	if err := db.NewSelect().Model(&rec).Limit(1).Scan(context.Background()); err != nil {
		t.Fatalf("select record: %v", err)
	}

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Delete("/api/http-records/:uuid", h.HandleDeleteRecord)

	t.Run("missing uuid → 404", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/http-records/nope", "", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("delete existing", func(t *testing.T) {
		if status, body := doReq(t, app, http.MethodDelete, "/api/http-records/"+rec.UUID, "", nil); status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		if status, _ := doReq(t, app, http.MethodDelete, "/api/http-records/"+rec.UUID, "", nil); status != http.StatusNotFound {
			t.Errorf("re-delete status = %d, want 404", status)
		}
	})
}

// -----------------------------------------------------------------------------
// OAST interactions: list / get / delete
// -----------------------------------------------------------------------------

func TestHandleOASTInteractions(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	id := insertOAST(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/oast-interactions", h.HandleListOASTInteractions)
	app.Get("/api/oast-interactions/:id", h.HandleGetOASTInteraction)
	app.Delete("/api/oast-interactions/:id", h.HandleDeleteOASTInteraction)

	t.Run("list", func(t *testing.T) {
		status, body := doGet(t, app, "/api/oast-interactions?protocol=dns&limit=600&offset=0&scan_uuid=&module_id=&search=", nil)
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

	t.Run("get found", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/oast-interactions/"+strconv.FormatInt(id, 10), nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("get non-numeric → 400", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/oast-interactions/abc", nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("get missing → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/oast-interactions/999999", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("delete non-numeric → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/oast-interactions/abc", "", nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("delete missing → 404", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/oast-interactions/888888", "", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("delete existing", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodDelete, "/api/oast-interactions/"+strconv.FormatInt(id, 10), "", nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Get("/api/oast-interactions", hn.HandleListOASTInteractions)
		app2.Get("/api/oast-interactions/:id", hn.HandleGetOASTInteraction)
		app2.Delete("/api/oast-interactions/:id", hn.HandleDeleteOASTInteraction)
		if status, _ := doGet(t, app2, "/api/oast-interactions", nil); status != http.StatusServiceUnavailable {
			t.Errorf("list status = %d, want 503", status)
		}
		if status, _ := doGet(t, app2, "/api/oast-interactions/1", nil); status != http.StatusServiceUnavailable {
			t.Errorf("get status = %d, want 503", status)
		}
		if status, _ := doReq(t, app2, http.MethodDelete, "/api/oast-interactions/1", "", nil); status != http.StatusServiceUnavailable {
			t.Errorf("delete status = %d, want 503", status)
		}
	})
}
