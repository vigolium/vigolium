package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
)

// -----------------------------------------------------------------------------
// Modules: HandleListModules tag filter + moduleHasTag
// -----------------------------------------------------------------------------

func TestHandleListModules_TagFilter(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/api/modules", h.HandleListModules)

	// Find a tag that at least one registered module carries.
	var sampleTag string
	for _, m := range modules.GetActiveModules() {
		if len(m.Tags()) > 0 {
			sampleTag = m.Tags()[0]
			break
		}
	}
	if sampleTag == "" {
		t.Skip("no tagged active modules registered")
	}

	status, body := doGet(t, app, "/api/modules?tag="+sampleTag, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var resp struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.Total == 0 {
		t.Errorf("tag=%q returned 0 modules, expected some", sampleTag)
	}

	// A nonsense tag should return nothing.
	if _, b := doGet(t, app, "/api/modules?tag=zzz-no-such-tag", nil); func() bool {
		var r struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal(b, &r)
		return r.Total != 0
	}() {
		t.Errorf("nonsense tag returned modules, want 0")
	}
}

func TestModuleHasTag(t *testing.T) {
	var tagged modules.Module
	for _, m := range modules.GetActiveModules() {
		if len(m.Tags()) > 0 {
			tagged = m
			break
		}
	}
	if tagged == nil {
		t.Skip("no tagged modules")
	}
	tag := tagged.Tags()[0]
	if !moduleHasTag(tagged, tag) {
		t.Errorf("moduleHasTag should match %q", tag)
	}
	if moduleHasTag(tagged, "definitely-not-a-real-tag-xyz") {
		t.Errorf("moduleHasTag should not match a bogus tag")
	}
}

// -----------------------------------------------------------------------------
// Extensions: list / get / edit + API docs + filter helpers
// -----------------------------------------------------------------------------

func TestHandleListExtensions_NilSettings(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil) // settings nil
	app := fiber.New()
	app.Get("/api/extensions", h.HandleListExtensions)

	status, body := doGet(t, app, "/api/extensions", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var resp struct {
		Total            int  `json:"total"`
		ExtensionEnabled bool `json:"extensions_enabled"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.Total != 0 {
		t.Errorf("total = %d, want 0 with nil settings", resp.Total)
	}
}

func TestHandleListExtensions_WithSettings(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
	app := fiber.New()
	app.Get("/api/extensions", h.HandleListExtensions)

	// Exercises the LoadScripts/LoadFromConfig + filter branches. With default
	// settings there are typically no on-disk extensions configured, so the
	// result is an empty (non-nil) list.
	status, _ := doGet(t, app, "/api/extensions?type=active&search=anything", nil)
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
}

func TestHandleGetExtension_NotFound(t *testing.T) {
	t.Run("nil settings → 404", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Get("/api/extensions/:name", h.HandleGetExtension)
		if status, _ := doGet(t, app, "/api/extensions/missing.js", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("unknown name with settings → 404", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
		app := fiber.New()
		app.Get("/api/extensions/:name", h.HandleGetExtension)
		if status, _ := doGet(t, app, "/api/extensions/does-not-exist.js", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})
}

func TestHandleEditExtension_Validation(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
	app := fiber.New()
	app.Put("/api/extensions/:name", h.HandleEditExtension)

	t.Run("bad extension suffix → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPut, "/api/extensions/bad.txt", `{"content":"x"}`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("malformed body → 400", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPut, "/api/extensions/foo.js", `{not json`, nil); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("unknown extension → 404", func(t *testing.T) {
		if status, _ := doReq(t, app, http.MethodPut, "/api/extensions/unknown.js", `{"content":"x"}`, nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("nil settings → 404", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Put("/api/extensions/:name", hn.HandleEditExtension)
		if status, _ := doReq(t, app2, http.MethodPut, "/api/extensions/foo.js", `{"content":"x"}`, nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})
}

func TestHandleListExtensionAPI(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/api/extensions/docs", h.HandleListExtensionAPI)

	status, body := doGet(t, app, "/api/extensions/docs", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var resp struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.Total == 0 {
		t.Errorf("expected non-zero API functions")
	}

	// Search filter actually runs: a non-empty, bounded result where EVERY
	// returned function matches the term (a silently-ignored filter would
	// return functions that don't contain "http").
	_, b := doGet(t, app, "/api/extensions/docs?search=http", nil)
	var filtered struct {
		Total     int `json:"total"`
		Functions []struct {
			Name        string `json:"name"`
			Namespace   string `json:"namespace"`
			Description string `json:"description"`
		} `json:"functions"`
	}
	if err := json.Unmarshal(b, &filtered); err != nil {
		t.Fatalf("unmarshal filtered: %v\n%s", err, b)
	}
	if filtered.Total == 0 {
		t.Error("search=http returned no functions; the filter matched nothing")
	}
	if filtered.Total > resp.Total {
		t.Errorf("filtered total %d should be <= unfiltered %d", filtered.Total, resp.Total)
	}
	for _, fn := range filtered.Functions {
		hay := strings.ToLower(fn.Name + " " + fn.Namespace + " " + fn.Description)
		if !strings.Contains(hay, "http") {
			t.Errorf("filtered function %s.%s does not match search term 'http'", fn.Namespace, fn.Name)
		}
	}
}

func TestExtensionMatchesFilter(t *testing.T) {
	info := ExtensionInfo{ID: "xss-1", Name: "XSS Scanner", Type: "active", Description: "finds xss", Tags: []string{"xss", "light"}}

	if !extensionMatchesFilter(info, "", "") {
		t.Errorf("empty filter should match")
	}
	if !extensionMatchesFilter(info, "active", "") {
		t.Errorf("matching type should match")
	}
	if extensionMatchesFilter(info, "passive", "") {
		t.Errorf("non-matching type should not match")
	}
	if !extensionMatchesFilter(info, "all", "") {
		t.Errorf("type=all should match")
	}
	if !extensionMatchesFilter(info, "", "xss") {
		t.Errorf("search by description/id should match")
	}
	if !extensionMatchesFilter(info, "", "light") {
		t.Errorf("search by tag should match")
	}
	if extensionMatchesFilter(info, "", "no-match-term") {
		t.Errorf("non-matching search should not match")
	}
}

// -----------------------------------------------------------------------------
// Diagnostics / Metrics / Swagger
// -----------------------------------------------------------------------------

func TestHandleDiagnostics(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
	app := fiber.New()
	app.Get("/api/diagnostics", h.HandleDiagnostics)
	if status, _ := doGet(t, app, "/api/diagnostics", nil); status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
}

func TestHandleMetrics_NotConfigured(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/metrics", h.HandleMetrics)
	if status, _ := doGet(t, app, "/metrics", nil); status != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when metrics handler unset", status)
	}
}

func TestHandleSwaggerSpec(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/swagger/doc.json", h.HandleSwaggerSpec)
	status, body := doGet(t, app, "/swagger/doc.json", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	// The embedded spec must be valid JSON.
	var spec map[string]any
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Errorf("swagger spec is not valid JSON: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Agent status/session list + detail (DB-backed, no live agent dispatch)
// -----------------------------------------------------------------------------

func insertAgenticScan(t *testing.T, repo *database.Repository, projectUUID string) string {
	t.Helper()
	uuid := "ar-" + randSuffix()
	run := &database.AgenticScan{
		UUID:        uuid,
		ProjectUUID: projectUUID,
		Mode:        "swarm",
		AgentName:   "test-agent",
		Status:      "completed",
		CompletedAt: time.Now().UTC(),
	}
	if err := repo.CreateAgenticScan(context.Background(), run); err != nil {
		t.Fatalf("create agentic scan: %v", err)
	}
	return uuid
}

func TestHandleAgenticScanList(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	insertAgenticScan(t, repo, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/agent/status/list", h.HandleAgenticScanList)

	status, body := doGet(t, app, "/api/agent/status/list", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", status, body)
	}
	var statuses []*AgenticScanStatusResponse
	if err := json.Unmarshal(body, &statuses); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if len(statuses) == 0 {
		t.Errorf("expected at least one agentic scan in list")
	}
}

func TestHandleAgenticScanStatus(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	uuid := insertAgenticScan(t, repo, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/agent/status/:id", h.HandleAgenticScanStatus)

	t.Run("found in DB", func(t *testing.T) {
		status, body := doGet(t, app, "/api/agent/status/"+uuid, nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var resp AgenticScanStatusResponse
		_ = json.Unmarshal(body, &resp)
		if resp.AgenticScanUUID != uuid {
			t.Errorf("uuid = %q, want %q", resp.AgenticScanUUID, uuid)
		}
	})

	t.Run("missing → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/agent/status/no-such-run", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})
}

func TestHandleAgentSessionListAndDetail(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	uuid := insertAgenticScan(t, repo, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/agent/sessions", h.HandleAgentSessionList)
	app.Get("/api/agent/sessions/:id", h.HandleAgentSessionDetail)

	t.Run("list sessions", func(t *testing.T) {
		status, body := doGet(t, app, "/api/agent/sessions?limit=600&offset=0&mode=swarm", nil)
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

	t.Run("session detail found", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/agent/sessions/"+uuid, nil); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("session detail missing → 404", func(t *testing.T) {
		if status, _ := doGet(t, app, "/api/agent/sessions/no-such-id", nil); status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", status)
		}
	})

	t.Run("session list db unavailable → 503", func(t *testing.T) {
		hn := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app2 := fiber.New()
		app2.Get("/api/agent/sessions", hn.HandleAgentSessionList)
		app2.Get("/api/agent/sessions/:id", hn.HandleAgentSessionDetail)
		if status, _ := doGet(t, app2, "/api/agent/sessions", nil); status != http.StatusServiceUnavailable {
			t.Errorf("list status = %d, want 503", status)
		}
		if status, _ := doGet(t, app2, "/api/agent/sessions/x", nil); status != http.StatusServiceUnavailable {
			t.Errorf("detail status = %d, want 503", status)
		}
	})
}

func TestAgenticScanToStatusResponse(t *testing.T) {
	completed := time.Now().UTC()
	run := &database.AgenticScan{
		UUID: "ar-1", Mode: "autopilot", Status: "completed", AgentName: "a",
		FindingCount: 3, RecordCount: 5, SavedCount: 2, CompletedAt: completed,
	}
	resp := agenticScanToStatusResponse(run)
	if resp.AgenticScanUUID != "ar-1" || resp.FindingCount != 3 || resp.SavedCount != 2 {
		t.Errorf("unexpected conversion: %+v", resp)
	}
	if resp.CompletedAt == nil {
		t.Errorf("CompletedAt should be set for a completed run")
	}

	// Zero CompletedAt → nil pointer.
	running := &database.AgenticScan{UUID: "ar-2", Status: "running"}
	if r := agenticScanToStatusResponse(running); r.CompletedAt != nil {
		t.Errorf("CompletedAt should be nil for a run with zero completion time")
	}
}

// -----------------------------------------------------------------------------
// types.go accessors
// -----------------------------------------------------------------------------

func TestScanRequestRequest_Accessors(t *testing.T) {
	t.Run("ReqBase64 prefers http_request_base64", func(t *testing.T) {
		r := &ScanRequestRequest{HTTPRequestBase64: "preferred", RawRequest: "legacy"}
		if got := r.ReqBase64(); got != "preferred" {
			t.Errorf("ReqBase64 = %q, want preferred", got)
		}
		r2 := &ScanRequestRequest{RawRequest: "legacy"}
		if got := r2.ReqBase64(); got != "legacy" {
			t.Errorf("ReqBase64 fallback = %q, want legacy", got)
		}
	})

	t.Run("RespBase64 prefers http_response_base64", func(t *testing.T) {
		r := &ScanRequestRequest{HTTPResponseBase64: "preferred", RawResponse: "legacy"}
		if got := r.RespBase64(); got != "preferred" {
			t.Errorf("RespBase64 = %q, want preferred", got)
		}
		r2 := &ScanRequestRequest{RawResponse: "legacy"}
		if got := r2.RespBase64(); got != "legacy" {
			t.Errorf("RespBase64 fallback = %q, want legacy", got)
		}
	})
}

func TestAgentAuditDriverRequest_EffectivePlatform(t *testing.T) {
	if got := (AgentAuditDriverRequest{Platform: "claude", Agent: "codex"}).EffectivePlatform(); got != "claude" {
		t.Errorf("EffectivePlatform = %q, want claude (platform wins)", got)
	}
	if got := (AgentAuditDriverRequest{Agent: "codex"}).EffectivePlatform(); got != "codex" {
		t.Errorf("EffectivePlatform = %q, want codex (agent fallback)", got)
	}
	if got := (AgentAuditDriverRequest{}).EffectivePlatform(); got != "" {
		t.Errorf("EffectivePlatform = %q, want empty", got)
	}
}
