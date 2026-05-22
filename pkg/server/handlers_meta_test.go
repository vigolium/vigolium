package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// -----------------------------------------------------------------------------
// HandleStats + countEnabledModules
// -----------------------------------------------------------------------------

func TestHandleStats_NoSettingsAllEnabled(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil) // settings nil
	app := fiber.New()
	app.Get("/api/stats", h.HandleStats)

	status, body := doGet(t, app, "/api/stats", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var resp StatsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	activeTotal := len(modules.GetActiveModules())
	passiveTotal := len(modules.GetPassiveModules())
	if resp.Modules.Active.Total != activeTotal {
		t.Errorf("active total = %d, want %d", resp.Modules.Active.Total, activeTotal)
	}
	// With nil settings, every module should report as enabled.
	if resp.Modules.Active.Enabled != activeTotal {
		t.Errorf("active enabled = %d, want %d (all)", resp.Modules.Active.Enabled, activeTotal)
	}
	if resp.Modules.Passive.Enabled != passiveTotal {
		t.Errorf("passive enabled = %d, want %d (all)", resp.Modules.Passive.Enabled, passiveTotal)
	}
}

func TestHandleStats_WithDBCounts(t *testing.T) {
	db, repo := newProjectModelTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)
	insertRecord(t, db, database.DefaultProjectUUID)
	insertFinding(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, config.DefaultSettings())
	app := fiber.New()
	app.Get("/api/stats", h.HandleStats)

	_, body := doGet(t, app, "/api/stats", nil)
	var resp StatsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.HTTPRecords.Total != 2 {
		t.Errorf("records total = %d, want 2", resp.HTTPRecords.Total)
	}
	if resp.Findings.Total != 1 {
		t.Errorf("findings total = %d, want 1", resp.Findings.Total)
	}
	if resp.Findings.BySeverity == nil {
		t.Errorf("by_severity should be initialized")
	}
}

func TestCountEnabledModules(t *testing.T) {
	if got := countEnabledModules([]string{"all"}, 50); got != 50 {
		t.Errorf(`"all" => %d, want total 50`, got)
	}
	if got := countEnabledModules([]string{"a", "b", "c"}, 50); got != 3 {
		t.Errorf("explicit list => %d, want 3", got)
	}
	if got := countEnabledModules(nil, 50); got != 0 {
		t.Errorf("nil => %d, want 0", got)
	}
	if got := countEnabledModules([]string{"x", "all", "y"}, 12); got != 12 {
		t.Errorf(`list containing "all" => %d, want total 12`, got)
	}
}

// -----------------------------------------------------------------------------
// HandleListModules + module helpers
// -----------------------------------------------------------------------------

func TestHandleListModules(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/api/modules", h.HandleListModules)

	decode := func(path string) (int, int) {
		status, body := doGet(t, app, path, nil)
		var resp struct {
			Modules []ModuleInfo `json:"modules"`
			Total   int          `json:"total"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal %s: %v\n%s", path, err, body)
		}
		if resp.Total != len(resp.Modules) {
			t.Errorf("%s: total %d != len(modules) %d", path, resp.Total, len(resp.Modules))
		}
		return status, resp.Total
	}

	statusAll, totalAll := decode("/api/modules")
	if statusAll != http.StatusOK {
		t.Fatalf("status = %d, want 200", statusAll)
	}
	wantAll := len(modules.GetActiveModules()) + len(modules.GetPassiveModules())
	if totalAll != wantAll {
		t.Errorf("unfiltered total = %d, want %d", totalAll, wantAll)
	}

	// A search filter should return a strict subset (and there are XSS modules).
	_, totalXSS := decode("/api/modules?search=xss")
	if totalXSS == 0 {
		t.Errorf("search=xss returned 0 modules, expected some")
	}
	if totalXSS >= totalAll {
		t.Errorf("filtered total %d should be < unfiltered %d", totalXSS, totalAll)
	}

	// A nonsense search should match nothing.
	if _, n := decode("/api/modules?search=zzz-no-such-module-zzz"); n != 0 {
		t.Errorf("nonsense search returned %d, want 0", n)
	}
}

func TestScanScopeNames(t *testing.T) {
	cases := []struct {
		scope modkit.ScanScope
		want  []string
	}{
		{modkit.ScanScopeInsertionPoint, []string{"PER_INSERTION_POINT"}},
		{modkit.ScanScopeRequest, []string{"PER_REQUEST"}},
		{modkit.ScanScopeHost, []string{"PER_HOST"}},
		{modkit.ScanScopeInsertionPoint | modkit.ScanScopeRequest | modkit.ScanScopeHost,
			[]string{"PER_INSERTION_POINT", "PER_REQUEST", "PER_HOST"}},
	}
	for _, tc := range cases {
		got := scanScopeNames(tc.scope)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("scanScopeNames(%v) = %v, want %v", tc.scope, got, tc.want)
		}
	}
}

func TestBuildModuleInfo(t *testing.T) {
	// Use a real registered active module to exercise buildModuleInfo end to end.
	active := modules.GetActiveModules()
	if len(active) == 0 {
		t.Skip("no active modules registered")
	}
	m := active[0]
	info := buildModuleInfo(m, "active")
	if info.ID != m.ID() {
		t.Errorf("ID = %q, want %q", info.ID, m.ID())
	}
	if info.Type != "active" {
		t.Errorf("Type = %q, want active", info.Type)
	}
	if info.Tags == nil {
		t.Errorf("Tags should never be nil (got nil) — handler must coalesce to []string{}")
	}
	if info.Severity == "" {
		t.Errorf("Severity should be populated")
	}
}

// -----------------------------------------------------------------------------
// HandleGetConfig / HandleUpdateConfig
// -----------------------------------------------------------------------------

func TestHandleGetConfig(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
	app := fiber.New()
	app.Get("/api/config", h.HandleGetConfig)

	t.Run("returns sorted flattened entries", func(t *testing.T) {
		status, body := doGet(t, app, "/api/config", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		var resp ConfigListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
		if resp.Total == 0 || len(resp.Entries) == 0 {
			t.Fatalf("expected config entries, got %d", resp.Total)
		}
		// Verify ascending key sort.
		for i := 1; i < len(resp.Entries); i++ {
			if resp.Entries[i-1].Key > resp.Entries[i].Key {
				t.Errorf("entries not sorted: %q before %q", resp.Entries[i-1].Key, resp.Entries[i].Key)
				break
			}
		}
	})

	t.Run("filter narrows results", func(t *testing.T) {
		_, body := doGet(t, app, "/api/config?filter=agent", nil)
		var resp ConfigListResponse
		_ = json.Unmarshal(body, &resp)
		for _, e := range resp.Entries {
			if !strings.Contains(e.Key, "agent") {
				t.Errorf("filtered entry %q does not contain 'agent'", e.Key)
			}
		}
	})

	t.Run("sensitive values redacted by default", func(t *testing.T) {
		_, body := doGet(t, app, "/api/config", nil)
		var resp ConfigListResponse
		_ = json.Unmarshal(body, &resp)
		for _, e := range resp.Entries {
			if e.Sensitive && e.Value != "" && e.Value != "********" {
				t.Errorf("sensitive key %q leaked value %q", e.Key, e.Value)
			}
		}
	})
}

func TestHandleGetConfig_NoSettings(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil) // settings nil
	app := fiber.New()
	app.Get("/api/config", h.HandleGetConfig)
	status, _ := doGet(t, app, "/api/config", nil)
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when settings nil", status)
	}
}

func TestHandleUpdateConfig_Validation(t *testing.T) {
	postJSONLocal := func(h *Handlers, body string) (int, []byte) {
		app := fiber.New()
		app.Post("/api/config", h.HandleUpdateConfig)
		req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		return resp.StatusCode, buf[:n]
	}

	t.Run("nil settings → 500", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		if status, _ := postJSONLocal(h, `{"a":"b"}`); status != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", status)
		}
	})

	t.Run("malformed json → 400", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
		if status, _ := postJSONLocal(h, `{not json`); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("empty body → 400", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
		if status, _ := postJSONLocal(h, `{}`); status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("all-invalid keys → 400 with errors", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
		status, body := postJSONLocal(h, `{"this.is.not.a.real.key":"x"}`)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body %s", status, body)
		}
		var resp ConfigUpdateResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, body)
		}
		if len(resp.Errors) == 0 {
			t.Errorf("expected errors for unknown key, got none")
		}
	})
}
