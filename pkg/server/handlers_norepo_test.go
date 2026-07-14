package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	fiberrecover "github.com/gofiber/fiber/v3/middleware/recover"
)

// TestNewHandlers_NilRepoWithLiveDBDisablesDatabase pins the construction
// invariant that closed the nil-repo panic: a live *database.DB paired with a nil
// repository (the state the server lands in when NewDB succeeds but CreateSchema
// fails) must be collapsed to a fully DB-less handler, never left half-wired.
func TestNewHandlers_NilRepoWithLiveDBDisablesDatabase(t *testing.T) {
	db, _ := newProjectModelTestDB(t) // live, valid *database.DB

	// repo == nil while db != nil — the exact pairing that used to panic.
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, nil, nil)

	if h.db != nil {
		t.Fatalf("NewHandlers left h.db non-nil while repo was nil; repo-backed handlers will nil-pointer panic")
	}
	if h.repo != nil {
		t.Fatalf("h.repo = %v, want nil", h.repo)
	}
	if h.findings == nil || h.findings.db != nil || h.findings.repo != nil {
		t.Fatalf("findings sub-handler must also be DB-less: %+v", h.findings)
	}
}

// TestRepoBackedEndpoints_NilRepoDoNotPanic reproduces the reported REST bug: with
// a live db but no repository, every repo-backed endpoint used to nil-pointer
// panic (recovered by Fiber into HTTP 500). After the fix they must return their
// controlled "database required" status (503 for reads, 400 for the scan POST) and
// never a 500. The recover middleware mirrors production, so a regression that
// re-introduces the panic surfaces here as a 500 and fails the assertion.
func TestRepoBackedEndpoints_NilRepoDoNotPanic(t *testing.T) {
	db, _ := newProjectModelTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, nil, nil) // repo == nil

	app := fiber.New()
	app.Use(fiberrecover.New())
	app.Get("/api/scans", h.HandleListScans)
	app.Get("/api/projects", h.HandleListProjects)
	app.Get("/api/oast-interactions", h.HandleListOASTInteractions)
	app.Post("/api/scans/run", h.HandleRunScan)

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"list scans", http.MethodGet, "/api/scans", http.StatusServiceUnavailable},
		{"list projects", http.MethodGet, "/api/projects", http.StatusServiceUnavailable},
		{"list oast", http.MethodGet, "/api/oast-interactions", http.StatusServiceUnavailable},
		{"run scan", http.MethodPost, "/api/scans/run", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
			if err != nil {
				t.Fatalf("%s %s: %v", tc.method, tc.path, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusInternalServerError {
				t.Fatalf("%s %s returned 500 — nil-repo panic regressed", tc.method, tc.path)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("%s %s status = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.wantStatus)
			}
		})
	}
}
