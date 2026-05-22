package server

// Contract test for the trusted-operator project model.
//
// Per SECURITY.md ("Server authentication is not tenant isolation"), the server
// assumes a trusted operator or team: any valid login user or API token is
// trusted to operate the *whole* instance. `project_uuid` is a data-separation
// label, NOT a tenant-isolation or authorization boundary. Mutually untrusted
// users are expected to run separate instances and databases.
//
// This test pins that contract: a second admin can enumerate, read, update, and
// delete another admin's project through the full production middleware stack
// (BearerAuth -> RoleGuard -> handler). It is deliberately NOT a vulnerability
// PoC — it asserts the documented behaviour so that if per-owner ACLs are ever
// introduced (changing the security model), this test fails and forces a
// conscious update to SECURITY.md alongside the code.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/pkg/database"
)

// newProjectModelTestDB creates an in-memory SQLite database with the full
// schema and returns both the *database.DB and *database.Repository.
func newProjectModelTestDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	bunDB := bun.NewDB(sqldb, sqlitedialect.New())
	db := database.NewDBFromBun(bunDB, "sqlite")
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, database.NewRepository(db)
}

func TestProjectOwnerModel_TrustedOperatorSharedAccess(t *testing.T) {
	const (
		aliceToken = "vgl_contract_alice_admin_secret"
		bobToken   = "vgl_contract_bob_admin_secret"
	)

	users := []FileUser{
		{Name: "alice", Email: "alice@contract.local", AccessCode: aliceToken, Role: RoleAdmin},
		{Name: "bob", Email: "bob@contract.local", AccessCode: bobToken, Role: RoleAdmin},
	}
	store := NewUserStore(users)

	alice := store.Lookup(aliceToken)
	bob := store.Lookup(bobToken)
	if alice == nil || bob == nil {
		t.Fatal("user store setup error: lookup returned nil")
	}
	if alice.UUID == bob.UUID {
		t.Fatalf("UUID collision — alice and bob resolved to same UUID %s", alice.UUID)
	}

	db, repo := newProjectModelTestDB(t)
	cfg := ServerConfig{
		NoAuth:    false, // auth ENABLED — the shared-access contract holds even with auth on
		UserStore: store,
		NoAgent:   true,
		NoSwagger: true,
	}
	h := NewHandlers(nil, db, repo, nil, cfg, nil, nil, nil)
	t.Cleanup(func() { h.Close() })

	app := fiber.New()
	registerRoutes(app, h, cfg) // full production route table including BearerAuth + RoleGuard

	do := func(method, path, token, body string) (int, []byte) {
		t.Helper()
		var bodyReader io.Reader
		if body != "" {
			bodyReader = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, bodyReader)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}

	jmap := func(raw []byte) map[string]any {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}

	// Alice creates a project, recording herself as owner.
	createBody := `{"name":"alice-project","description":"alice owns this","owner_uuid":"` + alice.UUID + `"}`
	status, raw := do("POST", "/api/projects", aliceToken, createBody)
	if status != http.StatusCreated {
		t.Fatalf("alice project creation returned HTTP %d; body: %s", status, raw)
	}
	projectUUID, _ := jmap(raw)["uuid"].(string)
	if projectUUID == "" {
		t.Fatal("no uuid in project create response")
	}

	// Contract 1: a second admin (bob) sees alice's project when listing —
	// project_uuid is a label, not a visibility boundary.
	status, raw = do("GET", "/api/projects", bobToken, "")
	if status != http.StatusOK {
		t.Fatalf("GET /api/projects returned HTTP %d for bob", status)
	}
	var projectList []map[string]any
	_ = json.Unmarshal(raw, &projectList)
	visible := false
	for _, entry := range projectList {
		p := entry
		if nested, ok := entry["project"].(map[string]any); ok {
			p = nested
		}
		if uid, _ := p["uuid"].(string); uid == projectUUID {
			visible = true
		}
	}
	if !visible {
		t.Errorf("trusted-operator contract violated: bob (admin) cannot see alice's project in the list")
	}

	// Contract 2: bob can read alice's project directly.
	if status, _ = do("GET", "/api/projects/"+projectUUID, bobToken, ""); status != http.StatusOK {
		t.Errorf("trusted-operator contract violated: bob GET of alice's project returned HTTP %d, want 200", status)
	}

	// Contract 3: bob can update alice's project (including reassigning owner).
	updateBody := `{"name":"renamed-by-bob","owner_uuid":"` + bob.UUID + `"}`
	if status, raw = do("PUT", "/api/projects/"+projectUUID, bobToken, updateBody); status != http.StatusOK {
		t.Errorf("trusted-operator contract violated: bob PUT of alice's project returned HTTP %d, want 200; body: %s", status, raw)
	}

	// Contract 4: bob can delete alice's (now bob-owned) project, and it is gone.
	if status, raw = do("DELETE", "/api/projects/"+projectUUID, bobToken, ""); status != http.StatusOK {
		t.Errorf("trusted-operator contract violated: bob DELETE returned HTTP %d, want 200; body: %s", status, raw)
	}
	if status, _ = do("GET", "/api/projects/"+projectUUID, aliceToken, ""); status != http.StatusNotFound {
		t.Errorf("after delete, GET returned HTTP %d, want 404", status)
	}
}
