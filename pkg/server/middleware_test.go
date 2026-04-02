package server

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/pkg/database"
)

// newTestRepo creates an in-memory SQLite DB with schema, returns a Repository.
func newTestRepo(t *testing.T) *database.Repository {
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
	return database.NewRepository(db)
}

// insertProject is a test helper that inserts a project with the given access lists.
func insertProject(t *testing.T, repo *database.Repository, domains, emails []string) string {
	t.Helper()
	p := &database.Project{
		UUID:           uuid.NewString(),
		Name:           "test-" + uuid.NewString()[:8],
		AllowedDomains: domains,
		AllowedEmails:  emails,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := repo.CreateProject(context.Background(), p); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	return p.UUID
}

// setupApp creates a Fiber app with ProjectUUID + ProjectAccess middleware
// and a dummy 200 OK handler.
func setupApp(repo *database.Repository) *fiber.App {
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware())
	app.Use(ProjectAccessMiddleware(repo))
	app.Get("/test", func(c fiber.Ctx) error {
		return c.SendString("ok")
	})
	return app
}

func doRequest(app *fiber.App, projectUUID, userEmail string) (int, string) {
	req, _ := http.NewRequest("GET", "/test", nil)
	if projectUUID != "" {
		req.Header.Set("X-Project-UUID", projectUUID)
	}
	if userEmail != "" {
		req.Header.Set("X-User-Email", userEmail)
	}
	resp, err := app.Test(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestProjectAccessMiddleware_OpenProject(t *testing.T) {
	repo := newTestRepo(t)
	projectID := insertProject(t, repo, nil, nil) // no restrictions
	app := setupApp(repo)

	// No email header → allowed
	code, _ := doRequest(app, projectID, "")
	if code != 200 {
		t.Errorf("expected 200 for no email header, got %d", code)
	}

	// Any email → allowed (open project)
	code, _ = doRequest(app, projectID, "anyone@example.com")
	if code != 200 {
		t.Errorf("expected 200 for open project, got %d", code)
	}
}

func TestProjectAccessMiddleware_AllowedEmails(t *testing.T) {
	repo := newTestRepo(t)
	projectID := insertProject(t, repo, nil, []string{"alice@acme.com", "bob@partner.io"})
	app := setupApp(repo)

	// Exact match → allowed
	code, _ := doRequest(app, projectID, "alice@acme.com")
	if code != 200 {
		t.Errorf("expected 200 for allowed email, got %d", code)
	}

	// Case-insensitive match → allowed
	code, _ = doRequest(app, projectID, "Alice@Acme.Com")
	if code != 200 {
		t.Errorf("expected 200 for case-insensitive email match, got %d", code)
	}

	// Not in list → denied
	code, _ = doRequest(app, projectID, "eve@evil.com")
	if code != 403 {
		t.Errorf("expected 403 for non-allowed email, got %d", code)
	}

	// Same domain but different user → denied (emails take priority, not domain fallback)
	code, _ = doRequest(app, projectID, "charlie@acme.com")
	if code != 403 {
		t.Errorf("expected 403 for unlisted email even if domain matches, got %d", code)
	}
}

func TestProjectAccessMiddleware_AllowedDomains(t *testing.T) {
	repo := newTestRepo(t)
	projectID := insertProject(t, repo, []string{"@acme.com", "@partner.io"}, nil)
	app := setupApp(repo)

	// Domain match → allowed
	code, _ := doRequest(app, projectID, "anyone@acme.com")
	if code != 200 {
		t.Errorf("expected 200 for matching domain, got %d", code)
	}

	// Case-insensitive domain → allowed
	code, _ = doRequest(app, projectID, "user@PARTNER.IO")
	if code != 200 {
		t.Errorf("expected 200 for case-insensitive domain match, got %d", code)
	}

	// Wrong domain → denied
	code, _ = doRequest(app, projectID, "user@evil.com")
	if code != 403 {
		t.Errorf("expected 403 for non-matching domain, got %d", code)
	}
}

func TestProjectAccessMiddleware_EmailsTakePriorityOverDomains(t *testing.T) {
	repo := newTestRepo(t)
	// Both lists set — emails should be checked, domains ignored
	projectID := insertProject(t, repo, []string{"@acme.com"}, []string{"alice@acme.com"})
	app := setupApp(repo)

	// Listed email → allowed
	code, _ := doRequest(app, projectID, "alice@acme.com")
	if code != 200 {
		t.Errorf("expected 200 for listed email, got %d", code)
	}

	// Domain would match but email list is non-empty → denied
	code, _ = doRequest(app, projectID, "bob@acme.com")
	if code != 403 {
		t.Errorf("expected 403 when emails list is set and email not in it, got %d", code)
	}
}

func TestProjectAccessMiddleware_NoEmailHeader(t *testing.T) {
	repo := newTestRepo(t)
	// Restricted project but no email header → skip check
	projectID := insertProject(t, repo, []string{"@acme.com"}, []string{"alice@acme.com"})
	app := setupApp(repo)

	code, _ := doRequest(app, projectID, "")
	if code != 200 {
		t.Errorf("expected 200 when X-User-Email is absent, got %d", code)
	}
}

func TestProjectAccessMiddleware_ProjectNotFound(t *testing.T) {
	repo := newTestRepo(t)
	app := setupApp(repo)

	// Non-existent project UUID → middleware passes through
	code, _ := doRequest(app, "nonexistent-uuid", "user@acme.com")
	if code != 200 {
		t.Errorf("expected 200 for unknown project (let downstream handle), got %d", code)
	}
}

func TestProjectAccessMiddleware_NilRepo(t *testing.T) {
	app := setupApp(nil)

	code, _ := doRequest(app, "any-project", "user@acme.com")
	if code != 200 {
		t.Errorf("expected 200 when repo is nil, got %d", code)
	}
}

func TestProjectAccessMiddleware_PublicPathsSkipped(t *testing.T) {
	repo := newTestRepo(t)
	// Restricted project — only alice allowed
	projectID := insertProject(t, repo, nil, []string{"alice@acme.com"})

	app := fiber.New()
	app.Use(ProjectUUIDMiddleware())
	app.Use(ProjectAccessMiddleware(repo))
	for _, p := range []string{"/health", "/server-info", "/metrics"} {
		p := p
		app.Get(p, func(c fiber.Ctx) error { return c.SendString("ok") })
	}

	for _, path := range []string{"/health", "/server-info", "/metrics"} {
		req, _ := http.NewRequest("GET", path, nil)
		req.Header.Set("X-Project-UUID", projectID)
		req.Header.Set("X-User-Email", "unauthorized@evil.com")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("expected 200 for public path %s, got %d", path, resp.StatusCode)
		}
	}
}

func TestProjectAccessMiddleware_InvalidEmailFormat(t *testing.T) {
	repo := newTestRepo(t)
	projectID := insertProject(t, repo, []string{"@acme.com"}, nil)
	app := setupApp(repo)

	// Email with no @ → invalid format
	code, _ := doRequest(app, projectID, "not-an-email")
	if code != 403 {
		t.Errorf("expected 403 for invalid email format, got %d", code)
	}
}
