package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// -----------------------------------------------------------------------------
// BearerAuth
// -----------------------------------------------------------------------------

func TestBearerAuth(t *testing.T) {
	const apiKey = "legacy-api-key"
	const fileCode = "vgl_file_user_code"
	store := NewUserStore([]FileUser{
		{Name: "dana", Email: "dana@test.local", AccessCode: fileCode, Role: RoleViewer},
	})

	newApp := func() *fiber.App {
		app := fiber.New()
		app.Use(BearerAuth([]string{apiKey}, store))
		// Echo whatever user resolution landed in locals.
		app.Get("/api/whoami", func(c fiber.Ctx) error {
			u := getAuthUser(c)
			if u == nil {
				return c.JSON(fiber.Map{"resolved": false})
			}
			return c.JSON(fiber.Map{"resolved": true, "role": u.Role, "name": u.Name})
		})
		app.Get("/health", func(c fiber.Ctx) error { return c.SendString("ok") })
		app.Get("/swagger/index.html", func(c fiber.Ctx) error { return c.SendString("doc") })
		return app
	}

	call := func(app *fiber.App, path, authHeader string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("call %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	t.Run("public paths skip auth", func(t *testing.T) {
		app := newApp()
		for _, p := range []string{"/health", "/swagger/index.html"} {
			if status, _ := call(app, p, ""); status != http.StatusOK {
				t.Errorf("public path %s got %d, want 200", p, status)
			}
		}
	})

	t.Run("missing header rejected", func(t *testing.T) {
		if status, _ := call(newApp(), "/api/whoami", ""); status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})

	t.Run("non-bearer header rejected", func(t *testing.T) {
		if status, _ := call(newApp(), "/api/whoami", "Basic abc"); status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})

	t.Run("empty bearer token rejected", func(t *testing.T) {
		if status, _ := call(newApp(), "/api/whoami", "Bearer "); status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})

	t.Run("file user resolves to its role", func(t *testing.T) {
		status, m := call(newApp(), "/api/whoami", "Bearer "+fileCode)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if m["role"] != RoleViewer || m["name"] != "dana" {
			t.Errorf("resolution mismatch: %+v", m)
		}
	})

	t.Run("legacy api key resolves to admin", func(t *testing.T) {
		status, m := call(newApp(), "/api/whoami", "Bearer "+apiKey)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if m["role"] != RoleAdmin {
			t.Errorf("legacy key should map to admin, got %+v", m)
		}
	})

	t.Run("unknown token rejected", func(t *testing.T) {
		if status, _ := call(newApp(), "/api/whoami", "Bearer totally-unknown"); status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})
}

// -----------------------------------------------------------------------------
// RoleGuard
// -----------------------------------------------------------------------------

func TestRoleGuard(t *testing.T) {
	mkApp := func(allowed []string, user *ResolvedUser) *fiber.App {
		app := fiber.New()
		app.Use(func(c fiber.Ctx) error {
			if user != nil {
				c.Locals(authUserLocalsKey, user)
			}
			return c.Next()
		})
		app.Get("/guarded", RoleGuard(allowed...), func(c fiber.Ctx) error {
			return c.SendString("ok")
		})
		return app
	}

	call := func(app *fiber.App) int {
		req := httptest.NewRequest(http.MethodGet, "/guarded", nil)
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	t.Run("no user passes (no-auth mode)", func(t *testing.T) {
		if status := call(mkApp([]string{RoleAdmin}, nil)); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("allowed role passes", func(t *testing.T) {
		u := &ResolvedUser{Role: RoleOperator}
		if status := call(mkApp([]string{RoleAdmin, RoleOperator}, u)); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("disallowed role rejected", func(t *testing.T) {
		u := &ResolvedUser{Role: RoleViewer}
		if status := call(mkApp([]string{RoleAdmin}, u)); status != http.StatusForbidden {
			t.Errorf("status = %d, want 403", status)
		}
	})
}

// -----------------------------------------------------------------------------
// DefaultBodyLimitMiddleware / SecurityHeadersMiddleware
// -----------------------------------------------------------------------------

func TestDefaultBodyLimitMiddleware(t *testing.T) {
	// Raise Fiber's framework-level BodyLimit above our middleware's cap so the
	// 413 we assert on comes from DefaultBodyLimitMiddleware, not from Fiber
	// rejecting the body before our middleware ever runs.
	app := fiber.New(fiber.Config{BodyLimit: defaultBodyLimit * 4})
	app.Use(DefaultBodyLimitMiddleware())
	app.Post("/api/regular", func(c fiber.Ctx) error { return c.SendString("ok") })
	app.Post("/api/import", func(c fiber.Ctx) error { return c.SendString("ok") })

	post := func(path string, size int) int {
		body := strings.Repeat("x", size)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	t.Run("small body on regular route ok", func(t *testing.T) {
		if status := post("/api/regular", 1024); status != http.StatusOK {
			t.Errorf("status = %d, want 200", status)
		}
	})

	t.Run("oversized body on regular route rejected", func(t *testing.T) {
		if status := post("/api/regular", defaultBodyLimit+1); status != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", status)
		}
	})

	t.Run("oversized body on exempt route allowed", func(t *testing.T) {
		if status := post("/api/import", defaultBodyLimit+1); status != http.StatusOK {
			t.Errorf("exempt route status = %d, want 200", status)
		}
	})
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	app := fiber.New()
	app.Use(SecurityHeadersMiddleware())
	app.Get("/x", func(c fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
	}
	for h, v := range want {
		if got := resp.Header.Get(h); got != v {
			t.Errorf("header %s = %q, want %q", h, got, v)
		}
	}
}

// -----------------------------------------------------------------------------
// isPublicProjectPath / getProjectUUID / ProjectUUIDMiddleware
// -----------------------------------------------------------------------------

func TestIsPublicProjectPath(t *testing.T) {
	// Note: the prefix match on "/swagger" is intentionally broad — any path
	// starting with /swagger (including "/swaggerish") is treated as public.
	public := []string{"/", "/health", "/server-info", "/metrics", "/swagger", "/swagger/index.html", "/swaggerish"}
	private := []string{"/api/stats", "/api/projects", "/api/findings", "/sw", "/api/swagger"}
	for _, p := range public {
		if !isPublicProjectPath(p) {
			t.Errorf("isPublicProjectPath(%q) = false, want true", p)
		}
	}
	for _, p := range private {
		if isPublicProjectPath(p) {
			t.Errorf("isPublicProjectPath(%q) = true, want false", p)
		}
	}
}

func TestProjectUUIDMiddleware_HeaderAndDefault(t *testing.T) {
	app := fiber.New()
	// nil repo → no auto-create path, just locals population.
	app.Use(ProjectUUIDMiddleware(nil))
	app.Get("/api/echo-project", func(c fiber.Ctx) error {
		return c.SendString(getProjectUUID(c))
	})

	call := func(headerVal string) string {
		req := httptest.NewRequest(http.MethodGet, "/api/echo-project", nil)
		if headerVal != "" {
			req.Header.Set("X-Project-UUID", headerVal)
		}
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		return string(buf[:n])
	}

	if got := call(""); got != database.DefaultProjectUUID {
		t.Errorf("empty header → %q, want default %q", got, database.DefaultProjectUUID)
	}
	if got := call("proj-custom-123"); got != "proj-custom-123" {
		t.Errorf("header value not propagated: %q", got)
	}
}

func TestProjectUUIDMiddleware_AutoCreatesProject(t *testing.T) {
	db, repo := newProjectModelTestDB(t)
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(repo))
	app.Get("/api/touch", func(c fiber.Ctx) error { return c.SendString("ok") })

	const customUUID = "11111111-2222-3333-4444-555555555555"
	req := httptest.NewRequest(http.MethodGet, "/api/touch", nil)
	req.Header.Set("X-Project-UUID", customUUID)
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	_ = resp.Body.Close()

	// The middleware should have lazily created the stub project row.
	p, err := repo.GetProjectByUUID(context.Background(), customUUID)
	if err != nil {
		t.Fatalf("expected auto-created project, got err: %v", err)
	}
	if p.UUID != customUUID {
		t.Errorf("auto-created project UUID = %q, want %q", p.UUID, customUUID)
	}
	if p.OwnerUUID != database.DefaultUserUUID {
		t.Errorf("owner = %q, want default user", p.OwnerUUID)
	}
	_ = db
}

func TestProjectUUIDMiddleware_PublicPathNoAutoCreate(t *testing.T) {
	_, repo := newProjectModelTestDB(t)
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(repo))
	app.Get("/health", func(c fiber.Ctx) error { return c.SendString("ok") })

	const customUUID = "99999999-8888-7777-6666-555555555555"
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Project-UUID", customUUID)
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	_ = resp.Body.Close()

	// Public path must NOT trigger auto-create.
	if _, err := repo.GetProjectByUUID(context.Background(), customUUID); err == nil {
		t.Errorf("public path should not auto-create project %q", customUUID)
	}
}
