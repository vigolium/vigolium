package server

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

const projectUUIDLocalsKey = "project_uuid"

// ProjectUUIDMiddleware extracts the project UUID from the X-Project-UUID
// request header and stores it in Fiber locals. Falls back to DefaultProjectUUID
// when the header is empty.
//
// When repo is non-nil and the supplied UUID does not exist in the database,
// the middleware lazily creates a stub project row so callers (including UIs
// after a scanner DB reset) can keep working with the UUID stored client-side.
// Auto-creation is skipped for public/utility endpoints and for the default
// project UUID, which is seeded separately.
func ProjectUUIDMiddleware(repo *database.Repository) fiber.Handler {
	return func(c fiber.Ctx) error {
		projectUUID := c.Get("X-Project-UUID")
		if projectUUID == "" {
			projectUUID = database.DefaultProjectUUID
		}
		c.Locals(projectUUIDLocalsKey, projectUUID)

		if repo != nil && projectUUID != database.DefaultProjectUUID && !isPublicProjectPath(c.Path()) {
			ensureProjectExists(c, repo, projectUUID)
		}

		return c.Next()
	}
}

// isPublicProjectPath returns true for endpoints that should never trigger
// project auto-creation (health checks, swagger, static UI, etc.).
func isPublicProjectPath(path string) bool {
	if path == "/" || path == "/health" || path == "/server-info" || path == "/metrics" {
		return true
	}
	return strings.HasPrefix(path, "/swagger")
}

// ensureProjectExists looks up the project by UUID and inserts a stub row if
// it is missing. Errors are logged but never block the request — the next
// middleware/handler will surface a downstream error if the row truly
// can't be reached.
func ensureProjectExists(c fiber.Ctx, repo *database.Repository, projectUUID string) {
	if _, err := repo.GetProjectByUUID(c.Context(), projectUUID); err == nil {
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		// Real DB error — log and bail out without trying to write.
		zap.L().Debug("project lookup failed; skipping auto-create",
			zap.String("project_uuid", projectUUID),
			zap.Error(err))
		return
	}

	name := "auto-" + projectUUID
	if len(projectUUID) >= 8 {
		name = "auto-" + projectUUID[:8]
	}
	now := time.Now().UTC()
	stub := &database.Project{
		UUID:        projectUUID,
		Name:        name,
		Description: "Auto-created on first use",
		OwnerUUID:   database.DefaultUserUUID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := repo.CreateProject(c.Context(), stub); err != nil {
		// Likely a race with a concurrent insert — verify the row landed.
		if _, getErr := repo.GetProjectByUUID(c.Context(), projectUUID); getErr == nil {
			return
		}
		zap.L().Warn("failed to auto-create project",
			zap.String("project_uuid", projectUUID),
			zap.Error(err))
		return
	}
	zap.L().Info("auto-created project on first use",
		zap.String("project_uuid", projectUUID),
		zap.String("name", name))
}

// getProjectUUID retrieves the project UUID from Fiber context locals.
func getProjectUUID(c fiber.Ctx) string {
	if v, ok := c.Locals(projectUUIDLocalsKey).(string); ok && v != "" {
		return v
	}
	return database.DefaultProjectUUID
}

const authUserLocalsKey = "auth_user"

// BearerAuth returns fiber middleware that validates Bearer tokens and resolves user identity.
// Checks the UserStore first (file-based users), then falls back to legacy API keys (admin role).
// Skips authentication for public endpoints: /, /health, /swagger/*, /metrics.
func BearerAuth(validKeys []string, store *UserStore) fiber.Handler {
	return func(c fiber.Ctx) error {
		path := c.Path()
		// Skip auth for public endpoints
		if path == "/" || path == "/health" || path == "/metrics" || strings.HasPrefix(path, "/swagger") {
			return c.Next()
		}

		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: ErrMissingAuthHeader.Error(),
				Code:  fiber.StatusUnauthorized,
			})
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader || token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: ErrInvalidAuthToken.Error(),
				Code:  fiber.StatusUnauthorized,
			})
		}

		// 1. Try file-based user store first
		if user := store.Lookup(token); user != nil {
			c.Locals(authUserLocalsKey, user)
			return c.Next()
		}

		// 2. Fall back to legacy API key → admin
		if slices.Contains(validKeys, token) {
			c.Locals(authUserLocalsKey, &ResolvedUser{
				UUID: database.DefaultUserUUID,
				Name: "vigolium-admin",
				Role: RoleAdmin,
			})
			return c.Next()
		}

		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: ErrInvalidAuthToken.Error(),
			Code:  fiber.StatusUnauthorized,
		})
	}
}

// getAuthUser retrieves the resolved user from Fiber context locals.
func getAuthUser(c fiber.Ctx) *ResolvedUser {
	if v, ok := c.Locals(authUserLocalsKey).(*ResolvedUser); ok {
		return v
	}
	return nil
}

// RoleGuard returns middleware that rejects requests from users whose role
// is not in the allowed set. Must be applied after BearerAuth.
// When no auth user is present (--no-auth mode), requests are allowed through.
func RoleGuard(allowed ...string) fiber.Handler {
	set := make(map[string]bool, len(allowed))
	for _, r := range allowed {
		set[r] = true
	}
	return func(c fiber.Ctx) error {
		user := getAuthUser(c)
		if user == nil {
			// No user means auth was skipped (--no-auth) → allow
			return c.Next()
		}
		if !set[user.Role] {
			return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
				Error: ErrForbidden.Error(),
				Code:  fiber.StatusForbidden,
			})
		}
		return c.Next()
	}
}

// DebugRequestMiddleware logs the raw request body, URL/query parameters,
// and headers for every incoming request when --debug is enabled.
//
// Sensitive headers and BYOK body fields are scrubbed before the line is
// emitted — see redact.go for the precise lists. JSON-shaped bodies are
// parsed and re-serialized; non-JSON or malformed bodies are summarized
// rather than logged verbatim so a binary upload doesn't tank the log.
func DebugRequestMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		fields := []zap.Field{
			zap.String("method", c.Method()),
			zap.String("path", c.Path()),
		}

		// Query parameters — scoped scrubbing isn't worth it here because
		// the same secret field names aren't passed as query strings on any
		// agent endpoint. If that changes, extend redact.go to also walk a
		// url.Values map.
		if raw := string(c.Request().URI().QueryString()); raw != "" {
			fields = append(fields, zap.String("query", raw))
		}

		// Headers
		fields = append(fields, zap.Any("headers", redactSensitiveHeaders(c.GetReqHeaders())))

		// Body (for POST/PUT/PATCH)
		if body := c.Body(); len(body) > 0 {
			if scrubbed := redactJSONBody(body); len(scrubbed) > 0 {
				fields = append(fields, zap.ByteString("body", scrubbed))
			}
		}

		zap.L().Debug("Incoming request", fields...)

		return c.Next()
	}
}

const defaultBodyLimit = 4 << 20 // 4 MB — default for non-upload routes

// bodyLimitExemptPaths are routes that accept large uploads (archive bundles,
// source-code tarballs) and must skip the 4 MB cap. The matching is exact —
// every entry covers a single POST endpoint.
var bodyLimitExemptPaths = map[string]bool{
	"/api/import":                true,
	"/api/storage/upload-source": true,
}

// DefaultBodyLimitMiddleware rejects request bodies larger than defaultBodyLimit
// for routes that aren't in bodyLimitExemptPaths.
func DefaultBodyLimitMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		if bodyLimitExemptPaths[c.Path()] {
			return c.Next()
		}
		if len(c.Body()) > defaultBodyLimit {
			return c.Status(fiber.StatusRequestEntityTooLarge).JSON(ErrorResponse{
				Error: "request body exceeds 4 MB limit",
			})
		}
		return c.Next()
	}
}

// SecurityHeadersMiddleware adds security headers to all responses.
func SecurityHeadersMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "1; mode=block")
		return c.Next()
	}
}
