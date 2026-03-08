package server

import (
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

const projectUUIDLocalsKey = "project_uuid"

// ProjectUUIDMiddleware extracts the project UUID from the X-Project-UUID
// request header and stores it in Fiber locals. Falls back to DefaultProjectUUID.
func ProjectUUIDMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		projectUUID := c.Get("X-Project-UUID")
		if projectUUID == "" {
			projectUUID = database.DefaultProjectUUID
		}
		c.Locals(projectUUIDLocalsKey, projectUUID)
		return c.Next()
	}
}

// getProjectUUID retrieves the project UUID from Fiber context locals.
func getProjectUUID(c fiber.Ctx) string {
	if v, ok := c.Locals(projectUUIDLocalsKey).(string); ok && v != "" {
		return v
	}
	return database.DefaultProjectUUID
}

// BearerAuth returns fiber middleware that validates Bearer tokens.
// Skips authentication for public endpoints: /, /health, /swagger/*.
func BearerAuth(validKeys []string) fiber.Handler {
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

		if !slices.Contains(validKeys, token) {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: ErrInvalidAuthToken.Error(),
				Code:  fiber.StatusUnauthorized,
			})
		}

		return c.Next()
	}
}

// DebugRequestMiddleware logs the raw request body, URL/query parameters,
// and headers for every incoming request when --debug is enabled.
func DebugRequestMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		fields := []zap.Field{
			zap.String("method", c.Method()),
			zap.String("path", c.Path()),
		}

		// Query parameters
		if raw := string(c.Request().URI().QueryString()); raw != "" {
			fields = append(fields, zap.String("query", raw))
		}

		// Headers
		hdrs := make(map[string]string)
		for k, v := range c.GetReqHeaders() {
			// Mask Authorization value to avoid leaking tokens
			if strings.EqualFold(k, "Authorization") {
				hdrs[k] = "[REDACTED]"
			} else {
				hdrs[k] = strings.Join(v, ", ")
			}
		}
		fields = append(fields, zap.Any("headers", hdrs))

		// Raw body (for POST/PUT/PATCH)
		if body := c.Body(); len(body) > 0 {
			fields = append(fields, zap.ByteString("body", body))
		}

		zap.L().Debug("Incoming request", fields...)

		return c.Next()
	}
}

const defaultBodyLimit = 4 << 20 // 4 MB — default for non-upload routes

// DefaultBodyLimitMiddleware rejects request bodies larger than defaultBodyLimit
// for all routes except those explicitly exempt (e.g. file upload endpoints).
// The Fiber-level BodyLimit is set high to accommodate uploads; this middleware
// enforces the tighter limit everywhere else.
func DefaultBodyLimitMiddleware(exemptPaths ...string) fiber.Handler {
	return func(c fiber.Ctx) error {
		path := c.Path()
		for _, p := range exemptPaths {
			if path == p {
				return c.Next()
			}
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
