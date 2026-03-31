package backend

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"go.uber.org/zap"
)

// ValidateSessionConfig validates each session entry, attempts to sanitize
// fixable issues (like double-escaped JSON bodies), and drops entries that
// are beyond repair. Returns nil if no valid sessions remain.
func ValidateSessionConfig(cfg *agenttypes.AgentSessionConfig) *agenttypes.AgentSessionConfig {
	if cfg == nil || len(cfg.Sessions) == 0 {
		return cfg
	}

	var valid []agenttypes.AgentSessionEntry
	for i := range cfg.Sessions {
		entry := cfg.Sessions[i]

		// Try to sanitize fixable issues before validation
		SanitizeSessionEntry(&entry)

		if errs := ValidateSessionEntry(entry); len(errs) > 0 {
			zap.L().Warn("Dropping invalid session config entry",
				zap.String("name", entry.Name),
				zap.String("role", entry.Role),
				zap.Strings("errors", errs))
			continue
		}
		valid = append(valid, entry)
	}

	if len(valid) == 0 {
		zap.L().Warn("All session config entries failed validation",
			zap.Int("dropped", len(cfg.Sessions)))
		return nil
	}

	if len(valid) < len(cfg.Sessions) {
		zap.L().Info("Session config validation filtered entries",
			zap.Int("valid", len(valid)),
			zap.Int("dropped", len(cfg.Sessions)-len(valid)))
	}

	return &agenttypes.AgentSessionConfig{Sessions: valid}
}

// SessionValidationResult holds the outcome of session config validation,
// separating valid entries from invalid ones that may be repaired.
type SessionValidationResult struct {
	Valid   []agenttypes.AgentSessionEntry
	Invalid []InvalidSessionEntry
}

// InvalidSessionEntry pairs a dropped session entry with its validation errors.
type InvalidSessionEntry struct {
	Entry  agenttypes.AgentSessionEntry
	Errors []string
}

// ValidateSessionConfigDetailed validates each session entry and returns both
// valid and invalid entries. This enables partial repair of invalid entries
// while preserving entries that already pass validation.
func ValidateSessionConfigDetailed(cfg *agenttypes.AgentSessionConfig) SessionValidationResult {
	var result SessionValidationResult
	if cfg == nil || len(cfg.Sessions) == 0 {
		return result
	}
	for i := range cfg.Sessions {
		entry := cfg.Sessions[i]
		SanitizeSessionEntry(&entry)
		if errs := ValidateSessionEntry(entry); len(errs) > 0 {
			zap.L().Warn("Invalid session config entry",
				zap.String("name", entry.Name),
				zap.String("role", entry.Role),
				zap.Strings("errors", errs))
			result.Invalid = append(result.Invalid, InvalidSessionEntry{Entry: entry, Errors: errs})
		} else {
			result.Valid = append(result.Valid, entry)
		}
	}
	return result
}

// SanitizeSessionEntry attempts to fix common LLM output issues in-place.
func SanitizeSessionEntry(entry *agenttypes.AgentSessionEntry) {
	// Fix empty role — if this is the first session, assume primary
	// (caller can re-check after sanitization)
	entry.Role = strings.TrimSpace(entry.Role)

	if entry.Login != nil {
		sanitizeLoginFlow(entry.Login)
	}
}

// sanitizeLoginFlow fixes common LLM garbling in login flow fields.
func sanitizeLoginFlow(login *agenttypes.AgentLoginFlow) {
	// Fix double-escaped JSON bodies: \\\" → \"  and then \" → "
	// LLMs frequently double-escape when producing JSON strings inside JSON.
	// The typical garbled pattern is: {\\\"email\\\":\\\"val\\\"}
	// which should become: {"email":"val"}
	if login.Body != "" && strings.Contains(login.Body, `\\\"`) {
		// Step 1: \\\" → \"
		unescaped := strings.ReplaceAll(login.Body, `\\\"`, `\"`)
		// Step 2: \" → " (unescape the remaining escaped quotes)
		unescaped = strings.ReplaceAll(unescaped, `\"`, `"`)
		// Verify the fully unescaped version is valid JSON
		if json.Valid([]byte(unescaped)) {
			login.Body = unescaped
		}
	} else if login.Body != "" && strings.Contains(login.Body, `\"`) && !json.Valid([]byte(login.Body)) {
		// Single-escaped: \" → "
		unescaped := strings.ReplaceAll(login.Body, `\"`, `"`)
		if json.Valid([]byte(unescaped)) {
			login.Body = unescaped
		}
	}

	// Fix content_type that has URL path leaked into it:
	// e.g. "application/rest/user/login" should be "application/json"
	if login.ContentType != "" {
		ct := strings.ToLower(login.ContentType)
		if strings.HasPrefix(ct, "application/") && !IsValidContentType(ct) {
			// If body looks like JSON, fix to application/json
			if LooksLikeJSON(login.Body) {
				login.ContentType = "application/json"
			}
		}
	}

	// If body looks like JSON but content_type is empty, set it
	if login.ContentType == "" && LooksLikeJSON(login.Body) {
		login.ContentType = "application/json"
	}

	// Fix URL that's missing path — if the URL is just host:port with no path
	// and the content_type/body suggest a login endpoint, we can't auto-fix
	// the path, but we ensure the URL is well-formed.
	login.URL = strings.TrimSpace(login.URL)
}

// ValidateSessionEntry checks a single session entry for common corruption patterns.
// Returns a list of validation errors (empty if valid).
func ValidateSessionEntry(entry agenttypes.AgentSessionEntry) []string {
	var errs []string

	// Role must be exactly "primary" or "compare"
	if entry.Role != "primary" && entry.Role != "compare" {
		errs = append(errs, "role must be \"primary\" or \"compare\", got: "+TruncateForLog(entry.Role, 60))
	}

	// Name should be non-empty and reasonable
	if strings.TrimSpace(entry.Name) == "" {
		errs = append(errs, "empty session name")
	}

	// Must have either login or headers
	if entry.Login == nil && len(entry.Headers) == 0 {
		errs = append(errs, "session has neither login flow nor static headers")
	}

	// Validate login flow if present
	if entry.Login != nil {
		errs = append(errs, ValidateLoginFlow(entry.Login)...)
	}

	return errs
}

// ValidateLoginFlow checks a login flow for garbled or invalid fields.
func ValidateLoginFlow(login *agenttypes.AgentLoginFlow) []string {
	var errs []string

	// URL must be a valid URL with a host and a path (just host:port is too vague)
	if login.URL == "" {
		errs = append(errs, "login URL is empty")
	} else {
		u, err := url.Parse(login.URL)
		if err != nil {
			errs = append(errs, "login URL is not parseable: "+TruncateForLog(login.URL, 80))
		} else if u.Host == "" {
			errs = append(errs, "login URL has no host: "+TruncateForLog(login.URL, 80))
		} else if u.Scheme != "http" && u.Scheme != "https" {
			errs = append(errs, "login URL has invalid scheme: "+TruncateForLog(login.URL, 80))
		} else if u.Path == "" || u.Path == "/" {
			errs = append(errs, "login URL has no path (likely truncated): "+TruncateForLog(login.URL, 80))
		}
	}

	// Method must be a known HTTP method
	method := strings.ToUpper(login.Method)
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		// ok
	case "":
		errs = append(errs, "login method is empty")
	default:
		errs = append(errs, "login method is invalid: "+TruncateForLog(login.Method, 30))
	}

	// Content-type must be a valid MIME type if present
	if login.ContentType != "" && !IsValidContentType(strings.ToLower(login.ContentType)) {
		errs = append(errs, "login content_type is garbled: "+TruncateForLog(login.ContentType, 60))
	}

	// If content_type indicates JSON, body must be valid JSON
	if login.Body != "" && strings.Contains(strings.ToLower(login.ContentType), "json") {
		if !json.Valid([]byte(login.Body)) {
			errs = append(errs, "login body is not valid JSON: "+TruncateForLog(login.Body, 80))
		}
	}

	// Extract rules are required unless type shorthand is used.
	if len(login.Extract) == 0 && login.Type == "" {
		errs = append(errs, "login flow has no extract rules (or use type shorthand)")
	}

	// Check for garbled body: JSON keys/values that look corrupted
	if login.Body != "" && LooksLikeJSON(login.Body) {
		if bodyErrs := validateJSONBodyIntegrity(login.Body); len(bodyErrs) > 0 {
			errs = append(errs, bodyErrs...)
		}
	}

	return errs
}

// IsValidContentType checks if a content type string is a reasonable MIME type.
// It catches garbled types like "application/rest/user/login".
func IsValidContentType(ct string) bool {
	// Strip any parameters (e.g., "application/json; charset=utf-8" → "application/json")
	if idx := strings.Index(ct, ";"); idx > 0 {
		ct = strings.TrimSpace(ct[:idx])
	}

	// A valid MIME type has exactly type/subtype — no additional slashes.
	// Garbled content types have URL paths leaked in: "application/rest/user/login"
	parts := strings.SplitN(ct, "/", 2)
	if len(parts) != 2 {
		return false
	}
	// More than one slash in the subtype means a URL path leaked in
	if strings.Contains(parts[1], "/") {
		return false
	}
	return true
}

// LooksLikeJSON returns true if the string looks like it could be a JSON object or array.
func LooksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	return (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) ||
		(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"))
}

// validateJSONBodyIntegrity checks for corruption patterns in a JSON body string.
// Even if the body is technically valid JSON, the values inside may be garbled
// (e.g., field names merged with values).
func validateJSONBodyIntegrity(body string) []string {
	var errs []string

	// Try to parse as a JSON object
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		// Already caught by json.Valid check
		return nil
	}

	for key := range obj {
		// Check for garbled field names: keys that contain @ or look like
		// partial email addresses merged with field names.
		// e.g., "email@juice" instead of "email"
		if strings.Contains(key, "@") && !isLikelyEmailFieldName(key) {
			errs = append(errs, "login body has garbled field name: "+TruncateForLog(key, 40))
		}

	}

	return errs
}

// isLikelyEmailFieldName returns true if the key name is a legitimate field
// that might contain @, vs a garbled merge of field name and email value.
func isLikelyEmailFieldName(key string) bool {
	// Legitimate field names: "email", "user_email", "login_email", etc.
	// Garbled: "email@juice" (email value leaked into field name)
	atIdx := strings.Index(key, "@")
	if atIdx < 0 {
		return true
	}
	// If the part before @ is a common field name prefix, it's garbled
	prefix := strings.ToLower(key[:atIdx])
	garbledPrefixes := []string{"email", "user", "username", "login", "mail", "account"}
	for _, gp := range garbledPrefixes {
		if prefix == gp {
			return false // field name merged with email value
		}
	}
	return true
}

// TruncateForLog truncates a string for log output, adding ellipsis if truncated.
func TruncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

