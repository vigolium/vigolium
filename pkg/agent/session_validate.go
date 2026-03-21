package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// ValidateSessionConfig validates each session entry, attempts to sanitize
// fixable issues (like double-escaped JSON bodies), and drops entries that
// are beyond repair. Returns nil if no valid sessions remain.
func ValidateSessionConfig(cfg *AgentSessionConfig) *AgentSessionConfig {
	if cfg == nil || len(cfg.Sessions) == 0 {
		return cfg
	}

	var valid []AgentSessionEntry
	for i := range cfg.Sessions {
		entry := cfg.Sessions[i]

		// Try to sanitize fixable issues before validation
		sanitizeSessionEntry(&entry)

		if errs := validateSessionEntry(entry); len(errs) > 0 {
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

	return &AgentSessionConfig{Sessions: valid}
}

// sanitizeSessionEntry attempts to fix common LLM output issues in-place.
func sanitizeSessionEntry(entry *AgentSessionEntry) {
	// Fix empty role — if this is the first session, assume primary
	// (caller can re-check after sanitization)
	entry.Role = strings.TrimSpace(entry.Role)

	if entry.Login != nil {
		sanitizeLoginFlow(entry.Login)
	}
}

// sanitizeLoginFlow fixes common LLM garbling in login flow fields.
func sanitizeLoginFlow(login *AgentLoginFlow) {
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
		if strings.HasPrefix(ct, "application/") && !isValidContentType(ct) {
			// If body looks like JSON, fix to application/json
			if looksLikeJSON(login.Body) {
				login.ContentType = "application/json"
			}
		}
	}

	// If body looks like JSON but content_type is empty, set it
	if login.ContentType == "" && looksLikeJSON(login.Body) {
		login.ContentType = "application/json"
	}

	// Fix URL that's missing path — if the URL is just host:port with no path
	// and the content_type/body suggest a login endpoint, we can't auto-fix
	// the path, but we ensure the URL is well-formed.
	login.URL = strings.TrimSpace(login.URL)
}

// validateSessionEntry checks a single session entry for common corruption patterns.
// Returns a list of validation errors (empty if valid).
func validateSessionEntry(entry AgentSessionEntry) []string {
	var errs []string

	// Role must be exactly "primary" or "compare"
	if entry.Role != "primary" && entry.Role != "compare" {
		errs = append(errs, "role must be \"primary\" or \"compare\", got: "+truncateForLog(entry.Role, 60))
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
		errs = append(errs, validateLoginFlow(entry.Login)...)
	}

	return errs
}

// validateLoginFlow checks a login flow for garbled or invalid fields.
func validateLoginFlow(login *AgentLoginFlow) []string {
	var errs []string

	// URL must be a valid URL with a host and a path (just host:port is too vague)
	if login.URL == "" {
		errs = append(errs, "login URL is empty")
	} else {
		u, err := url.Parse(login.URL)
		if err != nil {
			errs = append(errs, "login URL is not parseable: "+truncateForLog(login.URL, 80))
		} else if u.Host == "" {
			errs = append(errs, "login URL has no host: "+truncateForLog(login.URL, 80))
		} else if u.Scheme != "http" && u.Scheme != "https" {
			errs = append(errs, "login URL has invalid scheme: "+truncateForLog(login.URL, 80))
		} else if u.Path == "" || u.Path == "/" {
			errs = append(errs, "login URL has no path (likely truncated): "+truncateForLog(login.URL, 80))
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
		errs = append(errs, "login method is invalid: "+truncateForLog(login.Method, 30))
	}

	// Content-type must be a valid MIME type if present
	if login.ContentType != "" && !isValidContentType(strings.ToLower(login.ContentType)) {
		errs = append(errs, "login content_type is garbled: "+truncateForLog(login.ContentType, 60))
	}

	// If content_type indicates JSON, body must be valid JSON
	if login.Body != "" && strings.Contains(strings.ToLower(login.ContentType), "json") {
		if !json.Valid([]byte(login.Body)) {
			errs = append(errs, "login body is not valid JSON: "+truncateForLog(login.Body, 80))
		}
	}

	// Extract rules are required for login-based sessions — the downstream
	// session.Validate() will reject sessions with login but no extract rules.
	if len(login.Extract) == 0 {
		errs = append(errs, "login flow has no extract rules")
	}

	// Check for garbled body: JSON keys/values that look corrupted
	if login.Body != "" && looksLikeJSON(login.Body) {
		if bodyErrs := validateJSONBodyIntegrity(login.Body); len(bodyErrs) > 0 {
			errs = append(errs, bodyErrs...)
		}
	}

	return errs
}

// isValidContentType checks if a content type string is a reasonable MIME type.
// It catches garbled types like "application/rest/user/login".
func isValidContentType(ct string) bool {
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

// looksLikeJSON returns true if the string looks like it could be a JSON object or array.
func looksLikeJSON(s string) bool {
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

	for key, val := range obj {
		// Check for garbled field names: keys that contain @ or look like
		// partial email addresses merged with field names.
		// e.g., "email@juice" instead of "email"
		if strings.Contains(key, "@") && !isLikelyEmailFieldName(key) {
			errs = append(errs, "login body has garbled field name: "+truncateForLog(key, 40))
		}

		// Check for values that look like they have field names merged in
		if strVal, ok := val.(string); ok {
			// Value that starts with a common field name suggests garbled merge:
			// e.g., "jim-sh.op" where the domain was mangled
			// We can't be too aggressive here; just flag obviously garbled patterns
			_ = strVal
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

// truncateForLog truncates a string for log output, adding ellipsis if truncated.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// RepairInvalidSessionConfig sends a garbled session config to the LLM agent
// for repair. Unlike RepairSessionConfigWithLLM (which fixes JSON syntax from raw output),
// this function fixes semantic issues: garbled roles, truncated URLs, corrupted content
// types, and malformed body fields. Returns nil if repair fails.
func RepairInvalidSessionConfig(ctx context.Context, engine *Engine, original *AgentSessionConfig, targetURL string, cfg repairConfig) *AgentSessionConfig {
	if engine == nil || original == nil || len(original.Sessions) == 0 {
		return nil
	}

	// Marshal the garbled config for the prompt
	garbledJSON, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		return nil
	}

	// Collect validation errors for each entry
	var errorLines []string
	for _, entry := range original.Sessions {
		if errs := validateSessionEntry(entry); len(errs) > 0 {
			errorLines = append(errorLines, fmt.Sprintf("  Session %q: %s", entry.Name, strings.Join(errs, "; ")))
		}
	}

	prompt := buildSessionRepairPrompt(string(garbledJSON), errorLines, targetURL)

	zap.L().Info("Attempting LLM repair for garbled session config",
		zap.Int("entries", len(original.Sessions)),
		zap.Int("errors", len(errorLines)))

	result, runErr := engine.Run(ctx, Options{
		AgentName:    cfg.AgentName,
		AgentACPCmd:  cfg.AgentACPCmd,
		PromptInline: prompt,
		ShowPrompt:   cfg.ShowPrompt,
		SessionKey:   "session-config-repair",
	})
	if runErr != nil {
		zap.L().Warn("LLM session config repair failed", zap.Error(runErr))
		return nil
	}

	// Extract JSON from the response
	repaired := parseRepairedSessionConfig(result.RawOutput)
	if repaired == nil {
		zap.L().Warn("Could not parse repaired session config from LLM output")
		return nil
	}

	// Sanitize + validate the repaired config too
	for i := range repaired.Sessions {
		sanitizeSessionEntry(&repaired.Sessions[i])
	}
	repaired = ValidateSessionConfig(repaired)
	if repaired == nil {
		zap.L().Warn("LLM-repaired session config still has invalid entries")
		return nil
	}

	zap.L().Info("LLM successfully repaired session config",
		zap.Int("sessions", len(repaired.Sessions)))
	return repaired
}

// buildSessionRepairPrompt constructs the prompt for session config repair.
func buildSessionRepairPrompt(garbledJSON string, errorLines []string, targetURL string) string {
	var sb strings.Builder
	sb.WriteString("The following session config JSON was generated by a source analysis agent but contains errors.\n")
	sb.WriteString("Fix the session config and return ONLY the corrected JSON in a single ```json fenced code block.\n")
	sb.WriteString("Do NOT add explanations outside the code block.\n\n")

	sb.WriteString("## Rules\n\n")
	sb.WriteString("- Each session must have `role` set to exactly `\"primary\"` or `\"compare\"`\n")
	sb.WriteString("- The highest-privilege account should be `\"primary\"`, others `\"compare\"`\n")
	sb.WriteString("- Login URLs must include the full path (e.g., `" + targetURL + "/rest/user/login`), not just host:port\n")
	sb.WriteString("- `content_type` must be a valid MIME type (e.g., `application/json`), not a URL path\n")
	sb.WriteString("- `body` must be valid JSON when `content_type` is `application/json`\n")
	sb.WriteString("- Body field names must be correct (e.g., `email` not `email@juice`)\n")
	sb.WriteString("- Use real credentials found in the garbled data — do not invent new ones\n")
	sb.WriteString("- If a field is garbled beyond recognition, omit that session entirely\n\n")

	if len(errorLines) > 0 {
		sb.WriteString("## Validation Errors\n\n")
		for _, line := range errorLines {
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	if targetURL != "" {
		sb.WriteString("## Target\n\n")
		sb.WriteString("Target URL: " + targetURL + "\n\n")
	}

	sb.WriteString("## Garbled Session Config\n\n")
	sb.WriteString("```json\n")
	sb.WriteString(garbledJSON)
	sb.WriteString("\n```\n")

	return sb.String()
}

// parseRepairedSessionConfig extracts an AgentSessionConfig from the LLM repair output.
func parseRepairedSessionConfig(raw string) *AgentSessionConfig {
	// Look for ```json fenced block first
	if jsonStr, err := extractJSONFromFencedBlock(raw); err == nil && jsonStr != "" {
		var cfg AgentSessionConfig
		if err := json.Unmarshal([]byte(jsonStr), &cfg); err == nil && len(cfg.Sessions) > 0 {
			return &cfg
		}
	}

	// Fallback: try to find any JSON object with "sessions" in it
	if idx := strings.Index(raw, `"sessions"`); idx >= 0 {
		// Walk backward to find opening {
		for i := idx - 1; i >= 0; i-- {
			if raw[i] == '{' {
				// Find matching closing }
				depth := 0
				for j := i; j < len(raw); j++ {
					if raw[j] == '{' {
						depth++
					} else if raw[j] == '}' {
						depth--
						if depth == 0 {
							var cfg AgentSessionConfig
							if err := json.Unmarshal([]byte(raw[i:j+1]), &cfg); err == nil && len(cfg.Sessions) > 0 {
								return &cfg
							}
							break
						}
					}
				}
				break
			}
		}
	}

	return nil
}
