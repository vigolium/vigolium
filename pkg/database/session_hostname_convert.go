package database

import (
	"encoding/json"
	"strings"

	"github.com/vigolium/vigolium/pkg/authentication"
)

// extractPrimaryToken extracts the primary session token value from a headers map.
// It checks Authorization (Bearer/token) first, then Cookie, then falls back to
// the first header value. Returns empty string if no headers.
func ExtractPrimaryToken(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}

	// Prefer Authorization header — strip "Bearer " / "Token " prefix.
	for k, v := range headers {
		lower := strings.ToLower(k)
		if lower == "authorization" {
			v = strings.TrimSpace(v)
			for _, prefix := range []string{"Bearer ", "bearer ", "Token ", "token "} {
				if strings.HasPrefix(v, prefix) {
					return strings.TrimPrefix(v, prefix)
				}
			}
			return v
		}
	}

	// Fall back to Cookie header value.
	for k, v := range headers {
		if strings.ToLower(k) == "cookie" {
			return v
		}
	}

	// Last resort: first header value.
	for _, v := range headers {
		return v
	}
	return ""
}

// AuthenticationHostnameToSession converts a DB AuthenticationHostname row to a native authentication.Session.
//
// Note: the DB schema does not carry the type/token_path shorthand fields —
// only the expanded ExtractRules. SessionToAuthenticationHostname normalizes
// shorthand into explicit rules on write so they round-trip correctly.
func AuthenticationHostnameToSession(sh *AuthenticationHostname) *authentication.Session {
	if sh == nil {
		return nil
	}

	s := &authentication.Session{
		Name:    sh.SessionName,
		Role:    authentication.Role(sh.SessionRole),
		Headers: sh.Headers,
	}

	// Map flat login fields to LoginFlow if login_url is set.
	if sh.LoginURL != "" {
		lf := &authentication.LoginFlow{
			URL:         sh.LoginURL,
			Method:      sh.LoginMethod,
			ContentType: sh.LoginContentType,
			Body:        sh.LoginBody,
		}
		// Unmarshal extract rules JSON into typed slice.
		if sh.ExtractRules != "" {
			var rules []authentication.ExtractRule
			if err := json.Unmarshal([]byte(sh.ExtractRules), &rules); err == nil {
				lf.Extract = rules
			}
		}
		s.Login = lf
	}

	// Map raw login request if present.
	if sh.LoginRequest != "" {
		s.LoginRequest = sh.LoginRequest
	}

	return s
}

// AuthenticationHostnamesToSessionConfig converts a slice of DB rows (typically for one hostname)
// into a authentication.SessionConfig with ordered sessions.
func AuthenticationHostnamesToSessionConfig(rows []*AuthenticationHostname) *authentication.SessionConfig {
	if len(rows) == 0 {
		return nil
	}
	cfg := &authentication.SessionConfig{
		Sessions: make([]authentication.Session, 0, len(rows)),
	}
	for _, sh := range rows {
		s := AuthenticationHostnameToSession(sh)
		if s != nil {
			cfg.Sessions = append(cfg.Sessions, *s)
		}
	}
	return cfg
}

// SessionToAuthenticationHostname converts a native authentication.Session to a DB AuthenticationHostname row.
// The caller must set ProjectUUID, Hostname, and optionally ScanUUID on the returned row.
func SessionToAuthenticationHostname(s *authentication.Session, position int) *AuthenticationHostname {
	if s == nil {
		return nil
	}

	sh := &AuthenticationHostname{
		SessionName:  s.Name,
		SessionRole:  string(s.Role),
		Position:     position,
		SessionToken: ExtractPrimaryToken(s.Headers),
		Headers:      s.Headers,
		Source:       "cli",
	}

	if s.Login != nil {
		// Expand the type/token_path shorthand into explicit Extract rules
		// before serializing — the DB schema has no columns for those
		// shorthand fields (see AuthenticationHostname in models.go), so a
		// shorthand-only LoginFlow would round-trip with zero extract rules
		// and silently fail to hydrate. NormalizeLoginFlow is a no-op when
		// Extract is already populated.
		authentication.NormalizeLoginFlow(s.Login)

		sh.LoginURL = s.Login.URL
		sh.LoginMethod = s.Login.Method
		sh.LoginContentType = s.Login.ContentType
		sh.LoginBody = s.Login.Body

		if len(s.Login.Extract) > 0 {
			if data, err := json.Marshal(s.Login.Extract); err == nil {
				sh.ExtractRules = string(data)
			}
		}
	}

	if s.LoginRequest != "" {
		sh.LoginRequest = s.LoginRequest
	}

	return sh
}

// SessionsToAuthenticationHostnames converts a slice of authentication.Session objects to DB rows
// for a given hostname. Sets ProjectUUID and Hostname on each row.
func SessionsToAuthenticationHostnames(sessions []*authentication.Session, projectUUID, hostname string) []*AuthenticationHostname {
	if len(sessions) == 0 {
		return nil
	}

	rows := make([]*AuthenticationHostname, 0, len(sessions))
	for i, s := range sessions {
		sh := SessionToAuthenticationHostname(s, i)
		if sh == nil {
			continue
		}
		sh.ProjectUUID = projectUUID
		sh.Hostname = hostname
		rows = append(rows, sh)
	}
	return rows
}
