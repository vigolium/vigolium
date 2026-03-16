package database

import (
	"encoding/json"

	"github.com/vigolium/vigolium/pkg/session"
)

// SessionHostnameToSession converts a DB SessionHostname row to a native session.Session.
func SessionHostnameToSession(sh *SessionHostname) *session.Session {
	if sh == nil {
		return nil
	}

	s := &session.Session{
		Name:    sh.SessionName,
		Role:    session.Role(sh.SessionRole),
		Headers: sh.Headers,
	}

	// Map flat login fields to LoginFlow if login_url is set.
	if sh.LoginURL != "" {
		lf := &session.LoginFlow{
			URL:         sh.LoginURL,
			Method:      sh.LoginMethod,
			ContentType: sh.LoginContentType,
			Body:        sh.LoginBody,
		}
		// Unmarshal extract rules JSON into typed slice.
		if sh.ExtractRules != "" {
			var rules []session.ExtractRule
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

// SessionHostnamesToSessionConfig converts a slice of DB rows (typically for one hostname)
// into a session.SessionConfig with ordered sessions.
func SessionHostnamesToSessionConfig(rows []*SessionHostname) *session.SessionConfig {
	if len(rows) == 0 {
		return nil
	}
	cfg := &session.SessionConfig{
		Sessions: make([]session.Session, 0, len(rows)),
	}
	for _, sh := range rows {
		s := SessionHostnameToSession(sh)
		if s != nil {
			cfg.Sessions = append(cfg.Sessions, *s)
		}
	}
	return cfg
}

// SessionToSessionHostname converts a native session.Session to a DB SessionHostname row.
// The caller must set ProjectUUID, Hostname, and optionally ScanUUID on the returned row.
func SessionToSessionHostname(s *session.Session, position int) *SessionHostname {
	if s == nil {
		return nil
	}

	sh := &SessionHostname{
		SessionName: s.Name,
		SessionRole: string(s.Role),
		Position:    position,
		Headers:     s.Headers,
		Source:      "cli",
	}

	if s.Login != nil {
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

// SessionsToSessionHostnames converts a slice of session.Session objects to DB rows
// for a given hostname. Sets ProjectUUID and Hostname on each row.
func SessionsToSessionHostnames(sessions []*session.Session, projectUUID, hostname string) []*SessionHostname {
	if len(sessions) == 0 {
		return nil
	}

	rows := make([]*SessionHostname, 0, len(sessions))
	for i, s := range sessions {
		sh := SessionToSessionHostname(s, i)
		if sh == nil {
			continue
		}
		sh.ProjectUUID = projectUUID
		sh.Hostname = hostname
		rows = append(rows, sh)
	}
	return rows
}
