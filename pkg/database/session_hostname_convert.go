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
