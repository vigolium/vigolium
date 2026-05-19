package authentication

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Manager loads, validates, and hydrates sessions for multi-session scanning.
type Manager struct {
	sessions   []*Session
	primary    *Session
	sessionDir string // resolved directory for session file lookup
}

// ManagerOption configures optional Manager behavior.
type ManagerOption func(*Manager)

// WithSessionDir overrides the default directory used to resolve session file names.
func WithSessionDir(dir string) ManagerOption {
	return func(m *Manager) {
		m.sessionDir = dir
	}
}

// NewManager creates a Manager from the resolved session list.
func NewManager(sessions []*Session, opts ...ManagerOption) (*Manager, error) {
	if len(sessions) == 0 {
		return nil, fmt.Errorf("at least one session is required")
	}

	// Validate all sessions
	for _, s := range sessions {
		if err := s.Validate(); err != nil {
			return nil, err
		}
	}

	// Auto-assign roles if not set
	hasPrimary := false
	for _, s := range sessions {
		if s.Role == RolePrimary {
			hasPrimary = true
			break
		}
	}
	if !hasPrimary {
		sessions[0].Role = RolePrimary
	}

	m := &Manager{sessions: sessions}
	for _, o := range opts {
		o(m)
	}
	for _, s := range sessions {
		if s.Role == RolePrimary {
			m.primary = s
			break
		}
	}

	return m, nil
}

// HydrateSessions executes login flows for sessions that need them.
func (m *Manager) HydrateSessions() error {
	for _, s := range m.sessions {
		if s.Login != nil && !s.IsHydrated() {
			zap.L().Info("Executing login flow", zap.String("session", s.Name), zap.String("url", s.Login.URL))
			if err := executeLogin(s); err != nil {
				return err
			}
			zap.L().Info("Login successful", zap.String("session", s.Name))
		}
	}
	return nil
}

// Primary returns the primary session.
func (m *Manager) Primary() *Session {
	return m.primary
}

// CompareSessions returns all non-primary sessions used for comparison.
func (m *Manager) CompareSessions() []*Session {
	var result []*Session
	for _, s := range m.sessions {
		if s.Role != RolePrimary {
			result = append(result, s)
		}
	}
	return result
}

// AllSessions returns all sessions.
func (m *Manager) AllSessions() []*Session {
	return m.sessions
}

// PrimaryHeaders returns the primary session's headers as a slice for types.Options.Headers.
func (m *Manager) PrimaryHeaders() []string {
	if m.primary == nil {
		return nil
	}
	return m.primary.HeaderSlice()
}

// LoadFromAuthFiles loads sessions from one or more --auth-file values. Each
// value is either a file path (YAML/JSON, single session or sessions: bundle)
// or a bare name resolved against sessionDir (default ~/.vigolium/sessions/),
// trying .yaml, .yml, .json in order. Files support ${ENV} expansion before
// parsing.
func LoadFromAuthFiles(paths []string, sessionDir string) ([]*Session, error) {
	var sessions []*Session
	for _, p := range paths {
		resolved := resolveSessionPath(p, sessionDir)
		data, err := os.ReadFile(resolved)
		if err != nil {
			return nil, fmt.Errorf("failed to read auth file %s: %w", resolved, err)
		}
		content := os.ExpandEnv(string(data))
		loaded, err := parseSessionContent(resolved, content)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, loaded...)
	}
	return sessions, nil
}

// LoadFromAuthInline parses --auth values in "name:Header:value" format.
func LoadFromAuthInline(values []string) ([]*Session, error) {
	var sessions []*Session
	for _, v := range values {
		s, err := ParseInlineSession(v)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

// parseSessionContent parses YAML or JSON content as either a sessions: bundle
// (SessionConfig) or a single top-level Session.
func parseSessionContent(path string, content string) ([]*Session, error) {
	asJSON := isJSON(path, content)

	// Try bundle (sessions: ...) first.
	var cfg SessionConfig
	var bundleErr error
	if asJSON {
		bundleErr = json.Unmarshal([]byte(content), &cfg)
	} else {
		bundleErr = yaml.Unmarshal([]byte(content), &cfg)
	}
	if bundleErr == nil && len(cfg.Sessions) > 0 {
		result := make([]*Session, len(cfg.Sessions))
		for i := range cfg.Sessions {
			result[i] = &cfg.Sessions[i]
		}
		return result, nil
	}

	// Fall back to single session at top level.
	var s Session
	var singleErr error
	if asJSON {
		singleErr = json.Unmarshal([]byte(content), &s)
	} else {
		singleErr = yaml.Unmarshal([]byte(content), &s)
	}
	if singleErr != nil {
		return nil, fmt.Errorf("failed to parse auth file %s: %w", path, singleErr)
	}
	if s.Name == "" {
		return nil, fmt.Errorf("auth file %s: no sessions defined", path)
	}
	return []*Session{&s}, nil
}

// resolveSessionPath resolves a session file path.
// If the path has no directory component, looks in sessionDir (falling back
// to ~/.vigolium/sessions/ when sessionDir is empty).
func resolveSessionPath(path string, sessionDir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	// If path has a directory separator, treat as relative
	if strings.Contains(path, string(filepath.Separator)) || strings.Contains(path, "/") {
		return path
	}
	// If the path already has a known extension, use it as-is for lookup
	hasExt := strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".json")

	// Use configured session dir or default to ~/.vigolium/sessions/
	dir := sessionDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			if !hasExt {
				return path + ".yaml"
			}
			return path
		}
		dir = filepath.Join(home, ".vigolium", "sessions")
	}
	// Expand ~ prefix in configured dir
	if strings.HasPrefix(dir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			if !hasExt {
				return path + ".yaml"
			}
			return path
		}
		dir = filepath.Join(home, dir[2:])
	}

	if hasExt {
		candidate := filepath.Join(dir, path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		return path
	}

	// Try extensions in order: .yaml, .yml, .json
	for _, ext := range []string{".yaml", ".yml", ".json"} {
		candidate := filepath.Join(dir, path+ext)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return path + ".yaml"
}

// isJSON returns true if the file should be parsed as JSON.
// Checks file extension first, then falls back to content sniffing.
func isJSON(path string, content string) bool {
	if strings.HasSuffix(path, ".json") {
		return true
	}
	trimmed := strings.TrimSpace(content)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}
