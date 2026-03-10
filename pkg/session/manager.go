package session

import (
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

// LoadFromConfig loads sessions from an auth-config YAML file.
func LoadFromConfig(path string) ([]*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth config %s: %w", path, err)
	}

	// Expand environment variables
	content := os.ExpandEnv(string(data))

	var cfg SessionConfig
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse auth config %s: %w", path, err)
	}

	if len(cfg.Sessions) == 0 {
		return nil, fmt.Errorf("auth config %s: no sessions defined", path)
	}

	result := make([]*Session, len(cfg.Sessions))
	for i := range cfg.Sessions {
		result[i] = &cfg.Sessions[i]
	}
	return result, nil
}

// LoadFromSessionFiles loads sessions from individual YAML files.
// An optional sessionDir overrides the default ~/.vigolium/sessions/ lookup directory.
func LoadFromSessionFiles(paths []string, sessionDir string) ([]*Session, error) {
	var sessions []*Session
	for _, p := range paths {
		// Resolve from sessionDir (or ~/.vigolium/sessions/) if not absolute
		resolved := resolveSessionPath(p, sessionDir)
		data, err := os.ReadFile(resolved)
		if err != nil {
			return nil, fmt.Errorf("failed to read session file %s: %w", resolved, err)
		}
		content := os.ExpandEnv(string(data))
		var s Session
		if err := yaml.Unmarshal([]byte(content), &s); err != nil {
			return nil, fmt.Errorf("failed to parse session file %s: %w", resolved, err)
		}
		sessions = append(sessions, &s)
	}
	return sessions, nil
}

// LoadFromInlineFlags parses --session flag values into sessions.
func LoadFromInlineFlags(flags []string) ([]*Session, error) {
	var sessions []*Session
	for _, f := range flags {
		s, err := ParseInlineSession(f)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
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
	// Add .yaml extension if missing
	if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
		path += ".yaml"
	}
	// Use configured session dir or default to ~/.vigolium/sessions/
	dir := sessionDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		dir = filepath.Join(home, ".vigolium", "sessions")
	}
	// Expand ~ prefix in configured dir
	if strings.HasPrefix(dir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		dir = filepath.Join(home, dir[2:])
	}
	candidate := filepath.Join(dir, path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return path
}
