package session

import (
	"fmt"
	"strings"
)

// Role identifies how a session is used during scanning.
type Role string

const (
	// RolePrimary drives discovery and spidering — the "owner" of the resources.
	RolePrimary Role = "primary"
	// RoleCompare is replayed during dynamic assessment for cross-session comparison.
	RoleCompare Role = "compare"
)

// ExtractSource specifies where to extract authentication tokens from a login response.
type ExtractSource string

const (
	ExtractCookie ExtractSource = "cookie" // Extract from Set-Cookie header
	ExtractJSON   ExtractSource = "json"   // Extract from JSON response body
	ExtractHeader ExtractSource = "header" // Extract from response header
)

// ExtractRule defines how to extract an auth token from a login response.
type ExtractRule struct {
	Source  ExtractSource `yaml:"source" json:"source"`
	Name   string        `yaml:"name,omitempty" json:"name,omitempty"`       // Cookie name or header name
	Path   string        `yaml:"path,omitempty" json:"path,omitempty"`       // JSONPath for json source
	ApplyAs string       `yaml:"apply_as,omitempty" json:"apply_as,omitempty"` // Header template, e.g. "Authorization: Bearer {value}"
}

// LoginFlow defines how to authenticate to get session credentials.
type LoginFlow struct {
	URL         string        `yaml:"url" json:"url"`
	Method      string        `yaml:"method" json:"method"`
	ContentType string        `yaml:"content_type,omitempty" json:"content_type,omitempty"`
	Body        string        `yaml:"body,omitempty" json:"body,omitempty"`
	Extract     []ExtractRule `yaml:"extract" json:"extract"`
}

// Session represents a named authentication identity used during scanning.
type Session struct {
	Name    string            `yaml:"name" json:"name"`
	Role    Role              `yaml:"role" json:"role"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Login   *LoginFlow        `yaml:"login,omitempty" json:"login,omitempty"`
	// LoginRequest is a raw HTTP request string for the login flow.
	LoginRequest string `yaml:"login_request,omitempty" json:"login_request,omitempty"`

	// hydrated indicates whether the login flow has been executed.
	hydrated bool
}

// SessionConfig holds multiple sessions, used for --auth-config files (YAML or JSON).
type SessionConfig struct {
	Sessions []Session `yaml:"sessions" json:"sessions"`
}

// Validate checks that the session definition is well-formed.
func (s *Session) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("session name is required")
	}
	switch s.Role {
	case RolePrimary, RoleCompare, "":
		// valid
	default:
		return fmt.Errorf("session %q: invalid role %q (must be 'primary' or 'compare')", s.Name, s.Role)
	}
	hasStatic := len(s.Headers) > 0
	hasLogin := s.Login != nil
	hasRawLogin := s.LoginRequest != ""
	sources := 0
	if hasStatic {
		sources++
	}
	if hasLogin {
		sources++
	}
	if hasRawLogin {
		sources++
	}
	if sources > 1 {
		return fmt.Errorf("session %q: specify only one of headers, login, or login_request", s.Name)
	}
	if hasLogin {
		if s.Login.URL == "" {
			return fmt.Errorf("session %q: login.url is required", s.Name)
		}
		if s.Login.Method == "" {
			return fmt.Errorf("session %q: login.method is required", s.Name)
		}
		if len(s.Login.Extract) == 0 {
			return fmt.Errorf("session %q: login.extract requires at least one rule", s.Name)
		}
	}
	return nil
}

// IsHydrated returns true if the session has been populated with credentials.
func (s *Session) IsHydrated() bool {
	return s.hydrated || len(s.Headers) > 0
}

// HeaderSlice converts the session headers map to a slice of "Name: Value" strings,
// compatible with types.Options.Headers.
func (s *Session) HeaderSlice() []string {
	if len(s.Headers) == 0 {
		return nil
	}
	result := make([]string, 0, len(s.Headers))
	for k, v := range s.Headers {
		result = append(result, k+": "+v)
	}
	return result
}

// ParseInlineSession parses a CLI --session flag value in "name:Header:value" format.
// Example: "admin:Cookie:session=abc" → Session{Name:"admin", Headers:{"Cookie":"session=abc"}}
func ParseInlineSession(s string) (*Session, error) {
	// Format: name:HeaderName:HeaderValue
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid --session format %q: expected name:Header:value (e.g. admin:Cookie:session=abc)", s)
	}
	name := strings.TrimSpace(parts[0])
	headerName := strings.TrimSpace(parts[1])
	headerValue := strings.TrimSpace(parts[2])
	if name == "" || headerName == "" {
		return nil, fmt.Errorf("invalid --session format %q: name and header name cannot be empty", s)
	}
	return &Session{
		Name: name,
		Role: RoleCompare, // default; first session auto-promoted to primary by manager
		Headers: map[string]string{
			headerName: headerValue,
		},
	}, nil
}
