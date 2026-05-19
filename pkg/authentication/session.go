package authentication

import (
	"fmt"
	"net/url"
	"strings"
)

// Role identifies how a session is used during scanning.
type Role string

const (
	// RolePrimary drives discovery and spidering — the "owner" of the resources.
	RolePrimary Role = "primary"
	// RoleCompare is replayed during audit phase for cross-session comparison.
	RoleCompare Role = "compare"
)

// ExtractSource specifies where to extract authentication tokens from a login response.
type ExtractSource string

const (
	ExtractCookie ExtractSource = "cookie" // Extract from Set-Cookie header
	ExtractJSON   ExtractSource = "json"   // Extract from JSON response body
	ExtractHeader ExtractSource = "header" // Extract from response header
	ExtractRegex  ExtractSource = "regex"  // Extract from response body via regex
)

// LoginType is a shorthand preset that auto-expands into extract rules.
type LoginType string

const (
	LoginTypeBearer LoginType = "bearer" // JSON body → Authorization: Bearer {value}
	LoginTypeCookie LoginType = "cookie" // Capture all Set-Cookie headers
)

// ExtractRule defines how to extract an auth token from a login response.
type ExtractRule struct {
	Source  ExtractSource `yaml:"source" json:"source"`
	Name    string        `yaml:"name,omitempty" json:"name,omitempty"`         // Cookie name or header name
	Path    string        `yaml:"path,omitempty" json:"path,omitempty"`         // JSONPath for json source
	ApplyAs string        `yaml:"apply_as,omitempty" json:"apply_as,omitempty"` // Header template, e.g. "Authorization: Bearer {value}"
	// Regex extraction fields (source: "regex")
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty"` // Regex pattern with capture group
	Group   int    `yaml:"group,omitempty" json:"group,omitempty"`     // Capture group index (default: 1)
}

// ExpectResponse defines validation rules for a login response.
type ExpectResponse struct {
	Status       []int  `yaml:"status,omitempty" json:"status,omitempty"`               // Acceptable status codes (e.g. [200, 201])
	BodyContains string `yaml:"body_contains,omitempty" json:"body_contains,omitempty"` // Response body must contain this string
}

// LoginStep defines a single step in a multi-step login flow.
type LoginStep struct {
	URL         string          `yaml:"url" json:"url"`
	Method      string          `yaml:"method" json:"method"`
	ContentType string          `yaml:"content_type,omitempty" json:"content_type,omitempty"`
	Body        string          `yaml:"body,omitempty" json:"body,omitempty"`
	Extract     []ExtractRule   `yaml:"extract,omitempty" json:"extract,omitempty"`
	Expect      *ExpectResponse `yaml:"expect,omitempty" json:"expect,omitempty"`
}

// LoginFlow defines how to authenticate to get session credentials.
type LoginFlow struct {
	URL         string        `yaml:"url" json:"url"`
	Method      string        `yaml:"method" json:"method"`
	ContentType string        `yaml:"content_type,omitempty" json:"content_type,omitempty"`
	Body        string        `yaml:"body,omitempty" json:"body,omitempty"`
	Extract     []ExtractRule `yaml:"extract,omitempty" json:"extract,omitempty"`
	// Shorthand: type + token_path expand into extract rules automatically.
	Type      LoginType `yaml:"type,omitempty" json:"type,omitempty"`
	TokenPath string    `yaml:"token_path,omitempty" json:"token_path,omitempty"`
	// Response validation.
	Expect *ExpectResponse `yaml:"expect,omitempty" json:"expect,omitempty"`
	// Multi-step login flows. When set, URL/Method/Body/Extract on the parent are ignored.
	Steps []LoginStep `yaml:"steps,omitempty" json:"steps,omitempty"`
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
		if err := s.Login.Validate(s.Name); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks that a LoginFlow is well-formed.
func (lf *LoginFlow) Validate(sessionName string) error {
	// Multi-step flows: validate each step instead of top-level fields.
	if len(lf.Steps) > 0 {
		for i, step := range lf.Steps {
			if step.URL == "" {
				return fmt.Errorf("session %q: steps[%d].url is required", sessionName, i)
			}
			if step.Method == "" {
				return fmt.Errorf("session %q: steps[%d].method is required", sessionName, i)
			}
		}
		// Last step must have extract rules or the parent must use type shorthand.
		lastStep := lf.Steps[len(lf.Steps)-1]
		if len(lastStep.Extract) == 0 {
			return fmt.Errorf("session %q: last step must have at least one extract rule", sessionName)
		}
		return nil
	}

	// Shorthand type: type + token_path is valid without explicit extract rules.
	if lf.Type != "" {
		switch lf.Type {
		case LoginTypeBearer:
			if lf.TokenPath == "" {
				return fmt.Errorf("session %q: login.token_path is required when type is \"bearer\"", sessionName)
			}
		case LoginTypeCookie:
			// No token_path needed for cookie type.
		default:
			return fmt.Errorf("session %q: unknown login type %q (must be 'bearer' or 'cookie')", sessionName, lf.Type)
		}
		// URL and Method are still required.
		if lf.URL == "" {
			return fmt.Errorf("session %q: login.url is required", sessionName)
		}
		if lf.Method == "" {
			return fmt.Errorf("session %q: login.method is required", sessionName)
		}
		return nil
	}

	// Standard login flow validation.
	if lf.URL == "" {
		return fmt.Errorf("session %q: login.url is required", sessionName)
	}
	if lf.Method == "" {
		return fmt.Errorf("session %q: login.method is required", sessionName)
	}
	if len(lf.Extract) == 0 {
		return fmt.Errorf("session %q: login.extract requires at least one rule (or use type shorthand)", sessionName)
	}
	return nil
}

// NormalizeLoginFlow expands shorthand type/token_path into explicit extract rules
// and validates the URL. Called before execution; safe to call multiple times.
func NormalizeLoginFlow(lf *LoginFlow) {
	if lf == nil {
		return
	}
	// Expand type shorthand into extract rules if no explicit extract rules are set.
	if lf.Type != "" && len(lf.Extract) == 0 {
		switch lf.Type {
		case LoginTypeBearer:
			lf.Extract = expandBearerTokenPath(lf.TokenPath)
		case LoginTypeCookie:
			lf.Extract = []ExtractRule{{
				Source: ExtractCookie,
			}}
		}
	}

	// Auto-detect content type from body if not set.
	if lf.ContentType == "" && lf.Body != "" {
		if strings.HasPrefix(strings.TrimSpace(lf.Body), "{") {
			lf.ContentType = "application/json"
		}
	}
}

// expandBearerTokenPath parses token_path and returns the appropriate extract rule.
// Supported formats:
//   - ".token", ".data.access_token" → extract from JSON body (default)
//   - "header:X-JWT-Token"           → extract from response header
//   - empty                          → defaults to ".token" from JSON body
func expandBearerTokenPath(tokenPath string) []ExtractRule {
	if tokenPath == "" {
		return []ExtractRule{{
			Source:  ExtractJSON,
			Path:    ".token",
			ApplyAs: "Authorization: Bearer {value}",
		}}
	}

	// header:HeaderName → extract from response header.
	if after, ok := strings.CutPrefix(tokenPath, "header:"); ok {
		return []ExtractRule{{
			Source:  ExtractHeader,
			Name:    after,
			ApplyAs: "Authorization: Bearer {value}",
		}}
	}

	// Default: treat as JSON path.
	return []ExtractRule{{
		Source:  ExtractJSON,
		Path:    tokenPath,
		ApplyAs: "Authorization: Bearer {value}",
	}}
}

// ValidateExpect checks if an HTTP response satisfies the expect constraints.
func ValidateExpect(expect *ExpectResponse, statusCode int, body []byte) error {
	if expect == nil {
		return nil
	}
	if len(expect.Status) > 0 {
		found := false
		for _, s := range expect.Status {
			if s == statusCode {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unexpected status %d (expected one of %v)", statusCode, expect.Status)
		}
	}
	if expect.BodyContains != "" {
		if !strings.Contains(string(body), expect.BodyContains) {
			return fmt.Errorf("response body does not contain %q", expect.BodyContains)
		}
	}
	return nil
}

// LoginURL returns the login URL for the session. For multi-step flows, returns
// the URL of the first step.
func (lf *LoginFlow) LoginURL() string {
	if len(lf.Steps) > 0 {
		return lf.Steps[0].URL
	}
	return lf.URL
}

// LintIssue represents a single validation issue found during linting.
type LintIssue struct {
	Field    string // dot-notation path, e.g. "sessions[0].login.url"
	Severity string // "error" or "warning"
	Message  string
}

// LintSessionConfig performs detailed validation of a SessionConfig and returns
// all issues found, rather than stopping at the first error.
func LintSessionConfig(cfg *SessionConfig) []LintIssue {
	var issues []LintIssue

	if len(cfg.Sessions) == 0 {
		issues = append(issues, LintIssue{
			Field:    "sessions",
			Severity: "error",
			Message:  "no sessions defined",
		})
		return issues
	}

	primaryCount := 0
	names := map[string]int{}

	for i := range cfg.Sessions {
		prefix := fmt.Sprintf("sessions[%d]", i)
		s := &cfg.Sessions[i]
		issues = append(issues, lintSession(s, prefix)...)

		if s.Role == RolePrimary {
			primaryCount++
		}
		names[s.Name]++
	}

	if primaryCount == 0 {
		issues = append(issues, LintIssue{
			Field:    "sessions",
			Severity: "warning",
			Message:  "no session has role \"primary\" — first session will be auto-promoted",
		})
	}
	if primaryCount > 1 {
		issues = append(issues, LintIssue{
			Field:    "sessions",
			Severity: "error",
			Message:  fmt.Sprintf("multiple sessions have role \"primary\" (%d found)", primaryCount),
		})
	}
	for name, count := range names {
		if count > 1 {
			issues = append(issues, LintIssue{
				Field:    "sessions",
				Severity: "warning",
				Message:  fmt.Sprintf("duplicate session name %q (%d occurrences)", name, count),
			})
		}
	}

	return issues
}

func lintSession(s *Session, prefix string) []LintIssue {
	var issues []LintIssue

	if s.Name == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".name", Severity: "error",
			Message: "session name is required",
		})
	}

	switch s.Role {
	case RolePrimary, RoleCompare, "":
		// ok
	default:
		issues = append(issues, LintIssue{
			Field: prefix + ".role", Severity: "error",
			Message: fmt.Sprintf("invalid role %q (must be \"primary\" or \"compare\")", s.Role),
		})
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
	if sources == 0 {
		issues = append(issues, LintIssue{
			Field: prefix, Severity: "warning",
			Message: "session has no auth source (no headers, login, or login_request)",
		})
	}
	if sources > 1 {
		issues = append(issues, LintIssue{
			Field: prefix, Severity: "error",
			Message: "specify only one of headers, login, or login_request",
		})
	}

	if hasLogin {
		issues = append(issues, lintLoginFlow(s.Login, prefix+".login")...)
	}

	return issues
}

func lintLoginFlow(lf *LoginFlow, prefix string) []LintIssue {
	var issues []LintIssue

	// Multi-step flows.
	if len(lf.Steps) > 0 {
		if lf.URL != "" || lf.Method != "" {
			issues = append(issues, LintIssue{
				Field: prefix, Severity: "warning",
				Message: "url/method on login are ignored when steps are defined",
			})
		}
		for i, step := range lf.Steps {
			stepPrefix := fmt.Sprintf("%s.steps[%d]", prefix, i)
			issues = append(issues, lintLoginStep(&step, stepPrefix)...)
		}
		lastStep := lf.Steps[len(lf.Steps)-1]
		if len(lastStep.Extract) == 0 {
			issues = append(issues, LintIssue{
				Field: fmt.Sprintf("%s.steps[%d].extract", prefix, len(lf.Steps)-1), Severity: "error",
				Message: "last step must have at least one extract rule",
			})
		}
		return issues
	}

	// Type shorthand.
	if lf.Type != "" {
		switch lf.Type {
		case LoginTypeBearer:
			if lf.TokenPath == "" {
				issues = append(issues, LintIssue{
					Field: prefix + ".token_path", Severity: "error",
					Message: "token_path is required when type is \"bearer\" (e.g. \".token\" for JSON body, \"header:X-JWT-Token\" for response header)",
				})
			} else if after, ok := strings.CutPrefix(lf.TokenPath, "header:"); ok && strings.TrimSpace(after) == "" {
				issues = append(issues, LintIssue{
					Field: prefix + ".token_path", Severity: "error",
					Message: "header name is empty in token_path \"header:\" — expected \"header:HeaderName\"",
				})
			}
		case LoginTypeCookie:
			if lf.TokenPath != "" {
				issues = append(issues, LintIssue{
					Field: prefix + ".token_path", Severity: "warning",
					Message: "token_path is ignored when type is \"cookie\"",
				})
			}
		default:
			issues = append(issues, LintIssue{
				Field: prefix + ".type", Severity: "error",
				Message: fmt.Sprintf("unknown login type %q (must be \"bearer\" or \"cookie\")", lf.Type),
			})
		}
		if len(lf.Extract) > 0 {
			issues = append(issues, LintIssue{
				Field: prefix + ".extract", Severity: "warning",
				Message: "extract rules are ignored when type shorthand is used",
			})
		}
	}

	// URL validation.
	if lf.URL == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".url", Severity: "error",
			Message: "login URL is required",
		})
	} else {
		if u, err := url.Parse(lf.URL); err != nil {
			issues = append(issues, LintIssue{
				Field: prefix + ".url", Severity: "error",
				Message: fmt.Sprintf("invalid URL: %v", err),
			})
		} else if u.Scheme != "http" && u.Scheme != "https" {
			issues = append(issues, LintIssue{
				Field: prefix + ".url", Severity: "error",
				Message: fmt.Sprintf("URL scheme must be http or https, got %q", u.Scheme),
			})
		}
	}

	if lf.Method == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".method", Severity: "error",
			Message: "login method is required",
		})
	}

	// Extract rules validation (only required when no type shorthand).
	if lf.Type == "" && len(lf.Extract) == 0 {
		issues = append(issues, LintIssue{
			Field: prefix + ".extract", Severity: "error",
			Message: "at least one extract rule is required (or use type shorthand)",
		})
	}

	for i, rule := range lf.Extract {
		rulePrefix := fmt.Sprintf("%s.extract[%d]", prefix, i)
		issues = append(issues, lintExtractRule(&rule, rulePrefix)...)
	}

	// Expect validation.
	if lf.Expect != nil {
		issues = append(issues, lintExpect(lf.Expect, prefix+".expect")...)
	}

	return issues
}

func lintLoginStep(step *LoginStep, prefix string) []LintIssue {
	var issues []LintIssue

	if step.URL == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".url", Severity: "error",
			Message: "step URL is required",
		})
	}
	if step.Method == "" {
		issues = append(issues, LintIssue{
			Field: prefix + ".method", Severity: "error",
			Message: "step method is required",
		})
	}
	for i, rule := range step.Extract {
		rulePrefix := fmt.Sprintf("%s.extract[%d]", prefix, i)
		issues = append(issues, lintExtractRule(&rule, rulePrefix)...)
	}
	if step.Expect != nil {
		issues = append(issues, lintExpect(step.Expect, prefix+".expect")...)
	}
	return issues
}

func lintExtractRule(rule *ExtractRule, prefix string) []LintIssue {
	var issues []LintIssue

	switch rule.Source {
	case ExtractCookie:
		// Name is optional (empty = all cookies).
	case ExtractJSON:
		if rule.Path == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".path", Severity: "error",
				Message: "path is required for json extraction",
			})
		}
		if rule.ApplyAs == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".apply_as", Severity: "error",
				Message: "apply_as is required for json extraction",
			})
		}
	case ExtractHeader:
		if rule.Name == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".name", Severity: "error",
				Message: "name is required for header extraction",
			})
		}
	case ExtractRegex:
		if rule.Pattern == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".pattern", Severity: "error",
				Message: "pattern is required for regex extraction",
			})
		}
		if rule.ApplyAs == "" {
			issues = append(issues, LintIssue{
				Field: prefix + ".apply_as", Severity: "error",
				Message: "apply_as is required for regex extraction",
			})
		}
	case "":
		issues = append(issues, LintIssue{
			Field: prefix + ".source", Severity: "error",
			Message: "extract source is required (cookie, json, header, or regex)",
		})
	default:
		issues = append(issues, LintIssue{
			Field: prefix + ".source", Severity: "error",
			Message: fmt.Sprintf("unknown extract source %q (must be cookie, json, header, or regex)", rule.Source),
		})
	}

	// Validate apply_as format if present.
	if rule.ApplyAs != "" && !strings.Contains(rule.ApplyAs, ":") {
		issues = append(issues, LintIssue{
			Field: prefix + ".apply_as", Severity: "error",
			Message: fmt.Sprintf("apply_as must be in \"HeaderName: value\" format, got %q", rule.ApplyAs),
		})
	}

	return issues
}

func lintExpect(expect *ExpectResponse, prefix string) []LintIssue {
	var issues []LintIssue
	if len(expect.Status) == 0 && expect.BodyContains == "" {
		issues = append(issues, LintIssue{
			Field: prefix, Severity: "warning",
			Message: "expect block is empty (no status codes or body_contains)",
		})
	}
	for i, code := range expect.Status {
		if code < 100 || code > 599 {
			issues = append(issues, LintIssue{
				Field:    fmt.Sprintf("%s.status[%d]", prefix, i),
				Severity: "error",
				Message:  fmt.Sprintf("invalid HTTP status code %d", code),
			})
		}
	}
	return issues
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
