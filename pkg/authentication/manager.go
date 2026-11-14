package authentication

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DefaultLoginBudget bounds the time ALL login flows together may take. It is a
// total, not a per-request timeout (each request keeps its own 30s): a scan
// configured with six sessions, each a three-step flow, could otherwise spend
// nine minutes in setup before sending a single scan request, with no output and
// no way to tell a slow login from a hung one. Two minutes is many times what a
// working login needs and short enough that a wedged one is a visible delay
// rather than an apparent hang.
const DefaultLoginBudget = 2 * time.Minute

// Manager loads, validates, and hydrates sessions for multi-session scanning.
type Manager struct {
	sessions   []*Session
	primary    *Session
	sessionDir string // resolved directory for session file lookup
	// loginTransport is the RoundTripper login requests go out over. nil means
	// http.DefaultTransport — which honours neither --proxy nor a self-signed
	// target cert, so a scan that wants either must install one (see
	// pkg/http.LoginTransport, the single owner of that policy).
	loginTransport http.RoundTripper
	// loginBudget caps the total hydration time across every session and step.
	// <= 0 means DefaultLoginBudget.
	loginBudget time.Duration
	// flowMu guards the login flows rehydrate copies and writes back (a
	// rotated OAuth2 refresh_token).
	flowMu sync.Mutex

	// loginResults are the logins HydrateSessionsContext ran (LoginResults).
	loginMu      sync.Mutex
	loginResults []LoginResult
}

// ManagerOption configures optional Manager behavior.
type ManagerOption func(*Manager)

// WithSessionDir overrides the default directory used to resolve session file names.
func WithSessionDir(dir string) ManagerOption {
	return func(m *Manager) {
		m.sessionDir = dir
	}
}

// WithLoginTransport routes login requests over rt. A login request targets the
// host the scan is about to attack, so it belongs on the same proxy and the same
// permissive TLS stance as the rest of the scan's traffic; pkg/http.LoginTransport
// builds exactly that. A nil rt is ignored (Go's default transport stands).
func WithLoginTransport(rt http.RoundTripper) ManagerOption {
	return func(m *Manager) {
		if rt != nil {
			m.loginTransport = rt
		}
	}
}

// WithLoginBudget overrides the total time all login flows together may take.
// A non-positive value keeps DefaultLoginBudget.
func WithLoginBudget(d time.Duration) ManagerOption {
	return func(m *Manager) {
		if d > 0 {
			m.loginBudget = d
		}
	}
}

// NewManager creates a Manager from the resolved session list.
func NewManager(sessions []*Session, opts ...ManagerOption) (*Manager, error) {
	if len(sessions) == 0 {
		return nil, fmt.Errorf("at least one session is required")
	}

	// Validate all sessions, then give each login_request-only session the
	// LoginFlow HydrateSessions runs.
	for _, s := range sessions {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		if err := s.convertLoginRequest(); err != nil {
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

	m := &Manager{sessions: sessions, loginBudget: DefaultLoginBudget}
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

// HydrateSessions executes login flows for sessions that need them on a
// background context. It is the convenience wrapper for callers with no context
// of their own; anything inside a scan should call HydrateSessionsContext so a
// cancelled scan stops logging in.
func (m *Manager) HydrateSessions() error {
	return m.HydrateSessionsContext(context.Background())
}

// HydrateSessionsContext executes login flows for sessions that need them,
// bounded by ctx AND by the manager's total login budget (whichever expires
// first). The budget wraps the WHOLE loop rather than each session, so N
// sessions cannot cost N × the budget; a flow that runs out mid-way reports
// which session it died on.
//
// A cancelled or expired ctx is reported before the first request, so a
// cancelled scan does not start a login it is about to abandon.
func (m *Manager) HydrateSessionsContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	budget := m.loginBudget
	if budget <= 0 {
		budget = DefaultLoginBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	client := m.loginClient()
	for _, s := range m.sessions {
		if s.Login == nil || s.IsHydrated() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("session %q: login not attempted: %w", s.Name, err)
		}
		zap.L().Info("Executing login flow", zap.String("session", s.Name), zap.String("url", s.Login.URL))
		// CheckLogin is the scan's login (executeLogin) plus the verdict on
		// whether the response proves it worked, which the runner reports.
		res := CheckLogin(ctx, s, client)
		m.recordLogin(res)
		if !res.OK {
			return res.Err
		}
		if res.Verified {
			zap.L().Info("Login successful", zap.String("session", s.Name))
		} else {
			zap.L().Warn("Login ran but could not be verified", zap.String("session", s.Name), zap.String("detail", res.Message))
		}
	}
	return nil
}

// rehydrate runs the named session's login flow again and returns the fresh
// credential headers, for a scan whose session expired mid-run (LiveSession),
// and when they expire (zero when the login did not say).
//
// It is safe to call from several goroutines and while the scan reads the
// sessions: the flow runs on a CLONE of the session with an empty header map,
// so the shared Session (and its Headers map, which the manager handed out at
// setup) is never mutated. The login goes out over the manager's login
// transport, so it follows the scan's proxy, TLS stance and egress gate (the
// priority lane under GatedLoginTransport), bounded by ctx and by the
// manager's login budget. An OAuth2 refresh token the server rotated is
// written back to the managed session's flow, so the next re-login presents
// the new one.
func (m *Manager) rehydrate(ctx context.Context, name string) (map[string]string, time.Time, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var src *Session
	for _, s := range m.sessions {
		if s.Name == name {
			src = s
			break
		}
	}
	if src == nil {
		return nil, time.Time{}, fmt.Errorf("session %q: not managed", name)
	}
	if src.Login == nil {
		return nil, time.Time{}, fmt.Errorf("session %q: no login flow to re-run (static headers cannot be refreshed)", name)
	}
	budget := m.loginBudget
	if budget <= 0 {
		budget = DefaultLoginBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	m.flowMu.Lock()
	clone := *src
	flow := *src.Login // runLogin normalizes the flow in place: give it its own copy
	m.flowMu.Unlock()
	usedRefresh := flow.RefreshToken
	clone.Login = &flow
	clone.Headers = make(map[string]string)
	clone.hydrated = false
	clone.expiresAt = time.Time{}
	if err := executeLogin(ctx, &clone, m.loginClient()); err != nil {
		return nil, time.Time{}, err
	}
	if flow.RefreshToken != usedRefresh {
		m.flowMu.Lock()
		if src.Login.RefreshToken == usedRefresh {
			src.Login.RefreshToken = flow.RefreshToken
		}
		m.flowMu.Unlock()
	}
	return clone.Headers, clone.expiresAt, nil
}

// probeClient is the client a LiveSession's logged-in probe uses: the login
// transport (proxy, target TLS, the egress gate's priority lane) with
// redirects NOT followed, so a 302 to the login page is seen as such.
func (m *Manager) probeClient() *http.Client {
	c := m.loginClient()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// LoginBudget is the total time one hydration (or one re-login) may take.
func (m *Manager) LoginBudget() time.Duration {
	if m == nil || m.loginBudget <= 0 {
		return DefaultLoginBudget
	}
	return m.loginBudget
}

// loginClient builds the HTTP client the login flows share: the manager's
// transport (proxy + target TLS policy), redirects followed so a login that
// lands its Set-Cookie on a 302 still works, and a per-request timeout that
// keeps one unanswered request from eating the whole budget.
//
// The cookie jar is per-flow, not shared here: executeLogin and
// executeMultiStepLogin each need their own jar to read the cookies their own
// login earned, and sharing one across sessions would let one session's cookies
// satisfy another's extract rule.
func (m *Manager) loginClient() *http.Client {
	return &http.Client{
		Timeout:   loginRequestTimeout,
		Transport: m.loginTransport,
	}
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
// value is either a file path (YAML/JSON: a sessions: bundle, a single session,
// or an agent session-config.json) or a bare name resolved against sessionDir
// (default ~/.vigolium/sessions/), trying .yaml, .yml, .json in order. Files
// support ${ENV} expansion before parsing.
//
// An unknown field is logged as a warning, not refused: a file that loaded
// before the parser learned to notice extra keys keeps loading. `auth lint`
// reports the same field as an error, with its line.
func LoadFromAuthFiles(paths []string, sessionDir string) ([]*Session, error) {
	var sessions []*Session
	for _, p := range paths {
		resolved := resolveSessionPath(p, sessionDir)
		data, err := os.ReadFile(resolved)
		if err != nil {
			return nil, fmt.Errorf("failed to read auth file %s: %w", resolved, err)
		}
		loaded, issues, err := ParseSessionBytes(data, resolved, ParseOptions{})
		if err != nil {
			return nil, fmt.Errorf("auth file: %w", err)
		}
		for _, is := range issues {
			zap.L().Warn("Auth file has an unknown field (ignored); run `vigolium auth lint` to check it",
				zap.String("file", resolved), zap.String("field", is.Field),
				zap.Int("line", is.Line), zap.String("issue", is.Message))
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

// ResolveSessionPath resolves an --auth-file value the way LoadFromAuthFiles
// does: a path is used as is, a bare name is looked up in sessionDir (default
// ~/.vigolium/sessions/) with .yaml, .yml and .json tried in order.
func ResolveSessionPath(path, sessionDir string) string {
	return resolveSessionPath(path, sessionDir)
}

// recordLogin keeps a login's result for LoginResults.
func (m *Manager) recordLogin(res LoginResult) {
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	m.loginResults = append(m.loginResults, res)
}

// LoginResults returns the result of every login HydrateSessionsContext ran,
// in order: whether each succeeded and whether its response proved it.
func (m *Manager) LoginResults() []LoginResult {
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	return append([]LoginResult(nil), m.loginResults...)
}
