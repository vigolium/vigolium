package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/session"
	"github.com/vigolium/vigolium/pkg/terminal"
	"gopkg.in/yaml.v3"
)

var (
	sessionLoadHost        string
	sessionLoadNoValidate  bool
	sessionLoadSource      string
	sessionLoadAgentFormat bool
	sessionLoadName        string
)

var sessionLoadCmd = &cobra.Command{
	Use:   "load [session-file]",
	Short: "Load session auth configs from a file or stdin into the database",
	Long: `Load session authentication configurations from a YAML/JSON file or stdin and
persist them to the session_hostnames database table. Supports both native session
config format (used by --auth-config) and agent session-config.json format (produced
by agent source analysis).

Also supports raw HTTP login requests — the command will send the request,
auto-discover tokens from the response (JSON body, Set-Cookie, auth headers),
and persist the session with auto-generated extract rules.

The --host flag is optional when session configs contain login URLs — the hostname
is derived automatically from the first login URL.

Agent format is auto-detected when the file path contains "agent-sessions/" or
can be forced with --agent-format.

Login flows are validated by default — the command sends each login request to
verify that the credentials work. Use --no-validate to skip.

Examples:
  vigolium session load auth-config.yaml --host example.com
  vigolium session load ~/.vigolium/agent-sessions/agt-xxx/session-config.json
  vigolium session load sessions.json --no-validate
  cat session-config.json | vigolium session load
  cat login-req.txt | vigolium session load
  cat login-req.txt | vigolium session load --name admin --host juice-shop.example.com`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSessionLoad,
}

func init() {
	sessionCmd.AddCommand(sessionLoadCmd)
	sessionLoadCmd.Flags().StringVar(&sessionLoadHost, "host", "", "Hostname to associate sessions with (derived from login URL if omitted)")
	sessionLoadCmd.Flags().BoolVar(&sessionLoadNoValidate, "no-validate", false, "Skip executing login flows for validation")
	sessionLoadCmd.Flags().StringVar(&sessionLoadSource, "source", "cli", "Source label for the session rows")
	sessionLoadCmd.Flags().BoolVar(&sessionLoadAgentFormat, "agent-format", false, "Force parsing as agent session-config.json format")
	sessionLoadCmd.Flags().StringVar(&sessionLoadName, "name", "", "Session name (used with raw HTTP request input)")
}

func runSessionLoad(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Read input.
	var data []byte
	var err error

	if len(args) == 0 || args[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		if len(data) == 0 {
			return fmt.Errorf("no input provided on stdin")
		}
	} else {
		data, err = os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", args[0], err)
		}
	}

	// Check if this is a raw HTTP request — auto-discover path.
	if session.IsRawHTTPRequest(data) {
		return runSessionLoadRawRequest(data)
	}

	// Otherwise, parse as session config (native/agent format).
	var sessions []*session.Session

	if len(args) > 0 && args[0] != "-" {
		if sessionLoadAgentFormat || isAgentSessionFile(args[0]) {
			sessions, err = parseAgentSessionBytes(data)
		} else {
			sessions, err = loadSessionsFromFile(args[0])
		}
	} else {
		sessions, err = loadSessionsFromBytes(data)
	}
	if err != nil {
		return fmt.Errorf("failed to load session config: %w", err)
	}

	if len(sessions) == 0 {
		return fmt.Errorf("no sessions found in input")
	}

	// Derive --host from login URLs if not provided.
	if sessionLoadHost == "" {
		sessionLoadHost = deriveHostFromSessions(sessions)
	}
	if sessionLoadHost == "" {
		return fmt.Errorf("--host is required when session configs have no login URLs")
	}

	// Validate login flows unless --no-validate.
	if !sessionLoadNoValidate {
		fmt.Printf("%s Validating login flows...\n\n", terminal.InfoSymbol())
		for _, sess := range sessions {
			if sess.Login == nil {
				fmt.Printf("  %s  %s  %s\n", terminal.Cyan("–"), sess.Name, "static headers")
				continue
			}
			statusCode, probeErr := session.ProbeLogin(sess)
			if probeErr != nil {
				fmt.Printf("  %s  %s  error: %s\n", terminal.Red("✗"), sess.Name, probeErr)
			} else if statusCode >= 200 && statusCode < 400 {
				extra := ""
				if len(sess.Headers) > 0 {
					// Show extracted header names.
					names := make([]string, 0, len(sess.Headers))
					for k := range sess.Headers {
						names = append(names, k)
					}
					extra = fmt.Sprintf("  extracted=[%s]", strings.Join(names, ", "))
				}
				fmt.Printf("  %s  %s  status=%s%s\n",
					terminal.Green("✓"), sess.Name,
					terminal.Green(fmt.Sprintf("%d", statusCode)), extra)
			} else {
				fmt.Printf("  %s  %s  status=%s  (unexpected)\n",
					terminal.Red("✗"), sess.Name,
					terminal.Red(fmt.Sprintf("%d", statusCode)))
			}
		}
		fmt.Println()
	}

	return persistSessions(sessions)
}

// runSessionLoadRawRequest handles raw HTTP request auto-discovery.
func runSessionLoadRawRequest(data []byte) error {
	loginReq, err := session.ParseRawLoginRequest(string(data))
	if err != nil {
		return fmt.Errorf("failed to parse raw HTTP request: %w", err)
	}

	fmt.Printf("%s Sending login request: %s %s\n\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan(loginReq.Method),
		terminal.Cyan(loginReq.URL))

	result, err := session.DiscoverLogin(loginReq)
	if err != nil {
		if result != nil {
			fmt.Printf("  %s  status=%s  %s\n\n",
				terminal.Red("✗"),
				terminal.Red(fmt.Sprintf("%d", result.StatusCode)),
				err)
		}
		return fmt.Errorf("auto-discovery failed: %w", err)
	}

	// Print discovered tokens.
	fmt.Printf("  %s  status=%s\n",
		terminal.Green("✓"),
		terminal.Green(fmt.Sprintf("%d", result.StatusCode)))

	for _, src := range result.TokenSources {
		fmt.Printf("  %s  %s\n", terminal.Cyan("→"), src)
	}
	fmt.Println()

	sess := result.Session

	// Apply --name override.
	if sessionLoadName != "" {
		sess.Name = sessionLoadName
	}

	// Derive --host from the login URL.
	if sessionLoadHost == "" {
		u, urlErr := url.Parse(loginReq.URL)
		if urlErr == nil && u.Host != "" {
			sessionLoadHost = u.Host
		}
	}
	if sessionLoadHost == "" {
		return fmt.Errorf("--host is required")
	}

	// Show summary of what was discovered.
	fmt.Printf("%s Discovered session %s for %s\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan(sess.Name),
		terminal.Cyan(sessionLoadHost))

	if len(sess.Headers) > 0 {
		for k, v := range sess.Headers {
			display := v
			if len(display) > 60 {
				display = display[:57] + "..."
			}
			fmt.Printf("  %s %s: %s\n", terminal.Gray("→"), terminal.Cyan(k), terminal.Gray(display))
		}
	}
	fmt.Println()

	return persistSessionsWithResponse([]*session.Session{sess}, result.RawResponse)
}

// persistSessionsWithResponse is like persistSessions but also stores a login response.
func persistSessionsWithResponse(sessions []*session.Session, loginResponse string) error {
	if sessionLoadHost == "" {
		return fmt.Errorf("--host is required")
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	ctx := context.Background()
	if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
		return fmt.Errorf("failed to create schema: %w", schemaErr)
	}

	repo := database.NewRepository(db)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	rows := database.SessionsToSessionHostnames(sessions, projectUUID, sessionLoadHost)
	now := time.Now()
	for _, r := range rows {
		r.Source = sessionLoadSource
		r.HydratedAt = &now
		if loginResponse != "" {
			r.LoginResponse = loginResponse
		}
	}

	if err := repo.SaveSessionHostnames(ctx, rows); err != nil {
		return fmt.Errorf("failed to save sessions: %w", err)
	}

	fmt.Printf("%s Loaded %d session(s) for host %s\n\n",
		terminal.InfoSymbol(), len(rows), terminal.Cyan(sessionLoadHost))

	for _, r := range rows {
		role := r.SessionRole
		switch role {
		case "primary":
			role = terminal.Green(role)
		case "compare":
			role = terminal.Yellow(role)
		}
		token := r.SessionToken
		if token != "" {
			if len(token) > 40 {
				token = token[:37] + "..."
			}
			fmt.Printf("  %s  role=%s  token=%s\n", r.SessionName, role, terminal.Gray(token))
		} else {
			hasLogin := "no"
			if r.LoginURL != "" {
				hasLogin = terminal.Cyan(r.LoginURL)
			}
			fmt.Printf("  %s  role=%s  login=%s\n", r.SessionName, role, hasLogin)
		}
	}
	fmt.Println()
	return nil
}

// persistSessions converts sessions to DB rows and saves them.
func persistSessions(sessions []*session.Session) error {
	if sessionLoadHost == "" {
		return fmt.Errorf("--host is required")
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	ctx := context.Background()
	if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
		return fmt.Errorf("failed to create schema: %w", schemaErr)
	}

	repo := database.NewRepository(db)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	// Convert to DB rows and persist.
	rows := database.SessionsToSessionHostnames(sessions, projectUUID, sessionLoadHost)
	now := time.Now()
	for _, r := range rows {
		r.Source = sessionLoadSource
		// If session has headers (hydrated), set HydratedAt.
		if len(r.Headers) > 0 {
			r.HydratedAt = &now
		}
	}

	if err := repo.SaveSessionHostnames(ctx, rows); err != nil {
		return fmt.Errorf("failed to save sessions: %w", err)
	}

	// Print summary.
	fmt.Printf("%s Loaded %d session(s) for host %s\n\n",
		terminal.InfoSymbol(), len(rows), terminal.Cyan(sessionLoadHost))

	for _, r := range rows {
		role := r.SessionRole
		switch role {
		case "primary":
			role = terminal.Green(role)
		case "compare":
			role = terminal.Yellow(role)
		}
		hasLogin := "no"
		if r.LoginURL != "" {
			hasLogin = terminal.Cyan(r.LoginURL)
		}
		token := r.SessionToken
		if token != "" {
			if len(token) > 40 {
				token = token[:37] + "..."
			}
			fmt.Printf("  %s  role=%s  token=%s  login=%s\n", r.SessionName, role, terminal.Gray(token), hasLogin)
		} else {
			fmt.Printf("  %s  role=%s  login=%s\n", r.SessionName, role, hasLogin)
		}
	}
	fmt.Println()

	return nil
}

// deriveHostFromSessions extracts the hostname from the first session with a login URL.
func deriveHostFromSessions(sessions []*session.Session) string {
	for _, s := range sessions {
		if s.Login != nil && s.Login.URL != "" {
			u, err := url.Parse(s.Login.URL)
			if err == nil && u.Host != "" {
				return u.Host
			}
		}
	}
	return ""
}

// loadSessionsFromFile loads sessions from a file, auto-detecting agent vs native format.
func loadSessionsFromFile(filePath string) ([]*session.Session, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	if sessionLoadAgentFormat || isAgentSessionFile(filePath) {
		return parseAgentSessionBytes(data)
	}

	// Try native format first (supports YAML and JSON).
	sessions, err := loadSessionsFromBytes(data)
	if err != nil {
		// If native parsing fails and it's a JSON file, try agent format as fallback.
		if strings.HasSuffix(filePath, ".json") {
			agentSessions, agentErr := parseAgentSessionBytes(data)
			if agentErr == nil && len(agentSessions) > 0 {
				return agentSessions, nil
			}
		}
		return nil, err
	}
	return sessions, nil
}

// loadSessionsFromBytes parses session config bytes, trying native format first
// then falling back to agent format.
func loadSessionsFromBytes(data []byte) ([]*session.Session, error) {
	content := os.ExpandEnv(string(data))

	// Try native format (JSON or YAML).
	var cfg session.SessionConfig
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(content), &cfg); err == nil && len(cfg.Sessions) > 0 {
			return sessionsToPointers(cfg.Sessions), nil
		}
	} else {
		if err := yaml.Unmarshal([]byte(content), &cfg); err == nil && len(cfg.Sessions) > 0 {
			return sessionsToPointers(cfg.Sessions), nil
		}
	}

	// Fallback: try agent format.
	agentSessions, err := parseAgentSessionBytes(data)
	if err == nil && len(agentSessions) > 0 {
		return agentSessions, nil
	}

	return nil, fmt.Errorf("failed to parse session config: unrecognized format")
}

// parseAgentSessionBytes parses agent session-config.json bytes and converts to native sessions.
func parseAgentSessionBytes(data []byte) ([]*session.Session, error) {
	content := os.ExpandEnv(string(data))

	var cfg agent.AgentSessionConfig
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse agent session config: %w", err)
	}

	if len(cfg.Sessions) == 0 {
		return nil, fmt.Errorf("no sessions found in agent config")
	}

	sessions := agent.AgentSessionConfigToSessions(&cfg)

	// Auto-assign primary role if none specified.
	hasPrimary := false
	for _, s := range sessions {
		if s.Role == session.RolePrimary {
			hasPrimary = true
			break
		}
	}
	if !hasPrimary && len(sessions) > 0 {
		sessions[0].Role = session.RolePrimary
	}

	return sessions, nil
}

// sessionsToPointers converts a slice of Session values to a slice of Session pointers.
func sessionsToPointers(sessions []session.Session) []*session.Session {
	result := make([]*session.Session, len(sessions))
	for i := range sessions {
		result[i] = &sessions[i]
	}
	return result
}

// isAgentSessionFile returns true if the file path looks like an agent session config.
func isAgentSessionFile(path string) bool {
	return strings.Contains(path, "agent-sessions/") || strings.HasSuffix(path, "session-config.json")
}
