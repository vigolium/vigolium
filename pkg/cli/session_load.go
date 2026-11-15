package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/redact"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

var (
	sessionLoadHost        string
	sessionLoadNoValidate  bool
	sessionLoadSource      string
	sessionLoadAgentFormat bool
	sessionLoadName        string
	sessionLoadForce       bool
	sessionLoadTimeout     time.Duration
)

// sessionLoadDefaultTimeout is the per-request login timeout: the same 30s a
// scan's login flow gets.
const sessionLoadDefaultTimeout = 30 * time.Second

var sessionLoadCmd = &cobra.Command{
	Use:   "load [session-file]",
	Short: "Load session auth configs from a file or stdin into the database",
	Long: `Load session authentication configurations from a YAML/JSON file or stdin and
persist them to the authentication_hostnames database table. Accepts every form
--auth-file accepts: a sessions: bundle, a single session at the top level, and
the agent session-config.json format (produced by agent source analysis). An
unknown field is a warning here; 'vigolium auth lint' reports it as an error.

Also supports raw HTTP login requests — the command will send the request,
auto-discover tokens from the response (JSON body, Set-Cookie, auth headers),
and persist the session with auto-generated extract rules.

The --host flag is optional when session configs contain login URLs — the hostname
is derived automatically from the first login URL.

Agent format is auto-detected when the file path contains "agent-sessions/",
when the JSON only parses leniently, or can be forced with --agent-format.

Login flows are checked by default exactly as a scan runs them: every step of a
multi-step flow, every expect block, over the scan's transport (--proxy, the
scan's TLS stance, --timeout per request). A session whose login fails is NOT
saved and the command exits 1 (error code login_failed); --force saves it
anyway. A login with no expect block that cannot be confirmed (for example the
login form came back) is saved with an "unverified" warning and exit 0. Use
--no-validate to skip the check.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSessionLoad,
}

func init() {
	authCmd.AddCommand(sessionLoadCmd)
	sessionLoadCmd.Flags().StringVar(&sessionLoadHost, "host", "", "Hostname to associate sessions with (derived from login URL if omitted)")
	sessionLoadCmd.Flags().BoolVar(&sessionLoadNoValidate, "no-validate", false, "Skip executing login flows for validation")
	sessionLoadCmd.Flags().StringVar(&sessionLoadSource, "source", "cli", "Source label for the session rows")
	sessionLoadCmd.Flags().BoolVar(&sessionLoadAgentFormat, "agent-format", false, "Force parsing as agent session-config.json format")
	sessionLoadCmd.Flags().StringVar(&sessionLoadName, "name", "", "Session name (used with raw HTTP request input)")
	sessionLoadCmd.Flags().BoolVar(&sessionLoadForce, "force", false, "Save sessions whose login check failed (still exits 1)")
	sessionLoadCmd.Flags().DurationVar(&sessionLoadTimeout, "timeout", sessionLoadDefaultTimeout, "Timeout for each login request")
}

// sessionLoginClient is the client a login check runs over: the transport a
// scan's login uses (pkg/http.LoginTransport — --proxy or the environment
// proxy, the scan's permissive target TLS) and the per-request timeout
// (<= 0: sessionLoadDefaultTimeout).
func sessionLoginClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = sessionLoadDefaultTimeout
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: vighttp.LoginTransport(&types.Options{ProxyURL: globalProxy, Timeout: timeout}),
	}
}

func runSessionLoad(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()
	w := humanOut()

	// Read input.
	var data []byte
	var err error

	fromFile := len(args) > 0 && args[0] != "-"
	name := "<stdin>"
	if !fromFile {
		data, err = readStdin()
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		if len(data) == 0 {
			return usageErrorf("no input provided on stdin")
		}
	} else {
		name = args[0]
		data, err = os.ReadFile(name)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", name, err)
		}
	}

	// Check if this is a raw HTTP request — auto-discover path.
	if authentication.IsRawHTTPRequest(data) {
		return runSessionLoadRawRequest(cmd, data, w)
	}

	// Otherwise, parse as session config: the same parser --auth-file and
	// auth lint use.
	opt := authentication.ParseOptions{Agent: sessionLoadAgentFormat || (fromFile && isAgentSessionFile(name))}
	sessions, issues, err := authentication.ParseSessionBytes(data, name, opt)
	if err != nil {
		return fmt.Errorf("failed to load session config: %w", err)
	}
	for _, is := range issues {
		fmt.Fprintf(os.Stderr, "%s %s%s: %s (run 'vigolium auth lint')\n",
			terminal.WarningSymbol(), name, issuePos(is), is.Message)
	}
	// What `auth lint` rejects is not saved: a stored session the linter calls
	// broken is one later scans load without saying so.
	if err := sessionLintGate(name, issues); err != nil {
		return err
	}

	// Derive --host from login URLs if not provided.
	if sessionLoadHost == "" {
		sessionLoadHost = deriveHostFromSessions(sessions)
	}
	if sessionLoadHost == "" {
		return usageErrorf("--host is required when session configs have no login URLs")
	}

	results := checkSessionLogins(cmdContext(cmd), sessions, w)

	// A failed login is not saved unless --force: a stored session that cannot
	// log in is a scan that runs unauthenticated without saying so.
	var keep []*authentication.Session
	var persisted, failed []string
	for i, sess := range sessions {
		if !results[i].OK {
			failed = append(failed, sess.Name)
			if !sessionLoadForce {
				continue
			}
		}
		keep = append(keep, sess)
		persisted = append(persisted, sess.Name)
	}
	if len(keep) > 0 {
		if err := persistSessions(keep, w); err != nil {
			return err
		}
	}

	var failErr error
	if len(failed) > 0 {
		failErr = loginFailedError(failed, results)
		if !sessionLoadForce {
			_, _ = fmt.Fprintf(w, "%s %d session(s) failed to log in and were not saved: %s (use --force to save them anyway)\n\n",
				terminal.ErrorSymbol(), len(failed), strings.Join(failed, ", "))
		}
	}

	if globalJSON {
		if err := emitSessionLoad(cmd, results, persisted, failed, failErr); err != nil {
			return err
		}
	}
	return failErr
}

// checkSessionLogins runs CheckLogin for every session with a login flow and
// prints one line per session. A session with static headers, or every session
// under --no-validate, is reported without a request.
func checkSessionLogins(ctx context.Context, sessions []*authentication.Session, w io.Writer) []authentication.LoginResult {
	results := make([]authentication.LoginResult, len(sessions))
	if sessionLoadNoValidate {
		for i, sess := range sessions {
			results[i] = authentication.LoginResult{Session: sess.Name, OK: true, Reason: authentication.LoginReasonNotValidated}
		}
		return results
	}

	_, _ = fmt.Fprintf(w, "%s Validating login flows...\n\n", terminal.InfoSymbol())
	client := sessionLoginClient(sessionLoadTimeout)
	for i, sess := range sessions {
		if sess.Login == nil && sess.LoginRequest == "" {
			results[i] = authentication.LoginResult{
				Session: sess.Name, OK: true, Reason: authentication.LoginReasonStaticHeaders,
				ExtractedHeaders: sortedHeaderNames(sess.Headers),
			}
			_, _ = fmt.Fprintf(w, "  %s  %s  %s\n", terminal.Cyan("–"), sess.Name, "static headers")
			continue
		}
		res := authentication.CheckLogin(ctx, sess, client)
		results[i] = res
		printLoginResult(w, res)
	}
	_, _ = fmt.Fprintln(w)
	return results
}

func printLoginResult(w io.Writer, res authentication.LoginResult) {
	status := ""
	if res.Status > 0 {
		status = fmt.Sprintf("  status=%d", res.Status)
	}
	switch {
	case !res.OK:
		_, _ = fmt.Fprintf(w, "  %s  %s%s  %s: %s\n", terminal.Red("✗"), res.Session, status, terminal.Red(res.Reason), res.Message)
	case res.Reason != "":
		_, _ = fmt.Fprintf(w, "  %s  %s%s  %s: %s\n", terminal.Yellow("!"), res.Session, status, terminal.Yellow(res.Reason), res.Message)
	default:
		extra := ""
		if len(res.ExtractedHeaders) > 0 {
			extra = fmt.Sprintf("  extracted=[%s]", strings.Join(res.ExtractedHeaders, ", "))
		}
		_, _ = fmt.Fprintf(w, "  %s  %s%s%s\n", terminal.Green("✓"), res.Session, terminal.Green(status), extra)
	}
}

// loginFailedError is the coded error a failed login check exits with.
func loginFailedError(failed []string, results []authentication.LoginResult) error {
	var parts []string
	for _, r := range results {
		if !r.OK {
			parts = append(parts, fmt.Sprintf("%s (%s)", r.Session, r.Reason))
		}
	}
	saved := "not saved"
	if sessionLoadForce {
		saved = "saved anyway (--force)"
	}
	return codedErrorf(apicontract.CodeLoginFailed, "login failed for %d session(s): %s; %s",
		len(failed), strings.Join(parts, ", "), saved)
}

// emitSessionLoad writes the -j document: the mutation envelope with one
// LoginResult per session, plus the names saved and the names that failed.
// When a login failed the document also carries ok:false and the coded error
// (the error envelope is not printed after a result document), so the caller
// gets both the per-session detail and the code it branches on.
func emitSessionLoad(cmd *cobra.Command, results []authentication.LoginResult, persisted, failed []string, failErr error) error {
	action := "load"
	if len(persisted) == 0 {
		action = "noop"
	}
	opts := []envOpt{}
	if failErr != nil {
		opts = append(opts, withResultFailure(failErr))
	}
	return emitMutation(cmd, "", mutationResult{
		Changed: len(persisted) > 0,
		Action:  action,
		Items:   results,
		Extra: map[string]any{
			"host":      sessionLoadHost,
			"persisted": nonNilStrings(persisted),
			"failed":    nonNilStrings(failed),
		},
	}, opts...)
}

// withResultFailure turns a result document into a failed one: ok:false and
// the same `error` object the error envelope carries ({code, message,
// exit_code}). For a command whose failure has per-item detail worth keeping
// (which logins failed, which lint issues) — one document, one parse.
func withResultFailure(err error) envOpt {
	return func(e *agentEnvelope) {
		e.OK = false
		e.Error = &agentError{
			Code:     classifyErrorCode(err, ExitError),
			Message:  err.Error(),
			ExitCode: ExitError,
		}
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// issuePos renders ":line:col" for an issue that has a position.
func issuePos(is authentication.LintIssue) string {
	switch {
	case is.Line > 0 && is.Column > 0:
		return fmt.Sprintf(":%d:%d", is.Line, is.Column)
	case is.Line > 0:
		return fmt.Sprintf(":%d", is.Line)
	}
	return ""
}

func cmdContext(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

// runSessionLoadRawRequest handles raw HTTP request auto-discovery.
func runSessionLoadRawRequest(cmd *cobra.Command, data []byte, w io.Writer) error {
	loginReq, err := authentication.ParseRawLoginRequest(string(data))
	if err != nil {
		return fmt.Errorf("failed to parse raw HTTP request: %w", err)
	}

	_, _ = fmt.Fprintf(w, "%s Sending login request: %s %s\n\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan(loginReq.Method),
		terminal.Cyan(loginReq.URL))

	name := sessionLoadName
	if name == "" {
		name = "auto-discovered"
	}
	res := authentication.LoginResult{Session: name, URL: loginReq.URL}

	result, err := authentication.DiscoverLoginContext(cmdContext(cmd), loginReq, sessionLoginClient(sessionLoadTimeout))
	if err != nil {
		reason := authentication.LoginReasonNetworkError
		if result != nil {
			res.Status = result.StatusCode
			reason = authentication.LoginReasonUnexpectedStatus
			if result.StatusCode >= 200 && result.StatusCode < 400 {
				reason = authentication.LoginReasonExtractFailed
			}
			_, _ = fmt.Fprintf(w, "  %s  status=%s  %s\n\n",
				terminal.Red("✗"),
				terminal.Red(fmt.Sprintf("%d", result.StatusCode)),
				err)
		}
		res.Reason, res.Message, res.Err = reason, err.Error(), err
		failErr := codedErrorf(apicontract.CodeLoginFailed, "auto-discovery failed: %v", err)
		if globalJSON {
			if emitErr := emitSessionLoad(cmd, []authentication.LoginResult{res}, nil, []string{name}, failErr); emitErr != nil {
				return emitErr
			}
		}
		return failErr
	}

	// Print discovered tokens.
	_, _ = fmt.Fprintf(w, "  %s  status=%s\n",
		terminal.Green("✓"),
		terminal.Green(fmt.Sprintf("%d", result.StatusCode)))

	for _, src := range result.TokenSources {
		_, _ = fmt.Fprintf(w, "  %s  %s\n", terminal.Cyan("→"), src)
	}
	_, _ = fmt.Fprintln(w)

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
		return usageErrorf("--host is required")
	}

	// Show summary of what was discovered.
	_, _ = fmt.Fprintf(w, "%s Discovered session %s for %s\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan(sess.Name),
		terminal.Cyan(sessionLoadHost))

	if len(sess.Headers) > 0 {
		for k, v := range sess.Headers {
			display := redactSessionValue(k, v)
			if len(display) > 60 {
				display = display[:57] + "..."
			}
			_, _ = fmt.Fprintf(w, "  %s %s: %s\n", terminal.Gray("→"), terminal.Cyan(k), terminal.Gray(display))
		}
	}
	_, _ = fmt.Fprintln(w)

	// Linted as a definition: the headers the login just captured are its
	// result, not a second auth source next to the login request.
	def := *sess
	if def.Login != nil || def.LoginRequest != "" {
		def.Headers = nil
	}
	if err := sessionLintGate(sess.Name, authentication.LintSessionConfig(&authentication.SessionConfig{Sessions: []authentication.Session{def}})); err != nil {
		return err
	}
	if err := persistSessionsWithResponse([]*authentication.Session{sess}, result.RawResponse, w); err != nil {
		return err
	}
	if globalJSON {
		res.Session = sess.Name
		res.OK, res.Verified, res.Status = true, true, result.StatusCode
		res.ExtractedHeaders = sortedHeaderNames(sess.Headers)
		return emitSessionLoad(cmd, []authentication.LoginResult{res}, []string{sess.Name}, nil, nil)
	}
	return nil
}

// persistSessionsWithResponse is like persistSessions but also stores a login response.
func persistSessionsWithResponse(sessions []*authentication.Session, loginResponse string, w io.Writer) error {
	if sessionLoadHost == "" {
		return usageErrorf("--host is required")
	}

	db, err := getDBFor(clicommon.IntentWrite)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	ctx := context.Background()
	repo := database.NewRepository(db)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	rows := database.SessionsToAuthenticationHostnames(sessions, projectUUID, database.AuthHostKey(sessionLoadHost))
	now := time.Now()
	for _, r := range rows {
		r.Source = sessionLoadSource
		r.HydratedAt = &now
		if loginResponse != "" {
			r.LoginResponse = loginResponse
		}
	}

	if err := repo.SaveAuthenticationHostnames(ctx, rows); err != nil {
		return fmt.Errorf("failed to save sessions: %w", err)
	}

	_, _ = fmt.Fprintf(w, "%s Loaded %d session(s) for host %s\n\n",
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
			// A token is a credential: shown as present, never in clear.
			token = redact.Placeholder
			_, _ = fmt.Fprintf(w, "  %s  role=%s  token=%s\n", r.SessionName, role, terminal.Gray(token))
		} else {
			hasLogin := "no"
			if r.LoginURL != "" {
				hasLogin = terminal.Cyan(r.LoginURL)
			}
			_, _ = fmt.Fprintf(w, "  %s  role=%s  login=%s\n", r.SessionName, role, hasLogin)
		}
	}
	_, _ = fmt.Fprintln(w)
	return nil
}

// persistSessions converts sessions to DB rows and saves them.
func persistSessions(sessions []*authentication.Session, w io.Writer) error {
	if sessionLoadHost == "" {
		return usageErrorf("--host is required")
	}

	db, err := getDBFor(clicommon.IntentWrite)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	ctx := context.Background()
	repo := database.NewRepository(db)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	// Convert to DB rows and persist.
	rows := database.SessionsToAuthenticationHostnames(sessions, projectUUID, database.AuthHostKey(sessionLoadHost))
	now := time.Now()
	for _, r := range rows {
		r.Source = sessionLoadSource
		// If session has headers (hydrated), set HydratedAt.
		if len(r.Headers) > 0 {
			r.HydratedAt = &now
		}
	}

	if err := repo.SaveAuthenticationHostnames(ctx, rows); err != nil {
		return fmt.Errorf("failed to save sessions: %w", err)
	}

	// Print summary.
	_, _ = fmt.Fprintf(w, "%s Loaded %d session(s) for host %s\n\n",
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
			// A token is a credential: shown as present, never in clear.
			token = redact.Placeholder
			_, _ = fmt.Fprintf(w, "  %s  role=%s  token=%s  login=%s\n", r.SessionName, role, terminal.Gray(token), hasLogin)
		} else {
			_, _ = fmt.Fprintf(w, "  %s  role=%s  login=%s\n", r.SessionName, role, hasLogin)
		}
	}
	_, _ = fmt.Fprintln(w)

	return nil
}

// deriveHostFromSessions extracts the hostname from the first session with a
// login URL: the flow's own, the first step's of a multi-step flow, or a raw
// login_request's.
func deriveHostFromSessions(sessions []*authentication.Session) string {
	for _, s := range sessions {
		var loginURL string
		switch {
		case s.Login != nil:
			loginURL = s.Login.LoginURL()
		case s.LoginRequest != "":
			if lr, err := authentication.ParseRawLoginRequest(s.LoginRequest); err == nil {
				loginURL = lr.URL
			}
		}
		if loginURL == "" {
			continue
		}
		if u, err := url.Parse(loginURL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return ""
}

// isAgentSessionFile returns true if the file path looks like an agent session config.
func isAgentSessionFile(path string) bool {
	return strings.Contains(path, "agent-sessions/") || strings.HasSuffix(path, "session-config.json")
}

// redactSessionValue masks a session header value whose name reads as a
// credential (Cookie, Authorization, X-Api-Key, …) for display.
func redactSessionValue(name, value string) string {
	if redact.IsSensitiveName(name) {
		return redact.Placeholder
	}
	return value
}

// sessionLintGate refuses to save sessions with lint errors (warnings pass),
// unless --force.
func sessionLintGate(name string, issues []authentication.LintIssue) error {
	var errs []string
	for _, is := range issues {
		if is.Severity == "error" {
			errs = append(errs, is.Field+": "+is.Message)
		}
	}
	if len(errs) == 0 || sessionLoadForce {
		return nil
	}
	return clicommon.CLIError{
		Err:  fmt.Errorf("%s: %d lint error(s), nothing saved: %s", name, len(errs), strings.Join(errs, "; ")),
		Code: apicontract.CodeLintFailed,
		Hint: "fix them (vigolium auth lint " + name + "), or pass --force to save anyway",
	}
}
