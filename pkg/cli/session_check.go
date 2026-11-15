package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/authentication"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/httpstack"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

var (
	sessionCheckURL     string
	sessionCheckMethod  string
	sessionCheckSession string
	sessionCheckTimeout time.Duration
)

var sessionCheckCmd = &cobra.Command{
	Use:   "check <session-file|session-name> [--url <protected-url>]",
	Short: "Check that a session is really logged in on a protected URL",
	Long: `Log a session in exactly as a scan does, then fetch a protected URL twice
through the scan's HTTP stack: once with the session's credentials and once
without. The two responses decide the verdict:

  authenticated      the session reached what the anonymous request did not
  login_wall         the session was sent to a login page (redirect or form)
  unauthorized       the server refused the credentials (401/403, or the
                     session's check.logged_in rule failed)
  indistinguishable  both responses are the same, so the URL proves nothing:
                     pick a page only a logged-in user sees, or configure
                     check.logged_in
  error              the login or a request failed

The argument is a session file (any form --auth-file accepts; a bare name is
looked up in scanning_strategy.session.session_dir like --auth-file) or the
name of a session stored with 'auth load' in the current project. A file with
several sessions checks each of them; --session picks one.

The URL is --url, else the session's check.url, else the config's
scanning_strategy.session.validate_url. A path resolves against the login
URL's origin. The session's check.logged_in / check.logged_out rules, when
present, are applied to the responses before the heuristics.

Exits 0 only when every checked session is authenticated. Otherwise exit 1
with error code login_failed (a login did not work) or not_authenticated (any
other verdict); with -j each session is an item carrying its verdict, reason,
signals and both responses' status, length and Location.`,
	Args: cobra.ExactArgs(1),
	RunE: runSessionCheck,
}

func init() {
	authCmd.AddCommand(sessionCheckCmd)
	sessionCheckCmd.Flags().StringVar(&sessionCheckURL, "url", "", "Protected URL to check (default: the session's check.url, then scanning_strategy.session.validate_url)")
	sessionCheckCmd.Flags().StringVar(&sessionCheckMethod, "method", "", "HTTP method for the check request (default: check.method, then GET)")
	sessionCheckCmd.Flags().StringVar(&sessionCheckSession, "session", "", "Check only this session from a multi-session file")
	sessionCheckCmd.Flags().DurationVar(&sessionCheckTimeout, "timeout", sessionLoadDefaultTimeout, "Timeout for each login and check request")
	sessionCheckCmd.Example = FormatExamples(
		"# Check the sessions in a file against a protected page",
		"vigolium auth check sessions.yaml --url https://app.example.com/account",
		"# Check one stored session (loaded earlier with 'auth load')",
		"vigolium auth check admin --url https://app.example.com/api/me -j",
		"# Use the session's own check.url",
		"vigolium auth check sessions.yaml --session admin",
	)
}

// sessionCheckProbe is one response as the -j document reports it.
type sessionCheckProbe struct {
	Status   int    `json:"status,omitempty"`
	Length   int    `json:"length"`
	Location string `json:"location,omitempty"`
	Error    string `json:"error,omitempty"`
}

// sessionCheckItem is one session's result.
type sessionCheckItem struct {
	Session       string                      `json:"session"`
	URL           string                      `json:"url,omitempty"`
	Method        string                      `json:"method,omitempty"`
	Verdict       authentication.Verdict      `json:"verdict"`
	Authenticated bool                        `json:"authenticated"`
	Reason        string                      `json:"reason"`
	Signals       []authentication.Signal     `json:"signals,omitempty"`
	Similarity    *float64                    `json:"similarity,omitempty"`
	AuthResponse  *sessionCheckProbe          `json:"auth_response,omitempty"`
	AnonResponse  *sessionCheckProbe          `json:"anon_response,omitempty"`
	Login         *authentication.LoginResult `json:"login,omitempty"`
}

func runSessionCheck(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()
	ctx := cmdContext(cmd)

	w := humanOut()

	settings, err := loadProjectSettings(globalConfig)
	if err != nil {
		return err
	}
	sessCfg := settings.ScanningStrategy.Session
	defaults, err := sessCfg.SessionDefaults()
	if err != nil {
		return codedErrorf(apicontract.CodeConfigInvalid, "%v", err)
	}

	sessions, source, err := resolveCheckSessions(ctx, args[0], sessCfg.SessionDir)
	if err != nil {
		return err
	}
	if sessionCheckSession != "" {
		var picked []*authentication.Session
		for _, s := range sessions {
			if s.Name == sessionCheckSession {
				picked = append(picked, s)
			}
		}
		if len(picked) == 0 {
			return codedErrorf(apicontract.CodeNotFound, "%s has no session named %q", source, sessionCheckSession)
		}
		sessions = picked
	}

	// Defaults, validation and the URL are settled for every session before
	// any request goes out: a usage or config problem sends nothing.
	type plan struct {
		sess   *authentication.Session
		url    string
		method string
	}
	plans := make([]plan, 0, len(sessions))
	for _, s := range sessions {
		s.ApplyDefaults(defaults)
		if err := s.Validate(); err != nil {
			return codedErrorf(apicontract.CodeConfigInvalid, "%s: %v", source, err)
		}
		target, err := sessionCheckTarget(s)
		if err != nil {
			return err
		}
		method := strings.ToUpper(strings.TrimSpace(sessionCheckMethod))
		if method == "" {
			method = s.Check.EffectiveMethod()
		}
		plans = append(plans, plan{sess: s, url: target, method: method})
	}

	stack, err := sessionCheckStack()
	if err != nil {
		return err
	}
	defer stack.Close()
	requester := stack.Requester
	loginClient := sessionLoginClient(sessionCheckTimeout)

	items := make([]sessionCheckItem, 0, len(plans))
	for _, p := range plans {
		item := checkOneSession(ctx, p.sess, p.url, p.method, requester, loginClient)
		items = append(items, item)
		if !globalJSON {
			printSessionCheckItem(w, item)
		}
	}

	failErr := sessionCheckError(items)
	if globalJSON {
		var opts []envOpt
		opts = append(opts, withExtra("source", source))
		if err := emitRead(cmd, "", items, int64(len(items)), 0, len(items), opts...); err != nil {
			return err
		}
	}
	return failErr
}

// resolveCheckSessions reads the sessions arg names: a session file (a path,
// or a bare name in the session dir, as --auth-file resolves it), else a
// session stored in the current project's database. source labels where they
// came from for messages and the -j document.
func resolveCheckSessions(ctx context.Context, arg, sessionDir string) ([]*authentication.Session, string, error) {
	if arg == "-" {
		data, err := readStdin()
		if err != nil {
			return nil, "", fmt.Errorf("failed to read stdin: %w", err)
		}
		sessions, err := parseCheckSessionFile(data, "<stdin>")
		return sessions, "<stdin>", err
	}
	if path := authentication.ResolveSessionPath(arg, sessionDir); fileExists(path) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read %s: %w", path, err)
		}
		sessions, err := parseCheckSessionFile(data, path)
		return sessions, path, err
	}
	if strings.ContainsAny(arg, `/\`) || strings.HasSuffix(arg, ".yaml") || strings.HasSuffix(arg, ".yml") || strings.HasSuffix(arg, ".json") {
		return nil, "", codedErrorf(apicontract.CodeSourceMissing, "session file %s does not exist", arg)
	}

	db, err := getDBFor(clicommon.IntentRead)
	if err != nil {
		return nil, "", fmt.Errorf("no session file named %q, and the database could not be opened to look for a stored session: %w", arg, err)
	}
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return nil, "", err
	}
	rows, err := database.NewRepository(db).GetAuthenticationHostnamesByProject(ctx, projectUUID)
	if err != nil && !strings.Contains(err.Error(), "no such table") {
		return nil, "", fmt.Errorf("failed to read stored sessions: %w", err)
	}
	var match []*database.AuthenticationHostname
	for _, r := range rows {
		if r.SessionName == arg {
			match = append(match, r)
		}
	}
	if len(match) == 0 {
		return nil, "", codedErrorf(apicontract.CodeNotFound,
			"no session file %q and no stored session named %q in the current project (see 'vigolium auth list')", arg, arg)
	}
	// The same name may be stored for several hosts: prefer the one --url
	// points at.
	row := match[0]
	if host := httpmsg.HostnameFromURL(sessionCheckURL); host != "" {
		for _, r := range match {
			if strings.EqualFold(r.Hostname, host) {
				row = r
				break
			}
		}
	}
	return []*authentication.Session{database.AuthenticationHostnameToSession(row)}, "stored session " + arg, nil
}

func parseCheckSessionFile(data []byte, name string) ([]*authentication.Session, error) {
	sessions, issues, err := authentication.ParseSessionBytes(data, name, authentication.ParseOptions{})
	if err != nil {
		return nil, codedErrorf(apicontract.CodeConfigInvalid, "%v", err)
	}
	for _, is := range issues {
		fmt.Fprintf(os.Stderr, "%s %s%s: %s (ignored; run 'vigolium auth lint')\n",
			terminal.WarningSymbol(), name, issuePos(is), is.Message)
	}
	return sessions, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// sessionCheckTarget is the URL to check s on: --url, else check.url (after
// config defaults), a path resolved against the login URL's origin.
func sessionCheckTarget(s *authentication.Session) (string, error) {
	raw := strings.TrimSpace(sessionCheckURL)
	if raw == "" && s.Check != nil {
		raw = s.Check.URL
	}
	if raw == "" {
		return "", usageErrorf("--url is required: session %q has no check.url and scanning_strategy.session.validate_url is not set", s.Name)
	}
	target, err := authentication.ResolveCheckURL(raw, sessionLoginURL(s))
	if err != nil {
		return "", usageErrorf("session %q: %v; pass an absolute --url", s.Name, err)
	}
	return target, nil
}

// sessionLoginURL is the session's login URL, the origin a relative check
// URL resolves against; "" for a static-header session.
func sessionLoginURL(s *authentication.Session) string {
	switch {
	case s.Login != nil:
		return s.Login.LoginURL()
	case s.LoginRequest != "":
		if lr, err := authentication.ParseRawLoginRequest(s.LoginRequest); err == nil {
			return lr.URL
		}
	}
	return ""
}

// sessionCheckStack builds the scan's requester (same client, proxy, TLS
// stance and default headers a scan sends with) for the two check requests.
func sessionCheckStack() (*httpstack.Stack, error) {
	opts := types.DefaultOptions()
	opts.Timeout = sessionCheckTimeout
	if opts.Timeout <= 0 {
		opts.Timeout = sessionLoadDefaultTimeout
	}
	opts.ProxyURL = globalProxy
	opts.Verbose = globalVerbose
	opts.Debug = globalDebug
	opts.DumpTraffic = globalDumpTraffic
	return httpstack.New(httpstack.Config{Options: opts, MaxHosts: 100})
}

// checkOneSession logs s in (when it has a login flow), then sends the
// authenticated and anonymous requests and assesses them.
func checkOneSession(ctx context.Context, s *authentication.Session, target, method string, requester *vighttp.Requester, loginClient *http.Client) sessionCheckItem {
	item := sessionCheckItem{Session: s.Name, URL: target, Method: method}

	if s.Login != nil || s.LoginRequest != "" {
		res := authentication.CheckLogin(ctx, s, loginClient)
		item.Login = &res
		if !res.OK {
			item.Verdict = authentication.VerdictError
			item.Reason = fmt.Sprintf("login failed (%s): %s", res.Reason, res.Message)
			return item
		}
	}

	authView, err := requester.WithAdditionalHeaders(s.HeaderSlice())
	if err != nil {
		item.Verdict = authentication.VerdictError
		item.Reason = fmt.Sprintf("cannot apply the session's headers: %v", err)
		return item
	}
	anon := sendCheckRequest(ctx, requester, target, method)
	auth := sendCheckRequest(ctx, authView, target, method)
	item.AnonResponse = probeView(anon)
	item.AuthResponse = probeView(auth)

	a := authentication.AssessAuthenticated(auth, anon, s.Check)
	item.Verdict = a.Verdict
	item.Authenticated = a.Authenticated()
	item.Reason = a.Reason
	item.Signals = a.Signals
	if a.Similarity >= 0 {
		sim := a.Similarity
		item.Similarity = &sim
	}
	return item
}

// sendCheckRequest sends one check request without following redirects (a
// redirect to the login page is the evidence) and without clustering (the
// two requests must each reach the server).
func sendCheckRequest(ctx context.Context, r *vighttp.Requester, target, method string) *authentication.ProbeResponse {
	p := &authentication.ProbeResponse{URL: target}
	req, err := httpmsg.HttpRequestFromURL(target)
	if err != nil {
		p.Err = err
		return p
	}
	if method != "" && method != http.MethodGet {
		req = req.WithMethod(method)
	}
	chain, _, err := r.ExecuteContext(ctx, httpmsg.NewHttpRequestResponse(req, nil),
		vighttp.Options{NoRedirects: true, NoClustering: true, DisableCompression: true})
	if err != nil {
		p.Err = err
		return p
	}
	defer chain.Close()
	resp := chain.Response()
	if resp == nil {
		p.Err = errors.New("no response")
		return p
	}
	p.Status = resp.StatusCode
	p.Header = resp.Header.Clone()
	p.Body = append([]byte(nil), chain.BodyBytes()...)
	return p
}

func probeView(p *authentication.ProbeResponse) *sessionCheckProbe {
	if p == nil {
		return nil
	}
	v := &sessionCheckProbe{Status: p.Status, Length: len(p.Body), Location: p.Location()}
	if p.Err != nil {
		v.Error = p.Err.Error()
	}
	return v
}

// sessionCheckError is the coded error for a run where some session is not
// authenticated: login_failed when a login did not work, not_authenticated
// for every other verdict. nil when all are authenticated.
func sessionCheckError(items []sessionCheckItem) error {
	var parts []string
	loginFailed := false
	for _, it := range items {
		if it.Authenticated {
			continue
		}
		if it.Login != nil && !it.Login.OK {
			loginFailed = true
			parts = append(parts, fmt.Sprintf("%s (login_failed: %s)", it.Session, it.Login.Reason))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", it.Session, it.Verdict))
	}
	if len(parts) == 0 {
		return nil
	}
	code := apicontract.CodeNotAuthenticated
	if loginFailed {
		code = apicontract.CodeLoginFailed
	}
	return codedErrorf(code, "auth check: %d of %d session(s) not authenticated: %s",
		len(parts), len(items), strings.Join(parts, ", "))
}

func printSessionCheckItem(w io.Writer, it sessionCheckItem) {
	statuses := ""
	if it.AuthResponse != nil && it.AnonResponse != nil {
		statuses = fmt.Sprintf("  auth=%s anon=%s", checkStatusText(it.AuthResponse), checkStatusText(it.AnonResponse))
	}
	verdict := string(it.Verdict)
	switch {
	case it.Authenticated:
		_, _ = fmt.Fprintf(w, "%s %s  %s  %s %s%s\n", terminal.SuccessSymbol(), terminal.BoldCyan(it.Session), terminal.Green(verdict), it.Method, it.URL, statuses)
	case it.Verdict == authentication.VerdictIndistinguishable:
		_, _ = fmt.Fprintf(w, "%s %s  %s  %s %s%s\n", terminal.WarningSymbol(), terminal.BoldCyan(it.Session), terminal.Yellow(verdict), it.Method, it.URL, statuses)
	default:
		_, _ = fmt.Fprintf(w, "%s %s  %s  %s %s%s\n", terminal.ErrorSymbol(), terminal.BoldCyan(it.Session), terminal.Red(verdict), it.Method, it.URL, statuses)
	}
	_, _ = fmt.Fprintf(w, "    %s\n", it.Reason)
}

func checkStatusText(p *sessionCheckProbe) string {
	if p.Error != "" {
		return "error"
	}
	return fmt.Sprintf("%d", p.Status)
}
