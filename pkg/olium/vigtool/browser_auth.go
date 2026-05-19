package vigtool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// NewBrowserAuthTool returns the browser_auth tool, an agent-friendly
// wrapper over `agent-browser`. The tool drives a persistent named browser
// session across calls so the agent can interleave snapshot/fill/click in
// a natural login flow, and on `save_as` it dumps cookies straight into
// authentication_hostnames so auth_session_lookup picks them up.
//
// Returns nil if agent-browser is not on PATH or the tool has no repo —
// the caller should fall back to omitting the tool registration entirely.
func NewBrowserAuthTool(repo *database.Repository, projectUUID string) tool.Tool {
	if repo == nil || projectUUID == "" {
		return nil
	}
	bin, err := exec.LookPath("agent-browser")
	if err != nil {
		return nil
	}
	return &browserAuthTool{
		repo:        repo,
		projectUUID: projectUUID,
		bin:         bin,
	}
}

type browserAuthTool struct {
	repo        *database.Repository
	projectUUID string
	bin         string

	sessionMu   sync.Mutex
	sessionName string // generated once per run, reused across calls
}

func (*browserAuthTool) Name() string     { return "browser_auth" }
func (*browserAuthTool) Label() string    { return "Browser auth flow" }
func (*browserAuthTool) Category() string { return tool.CategoryVigolium }
func (*browserAuthTool) IsReadOnly() bool { return false }
func (*browserAuthTool) Description() string {
	return "Drive a stateful headless browser session via agent-browser to complete an auth flow " +
		"and persist the resulting cookies as an auth session — so the rest of the toolchain " +
		"(replay_request, run_scan, list_auth_sessions / auth_session_lookup) can act as a " +
		"logged-in user without re-implementing the login. Pass `steps` as an ordered array " +
		"of {action,...} entries; the typical flow is open → snapshot → fill (using @ref ids " +
		"from the snapshot) → click → wait → snapshot → call again with save_as. The browser " +
		"session persists across calls so the agent can iterate: call once to navigate + " +
		"snapshot, read refs from the result, then call again with the fill/click steps. " +
		"Set save_as on the last call to dump cookies and write them to authentication_hostnames."
}

func (*browserAuthTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"steps": map[string]any{
				"type":        "array",
				"description": "Ordered actions to apply in this call. Empty = no actions (useful when only save_as is set).",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"action": map[string]any{
							"type":        "string",
							"enum":        []string{"open", "snapshot", "fill", "click", "press", "wait"},
							"description": "open=navigate; snapshot=dump interactive elements with @ref ids; fill=type into element; click=click element; press=press a key (Enter/Tab/Escape/etc); wait=pause for ms/selector/url-pattern.",
						},
						"url":          map[string]any{"type": "string", "description": "(open) URL to navigate to."},
						"ref":          map[string]any{"type": "string", "description": "(fill, click) @ref id from a prior snapshot, or a CSS selector."},
						"value":        map[string]any{"type": "string", "description": "(fill) text to type."},
						"key":          map[string]any{"type": "string", "description": "(press) key name, e.g. 'Enter', 'Tab'."},
						"wait_ms":      map[string]any{"type": "integer", "description": "(wait) milliseconds to pause."},
						"wait_url":     map[string]any{"type": "string", "description": "(wait) URL glob to wait for (e.g. '**/dashboard'). agent-browser --url syntax."},
						"wait_selector": map[string]any{"type": "string", "description": "(wait) CSS selector to wait for."},
						"scope":        map[string]any{"type": "string", "description": "(snapshot) optional CSS selector to scope the snapshot to."},
					},
					"required": []string{"action"},
				},
			},
			"save_as": map[string]any{
				"type": "object",
				"description": "When set, after all steps run, dump cookies and persist as an auth session row. Subsequent auth_session_lookup({hostname, name}) calls will return the saved headers.",
				"properties": map[string]any{
					"hostname":     map[string]any{"type": "string", "description": "Hostname to register the session under. Default: host of current page URL."},
					"session_name": map[string]any{"type": "string", "description": "Session name (key for auth_session_lookup). Default 'default'."},
					"role":         map[string]any{"type": "string", "description": "Optional role label ('user', 'admin', etc)."},
				},
			},
		},
	}
}

type browserAuthStep struct {
	Action       string
	URL          string
	Ref          string
	Value        string
	Key          string
	WaitMS       int
	WaitURL      string
	WaitSelector string
	Scope        string
}

type browserAuthSaveAs struct {
	Hostname    string
	SessionName string
	Role        string
}

type browserAuthStepResult struct {
	Action  string `json:"action"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
	Skipped bool   `json:"skipped,omitempty"`
}

func (b *browserAuthTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	steps, err := parseBrowserAuthSteps(args["steps"])
	if err != nil {
		return tool.Result{Content: "browser_auth: " + err.Error(), IsError: true}, nil
	}
	saveAs, err := parseBrowserAuthSaveAs(args["save_as"])
	if err != nil {
		return tool.Result{Content: "browser_auth: " + err.Error(), IsError: true}, nil
	}
	if len(steps) == 0 && saveAs == nil {
		return tool.Result{
			Content: "browser_auth: provide at least one of 'steps' or 'save_as'",
			IsError: true,
		}, nil
	}

	session := b.ensureSession()

	results := make([]browserAuthStepResult, 0, len(steps))
	for _, st := range steps {
		res := b.runStep(ctx, session, st)
		results = append(results, res)
		if res.Error != "" {
			// Stop the batch on the first error — later steps almost always
			// depend on the failed step's effect (e.g. fill after a failed
			// snapshot has stale @refs). Partial transcript is returned so
			// the model sees where it went wrong.
			break
		}
	}

	out := struct {
		Session     string                  `json:"agent_browser_session"`
		StepResults []browserAuthStepResult `json:"steps"`
		Saved       *savedAuthSummary       `json:"saved,omitempty"`
		Hint        string                  `json:"hint,omitempty"`
	}{
		Session:     session,
		StepResults: results,
	}

	if saveAs != nil {
		saved, serr := b.saveAuthSession(ctx, session, *saveAs)
		if serr != nil {
			out.Hint = "save_as failed: " + serr.Error()
		} else {
			out.Saved = saved
		}
	}

	if out.Saved == nil && saveAs == nil && len(results) > 0 {
		out.Hint = "When the flow lands you on a logged-in page, call browser_auth again with save_as={hostname,session_name} (no further steps needed) to persist cookies into authentication_hostnames."
	}

	body, _ := json.Marshal(out)
	details := map[string]any{
		"session": session,
		"steps":   len(results),
	}
	if out.Saved != nil {
		details["saved_session_name"] = out.Saved.SessionName
		details["saved_hostname"] = out.Saved.Hostname
		details["cookie_count"] = out.Saved.CookieCount
	}
	return tool.Result{
		Content: string(body),
		Details: details,
	}, nil
}

// ensureSession lazy-generates a per-run session name. The same name is
// reused across every call so cookies/storage persist across the iterative
// snapshot → fill → click → snapshot loop the model needs to run.
func (b *browserAuthTool) ensureSession() string {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessionName == "" {
		var buf [6]byte
		_, _ = rand.Read(buf[:])
		b.sessionName = "vigolium-autopilot-" + hex.EncodeToString(buf[:])
	}
	return b.sessionName
}

// runStep maps a step to the corresponding agent-browser subcommand and
// returns a structured result. Errors land in result.Error rather than
// propagating so the model always gets a coherent transcript.
func (b *browserAuthTool) runStep(ctx context.Context, session string, st browserAuthStep) browserAuthStepResult {
	res := browserAuthStepResult{Action: st.Action}
	sessFlag := []string{"--session-name", session}

	var argv []string
	timeout := 30 * time.Second

	switch st.Action {
	case "open":
		if st.URL == "" {
			res.Error = "open: url is required"
			return res
		}
		argv = append(sessFlag, "open", st.URL)
	case "snapshot":
		argv = append(sessFlag, "snapshot", "-i", "--json")
		if st.Scope != "" {
			argv = append(argv, "-s", st.Scope)
		}
	case "fill":
		if st.Ref == "" || st.Value == "" {
			res.Error = "fill: ref and value are required"
			return res
		}
		argv = append(sessFlag, "fill", st.Ref, st.Value)
	case "click":
		if st.Ref == "" {
			res.Error = "click: ref is required"
			return res
		}
		argv = append(sessFlag, "click", st.Ref)
	case "press":
		if st.Key == "" {
			res.Error = "press: key is required"
			return res
		}
		argv = append(sessFlag, "press", st.Key)
	case "wait":
		switch {
		case st.WaitURL != "":
			argv = append(sessFlag, "wait", "--url", st.WaitURL)
			timeout = 60 * time.Second
		case st.WaitSelector != "":
			argv = append(sessFlag, "wait", "--selector", st.WaitSelector)
			timeout = 60 * time.Second
		case st.WaitMS > 0:
			argv = append(sessFlag, "wait", "--ms", fmt.Sprintf("%d", st.WaitMS))
			timeout = time.Duration(st.WaitMS+5000) * time.Millisecond
		default:
			res.Error = "wait: one of wait_ms / wait_url / wait_selector is required"
			return res
		}
	default:
		res.Error = "unknown action: " + st.Action
		return res
	}

	out, runErr := runAgentBrowser(ctx, b.bin, timeout, argv...)
	res.Output = strings.TrimRight(string(out), "\n")
	// Clip giant snapshot dumps so the model isn't drowning. Full output is
	// still accessible by re-running the step with a tighter scope.
	if len(res.Output) > 6*1024 {
		res.Output = res.Output[:6*1024] + "\n…[truncated]"
	}
	if runErr != nil {
		res.Error = runErr.Error()
	}
	return res
}

type browserCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	Expires  float64 `json:"expires"`
}

type savedAuthSummary struct {
	Hostname    string `json:"hostname"`
	SessionName string `json:"session_name"`
	Role        string `json:"role,omitempty"`
	CookieCount int    `json:"cookie_count"`
}

// saveAuthSession dumps cookies from the agent-browser session, folds them
// into a Cookie header, and upserts an authentication_hostnames row so
// auth_session_lookup({hostname, name=session_name}) returns the headers.
// When hostname is empty we use the host of the browser's current URL.
func (b *browserAuthTool) saveAuthSession(ctx context.Context, session string, sa browserAuthSaveAs) (*savedAuthSummary, error) {
	sessFlag := []string{"--session-name", session}

	hostname := strings.TrimSpace(sa.Hostname)
	if hostname == "" {
		curURL, err := runAgentBrowser(ctx, b.bin, 5*time.Second, append(sessFlag, "get", "url")...)
		if err != nil {
			return nil, fmt.Errorf("read current url: %w", err)
		}
		if u, perr := url.Parse(strings.TrimSpace(string(curURL))); perr == nil && u.Host != "" {
			hostname = u.Hostname()
		}
	}
	if hostname == "" {
		return nil, fmt.Errorf("could not determine hostname (pass save_as.hostname explicitly)")
	}

	cookiesRaw, err := runAgentBrowser(ctx, b.bin, 10*time.Second, append(sessFlag, "cookies", "--json")...)
	if err != nil {
		return nil, fmt.Errorf("dump cookies: %w", err)
	}

	cookies, err := parseBrowserCookies(cookiesRaw)
	if err != nil {
		return nil, fmt.Errorf("parse cookies: %w", err)
	}

	// Filter cookies down to those that apply to this hostname so we don't
	// fold in cross-site cookies the browser also happens to hold.
	relevant := filterCookiesForHost(cookies, hostname)
	if len(relevant) == 0 {
		return nil, fmt.Errorf("no cookies in session matched hostname %s — the login flow may not have completed", hostname)
	}

	cookieHeader := buildCookieHeader(relevant)
	sessionName := strings.TrimSpace(sa.SessionName)
	if sessionName == "" {
		sessionName = "default"
	}

	now := time.Now()
	row := &database.AuthenticationHostname{
		ProjectUUID: b.projectUUID,
		Hostname:    hostname,
		SessionName: sessionName,
		SessionRole: sa.Role,
		Headers:     map[string]string{"Cookie": cookieHeader},
		Source:      "browser_auth",
		HydratedAt:  &now,
	}
	if err := b.repo.SaveAuthenticationHostname(ctx, row); err != nil {
		return nil, fmt.Errorf("save authentication hostname: %w", err)
	}

	return &savedAuthSummary{
		Hostname:    hostname,
		SessionName: sessionName,
		Role:        sa.Role,
		CookieCount: len(relevant),
	}, nil
}

func runAgentBrowser(ctx context.Context, bin string, timeout time.Duration, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func parseBrowserAuthSteps(raw any) ([]browserAuthStep, error) {
	if raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("'steps' must be an array")
	}
	out := make([]browserAuthStep, 0, len(arr))
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("steps[%d]: must be an object", i)
		}
		st := browserAuthStep{
			Action:       strings.TrimSpace(argsString(obj, "action")),
			URL:          argsString(obj, "url"),
			Ref:          argsString(obj, "ref"),
			Value:        argsString(obj, "value"),
			Key:          argsString(obj, "key"),
			WaitURL:      argsString(obj, "wait_url"),
			WaitSelector: argsString(obj, "wait_selector"),
			Scope:        argsString(obj, "scope"),
		}
		st.WaitMS = argsInt(obj, "wait_ms")
		if st.Action == "" {
			return nil, fmt.Errorf("steps[%d]: 'action' is required", i)
		}
		out = append(out, st)
	}
	return out, nil
}

func parseBrowserAuthSaveAs(raw any) (*browserAuthSaveAs, error) {
	if raw == nil {
		return nil, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("'save_as' must be an object")
	}
	return &browserAuthSaveAs{
		Hostname:    argsString(obj, "hostname"),
		SessionName: argsString(obj, "session_name"),
		Role:        argsString(obj, "role"),
	}, nil
}

// parseBrowserCookies handles both the canonical [{...}] shape and a
// {"cookies":[...]} wrapper some agent-browser versions emit.
func parseBrowserCookies(raw []byte) ([]browserCookie, error) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil, nil
	}
	switch raw[0] {
	case '[':
		var arr []browserCookie
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	case '{':
		var wrap struct {
			Cookies []browserCookie `json:"cookies"`
		}
		if err := json.Unmarshal(raw, &wrap); err != nil {
			return nil, err
		}
		return wrap.Cookies, nil
	}
	return nil, fmt.Errorf("unexpected cookie output (first byte %q)", raw[0])
}

// filterCookiesForHost keeps cookies whose Domain matches hostname per the
// usual ".example.com matches sub.example.com" rule. Cookies with empty
// Domain are assumed to be host-only for the current page and kept as-is.
func filterCookiesForHost(in []browserCookie, hostname string) []browserCookie {
	out := make([]browserCookie, 0, len(in))
	for _, c := range in {
		d := strings.TrimPrefix(c.Domain, ".")
		if d == "" || d == hostname || strings.HasSuffix(hostname, "."+d) {
			out = append(out, c)
		}
	}
	return out
}

// buildCookieHeader joins cookies into a single Cookie request header
// suitable for replay_request / web_fetch overlays.
func buildCookieHeader(cookies []browserCookie) string {
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c.Name == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}
