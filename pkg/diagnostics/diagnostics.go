package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/audit/bin"
	"github.com/vigolium/vigolium/pkg/browserprobe"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/olium/auth"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/queue"
)

// browserLaunchProbe smoke-launches a resolved browser binary to prove it can
// actually render, not just print a version. Indirected through a var so tests
// can stub it (a real probe spawns a headless browser). See checkChromium.
var browserLaunchProbe = browserprobe.Launchable

// validReasoningEfforts is the set of values accepted by olium's reasoning_effort knob.
var validReasoningEfforts = map[string]struct{}{
	"":        {}, // empty = use provider default (medium for codex)
	"minimal": {},
	"low":     {},
	"medium":  {},
	"high":    {},
	"xhigh":   {},
}

// Status represents the state of a diagnostic check.
type Status string

const (
	StatusOK      Status = "ok"
	StatusWarning Status = "warning"
	StatusError   Status = "error"
)

// CheckResult holds the outcome of a single diagnostic check.
type CheckResult struct {
	Status  Status   `json:"status"`
	Message string   `json:"message,omitempty"`
	Details []string `json:"details,omitempty"` // verbose-only diagnostic details
	Tip     string   `json:"tip,omitempty"`     // remediation hint shown at all verbosity levels
}

// AgentCheck holds the outcome of the agent backend check.
type AgentCheck struct {
	Status       Status   `json:"status"`
	Name         string   `json:"name"`
	Binary       string   `json:"binary,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	PingResponse string   `json:"ping_response,omitempty"`
	Message      string   `json:"message,omitempty"`
	Details      []string `json:"details,omitempty"`
	Tip          string   `json:"tip,omitempty"`
}

// ToolCheck holds the outcome of a third-party tool check.
type ToolCheck struct {
	Status  Status   `json:"status"`
	Path    string   `json:"path,omitempty"`
	Message string   `json:"message,omitempty"`
	Details []string `json:"details,omitempty"`
	Tip     string   `json:"tip,omitempty"`
}

// Report is the complete diagnostic report.
type Report struct {
	Status           Status                  `json:"status"` // "ready", "degraded", "not_ready"
	Timestamp        string                  `json:"timestamp"`
	Database         *CheckResult            `json:"database"`
	Initialized      *CheckResult            `json:"initialized"`
	Queue            *CheckResult            `json:"queue,omitempty"`
	Agent            *AgentCheck             `json:"agent"`
	Browser          *CheckResult            `json:"browser"`
	SessionsDir      *CheckResult            `json:"sessions_dir"`
	EmbeddedBinaries map[string]*CheckResult `json:"embedded_binaries,omitempty"`
	Audit            *CheckResult            `json:"audit,omitempty"`   // omitted when audit integration is disabled
	Piolium          *CheckResult            `json:"piolium,omitempty"` // soft check — feature-gates audit --driver=piolium
	Tools            map[string]*ToolCheck   `json:"tools"`
	TemplatesDir     *CheckResult            `json:"templates_dir"`
	NucleiTemplates  *CheckResult            `json:"nuclei_templates"`
}

// Deps provides the dependencies needed to run diagnostics.
// All fields are optional — nil values are handled gracefully.
type Deps struct {
	DB *database.DB
	// DBErr carries the error from opening the database when DB is nil. The
	// CLI populates this so checkDatabase can surface real connect failures
	// (refused, auth failed, unknown host) instead of "not configured".
	DBErr    error
	Queue    queue.Queue
	Settings *config.Settings
	// ProbeBrowserLaunch, when set, makes the chromium check actually launch the
	// resolved browser headless (catching a binary that passes --version but
	// crashes on real startup). It spawns a browser process (~1-2s), so only the
	// one-shot CLI paths (doctor, first-run init) enable it; the server
	// /diagnostics endpoint leaves it off to stay a cheap, poll-safe readout.
	ProbeBrowserLaunch bool
}

// AuditPathStatus describes one of the two driver paths under "Audit mode"
// in the doctor renderer. Paths are independent — either one being OK is
// enough to consider the audit mode usable.
type AuditPathStatus struct {
	OK      bool     // true when every component this path needs is healthy
	Reasons []string // one line per failing component (e.g. "claude: not found in PATH")
}

// AuditPathA reports the status of the claude/audit driver path used by
// `vigolium agent audit --driver=audit`. Both the `claude` CLI and the
// embedded vigolium-audit binary are required; when `agent.audit.enabled=false`
// the path is treated as unavailable (the user has explicitly opted out).
func AuditPathA(r *Report) AuditPathStatus {
	var reasons []string
	if t := r.Tools["claude"]; t == nil || t.Status != StatusOK {
		reasons = append(reasons, "claude CLI not found in PATH")
	}
	switch {
	case r.Audit == nil:
		reasons = append(reasons, "audit disabled (set agent.audit.enable=true)")
	case r.Audit.Status != StatusOK:
		reasons = append(reasons, "audit: "+r.Audit.Message)
	}
	return AuditPathStatus{OK: len(reasons) == 0, Reasons: reasons}
}

// AuditPathB reports the status of the piolium driver path used by
// `vigolium agent audit --driver=piolium`. Needs pi (the runtime) and the
// piolium Pi extension loaded. pi is installed via bun or npm, but once
// present it's a standalone binary — neither bun nor npm is required at
// audit time, so they are not part of this path's required set.
func AuditPathB(r *Report) AuditPathStatus {
	var reasons []string
	if t := r.Tools["pi"]; t == nil || t.Status != StatusOK {
		reasons = append(reasons, "pi not found in PATH")
	}
	if r.Piolium == nil || r.Piolium.Status != StatusOK {
		reasons = append(reasons, "piolium Pi extension not loaded")
	}
	return AuditPathStatus{OK: len(reasons) == 0, Reasons: reasons}
}

// Run performs all diagnostic checks and returns a report.
func Run(deps Deps) *Report {
	settings := deps.Settings
	if settings == nil {
		settings = config.DefaultSettings()
	}

	r := &Report{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools:     make(map[string]*ToolCheck),
	}

	r.Database = checkDatabase(deps.DB, deps.DBErr)
	r.Initialized = checkInitMarker()
	r.Queue = checkQueue(deps.Queue)
	r.Agent = checkAgent(settings)
	r.Browser = checkBrowser(settings)
	chromiumFallbacks := []string{"chromium-browser", "google-chrome", "google-chrome-stable"}
	if runtime.GOOS == "darwin" {
		chromiumFallbacks = append(chromiumFallbacks,
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		)
	}
	r.Tools["chromium"] = checkTool("chromium", chromiumFallbacks)
	if deps.ProbeBrowserLaunch {
		r.Tools["chromium"] = probeChromium(r.Tools["chromium"])
	}
	r.Tools["bun"] = checkTool("bun", []string{config.ExpandPath("~/.bun/bin/bun")})
	r.Tools["npm"] = checkTool("npm", nil)
	r.Tools["agent-browser"] = checkTool("agent-browser", nil)
	r.Tools["pi"] = checkTool("pi", nil)
	r.Tools["claude"] = checkTool("claude", nil)
	r.Tools["codex"] = checkTool("codex", nil)

	// Soft tools are feature-gating, not blocking — when missing, attach a tip
	// pointing at the specific command that needs them so the user knows what
	// they lose. Overall status (computeOverallStatus) ignores these warnings.
	claudeOK := r.Tools["claude"] != nil && r.Tools["claude"].Status == StatusOK
	if t := r.Tools["pi"]; t != nil && t.Status != StatusOK {
		if claudeOK {
			t.Tip = "optional — claude CLI is already available for `vigolium agent audit --driver=audit`; install pi only if you also want the piolium driver."
		} else {
			t.Tip = "`vigolium agent audit --driver=piolium` will not work — install with `vigolium doctor --fix --only piolium`."
		}
	}
	if t := r.Tools["claude"]; t != nil && t.Status != StatusOK {
		t.Tip = "`vigolium agent audit --driver=audit` (claude platform) will not work — install with `vigolium doctor --fix --only claude`."
	}
	if t := r.Tools["codex"]; t != nil && t.Status != StatusOK {
		t.Tip = "install with `bun add -g @openai/codex` — needed for `vigolium agent audit --driver=audit` (codex platform)"
	}

	// If no system chromium found, check CfT cache only (no download).
	if r.Tools["chromium"].Status != StatusOK {
		if cftbrowser.IsSupported() {
			if cached, err := cftbrowser.FindCachedBrowser(); err == nil {
				r.Tools["chromium"] = &ToolCheck{
					Status:  StatusOK,
					Path:    cached,
					Message: "Chrome for Testing (cached)",
					Details: []string{fmt.Sprintf("found cached Chrome for Testing: %s", cached)},
				}
			}
		}
	}
	// Still nothing? Attach a package-manager-specific install hint so the
	// user can either grab a system chromium or fall back to the bundled
	// Chrome for Testing download. A launch-failure downgrade already carries a
	// more specific tip (see probeChromium), so don't clobber it.
	if t := r.Tools["chromium"]; t != nil && t.Status != StatusOK && t.Tip == "" {
		t.Tip = chromiumInstallHint()
	}

	r.SessionsDir = checkSessionsDir(settings)
	r.EmbeddedBinaries = map[string]*CheckResult{
		"jstangle":         checkJSTangleBinary(),
		"vigolium-audit": checkAuditBinary(),
	}
	r.Audit = checkAudit(settings, r.EmbeddedBinaries["vigolium-audit"])
	r.Piolium = checkPiolium()
	// When claude (Path A) is available, frame a missing piolium as optional
	// rather than a problem to fix — the user already has a working audit
	// driver. The status stays as-is (still reflects whether piolium itself
	// is installed) so the JSON output remains accurate; only the user-
	// facing tip changes.
	if r.Piolium != nil && r.Piolium.Status != StatusOK && claudeOK {
		r.Piolium.Tip = "optional — claude (Path A) is available; install only if you also want the piolium driver: `vigolium doctor --fix --only piolium`"
	}
	r.TemplatesDir = checkTemplatesDir(settings)
	r.NucleiTemplates = checkNucleiTemplates(settings)

	r.Status = computeOverallStatus(r)
	return r
}

func checkDatabase(db *database.DB, dbErr error) *CheckResult {
	if db == nil {
		if dbErr != nil {
			return &CheckResult{
				Status:  StatusError,
				Message: dbErr.Error(),
				Details: []string{"database failed to open before any health probes could run"},
				Tip:     "Verify database.driver and the matching database.{sqlite,postgres} block in ~/.vigolium/vigolium-configs.yaml; for postgres ensure the server is reachable and credentials are correct.",
			}
		}
		return &CheckResult{Status: StatusError, Message: "not configured", Details: []string{"checking database connection via ping with 2s timeout"}}
	}

	driver := db.Driver()
	details := []string{
		fmt.Sprintf("driver: %s", driver),
		"checking database connection via ping with 2s timeout",
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("ping failed: %v", err),
			Details: details,
			Tip:     "Check that the database server is running and that database.{host,port,user,password,database,sslmode} match its configuration.",
		}
	}
	details = append(details, "ping: ok")

	// Version doubles as the "session can execute statements" probe — its
	// success implies the connection is healthy beyond the ping handshake.
	versionCtx, versionCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer versionCancel()
	version, err := db.ServerVersion(versionCtx)
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("query failed: %v", err),
			Details: append(details, "version() query failed after successful ping — connection is up but cannot execute statements"),
			Tip:     "The connection is open but cannot run queries. Check user privileges, default search_path, and whether the server is in a read-only or recovery state.",
		}
	}
	details = append(details, fmt.Sprintf("server: %s", version))

	tablesCtx, tablesCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer tablesCancel()
	tables, err := database.ListTables(tablesCtx, db)
	if err != nil {
		return &CheckResult{
			Status:  StatusWarning,
			Message: fmt.Sprintf("driver=%s, schema=unknown", driver),
			Details: append(details, fmt.Sprintf("schema probe failed: %v", err)),
			Tip:     "Connection works but schema metadata is unreadable. Check user privileges on information_schema (postgres) or sqlite_master (sqlite).",
		}
	}
	if !slices.Contains(tables, "scans") {
		return &CheckResult{
			Status:  StatusWarning,
			Message: fmt.Sprintf("driver=%s, schema=missing", driver),
			Details: append(details, "schema: scans table not found — migrations have not run yet"),
			Tip:     "Run `vigolium init` (or any scan/ingest subcommand) once to create the schema.",
		}
	}
	details = append(details, fmt.Sprintf("schema: %d tables present", len(tables)))

	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("driver=%s, schema=ok", driver),
		Details: details,
	}
}

// checkInitMarker inspects ~/.vigolium/initialized, the sentinel written by
// ensureCoreDeps after the first-run dependency setup (chromium + nuclei
// templates) completes. The marker is a status/debugging surface — its
// absence here just means the user has not yet run a scan-touching command,
// not that anything is broken — so the result is StatusWarning at worst and
// never affects overall readiness.
func checkInitMarker() *CheckResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return &CheckResult{
			Status:  StatusWarning,
			Message: fmt.Sprintf("cannot resolve home directory: %v", err),
		}
	}
	markerPath := filepath.Join(home, ".vigolium", "initialized")
	details := []string{fmt.Sprintf("checking marker: %s", markerPath)}

	data, err := os.ReadFile(markerPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &CheckResult{
				Status:  StatusWarning,
				Message: "first-run dep setup not yet completed",
				Details: details,
				Tip:     "Run any scan command (e.g. `vigolium scan-url <target>`) or `vigolium init` to trigger the chromium + nuclei-templates install and stamp the marker.",
			}
		}
		return &CheckResult{
			Status:  StatusWarning,
			Message: fmt.Sprintf("read failed: %v", err),
			Details: details,
		}
	}

	var meta struct {
		Version       string `json:"version"`
		InitializedAt string `json:"initialized_at"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return &CheckResult{
			Status:  StatusWarning,
			Message: fmt.Sprintf("marker malformed: %v", err),
			Details: append(details, fmt.Sprintf("raw contents: %s", strings.TrimSpace(string(data)))),
			Tip:     "Re-run `vigolium init --force` to regenerate the marker (also rotates auth_api_key and re-extracts presets).",
		}
	}

	msg := fmt.Sprintf("path=%s, version=%s", config.ContractPath(markerPath), meta.Version)
	details = append(details, fmt.Sprintf("version: %s", meta.Version))
	if meta.InitializedAt != "" {
		details = append(details, fmt.Sprintf("initialized_at: %s", meta.InitializedAt))
		if ts, err := time.Parse(time.RFC3339, meta.InitializedAt); err == nil {
			msg += ", initialized " + roundedAge(time.Since(ts))
		}
	}
	return &CheckResult{
		Status:  StatusOK,
		Message: msg,
		Details: details,
	}
}

// roundedAge formats a duration as a coarse "Nm ago" / "Nh ago" / "Nd ago"
// suffix for the doctor "initialized X" line, collapsing sub-minute deltas to
// "just now". The default time.Duration string would carry seconds and
// nanoseconds — too noisy for an at-a-glance status row.
func roundedAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func checkQueue(q queue.Queue) *CheckResult {
	if q == nil {
		return nil // queue is server-only, omit from CLI reports
	}

	metrics := q.Metrics()
	if metrics == nil {
		return &CheckResult{Status: StatusWarning, Message: "metrics unavailable"}
	}

	totalErrors := metrics.EnqueueErrors + metrics.DequeueErrors
	if totalErrors > 0 {
		return &CheckResult{
			Status:  StatusWarning,
			Message: fmt.Sprintf("depth=%d, errors=%d", metrics.Depth, totalErrors),
		}
	}

	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("depth=%d", metrics.Depth),
	}
}

func checkAgent(settings *config.Settings) *AgentCheck {
	if err := settings.Agent.Validate(); err != nil {
		return &AgentCheck{
			Status:  StatusError,
			Name:    "olium",
			Message: fmt.Sprintf("invalid agent config: %v", err),
			Tip:     "Set agent.default_agent in ~/.vigolium/vigolium-configs.yaml (typical value: \"olium\").",
		}
	}

	cfg := settings.Agent.Olium
	provider := cfg.Provider
	if provider == "" {
		provider = "openai-codex-oauth" // matches DefaultOliumConfig
	}

	var binary string // resolved subprocess binary for providers that need one
	details := []string{
		fmt.Sprintf("provider: %s", provider),
	}
	if cfg.Model != "" {
		details = append(details, fmt.Sprintf("model: %s", cfg.Model))
	}

	if _, ok := validReasoningEfforts[cfg.ReasoningEffort]; !ok {
		return &AgentCheck{
			Status:   StatusError,
			Name:     "olium",
			Protocol: provider,
			Message:  fmt.Sprintf("invalid reasoning_effort %q", cfg.ReasoningEffort),
			Details:  details,
			Tip:      "Set agent.olium.reasoning_effort to one of: minimal, low, medium, high, xhigh.",
		}
	}
	if cfg.ReasoningEffort != "" {
		details = append(details, fmt.Sprintf("reasoning_effort: %s", cfg.ReasoningEffort))
	}

	switch provider {
	case "openai-codex-oauth":
		credPath := cfg.OAuthCredPath
		if credPath == "" {
			credPath = "~/.codex/auth.json"
		}
		expanded := config.ExpandPath(credPath)
		details = append(details, fmt.Sprintf("oauth_cred_path: %s", expanded))
		// Parse the auth file the same way the runtime does — catches missing
		// file, malformed JSON, and absent access_token in one shot.
		if _, err := auth.LoadCodex(expanded); err != nil {
			tip := "Run `codex login` to create ~/.codex/auth.json, or set agent.olium.oauth_cred_path to a different path."
			if errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
				return &AgentCheck{
					Status:   StatusError,
					Name:     "olium",
					Protocol: provider,
					Message:  fmt.Sprintf("OAuth credential file not found at %s", expanded),
					Details:  details,
					Tip:      tip,
				}
			}
			return &AgentCheck{
				Status:   StatusError,
				Name:     "olium",
				Protocol: provider,
				Message:  fmt.Sprintf("OAuth credential file invalid: %v", err),
				Details:  details,
				Tip:      tip,
			}
		}
	case "anthropic-api-key":
		if cfg.LLMAPIKey == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
			return &AgentCheck{
				Status:   StatusError,
				Name:     "olium",
				Protocol: provider,
				Message:  "ANTHROPIC_API_KEY is not set",
				Details:  details,
				Tip:      "Export ANTHROPIC_API_KEY or set agent.olium.llm_api_key in ~/.vigolium/vigolium-configs.yaml.",
			}
		}
	case "anthropic-oauth":
		if cfg.OAuthToken == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
			return &AgentCheck{
				Status:   StatusError,
				Name:     "olium",
				Protocol: provider,
				Message:  "no Anthropic OAuth token configured",
				Details:  details,
				Tip:      "Run `claude setup-token` and export the result as $ANTHROPIC_API_KEY, or set agent.olium.oauth_token in ~/.vigolium/vigolium-configs.yaml.",
			}
		}
	case "openai-api-key", "openai-responses":
		// openai-responses uses the same OpenAI key resolution as openai-api-key;
		// only the wire format differs (Responses vs Chat Completions).
		if cfg.LLMAPIKey == "" && os.Getenv("OPENAI_API_KEY") == "" {
			return &AgentCheck{
				Status:   StatusError,
				Name:     "olium",
				Protocol: provider,
				Message:  "OPENAI_API_KEY is not set",
				Details:  details,
				Tip:      "Export OPENAI_API_KEY or set agent.olium.llm_api_key in ~/.vigolium/vigolium-configs.yaml.",
			}
		}
	case "anthropic-cli":
		path, err := exec.LookPath("claude")
		if err != nil {
			return &AgentCheck{
				Status:   StatusError,
				Name:     "olium",
				Protocol: provider,
				Message:  "`claude` binary not found in PATH",
				Details:  details,
				Tip:      "Install Claude Code (https://claude.ai/install.sh) or run `vigolium doctor --fix --only claude`.",
			}
		}
		details = append(details, fmt.Sprintf("claude binary: %s", path))
		binary = path
	case "anthropic-vertex", "google-vertex":
		// Vertex providers rely on GCP service-account credentials; we don't
		// validate the SA file here today (the LoadVertex path does it lazily
		// when the runtime actually dispatches a request). Keep the diagnostic
		// non-fatal so `vigolium doctor` still passes for users wired up via
		// $GOOGLE_APPLICATION_CREDENTIALS.
		if cfg.OAuthCredPath != "" && cfg.OAuthCredPath != "~/.codex/auth.json" {
			details = append(details, fmt.Sprintf("oauth_cred_path: %s", config.ExpandPath(cfg.OAuthCredPath)))
		}
		if envPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); envPath != "" {
			details = append(details, fmt.Sprintf("GOOGLE_APPLICATION_CREDENTIALS: %s", envPath))
		}
	case "openai-compatible", "anthropic-compatible":
		// A backend fronting a custom base_url — openai-compatible speaks the
		// OpenAI Chat Completions wire format (Ollama, LM Studio, vLLM,
		// OpenRouter, …); anthropic-compatible speaks the Anthropic Messages
		// format against a gateway/proxy. Both require base_url + a model;
		// api_key is optional (local backends omit it).
		baseURL := cfg.CustomProvider.BaseURL
		if baseURL == "" {
			return &AgentCheck{
				Status:   StatusError,
				Name:     "olium",
				Protocol: provider,
				Message:  fmt.Sprintf("%s provider requires a base URL", provider),
				Details:  details,
				Tip:      "Set agent.olium.custom_provider.base_url in ~/.vigolium/vigolium-configs.yaml (e.g. `http://localhost:11434/v1` for Ollama).",
			}
		}
		details = append(details, fmt.Sprintf("base_url: %s", baseURL))
		if cfg.Model == "" && cfg.CustomProvider.ModelID == "" {
			return &AgentCheck{
				Status:   StatusError,
				Name:     "olium",
				Protocol: provider,
				Message:  fmt.Sprintf("%s provider requires a model", provider),
				Details:  details,
				Tip:      "Set agent.olium.model or agent.olium.custom_provider.model_id in ~/.vigolium/vigolium-configs.yaml.",
			}
		}
	default:
		return &AgentCheck{
			Status:   StatusError,
			Name:     "olium",
			Protocol: provider,
			Message:  fmt.Sprintf("unknown olium provider %q", provider),
			Details:  details,
			Tip:      "Set agent.olium.provider to one of: openai-codex-oauth, openai-api-key, openai-responses, anthropic-api-key, anthropic-oauth, anthropic-cli, anthropic-vertex, google-vertex, openai-compatible, anthropic-compatible.",
		}
	}

	return &AgentCheck{
		Status:   StatusOK,
		Name:     "olium",
		Protocol: provider,
		Binary:   binary,
		Details:  details,
	}
}

func checkBrowser(settings *config.Settings) *CheckResult {
	details := []string{"checking agent.browser.enabled in config"}

	if !settings.Agent.Browser.IsEnabled() {
		return &CheckResult{
			Status:  StatusWarning,
			Message: "disabled in config",
			Details: details,
			Tip:     "Enable by adding `agent.browser.enable: true` to ~/.vigolium/vigolium-configs.yaml (optional: set `agent.browser.binary_path` to override the default `agent-browser` lookup).",
		}
	}

	bin := settings.Agent.Browser.EffectiveBinaryPath()
	details = append(details, fmt.Sprintf("looking up command %q in PATH", bin))

	path, err := exec.LookPath(bin)
	if err != nil {
		return &CheckResult{Status: StatusError, Message: fmt.Sprintf("%q not found in PATH", bin), Details: details}
	}

	details = append(details, fmt.Sprintf("resolved binary: %s", path))
	return &CheckResult{Status: StatusOK, Message: path, Details: details}
}

// checkSessionsDir verifies the agent sessions directory either exists and is
// writable, or can be created on first run. Permission failures are surfaced
// loudly because they translate into silent agent-run failures otherwise.
func checkSessionsDir(settings *config.Settings) *CheckResult {
	dir := settings.Agent.EffectiveSessionsDir()
	details := []string{fmt.Sprintf("checking directory: %s", dir)}

	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Directory will be created lazily by EnsureSessionDir on first run;
			// verify the parent is writable so we don't fail then.
			parent := filepath.Dir(dir)
			details = append(details, fmt.Sprintf("not yet created; checking parent writability: %s", parent))
			if err := probeWritable(parent); err != nil {
				return &CheckResult{
					Status:  StatusError,
					Message: fmt.Sprintf("parent of sessions dir not writable: %v", err),
					Details: details,
					Tip:     "Adjust permissions on " + parent + " or set agent.sessions_dir to a writable path.",
				}
			}
			return &CheckResult{
				Status:  StatusOK,
				Message: fmt.Sprintf("path=%s (will be created on first agent run)", config.ContractPath(dir)),
				Details: details,
			}
		}
		return &CheckResult{
			Status:  StatusWarning,
			Message: fmt.Sprintf("stat failed: %v", err),
			Details: details,
		}
	}
	if !info.IsDir() {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("not a directory: %s", dir),
			Details: details,
			Tip:     "Remove the conflicting file or set agent.sessions_dir to a different path.",
		}
	}
	if err := probeWritable(dir); err != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("not writable: %v", err),
			Details: details,
			Tip:     "Fix directory permissions on " + dir + " or set agent.sessions_dir to a writable path.",
		}
	}
	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("path=%s", config.ContractPath(dir)),
		Details: details,
	}
}

// probeWritable verifies the given directory accepts a temp file. The probe is
// removed before returning. Returns nil when writable.
func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".vigolium-doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// checkAudit reports whether audit mode is configured and has a working
// embedded vigolium-audit binary. Returns nil when the integration is disabled
// so the caller can omit the mode-level section from the report entirely; the
// raw embedded-binary check still appears under EmbeddedBinaries.
func checkAudit(settings *config.Settings, auditBinary *CheckResult) *CheckResult {
	if !settings.Agent.Audit.IsEnabled() {
		return nil
	}
	mode := settings.Agent.Audit.EffectiveMode()
	details := []string{fmt.Sprintf("mode: %s", mode)}
	if auditBinary == nil {
		auditBinary = checkAuditBinary()
	}
	details = append(details, auditBinary.Details...)
	if auditBinary.Status != StatusOK {
		return &CheckResult{
			Status:  auditBinary.Status,
			Message: auditBinary.Message,
			Details: details,
			Tip:     auditBinary.Tip,
		}
	}
	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("mode=%s, embedded binary ok", mode),
		Details: details,
	}
}

func checkJSTangleBinary() *CheckResult {
	details := []string{
		fmt.Sprintf("runtime: %s/%s", runtime.GOOS, runtime.GOARCH),
		"extracting embedded jstangle and validating cache checksum",
	}

	scanner, err := jstangle.NewScanner(jstangle.DefaultConfig())
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("not available: %v", err),
			Details: details,
			Tip:     "This installed Vigolium binary does not contain a usable jstangle for this platform. Reinstall the latest release; if it persists, report the package platform and `vigolium version` output.",
		}
	}
	if err := scanner.EnsureBinary(); err != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("extract failed: %v", err),
			Details: details,
			Tip:     "Check that your user cache directory is writable, then rerun `vigolium doctor`. If extraction still fails, reinstall Vigolium.",
		}
	}

	path := scanner.BinaryPath()
	checksum := scanner.Checksum()
	details = append(details,
		fmt.Sprintf("path: %s", config.ContractPath(path)),
		fmt.Sprintf("sha256: %s", checksum),
	)

	capabilities, err := scanner.Capabilities()
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("capability handshake failed: %v", err),
			Details: details,
			Tip:     "The embedded helper and Go wrapper use incompatible protocols. Rebuild with `make ensure-jstangle`, or reinstall a matching Vigolium release.",
		}
	}
	details = append(details,
		fmt.Sprintf("protocol: v%d", capabilities.ProtocolVersion),
		fmt.Sprintf("tool version: %s", capabilities.ToolVersion),
		fmt.Sprintf("source hash: %s", capabilities.SourceHash),
		fmt.Sprintf("profiles: %s", strings.Join(capabilities.Profiles, ", ")),
		fmt.Sprintf("capabilities: %s", strings.Join(capabilities.Capabilities, ", ")),
		fmt.Sprintf("framing: %s", strings.Join(capabilities.Framing, ", ")),
		"running JavaScript extraction probe",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Run the probe through the worker-pool Service — the same length-prefixed
	// path production scans use — rather than a one-shot invocation.
	service, err := jstangle.NewService(nil)
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("worker pool init failed: %v", err),
			Details: details,
			Tip:     "The embedded jstangle extracted but its worker pool could not start. Reinstall the correct platform build; if it persists, report the package platform and this doctor output.",
		}
	}
	defer func() { _ = service.Close() }()
	result, err := service.ScanWithOptions(ctx, []byte(`fetch("/vigolium-doctor-jstangle", {method: "POST", body: JSON.stringify({ok: true})});`), jstangle.ScanOptions{Profile: jstangle.ProfileEndpoints})
	if err != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("probe failed: %v", err),
			Details: details,
			Tip:     "The embedded jstangle extracted but could not execute. Reinstall the correct platform build; if it persists, report the package platform and this doctor output.",
		}
	}

	requests := 0
	bytesScanned := 0
	if result != nil {
		requests = len(result.Requests)
		bytesScanned = result.BytesScanned
	}
	details = append(details, fmt.Sprintf("probe: ok, requests=%d, bytes=%d", requests, bytesScanned))

	return &CheckResult{
		Status: StatusOK,
		Message: fmt.Sprintf("protocol=v%d, source=%s, capabilities=%d, probe=ok",
			capabilities.ProtocolVersion, shortDigest(capabilities.SourceHash), len(capabilities.Capabilities)),
		Details: details,
	}
}

func shortDigest(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func checkAuditBinary() *CheckResult {
	details := []string{
		fmt.Sprintf("runtime: %s/%s", runtime.GOOS, runtime.GOARCH),
		"extracting embedded vigolium-audit and validating executable platform",
	}

	if !bin.Available() {
		return &CheckResult{
			Status:  StatusError,
			Message: "vigolium-audit binary not embedded",
			Details: details,
			Tip:     "This installed Vigolium binary does not contain vigolium-audit. Reinstall the latest release; source builds should use `make build` or `make release`, not raw `go build`.",
		}
	}

	path, err := bin.Path()
	if err != nil {
		tip := "Reinstall the correct platform build. If this came from an official release, report the package platform and this doctor output."
		if errors.Is(err, bin.ErrBinaryMissing) {
			tip = "This installed Vigolium binary does not contain vigolium-audit. Reinstall the latest release; source builds should use `make build` or `make release`, not raw `go build`."
		}
		if errors.Is(err, bin.ErrBinaryPlatformMismatch) {
			tip = "The installed Vigolium package embedded a vigolium-audit binary for the wrong OS/arch. Reinstall the latest release; if it persists, report this as a packaging bug."
		}
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("extract failed: %v", err),
			Details: details,
			Tip:     tip,
		}
	}
	details = append(details,
		fmt.Sprintf("path: %s", config.ContractPath(path)),
		"running `vigolium-audit list` probe",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "list")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return &CheckResult{
			Status:  StatusError,
			Message: "probe timed out",
			Details: append(details, "timeout: 5s"),
			Tip:     "The embedded vigolium-audit binary extracted but did not respond to `list`. Reinstall Vigolium; if it persists, report this doctor output.",
		}
	}
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if len(trimmed) > 500 {
			trimmed = trimmed[:500] + "..."
		}
		if trimmed != "" {
			details = append(details, fmt.Sprintf("probe output: %s", trimmed))
		}
		return &CheckResult{
			Status:  StatusError,
			Message: fmt.Sprintf("probe failed: %v", err),
			Details: details,
			Tip:     "The embedded vigolium-audit extracted but could not run `list`. Reinstall the correct platform build; if it persists, report this doctor output.",
		}
	}

	details = append(details, fmt.Sprintf("probe: ok, output_bytes=%d", len(out)))
	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("runtime=%s/%s, list=ok", runtime.GOOS, runtime.GOARCH),
		Details: details,
	}
}

// checkPiolium reports the wiring state of the piolium Pi extension. Always
// runs (no config gate) since piolium is the audit harness for
// `vigolium agent audit --driver=piolium`. A miss is non-blocking: the
// section status is StatusWarning so the report makes the absence visible
// without dropping overall readiness to "degraded" — see computeOverallStatus.
func checkPiolium() *CheckResult {
	details := []string{"running piolium.Diagnose() (pi on PATH, registered in settings.json, --plm-* flags loaded)"}
	if home := piolium.Home(); home != "" {
		details = append(details, fmt.Sprintf("piolium home: %s", home))
	}

	if err := piolium.Diagnose(); err != nil {
		// Diagnose() returns multi-line errors (e.g. "install with:\n  pi install …")
		// for raw CLI display. Flatten to a single line for the table header so
		// the verbose details / tip carry the actionable parts.
		return &CheckResult{
			Status:  StatusWarning,
			Message: strings.ReplaceAll(strings.TrimSpace(err.Error()), "\n", " "),
			Details: append(details, strings.Split(err.Error(), "\n")...),
			Tip:     "`vigolium agent audit --driver=piolium` will not work — install with `vigolium doctor --fix --only piolium`.",
		}
	}

	return &CheckResult{
		Status:  StatusOK,
		Message: "pi + piolium extension loaded",
		Details: details,
	}
}

// chromiumInstallHint returns a platform-aware install command for chromium.
// On Linux we probe for the actual package manager so the suggested command
// matches the user's distro (apt/dnf/yum/pacman/zypper/apk). On macOS we
// suggest brew. Every branch also mentions the no-touch fallback that pulls
// Chrome for Testing without going through the system package manager.
func chromiumInstallHint() string {
	const fallback = "or run `vigolium doctor --fix --only chrome` to download Chrome for Testing"
	switch runtime.GOOS {
	case "darwin":
		return "install with `brew install --cask chromium` (" + fallback + ")"
	case "linux":
		linuxPMs := []struct{ bin, cmd string }{
			{"apt", "sudo apt install chromium"},
			{"apt-get", "sudo apt-get install chromium"},
			{"dnf", "sudo dnf install chromium"},
			{"yum", "sudo yum install chromium"},
			{"pacman", "sudo pacman -S chromium"},
			{"zypper", "sudo zypper install chromium"},
			{"apk", "sudo apk add chromium"},
		}
		for _, pm := range linuxPMs {
			if _, err := exec.LookPath(pm.bin); err == nil {
				return "install with `" + pm.cmd + "` (" + fallback + ")"
			}
		}
		return "install chromium via your package manager (" + fallback + ")"
	default:
		return "run `vigolium doctor --fix --only chrome` to download Chrome for Testing"
	}
}

// probeChromium hardens a resolved chromium ToolCheck by actually launching the
// binary headless. A binary on PATH that prints a version is NOT proof it runs:
// some distro Chromium builds crash on real headless startup (e.g. SIGTRAP on a
// KVM guest) and a downloaded Chrome can miss a shared library — both pass a
// `--version` check yet fail every spider. When the launch probe fails, the row
// is downgraded to a warning so the Chrome-for-Testing fallback (and the
// `--fix --only chrome` install) takes over instead of the doctor reporting a
// browser that will fail at scan time. A row that wasn't resolved, or has no
// path, is returned unchanged.
func probeChromium(t *ToolCheck) *ToolCheck {
	if t == nil || t.Status != StatusOK || t.Path == "" {
		return t
	}
	if err := browserLaunchProbe(t.Path); err != nil {
		return &ToolCheck{
			Status:  StatusWarning,
			Message: fmt.Sprintf("%s found but failed to launch headless", t.Path),
			Details: append(append([]string{}, t.Details...),
				fmt.Sprintf("launch probe failed: %v", err),
				"a --version check passes but the browser crashes on real startup"),
			// A launch-failure needs a different remedy than "not found": the
			// system browser is present but broken, so installing more of the
			// same won't help — download a known-good Chrome for Testing (or
			// point spidering.browser_path at a working browser). Set here so
			// the generic install hint below doesn't override it.
			Tip: "system browser crashes on launch — run `vigolium doctor --fix --only chrome` to download a working Chrome for Testing, or set `spidering.browser_path` to a working browser",
		}
	}
	t.Details = append(t.Details, "launch probe: ok")
	return t
}

func checkTool(name string, fallbacks []string) *ToolCheck {
	candidates := append([]string{name}, fallbacks...)
	details := []string{fmt.Sprintf("searching PATH for candidates: %v", candidates)}

	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			details = append(details, fmt.Sprintf("resolved %q: %s", candidate, path))
			return &ToolCheck{Status: StatusOK, Path: path, Details: details}
		}
	}

	return &ToolCheck{Status: StatusWarning, Message: "not found in PATH", Details: details}
}

func checkTemplatesDir(settings *config.Settings) *CheckResult {
	dir := settings.Agent.TemplatesDir
	if dir == "" {
		dir = "~/.vigolium/prompts/"
	}
	dir = config.ExpandPath(dir)

	details := []string{fmt.Sprintf("checking directory: %s", dir)}

	info, err := os.Stat(dir)
	if err != nil {
		return &CheckResult{Status: StatusWarning, Message: fmt.Sprintf("directory not found: %s", dir), Details: details}
	}
	if !info.IsDir() {
		return &CheckResult{Status: StatusWarning, Message: fmt.Sprintf("not a directory: %s", dir), Details: details}
	}

	// Recursively count Markdown templates. filepath.Glob does not expand `**`,
	// so we walk the tree to catch nested layouts (e.g. prompts/swarm/foo.md).
	count := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees, keep counting
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			count++
		}
		return nil
	})

	details = append(details, fmt.Sprintf("found %d template files", count))
	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("path=%s, templates=%d", config.ContractPath(dir), count),
		Details: details,
	}
}

// NucleiTemplatesDir resolves the nuclei templates directory from settings or
// the ~/nuclei-templates default. Exported so the `update` command resolves the
// same path as the doctor checks and fixes.
func NucleiTemplatesDir(settings *config.Settings) string {
	dir := settings.KnownIssueScan.TemplatesDir
	if dir == "" {
		return config.ExpandPath("~/nuclei-templates")
	}
	return config.ExpandPath(dir)
}

// nucleiTemplatesDir resolves the nuclei templates directory from settings or default.
func nucleiTemplatesDir(settings *config.Settings) string {
	return NucleiTemplatesDir(settings)
}

func checkNucleiTemplates(settings *config.Settings) *CheckResult {
	dir := nucleiTemplatesDir(settings)

	details := []string{fmt.Sprintf("checking nuclei templates directory: %s", dir)}

	info, err := os.Stat(dir)
	if err != nil {
		return &CheckResult{
			Status:  StatusWarning,
			Message: fmt.Sprintf("nuclei templates not found at %s — KnownIssueScan will fail. Install with: git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git %s", config.ContractPath(dir), config.ContractPath(dir)),
			Details: details,
		}
	}
	if !info.IsDir() {
		return &CheckResult{Status: StatusWarning, Message: fmt.Sprintf("not a directory: %s", dir), Details: details}
	}

	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("path=%s", config.ContractPath(dir)),
		Details: details,
	}
}

// computeOverallStatus distills the report into one of three verdicts.
// The doctor is grouped into three semantic buckets and each bucket has its
// own status contract:
//
//   - Core: only Database. A DB failure is the single condition that drops
//     the system to "not_ready" — every scan path needs storage.
//   - Native scan (vigolium scan / vigolium run): chromium, nuclei templates,
//     and the embedded jstangle binary. Failures here drop to "degraded" —
//     native scans are partially broken but the rest of the system still works.
//   - Olium-based agentic modes (autopilot + swarm + query): olium provider,
//     sessions dir, prompt templates dir, and (when explicitly enabled) the
//     agent browser. Failures drop to "degraded".
//
// Audit mode (audit Path A and piolium Path B) and the codex/pi/claude tool
// rows are intentionally NOT status-affecting — audit is opt-in, both of its
// driver paths are independently optional, and degrading the verdict for a
// missing optional mode would mislead users about what's actually broken.
// Audit failures still surface as warning rows with install hints; they just
// don't change the footer line.
func computeOverallStatus(r *Report) Status {
	if r.Database == nil || r.Database.Status == StatusError {
		return "not_ready"
	}

	// Native scan dependencies.
	if r.NucleiTemplates != nil && r.NucleiTemplates.Status != StatusOK {
		return "degraded"
	}
	if t := r.Tools["chromium"]; t != nil && t.Status != StatusOK {
		return "degraded"
	}
	if r.EmbeddedBinaries != nil {
		if c := r.EmbeddedBinaries["jstangle"]; c != nil && c.Status != StatusOK {
			return "degraded"
		}
	}

	// Olium-based modes (autopilot + swarm + query).
	if r.Agent != nil && r.Agent.Status != StatusOK {
		return "degraded"
	}
	if r.SessionsDir != nil && r.SessionsDir.Status != StatusOK {
		return "degraded"
	}
	if r.TemplatesDir != nil && r.TemplatesDir.Status != StatusOK {
		return "degraded"
	}
	// Browser disabled in config (StatusWarning) is a user choice, not a
	// failure — only degrade when it's enabled but the binary is missing.
	if r.Browser != nil && r.Browser.Status == StatusError {
		return "degraded"
	}

	// Queue is server-only and doesn't gate readiness, but a non-OK queue
	// signals a server backend issue worth surfacing.
	if r.Queue != nil && r.Queue.Status != StatusOK {
		return "degraded"
	}

	return "ready"
}
