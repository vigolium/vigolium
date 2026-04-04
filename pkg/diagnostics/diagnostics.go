package diagnostics

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/cftbrowser"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/queue"
)

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
}

// ToolCheck holds the outcome of a third-party tool check.
type ToolCheck struct {
	Status  Status   `json:"status"`
	Path    string   `json:"path,omitempty"`
	Message string   `json:"message,omitempty"`
	Details []string `json:"details,omitempty"`
}

// Report is the complete diagnostic report.
type Report struct {
	Status           Status                `json:"status"` // "ready", "degraded", "not_ready"
	Timestamp        string                `json:"timestamp"`
	Database         *CheckResult          `json:"database"`
	Queue            *CheckResult          `json:"queue,omitempty"`
	Agent            *AgentCheck           `json:"agent"`
	Browser          *CheckResult          `json:"browser"`
	Tools            map[string]*ToolCheck `json:"tools"`
	TemplatesDir     *CheckResult          `json:"templates_dir"`
	NucleiTemplates  *CheckResult          `json:"nuclei_templates"`
}

// Deps provides the dependencies needed to run diagnostics.
// All fields are optional — nil values are handled gracefully.
type Deps struct {
	DB             *database.DB
	Queue          queue.Queue
	Settings       *config.Settings
	SkipAgentPing  bool // skip the slow agent ping (useful for recheck after --fix)
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

	r.Database = checkDatabase(deps.DB)
	r.Queue = checkQueue(deps.Queue)
	r.Agent = checkAgent(settings, deps.SkipAgentPing)
	r.Browser = checkBrowser(settings)
	r.Tools["ast-grep"] = checkTool("ast-grep", nil)
	r.Tools["chromium"] = checkTool("chromium", []string{"chromium-browser", "google-chrome", "google-chrome-stable"})
	r.Tools["bun"] = checkTool("bun", []string{config.ExpandPath("~/.bun/bin/bun")})
	r.Tools["claude"] = checkTool("claude", nil)
	r.Tools["agent-browser"] = checkTool("agent-browser", nil)

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

	r.TemplatesDir = checkTemplatesDir(settings)
	r.NucleiTemplates = checkNucleiTemplates(settings)

	r.Status = computeOverallStatus(r)
	return r
}

func checkDatabase(db *database.DB) *CheckResult {
	if db == nil {
		return &CheckResult{Status: StatusError, Message: "not configured", Details: []string{"checking database connection via ping with 2s timeout"}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	details := []string{
		fmt.Sprintf("driver: %s", db.Driver()),
		"checking database connection via ping with 2s timeout",
	}

	if err := db.PingContext(ctx); err != nil {
		return &CheckResult{Status: StatusError, Message: fmt.Sprintf("ping failed: %v", err), Details: details}
	}

	return &CheckResult{Status: StatusOK, Message: fmt.Sprintf("driver=%s", db.Driver()), Details: details}
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

func checkAgent(settings *config.Settings, skipPing bool) *AgentCheck {
	name := settings.Agent.DefaultAgent
	if name == "" {
		return &AgentCheck{Status: StatusError, Name: "(none)", Message: "no default agent configured", Details: []string{"checking agent.default_agent in config"}}
	}

	def, ok := settings.Agent.Backends[name]
	if !ok {
		return &AgentCheck{Status: StatusError, Name: name, Message: "agent not found in backends config", Details: []string{fmt.Sprintf("looking up %q in agent.backends config", name)}}
	}

	if !def.IsEnabled() {
		return &AgentCheck{Status: StatusError, Name: name, Message: "agent is disabled", Details: []string{fmt.Sprintf("agent %q is configured but disabled", name)}}
	}

	cmd := def.Command
	if cmd == "" {
		cmd = "claude" // default for SDK protocol
	}

	details := []string{
		fmt.Sprintf("default_agent: %s", name),
		fmt.Sprintf("protocol: %s", def.EffectiveProtocol()),
		fmt.Sprintf("looking up command %q in PATH", cmd),
	}

	path, err := exec.LookPath(cmd)
	if err != nil {
		return &AgentCheck{
			Status:   StatusError,
			Name:     name,
			Protocol: def.EffectiveProtocol(),
			Message:  fmt.Sprintf("%q not found in PATH", cmd),
			Details:  details,
		}
	}

	details = append(details, fmt.Sprintf("resolved binary: %s", path))

	if skipPing {
		details = append(details, "ping skipped")
		return &AgentCheck{
			Status:   StatusOK,
			Name:     name,
			Binary:   path,
			Protocol: def.EffectiveProtocol(),
			Details:  details,
		}
	}

	// Live ping: send a test prompt and verify the agent responds
	details = append(details, "sending test prompt to verify agent responsiveness")
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer pingCancel()

	pingResp, pingErr := agent.Ping(pingCtx, def, path)
	if pingErr != nil {
		details = append(details, fmt.Sprintf("ping error: %v", pingErr))
		return &AgentCheck{
			Status:   StatusWarning,
			Name:     name,
			Binary:   path,
			Protocol: def.EffectiveProtocol(),
			Message:  fmt.Sprintf("binary found but agent not responding: %v", pingErr),
			Details:  details,
		}
	}

	details = append(details, fmt.Sprintf("ping response: %s", truncate(pingResp, 80)))
	return &AgentCheck{
		Status:       StatusOK,
		Name:         name,
		Binary:       path,
		Protocol:     def.EffectiveProtocol(),
		PingResponse: truncate(pingResp, 200),
		Details:      details,
	}
}

func checkBrowser(settings *config.Settings) *CheckResult {
	details := []string{"checking agent.browser.enabled in config"}

	if !settings.Agent.Browser.IsEnabled() {
		return &CheckResult{Status: StatusWarning, Message: "disabled in config", Details: details}
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

	matches, _ := filepath.Glob(filepath.Join(dir, "**", "*.md"))
	topLevel, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	count := len(matches) + len(topLevel)

	details = append(details, fmt.Sprintf("found %d template files", count))
	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("path=%s, templates=%d", config.ContractPath(dir), count),
		Details: details,
	}
}

// nucleiTemplatesDir resolves the nuclei templates directory from settings or default.
func nucleiTemplatesDir(settings *config.Settings) string {
	dir := settings.KnownIssueScan.TemplatesDir
	if dir == "" {
		return config.ExpandPath("~/nuclei-templates")
	}
	return config.ExpandPath(dir)
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

// truncate shortens a string to maxLen, appending "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

func computeOverallStatus(r *Report) Status {
	hasCriticalError := false
	hasWarningOrNonCritical := false

	// Database and agent are critical
	if r.Database != nil && r.Database.Status == StatusError {
		hasCriticalError = true
	}
	if r.Agent != nil && r.Agent.Status == StatusError {
		hasCriticalError = true
	}

	if hasCriticalError {
		return "not_ready"
	}

	// Check all non-critical for warnings/errors
	checks := []*CheckResult{r.Browser, r.TemplatesDir, r.NucleiTemplates}
	if r.Queue != nil {
		checks = append(checks, r.Queue)
	}
	for _, c := range checks {
		if c != nil && (c.Status == StatusWarning || c.Status == StatusError) {
			hasWarningOrNonCritical = true
		}
	}
	for _, t := range r.Tools {
		if t != nil && (t.Status == StatusWarning || t.Status == StatusError) {
			hasWarningOrNonCritical = true
		}
	}

	if hasWarningOrNonCritical {
		return "degraded"
	}
	return "ready"
}
