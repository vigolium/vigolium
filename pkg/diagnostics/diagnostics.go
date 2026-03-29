package diagnostics

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/internal/config"
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
	Status  Status `json:"status"`
	Message string `json:"message,omitempty"`
}

// AgentCheck holds the outcome of the agent backend check.
type AgentCheck struct {
	Status   Status `json:"status"`
	Name     string `json:"name"`
	Binary   string `json:"binary,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Message  string `json:"message,omitempty"`
}

// ToolCheck holds the outcome of a third-party tool check.
type ToolCheck struct {
	Status  Status `json:"status"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message,omitempty"`
}

// Report is the complete diagnostic report.
type Report struct {
	Status       Status                `json:"status"` // "ready", "degraded", "not_ready"
	Timestamp    string                `json:"timestamp"`
	Database     *CheckResult          `json:"database"`
	Queue        *CheckResult          `json:"queue,omitempty"`
	Agent        *AgentCheck           `json:"agent"`
	Browser      *CheckResult          `json:"browser"`
	Tools        map[string]*ToolCheck `json:"tools"`
	TemplatesDir *CheckResult          `json:"templates_dir"`
	SessionsDir  *CheckResult          `json:"sessions_dir"`
}

// Deps provides the dependencies needed to run diagnostics.
// All fields are optional — nil values are handled gracefully.
type Deps struct {
	DB       *database.DB
	Queue    queue.Queue
	Settings *config.Settings
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
	r.Agent = checkAgent(settings)
	r.Browser = checkBrowser(settings)
	r.Tools["ast-grep"] = checkTool("ast-grep", nil)
	r.Tools["chromium"] = checkTool("chromium", []string{"chromium-browser", "google-chrome", "google-chrome-stable"})
	r.TemplatesDir = checkTemplatesDir(settings)
	r.SessionsDir = checkSessionsDir(settings)

	r.Status = computeOverallStatus(r)
	return r
}

func checkDatabase(db *database.DB) *CheckResult {
	if db == nil {
		return &CheckResult{Status: StatusError, Message: "not configured"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return &CheckResult{Status: StatusError, Message: fmt.Sprintf("ping failed: %v", err)}
	}

	return &CheckResult{Status: StatusOK, Message: fmt.Sprintf("driver=%s", db.Driver())}
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
	name := settings.Agent.DefaultAgent
	if name == "" {
		return &AgentCheck{Status: StatusError, Name: "(none)", Message: "no default agent configured"}
	}

	def, ok := settings.Agent.Backends[name]
	if !ok {
		return &AgentCheck{Status: StatusError, Name: name, Message: "agent not found in backends config"}
	}

	if !def.IsEnabled() {
		return &AgentCheck{Status: StatusError, Name: name, Message: "agent is disabled"}
	}

	cmd := def.Command
	if cmd == "" {
		cmd = "claude" // default for SDK protocol
	}

	path, err := exec.LookPath(cmd)
	if err != nil {
		return &AgentCheck{
			Status:   StatusError,
			Name:     name,
			Protocol: def.EffectiveProtocol(),
			Message:  fmt.Sprintf("%q not found in PATH", cmd),
		}
	}

	return &AgentCheck{
		Status:   StatusOK,
		Name:     name,
		Binary:   path,
		Protocol: def.EffectiveProtocol(),
	}
}

func checkBrowser(settings *config.Settings) *CheckResult {
	if !settings.Agent.Browser.IsEnabled() {
		return &CheckResult{Status: StatusWarning, Message: "disabled in config"}
	}

	bin := settings.Agent.Browser.EffectiveBinaryPath()
	path, err := exec.LookPath(bin)
	if err != nil {
		return &CheckResult{Status: StatusError, Message: fmt.Sprintf("%q not found in PATH", bin)}
	}

	return &CheckResult{Status: StatusOK, Message: path}
}

func checkTool(name string, fallbacks []string) *ToolCheck {
	candidates := append([]string{name}, fallbacks...)
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return &ToolCheck{Status: StatusOK, Path: path}
		}
	}

	return &ToolCheck{Status: StatusWarning, Message: "not found in PATH"}
}

func checkTemplatesDir(settings *config.Settings) *CheckResult {
	dir := settings.Agent.TemplatesDir
	if dir == "" {
		dir = "~/.vigolium/prompts/"
	}
	dir = config.ExpandPath(dir)

	info, err := os.Stat(dir)
	if err != nil {
		return &CheckResult{Status: StatusWarning, Message: fmt.Sprintf("directory not found: %s", dir)}
	}
	if !info.IsDir() {
		return &CheckResult{Status: StatusWarning, Message: fmt.Sprintf("not a directory: %s", dir)}
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "**", "*.md"))
	topLevel, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	count := len(matches) + len(topLevel)

	return &CheckResult{
		Status:  StatusOK,
		Message: fmt.Sprintf("path=%s, templates=%d", config.ContractPath(dir), count),
	}
}

func checkSessionsDir(settings *config.Settings) *CheckResult {
	dir := settings.Agent.EffectiveSessionsDir()

	info, err := os.Stat(dir)
	if err != nil {
		return &CheckResult{Status: StatusWarning, Message: fmt.Sprintf("directory not found: %s", config.ContractPath(dir))}
	}
	if !info.IsDir() {
		return &CheckResult{Status: StatusWarning, Message: fmt.Sprintf("not a directory: %s", config.ContractPath(dir))}
	}

	// Check writable by creating a temp file
	tmp := filepath.Join(dir, ".vigolium-doctor-probe")
	if err := os.WriteFile(tmp, []byte("probe"), 0600); err != nil {
		return &CheckResult{Status: StatusWarning, Message: fmt.Sprintf("not writable: %s", config.ContractPath(dir))}
	}
	os.Remove(tmp)

	return &CheckResult{Status: StatusOK, Message: fmt.Sprintf("path=%s, writable=true", config.ContractPath(dir))}
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
	checks := []*CheckResult{r.Browser, r.TemplatesDir, r.SessionsDir}
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
