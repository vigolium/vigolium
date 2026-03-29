package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// cancelGracePeriod is how long Cancel waits for SIGTERM before escalating to SIGKILL.
const cancelGracePeriod = 10 * time.Second

// AuditAgentRunner manages a vig-audit-agent running as a background Claude Code process.
// It launches the agent, periodically syncs audit-state.json to the vigolium session dir,
// and ingests findings into the database when complete.
type AuditAgentRunner struct {
	cfg  AuditAgentConfig
	repo *database.Repository

	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	err       error
	cancelled bool
}

// AuditAgentConfig configures a background audit agent run.
type AuditAgentConfig struct {
	PluginDir   string
	Mode        string // "full" or "lite"
	SourcePath  string
	SessionDir  string
	ProjectUUID string
	ScanUUID    string

	SyncInterval time.Duration // how often to sync audit-state.json (default: 30s)
	StreamWriter io.Writer     // optional: stream audit output in real-time
}

// AuditState represents the vig-audit-agent's audit-state.json structure.
type AuditState struct {
	Audits []AuditEntry `json:"audits"`
}

type AuditEntry struct {
	AuditID     string                    `json:"audit_id"`
	Commit      string                    `json:"commit"`
	Branch      string                    `json:"branch"`
	StartedAt   string                    `json:"started_at"`
	CompletedAt *string                   `json:"completed_at"`
	Status      string                    `json:"status"`
	Mode        string                    `json:"mode"`
	Phases      map[string]AuditPhaseInfo `json:"phases"`
}

type AuditPhaseInfo struct {
	Status      string  `json:"status"`
	CompletedAt *string `json:"completed_at,omitempty"`
}

// AuditFinding represents a parsed finding from a markdown file.
type AuditFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// AuditAgentStatus summarizes the current state of the background audit.
type AuditAgentStatus struct {
	Running         bool   `json:"running"`
	Status          string `json:"status"`
	Mode            string `json:"mode"`
	Phase           string `json:"current_phase"`
	CompletedPhases int    `json:"completed_phases"`
	TotalPhases     int    `json:"total_phases"`
}

// NewAuditAgentRunner creates a new runner for the background audit agent.
func NewAuditAgentRunner(cfg AuditAgentConfig, repo *database.Repository) *AuditAgentRunner {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	return &AuditAgentRunner{
		cfg:  cfg,
		repo: repo,
		done: make(chan struct{}),
	}
}

// Start launches the vig-audit-agent as a background Claude Code process.
func (r *AuditAgentRunner) Start(ctx context.Context) error {
	pluginDir := r.cfg.PluginDir
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		extracted, extractErr := ExtractAuditAgentPlugin()
		if extractErr != nil {
			return fmt.Errorf("audit agent plugin not found at %s and extraction failed: %w", pluginDir, extractErr)
		}
		if extracted != "" {
			pluginDir = extracted
		}
		if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
			return fmt.Errorf("audit agent plugin directory not found: %s (set agent.audit_agent.plugin_dir)", pluginDir)
		}
	}

	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return fmt.Errorf("claude CLI not found in PATH: %w", err)
	}

	command := "/vig-run:lite"
	if r.cfg.Mode == "full" {
		command = "/vig-run:run"
	}

	args := []string{
		"--print",
		"--dangerously-skip-permissions",
		"--plugin-dir", pluginDir,
		"-p", command,
	}

	zap.L().Info("Starting background audit agent",
		zap.String("plugin_dir", pluginDir),
		zap.String("mode", r.cfg.Mode),
		zap.String("source", r.cfg.SourcePath),
		zap.String("command", command))

	cmd := exec.CommandContext(ctx, claudePath, args...)
	cmd.Dir = r.cfg.SourcePath
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var outputBuf syncBuffer
	if r.cfg.StreamWriter != nil {
		cmd.Stdout = io.MultiWriter(&outputBuf, r.cfg.StreamWriter)
	} else {
		cmd.Stdout = &outputBuf
	}
	cmd.Stderr = &outputBuf

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start audit agent: %w", err)
	}

	r.mu.Lock()
	r.cmd = cmd
	r.mu.Unlock()

	go r.monitor(ctx, cmd, &outputBuf)
	go r.syncLoop(ctx)

	return nil
}

func (r *AuditAgentRunner) monitor(ctx context.Context, cmd *exec.Cmd, output *syncBuffer) {
	defer close(r.done)

	err := cmd.Wait()

	r.mu.Lock()
	r.err = err
	r.mu.Unlock()

	if err != nil {
		if r.cancelled {
			zap.L().Info("Audit agent cancelled")
		} else {
			zap.L().Warn("Audit agent process exited with error", zap.Error(err))
		}
	} else {
		zap.L().Info("Audit agent completed successfully")
	}

	r.syncStateOnce()
	r.ingestFindings(ctx)

	if r.cfg.SessionDir != "" {
		outputPath := filepath.Join(r.cfg.SessionDir, "audit-agent-output.txt")
		if writeErr := os.WriteFile(outputPath, output.Bytes(), 0o644); writeErr != nil {
			zap.L().Debug("Failed to save audit agent output", zap.Error(writeErr))
		}
	}
}

func (r *AuditAgentRunner) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.done:
			return
		case <-ticker.C:
			r.syncStateOnce()
		}
	}
}

func (r *AuditAgentRunner) syncStateOnce() {
	if r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}

	src := filepath.Join(r.cfg.SourcePath, "security", "audit-state.json")
	data, err := os.ReadFile(src)
	if err != nil {
		return // file may not exist yet
	}

	destDir := filepath.Join(r.cfg.SessionDir, "audit-agent")
	_ = os.MkdirAll(destDir, 0o755)
	dest := filepath.Join(destDir, "audit-state.json")
	if writeErr := os.WriteFile(dest, data, 0o644); writeErr != nil {
		zap.L().Debug("Failed to sync audit state", zap.Error(writeErr))
	}
}

// ingestFindings reads findings from the security/findings/ directory, stores them in the
// database, and copies them to the session dir. Each file is read once and reused for both.
func (r *AuditAgentRunner) ingestFindings(ctx context.Context) {
	findingsDir := filepath.Join(r.cfg.SourcePath, "security", "findings")
	entries, err := os.ReadDir(findingsDir)
	if err != nil {
		zap.L().Debug("No audit findings directory found", zap.String("path", findingsDir))
		return
	}

	// Prepare session dir for copies
	var destDir string
	if r.cfg.SessionDir != "" {
		destDir = filepath.Join(r.cfg.SessionDir, "audit-agent", "findings")
		_ = os.MkdirAll(destDir, 0o755)
	}

	var ingested int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join(findingsDir, entry.Name())
		data, readErr := os.ReadFile(srcPath)
		if readErr != nil {
			continue
		}

		// Copy to session dir (all files, not just .md)
		if destDir != "" {
			_ = os.WriteFile(filepath.Join(destDir, entry.Name()), data, 0o644)
		}

		// Only parse and ingest .md files
		if !strings.HasSuffix(entry.Name(), ".md") || r.repo == nil {
			continue
		}

		finding, parseErr := parseAuditFindingContent(entry.Name(), data)
		if parseErr != nil {
			zap.L().Debug("Failed to parse audit finding", zap.String("file", entry.Name()), zap.Error(parseErr))
			continue
		}

		dbFinding := &database.Finding{
			ProjectUUID:   r.cfg.ProjectUUID,
			ScanUUID:      r.cfg.ScanUUID,
			ModuleID:      "audit-agent",
			ModuleName:    finding.Title,
			FindingSource: "audit-agent",
			Severity:      normalizeSeverity(finding.Severity),
			Confidence:    "high",
			Description:   finding.Description,
			Remediation:   finding.Remediation,
			Tags:          []string{"audit-agent", finding.CWE},
		}

		if err := r.repo.SaveFindingDirect(ctx, dbFinding); err != nil {
			zap.L().Debug("Failed to save audit finding", zap.String("title", finding.Title), zap.Error(err))
			continue
		}
		ingested++
	}

	if ingested > 0 {
		zap.L().Info("Ingested audit agent findings", zap.Int("count", ingested))
	}
}

// Wait blocks until the audit agent finishes.
func (r *AuditAgentRunner) Wait() error {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Done returns a channel that closes when the audit agent finishes.
func (r *AuditAgentRunner) Done() <-chan struct{} {
	return r.done
}

// Cancel stops the audit agent process. Sends SIGTERM first, then SIGKILL after a grace period.
func (r *AuditAgentRunner) Cancel() {
	r.mu.Lock()
	r.cancelled = true
	cmd := r.cmd
	r.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)

	// Wait for graceful exit or escalate to SIGKILL
	select {
	case <-r.done:
		return
	case <-time.After(cancelGracePeriod):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// Status returns a summary of the current audit state.
func (r *AuditAgentRunner) Status() *AuditAgentStatus {
	state := r.readCurrentState()
	if state == nil || len(state.Audits) == 0 {
		return &AuditAgentStatus{Running: r.isRunning(), Phase: "initializing"}
	}

	latest := state.Audits[len(state.Audits)-1]
	completedPhases := 0
	totalPhases := len(latest.Phases)
	currentPhase := ""

	for id, phase := range latest.Phases {
		if phase.Status == "complete" {
			completedPhases++
		}
		if phase.Status == "in_progress" {
			currentPhase = id
		}
	}

	return &AuditAgentStatus{
		Running:         r.isRunning(),
		Status:          latest.Status,
		Mode:            latest.Mode,
		Phase:           currentPhase,
		CompletedPhases: completedPhases,
		TotalPhases:     totalPhases,
	}
}

func (r *AuditAgentRunner) isRunning() bool {
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

func (r *AuditAgentRunner) readCurrentState() *AuditState {
	src := filepath.Join(r.cfg.SourcePath, "security", "audit-state.json")
	data, err := os.ReadFile(src)
	if err != nil {
		return nil
	}
	var state AuditState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	return &state
}

// ParseAuditFinding reads and parses a finding file from disk.
func ParseAuditFinding(path string) (*AuditFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseAuditFindingContent(filepath.Base(path), data)
}

// parseAuditFindingContent parses finding metadata from markdown content.
// Severity is derived from the filename prefix (C-, H-, M-, L-, I-).
func parseAuditFindingContent(filename string, data []byte) (*AuditFinding, error) {
	content := string(data)
	finding := &AuditFinding{
		ID: strings.TrimSuffix(filename, filepath.Ext(filename)),
	}

	switch {
	case strings.HasPrefix(filename, "C-"):
		finding.Severity = "critical"
	case strings.HasPrefix(filename, "H-"):
		finding.Severity = "high"
	case strings.HasPrefix(filename, "M-"):
		finding.Severity = "medium"
	case strings.HasPrefix(filename, "L-"):
		finding.Severity = "low"
	case strings.HasPrefix(filename, "I-"):
		finding.Severity = "info"
	default:
		finding.Severity = "medium"
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			finding.Title = strings.TrimPrefix(line, "# ")
			break
		}
		if strings.HasPrefix(line, "## ") && finding.Title == "" {
			finding.Title = strings.TrimPrefix(line, "## ")
		}
	}

	if finding.Title == "" {
		finding.Title = finding.ID
	}

	finding.Description = content
	if len(finding.Description) > 10000 {
		finding.Description = finding.Description[:10000] + "\n\n[truncated]"
	}

	return finding, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "medium"
	}
}

// syncBuffer is a thread-safe buffer for capturing process output.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, len(b.buf))
	copy(cp, b.buf)
	return cp
}

// StartAuditAgent creates and starts a background audit agent.
// Returns nil runner when disabled or no source path.
func StartAuditAgent(ctx context.Context, agentCfg config.AuditAgentConfig, sourcePath, sessionDir, projectUUID, scanUUID string, repo *database.Repository) (*AuditAgentRunner, error) {
	if !agentCfg.IsEnabled() || sourcePath == "" {
		return nil, nil
	}

	cfg := AuditAgentConfig{
		PluginDir:    agentCfg.EffectivePluginDir(),
		Mode:         agentCfg.EffectiveMode(),
		SourcePath:   sourcePath,
		SessionDir:   sessionDir,
		ProjectUUID:  projectUUID,
		ScanUUID:     scanUUID,
		SyncInterval: time.Duration(agentCfg.EffectiveSyncInterval()) * time.Second,
	}

	runner := NewAuditAgentRunner(cfg, repo)
	if err := runner.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start audit agent: %w", err)
	}

	return runner, nil
}

// startAuditAgentBackground is a shared helper that starts the audit agent and returns
// a cleanup function to defer. Logs startup success/failure via the provided logFn.
// Returns nil cleanup when the audit agent is not started.
func startAuditAgentBackground(ctx context.Context, auditCfg *config.AuditAgentConfig, sourcePath, sessionDir, projectUUID, scanUUID string, repo *database.Repository, logFn func(msg string)) func() {
	if auditCfg == nil || !auditCfg.IsEnabled() || sourcePath == "" {
		return nil
	}

	runner, err := StartAuditAgent(ctx, *auditCfg, sourcePath, sessionDir, projectUUID, scanUUID, repo)
	if err != nil {
		zap.L().Warn("Failed to start background audit agent, continuing without it", zap.Error(err))
		if logFn != nil {
			logFn(fmt.Sprintf("audit agent failed to start: %v", err))
		}
		return nil
	}
	if runner == nil {
		return nil
	}

	if logFn != nil {
		logFn(fmt.Sprintf("background audit started (%s mode)", auditCfg.EffectiveMode()))
	}

	return func() {
		if runner.isRunning() {
			runner.Cancel()
			<-runner.Done()
		}
		if status := runner.Status(); status != nil && logFn != nil {
			logFn(fmt.Sprintf("%d/%d phases completed (status: %s)", status.CompletedPhases, status.TotalPhases, status.Status))
		}
	}
}

// ResolveAuditAgentConfig merges a CLI/API flag value with the YAML config.
// Returns nil when the audit agent should not run.
//
// Flag values: "" (use config default), "lite", "full", "off" (force disable).
func ResolveAuditAgentConfig(flag string, agentCfg config.AuditAgentConfig) *config.AuditAgentConfig {
	if flag == "off" {
		return nil
	}
	if flag != "" {
		enabled := true
		return &config.AuditAgentConfig{
			Enable:       &enabled,
			PluginDir:    agentCfg.PluginDir,
			Mode:         flag,
			SyncInterval: agentCfg.SyncInterval, // preserve YAML sync_interval
		}
	}
	if agentCfg.IsEnabled() {
		cfg := agentCfg
		return &cfg
	}
	return nil
}
