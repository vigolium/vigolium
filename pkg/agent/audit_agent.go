package agent

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/archon/claudestream"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// cancelGracePeriod is how long Cancel waits for SIGTERM before escalating to SIGKILL.
const cancelGracePeriod = 10 * time.Second

// AuditAgentRunner manages an archon-audit running as a background agent process.
// It launches the agent (Claude, Codex, or OpenCode), periodically syncs audit-state.json
// and findings to the vigolium session dir, and imports findings into the database when complete.
type AuditAgentRunner struct {
	cfg  AuditAgentConfig
	repo *database.Repository

	agentRunUUID string // UUID of the child AgentRun record tracking this audit

	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	err       error
	cancelled bool

	lastStateHash string           // cached hash for change detection in syncLoop
	syncedFiles   map[string]int64 // filename → size, for incremental sync

	// Populated by importArchonFindings after monitor() completes.
	findingStats FindingStats
}

// FindingStats summarises the archon findings imported by a single audit run.
type FindingStats struct {
	Parsed     int            // total findings parsed from the session dir
	Saved      int            // findings successfully persisted to the database
	BySeverity map[string]int // count by normalized severity (critical/high/medium/low/info)
}

// SeverityBreakdownString renders a colored "critical:N  high:N  ..." string in
// descending severity order. Buckets with zero count are skipped. Returns ""
// when no findings were counted.
func (s FindingStats) SeverityBreakdownString() string {
	order := []struct {
		name  string
		color func(string) string
	}{
		{"critical", terminal.Red},
		{"high", terminal.Orange},
		{"medium", terminal.Yellow},
		{"low", terminal.Cyan},
		{"info", terminal.Gray},
	}
	var parts []string
	for _, b := range order {
		if n := s.BySeverity[b.name]; n > 0 {
			parts = append(parts, b.color(fmt.Sprintf("%s:%d", b.name, n)))
		}
	}
	return strings.Join(parts, "  ")
}

// NewAuditAgentRunner creates a new runner for the background archon-audit.
func NewAuditAgentRunner(cfg AuditAgentConfig, repo *database.Repository) *AuditAgentRunner {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	return &AuditAgentRunner{
		cfg:          cfg,
		repo:         repo,
		agentRunUUID: uuid.New().String(),
		done:         make(chan struct{}),
		syncedFiles:  make(map[string]int64),
	}
}

// Start launches archon-audit as a background agent process.
// The platform field determines which CLI binary and args are used.
func (r *AuditAgentRunner) Start(ctx context.Context) error {
	platform := r.cfg.Platform
	if platform == "" {
		platform = archon.PlatformClaude
	}

	pluginDir := r.cfg.PluginDir
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		extracted, extractErr := ExtractArchonPluginForPlatform(platform)
		if extractErr != nil {
			return fmt.Errorf("archon harness not found at %s and extraction failed: %w", pluginDir, extractErr)
		}
		if extracted != "" {
			pluginDir = extracted
		}
		if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
			return fmt.Errorf("archon harness directory not found: %s (set agent.archon.plugin_dir)", pluginDir)
		}
	}

	// Stream-json rendering is Claude-only; other platforms ignore it.
	streamJSON := r.cfg.Stream && platform == archon.PlatformClaude && r.cfg.StreamWriter != nil

	binary, args, stdinPrompt, err := buildAuditAgentCommand(platform, pluginDir, r.cfg.Mode, r.cfg.SourcePath, streamJSON)
	if err != nil {
		return err
	}

	// Build readable command line for console output
	var cmdLine strings.Builder
	cmdLine.WriteString(binary)
	for _, a := range args {
		cmdLine.WriteByte(' ')
		if strings.ContainsAny(a, " \t\n'\"\\") {
			cmdLine.WriteString("'" + strings.ReplaceAll(a, "'", "'\\''") + "'")
		} else {
			cmdLine.WriteString(a)
		}
	}
	zap.L().Debug("starting background archon-audit",
		zap.String("cmd", cmdLine.String()),
		zap.String("platform", platform),
		zap.String("plugin_dir", pluginDir),
		zap.String("mode", r.cfg.Mode),
		zap.String("source", r.cfg.SourcePath))

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = r.cfg.SourcePath
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if stdinPrompt != "" {
		cmd.Stdin = strings.NewReader(stdinPrompt)
	}

	var outputBuf syncBuffer
	var streamPipe io.ReadCloser
	var streamRawLog *os.File

	if streamJSON {
		// Claude stream-json: decode via claudestream, tee raw JSONL to session dir,
		// and still capture into outputBuf for the fallback-output path in monitor().
		pipe, pipeErr := cmd.StdoutPipe()
		if pipeErr != nil {
			return fmt.Errorf("stdout pipe: %w", pipeErr)
		}
		streamPipe = pipe

		if r.cfg.SessionDir != "" {
			rawPath := filepath.Join(r.cfg.SessionDir, "audit-stream.jsonl")
			_ = os.MkdirAll(filepath.Dir(rawPath), 0o755)
			if f, err := os.OpenFile(rawPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				streamRawLog = f
			} else {
				zap.L().Debug("Failed to open audit-stream.jsonl", zap.Error(err))
			}
		}
	} else if r.cfg.StreamWriter != nil {
		cmd.Stdout = io.MultiWriter(&outputBuf, r.cfg.StreamWriter)
	} else {
		cmd.Stdout = &outputBuf
	}
	cmd.Stderr = &outputBuf

	if err := cmd.Start(); err != nil {
		if streamRawLog != nil {
			_ = streamRawLog.Close()
		}
		return fmt.Errorf("failed to start archon-audit: %w", err)
	}

	r.mu.Lock()
	r.cmd = cmd
	r.mu.Unlock()

	// Launch the stream-json decoder goroutine now that the child has started.
	if streamJSON {
		go func() {
			defer func() {
				if streamRawLog != nil {
					_ = streamRawLog.Close()
				}
			}()
			opts := claudestream.Options{}
			if streamRawLog != nil {
				opts.RawLog = io.MultiWriter(&outputBuf, streamRawLog)
			} else {
				opts.RawLog = &outputBuf
			}
			if err := claudestream.Stream(streamPipe, r.cfg.StreamWriter, opts); err != nil {
				zap.L().Debug("claudestream decoder exited with error", zap.Error(err))
			}
		}()
	}

	// Create child AgentRun record
	r.createAgentRun(ctx)

	go r.monitor(ctx, cmd, &outputBuf)
	go r.syncLoop(ctx)

	return nil
}

func (r *AuditAgentRunner) createAgentRun(ctx context.Context) {
	if r.repo == nil {
		return
	}
	run := &database.AgentRun{
		UUID:          r.agentRunUUID,
		ProjectUUID:   r.cfg.ProjectUUID,
		ScanUUID:      r.cfg.ScanUUID,
		Mode:          "archon",
		AgentName:     "archon-audit",
		InputType:     "archon",
		Status:        "running",
		CurrentPhase:  "initializing",
		SourcePath:    r.cfg.SourcePath,
		ParentRunUUID: r.cfg.ParentRunUUID,
		StartedAt:     time.Now(),
	}
	if err := r.repo.CreateAgentRun(ctx, run); err != nil {
		zap.L().Debug("Failed to create archon AgentRun", zap.Error(err))
	}
}

func (r *AuditAgentRunner) monitor(ctx context.Context, cmd *exec.Cmd, output *syncBuffer) {
	defer close(r.done)

	err := cmd.Wait()

	r.mu.Lock()
	r.err = err
	r.mu.Unlock()

	if err != nil {
		if r.cancelled {
			zap.L().Info("Archon audit cancelled")
		} else {
			zap.L().Warn("Archon audit process exited with error", zap.Error(err))
		}
	} else {
		zap.L().Info("Archon audit completed successfully")
	}

	// Final sync and import
	r.syncFolderFull()
	r.importArchonFindings(ctx)

	// Cleanup: remove archon/ dir from source since we have a copy in session
	archonDir := filepath.Join(r.cfg.SourcePath, "archon")
	if _, statErr := os.Stat(archonDir); statErr == nil {
		if rmErr := os.RemoveAll(archonDir); rmErr != nil {
			zap.L().Debug("Failed to cleanup archon dir from source", zap.Error(rmErr))
		} else {
			zap.L().Info("Cleaned up archon dir from source", zap.String("path", archonDir))
		}
	}

	// Save raw output
	if r.cfg.SessionDir != "" {
		outputPath := filepath.Join(r.cfg.SessionDir, "archon-audit-output.md")
		rawOutput := output.Bytes()

		// If stdout buffer is empty (process killed before --print flushed),
		// fall back to reading key archon output files from the synced session dir.
		if len(rawOutput) == 0 {
			rawOutput = r.collectFallbackOutput()
		}

		if len(rawOutput) > 0 {
			if writeErr := os.WriteFile(outputPath, rawOutput, 0o644); writeErr != nil {
				zap.L().Debug("Failed to save archon audit output", zap.Error(writeErr))
			}
		}
	}

	// Update AgentRun as completed/failed
	r.finalizeAgentRun(ctx, err)
}

// collectFallbackOutput reads key archon output files from the synced session
// directory and concatenates them. Used when the process was killed before
// stdout was flushed (e.g. --print mode with early cancellation).
func (r *AuditAgentRunner) collectFallbackOutput() []byte {
	archonDir := filepath.Join(r.cfg.SessionDir, "archon-audit")

	// Ordered list of output files to try, covering lite through deep modes.
	candidates := []string{
		"lite-recon.md",
		"commit-recon-report.md",
		"knowledge-base-report.md",
		"enrichment-report.md",
		"spec-gap-report.md",
		"advisory-report.md",
		"final-audit-report.md",
	}

	var parts [][]byte
	for _, name := range candidates {
		data, err := os.ReadFile(filepath.Join(archonDir, name))
		if err != nil || len(data) == 0 {
			continue
		}
		header := fmt.Sprintf("# %s\n\n", strings.TrimSuffix(name, ".md"))
		parts = append(parts, []byte(header))
		parts = append(parts, data)
		parts = append(parts, []byte("\n\n---\n\n"))
	}

	// List finding files if any exist.
	findingsDir := filepath.Join(archonDir, "findings-draft")
	if entries, err := os.ReadDir(findingsDir); err == nil {
		var findingNames []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
				findingNames = append(findingNames, e.Name())
			}
		}
		if len(findingNames) > 0 {
			sort.Strings(findingNames)
			summary := fmt.Sprintf("# Findings Draft\n\n%d finding files produced:\n", len(findingNames))
			for _, name := range findingNames {
				summary += fmt.Sprintf("- %s\n", name)
			}
			parts = append(parts, []byte(summary))
		}
	}

	if len(parts) == 0 {
		return nil
	}

	var buf []byte
	for _, p := range parts {
		buf = append(buf, p...)
	}
	return buf
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
			r.syncFindingsIncremental()
		}
	}
}

// syncStateOnce copies audit-state.json from source to session dir
// and updates the child AgentRun with current phase info.
// Skips DB updates when the state hasn't changed since last tick.
func (r *AuditAgentRunner) syncStateOnce() {
	if r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}

	src := filepath.Join(r.cfg.SourcePath, "archon", "audit-state.json")
	data, err := os.ReadFile(src)
	if err != nil {
		return // file may not exist yet
	}

	destDir := filepath.Join(r.cfg.SessionDir, "archon-audit")
	_ = os.MkdirAll(destDir, 0o755)
	dest := filepath.Join(destDir, "audit-state.json")
	if writeErr := os.WriteFile(dest, data, 0o644); writeErr != nil {
		zap.L().Debug("Failed to sync archon audit state", zap.Error(writeErr))
	}

	// Only update DB when state has changed
	hash := fmt.Sprintf("%x", md5.Sum(data))
	if hash != r.lastStateHash {
		r.lastStateHash = hash
		r.updateAgentRunProgress(data)
	}
}

// syncFindingsIncremental copies new/changed files from findings-draft/ to session dir.
// Tracks synced files by size to avoid re-copying unchanged files.
func (r *AuditAgentRunner) syncFindingsIncremental() {
	if r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}

	srcDir := filepath.Join(r.cfg.SourcePath, "archon", "findings-draft")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return
	}

	destDir := filepath.Join(r.cfg.SessionDir, "archon-audit", "findings-draft")
	_ = os.MkdirAll(destDir, 0o755)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		// Skip if already synced with same size
		if prevSize, ok := r.syncedFiles[entry.Name()]; ok && prevSize == info.Size() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcDir, entry.Name()))
		if err != nil {
			continue
		}
		if writeErr := os.WriteFile(filepath.Join(destDir, entry.Name()), data, 0o644); writeErr == nil {
			r.syncedFiles[entry.Name()] = info.Size()
		}
	}
}

// syncFolderFull copies the entire archon/ folder to session dir.
func (r *AuditAgentRunner) syncFolderFull() {
	if r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}

	srcDir := filepath.Join(r.cfg.SourcePath, "archon")
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		return
	}

	destDir := filepath.Join(r.cfg.SessionDir, "archon-audit")
	_ = os.MkdirAll(destDir, 0o755)

	copyDir(srcDir, destDir)
}

// importArchonFindings parses the archon output from session dir and imports findings.
// Populates r.findingStats so the CLI summary can report what was persisted.
func (r *AuditAgentRunner) importArchonFindings(ctx context.Context) {
	// Parse from session dir (synced copy) or fall back to source dir
	var archonDir string
	if r.cfg.SessionDir != "" {
		archonDir = filepath.Join(r.cfg.SessionDir, "archon-audit")
	} else {
		archonDir = filepath.Join(r.cfg.SourcePath, "archon")
	}

	result, err := archon.ParseAuditFolder(archonDir)
	if err != nil {
		zap.L().Debug("Failed to parse archon output for import", zap.Error(err))
		return
	}

	auditID := ""
	if len(result.State.Audits) > 0 {
		auditID = result.State.Audits[0].AuditID
	}

	findings := archon.BuildFindings(result.RawFindings, auditID, r.agentRunUUID, r.cfg.ProjectUUID, result.RepoName)

	stats := FindingStats{
		Parsed:     len(findings),
		BySeverity: make(map[string]int, len(findings)),
	}
	for _, f := range findings {
		stats.BySeverity[f.Severity]++
	}

	// Persist when a repository is available — otherwise we still want Parsed
	// and BySeverity on the runner so the CLI summary can render counts.
	if r.repo != nil {
		for _, f := range findings {
			f.ScanUUID = r.cfg.ScanUUID
			if err := r.repo.SaveFindingDirect(ctx, f); err != nil {
				continue
			}
			if f.ID > 0 {
				stats.Saved++
			}
		}
	}

	r.mu.Lock()
	r.findingStats = stats
	r.mu.Unlock()

	if stats.Parsed > 0 {
		zap.L().Info("Imported archon audit findings",
			zap.Int("parsed", stats.Parsed),
			zap.Int("saved", stats.Saved))
	}
}

// FindingStats returns the summary of findings parsed and imported by this
// audit run. Only populated after monitor() has completed.
func (r *AuditAgentRunner) FindingStats() FindingStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := r.findingStats
	if stats.BySeverity != nil {
		cp := make(map[string]int, len(stats.BySeverity))
		for k, v := range stats.BySeverity {
			cp[k] = v
		}
		stats.BySeverity = cp
	}
	return stats
}

func (r *AuditAgentRunner) updateAgentRunProgress(stateData []byte) {
	if r.repo == nil {
		return
	}

	var state archon.AuditState
	if err := json.Unmarshal(stateData, &state); err != nil || len(state.Audits) == 0 {
		return
	}

	latest := state.Audits[len(state.Audits)-1]

	var phases []string
	currentPhase := ""
	for id, phase := range latest.Phases {
		if phase.Status == "complete" {
			phases = append(phases, id)
		}
		if phase.Status == "in_progress" {
			currentPhase = id
		}
	}

	ctx := context.Background()
	run, err := r.repo.GetAgentRun(ctx, r.agentRunUUID)
	if err != nil {
		return
	}

	run.PhasesRun = phases
	run.CurrentPhase = currentPhase
	if latest.Status != "" {
		if latest.Status == "complete" {
			run.Status = "completed"
		} else {
			run.Status = "running"
		}
	}

	_ = r.repo.UpdateAgentRun(ctx, run)
}

func (r *AuditAgentRunner) finalizeAgentRun(ctx context.Context, processErr error) {
	if r.repo == nil {
		return
	}

	run, err := r.repo.GetAgentRun(ctx, r.agentRunUUID)
	if err != nil {
		return
	}

	run.CompletedAt = time.Now()
	run.DurationMs = run.CompletedAt.Sub(run.StartedAt).Milliseconds()

	switch {
	case processErr == nil:
		// Process exited cleanly — always "completed", even if Cancel() was
		// racily invoked after the process had already finished successfully.
		run.Status = "completed"
	case r.cancelled || ctx.Err() != nil:
		// Explicit cancel or parent context cancellation (SIGINT/timeout).
		run.Status = "cancelled"
	default:
		run.Status = "failed"
		run.ErrorMessage = processErr.Error()
	}

	// Load final state for result_json
	stateFile := filepath.Join(r.cfg.SessionDir, "archon-audit", "audit-state.json")
	if data, readErr := os.ReadFile(stateFile); readErr == nil {
		run.ResultJSON = string(data)
	}

	_ = r.repo.UpdateAgentRun(ctx, run)
}

// Wait blocks until the archon audit finishes.
func (r *AuditAgentRunner) Wait() error {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Done returns a channel that closes when the archon audit finishes.
func (r *AuditAgentRunner) Done() <-chan struct{} {
	return r.done
}

// Cancel stops the archon audit process. Sends SIGTERM first, then SIGKILL after a grace period.
func (r *AuditAgentRunner) Cancel() {
	r.mu.Lock()
	r.cancelled = true
	cmd := r.cmd
	r.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)

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
		Mode:            r.cfg.Mode,
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

func (r *AuditAgentRunner) readCurrentState() *archon.AuditState {
	// Try the source dir first (authoritative while the audit is running),
	// then fall back to the synced copy in the session dir. The fallback
	// matters after monitor() removes SourcePath/archon on cleanup: by the
	// time Status() is called from the CLI summary, only the session copy
	// remains.
	candidates := []string{
		filepath.Join(r.cfg.SourcePath, "archon", "audit-state.json"),
	}
	if r.cfg.SessionDir != "" {
		candidates = append(candidates, filepath.Join(r.cfg.SessionDir, "archon-audit", "audit-state.json"))
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var state archon.AuditState
		if err := json.Unmarshal(data, &state); err != nil {
			continue
		}
		return &state
	}
	return nil
}

// --- Process management helpers ---

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

// copyDir recursively copies a directory's contents. Silently skips errors.
func copyDir(src, dest string) {
	_ = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return nil
		}
		destPath := filepath.Join(dest, rel)

		if d.IsDir() {
			_ = os.MkdirAll(destPath, 0o755)
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		_ = os.MkdirAll(filepath.Dir(destPath), 0o755)
		_ = os.WriteFile(destPath, data, 0o644)
		return nil
	})
}

// --- Platform command builders ---

// buildAuditAgentCommand resolves the CLI binary and builds the argument list
// for launching archon-audit on the given platform. When stream is true and
// the platform is Claude, the command emits stream-json events on stdout so
// the caller can render a live activity feed via claudestream.
func buildAuditAgentCommand(platform, pluginDir, mode, sourcePath string, stream bool) (binary string, args []string, stdinPrompt string, err error) {
	switch platform {
	case archon.PlatformCodex:
		binary, err = exec.LookPath("codex")
		if err != nil {
			return "", nil, "", fmt.Errorf("codex CLI not found in PATH: %w", err)
		}
		// Codex uses AGENTS.md dispatch — run with the audit skill prompt.
		// The agents-dispatch.md is installed as AGENTS.md in pluginDir.
		args = []string{
			"--full-auto",
			"-C", pluginDir,
			"Run a " + mode + " security audit using the archon-audit methodology. " +
				"Follow the AGENTS.md dispatch table to spawn the correct subagents for each phase.",
		}

	case archon.PlatformOpenCode:
		binary, err = exec.LookPath("opencode")
		if err != nil {
			return "", nil, "", fmt.Errorf("opencode CLI not found in PATH: %w", err)
		}
		// OpenCode uses the same plugin structure as Claude but with its own agent format.
		command := "/archon-audit:archon:" + mode
		args = []string{
			"run",
			"--agents-dir", filepath.Join(pluginDir, "agents"),
			"-p", command,
		}

	default: // PlatformClaude
		binary, err = exec.LookPath("claude")
		if err != nil {
			return "", nil, "", fmt.Errorf("claude CLI not found in PATH: %w", err)
		}
		command := "/archon-audit:archon:" + mode
		if stream {
			args = []string{
				"--plugin-dir", pluginDir,
				"--dangerously-skip-permissions",
				"--allowedTools", "Bash,Read,Write,Edit,Glob,Grep,Agent,WebSearch,WebFetch,AskUserQuestion,TaskCreate,TaskGet,TaskList,TaskUpdate",
				"--output-format", "stream-json",
				"--verbose",
				"--include-partial-messages",
				"--print", command,
			}
		} else {
			args = []string{
				"--print",
				"--dangerously-skip-permissions",
				"--plugin-dir", pluginDir,
				"--allowedTools", "Bash,Read,Write,Edit,Glob,Grep,Agent,WebSearch,WebFetch,AskUserQuestion,TaskCreate,TaskGet,TaskList,TaskUpdate",
				command,
			}
		}
	}

	return binary, args, stdinPrompt, nil
}

// --- Public API ---

// StartAuditAgent creates and starts a background archon-audit.
// Returns nil runner when disabled or no source path.
// When streamWriter is non-nil, audit output is streamed in real-time; for
// the Claude platform this enables stream-json rendering via claudestream.
func StartAuditAgent(ctx context.Context, agentCfg config.AuditAgentConfig, sourcePath, sessionDir, projectUUID, scanUUID, parentRunUUID string, repo *database.Repository, streamWriter io.Writer) (*AuditAgentRunner, error) {
	if !agentCfg.IsEnabled() || sourcePath == "" {
		return nil, nil
	}

	cfg := AuditAgentConfig{
		PluginDir:     agentCfg.EffectivePluginDir(),
		Mode:          agentCfg.EffectiveMode(),
		Platform:      agentCfg.EffectivePlatform(),
		SourcePath:    sourcePath,
		SessionDir:    sessionDir,
		ProjectUUID:   projectUUID,
		ScanUUID:      scanUUID,
		ParentRunUUID: parentRunUUID,
		SyncInterval:  time.Duration(agentCfg.EffectiveSyncInterval()) * time.Second,
		StreamWriter:  streamWriter,
		Stream:        streamWriter != nil,
	}

	runner := NewAuditAgentRunner(cfg, repo)
	if err := runner.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start archon-audit: %w", err)
	}

	return runner, nil
}

// startAuditAgentBackground is a shared helper that starts the archon-audit and returns
// the runner and a cleanup function. Logs startup success/failure via the provided logFn.
// Returns nil runner and nil cleanup when the audit agent is not started.
// When streamWriter is non-nil, audit output is streamed live (same rendering
// as the standalone `vigolium agent archon` command).
func startAuditAgentBackground(ctx context.Context, auditCfg *config.AuditAgentConfig, sourcePath, sessionDir, projectUUID, scanUUID, parentRunUUID string, repo *database.Repository, streamWriter io.Writer, logFn func(msg string)) (*AuditAgentRunner, func()) {
	if auditCfg == nil || !auditCfg.IsEnabled() || sourcePath == "" {
		return nil, nil
	}

	// Clean up stale archon/ dir from a previous crashed run.
	// Safe: no new archon-audit is running yet at this point.
	staleArchonDir := filepath.Join(sourcePath, "archon")
	if info, statErr := os.Stat(staleArchonDir); statErr == nil && info.IsDir() {
		zap.L().Info("Removing stale archon dir from previous run", zap.String("path", staleArchonDir))
		if rmErr := os.RemoveAll(staleArchonDir); rmErr != nil {
			zap.L().Warn("Failed to remove stale archon dir", zap.Error(rmErr))
		} else if logFn != nil {
			logFn("cleaned up stale archon/ dir from previous run")
		}
	}

	runner, err := StartAuditAgent(ctx, *auditCfg, sourcePath, sessionDir, projectUUID, scanUUID, parentRunUUID, repo, streamWriter)
	if err != nil {
		zap.L().Warn("Failed to start background archon-audit, continuing without it", zap.Error(err))
		if logFn != nil {
			logFn(fmt.Sprintf("archon-audit failed to start: %v", err))
		}
		return nil, nil
	}
	if runner == nil {
		return nil, nil
	}

	if logFn != nil {
		logFn(fmt.Sprintf("started (%s mode)", auditCfg.EffectiveMode()))
	}

	// wait blocks until the archon runner's monitor goroutine has fully exited.
	// Callers use this to wait for a parallel archon-audit to finish naturally —
	// do NOT call Cancel() here or a fast-finishing parent pipeline would abort
	// a still-running archon and mark it as "cancelled" in the DB. When the
	// parent ctx is cancelled (SIGINT/timeout), exec.CommandContext already
	// kills the subprocess and the monitor will complete on its own.
	wait := func() {
		<-runner.Done()
	}
	return runner, wait
}

// ResolveAuditAgentConfig determines whether archon-audit should run.
// Archon is enabled by default when source code is available. Pass noArchon=true
// to force-disable it (--no-archon flag). The mode defaults to "lite" when empty.
// Returns nil when the audit agent should not run.
func ResolveAuditAgentConfig(noArchon bool, mode string, sourcePath string, agentCfg config.AuditAgentConfig) *config.AuditAgentConfig {
	// Explicit disable
	if noArchon {
		return nil
	}
	// No source code — archon has nothing to audit
	if sourcePath == "" {
		return nil
	}
	// Source is provided and not disabled: always enabled
	effectiveMode := mode
	if effectiveMode == "" {
		effectiveMode = agentCfg.EffectiveMode()
	}
	if effectiveMode == "" {
		effectiveMode = "lite"
	}
	// Validate mode
	if !isValidArchonMode(effectiveMode) {
		zap.L().Warn("Invalid archon mode, falling back to lite", zap.String("mode", effectiveMode))
		effectiveMode = "lite"
	}
	enabled := true
	return &config.AuditAgentConfig{
		Enable:       &enabled,
		PluginDir:    agentCfg.PluginDir,
		Mode:         effectiveMode,
		Platform:     agentCfg.Platform,
		SyncInterval: agentCfg.SyncInterval,
	}
}

// isValidArchonMode returns true for recognized archon audit modes.
func isValidArchonMode(mode string) bool {
	switch mode {
	case "lite", "scan", "deep", "mock":
		return true
	default:
		return false
	}
}
