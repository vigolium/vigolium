package agent

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/archon/claudecost"
	"github.com/vigolium/vigolium/pkg/archon/claudestream"
	"github.com/vigolium/vigolium/pkg/archon/codexcost"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// cancelGracePeriod is how long Cancel waits for SIGTERM before escalating to SIGKILL.
const cancelGracePeriod = 10 * time.Second

// archonProtocolForPlatform maps the platform onto the AgenticScan protocol
// vocabulary. Archon audit always shells out to a tool-using SDK CLI, so
// these are all SDK-flavored protocols.
func archonProtocolForPlatform(platform string) string {
	switch platform {
	case archon.PlatformCodex:
		return "codex-sdk"
	case archon.PlatformOpenCode:
		return "opencode-sdk"
	case archon.PlatformClaude, "":
		return "sdk"
	default:
		return ""
	}
}

// ownerRepoRE matches a single owner/repo segment, e.g. "vigolium/archon-audit".
// Used by normalizeOwnerRepo to validate the candidate before returning it.
var ownerRepoRE = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

// AuditAgenticScanner manages an archon-audit running as a background agent process.
// It launches the agent (Claude, Codex, or OpenCode), periodically syncs audit-state.json
// and findings to the vigolium session dir, and imports findings into the database when complete.
type AuditAgenticScanner struct {
	cfg  AuditAgentConfig
	repo *database.Repository

	agenticScanUUID string // UUID of the child AgenticScan record tracking this audit

	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	err       error
	cancelled bool
	startedAt time.Time // wall time the agent subprocess was launched

	lastStateHash string           // cached hash for change detection in syncLoop
	syncedFiles   map[string]int64 // filename → size, for incremental sync

	// Populated by importArchonFindings after monitor() completes.
	findingStats FindingStats

	// Populated by finalizeAgenticScan from the backend's session transcript
	// (audit-stream.jsonl for Claude, ~/.codex/sessions/*.jsonl for Codex).
	// Zero-valued when the run used an unsupported backend or the transcript
	// could not be parsed — callers must handle that.
	costSummary ScanCost
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

// NewAuditAgenticScanner creates a new runner for the background archon-audit.
//
// The AgenticScan DB row's UUID is derived as follows:
//
//   - Standalone archon (ParentRunUUID empty, SessionDir set): UUID is
//     filepath.Base(cfg.SessionDir). This gives the invariant that
//     `vigolium log <uuid>` and `vigolium log ls` resolve the session's
//     runtime.log via the conventional `{sessions_dir}/{uuid}/` path.
//   - Nested archon (ParentRunUUID set, e.g. spawned by autopilot/swarm):
//     a fresh UUID is generated. The parent already owns a row at
//     filepath.Base(SessionDir), so the child must differ to avoid a
//     primary-key collision on create. Resolution back to runtime.log
//     relies on the child row's persisted SessionDir column instead.
//   - No SessionDir: a fresh UUID is generated.
func NewAuditAgenticScanner(cfg AuditAgentConfig, repo *database.Repository) *AuditAgenticScanner {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	scanUUID := uuid.New().String()
	if cfg.SessionDir != "" && cfg.ParentRunUUID == "" {
		scanUUID = filepath.Base(cfg.SessionDir)
	}
	return &AuditAgenticScanner{
		cfg:             cfg,
		repo:            repo,
		agenticScanUUID: scanUUID,
		done:            make(chan struct{}),
		syncedFiles:     make(map[string]int64),
	}
}

// Start launches archon-audit as a background agent process.
// The platform field determines which CLI binary and args are used.
func (r *AuditAgenticScanner) Start(ctx context.Context) error {
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
	cmd.Env = append(os.Environ(), archonEnvFor(r.cfg.SourcePath, r.agenticScanUUID, r.cfg.CommitScanLimit, r.cfg.CommitScanSince)...)
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
	// Tee stderr to StreamWriter too — warnings and errors from non-Claude
	// backends (codex, opencode) often only come through stderr, and we want
	// them in runtime.log for later replay.
	if r.cfg.StreamWriter != nil {
		cmd.Stderr = io.MultiWriter(&outputBuf, r.cfg.StreamWriter)
	} else {
		cmd.Stderr = &outputBuf
	}

	if err := cmd.Start(); err != nil {
		if streamRawLog != nil {
			_ = streamRawLog.Close()
		}
		return fmt.Errorf("failed to start archon-audit: %w", err)
	}

	r.mu.Lock()
	r.cmd = cmd
	r.startedAt = time.Now()
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

	// Create child AgenticScan record
	r.createAgenticScan(ctx)

	go r.monitor(ctx, cmd, &outputBuf)
	go r.syncLoop(ctx)

	return nil
}

func (r *AuditAgenticScanner) createAgenticScan(ctx context.Context) {
	if r.repo == nil {
		return
	}
	run := &database.AgenticScan{
		UUID:          r.agenticScanUUID,
		ProjectUUID:   r.cfg.ProjectUUID,
		ScanUUID:      r.cfg.ScanUUID,
		Mode:          "archon",
		AgentName:     "archon-audit",
		Protocol:      archonProtocolForPlatform(r.cfg.Platform),
		InputType:     "archon",
		Status:        "running",
		CurrentPhase:  "initializing",
		SourcePath:    r.cfg.SourcePath,
		SessionDir:    r.cfg.SessionDir,
		ParentRunUUID: r.cfg.ParentRunUUID,
		StartedAt:     time.Now(),
	}
	if err := r.repo.CreateAgenticScan(ctx, run); err != nil {
		zap.L().Debug("Failed to create archon AgenticScan", zap.Error(err))
	}
}

func (r *AuditAgenticScanner) monitor(ctx context.Context, cmd *exec.Cmd, output *syncBuffer) {
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
			if info, detectErr := claudestream.DetectQuotaReset(bytes.NewReader(output.Bytes()), time.Now()); detectErr == nil && info != nil {
				zap.L().Warn("Claude quota exhausted — resets at",
					zap.Time("reset_at", info.ResetAt),
					zap.Duration("wait", time.Until(info.ResetAt).Round(time.Second)),
					zap.String("message", info.Message))
			}
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

	// Update AgenticScan as completed/failed
	r.finalizeAgenticScan(ctx, err)
}

// collectFallbackOutput reads key archon output files from the synced session
// directory and concatenates them. Used when the process was killed before
// stdout was flushed (e.g. --print mode with early cancellation).
func (r *AuditAgenticScanner) collectFallbackOutput() []byte {
	archonDir := filepath.Join(r.cfg.SessionDir, "archon-audit")

	// Top-level reports across lite/scan/deep modes. Includes the Phase 5A/5B/5C
	// matrices added in upstream commit 87b2281.
	candidates := []string{
		"lite-recon.md",
		"commit-recon-report.md",
		"knowledge-base-report.md",
		"enrichment-report.md",
		"spec-gap-report.md",
		"advisory-report.md",
		"authz-matrix.md",
		"cross-service-edges.md",
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

	// Enumerate confirmed findings (each in archon/findings/<ID>-<slug>/report.md).
	// findings-draft/ is wiped at the end of every successful run so we no longer
	// scan it; consolidated findings live under findings/ regardless of mode.
	findingsDir := filepath.Join(archonDir, "findings")
	if entries, err := os.ReadDir(findingsDir); err == nil {
		var findingDirs []string
		for _, e := range entries {
			if e.IsDir() {
				findingDirs = append(findingDirs, e.Name())
			}
		}
		if len(findingDirs) > 0 {
			sort.Strings(findingDirs)
			summary := fmt.Sprintf("# Findings\n\n%d findings produced:\n", len(findingDirs))
			for _, name := range findingDirs {
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

func (r *AuditAgenticScanner) syncLoop(ctx context.Context) {
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
// and updates the child AgenticScan with current phase info.
// Skips DB updates when the state hasn't changed since last tick.
func (r *AuditAgenticScanner) syncStateOnce() {
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
		r.updateAgenticScanProgress(data)
	}
}

// syncFindingsIncremental copies new/changed files from findings-draft/ to session dir.
// Tracks synced files by size to avoid re-copying unchanged files.
func (r *AuditAgenticScanner) syncFindingsIncremental() {
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
func (r *AuditAgenticScanner) syncFolderFull() {
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
func (r *AuditAgenticScanner) importArchonFindings(ctx context.Context) {
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

	findings := archon.BuildFindings(result.RawFindings, auditID, r.agenticScanUUID, r.cfg.ProjectUUID, result.RepoName)

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
func (r *AuditAgenticScanner) FindingStats() FindingStats {
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

func (r *AuditAgenticScanner) updateAgenticScanProgress(stateData []byte) {
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
	run, err := r.repo.GetAgenticScan(ctx, r.agenticScanUUID)
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

	_ = r.repo.UpdateAgenticScan(ctx, run)
}

func (r *AuditAgenticScanner) finalizeAgenticScan(ctx context.Context, processErr error) {
	// Compute the cost summary regardless of whether a DB repo is attached
	// — the CLI summary reads it from memory, so we want it populated even
	// in the no-persistence path.
	r.computeCostSummary()

	if r.repo == nil {
		return
	}

	run, err := r.repo.GetAgenticScan(ctx, r.agenticScanUUID)
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

	applyScanCost(run, r.costSummary)

	_ = r.repo.UpdateAgenticScan(ctx, run)
}

// computeCostSummary parses the archon session's backend-specific
// transcript into a priced ScanCost and stores it on the runner.
// Supported backends: Claude (audit-stream.jsonl in the session dir),
// Codex (per-session rollout under ~/.codex/sessions/). For any other
// backend, costSummary stays zero-valued.
func (r *AuditAgenticScanner) computeCostSummary() {
	platform := r.cfg.Platform
	if platform == "" {
		platform = archon.PlatformClaude
	}

	var cost ScanCost
	switch platform {
	case archon.PlatformClaude:
		if r.cfg.SessionDir == "" {
			return
		}
		streamPath := filepath.Join(r.cfg.SessionDir, "audit-stream.jsonl")
		if _, err := os.Stat(streamPath); err != nil {
			return
		}
		s, err := claudecost.BuildSummary(streamPath, os.Getuid())
		if err != nil {
			zap.L().Debug("Failed to compute archon cost summary", zap.Error(err))
			return
		}
		cost = scanCostFromClaude(s)
	case archon.PlatformCodex:
		if r.cfg.SourcePath == "" {
			return
		}
		// Use the runner's recorded StartedAt-equivalent — the scan row
		// hasn't been reloaded yet at this point, so we approximate
		// with the process start time by pulling it from cmd.
		startedAt := r.processStartedAt()
		s, err := codexcost.BuildSummary(r.cfg.SourcePath, startedAt)
		if err != nil {
			zap.L().Debug("Failed to compute codex cost summary", zap.Error(err))
			return
		}
		cost = scanCostFromCodex(s)
	default:
		return
	}

	r.mu.Lock()
	r.costSummary = cost
	r.mu.Unlock()
}

// processStartedAt returns the wall time the archon subprocess was
// launched. Codex's rollout matcher uses this to disambiguate rollouts
// when multiple have the same cwd.
func (r *AuditAgenticScanner) processStartedAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.startedAt
}

// CostSummary returns the priced token summary for this audit run. The
// zero value is returned when the run is still active, used an
// unsupported backend, or the backend transcript could not be parsed.
func (r *AuditAgenticScanner) CostSummary() ScanCost {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Shallow copy is sufficient — ScanCost holds no slices the caller
	// could mutate, and the Blob map is never modified post-build.
	return r.costSummary
}

// Wait blocks until the archon audit finishes.
func (r *AuditAgenticScanner) Wait() error {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Done returns a channel that closes when the archon audit finishes.
func (r *AuditAgenticScanner) Done() <-chan struct{} {
	return r.done
}

// Cancel stops the archon audit process. Sends SIGTERM first, then SIGKILL after a grace period.
func (r *AuditAgenticScanner) Cancel() {
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
func (r *AuditAgenticScanner) Status() *AuditAgentStatus {
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

func (r *AuditAgenticScanner) isRunning() bool {
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

func (r *AuditAgenticScanner) readCurrentState() *archon.AuditState {
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

// --- Archon environment ---

// archonEnvFor produces the ARCHON_* env vars upstream's CLI normally exports
// before launching the agent. Vigolium bypasses the archon-audit binary and
// runs claude/codex/opencode directly, so we replicate the exports here so
// agents (report-assembler, advisory-hunter, commit-archaeologist) see the
// repo identity, git availability, commit scan limits, and a stable session UUID.
func archonEnvFor(sourcePath, sessionUUID string, commitLimit int, commitSince string) []string {
	repo := deriveRepositoryName(sourcePath)
	gitAvailable := "false"
	if isGitWorkTree(sourcePath) {
		gitAvailable = "true"
	}
	envs := []string{
		"ARCHON_REPOSITORY=" + repo,
		"ARCHON_GIT_AVAILABLE=" + gitAvailable,
		"ARCHON_SESSION_UUID=" + sessionUUID,
	}
	if commitLimit > 0 {
		envs = append(envs, fmt.Sprintf("ARCHON_COMMIT_SCAN_LIMIT=%d", commitLimit))
	}
	if commitSince != "" {
		envs = append(envs, "ARCHON_COMMIT_SCAN_SINCE="+commitSince)
	}
	return envs
}

// deriveRepositoryName resolves a repo identity for the audit target. Tries
// the git remote first (canonicalized to "owner/repo" when possible), then
// falls back to the directory basename. Mirrors the upstream behavior at a
// fraction of the surface area — manifest probing is omitted.
func deriveRepositoryName(target string) string {
	if name := repoNameFromGitRemote(target); name != "" {
		return name
	}
	return filepath.Base(target)
}

func repoNameFromGitRemote(target string) string {
	cmd := exec.Command("git", "-C", target, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return normalizeOwnerRepo(strings.TrimSpace(string(out)))
}

func isGitWorkTree(target string) bool {
	cmd := exec.Command("git", "-C", target, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// normalizeOwnerRepo canonicalizes a git URL or owner/repo string. Returns
// "" when the input doesn't contain a recognizable owner/repo segment.
func normalizeOwnerRepo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimSuffix(raw, "/")
	raw = strings.TrimSuffix(raw, ".git")
	// git@host:owner/repo or https://host/owner/repo
	if idx := strings.LastIndex(raw, ":"); idx >= 0 {
		if rest := strings.TrimLeft(raw[idx+1:], "/"); ownerRepoRE.MatchString(rest) {
			return rest
		}
	}
	if idx := strings.LastIndex(raw, "/"); idx > 0 {
		// Walk back one segment to capture owner/repo from a URL path.
		prev := strings.LastIndex(raw[:idx], "/")
		if prev >= 0 {
			rest := raw[prev+1:]
			if ownerRepoRE.MatchString(rest) {
				return rest
			}
		}
	}
	if ownerRepoRE.MatchString(raw) {
		return raw
	}
	return ""
}

// --- Platform command builders ---

// archonModePromptSuffix renders the mode qualifier in the exact form the
// archon codex harness (harnesses/codex/agents-dispatch.md) parses in its
// mode-selection table. Matches the prompts emitted by the standalone
// archon-audit CLI's codex platform BuildRunCmd.
func archonModePromptSuffix(mode string) string {
	switch mode {
	case "lite":
		return "Lite mode: Q0-Q2 only, no-git compatible"
	case "balanced", "scan":
		return "Balanced mode: L1-L6 only, no-git compatible"
	case "deep":
		return "Full deep mode: all phases"
	case "revisit":
		return "Revisit mode: R5-R11c — fresh pass on top of prior archon/ state"
	case "confirm":
		return "Confirm mode: verify findings, V1-V6"
	case "merge":
		return "Merge mode: M1-M7 — operate on the pre-merged archon/ tree"
	default:
		return "Balanced mode: L1-L6 only, no-git compatible"
	}
}

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
		// Codex uses AGENTS.md dispatch. Run with the `exec` subcommand so
		// codex stays non-interactive — without it, codex defaults to the
		// interactive TUI and dies with "stdin is not a terminal" because
		// our stdout is a pipe buffer. `-C sourcePath` gives agents access
		// to the source tree and anchors relative `archon/...` artifact
		// paths under the source dir (syncLoop/importArchonFindings both
		// read from `<source>/archon/`).
		args = []string{
			"exec",
			"--full-auto",
			"--skip-git-repo-check",
			"-C", sourcePath,
		}
		// Force ANSI color when the user's own stdout is a TTY, since
		// codex's stdout is wired to a pipe and it otherwise auto-detects
		// no-color. Non-TTY vigolium runs leave codex on --color auto so
		// runtime.log stays free of escape codes.
		if terminal.IsColorEnabled() {
			args = append(args, "--color", "always")
		}
		args = append(args, "archon:* ("+archonModePromptSuffix(mode)+")")

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
func StartAuditAgent(ctx context.Context, agentCfg config.AuditAgentConfig, sourcePath, sessionDir, projectUUID, scanUUID, parentRunUUID string, repo *database.Repository, streamWriter io.Writer) (*AuditAgenticScanner, error) {
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

	runner := NewAuditAgenticScanner(cfg, repo)
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
func startAuditAgentBackground(ctx context.Context, auditCfg *config.AuditAgentConfig, sourcePath, sessionDir, projectUUID, scanUUID, parentRunUUID string, repo *database.Repository, streamWriter io.Writer, logFn func(msg string)) (*AuditAgenticScanner, func(), error) {
	if auditCfg == nil || !auditCfg.IsEnabled() || sourcePath == "" {
		return nil, nil, nil
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
		return nil, nil, err
	}
	if runner == nil {
		return nil, nil, nil
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
	return runner, wait, nil
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
// "scan" is accepted as a legacy alias for "balanced"; EffectiveMode()
// normalizes it when the slash command is dispatched.
func isValidArchonMode(mode string) bool {
	switch mode {
	case "lite", "balanced", "scan", "deep", "mock", "confirm", "merge", "revisit":
		return true
	default:
		return false
	}
}
