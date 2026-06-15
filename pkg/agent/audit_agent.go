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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/audit"
	"github.com/vigolium/vigolium/pkg/audit/bin"
	"github.com/vigolium/vigolium/pkg/audit/stream"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/piolium/picost"
	"github.com/vigolium/vigolium/pkg/piolium/pistream"
	"github.com/vigolium/vigolium/pkg/procutil"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// cancelGracePeriod is how long Cancel waits for SIGTERM before escalating to SIGKILL.
const cancelGracePeriod = 10 * time.Second

// PlatformPi is the Pi runtime platform — runs piolium via `pi --mode json`.
const PlatformPi = "pi"

// PlatformAuditBin identifies the embedded vigolium-audit binary as the
// audit runner. vigolium-audit dispatches to claude or codex internally; the
// per-run agent comes from AuditAgentConfig.AuditDriverInvocation.
const PlatformAuditBin = "audit"

// DefaultAuditHarness returns the canonical audit harness spec used by
// `vigolium agent audit` and the autopilot/swarm background audit. The zero
// value of AuditAgentConfig.Harness is treated as this for backward compat.
func DefaultAuditHarness() HarnessSpec {
	return HarnessSpec{
		Name:            audit.HarnessName,
		SourceFolder:    "vigolium-results",
		SessionSubdir:   "vigolium-results",
		EnvPrefix:       "VIGOLIUM_AUDIT_",
		DBMode:          audit.HarnessName,
		DBAgentName:     "vigolium-audit",
		DBInputType:     audit.HarnessName,
		FindingIDPrefix: audit.HarnessName,
		FindingTag:      audit.HarnessName,
	}
}

// effectiveHarness returns the configured harness or the audit default.
func effectiveHarness(cfg AuditAgentConfig) HarnessSpec {
	if cfg.Harness.Name == "" {
		return DefaultAuditHarness()
	}
	return cfg.Harness
}

// harnessFindingSource projects the DB-tagging fields of a HarnessSpec onto
// the audit parser's FindingSource shape. Used wherever findings parsed
// from `<harness.SessionSubdir>/findings/` need to land in the database
// tagged with the right harness's mode/agent_name/tag set.
func harnessFindingSource(h HarnessSpec) audit.FindingSource {
	return audit.FindingSource{
		Mode:      h.DBMode,
		AgentName: h.DBAgentName,
		InputType: h.DBInputType,
		IDPrefix:  h.FindingIDPrefix,
		Tag:       h.FindingTag,
	}
}

// harness returns the resolved harness spec, populating the cache on first
// call. Used instead of effectiveHarness(r.cfg) so the resolution runs once
// per runner. Tolerates direct-literal AuditAgenticScanner construction
// (some tests skip NewAuditAgenticScanner).
func (r *AuditAgenticScanner) harness() HarnessSpec {
	if r.resolvedSpec.Name == "" {
		r.resolvedSpec = effectiveHarness(r.cfg)
	}
	return r.resolvedSpec
}

// auditProtocolForPlatform maps the platform onto the AgenticScan
// protocol vocabulary stored on the DB row.
func auditProtocolForPlatform(platform string) string {
	switch platform {
	case PlatformPi:
		return "pi-sdk"
	case PlatformAuditBin, "":
		return "audit-bin"
	default:
		return ""
	}
}

// ownerRepoRE matches a single owner/repo segment, e.g. "vigolium/vigolium-audit".
// Used by normalizeOwnerRepo to validate the candidate before returning it.
var ownerRepoRE = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

// AuditAgenticScanner manages an vigolium-audit running as a background agent process.
// It launches the agent (Claude or Codex), periodically syncs audit-state.json
// and findings to the vigolium session dir, and imports findings into the database when complete.
type AuditAgenticScanner struct {
	cfg          AuditAgentConfig
	resolvedSpec HarnessSpec // cached harness spec; populated lazily by harness()
	repo         *database.Repository

	agenticScanUUID string // UUID of the child AgenticScan record tracking this audit

	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	err       error
	cancelled bool
	startedAt time.Time // wall time the agent subprocess was launched

	lastStateHash string           // cached hash for change detection in syncLoop
	syncedFiles   map[string]int64 // filename → size, for incremental sync

	// Populated by importFindings after monitor() completes.
	findingStats FindingStats

	// Populated by finalizeAgenticScan from the harness's NDJSON output
	// (audit `result` event for audit, picost transcripts for piolium).
	// Zero-valued when the harness did not produce a usable summary.
	costSummary ScanCost

	// auditResult captures the final `result` event observed on the
	// audit NDJSON stream. Populated by the streaming goroutine in
	// Start() and read by computeCostSummary after monitor() drains the
	// pipe. Zero-valued for piolium runs.
	auditResult stream.Result

	// streamDone is closed by the streaming goroutine when it has
	// finished consuming the subprocess's stdout. monitor() waits on
	// this before computing cost / fallback output, so the captured
	// result is observable.
	streamDone chan struct{}

	// byokCleanup is set by Start() when a piolium codex BYOK run staged
	// auth.json into PI_CODING_AGENT_DIR. monitor() invokes it after the
	// subprocess exits to remove the staged file, restore the backup (if
	// any), and release the per-dir lock. Nil when no staging happened.
	byokCleanup func()
}

// FindingStats summarises the audit findings imported by a single audit run.
type FindingStats struct {
	Parsed     int            // total findings parsed from the session dir
	Saved      int            // findings successfully persisted to the database
	BySeverity map[string]int // count by normalized severity (critical/high/medium/low/info)

	// Reported is the count reported by the audit binary's own NDJSON
	// `result` event. It is only consulted when the on-disk findings tree
	// could not be parsed (Parsed == 0) and serves as a display-only
	// fallback so the CLI summary mirrors the streamer's `[result]` line
	// even when persistence didn't run. Severity keys are normalized to
	// lowercase to match BySeverity.
	Reported           int
	ReportedBySeverity map[string]int
}

// SeverityBreakdownString renders a colored "critical:N  high:N  ..." string in
// descending severity order. Buckets with zero count are skipped. Falls back to
// the audit-reported breakdown when the on-disk parse yielded nothing. Returns
// "" when no findings were counted at all.
func (s FindingStats) SeverityBreakdownString() string {
	src := s.BySeverity
	if len(src) == 0 || s.Parsed == 0 {
		if len(s.ReportedBySeverity) > 0 {
			src = s.ReportedBySeverity
		}
	}
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
		if n := src[b.name]; n > 0 {
			parts = append(parts, b.color(fmt.Sprintf("%s:%d", b.name, n)))
		}
	}
	return strings.Join(parts, "  ")
}

// NewAuditAgenticScanner creates a new runner for the background vigolium-audit.
//
// The AgenticScan DB row's UUID is derived as follows:
//
//   - Standalone audit (ParentAgenticScanUUID empty, SessionDir set): UUID is
//     filepath.Base(cfg.SessionDir). This gives the invariant that
//     `vigolium log <uuid>` and `vigolium log ls` resolve the session's
//     runtime.log via the conventional `{sessions_dir}/{uuid}/` path.
//   - Nested audit (ParentAgenticScanUUID set, e.g. spawned by autopilot/swarm):
//     a fresh UUID is generated. The parent already owns a row at
//     filepath.Base(SessionDir), so the child must differ to avoid a
//     primary-key collision on create. Resolution back to runtime.log
//     relies on the child row's persisted SessionDir column instead.
//   - No SessionDir: a fresh UUID is generated.
func NewAuditAgenticScanner(cfg AuditAgentConfig, repo *database.Repository) *AuditAgenticScanner {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	return &AuditAgenticScanner{
		cfg:             cfg,
		resolvedSpec:    effectiveHarness(cfg),
		repo:            repo,
		agenticScanUUID: deriveAuditScanUUID(cfg),
		done:            make(chan struct{}),
		syncedFiles:     make(map[string]int64),
	}
}

// Start launches the audit harness (vigolium-audit binary or piolium via `pi`)
// as a background process. The harness selection drives binary
// resolution, argv construction, and stream decoding.
//
// On any failure path AFTER BYOK staging has run (codex auth.json copy)
// but BEFORE cmd.Start() succeeds, the staged file must be cleaned up
// here — monitor() never runs in that case. Past that point, monitor's
// deferred cleanup owns the restore.
func (r *AuditAgenticScanner) Start(ctx context.Context) error {
	platform := r.cfg.Platform

	// startSucceeded gates whether the deferred BYOK cleanup ownership
	// transfers to monitor (true) or fires here (false). r.byokCleanup is
	// nil-checked inside the defer to keep the no-BYOK path cheap.
	startSucceeded := false
	defer func() {
		if !startSucceeded && r.byokCleanup != nil {
			r.byokCleanup()
			r.byokCleanup = nil
		}
	}()

	// Validate source path up front. The subprocess inherits cmd.Dir =
	// SourcePath; if the directory doesn't exist, the kernel's chdir fails and
	// Go reports `fork/exec <binary>: no such file or directory` — pointing at
	// the binary instead of the cwd. Fail here with a clear message instead.
	if r.cfg.SourcePath == "" {
		return fmt.Errorf("audit source path is empty")
	}
	if info, err := os.Stat(r.cfg.SourcePath); err != nil {
		return fmt.Errorf("audit source path %q is not accessible: %w", r.cfg.SourcePath, err)
	} else if !info.IsDir() {
		return fmt.Errorf("audit source path %q is not a directory", r.cfg.SourcePath)
	}

	harness := r.harness()
	isAudit := harness.Name == audit.HarnessName
	if isAudit {
		platform = PlatformAuditBin
	}

	// Audit always runs with --json so the streaming goroutine can
	// extract the result event for cost reporting; piolium opts in via
	// cfg.StreamDecoder + StreamWriter.
	streamJSON := isAudit || (r.cfg.Stream && r.cfg.StreamWriter != nil && r.cfg.StreamDecoder != nil)

	binary, args, stdinPrompt, err := buildAuditAgentCommand(platform, r.cfg, streamJSON)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = r.cfg.SourcePath
	procutil.SetupProcessGroup(cmd) // own process group so the whole harness tree can be torn down
	// harnessEnv carries the vigolium-injected vars (PIOLIUM_REPOSITORY,
	// PIOLIUM_GIT_AVAILABLE, PIOLIUM_SESSION_UUID, optional commit-scan
	// knobs, and the audit-equivalent under ARCHON_*). Captured rather
	// than appended inline so the debug line can render them.
	harnessEnv := auditEnvFor(harness.EnvPrefix, r.cfg.SourcePath, r.agenticScanUUID, r.cfg.CommitScanLimit, r.cfg.CommitScanSince)
	cmd.Env = append(os.Environ(), harnessEnv...)
	// pioliumExtraEnv is the piolium-only runtime injection
	// (PI_CODING_AGENT_DIR) — distinct from harnessEnv since it's
	// opt-in via $PIOLIUM_HOME / the /opt/piolium auto-probe and
	// reads as nil otherwise.
	var pioliumExtraEnv []string
	// pioliumAuthEnv is the BYOK env-var bundle (api-key / oauth-token)
	// derived from r.cfg.AuthOverride. Tracked separately from
	// pioliumExtraEnv so we can redact its values in logs without
	// stripping the harmless PI_CODING_AGENT_DIR line.
	var pioliumAuthEnv []string
	// "" when no $PIOLIUM_HOME and no /opt/piolium probe hit. Resolved
	// once here and reused for both BYOK staging (codex auth.json) and
	// the debug-line render below — AgentDir() probes the filesystem.
	pioliumAgentDir := piolium.AgentDir()
	if harness.Name == piolium.HarnessName {
		pioliumExtraEnv = piolium.RuntimeEnv()
		cmd.Env = append(cmd.Env, pioliumExtraEnv...)
		// Pre-create the per-scan pi-session subdir so pi doesn't have
		// to. Best-effort — if it fails, pi will surface a more
		// specific error than "no such directory".
		if r.cfg.SessionDir != "" {
			_ = os.MkdirAll(filepath.Join(r.cfg.SessionDir, "pi-session"), 0o755)
		}

		if err := r.applyPioliumBYOK(cmd, &pioliumAuthEnv, pioliumAgentDir); err != nil {
			return err
		}
	}

	// Build readable command line for console output. Piolium runtime
	// env vars are prepended in shell form so a debug reader can tell
	// whether $PIOLIUM_HOME-driven injection actually fired this run.
	var cmdLine strings.Builder
	for _, env := range pioliumExtraEnv {
		cmdLine.WriteString(env)
		cmdLine.WriteByte(' ')
	}
	cmdLine.WriteString(binary)
	for _, a := range args {
		cmdLine.WriteByte(' ')
		if strings.ContainsAny(a, " \t\n'\"\\") {
			cmdLine.WriteString("'" + strings.ReplaceAll(a, "'", "'\\''") + "'")
		} else {
			cmdLine.WriteString(a)
		}
	}
	// Combine harness vars (always present), piolium runtime vars (often
	// nil), and BYOK auth env (only set when an override fired) into one
	// slice so the operator sees the full set vigolium injected on top
	// of the inherited shell env. Secret values are redacted before logging
	// — the live cmd.Env still has the real values, this is log-only.
	injectedEnv := append([]string(nil), harnessEnv...)
	injectedEnv = append(injectedEnv, pioliumExtraEnv...)
	injectedEnv = append(injectedEnv, pioliumAuthEnv...)
	zap.L().Debug("starting background audit",
		zap.String("cmd", redactAuditDriverCmdLine(cmdLine.String())),
		zap.String("platform", platform),
		zap.String("harness", harness.Name),
		zap.String("mode", r.cfg.Mode),
		zap.String("source", r.cfg.SourcePath),
		zap.String("piolium_agent_dir", pioliumAgentDir),
		zap.Strings("injected_env", redactEnvSlice(injectedEnv)))
	if stdinPrompt != "" {
		cmd.Stdin = strings.NewReader(stdinPrompt)
	}

	var outputBuf syncBuffer
	var streamPipe io.ReadCloser
	var streamRawLog *os.File

	if streamJSON {
		// NDJSON harnesses (audit-bin always, piolium when its
		// StreamDecoder is wired in): decode via the per-harness
		// streamer, tee raw JSONL to the session dir, and still
		// capture into outputBuf for the fallback-output path in
		// monitor().
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
	// Tee stderr to StreamWriter too — non-Claude backends often surface
	// warnings/errors only on stderr, and we want them in runtime.log
	// for later replay.
	if r.cfg.StreamWriter != nil {
		cmd.Stderr = io.MultiWriter(&outputBuf, r.cfg.StreamWriter)
	} else {
		cmd.Stderr = &outputBuf
	}

	if err := cmd.Start(); err != nil {
		if streamRawLog != nil {
			_ = streamRawLog.Close()
		}
		return fmt.Errorf("failed to start audit (harness=%s binary=%s cwd=%s): %w", harness.Name, binary, cmd.Dir, err)
	}

	r.mu.Lock()
	r.cmd = cmd
	r.startedAt = time.Now()
	r.streamDone = make(chan struct{})
	r.mu.Unlock()

	if streamJSON {
		go func() {
			defer close(r.streamDone)
			defer func() {
				if streamRawLog != nil {
					_ = streamRawLog.Close()
				}
			}()
			// When streamRawLog is open, the on-disk audit-stream.jsonl
			// is the canonical replay artifact — don't also accumulate
			// the full NDJSON in outputBuf. The buffer's only consumer
			// is the early-exit fallback in monitor(), which fires when
			// no output reached either sink (collectFallbackOutput then
			// reconstructs from synced findings).
			var rawWriter io.Writer = &outputBuf
			if streamRawLog != nil {
				rawWriter = streamRawLog
			}
			renderTo := r.cfg.StreamWriter
			if renderTo == nil {
				renderTo = io.Discard
			}
			if isAudit {
				res, err := stream.Stream(streamPipe, renderTo, stream.Options{
					RawLog:       rawWriter,
					ShowThinking: r.cfg.ShowThinking,
				})
				if err != nil {
					zap.L().Debug("audit stream decoder exited with error", zap.Error(err))
				}
				r.mu.Lock()
				r.auditResult = res
				r.mu.Unlock()
				return
			}
			if r.cfg.StreamDecoder != nil {
				if err := r.cfg.StreamDecoder(streamPipe, renderTo, rawWriter); err != nil {
					zap.L().Debug("audit stream decoder exited with error", zap.Error(err))
				}
			}
		}()
	} else {
		// No streaming goroutine — close streamDone immediately so
		// monitor() doesn't block waiting for it.
		close(r.streamDone)
	}

	// Create child AgenticScan record
	r.createAgenticScan(ctx)

	go r.monitor(ctx, cmd, &outputBuf)
	go r.syncLoop(ctx)

	// Past this point monitor() owns the BYOK cleanup. Flip the gate so
	// the deferred-on-failure handler at the top of Start() doesn't fire.
	startSucceeded = true
	return nil
}

// newAuditAgenticScanRow builds the initial "running" AgenticScan row for
// an audit run. Shared by the single-subprocess scanner and the piolium
// chain scanner so the row shape stays in lockstep.
func newAuditAgenticScanRow(cfg AuditAgentConfig, harness HarnessSpec, scanUUID string, startedAt time.Time) *database.AgenticScan {
	return &database.AgenticScan{
		UUID:                  scanUUID,
		ProjectUUID:           cfg.ProjectUUID,
		ScanUUID:              cfg.ScanUUID,
		Mode:                  harness.DBMode,
		AgentName:             harness.DBAgentName,
		Protocol:              auditProtocolForPlatform(cfg.Platform),
		InputType:             harness.DBInputType,
		Status:                "running",
		CurrentPhase:          "initializing",
		SourcePath:            cfg.SourcePath,
		SessionDir:            cfg.SessionDir,
		ParentAgenticScanUUID: cfg.ParentAgenticScanUUID,
		StartedAt:             startedAt,
	}
}

// applyAuditTerminalStatus resolves an audit run's final Status from its
// process error and cancellation state. Shared by every audit finalizer
// so "completed / cancelled / failed" is decided in one place.
func applyAuditTerminalStatus(run *database.AgenticScan, runErr error, cancelled bool) {
	switch {
	case runErr == nil:
		run.Status = "completed"
	case cancelled:
		run.Status = "cancelled"
	default:
		run.Status = "failed"
		run.ErrorMessage = runErr.Error()
	}
}

func (r *AuditAgenticScanner) createAgenticScan(ctx context.Context) {
	if r.repo == nil || r.cfg.SuppressAgenticScanRow {
		return
	}
	run := newAuditAgenticScanRow(r.cfg, r.harness(), r.agenticScanUUID, time.Now())
	if err := r.repo.CreateAgenticScan(ctx, run); err != nil {
		zap.L().Debug("Failed to create audit AgenticScan", zap.Error(err))
	}
}

func (r *AuditAgenticScanner) monitor(ctx context.Context, cmd *exec.Cmd, output *syncBuffer) {
	defer close(r.done)

	// BYOK cleanup (currently: piolium codex auth.json restore + lock
	// release). Runs as the very last thing in monitor so that a panic /
	// early-return in any later step still triggers it.
	if r.byokCleanup != nil {
		defer r.byokCleanup()
	}

	err := cmd.Wait()

	// Drain the streaming goroutine (if any) before reading captured
	// state — auditResult and the raw outputBuf both depend on the
	// stdout pipe being fully consumed.
	r.mu.Lock()
	streamDone := r.streamDone
	r.mu.Unlock()
	if streamDone != nil {
		<-streamDone
	}

	r.mu.Lock()
	r.err = err
	r.mu.Unlock()

	harnessName := r.harness().Name
	if err != nil {
		if r.cancelled {
			zap.L().Info("Audit cancelled", zap.String("harness", harnessName))
		} else {
			zap.L().Warn("Audit process exited with error",
				zap.String("harness", harnessName),
				zap.Error(err))
		}
	} else {
		zap.L().Info("Audit completed successfully", zap.String("harness", harnessName))
	}

	// Final sync and import
	r.syncFolderFull()
	r.importFindings(ctx)

	// Cleanup: remove the harness output dir from source since we have a
	// copy in session. KeepSourceOutputDir opts out (see its field doc).
	harness := r.harness()
	srcOutputDir := filepath.Join(r.cfg.SourcePath, harness.SourceFolder)
	if _, statErr := os.Stat(srcOutputDir); statErr == nil && !r.cfg.KeepSourceOutputDir {
		if rmErr := os.RemoveAll(srcOutputDir); rmErr != nil {
			zap.L().Debug("Failed to cleanup harness output dir from source", zap.Error(rmErr))
		} else {
			zap.L().Info("Cleaned up harness output dir from source", zap.String("path", srcOutputDir))
		}
	}

	// Save raw output
	if r.cfg.SessionDir != "" {
		outputPath := filepath.Join(r.cfg.SessionDir, harness.Name+"-audit-output.md")
		rawOutput := output.Bytes()

		// If stdout buffer is empty (process killed before --print flushed),
		// fall back to reading key audit output files from the synced session dir.
		if len(rawOutput) == 0 {
			rawOutput = r.collectFallbackOutput()
		}

		if len(rawOutput) > 0 {
			if writeErr := os.WriteFile(outputPath, rawOutput, 0o644); writeErr != nil {
				zap.L().Debug("Failed to save audit output", zap.Error(writeErr))
			}
		}
	}

	// Update AgenticScan as completed/failed
	r.finalizeAgenticScan(ctx, err)
}

// collectFallbackOutput reads key audit output files from the synced session
// directory and concatenates them. Used when the process was killed before
// stdout was flushed (e.g. --print mode with early cancellation).
func (r *AuditAgenticScanner) collectFallbackOutput() []byte {
	auditDirLocal := filepath.Join(r.cfg.SessionDir, r.harness().SessionSubdir)

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
		data, err := os.ReadFile(filepath.Join(auditDirLocal, name))
		if err != nil || len(data) == 0 {
			continue
		}
		header := fmt.Sprintf("# %s\n\n", strings.TrimSuffix(name, ".md"))
		parts = append(parts, []byte(header))
		parts = append(parts, data)
		parts = append(parts, []byte("\n\n---\n\n"))
	}

	// Enumerate confirmed findings (each in audit/findings/<ID>-<slug>/report.md).
	// findings-draft/ is wiped at the end of every successful run so we no longer
	// scan it; consolidated findings live under findings/ regardless of mode.
	findingsDir := filepath.Join(auditDirLocal, "findings")
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
			r.syncStateOnce(ctx)
			r.syncFindingsIncremental()
		}
	}
}

// syncStateOnce copies audit-state.json from source to session dir
// and updates the child AgenticScan with current phase info. Skips
// both the disk write and the DB update when the state hash is
// unchanged from the previous tick — long-running audits don't churn
// hundreds of KB of identical bytes through fsync once a minute.
func (r *AuditAgenticScanner) syncStateOnce(ctx context.Context) {
	if r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}
	harness := r.harness()

	src := filepath.Join(r.cfg.SourcePath, harness.SourceFolder, "audit-state.json")
	data, err := os.ReadFile(src)
	if err != nil {
		return // file may not exist yet
	}

	hash := fmt.Sprintf("%x", md5.Sum(data))
	if hash == r.lastStateHash {
		return
	}
	r.lastStateHash = hash

	destDir := filepath.Join(r.cfg.SessionDir, harness.SessionSubdir)
	_ = os.MkdirAll(destDir, 0o755)
	dest := filepath.Join(destDir, "audit-state.json")
	if writeErr := os.WriteFile(dest, data, 0o644); writeErr != nil {
		zap.L().Debug("Failed to sync audit state", zap.Error(writeErr))
	}
	r.updateAgenticScanProgress(ctx, data)
}

// syncFindingsIncremental copies new/changed files from findings-draft/ to session dir.
// Tracks synced files by size to avoid re-copying unchanged files.
func (r *AuditAgenticScanner) syncFindingsIncremental() {
	if r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}
	harness := r.harness()

	srcDir := filepath.Join(r.cfg.SourcePath, harness.SourceFolder, "findings-draft")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return
	}

	destDir := filepath.Join(r.cfg.SessionDir, harness.SessionSubdir, "findings-draft")
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

// syncFolderFull copies the entire harness output folder to session dir.
func (r *AuditAgenticScanner) syncFolderFull() {
	if r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}
	harness := r.harness()

	srcDir := filepath.Join(r.cfg.SourcePath, harness.SourceFolder)
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		return
	}

	destDir := filepath.Join(r.cfg.SessionDir, harness.SessionSubdir)
	_ = os.MkdirAll(destDir, 0o755)

	copyDir(srcDir, destDir)
}

// importFindings parses the harness output from session dir and imports findings.
// Populates r.findingStats so the CLI summary can report what was persisted.
func (r *AuditAgenticScanner) importFindings(ctx context.Context) {
	harness := r.harness()

	// Parse from session dir (synced copy) or fall back to source dir
	var auditDirLocal string
	if r.cfg.SessionDir != "" {
		auditDirLocal = filepath.Join(r.cfg.SessionDir, harness.SessionSubdir)
	} else {
		auditDirLocal = filepath.Join(r.cfg.SourcePath, harness.SourceFolder)
	}

	result, err := audit.ParseFolder(auditDirLocal)
	if err != nil {
		// ParseFolder returns a nil error for a missing/empty dir, so a non-nil
		// error means the audit output is corrupt and every finding is being
		// dropped — warn loudly with the path rather than swallowing it at Debug.
		zap.L().Warn("Failed to parse harness output for import (findings dropped)",
			zap.String("dir", auditDirLocal),
			zap.Error(err))
		return
	}

	auditID := ""
	if len(result.State.Audits) > 0 {
		auditID = result.State.Audits[0].AuditID
	}

	findings := audit.BuildFindingsWithSource(result.RawFindings, auditID, r.agenticScanUUID, r.cfg.ProjectUUID, result.RepoName, harnessFindingSource(harness))

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

	// Always capture what the audit binary itself reported on its NDJSON
	// stream. The CLI summary falls back to these counts when on-disk
	// parsing yielded nothing, so the operator sees the same totals the
	// streamer just printed in the `[result]` line.
	r.mu.Lock()
	res := r.auditResult
	r.mu.Unlock()
	if res.Findings.Total > 0 {
		stats.Reported = res.Findings.Total
		stats.ReportedBySeverity = make(map[string]int, len(res.Findings.BySeverity))
		for sev, n := range res.Findings.BySeverity {
			if n <= 0 {
				continue
			}
			stats.ReportedBySeverity[strings.ToLower(sev)] += n
		}
	}

	r.mu.Lock()
	r.findingStats = stats
	r.mu.Unlock()

	if stats.Parsed > 0 {
		zap.L().Info("Imported audit findings",
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
	if stats.ReportedBySeverity != nil {
		cp := make(map[string]int, len(stats.ReportedBySeverity))
		for k, v := range stats.ReportedBySeverity {
			cp[k] = v
		}
		stats.ReportedBySeverity = cp
	}
	return stats
}

func (r *AuditAgenticScanner) updateAgenticScanProgress(ctx context.Context, stateData []byte) {
	if r.repo == nil || r.cfg.SuppressAgenticScanRow {
		return
	}

	var state audit.State
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

	if err := r.repo.UpdateAgenticScan(ctx, run); err != nil {
		zap.L().Warn("failed to persist agentic scan progress", zap.String("run", run.UUID), zap.Error(err))
	}
}

func (r *AuditAgenticScanner) finalizeAgenticScan(ctx context.Context, processErr error) {
	// Compute the cost summary regardless of whether a DB repo is attached
	// — the CLI summary reads it from memory, so we want it populated even
	// in the no-persistence path.
	r.computeCostSummary()

	// SuppressAgenticScanRow: the piolium chain scanner owns the single
	// aggregated row and finalizes it itself after all modes run. The
	// cost summary above is still computed so the chain can sum it.
	if r.repo == nil || r.cfg.SuppressAgenticScanRow {
		return
	}

	run, err := r.repo.GetAgenticScan(ctx, r.agenticScanUUID)
	if err != nil {
		return
	}

	run.CompletedAt = time.Now()
	run.DurationMs = run.CompletedAt.Sub(run.StartedAt).Milliseconds()

	// A clean process exit is "completed" even if Cancel() raced in after
	// the process already finished — processErr==nil takes precedence.
	applyAuditTerminalStatus(run, processErr, r.cancelled || ctx.Err() != nil)

	// Load final state for result_json
	stateFile := filepath.Join(r.cfg.SessionDir, r.harness().SessionSubdir, "audit-state.json")
	if data, readErr := os.ReadFile(stateFile); readErr == nil {
		run.ResultJSON = string(data)
	}

	applyScanCost(run, r.costSummary)

	if err := r.repo.UpdateAgenticScan(ctx, run); err != nil {
		zap.L().Warn("failed to persist finalized agentic scan", zap.String("run", run.UUID), zap.Error(err))
	}
}

// computeCostSummary derives a priced ScanCost for the run and stores
// it on the runner. Sources by harness:
//
//   - audit: the captured `result` event from auditstream (totalUsd
//     and totalTokens are emitted by the binary itself).
//   - piolium: per-session rollout under <source>/.piolium/.
func (r *AuditAgenticScanner) computeCostSummary() {
	harness := r.harness()

	var cost ScanCost
	switch harness.Name {
	case piolium.HarnessName:
		if r.cfg.SourcePath == "" {
			return
		}
		s, err := picost.BuildSummary(r.cfg.SourcePath, r.processStartedAt())
		if err != nil {
			zap.L().Debug("Failed to compute pi cost summary", zap.Error(err))
			return
		}
		cost = scanCostFromPi(s)
	default:
		// audit (and unset → audit by harness() default).
		r.mu.Lock()
		res := r.auditResult
		r.mu.Unlock()
		cost = scanCostFromAudit(res, r.cfg.AuditDriverInvocation.Agent)
	}

	if cost.IsZero() {
		return
	}
	r.mu.Lock()
	r.costSummary = cost
	r.mu.Unlock()
}

// ProcessStartedAt returns the wall time the audit subprocess was launched.
// Used to disambiguate codex rollouts (when multiple share a cwd) and to
// classify early-runtime failures for the audit fallback path. Returns the
// zero time if Start has not been called.
func (r *AuditAgenticScanner) ProcessStartedAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.startedAt
}

// processStartedAt is the internal alias kept for the few package-internal
// callers. New code should use ProcessStartedAt.
func (r *AuditAgenticScanner) processStartedAt() time.Time {
	return r.ProcessStartedAt()
}

// Harness returns the harness spec the runner was configured with. Lets
// callers label output and tag findings without re-reading config or
// hard-coding harness names like "piolium" / "audit".
func (r *AuditAgenticScanner) Harness() HarnessSpec {
	return r.cfg.Harness
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

// Wait blocks until the audit finishes.
func (r *AuditAgenticScanner) Wait() error {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Done returns a channel that closes when the audit finishes.
func (r *AuditAgenticScanner) Done() <-chan struct{} {
	return r.done
}

// Cancel stops the audit process. Sends SIGTERM first, then SIGKILL after a grace period.
func (r *AuditAgenticScanner) Cancel() {
	r.mu.Lock()
	r.cancelled = true
	cmd := r.cmd
	r.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return
	}

	_ = procutil.SignalProcessGroup(cmd.Process.Pid, false) // SIGTERM the process group

	select {
	case <-r.done:
		return
	case <-time.After(cancelGracePeriod):
		_ = procutil.SignalProcessGroup(cmd.Process.Pid, true) // escalate to SIGKILL
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
		Mode:            JoinModes(r.cfg.EffectiveModes()),
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

func (r *AuditAgenticScanner) readCurrentState() *audit.State {
	// Try the source dir first (authoritative while the audit is running),
	// then fall back to the synced copy in the session dir. The fallback
	// matters after monitor() removes the source-side output dir on cleanup:
	// by the time Status() is called from the CLI summary, only the session
	// copy remains.
	harness := r.harness()
	candidates := []string{
		filepath.Join(r.cfg.SourcePath, harness.SourceFolder, "audit-state.json"),
	}
	if r.cfg.SessionDir != "" {
		candidates = append(candidates, filepath.Join(r.cfg.SessionDir, harness.SessionSubdir, "audit-state.json"))
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var state audit.State
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
		writeSessionArtifact(destPath, data)
		return nil
	})
}

// --- Audit harness environment ---

// applyPioliumBYOK injects per-run BYOK creds into the pi subprocess: env
// vars for api-key / oauth-token paths, a staged <pi-agent-dir>/auth.json
// for codex cred files. No-op when the override is empty so non-BYOK runs
// pay no cost. authEnv is appended to (caller tracks it separately so
// secret values can be redacted in the debug line).
//
// Before staging, sweep any orphaned lock + backup left behind by a prior
// crashed run in the same agent dir so we don't error on a dead lock. The
// sweep is best-effort and never blocks the launch.
func (r *AuditAgenticScanner) applyPioliumBYOK(cmd *exec.Cmd, authEnv *[]string, pioliumAgentDir string) error {
	if r.cfg.AuthOverride.IsZero() {
		return nil
	}
	if envEntries := PiAuthEnv(r.cfg.AuthOverride); len(envEntries) > 0 {
		*authEnv = envEntries
		cmd.Env = append(cmd.Env, envEntries...)
	}
	if r.cfg.AuthOverride.OAuthCredFile == "" ||
		normalizedAgent(r.cfg.AuthOverride.Agent) != string(AuditDriverAgentCodex) {
		return nil
	}
	if pioliumAgentDir != "" {
		sweep := SweepStalePioliumAuth([]string{pioliumAgentDir})
		for _, s := range sweep.Swept {
			zap.L().Warn("piolium codex BYOK: restored stale backup from crashed run",
				zap.String("dir", s.Dir),
				zap.String("restored_from", s.BackupPath),
				zap.String("dead_run", s.Holder.Run),
				zap.Int("dead_pid", s.Holder.PID))
		}
		for _, o := range sweep.Orphaned {
			zap.L().Warn("piolium codex BYOK: orphaned backup left in place (manual restore required)",
				zap.String("path", o))
		}
	}
	cleanup, err := stagePioliumCodexCred(
		r.cfg.AuthOverride.OAuthCredFile,
		pioliumAgentDir,
		r.agenticScanUUID,
	)
	if err != nil {
		return fmt.Errorf("piolium codex BYOK: %w", err)
	}
	r.byokCleanup = cleanup
	return nil
}

// auditEnvFor produces the harness-specific env vars upstream CLIs normally
// export before launching the agent. Vigolium bypasses those wrappers and
// runs claude/codex/pi directly, so we replicate the exports here
// so the harness's agents see the repo identity, git availability, commit
// scan limits, and a stable session UUID.
//
// prefix is the harness env-var namespace (e.g. "ARCHON_", "PIOLIUM_").
func auditEnvFor(prefix, sourcePath, sessionUUID string, commitLimit int, commitSince string) []string {
	if prefix == "" {
		prefix = "ARCHON_"
	}
	repo := deriveRepositoryName(sourcePath)
	gitAvailable := "false"
	if isGitWorkTree(sourcePath) {
		gitAvailable = "true"
	}
	envs := []string{
		prefix + "REPOSITORY=" + repo,
		prefix + "GIT_AVAILABLE=" + gitAvailable,
		prefix + "SESSION_UUID=" + sessionUUID,
	}
	// Surface a hand-curated `<source>/vigolium-results/INFO.md` to the harness's
	// knowledge-base-builder, which treats it as authoritative project context
	// when ARCHON_INFO_AVAILABLE=true. Only emitted under the ARCHON_ prefix —
	// piolium has no equivalent today.
	if prefix == "ARCHON_" {
		envs = append(envs, prefix+"INFO_AVAILABLE="+infoFileAvailable(sourcePath))
	}
	if commitLimit > 0 {
		envs = append(envs, fmt.Sprintf("%sCOMMIT_SCAN_LIMIT=%d", prefix, commitLimit))
	}
	if commitSince != "" {
		envs = append(envs, prefix+"COMMIT_SCAN_SINCE="+commitSince)
	}
	return envs
}

// infoFileAvailable reports "true" when <target>/vigolium-results/INFO.md exists as a
// non-empty regular file. Mirrors the standalone vigolium-audit CLI's
// hasAuditDriverInfoFile helper so vigolium-launched runs see the same signal.
func infoFileAvailable(target string) string {
	if target == "" {
		return "false"
	}
	info, err := os.Stat(filepath.Join(target, "vigolium-results", "INFO.md"))
	if err != nil {
		return "false"
	}
	if info.IsDir() || info.Size() == 0 {
		return "false"
	}
	return "true"
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

// AgenticScanUUID returns the UUID of the AgenticScan row this runner owns.
// Useful for tests and callers that need to look up the row after Wait().
func (r *AuditAgenticScanner) AgenticScanUUID() string {
	return r.agenticScanUUID
}

// piPreArgs builds the pre-`--mode json -p` flag list passed to `pi`.
// Empty when neither PiProvider nor PiModel is set.
func piPreArgs(cfg AuditAgentConfig) []string {
	var out []string
	if cfg.PiProvider != "" {
		out = append(out, "--provider", cfg.PiProvider)
	}
	if cfg.PiModel != "" {
		out = append(out, "--model", cfg.PiModel)
	}
	return out
}

// buildAuditAgentCommand resolves the CLI binary and builds the argument list
// for launching vigolium-audit (claude/codex) or piolium (pi) on the
// given platform. When stream is true the command emits line-oriented JSON on
// stdout (Claude's stream-json or Pi's --mode json) so the caller can render
// a live activity feed via the appropriate decoder.
//
// sessionDir is vigolium's per-scan session root. On the pi platform it
// becomes `--session-dir <sessionDir>/pi-session` so pi's transcripts and
// state land alongside vigolium's audit-stream.jsonl and synced findings.
// This is independent of $PIOLIUM_SESSION_DIR (the standalone-piolium
// default): vigolium owns per-scan isolation; $PIOLIUM_HOME is only the
// piolium *agent config* root (set via PI_CODING_AGENT_DIR — see
// piolium.RuntimeEnv). Empty sessionDir omits the flag and lets pi pick
// its own location (used by tests and ad-hoc runs).
//
// cfg.AdditionalArgs are appended verbatim after the harness-specific args
// and are typically piolium's --plm-* passthrough flags. They are ignored
// for the audit harness.
//
// piPreArgs are inserted ahead of `--mode json -p` on the pi platform so
// pi sees them as its own flags (e.g. `--provider`, `--model`). Ignored
// for non-pi platforms.
func buildAuditAgentCommand(platform string, cfg AuditAgentConfig, stream bool) (binary string, args []string, stdinPrompt string, err error) {
	switch platform {
	case PlatformPi:
		binary, err = exec.LookPath("pi")
		if err != nil {
			return "", nil, "", fmt.Errorf("pi CLI not found in PATH: %w", err)
		}
		command := "/piolium-" + cfg.Mode
		args = append(args, piPreArgs(cfg)...)
		if cfg.SessionDir != "" {
			args = append(args, "--session-dir", filepath.Join(cfg.SessionDir, "pi-session"))
		}
		if stream {
			args = append(args, "--mode", "json", "-p", command)
		} else {
			args = append(args, "-p", command)
		}
		if len(cfg.AdditionalArgs) > 0 {
			args = append(args, cfg.AdditionalArgs...)
		}
		return binary, args, stdinPrompt, nil

	case PlatformAuditBin, "":
		binary, err = bin.Path()
		if err != nil {
			return "", nil, "", fmt.Errorf("locate embedded vigolium-audit binary: %w (run `make build-audit`)", err)
		}
		// vigolium-audit CLI: `audit run --target <abs> (--mode <mode> |
		// --modes a,b,c) --agent <claude|codex> [--api-key|--oauth-*]
		// [--json]`. vigolium handles git clone / archive extraction in Go
		// before launch, so --target is always a local absolute path.
		//
		// A multi-mode chain is handed to audit's native `--modes` so
		// audit owns the sequential execution, stop-on-non-complete, the
		// --from-audit auto-detect between modes, and the aggregate
		// --max-cost cap. A single mode keeps the original `--mode` form so
		// existing behavior (and audit's per-mode resume semantics) is
		// untouched.
		args = []string{
			"run",
			"--target", cfg.SourcePath,
		}
		if modes := cfg.EffectiveModes(); len(modes) > 1 {
			args = append(args, "--modes", JoinModes(modes))
		} else {
			args = append(args, "--mode", modes[0])
		}
		args = append(args, cfg.AuditDriverInvocation.Args()...)
		// Pass our AgenticScan UUID to audit so its auth-overrides path can
		// namespace backup files (.audit-backup-<uuid>) and the cred-dir
		// lock breadcrumb. Two concurrent BYOK audits would otherwise
		// collide on a fixed-name backup; the per-uuid suffix makes the
		// collision a hard error from the lock instead of a silent stomp.
		if cfg.ScanUUID != "" {
			args = append(args, "--run-uuid", cfg.ScanUUID)
		}
		if cfg.KeepRaw {
			args = append(args, "--keep-raw")
		}
		if stream {
			args = append(args, "--json")
		}
		return binary, args, stdinPrompt, nil

	default:
		return "", nil, "", fmt.Errorf("unsupported audit platform %q", platform)
	}
}

// --- Public API ---

// StartAuditAgent creates and starts a background audit run for the given
// harness (audit or piolium). Returns nil runner when the cfg is disabled
// or sourcePath is empty. When streamWriter is non-nil, audit output is
// streamed in real-time. Harness-specific bits (Platform=pi + StreamDecoder
// for piolium) are auto-installed when harness.Name == "piolium".
func StartAuditAgent(ctx context.Context, agentCfg config.AuditAgentConfig, harness HarnessSpec, sourcePath, sessionDir, projectUUID, scanUUID, parentAgenticScanUUID string, repo *database.Repository, streamWriter io.Writer) (*AuditAgenticScanner, error) {
	if !agentCfg.IsEnabled() || sourcePath == "" {
		return nil, nil
	}
	if harness.Name == "" {
		harness = DefaultAuditHarness()
	}

	cfg := AuditAgentConfig{
		Harness:               harness,
		Mode:                  agentCfg.EffectiveMode(),
		Platform:              PlatformAuditBin,
		SourcePath:            sourcePath,
		SessionDir:            sessionDir,
		ProjectUUID:           projectUUID,
		ScanUUID:              scanUUID,
		ParentAgenticScanUUID: parentAgenticScanUUID,
		SyncInterval:          time.Duration(agentCfg.EffectiveSyncInterval()) * time.Second,
		StreamWriter:          streamWriter,
		Stream:                streamWriter != nil,
	}

	if harness.Name == piolium.HarnessName {
		cfg.Platform = PlatformPi
		cfg.Stream = true
		cfg.StreamDecoder = func(in io.Reader, render io.Writer, raw io.Writer) error {
			return pistream.Stream(in, render, pistream.Options{RawLog: raw})
		}
	}

	runner := NewAuditAgenticScanner(cfg, repo)
	if err := runner.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start %s-audit: %w", harness.Name, err)
	}

	return runner, nil
}

// startAuditAgentBackground is a shared helper that starts an audit (audit
// or piolium) and returns the runner and a wait func. Logs startup
// success/failure via the provided logFn. Returns nil runner and nil wait
// when the audit is disabled or fails to start. The harness drives the
// stale-output-dir cleanup (`<source>/<harness.SourceFolder>/`) and the
// platform/stream-decoder selection inside StartAuditAgent.
func startAuditAgentBackground(ctx context.Context, auditCfg *config.AuditAgentConfig, harness HarnessSpec, sourcePath, sessionDir, projectUUID, scanUUID, parentAgenticScanUUID string, repo *database.Repository, streamWriter io.Writer, logFn func(msg string)) (*AuditAgenticScanner, func(), error) {
	if auditCfg == nil || !auditCfg.IsEnabled() || sourcePath == "" {
		return nil, nil, nil
	}
	if harness.Name == "" {
		harness = DefaultAuditHarness()
	}

	// Clean up stale harness output dir from a previous crashed run.
	// Safe: no new audit is running yet at this point.
	staleDir := filepath.Join(sourcePath, harness.SourceFolder)
	if info, statErr := os.Stat(staleDir); statErr == nil && info.IsDir() {
		zap.L().Info("Removing stale audit output dir from previous run",
			zap.String("path", staleDir),
			zap.String("harness", harness.Name))
		if rmErr := os.RemoveAll(staleDir); rmErr != nil {
			zap.L().Warn("Failed to remove stale audit dir", zap.Error(rmErr))
		} else if logFn != nil {
			logFn(fmt.Sprintf("cleaned up stale %s/ dir from previous run", harness.SourceFolder))
		}
	}

	runner, err := StartAuditAgent(ctx, *auditCfg, harness, sourcePath, sessionDir, projectUUID, scanUUID, parentAgenticScanUUID, repo, streamWriter)
	if err != nil {
		zap.L().Warn("Failed to start background audit, continuing without it",
			zap.String("harness", harness.Name),
			zap.Error(err))
		if logFn != nil {
			logFn(fmt.Sprintf("%s-audit failed to start: %v", harness.Name, err))
		}
		return nil, nil, err
	}
	if runner == nil {
		return nil, nil, nil
	}

	if logFn != nil {
		logFn(fmt.Sprintf("started (%s mode)", auditCfg.EffectiveMode()))
	}

	// wait blocks until the runner's monitor goroutine has fully exited.
	// Callers use this to wait for a parallel audit to finish naturally —
	// do NOT call Cancel() here or a fast-finishing parent pipeline would
	// abort a still-running audit and mark it as "cancelled" in the DB.
	// When the parent ctx is cancelled (SIGINT/timeout), exec.CommandContext
	// already kills the subprocess and the monitor will complete on its own.
	wait := func() {
		<-runner.Done()
	}
	return runner, wait, nil
}

// ResolveAuditAgentConfig determines whether vigolium-audit should run.
