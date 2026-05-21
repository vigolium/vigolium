package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/storage"
	"go.uber.org/zap"
)

// auditRunPlan captures everything an audit-style endpoint needs to launch a
// run regardless of which harness (audit or piolium) backs it. The plumbing
// below — slot acquisition, session-dir creation, source resolution, SSE
// pump, runner wait, finalize — is identical across harnesses; harness-
// specific runtime fields (Mode, Platform, PluginDir, StreamDecoder,
// AdditionalArgs, PiProvider/PiModel, CommitScan*) are filled in by the
// buildCfg closure each endpoint supplies.
//
// Drives the single-driver paths: /agent/run/audit, /agent/run/audit
// with driver=audit, and /agent/run/audit with driver=piolium. The
// multi-driver driver=auto/both path lives in startCombinedAuditRun,
// which orchestrates these drivers sequentially under a parent
// AgenticScan UUID (auto stops after a clean audit run; both always
// runs piolium too).
type auditRunPlan struct {
	agenticScanUUID string

	source        string
	target        string
	diff          string
	lastCommits   int
	commitDepth   int
	files         []string
	stream        bool
	uploadResults bool
	projectUUID   string
	scanUUID      string

	timeout time.Duration

	// harness drives the AgenticScan row tags (Mode/AgentName), the user-
	// visible run-kind label in SSE messages, and is auto-installed onto
	// cfg.Harness before buildCfg runs.
	harness agent.HarnessSpec

	buildCfg func(cfg *agent.AuditAgentConfig)

	// authCleanup is fired once the audit finishes (success, failure, or
	// abort). Used to tear down per-request staged credentials from
	// oauth_cred_json. Nil-safe; the dispatch path always sets a non-nil
	// closure (even if it's a no-op).
	authCleanup func()
}

// auditRunSetup holds the resolved on-disk state shared by the SSE and
// background paths: session dir, runtime.log handle, resolved source path.
// cleanup is non-nil only when source resolution allocated a temp dir (e.g.
// gs:// download) that must be removed once the run completes.
type auditRunSetup struct {
	sessionDir string
	sourcePath string
	logFile    *os.File
	cleanup    func()
	failure    error
}

// startAuditRun acquires a heavy agent slot, registers the run, and dispatches
// to either the SSE or background path.
func (h *Handlers) startAuditRun(c fiber.Ctx, plan auditRunPlan) error {
	// Resolve project UUID before slot acquisition so per-project caps apply.
	if plan.projectUUID == "" {
		plan.projectUUID = getProjectUUID(c)
	}

	if !h.acquireHeavyAgentSlotForProject(c, plan.projectUUID) {
		if plan.authCleanup != nil {
			plan.authCleanup()
		}
		return nil // 429 already sent
	}

	agenticScanUUID, err := h.registerRunningAgenticScan(plan.harness.DBMode, plan.harness.DBAgentName, plan.scanUUID)
	if err != nil {
		h.releaseHeavyAgentSlotForProject(plan.projectUUID)
		if plan.authCleanup != nil {
			plan.authCleanup()
		}
		return respondScanPinError(c, err)
	}
	plan.agenticScanUUID = agenticScanUUID

	// Pre-populate request-time fields so /agent/sessions/:id shows useful info
	// while the run is in progress.
	h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
		run.ProjectUUID = plan.projectUUID
		run.TargetURL = plan.target
		run.SourcePath = plan.source
		run.SourceType = database.InferSourceType(plan.source)
	})

	if plan.stream {
		return h.handleAuditSSE(c, plan)
	}

	go h.runBackgroundAudit(plan)

	return c.Status(fiber.StatusAccepted).JSON(AgenticScanResponse{
		AgenticScanUUID: agenticScanUUID,
		Status:          "running",
		Message:         plan.harness.Name + " run started",
	})
}

// prepareAuditRun creates the session dir, opens runtime.log, and resolves the
// source (downloading gs:// archives, cloning git URLs, or extracting local
// archives) into a usable absolute path. On failure, returns a non-nil failure
// error and leaves logFile nil. Callers must invoke setup.cleanup when non-nil.
func (h *Handlers) prepareAuditRun(plan auditRunPlan) auditRunSetup {
	var setup auditRunSetup

	sessionDir, sessionErr := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), plan.agenticScanUUID)
	if sessionErr != nil {
		setup.failure = fmt.Errorf("create session dir: %w", sessionErr)
		return setup
	}
	setup.sessionDir = sessionDir

	sourcePath := plan.source
	files := plan.files

	// gs:// preflight: download+extract into a temp dir, then hand the local
	// path to ResolveSourceAndDiff like any other on-disk source.
	if storage.IsGCSURI(sourcePath) {
		extractedPath, gcsCleanup, gcsErr := storage.ResolveGCSSource(&h.settings.Storage, sourcePath, plan.projectUUID)
		if gcsErr != nil {
			setup.failure = fmt.Errorf("resolve gs:// source: %w", gcsErr)
			return setup
		}
		setup.cleanup = gcsCleanup
		sourcePath = extractedPath
	}

	if sourcePath != "" || plan.diff != "" || plan.lastCommits > 0 {
		resolved, _, _, err := agent.ResolveSourceAndDiff(
			sourcePath, plan.diff, plan.lastCommits, files, sessionDir,
			agent.WithCloneDepth(plan.commitDepth),
		)
		if err != nil {
			setup.failure = fmt.Errorf("resolve source: %w", err)
			return setup
		}
		sourcePath = resolved
	}
	setup.sourcePath = sourcePath

	logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		setup.logFile = f
	} else {
		zap.L().Warn("Failed to open audit runtime.log",
			zap.String("agentic_scan_uuid", plan.agenticScanUUID),
			zap.String("harness", plan.harness.Name),
			zap.Error(err))
	}

	return setup
}

// runBackgroundAudit executes the audit harness in a goroutine and updates
// status. The audit_agent runner persists most DB fields itself (status,
// duration, phases, result_json); this handler tops up the in-memory status
// snapshot and the FindingCount column that audit_agent doesn't currently
// set.
func (h *Handlers) runBackgroundAudit(plan auditRunPlan) {
	defer h.releaseHeavyAgentSlotForProject(plan.projectUUID)
	if plan.authCleanup != nil {
		defer plan.authCleanup()
	}

	ctx, cancel := context.WithTimeout(context.Background(), plan.timeout)
	defer cancel()

	setup := h.prepareAuditRun(plan)
	if setup.cleanup != nil {
		defer setup.cleanup()
	}
	if setup.logFile != nil {
		defer func() { _ = setup.logFile.Close() }()
	}
	if setup.failure != nil {
		h.recordAuditFailure(plan.agenticScanUUID, setup.failure)
		return
	}

	h.enrichAgenticScanRecord(plan.agenticScanUUID, func(run *database.AgenticScan) {
		run.SourcePath = setup.sourcePath
		run.SourceType = database.InferSourceType(setup.sourcePath)
		run.SessionDir = setup.sessionDir
	})

	streamWriter := io.Writer(io.Discard)
	if setup.logFile != nil {
		streamWriter = setup.logFile
	}

	runner, startErr := h.startAuditRunner(ctx, plan, setup, streamWriter)
	if startErr != nil {
		h.recordAuditFailure(plan.agenticScanUUID, startErr)
		return
	}
	runErr := h.waitAuditRunner(ctx, runner)
	h.finalizeAuditRun(plan, runner, runErr, setup.sessionDir)
}

// handleAuditSSE runs the audit harness synchronously while streaming chunks
// to the client. The stream writer is tee'd to runtime.log so SSE-mode runs
// also leave on-disk artifacts that /agent/sessions/:id/logs can serve later.
func (h *Handlers) handleAuditSSE(c fiber.Ctx, plan auditRunPlan) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer h.releaseHeavyAgentSlotForProject(plan.projectUUID)
		if plan.authCleanup != nil {
			defer plan.authCleanup()
		}

		ctx, cancel := context.WithTimeout(context.Background(), plan.timeout)
		defer cancel()

		setup := h.prepareAuditRun(plan)
		if setup.cleanup != nil {
			defer setup.cleanup()
		}
		if setup.logFile != nil {
			defer func() { _ = setup.logFile.Close() }()
		}
		if setup.failure != nil {
			h.recordAuditFailure(plan.agenticScanUUID, setup.failure)
			_ = writeSSE(w, sseEvent{Type: "error", Error: setup.failure.Error()})
			return
		}

		h.enrichAgenticScanRecord(plan.agenticScanUUID, func(run *database.AgenticScan) {
			run.SourcePath = setup.sourcePath
			run.SourceType = database.InferSourceType(setup.sourcePath)
			run.SessionDir = setup.sessionDir
		})

		pr, pw := io.Pipe()
		var streamWriter io.Writer = pw
		if setup.logFile != nil {
			streamWriter = io.MultiWriter(pw, setup.logFile)
		}

		runner, startErr := h.startAuditRunner(ctx, plan, setup, streamWriter)
		if startErr != nil {
			h.recordAuditFailure(plan.agenticScanUUID, startErr)
			_ = pw.Close()
			_ = writeSSE(w, sseEvent{Type: "error", Error: "failed to start " + plan.harness.Name})
			return
		}

		// Closer goroutine: when the runner finishes, close pw so the SSE read
		// loop exits.
		done := make(chan error, 1)
		go func() {
			done <- h.waitAuditRunner(ctx, runner)
			_ = pw.Close()
		}()

		buf := make([]byte, 4096)
		for {
			n, readErr := pr.Read(buf)
			if n > 0 {
				if writeErr := writeSSE(w, sseEvent{Type: "chunk", Text: string(buf[:n])}); writeErr != nil {
					_ = pr.Close()
					<-done
					return
				}
			}
			if readErr != nil {
				break
			}
		}

		runErr := <-done
		h.finalizeAuditRun(plan, runner, runErr, setup.sessionDir)

		if runErr != nil {
			_ = writeSSE(w, sseEvent{Type: "error", Error: runErr.Error()})
			return
		}
		_ = writeSSE(w, sseEvent{Type: "done"})
	})
}

// startAuditRunner builds the AuditAgentConfig and launches the audit
// scanner. Returns (nil, err) on start failure.
func (h *Handlers) startAuditRunner(ctx context.Context, plan auditRunPlan, setup auditRunSetup, streamWriter io.Writer) (agent.AuditRunner, error) {
	cfg := agent.AuditAgentConfig{
		Harness:      plan.harness,
		SourcePath:   setup.sourcePath,
		SessionDir:   setup.sessionDir,
		ProjectUUID:  plan.projectUUID,
		ScanUUID:     plan.scanUUID,
		SyncInterval: 30 * time.Second,
		StreamWriter: streamWriter,
	}
	if plan.buildCfg != nil {
		plan.buildCfg(&cfg)
	}

	agentName, agentProvider, agentModel := h.auditDriverAgentInfo(plan.harness.Name, cfg)
	zap.L().Info("Audit driver dispatching",
		zap.String("agentic_scan_uuid", plan.agenticScanUUID),
		zap.String("driver", plan.harness.Name),
		zap.String("agent", agentName),
		zap.String("provider", agentProvider),
		zap.String("model", agentModel))

	runner := agent.NewAuditRunner(cfg, h.repo)
	if err := runner.Start(ctx); err != nil {
		zap.L().Error("Failed to start audit-agent",
			zap.String("source", setup.sourcePath),
			zap.String("harness", plan.harness.Name),
			zap.String("mode", cfg.Mode),
			zap.String("platform", cfg.Platform),
			zap.Error(err))
		return nil, fmt.Errorf("start %s: %w", plan.harness.Name, err)
	}
	return runner, nil
}

// waitAuditRunner blocks until the runner exits or ctx is cancelled. On
// cancellation we ask the runner to stop and then drain Done() so the caller
// is guaranteed to see final state.
func (h *Handlers) waitAuditRunner(ctx context.Context, runner agent.AuditRunner) error {
	select {
	case <-runner.Done():
	case <-ctx.Done():
		runner.Cancel()
		<-runner.Done()
	}
	return runner.Wait()
}

// finalizeAuditRun records the final status to in-memory + DB and optionally
// uploads the session bundle. The audit_agent runner already persists status,
// duration, phases, and result_json — this handler covers the FindingCount
// column (audit_agent doesn't write it) and the in-memory status snapshot.
func (h *Handlers) finalizeAuditRun(plan auditRunPlan, runner agent.AuditRunner, runErr error, sessionDir string) {
	now := time.Now()
	stats := runner.FindingStats()

	h.agentMu.Lock()
	if status := h.agenticScanStatus[plan.agenticScanUUID]; status != nil {
		if runErr != nil {
			status.Status = "failed"
			status.Error = runErr.Error()
		} else {
			status.Status = "completed"
		}
		status.CompletedAt = &now
		status.FindingCount = stats.Parsed
		status.SavedCount = stats.Saved
	}
	h.agentMu.Unlock()

	// Top up the FindingCount column — audit_agent's finalize doesn't set it.
	h.enrichAgenticScanRecord(plan.agenticScanUUID, func(run *database.AgenticScan) {
		if stats.Parsed > 0 {
			run.FindingCount = stats.Parsed
		}
		if stats.Saved > 0 {
			run.SavedCount = stats.Saved
		}
	})

	if plan.uploadResults && sessionDir != "" {
		h.uploadAgenticResults(plan.projectUUID, plan.agenticScanUUID, sessionDir)
	}

	webhook.FireAgenticScan(h.settings, h.repo, plan.agenticScanUUID)

	zap.L().Info("Audit run completed",
		zap.String("agentic_scan_uuid", plan.agenticScanUUID),
		zap.String("harness", plan.harness.Name),
		zap.String("session_dir", sessionDir),
		zap.Int("findings_parsed", stats.Parsed),
		zap.Int("findings_saved", stats.Saved))
}

// recordAuditFailure marks the run as failed before the audit scanner has had
// a chance to write its own DB row. Used for setup errors (session dir, source
// resolution, scanner start).
func (h *Handlers) recordAuditFailure(agenticScanUUID string, err error) {
	now := time.Now()

	h.agentMu.Lock()
	if status := h.agenticScanStatus[agenticScanUUID]; status != nil {
		status.Status = "failed"
		status.Error = err.Error()
		status.CompletedAt = &now
	}
	h.agentMu.Unlock()

	h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
		run.Status = "failed"
		run.ErrorMessage = err.Error()
		run.CompletedAt = now
		run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
	})

	webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)

	zap.L().Error("Audit run failed during setup", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(err))
}
