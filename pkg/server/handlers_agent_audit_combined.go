package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/piolium/pistream"
	"github.com/vigolium/vigolium/pkg/storage"
	"go.uber.org/zap"
)

// auditMuxBufferSize is the chunk size the SSE pump reads from each
// driver's pipe. Matches the single-driver pump in handlers_agent_audit_runner.go.
const auditMuxBufferSize = 4096

// startCombinedAuditRun is the driver=both / driver=auto entry point.
// Creates a parent AgenticScan row, resolves the source once, then runs
// the driver(s) as child runs (each with its own per-driver session
// subdir + child AgenticScan row pointing at the parent). After the
// drivers exit, runs a project-wide findings dedup pass.
//
// driver=both runs archon then piolium unconditionally. driver=auto runs
// archon and only falls back to piolium when archon fails — a clean
// archon run finishes the audit and piolium is never started.
//
// SSE: when req.Stream is true, driver output is multiplexed into one
// stream with each event tagged via the "driver" field, bracketed by
// driver_start/driver_end markers.
//
// Under driver=both a failed driver does NOT abort the other — both run
// independently. The parent row is marked "completed_with_errors" if any
// driver failed.
func (h *Handlers) startCombinedAuditRun(c fiber.Ctx, driver string, req AgentAuditRequest, archonModes, pioliumModes []string, preset agent.ArchonIntensityPreset, additionalArgs []string, archonOverride, pioliumOverride agent.AuthOverride, authCleanup func()) error {
	// Resolve project UUID before slot acquisition so per-project caps apply.
	projectUUID := req.ProjectUUID
	if projectUUID == "" {
		projectUUID = getProjectUUID(c)
	}

	if !h.acquireHeavyAgentSlotForProject(c, projectUUID) {
		if authCleanup != nil {
			authCleanup()
		}
		return nil // 429 already sent
	}

	parentUUID, err := h.registerRunningAgenticScan("audit", driver, req.ScanUUID)
	if err != nil {
		h.releaseHeavyAgentSlotForProject(projectUUID)
		if authCleanup != nil {
			authCleanup()
		}
		return respondScanPinError(c, err)
	}

	h.enrichAgenticScanRecord(parentUUID, func(run *database.AgenticScan) {
		run.ProjectUUID = projectUUID
		run.TargetURL = req.Target
		run.SourcePath = req.Source
		run.SourceType = database.InferSourceType(req.Source)
	})

	plan := combinedAuditPlan{
		driver:          driver,
		req:             req,
		archonModes:     archonModes,
		pioliumModes:    pioliumModes,
		preset:          preset,
		additionalArgs:  additionalArgs,
		parentUUID:      parentUUID,
		projectUUID:     projectUUID,
		archonOverride:  archonOverride,
		pioliumOverride: pioliumOverride,
		authCleanup:     authCleanup,
	}

	if req.Stream {
		return h.handleCombinedAuditSSE(c, plan)
	}

	go h.runCombinedAuditBackground(plan)

	return c.Status(fiber.StatusAccepted).JSON(AgenticScanResponse{
		AgenticScanUUID: parentUUID,
		Status:          "running",
		Message:         fmt.Sprintf("audit (driver=%s) started", driver),
	})
}

type combinedAuditPlan struct {
	// driver is "both" or "auto". "auto" runs piolium only when archon
	// fails; "both" runs both unconditionally.
	driver string
	req    AgentAuditRequest
	// Per-driver filtered mode chains. For driver=auto/both these may
	// differ (per-driver skip-unsupported); an empty leg is skipped.
	archonModes    []string
	pioliumModes   []string
	preset         agent.ArchonIntensityPreset
	additionalArgs []string
	// archonOverride / pioliumOverride are the resolved BYOK bundles per
	// driver. Each is the top-level request override, or a per-driver
	// override from req.ArchonAuth / req.PioliumAuth when supplied. Already
	// validated and (if inline JSON) staged by HandleAgentAudit.
	archonOverride  agent.AuthOverride
	pioliumOverride agent.AuthOverride
	// authCleanup tears down any per-request staged cred files once both
	// drivers complete. Nil when no staging happened (CLI-style server
	// path cred or no BYOK at all).
	authCleanup func()

	parentUUID  string
	projectUUID string
}

func (h *Handlers) runCombinedAuditBackground(plan combinedAuditPlan) {
	defer h.releaseHeavyAgentSlotForProject(plan.projectUUID)
	if plan.authCleanup != nil {
		defer plan.authCleanup()
	}

	setup, err := h.prepareCombinedAuditRun(plan)
	if err != nil {
		h.recordAuditFailure(plan.parentUUID, err)
		return
	}
	if setup.cleanup != nil {
		defer setup.cleanup()
	}

	startedAt := time.Now()
	results := h.runDriversSequentially(context.Background(), plan, setup, nil)
	h.finalizeCombinedAuditRun(plan, setup, results, startedAt)
}

func (h *Handlers) handleCombinedAuditSSE(c fiber.Ctx, plan combinedAuditPlan) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer h.releaseHeavyAgentSlotForProject(plan.projectUUID)
		if plan.authCleanup != nil {
			defer plan.authCleanup()
		}

		setup, err := h.prepareCombinedAuditRun(plan)
		if err != nil {
			h.recordAuditFailure(plan.parentUUID, err)
			_ = writeSSE(w, sseEvent{Type: "error", Error: err.Error()})
			return
		}
		if setup.cleanup != nil {
			defer setup.cleanup()
		}

		startedAt := time.Now()
		// w is shared with the per-driver SSE pump goroutine; the pump's
		// pumpDone channel guarantees it has exited before we write the
		// closing aggregate event below, so concurrent writes to w never
		// overlap.
		results := h.runDriversSequentially(context.Background(), plan, setup, w)
		h.finalizeCombinedAuditRun(plan, setup, results, startedAt)

		anyErr := false
		for _, r := range results {
			if r.runErr != nil {
				anyErr = true
				break
			}
		}
		if anyErr {
			_ = writeSSE(w, sseEvent{Type: "error", Error: "one or more drivers failed; see driver_end events"})
			return
		}
		_ = writeSSE(w, sseEvent{Type: "done"})
	})
}

type combinedAuditSetup struct {
	parentSessionDir string
	resolvedSource   string
	cleanup          func()
}

type driverResult struct {
	name       string
	sessionDir string
	// AuditRunner so a multi-mode piolium chain
	// (*agent.PioliumChainScanner) is a drop-in for a single
	// *agent.AuditAgenticScanner.
	runner agent.AuditRunner
	runErr error
}

// prepareCombinedAuditRun creates the parent session dir and resolves
// the source (gs:// download, git clone, archive extraction) once. Both
// drivers reuse the resolved absolute path so we don't clone the same
// git URL twice.
func (h *Handlers) prepareCombinedAuditRun(plan combinedAuditPlan) (combinedAuditSetup, error) {
	var setup combinedAuditSetup

	parentDir, err := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), plan.parentUUID)
	if err != nil {
		return setup, fmt.Errorf("create parent session dir: %w", err)
	}
	setup.parentSessionDir = parentDir

	source := plan.req.Source
	if storage.IsGCSURI(source) {
		extractedPath, gcsCleanup, gcsErr := storage.ResolveGCSSource(&h.settings.Storage, source, plan.projectUUID)
		if gcsErr != nil {
			return setup, fmt.Errorf("resolve gs:// source: %w", gcsErr)
		}
		setup.cleanup = gcsCleanup
		source = extractedPath
	}

	resolved, _, _, err := agent.ResolveSourceAndDiff(
		source, plan.req.Diff, plan.req.LastCommits, plan.req.Files, parentDir,
		agent.WithCloneDepth(plan.preset.CommitDepth),
	)
	if err != nil {
		return setup, fmt.Errorf("resolve source: %w", err)
	}
	if resolved == "" {
		return setup, fmt.Errorf("source path could not be resolved: %s", plan.req.Source)
	}
	setup.resolvedSource = resolved

	h.enrichAgenticScanRecord(plan.parentUUID, func(run *database.AgenticScan) {
		run.SourcePath = resolved
		run.SourceType = database.InferSourceType(resolved)
		run.SessionDir = parentDir
	})

	return setup, nil
}

// runDriversSequentially runs archon then piolium.
//
// driver=both: both run unconditionally; one failing does NOT abort the
// other. driver=auto: archon runs first and, if it succeeds, the audit
// is complete — piolium is never started. piolium only runs as a
// fallback when archon fails.
func (h *Handlers) runDriversSequentially(ctx context.Context, plan combinedAuditPlan, setup combinedAuditSetup, sseWriter *bufio.Writer) []driverResult {
	results := make([]driverResult, 0, 2)

	// For driver=auto/both a chain may contain modes only one driver
	// understands; the other driver's filtered chain is empty and that
	// leg is skipped rather than running a bogus mode.
	archonHasModes := len(plan.archonModes) > 0
	pioliumHasModes := len(plan.pioliumModes) > 0

	archonRan := false
	var archonErr error
	if archonHasModes {
		archonRes := h.runOneCombinedDriver(ctx, agent.AuditDriverArchon, plan, setup, sseWriter)
		results = append(results, archonRes)
		archonRan = true
		archonErr = archonRes.runErr
	} else {
		zap.L().Info("Combined audit: archon leg skipped — no archon-supported modes in chain",
			zap.String("agentic_scan_uuid", plan.parentUUID))
	}

	// auto stops here on a clean archon run — piolium is fallback-only.
	if plan.driver == agent.AuditDriverAuto && archonRan && archonErr == nil {
		return results
	}

	if pioliumHasModes {
		results = append(results, h.runOneCombinedDriver(ctx, agent.AuditDriverPiolium, plan, setup, sseWriter))
	} else {
		zap.L().Info("Combined audit: piolium leg skipped — no piolium-supported modes in chain",
			zap.String("agentic_scan_uuid", plan.parentUUID))
	}
	return results
}

// runOneCombinedDriver executes a single child driver under the parent
// run with its own per-driver timeout (so an archon hang doesn't burn
// piolium's budget). Stream multiplexing for SSE is handled here so the
// driver-end marker fires on subprocess exit.
func (h *Handlers) runOneCombinedDriver(ctx context.Context, name string, plan combinedAuditPlan, setup combinedAuditSetup, sseWriter *bufio.Writer) driverResult {
	res := driverResult{
		name:       name,
		sessionDir: filepath.Join(setup.parentSessionDir, name),
	}

	if err := os.MkdirAll(res.sessionDir, 0o755); err != nil {
		res.runErr = fmt.Errorf("create %s session dir: %w", name, err)
		emitDriverFailure(sseWriter, name, res.runErr)
		return res
	}

	logPath := filepath.Join(res.sessionDir, config.RuntimeLogFilename)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		zap.L().Warn("Failed to open combined audit runtime.log",
			zap.String("agentic_scan_uuid", plan.parentUUID),
			zap.String("driver", name),
			zap.Error(err))
	} else {
		defer func() { _ = logFile.Close() }()
	}

	if sseWriter != nil {
		_ = writeSSE(sseWriter, sseEvent{Type: "driver_start", Driver: name})
	}

	cfg, cfgErr := h.buildCombinedDriverCfg(name, plan, res.sessionDir, setup.resolvedSource)
	if cfgErr != nil {
		res.runErr = cfgErr
		emitDriverFailure(sseWriter, name, cfgErr)
		return res
	}

	// Record which AI agent this driver dispatches so REST runs have the
	// same "what agent am I using" visibility as the CLI banner. Lands in
	// both the server log and the per-driver runtime.log.
	agentName, agentProvider, agentModel := h.auditDriverAgentInfo(name, cfg)
	zap.L().Info("Audit driver dispatching",
		zap.String("agentic_scan_uuid", plan.parentUUID),
		zap.String("driver", name),
		zap.String("agent", agentName),
		zap.String("provider", agentProvider),
		zap.String("model", agentModel))

	streamWriter, pipeReader, pipeWriter := buildDriverStreamWriter(sseWriter, logFile)
	cfg.StreamWriter = streamWriter

	driverTimeout := plan.preset.Timeout
	if driverTimeout <= 0 {
		driverTimeout = 6 * time.Hour
	}
	driverCtx, driverCancel := context.WithTimeout(ctx, driverTimeout)
	defer driverCancel()

	res.runner = agent.NewAuditRunner(cfg, h.repo)
	if err := res.runner.Start(driverCtx); err != nil {
		res.runErr = fmt.Errorf("start %s: %w", name, err)
		if pipeWriter != nil {
			_ = pipeWriter.Close()
		}
		emitDriverFailure(sseWriter, name, res.runErr)
		return res
	}

	pumpDone := runDriverSSEPump(sseWriter, pipeReader, name)

	res.runErr = h.waitAuditRunner(driverCtx, res.runner)

	if pipeWriter != nil {
		_ = pipeWriter.Close()
	}
	<-pumpDone

	if sseWriter != nil {
		end := sseEvent{Type: "driver_end", Driver: name}
		if res.runErr != nil {
			end.Error = res.runErr.Error()
		}
		_ = writeSSE(sseWriter, end)
	}

	return res
}

// buildDriverStreamWriter sets up the per-driver stream sink: per-driver
// runtime.log when the file is open, plus an io.Pipe-backed forwarder to
// the SSE writer when streaming. Returns the writer the runner should
// use plus the pipe handles the caller needs to close on shutdown.
func buildDriverStreamWriter(sseWriter *bufio.Writer, logFile *os.File) (io.Writer, *io.PipeReader, *io.PipeWriter) {
	if sseWriter == nil {
		if logFile != nil {
			return logFile, nil, nil
		}
		return io.Discard, nil, nil
	}
	pr, pw := io.Pipe()
	if logFile != nil {
		return io.MultiWriter(pw, logFile), pr, pw
	}
	return pw, pr, pw
}

// runDriverSSEPump reads chunks from pipeReader and forwards them as
// driver-tagged SSE events. On the first writeSSE error (typically
// client disconnect) it stops forwarding but keeps draining the pipe so
// the runner doesn't block on a full pipe — back-pressure stays at the
// SSE socket, not on the audit subprocess. Returns a channel that
// closes when the pump exits.
func runDriverSSEPump(sseWriter *bufio.Writer, pipeReader *io.PipeReader, driver string) <-chan struct{} {
	done := make(chan struct{})
	if pipeReader == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		buf := make([]byte, auditMuxBufferSize)
		clientGone := false
		for {
			n, readErr := pipeReader.Read(buf)
			if n > 0 && !clientGone {
				if err := writeSSE(sseWriter, sseEvent{Type: "chunk", Driver: driver, Text: string(buf[:n])}); err != nil {
					clientGone = true
				}
			}
			if readErr != nil {
				return
			}
		}
	}()
	return done
}

// emitDriverFailure writes the driver-tagged error + driver_end markers
// when the driver couldn't start. No-op when not streaming.
func emitDriverFailure(sseWriter *bufio.Writer, driver string, err error) {
	if sseWriter == nil {
		return
	}
	_ = writeSSE(sseWriter, sseEvent{Type: "error", Driver: driver, Error: err.Error()})
	_ = writeSSE(sseWriter, sseEvent{Type: "driver_end", Driver: driver, Error: err.Error()})
}

// auditDriverAgentInfo derives the (agent, provider, model) tuple for a
// driver's resolved config, for the "Audit driver dispatching" log. For
// archon the agent (claude|codex) is read back from the resolved
// invocation so it reflects req.Agent / BYOK-driven selection; the
// provider/model come from the server's olium config. For piolium the
// agent is pi and provider/model are the request overrides (empty =
// whatever pi's own settings.json configures).
func (h *Handlers) auditDriverAgentInfo(name string, cfg agent.AuditAgentConfig) (agentName, provider, model string) {
	orDefault := func(v, fallback string) string {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
		return fallback
	}
	switch name {
	case agent.AuditDriverPiolium:
		return "pi",
			orDefault(cfg.PiProvider, "(pi config)"),
			orDefault(cfg.PiModel, "(pi config)")
	default: // archon
		// archon dispatches the claude/codex CLI directly (no --model
		// flag); the model is governed by that CLI's own config, not the
		// in-process olium model. Don't report olium's provider/model.
		a := orDefault(string(cfg.ArchonInvocation.Agent), string(agent.ArchonAgentClaude))
		return a, a + " CLI", "(" + a + " CLI config)"
	}
}

// buildCombinedDriverCfg returns the AuditAgentConfig for one driver.
// Source is the already-resolved absolute path; SessionDir is the
// per-driver subdir under the parent session. ParentAgenticScanUUID
// makes the runner register a child row instead of a standalone one.
func (h *Handlers) buildCombinedDriverCfg(name string, plan combinedAuditPlan, sessionDir, sourcePath string) (agent.AuditAgentConfig, error) {
	switch name {
	case agent.AuditDriverArchon:
		invocation := agent.ResolveArchonInvocation(h.settings.Agent.Olium, h.archonPlatformForReq(&plan.req), plan.archonOverride)
		return agent.BuildArchonAuditCfg(agent.ArchonCfgInput{
			Mode:                  agent.FirstMode(plan.archonModes),
			Modes:                 plan.archonModes,
			SourcePath:            sourcePath,
			SessionDir:            sessionDir,
			ProjectUUID:           plan.projectUUID,
			ScanUUID:              plan.req.ScanUUID,
			ParentAgenticScanUUID: plan.parentUUID,
			Invocation:            invocation,
			Stream:                true,
			AuthOverride:          plan.archonOverride,
		}), nil

	case agent.AuditDriverPiolium:
		return agent.AuditAgentConfig{
			Harness:               piolium.DefaultHarness(),
			Mode:                  agent.FirstMode(plan.pioliumModes),
			Modes:                 plan.pioliumModes,
			Platform:              agent.PlatformPi,
			SourcePath:            sourcePath,
			SessionDir:            sessionDir,
			ProjectUUID:           plan.projectUUID,
			ScanUUID:              plan.req.ScanUUID,
			ParentAgenticScanUUID: plan.parentUUID,
			SyncInterval:          agent.DefaultAuditSyncInterval,
			Stream:                true,
			AdditionalArgs:        plan.additionalArgs,
			PiProvider:            plan.req.PiProvider,
			PiModel:               plan.req.PiModel,
			CommitScanLimit:       plan.req.PlmScanLimit,
			CommitScanSince:       plan.req.PlmScanSince,
			AuthOverride:          plan.pioliumOverride,
			StreamDecoder: func(r io.Reader, render io.Writer, raw io.Writer) error {
				return pistream.Stream(r, render, pistream.Options{RawLog: raw})
			},
		}, nil
	}
	return agent.AuditAgentConfig{}, fmt.Errorf("unknown driver %q", name)
}

func (h *Handlers) finalizeCombinedAuditRun(plan combinedAuditPlan, setup combinedAuditSetup, results []driverResult, startedAt time.Time) {
	if !plan.req.NoDedup && h.repo != nil && plan.projectUUID != "" {
		dedupCtx, cancel := context.WithTimeout(context.Background(), agent.AuditDedupTimeout)
		_, _, dedupErr := h.repo.DeduplicateFindings(dedupCtx, plan.projectUUID)
		cancel()
		if dedupErr != nil {
			zap.L().Warn("Combined audit findings dedup failed",
				zap.String("agentic_scan_uuid", plan.parentUUID),
				zap.Error(dedupErr))
		}
	}

	now := time.Now()
	totalParsed := 0
	totalSaved := 0
	status := "completed"
	var errMsg string
	for _, r := range results {
		if r.runner != nil {
			stats := r.runner.FindingStats()
			totalParsed += stats.Parsed
			totalSaved += stats.Saved
		}
		if r.runErr != nil {
			status = "completed_with_errors"
			if errMsg != "" {
				errMsg += "; "
			}
			errMsg += r.name + ": " + r.runErr.Error()
		}
	}

	h.agentMu.Lock()
	if memStatus := h.agenticScanStatus[plan.parentUUID]; memStatus != nil {
		memStatus.Status = status
		memStatus.CompletedAt = &now
		memStatus.FindingCount = totalParsed
		memStatus.SavedCount = totalSaved
		if errMsg != "" {
			memStatus.Error = errMsg
		}
	}
	h.agentMu.Unlock()

	h.enrichAgenticScanRecord(plan.parentUUID, func(run *database.AgenticScan) {
		run.Status = status
		run.ErrorMessage = errMsg
		run.CompletedAt = now
		run.DurationMs = now.Sub(startedAt).Milliseconds()
		run.FindingCount = totalParsed
		run.SavedCount = totalSaved
	})

	// Skip upload when any driver failed — partial uploads stamped as
	// "complete results" are worse than no upload.
	if plan.req.UploadResults && setup.parentSessionDir != "" && status == "completed" {
		h.uploadAgenticResults(plan.projectUUID, plan.parentUUID, setup.parentSessionDir)
	}

	webhook.FireAgenticScan(h.settings, h.repo, plan.parentUUID)

	zap.L().Info("Combined audit run completed",
		zap.String("agentic_scan_uuid", plan.parentUUID),
		zap.String("session_dir", setup.parentSessionDir),
		zap.String("status", status),
		zap.Int("findings_parsed", totalParsed),
		zap.Int("findings_saved", totalSaved))
}
