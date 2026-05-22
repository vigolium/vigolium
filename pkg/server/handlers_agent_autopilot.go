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
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// POST /api/agent/run/autopilot — autonomous scanning session
// ---------------------------------------------------------------------------

// HandleAgentAutopilot handles POST /api/agent/run/autopilot — launches an autonomous AI scanning session.
func (h *Handlers) HandleAgentAutopilot(c fiber.Ctx) error {
	var req AgentAutopilotRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
		})
	}

	// Natural language prompt: resolve when explicit fields are empty
	if req.Prompt != "" && req.Target == "" && req.Input == "" && req.SourcePath == "" && req.Diff == "" && req.LastCommits == 0 {
		if refused := h.refuseIfGuardrailBlocks(c, req.Prompt); refused != nil {
			return refused
		}
		resolved, resolveErr := h.resolvePromptIntent(c, req.Prompt)
		if resolveErr != nil {
			return resolveErr // already sent HTTP response
		}
		if req.DryRun {
			return c.Status(fiber.StatusOK).JSON(fiber.Map{"intent": resolved})
		}
		// Apply first app from intent (API handles single-app only; use swarm for multi-app)
		if len(resolved.Apps) > 0 {
			app := resolved.Apps[0]
			req.Target = app.Target
			if req.SourcePath == "" {
				req.SourcePath = app.SourcePath
			}
			if req.Focus == "" {
				req.Focus = app.Focus
			}
			if req.Instruction == "" {
				req.Instruction = app.Instruction
			}
			// Map intent audit to new fields (not legacy Audit)
			if app.Audit != "" && req.AuditDriverMode == "" {
				if app.Audit == "off" {
					req.NoAudit = true
				} else {
					req.AuditDriverMode = app.Audit
				}
			}
			if app.Diff != "" && req.Diff == "" {
				req.Diff = app.Diff
			}
			if len(app.Files) > 0 && len(req.Files) == 0 {
				req.Files = app.Files
			}
			if app.Browser && !req.Browser {
				req.Browser = true
			}
			if app.Credentials != "" && req.Credentials == "" {
				req.Credentials = app.Credentials
			}
			if len(app.CredentialSets) > 0 && len(req.CredentialSets) == 0 {
				req.CredentialSets = append([]agent.IntentCredentialSet(nil), app.CredentialSets...)
			}
			if app.AuthRequired && !req.AuthRequired {
				req.AuthRequired = true
			}
			if app.RequiresBrowser && !req.RequiresBrowser {
				req.RequiresBrowser = true
			}
			if app.BrowserStartURL != "" && req.BrowserStartURL == "" {
				req.BrowserStartURL = app.BrowserStartURL
			}
			if len(app.FocusRoutes) > 0 && len(req.FocusRoutes) == 0 {
				req.FocusRoutes = append([]string(nil), app.FocusRoutes...)
			}
			if app.MaxCommands > 0 && req.MaxCommands == 0 {
				req.MaxCommands = app.MaxCommands
			}
			if app.Timeout != "" && req.Timeout == "" {
				req.Timeout = app.Timeout
			}
			if app.Intensity != "" && req.Intensity == "" {
				req.Intensity = app.Intensity
			}
		}
	}

	// Derive target from input when target is not provided
	if req.Target == "" && req.Input != "" {
		targetURL, err := agent.TargetURLFromInput(context.Background(), req.Input, "", h.repo)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error: "could not extract target URL from input: " + err.Error(),
			})
		}
		req.Target = targetURL
	}

	if req.Target == "" && req.SourcePath == "" && req.Diff == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "target, source, or diff is required (use target, input, source, diff, or prompt field)",
		})
	}

	// Validate audit_mode if provided
	if mode := req.ResolvedAuditDriverMode(); mode != "lite" && mode != "balanced" && mode != "scan" && mode != "deep" && mode != "mock" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: fmt.Sprintf("invalid audit_mode %q: must be lite, balanced, deep, or mock", mode),
		})
	}

	// Resolve intensity preset
	intensity, intensityErr := agent.ValidateIntensity(req.Intensity)
	if intensityErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: intensityErr.Error()})
	}
	{
		changed := map[string]bool{
			"max-commands": req.MaxCommands != 0,
			"timeout":      req.Timeout != "",
			"audit-mode":   req.AuditDriverMode != "",
			"no-audit":     req.NoAudit || req.Audit == "off",
			"browser":      req.Browser || req.RequiresBrowser,
		}
		result := agent.ResolveAutopilotIntensity(intensity, agent.AutopilotIntensityPreset{
			MaxCommands:     req.MaxCommands,
			Timeout:         parseDurationOrDefault(req.Timeout, 6*time.Hour),
			AuditDriverMode: req.ResolvedAuditDriverMode(),
			Browser:         req.Browser || req.RequiresBrowser,
		}, changed)
		if req.MaxCommands == 0 {
			req.MaxCommands = result.MaxCommands
		}
		if req.Timeout == "" {
			req.Timeout = result.Timeout.String()
		}
		if req.AuditDriverMode == "" && req.Audit == "" {
			req.AuditDriverMode = result.AuditDriverMode
		}
		if !req.Browser {
			req.Browser = result.Browser
		}
	}

	timeout := parseDurationOrDefault(req.Timeout, 6*time.Hour)

	eng, cleanup, byokErr := h.engineForRequest(req.AgentBYOK)
	if byokErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "byok: " + byokErr.Error(),
		})
	}

	return h.startAutopilotRun(c, req, timeout, eng, cleanup)
}

// startAutopilotRun acquires a heavy agent slot, creates status tracking, and runs the autopilot pipeline.
func (h *Handlers) startAutopilotRun(c fiber.Ctx, req AgentAutopilotRequest, timeout time.Duration, engine *agent.Engine, byokCleanup func()) error {
	// Resolve project UUID before slot acquisition so the per-project cap
	// applies to this request. Falls back to the X-Project-UUID header
	// when the body field is empty.
	projectUUID := req.ProjectUUID
	if projectUUID == "" {
		projectUUID = getProjectUUID(c)
	}

	if !h.acquireHeavyAgentSlotForProject(c, projectUUID) {
		if byokCleanup != nil {
			byokCleanup()
		}
		return nil // 429 already sent
	}

	agenticScanUUID, err := h.registerRunningAgenticScan("autopilot", req.Agent, req.ScanUUID)
	if err != nil {
		h.releaseHeavyAgentSlotForProject(projectUUID)
		if byokCleanup != nil {
			byokCleanup()
		}
		return respondScanPinError(c, err)
	}

	// Populate the request-time fields right away so the session detail
	// endpoint shows meaningful info while the run is in progress.
	h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
		run.ProjectUUID = projectUUID
		run.TargetURL = req.Target
		run.SourcePath = req.SourcePath
		run.SourceType = database.InferSourceType(req.SourcePath)
		run.InputRaw = req.Instruction
	})

	if req.Stream {
		return h.handleAutopilotSSE(c, agenticScanUUID, req, projectUUID, timeout, engine, byokCleanup)
	}

	go h.runBackgroundAutopilot(agenticScanUUID, req, projectUUID, timeout, engine, byokCleanup)

	return c.Status(fiber.StatusAccepted).JSON(AgenticScanResponse{
		AgenticScanUUID: agenticScanUUID,
		Status:          "running",
		Message:         "autopilot run started",
	})
}

// resolveAutopilotAuditCfgServer mirrors the CLI's audit-harness auto-pick
// for the server's autopilot endpoint. When the request leaves both `audit`
// and `piolium` empty, piolium wins if the server has pi+piolium installed,
// otherwise audit's existing auto-on-source default applies. An explicit
// `piolium` value disables audit (one harness per scan).
func (h *Handlers) resolveAutopilotAuditCfgServer(req AgentAutopilotRequest, sourcePath string) (*config.AuditAgentConfig, agent.HarnessSpec) {
	pioliumMode := req.Piolium
	if sourcePath != "" && pioliumMode == "" {
		auditExplicit := req.Audit != "" || req.AuditDriverMode != "" || req.NoAudit
		if !auditExplicit && h.pioliumAvailableCached() {
			pioliumMode = req.ResolvedAuditDriverMode()
		}
	}
	return agent.PickAuditHarness(pioliumMode, req.ResolvedAuditDriverMode(), req.ResolvedNoAudit(), sourcePath, h.settings.Agent.Audit)
}

// resolveSwarmAuditCfgServer is the swarm counterpart. Swarm audit is opt-in
// (empty = nothing), so auto-pick fires only when both `audit` and `piolium`
// are empty AND a source path is set.
func (h *Handlers) resolveSwarmAuditCfgServer(req AgentSwarmRequest, sourcePath string) (*config.AuditAgentConfig, agent.HarnessSpec) {
	pioliumMode := req.Piolium
	if pioliumMode == "" && req.Audit == "" && sourcePath != "" && h.pioliumAvailableCached() {
		pioliumMode = "lite"
	}
	return agent.PickAuditHarness(pioliumMode, req.ResolvedAuditDriverMode(), req.ResolvedNoAudit(), sourcePath, h.settings.Agent.Audit)
}

// buildAutopilotPipelineConfig creates an AutopilotPipelineConfig from an autopilot request.
// projectUUID should be pre-resolved by the caller (from request body or X-Project-UUID header).
// parentAgenticScanUUID is the UUID of the parent AgenticScan row so child runs (audit) can reference it.
func (h *Handlers) buildAutopilotPipelineConfig(req AgentAutopilotRequest, projectUUID, parentAgenticScanUUID string) agent.AutopilotPipelineConfig {
	maxCmds := req.MaxCommands
	if maxCmds <= 0 {
		maxCmds = 100
	}

	sourcePath := req.SourcePath
	files := req.Files
	var diffCtx *agenttypes.DiffContext

	// Resolve source (git URL, archive, local path) and diff context
	if sourcePath != "" || req.Diff != "" || req.LastCommits > 0 {
		sessionDir := filepath.Join(h.settings.Agent.EffectiveSessionsDir(), "api-"+uuid.New().String()[:8])
		resolved, resolvedFiles, dc, err := agent.ResolveSourceAndDiff(sourcePath, req.Diff, req.LastCommits, files, sessionDir)
		if err != nil {
			zap.L().Warn("Source/diff resolution failed, proceeding with original values", zap.Error(err))
		} else {
			sourcePath = resolved
			files = resolvedFiles
			diffCtx = dc
		}
	}

	cfg := agent.AutopilotPipelineConfig{
		TargetURL:             req.Target,
		SourcePath:            sourcePath,
		Files:                 files,
		Instruction:           req.Instruction,
		Focus:                 req.Focus,
		AgentName:             h.effectiveAgentName(req.Agent),
		MaxCommands:           maxCmds,
		DryRun:                req.DryRun,
		Triage:                req.Triage,
		SessionsDir:           h.settings.Agent.EffectiveSessionsDir(),
		ProjectUUID:           projectUUID,
		ScanUUID:              req.ScanUUID,
		ParentAgenticScanUUID: parentAgenticScanUUID,
		DiffContext:           diffCtx,
		Credentials:           req.Credentials,
		CredentialSets:        append([]agent.IntentCredentialSet(nil), req.CredentialSets...),
		AuthRequired:          req.AuthRequired,
		BrowserRequested:      req.Browser || req.RequiresBrowser,
		RequiresBrowser:       req.RequiresBrowser,
		BrowserStartURL:       req.BrowserStartURL,
		FocusRoutes:           append([]string(nil), req.FocusRoutes...),
		PreflightDiscovery:    !req.NoPreflightDiscovery,
		PostHaltVerify:        !req.NoPostHaltVerify,
		PostHaltGapThreshold:  req.PostHaltGapThreshold,
	}

	auditCfg, harness := h.resolveAutopilotAuditCfgServer(req, sourcePath)
	if auditCfg != nil {
		cfg.Audit = auditCfg
		cfg.AuditHarness = harness
	}

	cfg.BrowserEnabled = h.settings.Agent.Browser.IsEnabled()
	if req.Browser {
		cfg.BrowserEnabled = true
	}

	// Intensity-derived browser: deep intensity enables browser without mutating shared settings
	if req.Intensity != "" {
		if intensity, err := agent.ValidateIntensity(req.Intensity); err == nil {
			if preset, ok := agenttypes.AutopilotPresets[intensity]; ok && preset.Browser {
				cfg.BrowserEnabled = true
			}
		}
	}

	return cfg
}

// handleAutopilotSSE runs the autopilot pipeline synchronously while streaming SSE events.
func (h *Handlers) handleAutopilotSSE(c fiber.Ctx, agenticScanUUID string, req AgentAutopilotRequest, projectUUID string, timeout time.Duration, engine *agent.Engine, byokCleanup func()) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer h.releaseHeavyAgentSlotForProject(projectUUID)
		if byokCleanup != nil {
			defer byokCleanup()
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cfg := h.buildAutopilotPipelineConfig(req, projectUUID, agenticScanUUID)

		// Pre-create the session dir under the API run UUID (matching the
		// async path) so SSE-mode runs also leave a runtime.log + artifacts
		// on disk for /sessions/:id/logs and /sessions/:id/artifacts.
		sessionDir, sessionErr := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), agenticScanUUID)
		if sessionErr != nil {
			zap.L().Warn("Failed to pre-create session dir",
				zap.String("agentic_scan_uuid", agenticScanUUID),
				zap.Error(sessionErr))
		} else {
			cfg.SessionDir = sessionDir
			h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
				run.SourcePath = cfg.SourcePath
				run.SourceType = database.InferSourceType(cfg.SourcePath)
				run.TargetURL = cfg.TargetURL
				run.SessionDir = sessionDir
			})
		}

		// Set up stream writer pipe AND tee to runtime.log so the SSE
		// client gets chunks live and disk-based consumers (logs / artifacts
		// endpoints, agent_raw_output snapshot) see the same content.
		pr, pw := io.Pipe()
		var streamWriter io.Writer = pw
		var streamFile *os.File
		if logFile := h.openSessionRuntimeLog(sessionDir, agenticScanUUID); logFile != nil {
			streamFile = logFile
			streamWriter = io.MultiWriter(pw, logFile)
			defer func() { _ = logFile.Close() }()
		}
		cfg.StreamWriter = streamWriter

		type autopilotRunResult struct {
			result *agent.AutopilotPipelineResult
			err    error
		}
		done := make(chan autopilotRunResult, 1)

		runner := agent.NewAutopilotPipelineRunner(engine, h.repo)
		go func() {
			result, runErr := runner.RunAutonomous(ctx, cfg)
			_ = pw.Close()
			done <- autopilotRunResult{result: result, err: runErr}
		}()

		// Stream chunks.
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

		res := <-done
		now := time.Now()
		h.agentMu.Lock()
		status := h.agenticScanStatus[agenticScanUUID]

		if res.err != nil {
			if status != nil {
				status.Status = "failed"
				status.Error = res.err.Error()
				status.CompletedAt = &now
			}
			h.agentMu.Unlock()

			h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
				run.Status = "failed"
				run.ErrorMessage = res.err.Error()
				run.CompletedAt = now
				run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
			})

			_ = writeSSE(w, sseEvent{Type: "error", Error: res.err.Error()})
			zap.L().Error("Autopilot run failed (streaming)",
				zap.String("agentic_scan_uuid", agenticScanUUID),
				zap.Error(res.err))
			return
		}

		if status != nil && res.result != nil {
			status.Status = "completed"
			status.CompletedAt = &now
			status.FindingCount = res.result.FindingsCount
			if res.result.VerifiedFindingCount > 0 {
				status.FindingCount = res.result.VerifiedFindingCount
			}
			if len(res.result.Warnings) > 0 {
				status.Error = strings.Join(res.result.Warnings, "\n")
			}
		}
		h.agentMu.Unlock()

		// Persist to DB. Snapshot the tee'd runtime.log into agent_raw_output
		// so the SSE-mode row matches the async-mode row produced by
		// runBackgroundAutopilot.
		rawOutput := snapshotAgentRawOutput(streamFile, sessionDir)
		h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
			run.Status = "completed"
			run.CompletedAt = now
			run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
			if res.result != nil {
				run.FindingCount = res.result.FindingsCount
				if res.result.VerifiedFindingCount > 0 {
					run.FindingCount = res.result.VerifiedFindingCount
				}
				if len(res.result.Warnings) > 0 {
					run.ErrorMessage = strings.Join(res.result.Warnings, "\n")
				}
			}
			if rawOutput != "" {
				run.AgentRawOutput = rawOutput
			}
		})

		_ = writeSSE(w, sseEvent{Type: "done", AutopilotResult: res.result})
		zap.L().Info("Autopilot run completed (streaming)",
			zap.String("agentic_scan_uuid", agenticScanUUID),
			zap.Int("audit_findings", res.result.FindingsCount),
			zap.Int("verified_findings", res.result.VerifiedFindingCount))
	})
}

// runBackgroundAutopilot executes the autopilot pipeline in a goroutine and updates status.
func (h *Handlers) runBackgroundAutopilot(agenticScanUUID string, req AgentAutopilotRequest, projectUUID string, timeout time.Duration, engine *agent.Engine, byokCleanup func()) {
	defer h.releaseHeavyAgentSlotForProject(projectUUID)
	if byokCleanup != nil {
		defer byokCleanup()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg := h.buildAutopilotPipelineConfig(req, projectUUID, agenticScanUUID)

	// Pre-create the session directory with agenticScanUUID as its name so the API
	// session UUID matches the filesystem artifact directory. This mirrors
	// what the CLI does via its own session-dir wiring and lets API clients
	// find output.md, audit-stream.jsonl, etc. from the run ID alone.
	sessionDir, sessionErr := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), agenticScanUUID)
	if sessionErr != nil {
		zap.L().Warn("Failed to pre-create session dir", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(sessionErr))
	} else {
		cfg.SessionDir = sessionDir
	}

	// Open a stream log file in the session dir so users can tail live
	// autopilot + audit output via `tail -f {session_dir}/runtime.log`. The CLI
	// writes the same stream to os.Stdout; the server has no terminal, so we
	// persist it to disk instead. A non-nil StreamWriter also forces
	// vigolium-audit down the Claude stream-json branch (the non-stream branch
	// collides with the variadic --allowedTools flag).
	var streamFile *os.File
	if sessionDir != "" {
		logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			cfg.StreamWriter = f
			streamFile = f
		} else {
			zap.L().Warn("Failed to open runtime.log, falling back to discard", zap.Error(err))
			cfg.StreamWriter = io.Discard
		}
	} else {
		cfg.StreamWriter = io.Discard
	}
	if streamFile != nil {
		defer func() { _ = streamFile.Close() }()
	}

	// Enrich the DB record with the config we just resolved so API clients
	// can see source_path / target_url / session_dir while the run is still
	// in progress (before the completion update fires).
	h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
		run.SourcePath = cfg.SourcePath
		run.SourceType = database.InferSourceType(cfg.SourcePath)
		run.TargetURL = cfg.TargetURL
		run.SessionDir = sessionDir
	})

	runner := agent.NewAutopilotPipelineRunner(engine, h.repo)
	result, runErr := runner.RunAutonomous(ctx, cfg)

	now := time.Now()

	// Hold agentMu only for the in-memory mutation. Anything below this block
	// (DB writes, file reads, the GCS upload) can — and uploadAgenticResults
	// does — re-acquire agentMu, so we must release it first or the second
	// Lock deadlocks (Go mutexes are non-reentrant).
	h.agentMu.Lock()
	status := h.agenticScanStatus[agenticScanUUID]
	if status == nil {
		h.agentMu.Unlock()
		return
	}
	if runErr != nil {
		status.Status = "failed"
		status.Error = runErr.Error()
		status.CompletedAt = &now
	} else {
		status.Status = "completed"
		status.CompletedAt = &now
		if result != nil {
			status.FindingCount = result.FindingsCount
			if result.VerifiedFindingCount > 0 {
				status.FindingCount = result.VerifiedFindingCount
			}
			if len(result.Warnings) > 0 {
				status.Error = strings.Join(result.Warnings, "\n")
			}
		}
	}
	findingCount := status.FindingCount
	h.agentMu.Unlock()

	if runErr != nil {
		// Persist the failure to the DB, preserving the source/target/session
		// fields that the enrichment step wrote earlier.
		h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
			run.Status = "failed"
			run.ErrorMessage = runErr.Error()
			run.CompletedAt = now
			run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
		})
		webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)
		zap.L().Error("Autopilot run failed",
			zap.String("agentic_scan_uuid", agenticScanUUID),
			zap.Error(runErr))
		return
	}

	// Snapshot the runtime.log we've been streaming into, strip ANSI, and
	// keep only the tail (head-truncated) so DB rows stay manageable. This
	// replaces the old output.md read — the autopilot pipeline no longer
	// emits a separate transcript file; runtime.log is the canonical record
	// of what the operator saw.
	rawOutput := snapshotAgentRawOutput(streamFile, sessionDir)

	// Persist the completed state plus the artifacts the CLI would have shown
	// live: a snapshot of runtime.log plus session dir summary fields.
	h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
		run.Status = "completed"
		run.CompletedAt = now
		run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
		if result != nil {
			run.FindingCount = result.FindingsCount
			if result.VerifiedFindingCount > 0 {
				run.FindingCount = result.VerifiedFindingCount
			}
			if result.SessionDir != "" {
				run.SessionDir = result.SessionDir
			}
			if len(result.Warnings) > 0 {
				run.ErrorMessage = strings.Join(result.Warnings, "\n")
			}
		}
		if rawOutput != "" {
			run.AgentRawOutput = rawOutput
		}
	})

	if req.UploadResults && sessionDir != "" {
		h.uploadAgenticResults(projectUUID, agenticScanUUID, sessionDir)
	}

	webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)

	zap.L().Info("Autopilot run completed",
		zap.String("agentic_scan_uuid", agenticScanUUID),
		zap.String("session_dir", sessionDir),
		zap.Int("finding_count", findingCount))
}

// enrichAgenticScanRecord loads the agentic_scans row for agenticScanUUID, applies mutate,
// and writes it back. Used by background handlers to populate fields like
// source_path / target_url / session_dir / agent_raw_output that the
// lightweight persistAgenticScan helpers don't cover.
