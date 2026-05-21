package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Agent concurrency helpers
// ---------------------------------------------------------------------------

// acquireAgentSlot tries to acquire a slot from the given semaphore channel.
// Returns true if a slot was acquired, false if all slots are busy (429 response already sent).
// Callers must return nil immediately when false is returned.
func (h *Handlers) acquireAgentSlot(c fiber.Ctx, sem chan struct{}) bool {
	timeout := h.config.AgentQueueTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	select {
	case sem <- struct{}{}:
		return true // slot acquired immediately
	default:
		// All slots busy — wait with timeout
		select {
		case sem <- struct{}{}:
			return true
		case <-time.After(timeout):
			_ = c.Status(fiber.StatusTooManyRequests).JSON(ErrorResponse{
				Error: fmt.Sprintf("all %d agent slots busy, try again later", cap(sem)),
			})
			return false
		}
	}
}

// releaseAgentSlot releases a slot back to the semaphore.
func (h *Handlers) releaseAgentSlot(sem chan struct{}) {
	<-sem
}

// effectiveHeavyPerProject returns the per-project heavy concurrency cap.
// AgentHeavyPerProject = 0 → default 2; negative → disabled (no cap).
// Centralized so callers don't have to repeat the defaulting rule.
func (h *Handlers) effectiveHeavyPerProject() int {
	v := h.config.AgentHeavyPerProject
	if v < 0 {
		return 0 // disabled
	}
	if v == 0 {
		return 2
	}
	return v
}

// acquireHeavyAgentSlotForProject acquires both the per-project heavy
// counter (best-effort cap so one tenant can't drain the cluster pool)
// AND the global agentHeavySem. Order matters: the per-project counter
// is taken first because incrementing it is a fast in-memory operation,
// while the global sem may block waiting for a slot. On 429 the
// per-project counter is decremented and the global sem is never
// touched.
//
// projectUUID == "" disables the per-project tier for this acquisition
// (e.g. utility endpoints that don't carry a project context). The
// global cap still applies.
//
// Returns true on success — caller MUST defer releaseHeavyAgentSlotForProject.
// Returns false when either tier rejects; in that case a 429 has already
// been sent and the caller should return nil from the handler.
func (h *Handlers) acquireHeavyAgentSlotForProject(c fiber.Ctx, projectUUID string) bool {
	perProjectCap := h.effectiveHeavyPerProject()
	if perProjectCap > 0 && projectUUID != "" {
		h.projectHeavyMu.Lock()
		if h.projectHeavyActive[projectUUID] >= perProjectCap {
			h.projectHeavyMu.Unlock()
			_ = c.Status(fiber.StatusTooManyRequests).JSON(ErrorResponse{
				Error: fmt.Sprintf("project %s already has %d heavy agent runs in flight (per-project cap)", projectUUID, perProjectCap),
			})
			return false
		}
		h.projectHeavyActive[projectUUID]++
		h.projectHeavyMu.Unlock()
	}
	if !h.acquireAgentSlot(c, h.agentHeavySem) {
		h.decrementProjectHeavy(projectUUID, perProjectCap)
		return false
	}
	return true
}

// releaseHeavyAgentSlotForProject is the symmetric release: returns the
// global slot, then decrements the per-project counter. Safe to call
// with an empty projectUUID — only the global slot is released.
func (h *Handlers) releaseHeavyAgentSlotForProject(projectUUID string) {
	h.releaseAgentSlot(h.agentHeavySem)
	h.decrementProjectHeavy(projectUUID, h.effectiveHeavyPerProject())
}

// decrementProjectHeavy lowers the per-project heavy counter and deletes
// the map entry when it reaches zero. No-op when the per-project tier is
// disabled (cap <= 0) or the project context is missing.
func (h *Handlers) decrementProjectHeavy(projectUUID string, perProjectCap int) {
	if perProjectCap <= 0 || projectUUID == "" {
		return
	}
	h.projectHeavyMu.Lock()
	defer h.projectHeavyMu.Unlock()
	h.projectHeavyActive[projectUUID]--
	if h.projectHeavyActive[projectUUID] <= 0 {
		delete(h.projectHeavyActive, projectUUID)
	}
}

// ---------------------------------------------------------------------------
// POST /api/agent/run/query — single-shot prompt execution
// ---------------------------------------------------------------------------

// HandleAgentQuery handles POST /api/agent/run/query — triggers a single-shot AI agent run.
// When "stream":true, the response is an SSE stream; otherwise it returns 202 async.
func (h *Handlers) HandleAgentQuery(c fiber.Ctx) error {
	var req AgenticScanRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
		})
	}

	if req.PromptTemplate == "" && req.PromptFile == "" && req.Prompt == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingPrompt.Error(),
		})
	}

	eng, cleanup, err := h.engineForRequest(req.AgentBYOK)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "byok: " + err.Error(),
		})
	}

	opts := h.buildQueryOpts(req)
	timeout := 10 * time.Minute

	projectUUID := req.ProjectUUID
	if projectUUID == "" {
		projectUUID = getProjectUUID(c)
	}

	return h.startAgenticScan(c, "query", req.Stream, opts, timeout, projectUUID, req.UploadResults, eng, cleanup)
}

// buildQueryOpts creates agent.Options from a query request.
func (h *Handlers) buildQueryOpts(req AgenticScanRequest) agent.Options {
	return agent.Options{
		AgentName:      h.effectiveAgentName(req.Agent),
		PromptTemplate: req.PromptTemplate,
		PromptFile:     req.PromptFile,
		PromptInline:   req.Prompt,
		SourcePath:     req.SourcePath,
		Files:          req.Files,
		Append:         req.Append,
		Instruction:    req.Instruction,
		Source:         req.Source,
		ScanUUID:       req.ScanUUID,
	}
}

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
			"audit-mode":  req.AuditDriverMode != "",
			"no-audit":    req.NoAudit || req.Audit == "off",
			"browser":      req.Browser || req.RequiresBrowser,
		}
		result := agent.ResolveAutopilotIntensity(intensity, agent.AutopilotIntensityPreset{
			MaxCommands: req.MaxCommands,
			Timeout:     parseDurationOrDefault(req.Timeout, 6*time.Hour),
			AuditDriverMode:  req.ResolvedAuditDriverMode(),
			Browser:     req.Browser || req.RequiresBrowser,
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
// ---------------------------------------------------------------------------
// POST /api/agent/run/swarm — AI-guided targeted vulnerability swarm
// ---------------------------------------------------------------------------

// HandleAgentSwarm handles POST /api/agent/run/swarm — launches an AI-guided targeted swarm.
func (h *Handlers) HandleAgentSwarm(c fiber.Ctx) error {
	var req AgentSwarmRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
		})
	}

	// Natural language prompt: resolve when explicit fields are empty
	hasExplicitInput := req.Input != "" || len(req.Inputs) > 0 || req.HTTPRequestBase64 != "" || req.SourcePath != "" || req.Diff != "" || req.LastCommits > 0
	if req.Prompt != "" && !hasExplicitInput {
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
		// Apply first app from intent
		if len(resolved.Apps) > 0 {
			app := resolved.Apps[0]
			if app.Target != "" {
				req.Input = app.Target
			}
			if req.SourcePath == "" {
				req.SourcePath = app.SourcePath
			}
			if req.Focus == "" {
				req.Focus = app.Focus
			}
			if req.Instruction == "" {
				req.Instruction = app.Instruction
			}
			if app.Discover {
				req.Discover = true
			}
			if app.CodeAudit {
				req.CodeAudit = true
			}
			if req.Audit == "" {
				req.Audit = app.Audit
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
			if app.AuthRequired && !req.AuthRequired {
				req.AuthRequired = true
			}
			if app.RequiresBrowser && !req.RequiresBrowser {
				req.RequiresBrowser = true
			}
			if app.RequiresBrowser && !req.Auth {
				req.Auth = true
			}
			if app.Credentials != "" && req.Credentials == "" {
				req.Credentials = app.Credentials
			}
			if len(app.CredentialSets) > 0 && len(req.CredentialSets) == 0 {
				req.CredentialSets = append([]agent.IntentCredentialSet(nil), app.CredentialSets...)
			}
			if app.BrowserStartURL != "" && req.BrowserStartURL == "" {
				req.BrowserStartURL = app.BrowserStartURL
			}
			if len(app.FocusRoutes) > 0 && len(req.FocusRoutes) == 0 {
				req.FocusRoutes = append([]string(nil), app.FocusRoutes...)
			}
			if app.Intensity != "" && req.Intensity == "" {
				req.Intensity = app.Intensity
			}
		}
	}

	// If base64 HTTP request is provided, ingest it and use the record UUID as input.
	if req.HTTPRequestBase64 != "" {
		recordUUID, err := h.ingestSwarmBase64(c, &req)
		if err != nil {
			return err // already sent HTTP response
		}
		req.Inputs = append(req.Inputs, recordUUID)
	}

	inputs := req.EffectiveInputs()
	if len(inputs) == 0 && req.SourcePath == "" && req.Diff == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "at least one input is required (input, inputs, http_request_base64, source, diff, or prompt field)",
		})
	}

	// Resolve intensity preset
	swarmIntensity, intensityErr := agent.ValidateIntensity(req.Intensity)
	if intensityErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: intensityErr.Error()})
	}
	{
		changed := map[string]bool{
			"discover":          req.Discover,
			"code-audit":        req.CodeAudit,
			"triage":            req.Triage,
			"max-iterations":    req.MaxIterations != 0,
			"audit":            req.Audit != "",
			"max-plan-records":  req.MaxPlanRecords != 0,
			"master-batch-size": req.MasterBatchSize != 0,
			"batch-concurrency": req.BatchConcurrency != 0,
			"probe-concurrency": req.ProbeConcurrency != 0,
			"browser":           req.Browser || req.RequiresBrowser,
			"auth":              req.Auth || req.AuthRequired || req.RequiresBrowser,
			"swarm-duration":    req.Timeout != "",
		}
		result := agent.ResolveSwarmIntensity(swarmIntensity, agent.SwarmIntensityPreset{
			Discover:         req.Discover,
			CodeAudit:        req.CodeAudit,
			Triage:           req.Triage,
			MaxIterations:    req.MaxIterations,
			Audit:           req.Audit,
			MaxPlanRecords:   req.MaxPlanRecords,
			MasterBatchSize:  req.MasterBatchSize,
			BatchConcurrency: req.BatchConcurrency,
			ProbeConcurrency: req.ProbeConcurrency,
			Browser:          req.Browser || req.RequiresBrowser,
			Auth:             req.Auth || req.AuthRequired || req.RequiresBrowser,
			SwarmDuration:    parseDurationOrDefault(req.Timeout, 12*time.Hour),
		}, changed)
		req.Discover = result.Discover
		req.CodeAudit = result.CodeAudit
		req.Triage = result.Triage
		if req.MaxIterations == 0 {
			req.MaxIterations = result.MaxIterations
		}
		if req.Audit == "" {
			req.Audit = result.Audit
		}
		if req.MaxPlanRecords == 0 {
			req.MaxPlanRecords = result.MaxPlanRecords
		}
		if req.MasterBatchSize == 0 {
			req.MasterBatchSize = result.MasterBatchSize
		}
		if req.BatchConcurrency == 0 {
			req.BatchConcurrency = result.BatchConcurrency
		}
		if req.ProbeConcurrency == 0 {
			req.ProbeConcurrency = result.ProbeConcurrency
		}
		if !req.Browser {
			req.Browser = result.Browser
		}
		if !req.Auth {
			req.Auth = result.Auth
		}
		if req.Timeout == "" {
			req.Timeout = result.SwarmDuration.String()
		}
	}

	timeout := parseDurationOrDefault(req.Timeout, 12*time.Hour)

	eng, cleanup, byokErr := h.engineForRequest(req.AgentBYOK)
	if byokErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "byok: " + byokErr.Error(),
		})
	}

	return h.startSwarmRun(c, req, timeout, eng, cleanup)
}

// ingestSwarmBase64 decodes the base64-encoded HTTP request (and optional response),
// saves it as an http_record, and returns the record UUID.
func (h *Handlers) ingestSwarmBase64(c fiber.Ctx, req *AgentSwarmRequest) (string, error) {
	if h.repo == nil {
		return "", c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	rawReq, err := base64.StdEncoding.DecodeString(req.HTTPRequestBase64)
	if err != nil {
		return "", c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid base64 in http_request_base64: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	var rr *httpmsg.HttpRequestResponse
	if req.URL != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(string(rawReq), req.URL)
	} else {
		rr, err = httpmsg.ParseRawRequest(string(rawReq))
	}
	if err != nil {
		return "", c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse raw request: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	// Attach response if provided.
	if req.HTTPResponseBase64 != "" {
		rawResp, decErr := base64.StdEncoding.DecodeString(req.HTTPResponseBase64)
		if decErr == nil {
			resp := httpmsg.NewHttpResponse(rawResp)
			if resp != nil {
				rr = rr.WithResponse(resp)
			}
		}
	}

	rr = h.fetchResponseIfNeeded(rr)

	projectUUID := req.ProjectUUID
	if projectUUID == "" {
		projectUUID = getProjectUUID(c)
	}

	recordUUID, err := h.saveRecord(c.Context(), rr, "agent-swarm", projectUUID)
	if err != nil {
		zap.L().Error("Failed to save ingested record for swarm", zap.Error(err))
		return "", c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to save record: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}

	return recordUUID, nil
}

// startSwarmRun acquires a heavy agent slot, creates status tracking, and runs the agent swarm.
func (h *Handlers) startSwarmRun(c fiber.Ctx, req AgentSwarmRequest, timeout time.Duration, engine *agent.Engine, byokCleanup func()) error {
	// Resolve project UUID before slot acquisition so per-project caps apply.
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

	agenticScanUUID, err := h.registerRunningAgenticScan("swarm", req.Agent, req.ScanUUID)
	if err != nil {
		h.releaseHeavyAgentSlotForProject(projectUUID)
		if byokCleanup != nil {
			byokCleanup()
		}
		return respondScanPinError(c, err)
	}

	if req.Stream {
		return h.handleSwarmSSE(c, agenticScanUUID, req, projectUUID, timeout, engine, byokCleanup)
	}

	go h.runBackgroundAgentSwarm(agenticScanUUID, req, projectUUID, timeout, engine, byokCleanup)

	return c.Status(fiber.StatusAccepted).JSON(AgenticScanResponse{
		AgenticScanUUID: agenticScanUUID,
		Status:          "running",
		Message:         "agent swarm started",
	})
}

// buildSwarmConfig creates an agent.SwarmConfig from an API request.
// projectUUID should be pre-resolved by the caller (from request body or X-Project-UUID header).
func (h *Handlers) buildSwarmConfig(req AgentSwarmRequest, projectUUID string) agent.SwarmConfig {
	maxIter := req.MaxIterations
	if maxIter <= 0 {
		maxIter = 3
	}

	// Normalize skip phases to support legacy aliases
	normalizedSkip := make([]string, len(req.SkipPhases))
	for i, p := range req.SkipPhases {
		normalizedSkip[i] = agent.NormalizeSwarmPhase(p)
	}

	// Skip triage+rescan by default unless explicitly enabled
	if !req.Triage && !agent.PhaseSkipped(normalizedSkip, agent.SwarmPhaseTriage) {
		normalizedSkip = append(normalizedSkip, agent.SwarmPhaseTriage)
	}

	// Apply scanning profile if specified
	settings := h.settings
	if req.Profile != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(req.Profile)
		profile, profileErr := config.LoadProfile(profilePath)
		if profileErr == nil {
			settingsCopy := *settings
			if applyErr := config.ApplyProfile(&settingsCopy, profile); applyErr == nil {
				settings = &settingsCopy
			}
		}
	}

	sourcePath := req.SourcePath
	files := req.Files
	var swarmDiffCtx *agenttypes.DiffContext

	// Resolve source (git URL, archive, local path) and diff context
	if sourcePath != "" || req.Diff != "" || req.LastCommits > 0 {
		sessionDir := filepath.Join(settings.Agent.EffectiveSessionsDir(), "api-"+uuid.New().String()[:8])
		resolved, resolvedFiles, dc, err := agent.ResolveSourceAndDiff(sourcePath, req.Diff, req.LastCommits, files, sessionDir)
		if err != nil {
			zap.L().Warn("Source/diff resolution failed, proceeding with original values", zap.Error(err))
		} else {
			sourcePath = resolved
			files = resolvedFiles
			swarmDiffCtx = dc
		}
	}

	cfg := agent.SwarmConfig{
		Inputs:             req.EffectiveInputs(),
		Instruction:        req.Instruction,
		SourcePath:         sourcePath,
		Files:              files,
		DiffContext:        swarmDiffCtx,
		VulnType:           req.VulnType,
		Focus:              req.Focus,
		ModuleNames:        req.ModuleNames,
		OnlyPhase:          req.OnlyPhase,
		SkipPhases:         normalizedSkip,
		MaxIterations:      maxIter,
		BatchConcurrency:   req.BatchConcurrency,
		MaxMasterRetries:   req.MaxMasterRetries,
		SAMaxConcurrency:   req.SAMaxConcurrency,
		MaxPlanRecords:     req.MaxPlanRecords,
		AgentName:          h.effectiveAgentName(req.Agent),
		DryRun:             req.DryRun,
		ShowPrompt:         req.ShowPrompt,
		SourceAnalysisOnly: req.SourceAnalysisOnly,
		CodeAudit:          req.CodeAudit,
		Browser:            req.Browser || req.Auth || req.RequiresBrowser || settings.Agent.Browser.IsEnabled() || swarmIntensityEnablesBrowser(req.Intensity),
		Auth:               req.Auth || req.AuthRequired || req.RequiresBrowser,
		Credentials:        req.Credentials,
		CredentialSets:     append([]agent.IntentCredentialSet(nil), req.CredentialSets...),
		AuthRequired:       req.AuthRequired,
		RequiresBrowser:    req.RequiresBrowser,
		BrowserStartURL:    req.BrowserStartURL,
		FocusRoutes:        append([]string(nil), req.FocusRoutes...),
		MasterBatchSize:    req.MasterBatchSize,
		ProbeConcurrency:   req.ProbeConcurrency,
		MaxProbeBodySize:   req.MaxProbeBodySize,
		SessionsDir:        settings.Agent.EffectiveSessionsDir(),
		ProjectUUID:        projectUUID,
		ScanUUID:           req.ScanUUID,
	}
	// SessionDir + AgenticScanUUID are caller-owned: handlers pre-create the session
	// directory with the API run UUID so the swarm runner's DB row, the
	// /sessions/:id endpoints, and the on-disk artifacts all line up under
	// the same identifier.

	var generatedAuthConfig string
	cfg.SourceAnalysisCallback = func(saResult *agent.SourceAnalysisResult) error {
		if saResult.SessionConfig == nil || len(saResult.SessionConfig.Sessions) == 0 || cfg.SessionDir == "" {
			return nil
		}
		authPath, err := agent.WriteAuthConfigYAML(cfg.SessionDir, saResult.SessionConfig)
		if err != nil {
			return err
		}
		generatedAuthConfig = authPath
		return nil
	}

	if req.ProbeTimeout != "" {
		if d, err := time.ParseDuration(req.ProbeTimeout); err == nil {
			cfg.ProbeTimeout = d
		}
	}

	// Resolve a target URL for the scan runner.
	// The runner needs at least one target to create an input source.
	targetURL := h.resolveSwarmTargetURL(req)

	// Wire scan callback using the server's runner infrastructure
	cfg.ScanFunc = h.buildServerAgentSwarmFunc(targetURL, projectUUID, req.ScanUUID, req.OnlyPhase, req.SkipPhases, settings, &generatedAuthConfig)

	// Wire optional discovery callback
	if req.Discover {
		cfg.DiscoverFunc = h.buildServerSwarmDiscoverFunc(targetURL, projectUUID, req.ScanUUID, settings, &generatedAuthConfig)
	}

	// Handle --start-from via synthetic checkpoint
	if req.StartFrom != "" {
		startFrom := agent.NormalizeSwarmPhase(req.StartFrom)
		syntheticCP := buildServerSyntheticCheckpoint(startFrom)
		if syntheticCP != nil && cfg.SessionDir != "" {
			_ = agent.WriteCheckpointToDir(cfg.SessionDir, syntheticCP)
			cfg.ResumeDir = cfg.SessionDir
		}
	}

	// Wire audit harness (audit or piolium, with auto-pick on availability).
	auditCfg, harness := h.resolveSwarmAuditCfgServer(req, sourcePath)
	if auditCfg != nil {
		cfg.Audit = auditCfg
		cfg.AuditHarness = harness
	}

	return cfg
}

// buildServerAgentSwarmFunc creates a callback that runs the scan.
// When IsRescan=false, it runs a full scan (all phases, all modules) by default.
// When IsRescan=true, it restricts to audit with targeted modules.
func (h *Handlers) buildServerAgentSwarmFunc(targetURL, projectUUID, scanUUID, onlyPhase string, skipPhases []string, settings *config.Settings, authConfigPath *string) agent.ScanFunc {
	return func(ctx context.Context, req agent.ScanRequest) error {
		opts := types.DefaultOptions()
		if targetURL != "" {
			opts.Targets = []string{targetURL}
		}
		opts.ProjectUUID = projectUUID
		opts.ScanUUID = scanUUID
		opts.HeuristicsCheck = "none"
		opts.PassiveModules = []string{"all"}
		opts.Silent = true
		opts.ScanConfigPrinted = true
		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthFiles = []string{*authConfigPath}
			opts.AuthBestEffort = true
		}

		if req.IsRescan {
			// Triage rescans: targeted audit only
			opts.OnlyPhase = "audit"
			opts.SkipIngestion = true
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
		} else {
			// Initial scan: full scan with all modules
			opts.Modules = []string{"all"}
			if onlyPhase != "" {
				opts.OnlyPhase = onlyPhase
			}
			if len(skipPhases) > 0 {
				opts.SkipPhases = skipPhases
			}
		}

		// Clone settings to apply extension dir without mutating global
		settingsCopy := *settings
		if req.ExtensionDir != "" {
			settingsCopy.DynamicAssessment.Extensions.Enabled = true
			settingsCopy.DynamicAssessment.Extensions.ExtensionDir = req.ExtensionDir
		}

		scanRunner, err := runner.New(opts)
		if err != nil {
			return err
		}
		defer scanRunner.Close()

		scanRunner.SetSettings(&settingsCopy)
		scanRunner.SetRepository(h.repo)
		return scanRunner.RunNativeScan()
	}
}

// swarmIntensityEnablesBrowser checks whether the given intensity preset enables browser.
func swarmIntensityEnablesBrowser(intensityStr string) bool {
	if intensityStr == "" {
		return false
	}
	intensity, err := agent.ValidateIntensity(intensityStr)
	if err != nil {
		return false
	}
	if preset, ok := agenttypes.SwarmPresets[intensity]; ok {
		return preset.Browser
	}
	return false
}

// buildServerSwarmDiscoverFunc creates a callback that runs discovery+spidering.
func (h *Handlers) buildServerSwarmDiscoverFunc(targetURL, projectUUID, scanUUID string, settings *config.Settings, authConfigPath *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts := types.DefaultOptions()
		if targetURL != "" {
			opts.Targets = []string{targetURL}
		}
		opts.ProjectUUID = projectUUID
		opts.ScanUUID = scanUUID
		opts.OnlyPhase = "discovery"
		opts.DiscoverEnabled = true
		opts.SpideringEnabled = true
		opts.HeuristicsCheck = "basic"
		opts.Silent = true
		opts.ScanConfigPrinted = true
		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthFiles = []string{*authConfigPath}
			opts.AuthBestEffort = true
		}

		scanRunner, err := runner.New(opts)
		if err != nil {
			return err
		}
		defer scanRunner.Close()

		scanRunner.SetSettings(settings)
		scanRunner.SetRepository(h.repo)
		return scanRunner.RunNativeScan()
	}
}

// buildServerSyntheticCheckpoint creates a checkpoint with all phases before the target
// marked as completed, enabling --start-from to skip earlier phases.
func buildServerSyntheticCheckpoint(startFrom string) *agent.SwarmCheckpoint {
	allPhases := []string{
		agent.SwarmPhaseNormalize,
		agent.SwarmPhaseSourceAnalysis,
		agent.SwarmPhaseCodeAudit,
		agent.SwarmPhaseDiscover,
		agent.SwarmPhasePlan,
		agent.SwarmPhaseExtension,
		agent.SwarmPhaseScan,
		agent.SwarmPhaseTriage,
	}

	var completed []string
	for _, p := range allPhases {
		if p == startFrom {
			break
		}
		completed = append(completed, p)
	}

	if len(completed) == 0 {
		return nil
	}
	return &agent.SwarmCheckpoint{
		CompletedPhases: completed,
	}
}

// resolveSwarmTargetURL extracts a target URL from the swarm request.
// It checks the URL hint, then tries each input to find a usable target.
func (h *Handlers) resolveSwarmTargetURL(req AgentSwarmRequest) string {
	// The URL field is an explicit hint — use it directly if provided.
	if req.URL != "" {
		return req.URL
	}

	// Try each input: if it looks like a URL, use it.
	// If it looks like a record UUID, look up its host from the DB.
	for _, input := range req.EffectiveInputs() {
		if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
			return input
		}
		if h.repo != nil && len(input) == 36 && strings.Count(input, "-") == 4 {
			if rec, err := h.repo.GetRecordByUUID(context.Background(), input); err == nil && rec != nil {
				scheme := rec.Scheme
				if scheme == "" {
					scheme = "https"
				}
				host := rec.Hostname
				if rec.Port > 0 && rec.Port != 80 && rec.Port != 443 {
					host = fmt.Sprintf("%s:%d", host, rec.Port)
				}
				return scheme + "://" + host
			}
		}
	}

	return ""
}

// handleSwarmSSE runs the agent swarm synchronously while streaming SSE events.
func (h *Handlers) handleSwarmSSE(c fiber.Ctx, agenticScanUUID string, req AgentSwarmRequest, projectUUID string, timeout time.Duration, engine *agent.Engine, byokCleanup func()) error {
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

		cfg := h.buildSwarmConfig(req, projectUUID)

		// Pin the swarm runner's DB record UUID and session dir to the API
		// run UUID — without this, SwarmRunner allocates its own UUID and
		// the row the API client polls stays empty.
		cfg.AgenticScanUUID = agenticScanUUID
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
				run.SessionDir = sessionDir
				if len(cfg.Inputs) > 0 {
					run.InputRaw = cfg.Inputs[0]
				}
			})
		}

		// Wire phase callback for SSE events
		cfg.PhaseCallback = func(phase string) {
			h.agentMu.Lock()
			if status := h.agenticScanStatus[agenticScanUUID]; status != nil {
				status.CurrentPhase = phase
			}
			h.agentMu.Unlock()

			_ = writeSSE(w, sseEvent{Type: "phase", Phase: phase})
		}

		// Wire progress callback for SSE events
		cfg.ProgressCallback = func(evt agent.ProgressEvent) {
			_ = writeSSE(w, sseEvent{Type: "progress", Progress: &evt})
		}

		// Set up stream writer pipe AND tee to runtime.log.
		pr, pw := io.Pipe()
		var streamWriter io.Writer = pw
		if logFile := h.openSessionRuntimeLog(sessionDir, agenticScanUUID); logFile != nil {
			streamWriter = io.MultiWriter(pw, logFile)
			defer func() { _ = logFile.Close() }()
		}
		cfg.StreamWriter = streamWriter

		type swarmRunResult struct {
			result *agent.SwarmResult
			err    error
		}
		done := make(chan swarmRunResult, 1)

		swarmRunner := agent.NewSwarmRunner(engine, h.repo)
		go func() {
			result, runErr := swarmRunner.Run(ctx, cfg)
			_ = pw.Close()
			done <- swarmRunResult{result: result, err: runErr}
		}()

		// Stream chunks
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

			// SwarmRunner.Run normally writes the failure itself before
			// returning, but this enrich is defensive in case the runner
			// errored before its own UpdateAgenticScan ran (e.g. an early
			// preflight failure). With UpdateAgenticScan's OmitZero, the
			// re-write is idempotent if the runner already wrote.
			h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
				run.Status = "failed"
				run.ErrorMessage = res.err.Error()
				run.CompletedAt = now
				run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
			})

			_ = writeSSE(w, sseEvent{Type: "error", Error: res.err.Error()})
			zap.L().Error("Agent swarm failed (streaming)",
				zap.String("agentic_scan_uuid", agenticScanUUID),
				zap.Error(res.err))
			return
		}

		if status != nil && res.result != nil {
			status.Status = "completed"
			status.CompletedAt = &now
			status.FindingCount = res.result.TotalFindings
			status.SwarmResult = res.result
		}
		h.agentMu.Unlock()

		// Persist to DB
		if status != nil {
			h.persistAgenticScanCompleted(agenticScanUUID, status)
		}

		webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)

		_ = writeSSE(w, sseEvent{Type: "done", SwarmResult: res.result})
		zap.L().Info("Agent swarm completed (streaming)",
			zap.String("agentic_scan_uuid", agenticScanUUID),
			zap.Int("findings", res.result.TotalFindings))
	})
}

// runBackgroundAgentSwarm executes an agent swarm in a goroutine and updates status.
func (h *Handlers) runBackgroundAgentSwarm(agenticScanUUID string, req AgentSwarmRequest, projectUUID string, timeout time.Duration, engine *agent.Engine, byokCleanup func()) {
	defer h.releaseHeavyAgentSlotForProject(projectUUID)
	if byokCleanup != nil {
		defer byokCleanup()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg := h.buildSwarmConfig(req, projectUUID)
	// Pin the swarm runner's DB record UUID to our agenticScanUUID so its internal
	// CreateAgenticScan/UpdateAgenticScan calls land on the same row the API
	// already returned to the client. Without this, the swarm runner picks
	// its own UUID and the session detail endpoint shows an empty record.
	cfg.AgenticScanUUID = agenticScanUUID

	// Pre-create the session dir under agenticScanUUID so it lines up with the API
	// session UUID and SwarmRunner won't auto-allocate a different one.
	sessionDir, sessionErr := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), agenticScanUUID)
	if sessionErr != nil {
		zap.L().Warn("Failed to pre-create session dir", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(sessionErr))
	} else {
		cfg.SessionDir = sessionDir
	}

	// Stream live agent output to a log file in the session dir so users can
	// `tail -f {session_dir}/runtime.log`. Non-nil writer is also required to
	// keep vigolium-audit on the working Claude stream-json branch.
	var streamCloser io.Closer
	if sessionDir != "" {
		logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			cfg.StreamWriter = f
			streamCloser = f
		} else {
			zap.L().Warn("Failed to open runtime.log, falling back to discard", zap.Error(err))
			cfg.StreamWriter = io.Discard
		}
	} else {
		cfg.StreamWriter = io.Discard
	}
	if streamCloser != nil {
		defer func() { _ = streamCloser.Close() }()
	}

	// Populate the row with request-time + session-dir info before kicking
	// off the run, so the session detail endpoint shows useful state during
	// in-progress queries.
	h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
		run.ProjectUUID = projectUUID
		run.SourcePath = cfg.SourcePath
		run.SourceType = database.InferSourceType(cfg.SourcePath)
		run.SessionDir = sessionDir
		if len(cfg.Inputs) > 0 {
			run.InputRaw = cfg.Inputs[0]
		}
	})

	// Wire phase callback for status updates
	cfg.PhaseCallback = func(phase string) {
		h.agentMu.Lock()
		if status := h.agenticScanStatus[agenticScanUUID]; status != nil {
			status.CurrentPhase = phase
		}
		h.agentMu.Unlock()
	}

	swarmRunner := agent.NewSwarmRunner(engine, h.repo)
	result, runErr := swarmRunner.Run(ctx, cfg)

	// The runner itself writes status/duration/finding_count/source_path/
	// session_dir via OmitZero, so the only thing the handler still owns is
	// the marshalled result blob (the runner doesn't know about ResultJSON).
	if result != nil {
		h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
			if data, err := json.Marshal(result); err == nil {
				run.ResultJSON = string(data)
			}
		})
	}

	now := time.Now()

	// Hold agentMu only for the in-memory mutation; release it before any
	// downstream work that might re-acquire it (persist, upload).
	// uploadAgenticResults takes agentMu to surface storage_url, so a held
	// mutex would deadlock here (Go mutexes are non-reentrant).
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
			status.FindingCount = result.TotalFindings
			status.SwarmResult = result
		}
	}
	statusSnapshot := *status
	h.agentMu.Unlock()

	h.persistAgenticScanCompleted(agenticScanUUID, &statusSnapshot)

	if runErr != nil {
		webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)
		zap.L().Error("Agent swarm failed",
			zap.String("agentic_scan_uuid", agenticScanUUID),
			zap.Error(runErr))
		return
	}

	if req.UploadResults && sessionDir != "" {
		h.uploadAgenticResults(projectUUID, agenticScanUUID, sessionDir)
	}

	webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)

	zap.L().Info("Agent swarm completed",
		zap.String("agentic_scan_uuid", agenticScanUUID),
		zap.String("session_dir", sessionDir),
		zap.Int("findings", statusSnapshot.FindingCount))
}

// ---------------------------------------------------------------------------
// SSE event types and helpers
// ---------------------------------------------------------------------------

// sseEvent is an SSE event payload sent during streaming agent runs.
type sseEvent struct {
	Type            string                         `json:"type"`                       // "chunk", "done", "error", "phase", "progress", "driver_start", "driver_end"
	Text            string                         `json:"text,omitempty"`             // for "chunk" events
	Result          *agent.Result                  `json:"result,omitempty"`           // for "done" events (query)
	AutopilotResult *agent.AutopilotPipelineResult `json:"autopilot_result,omitempty"` // for "done" events (autopilot)
	SwarmResult     *agent.SwarmResult             `json:"swarm_result,omitempty"`     // for "done" events (swarm/pipeline)
	Phase           string                         `json:"phase,omitempty"`            // for "phase" events
	Progress        *agent.ProgressEvent           `json:"progress,omitempty"`         // for "progress" events
	Error           string                         `json:"error,omitempty"`            // for "error" events
	Driver          string                         `json:"driver,omitempty"`           // for /agent/run/audit driver=auto/both: tags chunk/driver_start/driver_end events with "audit" or "piolium"
}

// writeSSE marshals an event to JSON and writes it as an SSE data line, then flushes.
func writeSSE(w *bufio.Writer, evt sseEvent) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// Status endpoints (unchanged)
// ---------------------------------------------------------------------------

// HandleAgenticScanList handles GET /api/agent/status/list — returns all agent run statuses.
// Returns from database for historical runs, merged with in-memory status for active runs.
func (h *Handlers) HandleAgenticScanList(c fiber.Ctx) error {
	// Try DB first for comprehensive history
	if h.repo != nil {
		mode := c.Query("mode")
		runs, _, err := h.repo.ListAgenticScans(context.Background(), "", mode, 100, 0)
		if err == nil && len(runs) > 0 {
			statuses := make([]*AgenticScanStatusResponse, 0, len(runs))
			for _, run := range runs {
				statuses = append(statuses, agenticScanToStatusResponse(run))
			}
			// Merge in-memory running statuses (they have richer data like Result objects).
			// Snapshot under the mutex — the run goroutines mutate the same pointers,
			// so handing the live entries to c.JSON would race with those writes.
			h.agentMu.Lock()
			for _, memStatus := range h.agenticScanStatus {
				if memStatus.Status == "running" {
					snapshot := *memStatus
					found := false
					for i, s := range statuses {
						if s.AgenticScanUUID == snapshot.AgenticScanUUID {
							statuses[i] = &snapshot
							found = true
							break
						}
					}
					if !found {
						statuses = append(statuses, &snapshot)
					}
				}
			}
			h.agentMu.Unlock()
			return c.JSON(statuses)
		}
	}

	// Fallback to in-memory — snapshot every entry under the lock so we
	// serialize stable copies rather than racing with concurrent mutators.
	h.agentMu.Lock()
	statuses := make([]*AgenticScanStatusResponse, 0, len(h.agenticScanStatus))
	for _, s := range h.agenticScanStatus {
		snapshot := *s
		statuses = append(statuses, &snapshot)
	}
	h.agentMu.Unlock()
	return c.JSON(statuses)
}

// HandleAgenticScanStatus handles GET /api/agent/status/:id — returns status of a specific agent run.
func (h *Handlers) HandleAgenticScanStatus(c fiber.Ctx) error {
	agenticScanUUID := c.Params("id")

	// Check in-memory first (richer data for active runs). Snapshot under
	// the mutex — c.JSON serializes after we Unlock, and run goroutines
	// concurrently mutate the same struct, so passing the live pointer
	// races with those writes.
	h.agentMu.Lock()
	memStatus, ok := h.agenticScanStatus[agenticScanUUID]
	var snapshot AgenticScanStatusResponse
	if ok {
		snapshot = *memStatus
	}
	h.agentMu.Unlock()

	if ok {
		return c.JSON(&snapshot)
	}

	// Fall back to DB for historical runs
	if h.repo != nil {
		run, err := h.repo.GetAgenticScan(context.Background(), agenticScanUUID)
		if err == nil {
			return c.JSON(agenticScanToStatusResponse(run))
		}
	}

	return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
		Error: ErrAgentNotFound.Error(),
	})
}

// agenticScanToStatusResponse converts a database AgenticScan to an API status response.
func agenticScanToStatusResponse(run *database.AgenticScan) *AgenticScanStatusResponse {
	resp := &AgenticScanStatusResponse{
		AgenticScanUUID: run.UUID,
		Mode:            run.Mode,
		Status:          run.Status,
		AgentName:       run.AgentName,
		TemplateID:      run.TemplateID,
		FindingCount:    run.FindingCount,
		RecordCount:     run.RecordCount,
		SavedCount:      run.SavedCount,
		Error:           run.ErrorMessage,
		CurrentPhase:    run.CurrentPhase,
		PhasesRun:       run.PhasesRun,
		StorageURL:      run.StorageURL,
	}
	if !run.CompletedAt.IsZero() {
		resp.CompletedAt = &run.CompletedAt
	}
	return resp
}

// ---------------------------------------------------------------------------
// GET /api/agent/sessions — Paginated list of agent sessions
// ---------------------------------------------------------------------------

// HandleAgentSessionList returns a paginated list of agent sessions from the database.
func (h *Handlers) HandleAgentSessionList(c fiber.Ctx) error {
	if h.repo == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := getProjectUUID(c)
	mode := c.Query("mode")
	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	if limit > 500 {
		limit = 500
	}

	runs, total, err := h.repo.ListAgenticScans(c.Context(), projectUUID, mode, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to list agent sessions: " + err.Error(),
		})
	}

	summaries := make([]*AgentSessionSummary, len(runs))
	for i, run := range runs {
		summaries[i] = agenticScanToSessionSummary(run)
	}

	return c.JSON(PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        summaries,
		Total:       total,
		Limit:       limit,
		Offset:      offset,
		HasMore:     int64(offset+len(runs)) < total,
	})
}

// HandleAgentSessionDetail returns full details for a single agent session.
func (h *Handlers) HandleAgentSessionDetail(c fiber.Ctx) error {
	if h.repo == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	agenticScanUUID := c.Params("id")
	if agenticScanUUID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing session id",
		})
	}

	run, err := h.repo.GetAgenticScan(c.Context(), agenticScanUUID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrAgentNotFound.Error(),
		})
	}

	detail := agenticScanToSessionDetail(run)

	// Attach child runs (e.g. audit sub-runs spawned by autopilot)
	if children, childErr := h.repo.GetChildAgenticScans(c.Context(), agenticScanUUID); childErr == nil && len(children) > 0 {
		for _, child := range children {
			detail.ChildRuns = append(detail.ChildRuns, agenticScanToSessionDetail(child))
		}
	}

	return c.JSON(detail)
}

// reANSIEscape matches ANSI CSI color/style sequences so they can be stripped
// for plain-text readers that don't render a terminal.
var reANSIEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// stripANSI returns s with ANSI color/style escape sequences removed.
func stripANSI(s string) string {
	return reANSIEscape.ReplaceAllString(s, "")
}

// openSessionRuntimeLog opens runtime.log in the given session dir for
// append-write. Returns nil and logs a warning when the open fails or
// sessionDir is empty. Callers own closing the returned file.
func (h *Handlers) openSessionRuntimeLog(sessionDir, agenticScanUUID string) *os.File {
	if sessionDir == "" {
		return nil
	}
	logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		zap.L().Warn("Failed to open runtime.log",
			zap.String("agentic_scan_uuid", agenticScanUUID),
			zap.Error(err))
		return nil
	}
	return f
}

// maxAgentRawOutputBytes caps how much of runtime.log we copy into the
// agent_raw_output DB column so a chatty multi-hour autopilot run can't bloat
// individual rows past a few hundred KB.
const maxAgentRawOutputBytes = 200 * 1024

// snapshotAgentRawOutput reads runtime.log from sessionDir, strips ANSI, and
// returns the head-truncated tail (last maxAgentRawOutputBytes). streamFile,
// when non-nil, is fsync'd first so the snapshot sees the final flushed
// bytes; the writer is left open (the deferred close in the caller still
// runs). Returns "" on any read error or empty/missing log.
func snapshotAgentRawOutput(streamFile *os.File, sessionDir string) string {
	if sessionDir == "" {
		return ""
	}
	if streamFile != nil {
		_ = streamFile.Sync()
	}
	logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
	data, err := os.ReadFile(logPath)
	if err != nil || len(data) == 0 {
		return ""
	}
	clean := stripANSI(string(data))
	if len(clean) > maxAgentRawOutputBytes {
		clean = "...[truncated head]...\n" + clean[len(clean)-maxAgentRawOutputBytes:]
	}
	return clean
}

// parseBoolParam interprets common truthy query values. Empty → false.
func parseBoolParam(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "y", "on":
		return true
	}
	return false
}

// HandleAgentSessionLogs serves the raw run.log console stream for an agent
// session. With Accept: text/event-stream it tails the file as SSE until the
// run reaches a terminal status; otherwise it returns the full file as
// text/plain. ANSI colors are preserved by default so clients that render a
// terminal (xterm.js, etc.) see what the CLI user would see; pass ?strip=1
// to get plain text with escape sequences removed.
func (h *Handlers) HandleAgentSessionLogs(c fiber.Ctx) error {
	sessionDir, agenticScanUUID, err := h.resolveSessionDirForRun(c)
	if err != nil {
		return err
	}
	logPath := resolveRuntimeLogPath(sessionDir)
	if logPath == "" {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "runtime.log not found for this session",
		})
	}

	strip := parseBoolParam(c.Query("strip"))

	if strings.Contains(c.Get("Accept"), "text/event-stream") {
		return h.streamAgentSessionLog(c, agenticScanUUID, logPath, strip)
	}

	data, readErr := os.ReadFile(logPath)
	if readErr != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to read runtime.log: " + readErr.Error(),
		})
	}
	if strip {
		data = []byte(stripANSI(string(data)))
	}
	c.Set("Content-Type", "text/plain; charset=utf-8")
	return c.Send(data)
}

// maxArtifactListEntries caps the number of files reported by
// HandleAgentSessionArtifacts so a runaway session dir cannot blow up the
// response. When the walk hits this limit, the response is marked truncated.
const maxArtifactListEntries = 500

// maxArtifactReadBytes is the default cap for HandleAgentSessionArtifact reads.
// Clients can request more via ?max_bytes=N, up to maxArtifactReadBytesHardCap.
const (
	maxArtifactReadBytes        = 10 * 1024 * 1024  // 10 MiB
	maxArtifactReadBytesHardCap = 100 * 1024 * 1024 // 100 MiB
)

// HandleAgentSessionArtifacts lists files inside an agent session directory.
// The walk is recursive but capped at maxArtifactListEntries; the response
// flags `truncated: true` when the cap is hit. Names are returned as paths
// relative to the session_dir so they can be passed back to
// HandleAgentSessionArtifact unchanged.
func (h *Handlers) HandleAgentSessionArtifacts(c fiber.Ctx) error {
	sessionDir, agenticScanUUID, err := h.resolveSessionDirForRun(c)
	if err != nil {
		return err // already sent
	}

	artifacts := make([]AgentArtifact, 0, 32)
	truncated := false
	// errArtifactCapHit aborts the walk once we've collected the cap; using a
	// sentinel error is the only way to short-circuit filepath.WalkDir
	// completely (SkipDir only skips the current dir's children).
	errArtifactCapHit := fmt.Errorf("artifact cap hit")
	walkErr := filepath.WalkDir(sessionDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if len(artifacts) >= maxArtifactListEntries {
			truncated = true
			return errArtifactCapHit
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(sessionDir, path)
		if relErr != nil {
			return nil
		}
		artifacts = append(artifacts, AgentArtifact{
			Name:       filepath.ToSlash(rel),
			Size:       info.Size(),
			ModifiedAt: info.ModTime(),
			Kind:       artifactKind(info.Name()),
		})
		return nil
	})
	if walkErr != nil && walkErr != errArtifactCapHit {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to walk session dir: " + walkErr.Error(),
		})
	}

	return c.JSON(AgentArtifactListResponse{
		AgenticScanUUID: agenticScanUUID,
		SessionDir:      sessionDir,
		Artifacts:       artifacts,
		Truncated:       truncated,
	})
}

// HandleAgentSessionArtifact serves a single file from an agent session
// directory. The file path is captured by the wildcard route segment and is
// resolved within the session_dir; any attempt to escape via "..", absolute
// paths, or symlinks pointing outside the session_dir is rejected with 400.
//
// When the file exists and is small enough, its bytes are streamed back with
// a content-type derived from the extension. Use ?max_bytes=N to override the
// default 10 MiB cap (hard cap: 100 MiB).
func (h *Handlers) HandleAgentSessionArtifact(c fiber.Ctx) error {
	sessionDir, _, err := h.resolveSessionDirForRun(c)
	if err != nil {
		return err
	}

	name := c.Params("*")
	if name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing artifact name",
		})
	}

	fullPath, err := safeArtifactPath(sessionDir, name)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
		})
	}

	f, openErr := os.Open(fullPath)
	if openErr != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "artifact not found",
		})
	}
	info, statErr := f.Stat()
	if statErr != nil || info.IsDir() {
		_ = f.Close()
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "artifact not found",
		})
	}

	maxBytes := int64(maxArtifactReadBytes)
	if v := c.Query("max_bytes"); v != "" {
		if parsed, parseErr := strconv.ParseInt(v, 10, 64); parseErr == nil && parsed > 0 {
			if parsed > maxArtifactReadBytesHardCap {
				parsed = maxArtifactReadBytesHardCap
			}
			maxBytes = parsed
		}
	}

	sendSize := info.Size()
	truncated := false
	if sendSize > maxBytes {
		sendSize = maxBytes
		truncated = true
	}

	c.Set("Content-Type", artifactContentType(info.Name()))
	if truncated {
		c.Set("X-Artifact-Truncated", "1")
		c.Set("X-Artifact-Total-Size", strconv.FormatInt(info.Size(), 10))
	}
	// Stream the file via fasthttp's body stream; it closes the reader when
	// done writing the response, so we don't keep a copy in memory.
	return c.SendStream(&closingLimitReader{R: io.LimitReader(f, sendSize), C: f}, int(sendSize))
}

// closingLimitReader couples a size-limited reader with the closer of the
// underlying *os.File, so fasthttp's SetBodyStream-driven Close call frees
// the file handle when the response finishes streaming.
type closingLimitReader struct {
	R io.Reader
	C io.Closer
}

func (cr *closingLimitReader) Read(p []byte) (int, error) { return cr.R.Read(p) }
func (cr *closingLimitReader) Close() error               { return cr.C.Close() }

// resolveSessionDirForRun loads the agentic_scans row for the URL :id param
// and returns the session_dir on disk along with the run UUID. The session
// dir from the DB is preferred; when missing (legacy rows) the conventional
// path under the configured sessions_dir is used. Errors are written to the
// response and returned to the caller.
func (h *Handlers) resolveSessionDirForRun(c fiber.Ctx) (string, string, error) {
	if h.repo == nil {
		return "", "", c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}
	agenticScanUUID := c.Params("id")
	if agenticScanUUID == "" {
		return "", "", c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing session id",
		})
	}
	run, err := h.repo.GetAgenticScan(c.Context(), agenticScanUUID)
	if err != nil || run == nil {
		return "", "", c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrAgentNotFound.Error(),
		})
	}
	sessionDir := run.SessionDir
	if sessionDir == "" {
		sessionDir = filepath.Join(h.settings.Agent.EffectiveSessionsDir(), agenticScanUUID)
	}
	if info, statErr := os.Stat(sessionDir); statErr != nil || !info.IsDir() {
		return "", "", c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "session directory not found",
		})
	}
	return sessionDir, agenticScanUUID, nil
}

// errInvalidArtifactName is returned by safeArtifactPath for any name that
// cannot be safely resolved within the session directory. The message is
// intentionally generic so it doesn't help an attacker probe the filesystem.
var errInvalidArtifactName = fmt.Errorf("invalid artifact name")

// pathIsUnderDir reports whether absChild lives at or under absParent. Both
// arguments must already be absolute and symlink-resolved.
func pathIsUnderDir(absChild, absParent string) bool {
	if absChild == absParent {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(absChild+sep, absParent+sep)
}

// safeArtifactPath resolves name against sessionDir, rejecting any path that
// could escape it. Rules: empty/"." names, absolute paths, and ".." segments
// are rejected outright; the joined path is then symlink-resolved and
// verified to still live inside the session_dir.
func safeArtifactPath(sessionDir, name string) (string, error) {
	if name == "" || name == "." {
		return "", errInvalidArtifactName
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", errInvalidArtifactName
	}
	for _, seg := range strings.Split(filepath.ToSlash(name), "/") {
		if seg == ".." {
			return "", errInvalidArtifactName
		}
	}
	// Resolve the session directory's symlinks so platforms with symlinked
	// temp/home dirs (e.g. macOS /var → /private/var) compare apples-to-apples.
	// The candidate is built atop the resolved root so a stat-failure on the
	// artifact itself doesn't poison the prefix check.
	resolvedSession, err := filepath.EvalSymlinks(sessionDir)
	if err != nil {
		resolvedSession = sessionDir
	}
	sessionAbs, err := filepath.Abs(resolvedSession)
	if err != nil {
		return "", fmt.Errorf("invalid session dir")
	}
	fullAbs, err := filepath.Abs(filepath.Join(sessionAbs, filepath.FromSlash(name)))
	if err != nil || !pathIsUnderDir(fullAbs, sessionAbs) {
		return "", errInvalidArtifactName
	}
	// Follow the artifact's own symlinks if it exists, so a symlink whose
	// target lives outside the session dir is rejected. Missing files are
	// fine here; os.Stat in the caller surfaces the 404.
	if resolved, evalErr := filepath.EvalSymlinks(fullAbs); evalErr == nil {
		resolvedAbs, _ := filepath.Abs(resolved)
		if !pathIsUnderDir(resolvedAbs, sessionAbs) {
			return "", errInvalidArtifactName
		}
	}
	return fullAbs, nil
}

// Artifact kind tags returned by artifactKind. Clients use these to pick a
// rendering mode (terminal log, JSON tree, markdown, etc.).
const (
	ArtifactKindLog      = "log"
	ArtifactKindJSON     = "json"
	ArtifactKindJSONL    = "jsonl"
	ArtifactKindMarkdown = "markdown"
	ArtifactKindYAML     = "yaml"
	ArtifactKindText     = "text"
)

// artifactKind classifies an artifact by filename. Unknown extensions fall
// back to ArtifactKindText so callers can default to a plain-text renderer.
func artifactKind(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".log"):
		return ArtifactKindLog
	case strings.HasSuffix(lower, ".jsonl"), strings.HasSuffix(lower, ".ndjson"):
		return ArtifactKindJSONL
	case strings.HasSuffix(lower, ".json"):
		return ArtifactKindJSON
	case strings.HasSuffix(lower, ".md"), strings.HasSuffix(lower, ".markdown"):
		return ArtifactKindMarkdown
	case strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"):
		return ArtifactKindYAML
	}
	return ArtifactKindText
}

// artifactContentType returns a Content-Type header for serving an artifact.
// JSON/YAML/markdown get their proper content types so browsers and clients
// can pretty-print; everything else falls through to plain text.
func artifactContentType(name string) string {
	switch artifactKind(name) {
	case ArtifactKindJSON:
		return "application/json; charset=utf-8"
	case ArtifactKindJSONL:
		return "application/x-ndjson; charset=utf-8"
	case ArtifactKindYAML:
		return "application/yaml; charset=utf-8"
	case ArtifactKindMarkdown:
		return "text/markdown; charset=utf-8"
	}
	return "text/plain; charset=utf-8"
}

// resolveRuntimeLogPath returns the first existing log file path within the
// session directory, preferring runtime.log but falling back to the legacy
// run.log filename so older sessions still resolve.
func resolveRuntimeLogPath(sessionDir string) string {
	for _, name := range []string{config.RuntimeLogFilename, "run.log"} {
		candidate := filepath.Join(sessionDir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// streamAgentSessionLog tails runtime.log and emits each new byte range as an SSE
// "chunk" event. Exits on client disconnect (detected via a failed SSE write)
// or once the agent run row enters a terminal status, at which point a "done"
// event is emitted. When strip is true, ANSI escape sequences are removed from
// each chunk before it is forwarded.
func (h *Handlers) streamAgentSessionLog(c fiber.Ctx, agenticScanUUID, logPath string, strip bool) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	// Disable proxy buffering so chunks reach the client promptly.
	c.Set("X-Accel-Buffering", "no")

	isDone := func() bool {
		run, err := h.repo.GetAgenticScan(context.Background(), agenticScanUUID)
		if err != nil || run == nil {
			return true
		}
		return isTerminalAgentStatus(run.Status)
	}

	return c.SendStreamWriter(func(w *bufio.Writer) {
		tailSessionLog(w, logPath, isDone, 500*time.Millisecond, 2*time.Hour, strip)
	})
}

// isTerminalAgentStatus reports whether an agentic_scans.status value indicates
// the run has finished and no more bytes will be appended to run.log.
func isTerminalAgentStatus(status string) bool {
	switch status {
	case "completed", "failed", "cancelled", "timeout", "error":
		return true
	}
	return false
}

// tailSessionLog reads logPath and writes SSE chunk events into w, polling for
// new bytes every pollInterval until isDone reports the run has finished. A
// safetyTimeout backstop prevents the loop from running forever if isDone is
// buggy or a client that hung up never triggers a write error. When strip is
// true, ANSI escape sequences are removed from each chunk before emission.
func tailSessionLog(w *bufio.Writer, logPath string, isDone func() bool, pollInterval, safetyTimeout time.Duration, strip bool) {
	f, err := os.Open(logPath)
	if err != nil {
		_ = writeSSE(w, sseEvent{Type: "error", Error: err.Error()})
		return
	}
	defer func() { _ = f.Close() }()

	deadline := time.Now().Add(safetyTimeout)
	buf := make([]byte, 4096)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			text := string(buf[:n])
			if strip {
				text = stripANSI(text)
			}
			if err := writeSSE(w, sseEvent{Type: "chunk", Text: text}); err != nil {
				// Client disconnected or writer broken — stop silently.
				return
			}
		}
		if readErr != nil && readErr != io.EOF {
			_ = writeSSE(w, sseEvent{Type: "error", Error: readErr.Error()})
			return
		}
		if n == 0 {
			if isDone() {
				_ = writeSSE(w, sseEvent{Type: "done"})
				return
			}
			if time.Now().After(deadline) {
				_ = writeSSE(w, sseEvent{Type: "done"})
				return
			}
			time.Sleep(pollInterval)
		}
	}
}

// agenticScanToSessionSummary converts a database AgenticScan to a lightweight session summary.
func agenticScanToSessionSummary(run *database.AgenticScan) *AgentSessionSummary {
	s := &AgentSessionSummary{
		UUID:                  run.UUID,
		Mode:                  run.Mode,
		Status:                run.Status,
		AgentName:             run.AgentName,
		TemplateID:            run.TemplateID,
		TargetURL:             run.TargetURL,
		SourcePath:            run.SourcePath,
		SessionDir:            run.SessionDir,
		VulnType:              run.VulnType,
		InputType:             run.InputType,
		ParentAgenticScanUUID: run.ParentAgenticScanUUID,
		CurrentPhase:          run.CurrentPhase,
		PhasesRun:             run.PhasesRun,
		FindingCount:          run.FindingCount,
		RecordCount:           run.RecordCount,
		SavedCount:            run.SavedCount,
		ErrorMessage:          run.ErrorMessage,
		DurationMs:            run.DurationMs,
		CreatedAt:             run.CreatedAt,
		StorageURL:            run.StorageURL,
	}
	if !run.StartedAt.IsZero() {
		s.StartedAt = &run.StartedAt
	}
	if !run.CompletedAt.IsZero() {
		s.CompletedAt = &run.CompletedAt
	}
	return s
}

// agenticScanToSessionDetail converts a database AgenticScan to a full session detail response.
func agenticScanToSessionDetail(run *database.AgenticScan) *AgentSessionDetail {
	return &AgentSessionDetail{
		AgentSessionSummary: *agenticScanToSessionSummary(run),
		InputRaw:            run.InputRaw,
		ModuleNames:         run.ModuleNames,
		SessionID:           run.SessionID,
		PromptSent:          run.PromptSent,
		AgentRawOutput:      run.AgentRawOutput,
		AttackPlan:          run.AttackPlan,
		TriageResult:        run.TriageResult,
		ResultJSON:          run.ResultJSON,
	}
}

// ---------------------------------------------------------------------------
// POST /api/agent/chat/completions — OpenAI-compatible (unchanged)
// ---------------------------------------------------------------------------

// HandleChatCompletions handles POST /api/agent/chat/completions — OpenAI-compatible chat endpoint.
//
// BYOK is accepted via two channels for OpenAI-client compatibility:
//
//  1. Standard body fields (api_key / oauth_token / oauth_cred_file /
//     oauth_cred_json) like every other /agent/run/* endpoint.
//  2. An `Authorization: Bearer <key>` header — what every OpenAI SDK
//     sends. The header is honored only when the body fields are empty
//     so a request can't smuggle two keys; the bearer value is mapped
//     into AgentBYOK.APIKey and routed through the same overlay path.
//
// The server-level BearerAuth middleware also consumes the Authorization
// header (validating user tokens) but only when --no-auth is off. In
// no-auth mode the header passes through to this handler untouched; in
// auth mode the user token IS the bearer, so BYOK via header is not
// available — fall back to body fields.
func (h *Handlers) HandleChatCompletions(c fiber.Ctx) error {
	var req ChatCompletionRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
		})
	}

	if len(req.Messages) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "messages must not be empty",
		})
	}

	// Promote `Authorization: Bearer <key>` into AgentBYOK.APIKey when the
	// server is in no-auth mode and the body fields are empty. The
	// no-auth check uses h.config.NoAuth — when auth IS enforced, the
	// header is the operator's user token, not a BYOK key, so we leave
	// it alone.
	if req.IsZero() && h.config.NoAuth {
		if hdr := c.Get("Authorization"); strings.HasPrefix(hdr, "Bearer ") {
			req.APIKey = strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
		}
	}

	var prompt string
	for i, msg := range req.Messages {
		if i > 0 {
			prompt += "\n\n"
		}
		prompt += msg.Role + ": " + msg.Content
	}

	// req.Model is retained for OpenAI-compat echoing; olium provider
	// selection comes from agent.olium.provider in config (or the
	// per-request BYOK overlay below).
	if !h.acquireAgentSlot(c, h.agentLightSem) {
		return nil // 429 already sent
	}
	defer h.releaseAgentSlot(h.agentLightSem)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	eng, cleanup, err := h.engineForRequest(req.AgentBYOK)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "byok: " + err.Error(),
		})
	}
	defer cleanup()

	opts := agent.Options{
		AgentName:    "olium",
		PromptInline: prompt,
	}

	result, err := eng.Run(ctx, opts)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "agent run failed: " + err.Error(),
		})
	}

	return c.JSON(ChatCompletionResponse{
		ID:      "chatcmpl-" + uuid.New().String(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []ChatChoice{
			{
				Index: 0,
				Message: ChatMessage{
					Role:    "assistant",
					Content: result.RawOutput,
				},
				FinishReason: "stop",
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// parseDurationOrDefault parses a Go duration string, returning the default on failure or empty input.
func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

// refuseIfGuardrailBlocks runs the prompt-safety classifier and, on refusal,
// writes a 400 JSON response and returns its error for early return. Returns
// nil when the prompt is allowed (or when the classifier failed open). The
// server has no override flag — this gate is always on for API callers.
func (h *Handlers) refuseIfGuardrailBlocks(c fiber.Ctx, prompt string) error {
	verdict := agent.ClassifyPromptSafety(c.Context(), h.settings, prompt)
	if verdict.Allowed {
		return nil
	}
	zap.L().Info("guardrail refused prompt",
		zap.String("reason", verdict.Reason),
		zap.Strings("categories", verdict.Categories))
	return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
		Error: "prompt refused by guardrail: " + verdict.Reason,
		Code:  fiber.StatusBadRequest,
	})
}

// resolvePromptIntent parses a natural language prompt into a ScanIntent using the agent engine.
// On error, it sends an HTTP error response and returns the error for early return.
func (h *Handlers) resolvePromptIntent(c fiber.Ctx, prompt string) (*agent.ScanIntent, error) {
	intent, err := agent.ParseAndResolveIntent(c.Context(), h.agentEngine, prompt)
	if err != nil {
		return nil, c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to parse natural language prompt: " + err.Error(),
		})
	}
	return intent, nil
}
