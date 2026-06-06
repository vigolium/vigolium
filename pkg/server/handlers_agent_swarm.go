package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
			"audit":             req.Audit != "",
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
			Audit:            req.Audit,
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

		ctx, cancel := context.WithTimeout(h.runContext(), timeout)
		defer cancel()
		h.registerRunCancel(agenticScanUUID, cancel)
		defer h.unregisterRunCancel(agenticScanUUID)

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

		// All SSE writes for this run funnel through one sink: the phase and
		// progress callbacks below fire from the swarm runner's goroutines,
		// concurrently with the chunk-drain loop and the finalization writes —
		// a bufio.Writer is not safe for concurrent use, so the sink serializes
		// them.
		sink := newSSESink(w)

		// Wire phase callback for SSE events
		cfg.PhaseCallback = func(phase string) {
			h.agentMu.Lock()
			if status := h.agenticScanStatus[agenticScanUUID]; status != nil {
				status.CurrentPhase = phase
			}
			h.agentMu.Unlock()

			_ = sink.send(sseEvent{Type: "phase", Phase: phase})
		}

		// Wire progress callback for SSE events
		cfg.ProgressCallback = func(evt agent.ProgressEvent) {
			_ = sink.send(sseEvent{Type: "progress", Progress: &evt})
		}

		// Set up stream writer pipe AND tee to runtime.log. Log file FIRST so
		// the disk record is never gated on the SSE client; drainAgentPipeToSSE
		// keeps reading pr after a disconnect so pw.Write never blocks.
		pr, pw := io.Pipe()
		var streamWriter io.Writer = pw
		if logFile := h.openSessionRuntimeLog(sessionDir, agenticScanUUID); logFile != nil {
			streamWriter = io.MultiWriter(logFile, pw)
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

		// Stream chunks. On client disconnect, keep draining to EOF so the
		// finalization below (DB status → completed/failed) always runs.
		clientConnected := drainAgentPipeToSSE(sink, pr, cancel)

		res := <-done
		now := time.Now()
		h.agentMu.Lock()
		status := h.agenticScanStatus[agenticScanUUID]

		if res.err != nil {
			runStatus := terminalStatusForRunErr(res.err)
			if status != nil {
				status.Status = runStatus
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
				run.Status = runStatus
				run.ErrorMessage = res.err.Error()
				run.CompletedAt = now
				run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
			})

			if clientConnected {
				_ = sink.send(sseEvent{Type: "error", Error: res.err.Error()})
			}
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

		if clientConnected {
			_ = sink.send(sseEvent{Type: "done", SwarmResult: res.result})
		}
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

	ctx, cancel := context.WithTimeout(h.runContext(), timeout)
	defer cancel()
	h.registerRunCancel(agenticScanUUID, cancel)
	defer h.unregisterRunCancel(agenticScanUUID)

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
