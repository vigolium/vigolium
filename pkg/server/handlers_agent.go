package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// POST /api/agent/run/query — single-shot prompt execution
// ---------------------------------------------------------------------------

// HandleAgentQuery handles POST /api/agent/run/query — triggers a single-shot AI agent run.
// When "stream":true, the response is an SSE stream; otherwise it returns 202 async.
func (h *Handlers) HandleAgentQuery(c fiber.Ctx) error {
	var req AgentRunRequest
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

	opts := h.buildQueryOpts(req)
	timeout := 10 * time.Minute

	return h.startAgentRun(c, "query", req.Stream, opts, timeout)
}

// buildQueryOpts creates agent.Options from a query request.
func (h *Handlers) buildQueryOpts(req AgentRunRequest) agent.Options {
	agentName := req.Agent
	if agentName == "" {
		agentName = h.settings.Agent.DefaultAgent
	}
	return agent.Options{
		AgentName:      agentName,
		PromptTemplate: req.PromptTemplate,
		PromptFile:     req.PromptFile,
		PromptInline:   req.Prompt,
		SourcePath:     req.EffectiveSourcePath(),
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

	if req.Target == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingTarget.Error(),
		})
	}

	timeout := parseDurationOrDefault(req.Timeout, 30*time.Minute)

	return h.startAutopilotRun(c, req, timeout)
}

// startAutopilotRun acquires concurrency lock, creates status tracking, and runs the autopilot pipeline.
func (h *Handlers) startAutopilotRun(c fiber.Ctx, req AgentAutopilotRequest, timeout time.Duration) error {
	h.agentMu.Lock()
	if h.agentHeavyRunning {
		h.agentMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrAgentHeavyAlreadyRunning.Error(),
		})
	}
	h.agentHeavyRunning = true

	runID := "agt-" + uuid.New().String()
	h.agentRunStatus[runID] = &AgentRunStatusResponse{
		RunID:  runID,
		Mode:   "autopilot",
		Status: "running",
	}
	h.agentMu.Unlock()

	// Persist to DB
	agentName := req.Agent
	if agentName == "" {
		agentName = h.settings.Agent.DefaultAgent
	}
	h.persistAgentRun(runID, "autopilot", agentName)

	if req.Stream {
		return h.handleAutopilotSSE(c, runID, req, timeout)
	}

	go h.runBackgroundAutopilot(runID, req, timeout)

	return c.Status(fiber.StatusAccepted).JSON(AgentRunResponse{
		RunID:   runID,
		Status:  "running",
		Message: "autopilot run started",
	})
}

// buildAutopilotPipelineConfig creates an AutopilotPipelineConfig from an autopilot request.
func (h *Handlers) buildAutopilotPipelineConfig(req AgentAutopilotRequest) agent.AutopilotPipelineConfig {
	agentName := req.Agent
	if agentName == "" {
		agentName = h.settings.Agent.DefaultAgent
	}

	maxCmds := req.MaxCommands
	if maxCmds <= 0 {
		maxCmds = 100
	}

	specialists := req.Specialists
	if len(specialists) == 0 {
		specialists = []string{"injection", "xss", "auth", "ssrf", "authz"}
	}

	return agent.AutopilotPipelineConfig{
		TargetURL:   req.Target,
		SourcePath:  req.EffectiveSourcePath(),
		Files:       req.Files,
		Instruction: req.Instruction,
		Focus:       req.Focus,
		Specialists: agent.ToVulnClasses(specialists),
		AgentName:   agentName,
		MaxCommands: maxCmds,
		DryRun:      req.DryRun,
		SessionsDir: h.settings.Agent.EffectiveSessionsDir(),
		ResumeDir:   req.ResumeDir,
		ProjectUUID: req.ProjectUUID,
		ScanUUID:    req.ScanUUID,
	}
}

// handleAutopilotSSE runs the autopilot pipeline synchronously while streaming SSE events.
func (h *Handlers) handleAutopilotSSE(c fiber.Ctx, runID string, req AgentAutopilotRequest, timeout time.Duration) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer func() {
			h.agentMu.Lock()
			h.agentHeavyRunning = false
			h.agentMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cfg := h.buildAutopilotPipelineConfig(req)

		// Set up stream writer pipe.
		pr, pw := io.Pipe()
		cfg.StreamWriter = pw

		type autopilotRunResult struct {
			result *agent.AutopilotPipelineResult
			err    error
		}
		done := make(chan autopilotRunResult, 1)

		runner := agent.NewAutopilotPipelineRunner(h.agentEngine, h.repo)
		go func() {
			result, runErr := runner.Run(ctx, cfg)
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
		status := h.agentRunStatus[runID]

		if res.err != nil {
			if status != nil {
				status.Status = "failed"
				status.Error = res.err.Error()
				status.CompletedAt = &now
			}
			h.agentMu.Unlock()

			_ = writeSSE(w, sseEvent{Type: "error", Error: res.err.Error()})
			zap.L().Error("Autopilot run failed (streaming)",
				zap.String("run_id", runID),
				zap.Error(res.err))
			return
		}

		if status != nil && res.result != nil {
			status.Status = "completed"
			status.CompletedAt = &now
			status.FindingCount = res.result.TotalFindings
		}
		h.agentMu.Unlock()

		// Persist to DB
		if status != nil {
			h.persistAgentRunCompleted(runID, status)
		}

		_ = writeSSE(w, sseEvent{Type: "done", AutopilotResult: res.result})
		zap.L().Info("Autopilot run completed (streaming)",
			zap.String("run_id", runID),
			zap.Int("findings", res.result.TotalFindings))
	})
}

// runBackgroundAutopilot executes the autopilot pipeline in a goroutine and updates status.
func (h *Handlers) runBackgroundAutopilot(runID string, req AgentAutopilotRequest, timeout time.Duration) {
	defer func() {
		h.agentMu.Lock()
		h.agentHeavyRunning = false
		h.agentMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg := h.buildAutopilotPipelineConfig(req)

	runner := agent.NewAutopilotPipelineRunner(h.agentEngine, h.repo)
	result, runErr := runner.Run(ctx, cfg)

	h.agentMu.Lock()
	defer h.agentMu.Unlock()

	status := h.agentRunStatus[runID]
	if status == nil {
		return
	}

	now := time.Now()
	if runErr != nil {
		status.Status = "failed"
		status.Error = runErr.Error()
		status.CompletedAt = &now
		zap.L().Error("Autopilot run failed",
			zap.String("run_id", runID),
			zap.Error(runErr))
		return
	}

	status.Status = "completed"
	status.CompletedAt = &now
	status.FindingCount = result.TotalFindings

	// Persist to DB
	h.persistAgentRunCompleted(runID, status)

	zap.L().Info("Autopilot run completed",
		zap.String("run_id", runID),
		zap.Int("findings", result.TotalFindings))
}

// ---------------------------------------------------------------------------
// POST /api/agent/run/pipeline — multi-phase scanning pipeline
// ---------------------------------------------------------------------------

// HandleAgentPipeline handles POST /api/agent/run/pipeline — launches the multi-phase AI pipeline.
func (h *Handlers) HandleAgentPipeline(c fiber.Ctx) error {
	var req AgentPipelineRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
		})
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

	if req.Target == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingTarget.Error(),
		})
	}

	timeout := parseDurationOrDefault(req.Timeout, 1*time.Hour)

	return h.startPipelineRun(c, req, timeout)
}

// startPipelineRun acquires the concurrency lock, creates status tracking, and runs the pipeline.
func (h *Handlers) startPipelineRun(c fiber.Ctx, req AgentPipelineRequest, timeout time.Duration) error {
	h.agentMu.Lock()
	if h.agentHeavyRunning {
		h.agentMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrAgentHeavyAlreadyRunning.Error(),
		})
	}
	h.agentHeavyRunning = true

	runID := "agt-" + uuid.New().String()
	h.agentRunStatus[runID] = &AgentRunStatusResponse{
		RunID:  runID,
		Mode:   "pipeline",
		Status: "running",
	}
	h.agentMu.Unlock()

	// Persist to DB
	agentName := req.Agent
	if agentName == "" {
		agentName = h.settings.Agent.DefaultAgent
	}
	h.persistAgentRun(runID, "pipeline", agentName)

	if req.Stream {
		return h.handlePipelineSSE(c, runID, req, timeout)
	}

	go h.runBackgroundPipeline(runID, req, timeout)

	return c.Status(fiber.StatusAccepted).JSON(AgentRunResponse{
		RunID:   runID,
		Status:  "running",
		Message: "pipeline run started",
	})
}

// pipelineToSwarmPhase maps pipeline phase names to swarm phase names.
var pipelineToSwarmPhase = map[string]string{
	"source-analysis": agent.SwarmPhaseSourceAnalysis,
	"code-audit":      agent.SwarmPhaseCodeAudit,
	"discover":        agent.SwarmPhaseDiscover,
	"plan":            agent.SwarmPhasePlan,
	"scan":            agent.SwarmPhaseScan,
	"triage":          agent.SwarmPhaseTriage,
	"rescan":          agent.SwarmPhaseRescan,
	"report":          "", // no-op in swarm
}

// buildPipelineSwarmConfig creates an agent.SwarmConfig from a pipeline API request,
// with discovery enabled (pipeline is an alias for swarm --discover).
func (h *Handlers) buildPipelineSwarmConfig(req AgentPipelineRequest) agent.SwarmConfig {
	agentName := req.Agent
	if agentName == "" {
		agentName = h.settings.Agent.DefaultAgent
	}

	maxIter := req.MaxRescanRounds
	if maxIter <= 0 {
		maxIter = 2
	}

	// Map pipeline skip phases to swarm phase names
	var swarmSkip []string
	for _, p := range req.SkipPhases {
		p = strings.TrimSpace(p)
		if mapped, ok := pipelineToSwarmPhase[p]; ok && mapped != "" {
			swarmSkip = append(swarmSkip, mapped)
		}
	}

	// Map pipeline start-from to swarm phase name
	startFrom := req.StartFrom
	if mapped, ok := pipelineToSwarmPhase[startFrom]; ok && mapped != "" {
		startFrom = mapped
	}
	startFrom = agent.NormalizeSwarmPhase(startFrom)

	cfg := agent.SwarmConfig{
		Inputs:        []string{req.Target},
		Instruction:   req.Instruction,
		Focus:         req.Focus,
		SourcePath:    req.EffectiveSourcePath(),
		Files:         req.Files,
		SkipPhases:    swarmSkip,
		MaxIterations: maxIter,
		AgentName:     agentName,
		DryRun:        req.DryRun,
		ProjectUUID:   req.ProjectUUID,
		ScanUUID:      req.ScanUUID,
	}

	// Build synthetic checkpoint for --start-from
	if startFrom != "" {
		allPhases := []string{
			agent.SwarmPhaseNormalize,
			agent.SwarmPhaseSourceAnalysis,
			agent.SwarmPhaseCodeAudit,
			agent.SwarmPhaseSAST,
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
		if len(completed) > 0 {
			sessionDir, sdErr := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), "agt-pipeline-resume")
			if sdErr == nil {
				_ = agent.WriteCheckpointToDir(sessionDir, &agent.SwarmCheckpoint{
					CompletedPhases: completed,
				})
				cfg.ResumeDir = sessionDir
			}
		}
	}

	// Resolve a target URL for the scan runner
	targetURL := req.Target

	// Wire scan callback and discovery callback (pipeline = swarm --discover)
	cfg.ScanFunc = h.buildServerAgentSwarmFunc(targetURL, req.ProjectUUID, req.ScanUUID, "", nil, h.settings)
	cfg.DiscoverFunc = h.buildServerDiscoverFunc(targetURL, req.ProjectUUID, req.ScanUUID, h.settings)

	return cfg
}

// buildServerDiscoverFunc creates a callback that runs discovery + spidering using the native runner.
func (h *Handlers) buildServerDiscoverFunc(target, projectUUID, scanUUID string, settings *config.Settings) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{target}
		opts.ProjectUUID = projectUUID
		opts.ScanUUID = scanUUID
		opts.OnlyPhase = "discovery"
		opts.DiscoverEnabled = true
		opts.SpideringEnabled = true
		opts.HeuristicsCheck = "basic"
		opts.Silent = true
		opts.ScanConfigPrinted = true

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



// handlePipelineSSE runs the pipeline (via swarm) synchronously while streaming SSE events.
func (h *Handlers) handlePipelineSSE(c fiber.Ctx, runID string, req AgentPipelineRequest, timeout time.Duration) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer func() {
			h.agentMu.Lock()
			h.agentHeavyRunning = false
			h.agentMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cfg := h.buildPipelineSwarmConfig(req)

		// Wire phase callback for SSE events and status updates.
		cfg.PhaseCallback = func(phase string) {
			h.agentMu.Lock()
			if status := h.agentRunStatus[runID]; status != nil {
				status.CurrentPhase = phase
			}
			h.agentMu.Unlock()

			_ = writeSSE(w, sseEvent{Type: "phase", Phase: phase})
		}

		// Wire progress callback for SSE events
		cfg.ProgressCallback = func(evt agent.ProgressEvent) {
			_ = writeSSE(w, sseEvent{Type: "progress", Progress: &evt})
		}

		// Set up stream writer pipe.
		pr, pw := io.Pipe()
		cfg.StreamWriter = pw

		type swarmRunResult struct {
			result *agent.SwarmResult
			err    error
		}
		done := make(chan swarmRunResult, 1)

		swarmRunner := agent.NewSwarmRunner(h.agentEngine, h.repo)
		go func() {
			result, runErr := swarmRunner.Run(ctx, cfg)
			_ = pw.Close()
			done <- swarmRunResult{result: result, err: runErr}
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
		status := h.agentRunStatus[runID]

		if res.err != nil {
			if status != nil {
				status.Status = "failed"
				status.Error = res.err.Error()
				status.CompletedAt = &now
			}
			h.agentMu.Unlock()

			_ = writeSSE(w, sseEvent{Type: "error", Error: res.err.Error()})
			zap.L().Error("Pipeline run failed (streaming)",
				zap.String("run_id", runID),
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
			h.persistAgentRunCompleted(runID, status)
		}

		_ = writeSSE(w, sseEvent{Type: "done", SwarmResult: res.result})
		zap.L().Info("Pipeline run completed (streaming)",
			zap.String("run_id", runID),
			zap.Int("findings", res.result.TotalFindings))
	})
}

// runBackgroundPipeline executes a pipeline run (via swarm) in a goroutine and updates status.
func (h *Handlers) runBackgroundPipeline(runID string, req AgentPipelineRequest, timeout time.Duration) {
	defer func() {
		h.agentMu.Lock()
		h.agentHeavyRunning = false
		h.agentMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg := h.buildPipelineSwarmConfig(req)

	// Wire phase callback for status updates.
	cfg.PhaseCallback = func(phase string) {
		h.agentMu.Lock()
		if status := h.agentRunStatus[runID]; status != nil {
			status.CurrentPhase = phase
		}
		h.agentMu.Unlock()
	}

	swarmRunner := agent.NewSwarmRunner(h.agentEngine, h.repo)
	result, runErr := swarmRunner.Run(ctx, cfg)

	h.agentMu.Lock()
	defer h.agentMu.Unlock()

	status := h.agentRunStatus[runID]
	if status == nil {
		return
	}

	now := time.Now()
	if runErr != nil {
		status.Status = "failed"
		status.Error = runErr.Error()
		status.CompletedAt = &now
		zap.L().Error("Pipeline run failed",
			zap.String("run_id", runID),
			zap.Error(runErr))
		return
	}

	status.Status = "completed"
	status.CompletedAt = &now
	status.FindingCount = result.TotalFindings
	status.SwarmResult = result

	// Persist to DB
	h.persistAgentRunCompleted(runID, status)

	zap.L().Info("Pipeline run completed",
		zap.String("run_id", runID),
		zap.Int("findings", result.TotalFindings))
}

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

	// If base64 HTTP request is provided, ingest it and use the record UUID as input.
	if req.HTTPRequestBase64 != "" {
		recordUUID, err := h.ingestSwarmBase64(c, &req)
		if err != nil {
			return err // already sent HTTP response
		}
		req.Inputs = append(req.Inputs, recordUUID)
	}

	inputs := req.EffectiveInputs()
	if len(inputs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "at least one input is required (input, inputs, or http_request_base64 field)",
		})
	}

	timeout := parseDurationOrDefault(req.Timeout, 15*time.Minute)
	return h.startSwarmRun(c, req, timeout)
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

// startSwarmRun acquires the concurrency lock, creates status tracking, and runs the agent swarm.
func (h *Handlers) startSwarmRun(c fiber.Ctx, req AgentSwarmRequest, timeout time.Duration) error {
	h.agentMu.Lock()
	if h.agentHeavyRunning {
		h.agentMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrAgentHeavyAlreadyRunning.Error(),
		})
	}
	h.agentHeavyRunning = true

	runID := "agt-" + uuid.New().String()
	h.agentRunStatus[runID] = &AgentRunStatusResponse{
		RunID:  runID,
		Mode:   "swarm",
		Status: "running",
	}
	h.agentMu.Unlock()

	// Persist to DB
	swarmAgentName := req.Agent
	if swarmAgentName == "" {
		swarmAgentName = h.settings.Agent.DefaultAgent
	}
	h.persistAgentRun(runID, "swarm", swarmAgentName)

	if req.Stream {
		return h.handleSwarmSSE(c, runID, req, timeout)
	}

	go h.runBackgroundAgentSwarm(runID, req, timeout)

	return c.Status(fiber.StatusAccepted).JSON(AgentRunResponse{
		RunID:   runID,
		Status:  "running",
		Message: "agent swarm started",
	})
}

// buildSwarmConfig creates an agent.SwarmConfig from an API request.
func (h *Handlers) buildSwarmConfig(req AgentSwarmRequest) agent.SwarmConfig {
	agentName := req.Agent
	if agentName == "" {
		agentName = h.settings.Agent.DefaultAgent
	}

	maxIter := req.MaxIterations
	if maxIter <= 0 {
		maxIter = 3
	}

	// Normalize skip phases to support legacy aliases
	normalizedSkip := make([]string, len(req.SkipPhases))
	for i, p := range req.SkipPhases {
		normalizedSkip[i] = agent.NormalizeSwarmPhase(p)
	}

	// Merge terminal config: request fields take precedence over config file
	slashCmds := req.SlashCommands
	customAgents := req.CustomAgents
	maxCommands := req.MaxCommands
	if len(slashCmds) == 0 {
		slashCmds = h.settings.Agent.SwarmTerminal.SlashCommands
	}
	if len(customAgents) == 0 {
		customAgents = h.settings.Agent.SwarmTerminal.CustomAgents
	}
	if maxCommands <= 0 {
		maxCommands = h.settings.Agent.SwarmTerminal.EffectiveMaxCommands()
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

	cfg := agent.SwarmConfig{
		Inputs:             req.EffectiveInputs(),
		Instruction:        req.Instruction,
		SourcePath:         req.SourcePath,
		Files:              req.Files,
		VulnType:           req.VulnType,
		Focus:              req.Focus,
		ModuleNames:        req.ModuleNames,
		OnlyPhase:          req.OnlyPhase,
		SkipPhases:         normalizedSkip,
		MaxIterations:      maxIter,
		BatchConcurrency:   req.BatchConcurrency,
		MaxMasterRetries:   req.MaxMasterRetries,
		SAMaxConcurrency:   req.SAMaxConcurrency,
		AgentName:          agentName,
		AgentACPCmd:        req.AgentACPCmd,
		SlashCommands:      slashCmds,
		CustomAgents:       customAgents,
		MaxCommands:        maxCommands,
		DryRun:             req.DryRun,
		ShowPrompt:         req.ShowPrompt,
		SourceAnalysisOnly: req.SourceAnalysisOnly,
		CodeAudit:          req.CodeAudit,
		SessionsDir:        settings.Agent.EffectiveSessionsDir(),
		ProjectUUID:        req.ProjectUUID,
		ScanUUID:           req.ScanUUID,
	}

	// Resolve a target URL for the scan runner.
	// The runner needs at least one target to create an input source.
	targetURL := h.resolveSwarmTargetURL(req)

	// Wire scan callback using the server's runner infrastructure
	cfg.ScanFunc = h.buildServerAgentSwarmFunc(targetURL, req.ProjectUUID, req.ScanUUID, req.OnlyPhase, req.SkipPhases, settings)

	// Wire optional discovery callback
	if req.Discover {
		cfg.DiscoverFunc = h.buildServerSwarmDiscoverFunc(targetURL, req.ProjectUUID, req.ScanUUID, settings)
	}

	// Wire SAST callback when source_path is provided (unless skip_sast)
	if req.SourcePath != "" && !req.SkipSAST {
		cfg.SASTFunc = h.buildServerSwarmSASTFunc(targetURL, req.SourcePath, req.ProjectUUID, req.ScanUUID, settings)
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

	return cfg
}

// buildServerAgentSwarmFunc creates a callback that runs the scan.
// When IsRescan=false, it runs a full scan (all phases, all modules) by default.
// When IsRescan=true, it restricts to audit with targeted modules.
func (h *Handlers) buildServerAgentSwarmFunc(targetURL, projectUUID, scanUUID, onlyPhase string, skipPhases []string, settings *config.Settings) agent.ScanFunc {
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
			settingsCopy.Audit.Extensions.Enabled = true
			settingsCopy.Audit.Extensions.CustomDir = append(
				settingsCopy.Audit.Extensions.CustomDir,
				req.ExtensionDir+"/*.js",
			)
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

// buildServerSwarmDiscoverFunc creates a callback that runs discovery+spidering.
func (h *Handlers) buildServerSwarmDiscoverFunc(targetURL, projectUUID, scanUUID string, settings *config.Settings) func(ctx context.Context) error {
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

// buildServerSwarmSASTFunc creates a callback that runs the native SAST phase
// (ast-grep route extraction, secret detection, third-party tools).
func (h *Handlers) buildServerSwarmSASTFunc(targetURL, sourcePath, projectUUID, scanUUID string, settings *config.Settings) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts := types.DefaultOptions()
		if targetURL != "" {
			opts.Targets = []string{targetURL}
		}
		opts.ProjectUUID = projectUUID
		opts.ScanUUID = scanUUID
		opts.SourcePath = sourcePath
		opts.SASTEnabled = true
		opts.OnlyPhase = "sast"
		opts.SkipIngestion = true
		opts.SkipAudit = true
		opts.HeuristicsCheck = "none"
		opts.Silent = true
		opts.ScanConfigPrinted = true

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
		agent.SwarmPhaseSAST,
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
func (h *Handlers) handleSwarmSSE(c fiber.Ctx, runID string, req AgentSwarmRequest, timeout time.Duration) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer func() {
			h.agentMu.Lock()
			h.agentHeavyRunning = false
			h.agentMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cfg := h.buildSwarmConfig(req)

		// Wire phase callback for SSE events
		cfg.PhaseCallback = func(phase string) {
			h.agentMu.Lock()
			if status := h.agentRunStatus[runID]; status != nil {
				status.CurrentPhase = phase
			}
			h.agentMu.Unlock()

			_ = writeSSE(w, sseEvent{Type: "phase", Phase: phase})
		}

		// Wire progress callback for SSE events
		cfg.ProgressCallback = func(evt agent.ProgressEvent) {
			_ = writeSSE(w, sseEvent{Type: "progress", Progress: &evt})
		}

		// Set up stream writer pipe
		pr, pw := io.Pipe()
		cfg.StreamWriter = pw

		type swarmRunResult struct {
			result *agent.SwarmResult
			err    error
		}
		done := make(chan swarmRunResult, 1)

		swarmRunner := agent.NewSwarmRunner(h.agentEngine, h.repo)
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
		status := h.agentRunStatus[runID]

		if res.err != nil {
			if status != nil {
				status.Status = "failed"
				status.Error = res.err.Error()
				status.CompletedAt = &now
			}
			h.agentMu.Unlock()

			_ = writeSSE(w, sseEvent{Type: "error", Error: res.err.Error()})
			zap.L().Error("Agent swarm failed (streaming)",
				zap.String("run_id", runID),
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

		_ = writeSSE(w, sseEvent{Type: "done", SwarmResult: res.result})
		zap.L().Info("Agent swarm completed (streaming)",
			zap.String("run_id", runID),
			zap.Int("findings", res.result.TotalFindings))
	})
}

// runBackgroundAgentSwarm executes an agent swarm in a goroutine and updates status.
func (h *Handlers) runBackgroundAgentSwarm(runID string, req AgentSwarmRequest, timeout time.Duration) {
	defer func() {
		h.agentMu.Lock()
		h.agentHeavyRunning = false
		h.agentMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg := h.buildSwarmConfig(req)

	// Wire phase callback for status updates
	cfg.PhaseCallback = func(phase string) {
		h.agentMu.Lock()
		if status := h.agentRunStatus[runID]; status != nil {
			status.CurrentPhase = phase
		}
		h.agentMu.Unlock()
	}

	swarmRunner := agent.NewSwarmRunner(h.agentEngine, h.repo)
	result, runErr := swarmRunner.Run(ctx, cfg)

	h.agentMu.Lock()
	defer h.agentMu.Unlock()

	status := h.agentRunStatus[runID]
	if status == nil {
		return
	}

	now := time.Now()
	if runErr != nil {
		status.Status = "failed"
		status.Error = runErr.Error()
		status.CompletedAt = &now
		h.persistAgentRunCompleted(runID, status)
		zap.L().Error("Agent swarm failed",
			zap.String("run_id", runID),
			zap.Error(runErr))
		return
	}

	status.Status = "completed"
	status.CompletedAt = &now
	status.FindingCount = result.TotalFindings
	status.SwarmResult = result
	h.persistAgentRunCompleted(runID, status)

	zap.L().Info("Agent swarm completed",
		zap.String("run_id", runID),
		zap.Int("findings", result.TotalFindings))
}

// ---------------------------------------------------------------------------
// Shared agent run helpers
// ---------------------------------------------------------------------------

// startAgentRun is the entry point for query mode.
// It acquires the concurrency lock, creates status tracking, and runs the agent.
func (h *Handlers) startAgentRun(c fiber.Ctx, mode string, stream bool, opts agent.Options, timeout time.Duration) error {
	h.agentMu.Lock()
	if h.agentLightRunning {
		h.agentMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrAgentLightAlreadyRunning.Error(),
		})
	}
	h.agentLightRunning = true

	runID := "agt-" + uuid.New().String()
	h.agentRunStatus[runID] = &AgentRunStatusResponse{
		RunID:  runID,
		Mode:   mode,
		Status: "running",
	}
	h.agentMu.Unlock()

	// Persist to DB
	h.persistAgentRun(runID, mode, opts.AgentName)

	if stream {
		return h.handleAgentSSE(c, runID, opts, timeout)
	}

	go h.runBackgroundAgentWithOpts(runID, opts, timeout)

	return c.Status(fiber.StatusAccepted).JSON(AgentRunResponse{
		RunID:   runID,
		Status:  "running",
		Message: mode + " run started",
	})
}

// handleAgentSSE runs the agent synchronously while streaming SSE events to the client.
func (h *Handlers) handleAgentSSE(c fiber.Ctx, runID string, opts agent.Options, timeout time.Duration) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer func() {
			h.agentMu.Lock()
			h.agentLightRunning = false
			h.agentMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		pr, pw := io.Pipe()
		opts.StreamWriter = pw

		type runResult struct {
			result *agent.Result
			err    error
		}
		done := make(chan runResult, 1)
		go func() {
			result, err := h.agentEngine.Run(ctx, opts)
			_ = pw.Close()
			done <- runResult{result: result, err: err}
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

		res := <-done
		now := time.Now()
		h.agentMu.Lock()
		status := h.agentRunStatus[runID]
		if res.err != nil {
			if status != nil {
				status.Status = "failed"
				status.Error = res.err.Error()
				status.CompletedAt = &now
			}
			h.agentMu.Unlock()

			_ = writeSSE(w, sseEvent{Type: "error", Error: res.err.Error()})
			zap.L().Error("Agent run failed (streaming)",
				zap.String("run_id", runID),
				zap.Error(res.err))
			return
		}

		if status != nil {
			status.Status = "completed"
			status.AgentName = res.result.AgentName
			status.TemplateID = res.result.TemplateID
			status.FindingCount = len(res.result.Findings)
			status.RecordCount = len(res.result.HTTPRecords)
			status.SavedCount = res.result.SavedCount
			status.CompletedAt = &now
			status.Result = res.result
		}
		h.agentMu.Unlock()

		// Persist to DB
		if status != nil {
			h.persistAgentRunCompleted(runID, status)
		}

		_ = writeSSE(w, sseEvent{Type: "done", Result: res.result})
		zap.L().Info("Agent run completed (streaming)",
			zap.String("run_id", runID),
			zap.String("agent", res.result.AgentName),
			zap.Int("findings", len(res.result.Findings)),
			zap.Int("saved", res.result.SavedCount))
	})
}

// runBackgroundAgentWithOpts executes an agent run in a goroutine and updates status.
func (h *Handlers) runBackgroundAgentWithOpts(runID string, opts agent.Options, timeout time.Duration) {
	defer func() {
		h.agentMu.Lock()
		h.agentLightRunning = false
		h.agentMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := h.agentEngine.Run(ctx, opts)

	h.agentMu.Lock()
	defer h.agentMu.Unlock()

	status := h.agentRunStatus[runID]
	if status == nil {
		return
	}

	now := time.Now()
	if err != nil {
		status.Status = "failed"
		status.Error = err.Error()
		status.CompletedAt = &now
		zap.L().Error("Agent run failed",
			zap.String("run_id", runID),
			zap.Error(err))
		return
	}

	status.Status = "completed"
	status.AgentName = result.AgentName
	status.TemplateID = result.TemplateID
	status.FindingCount = len(result.Findings)
	status.RecordCount = len(result.HTTPRecords)
	status.SavedCount = result.SavedCount
	status.CompletedAt = &now
	status.Result = result

	// Persist to DB
	h.persistAgentRunCompleted(runID, status)

	zap.L().Info("Agent run completed",
		zap.String("run_id", runID),
		zap.String("agent", result.AgentName),
		zap.Int("findings", len(result.Findings)),
		zap.Int("saved", result.SavedCount))
}

// ---------------------------------------------------------------------------
// SSE event types and helpers
// ---------------------------------------------------------------------------

// sseEvent is an SSE event payload sent during streaming agent runs.
type sseEvent struct {
	Type            string                         `json:"type"`                       // "chunk", "done", "error", "phase", "progress"
	Text            string                         `json:"text,omitempty"`             // for "chunk" events
	Result          *agent.Result                  `json:"result,omitempty"`           // for "done" events (query)
	AutopilotResult *agent.AutopilotPipelineResult `json:"autopilot_result,omitempty"` // for "done" events (autopilot)
	PipelineResult  *agent.PipelineResult          `json:"pipeline_result,omitempty"`  // for "done" events (pipeline)
	SwarmResult     *agent.SwarmResult              `json:"swarm_result,omitempty"`     // for "done" events (swarm)
	Phase           string                         `json:"phase,omitempty"`            // for "phase" events
	Progress        *agent.ProgressEvent           `json:"progress,omitempty"`         // for "progress" events
	Error           string                         `json:"error,omitempty"`            // for "error" events
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

// HandleAgentRunList handles GET /api/agent/status/list — returns all agent run statuses.
// Returns from database for historical runs, merged with in-memory status for active runs.
func (h *Handlers) HandleAgentRunList(c fiber.Ctx) error {
	// Try DB first for comprehensive history
	if h.repo != nil {
		mode := c.Query("mode")
		runs, _, err := h.repo.ListAgentRuns(context.Background(), "", mode, 100, 0)
		if err == nil && len(runs) > 0 {
			statuses := make([]*AgentRunStatusResponse, 0, len(runs))
			for _, run := range runs {
				statuses = append(statuses, agentRunToStatusResponse(run))
			}
			// Merge in-memory running statuses (they have richer data like Result objects)
			h.agentMu.Lock()
			for _, memStatus := range h.agentRunStatus {
				if memStatus.Status == "running" {
					// Replace DB entry with richer in-memory version
					found := false
					for i, s := range statuses {
						if s.RunID == memStatus.RunID {
							statuses[i] = memStatus
							found = true
							break
						}
					}
					if !found {
						statuses = append(statuses, memStatus)
					}
				}
			}
			h.agentMu.Unlock()
			return c.JSON(statuses)
		}
	}

	// Fallback to in-memory
	h.agentMu.Lock()
	statuses := make([]*AgentRunStatusResponse, 0, len(h.agentRunStatus))
	for _, s := range h.agentRunStatus {
		statuses = append(statuses, s)
	}
	h.agentMu.Unlock()
	return c.JSON(statuses)
}

// HandleAgentRunStatus handles GET /api/agent/status/:id — returns status of a specific agent run.
func (h *Handlers) HandleAgentRunStatus(c fiber.Ctx) error {
	runID := c.Params("id")

	// Check in-memory first (richer data for active runs)
	h.agentMu.Lock()
	status, ok := h.agentRunStatus[runID]
	h.agentMu.Unlock()

	if ok {
		return c.JSON(status)
	}

	// Fall back to DB for historical runs
	if h.repo != nil {
		run, err := h.repo.GetAgentRun(context.Background(), runID)
		if err == nil {
			return c.JSON(agentRunToStatusResponse(run))
		}
	}

	return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
		Error: ErrAgentNotFound.Error(),
	})
}

// agentRunToStatusResponse converts a database AgentRun to an API status response.
func agentRunToStatusResponse(run *database.AgentRun) *AgentRunStatusResponse {
	resp := &AgentRunStatusResponse{
		RunID:        run.UUID,
		Mode:         run.Mode,
		Status:       run.Status,
		AgentName:    run.AgentName,
		TemplateID:   run.TemplateID,
		FindingCount: run.FindingCount,
		RecordCount:  run.RecordCount,
		SavedCount:   run.SavedCount,
		Error:        run.ErrorMessage,
		CurrentPhase: run.CurrentPhase,
		PhasesRun:    run.PhasesRun,
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

	runs, total, err := h.repo.ListAgentRuns(c.Context(), projectUUID, mode, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to list agent sessions: " + err.Error(),
		})
	}

	summaries := make([]*AgentSessionSummary, len(runs))
	for i, run := range runs {
		summaries[i] = agentRunToSessionSummary(run)
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

	runID := c.Params("id")
	if runID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "missing session id",
		})
	}

	run, err := h.repo.GetAgentRun(c.Context(), runID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrAgentNotFound.Error(),
		})
	}

	return c.JSON(agentRunToSessionDetail(run))
}

// agentRunToSessionSummary converts a database AgentRun to a lightweight session summary.
func agentRunToSessionSummary(run *database.AgentRun) *AgentSessionSummary {
	s := &AgentSessionSummary{
		UUID:         run.UUID,
		Mode:         run.Mode,
		Status:       run.Status,
		AgentName:    run.AgentName,
		TemplateID:   run.TemplateID,
		TargetURL:    run.TargetURL,
		VulnType:     run.VulnType,
		InputType:    run.InputType,
		CurrentPhase: run.CurrentPhase,
		PhasesRun:    run.PhasesRun,
		FindingCount: run.FindingCount,
		RecordCount:  run.RecordCount,
		SavedCount:   run.SavedCount,
		ErrorMessage: run.ErrorMessage,
		DurationMs:   run.DurationMs,
		CreatedAt:    run.CreatedAt,
	}
	if !run.StartedAt.IsZero() {
		s.StartedAt = &run.StartedAt
	}
	if !run.CompletedAt.IsZero() {
		s.CompletedAt = &run.CompletedAt
	}
	return s
}

// agentRunToSessionDetail converts a database AgentRun to a full session detail response.
func agentRunToSessionDetail(run *database.AgentRun) *AgentSessionDetail {
	return &AgentSessionDetail{
		AgentSessionSummary: *agentRunToSessionSummary(run),
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

	var prompt string
	for i, msg := range req.Messages {
		if i > 0 {
			prompt += "\n\n"
		}
		prompt += msg.Role + ": " + msg.Content
	}

	agentName := h.settings.Agent.DefaultAgent
	if _, ok := h.settings.Agent.Backends[req.Model]; ok {
		agentName = req.Model
	}

	h.agentMu.Lock()
	if h.agentLightRunning {
		h.agentMu.Unlock()
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{
			Error: ErrAgentLightAlreadyRunning.Error(),
		})
	}
	h.agentLightRunning = true
	h.agentMu.Unlock()

	defer func() {
		h.agentMu.Lock()
		h.agentLightRunning = false
		h.agentMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	opts := agent.Options{
		AgentName:    agentName,
		PromptInline: prompt,
	}

	result, err := h.agentEngine.Run(ctx, opts)
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

