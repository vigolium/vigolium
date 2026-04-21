package server

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/storage"
	"go.uber.org/zap"
)

// persistAgenticScan creates an agentic_scans DB record for a new agent run.
func (h *Handlers) persistAgenticScan(runID, mode, agentName string) {
	if h.repo == nil {
		return
	}
	var protocol, model string
	if h.settings != nil {
		protocol, model = h.settings.Agent.BackendMeta(agentName)
	}
	run := &database.AgenticScan{
		UUID:      runID,
		Mode:      mode,
		AgentName: agentName,
		Protocol:  protocol,
		Model:     model,
		Status:    "running",
		StartedAt: time.Now(),
	}
	if err := h.repo.CreateAgenticScan(context.Background(), run); err != nil {
		zap.L().Debug("Failed to persist agent run", zap.String("run_id", runID), zap.Error(err))
	}
}

// persistAgenticScanCompleted updates the DB record for a completed agent run.
func (h *Handlers) persistAgenticScanCompleted(runID string, status *AgenticScanStatusResponse) {
	if h.repo == nil {
		return
	}
	run := &database.AgenticScan{
		UUID:         runID,
		Status:       status.Status,
		AgentName:    status.AgentName,
		TemplateID:   status.TemplateID,
		FindingCount: status.FindingCount,
		RecordCount:  status.RecordCount,
		SavedCount:   status.SavedCount,
		ErrorMessage: status.Error,
		CurrentPhase: status.CurrentPhase,
		PhasesRun:    status.PhasesRun,
	}
	if status.CompletedAt != nil {
		run.CompletedAt = *status.CompletedAt
	}
	_ = h.repo.UpdateAgenticScan(context.Background(), run)
}

func (h *Handlers) effectiveAgentName(agentName string) string {
	if agentName != "" {
		return agentName
	}
	if h.settings != nil {
		return h.settings.Agent.DefaultAgent
	}
	return ""
}

func (h *Handlers) registerRunningAgenticScan(mode, agentName string) string {
	runID := uuid.New().String()
	effectiveAgentName := h.effectiveAgentName(agentName)

	h.agentMu.Lock()
	h.agenticScanStatus[runID] = &AgenticScanStatusResponse{
		RunID:     runID,
		Mode:      mode,
		Status:    "running",
		AgentName: effectiveAgentName,
	}
	h.agentMu.Unlock()

	h.persistAgenticScan(runID, mode, effectiveAgentName)
	return runID
}

// enrichAgenticScanRecord loads the agentic_scans row for runID, applies mutate,
// and writes it back. This is used for request-time fields that the
// lightweight persistAgenticScan helpers don't cover.
func (h *Handlers) enrichAgenticScanRecord(runID string, mutate func(run *database.AgenticScan)) {
	if h.repo == nil || mutate == nil {
		return
	}
	ctx := context.Background()
	run, err := h.repo.GetAgenticScan(ctx, runID)
	if err != nil || run == nil {
		zap.L().Debug("enrichAgenticScanRecord: run not found", zap.String("run_id", runID), zap.Error(err))
		return
	}
	mutate(run)
	if err := h.repo.UpdateAgenticScan(ctx, run); err != nil {
		zap.L().Debug("enrichAgenticScanRecord: update failed", zap.String("run_id", runID), zap.Error(err))
	}
}

// uploadAgenticResults bundles the session directory and uploads it to cloud storage.
func (h *Handlers) uploadAgenticResults(projectUUID, runID, sessionDir string) {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		zap.L().Warn("upload_results requested but storage is not enabled")
		return
	}

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		zap.L().Warn("Failed to create storage client", zap.Error(err))
		return
	}

	key := storage.AgenticScanResultKey(runID)
	storageURL, err := sc.BundleAndUploadResults(context.Background(), projectUUID, key, sessionDir)
	if err != nil {
		zap.L().Warn("Failed to upload agentic results", zap.Error(err))
		return
	}

	if h.repo != nil {
		_ = h.repo.UpdateAgenticScanStorageURL(context.Background(), runID, storageURL)
	}

	zap.L().Info("Uploaded agentic scan results", zap.String("run_id", runID), zap.String("storage_url", storageURL))
}

// startAgenticScan is the entry point for query mode.
// It acquires a light agent slot, creates status tracking, and runs the agent.
func (h *Handlers) startAgenticScan(c fiber.Ctx, mode string, stream bool, opts agent.Options, timeout time.Duration) error {
	if !h.acquireAgentSlot(c, h.agentLightSem) {
		return nil // 429 already sent
	}

	opts.AgentName = h.effectiveAgentName(opts.AgentName)
	runID := h.registerRunningAgenticScan(mode, opts.AgentName)

	if stream {
		return h.handleAgentSSE(c, runID, opts, timeout)
	}

	go h.runBackgroundAgentWithOpts(runID, opts, timeout)

	return c.Status(fiber.StatusAccepted).JSON(AgenticScanResponse{
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
		defer h.releaseAgentSlot(h.agentLightSem)

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
		status := h.agenticScanStatus[runID]
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

		if status != nil {
			h.persistAgenticScanCompleted(runID, status)
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
	defer h.releaseAgentSlot(h.agentLightSem)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sessionDir, sessionErr := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), runID)
	if sessionErr != nil {
		zap.L().Warn("Failed to pre-create session dir", zap.String("run_id", runID), zap.Error(sessionErr))
	} else {
		opts.SessionDir = sessionDir
		h.enrichAgenticScanRecord(runID, func(run *database.AgenticScan) {
			run.SessionDir = sessionDir
		})
	}

	var streamCloser io.Closer
	if sessionDir != "" {
		logPath := filepath.Join(sessionDir, config.RuntimeLogFilename)
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			opts.StreamWriter = f
			streamCloser = f
		} else {
			zap.L().Warn("Failed to open runtime.log, falling back to discard", zap.Error(err))
			opts.StreamWriter = io.Discard
		}
	} else {
		opts.StreamWriter = io.Discard
	}
	if streamCloser != nil {
		defer func() { _ = streamCloser.Close() }()
	}

	result, err := h.agentEngine.Run(ctx, opts)

	h.agentMu.Lock()
	defer h.agentMu.Unlock()

	status := h.agenticScanStatus[runID]
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

	h.persistAgenticScanCompleted(runID, status)

	zap.L().Info("Agent run completed",
		zap.String("run_id", runID),
		zap.String("agent", result.AgentName),
		zap.Int("findings", len(result.Findings)),
		zap.Int("saved", result.SavedCount))
}
