package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// nativeScanUploadFormats is the set of per-format output files the API
// upload helper looks for under <scanDir>/output.<ext>. Kept narrow because
// API-launched scans only ever emit these formats today (see
// resolveAPIOutputFormats in handlers_scan.go).
var nativeScanUploadFormats = []string{"jsonl", "html"}

// persistAgenticScan creates an agentic_scans DB record for a new agent run.
// Returns ErrScanProjectMismatch when the caller pinned a UUID that already
// exists under a different project; other errors are logged but not returned.
func (h *Handlers) persistAgenticScan(agenticScanUUID, mode, agentName string) error {
	if h.repo == nil {
		return nil
	}
	var protocol, model string
	if h.settings != nil {
		protocol, model = h.settings.Agent.BackendMeta()
	}
	run := &database.AgenticScan{
		UUID:      agenticScanUUID,
		Mode:      mode,
		AgentName: agentName,
		Protocol:  protocol,
		Model:     model,
		Status:    "running",
		StartedAt: time.Now(),
	}
	// Detached on purpose: an agent run outlives the HTTP request that starts it,
	// so its DB lifecycle is not tied to any request context.
	if err := h.repo.CreateAgenticScan(context.Background(), run); err != nil {
		if errors.Is(err, database.ErrScanProjectMismatch) {
			return err
		}
		zap.L().Debug("Failed to persist agent run", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(err))
	}
	return nil
}

// persistAgenticScanCompleted updates the DB record for a completed agent run.
func (h *Handlers) persistAgenticScanCompleted(agenticScanUUID string, status *AgenticScanStatusResponse) {
	if h.repo == nil {
		return
	}
	run := &database.AgenticScan{
		UUID:         agenticScanUUID,
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
	if err := h.repo.UpdateAgenticScan(context.Background(), run); err != nil {
		zap.L().Warn("failed to persist agentic scan status update", zap.Error(err))
	}
}

// effectiveAgentName returns the agent identifier recorded on AgenticScan
// rows for this run. With the subprocess backend system removed, every run
// is olium-backed, so we ignore the request-supplied agent name and always
// return "olium" unless the caller wants something stored verbatim for
// downstream bookkeeping.
func (h *Handlers) effectiveAgentName(agentName string) string {
	if agentName != "" {
		return agentName
	}
	return "olium"
}

// respondScanPinError translates database scan-pin errors into HTTP responses:
// ErrScanProjectMismatch becomes 409 Conflict (clean fail-fast for cross-node
// sync). Anything else is a 500.
func respondScanPinError(c fiber.Ctx, err error) error {
	if errors.Is(err, database.ErrScanProjectMismatch) {
		return c.Status(fiber.StatusConflict).JSON(ErrorResponse{Error: err.Error()})
	}
	return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{Error: err.Error()})
}

// registerRunningAgenticScan creates the in-memory + DB tracking for a new
// agent run. When pinUUID is non-empty it becomes the run's UUID — used to
// attach a remote-created scan record across nodes; otherwise a fresh UUID is
// minted. Returns ErrScanProjectMismatch when pinUUID belongs to a different
// project, which the caller should surface as HTTP 409.
func (h *Handlers) registerRunningAgenticScan(mode, agentName, pinUUID string) (string, error) {
	agenticScanUUID := pinUUID
	if agenticScanUUID == "" {
		agenticScanUUID = uuid.New().String()
	}
	effectiveAgentName := h.effectiveAgentName(agentName)

	if err := h.persistAgenticScan(agenticScanUUID, mode, effectiveAgentName); err != nil {
		return "", err
	}

	h.agentMu.Lock()
	h.agenticScanStatus[agenticScanUUID] = &AgenticScanStatusResponse{
		AgenticScanUUID: agenticScanUUID,
		Mode:            mode,
		Status:          "running",
		AgentName:       effectiveAgentName,
	}
	h.agentMu.Unlock()

	return agenticScanUUID, nil
}

// enrichAgenticScanRecord loads the agentic_scans row for agenticScanUUID, applies mutate,
// and writes it back. This is used for request-time fields that the
// lightweight persistAgenticScan helpers don't cover.
func (h *Handlers) enrichAgenticScanRecord(agenticScanUUID string, mutate func(run *database.AgenticScan)) {
	if h.repo == nil || mutate == nil {
		return
	}
	ctx := context.Background()
	run, err := h.repo.GetAgenticScan(ctx, agenticScanUUID)
	if err != nil || run == nil {
		zap.L().Debug("enrichAgenticScanRecord: run not found", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(err))
		return
	}
	mutate(run)
	if err := h.repo.UpdateAgenticScan(ctx, run); err != nil {
		zap.L().Debug("enrichAgenticScanRecord: update failed", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(err))
	}
}

// uploadAgenticResults bundles the session directory and uploads it to cloud storage.
func (h *Handlers) uploadAgenticResults(projectUUID, agenticScanUUID, sessionDir string) {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		zap.L().Warn("upload_results requested but storage is not enabled")
		return
	}

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		zap.L().Warn("Failed to create storage client", zap.Error(err))
		return
	}

	key := storage.AgenticScanResultKey(agenticScanUUID)
	storageURL, err := sc.BundleAndUploadResults(context.Background(), projectUUID, key, sessionDir)
	if err != nil {
		zap.L().Warn("Failed to upload agentic results", zap.Error(err))
		return
	}

	if h.repo != nil {
		if err := h.repo.UpdateAgenticScanStorageURL(context.Background(), agenticScanUUID, storageURL); err != nil {
			zap.L().Warn("failed to persist agentic scan storage URL", zap.String("uuid", agenticScanUUID), zap.Error(err))
		}
	}

	// Surface the storage URL on the in-memory status entry so callers polling
	// /api/agent/status/:id see it without waiting for the entry to age out and
	// fall back to the DB row.
	h.agentMu.Lock()
	if status, ok := h.agenticScanStatus[agenticScanUUID]; ok && status != nil {
		status.StorageURL = storageURL
	}
	h.agentMu.Unlock()

	zap.L().Info("Uploaded agentic scan results", zap.String("agentic_scan_uuid", agenticScanUUID), zap.String("storage_url", storageURL))
}

// uploadNativeScanResults bundles the per-scan runtime.log and any per-format
// output files (jsonl/html) the runner emitted into a tar.gz under
// <projectUUID>/native-scans/<scanUUID>/results.tar.gz. Mirrors the CLI
// helper at pkg/cli/storage_upload.go. Missing files are skipped silently by
// BundleAndUploadFiles.
func (h *Handlers) uploadNativeScanResults(projectUUID, scanID string) {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		zap.L().Warn("upload_results requested but storage is not enabled")
		return
	}

	scanDir := filepath.Join(
		h.settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(),
		scanID,
	)
	files := map[string]string{
		config.RuntimeLogFilename: filepath.Join(scanDir, config.RuntimeLogFilename),
	}
	outputBase := filepath.Join(scanDir, "output")
	for _, format := range nativeScanUploadFormats {
		path := types.FormatOutputPath(outputBase, format)
		files[filepath.Base(path)] = path
	}

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		zap.L().Warn("Failed to create storage client", zap.Error(err))
		return
	}

	key := storage.NativeScanResultKey(scanID)
	storageURL, err := sc.BundleAndUploadFiles(context.Background(), projectUUID, key, files)
	if err != nil {
		zap.L().Warn("Failed to upload native scan results", zap.Error(err))
		return
	}

	if h.repo != nil {
		if err := h.repo.UpdateScanStorageURL(context.Background(), scanID, storageURL); err != nil {
			zap.L().Warn("failed to persist native scan storage URL", zap.String("scan", scanID), zap.Error(err))
		}
	}

	zap.L().Info("Uploaded native scan results", zap.String("scan_uuid", scanID), zap.String("storage_url", storageURL))
}

// startAgenticScan is the entry point for query mode.
// It acquires a light agent slot, creates status tracking, and runs the agent.
// projectUUID + uploadResults trigger an optional cloud-storage bundle upload
// after the run completes successfully.
//
// engine + byokCleanup are the per-request olium engine and its cleanup
// (see Handlers.engineForRequest). When BYOK isn't supplied, engine is
// the server-wide cached engine and byokCleanup is a no-op.
func (h *Handlers) startAgenticScan(c fiber.Ctx, mode string, stream bool, opts agent.Options, timeout time.Duration, projectUUID string, uploadResults bool, engine *agent.Engine, byokCleanup func()) error {
	if !h.acquireAgentSlot(c, h.agentLightSem) {
		if byokCleanup != nil {
			byokCleanup()
		}
		return nil // 429 already sent
	}

	opts.AgentName = h.effectiveAgentName(opts.AgentName)
	agenticScanUUID, err := h.registerRunningAgenticScan(mode, opts.AgentName, opts.ScanUUID)
	if err != nil {
		if byokCleanup != nil {
			byokCleanup()
		}
		return respondScanPinError(c, err)
	}

	if stream {
		return h.handleAgentSSE(c, agenticScanUUID, opts, timeout, projectUUID, uploadResults, engine, byokCleanup)
	}

	go h.runBackgroundAgentWithOpts(agenticScanUUID, opts, timeout, projectUUID, uploadResults, engine, byokCleanup)

	return c.Status(fiber.StatusAccepted).JSON(AgenticScanResponse{
		AgenticScanUUID: agenticScanUUID,
		Status:          "running",
		Message:         mode + " run started",
	})
}

// handleAgentSSE runs the agent synchronously while streaming SSE events to the client.
func (h *Handlers) handleAgentSSE(c fiber.Ctx, agenticScanUUID string, opts agent.Options, timeout time.Duration, projectUUID string, uploadResults bool, engine *agent.Engine, byokCleanup func()) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	return c.SendStreamWriter(func(w *bufio.Writer) {
		defer h.releaseAgentSlot(h.agentLightSem)
		if byokCleanup != nil {
			defer byokCleanup()
		}

		ctx, cancel := context.WithTimeout(h.runContext(), timeout)
		defer cancel()
		h.registerRunCancel(agenticScanUUID, cancel)
		defer h.unregisterRunCancel(agenticScanUUID)

		// Pre-create the session dir under the API run UUID (matching the
		// async path) so SSE-mode query runs also leave a runtime.log on
		// disk for /sessions/:id/logs.
		sessionDir, sessionErr := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), agenticScanUUID)
		if sessionErr != nil {
			zap.L().Warn("Failed to pre-create session dir",
				zap.String("agentic_scan_uuid", agenticScanUUID),
				zap.Error(sessionErr))
		} else {
			opts.SessionDir = sessionDir
			h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
				run.SessionDir = sessionDir
			})
		}

		// Log file FIRST in the MultiWriter so runtime.log is never gated on the
		// SSE client; drainAgentPipeToSSE keeps reading pr after a disconnect so
		// pw.Write never blocks and the agent keeps logging to disk.
		pr, pw := io.Pipe()
		var streamWriter io.Writer = pw
		if logFile := h.openSessionRuntimeLog(sessionDir, agenticScanUUID); logFile != nil {
			streamWriter = io.MultiWriter(logFile, pw)
			defer func() { _ = logFile.Close() }()
		}
		opts.StreamWriter = streamWriter

		// All SSE events for this run go through one sink (see sseSink).
		sink := newSSESink(w)

		type runResult struct {
			result *agent.Result
			err    error
		}
		done := make(chan runResult, 1)
		go func() {
			result, err := engine.Run(ctx, opts)
			_ = pw.Close()
			done <- runResult{result: result, err: err}
		}()

		// On client disconnect, keep draining to EOF so the finalization below
		// (DB status → completed/failed) always runs.
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

			h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
				run.Status = runStatus
				run.ErrorMessage = res.err.Error()
				run.CompletedAt = now
				run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
			})

			webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)

			if clientConnected {
				_ = sink.send(sseEvent{Type: "error", Error: res.err.Error()})
			}
			zap.L().Error("Agent run failed (streaming)",
				zap.String("agentic_scan_uuid", agenticScanUUID),
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
			h.persistAgenticScanCompleted(agenticScanUUID, status)
		}

		if uploadResults && sessionDir != "" {
			h.uploadAgenticResults(projectUUID, agenticScanUUID, sessionDir)
		}

		webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)

		if clientConnected {
			_ = sink.send(sseEvent{Type: "done", Result: res.result})
		}
		zap.L().Info("Agent run completed (streaming)",
			zap.String("agentic_scan_uuid", agenticScanUUID),
			zap.String("agent", res.result.AgentName),
			zap.Int("findings", len(res.result.Findings)),
			zap.Int("saved", res.result.SavedCount))
	})
}

// runBackgroundAgentWithOpts executes an agent run in a goroutine and updates status.
func (h *Handlers) runBackgroundAgentWithOpts(agenticScanUUID string, opts agent.Options, timeout time.Duration, projectUUID string, uploadResults bool, engine *agent.Engine, byokCleanup func()) {
	defer h.releaseAgentSlot(h.agentLightSem)
	if byokCleanup != nil {
		defer byokCleanup()
	}

	ctx, cancel := context.WithTimeout(h.runContext(), timeout)
	defer cancel()
	h.registerRunCancel(agenticScanUUID, cancel)
	defer h.unregisterRunCancel(agenticScanUUID)

	sessionDir, sessionErr := agent.EnsureSessionDir(h.settings.Agent.EffectiveSessionsDir(), agenticScanUUID)
	if sessionErr != nil {
		zap.L().Warn("Failed to pre-create session dir", zap.String("agentic_scan_uuid", agenticScanUUID), zap.Error(sessionErr))
	} else {
		opts.SessionDir = sessionDir
		h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
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

	result, err := engine.Run(ctx, opts)

	now := time.Now()

	// Hold agentMu only for the in-memory mutation; release it before any
	// downstream work that might re-acquire it (DB persist, GCS upload).
	// uploadAgenticResults takes agentMu to surface storage_url, so a held
	// mutex would deadlock here (Go mutexes are non-reentrant).
	h.agentMu.Lock()
	status := h.agenticScanStatus[agenticScanUUID]
	if status == nil {
		h.agentMu.Unlock()
		return
	}
	if err != nil {
		status.Status = "failed"
		status.Error = err.Error()
		status.CompletedAt = &now
	} else {
		status.Status = "completed"
		status.AgentName = result.AgentName
		status.TemplateID = result.TemplateID
		status.FindingCount = len(result.Findings)
		status.RecordCount = len(result.HTTPRecords)
		status.SavedCount = result.SavedCount
		status.CompletedAt = &now
		status.Result = result
	}
	statusSnapshot := *status
	h.agentMu.Unlock()

	if err != nil {
		h.enrichAgenticScanRecord(agenticScanUUID, func(run *database.AgenticScan) {
			run.Status = "failed"
			run.ErrorMessage = err.Error()
			run.CompletedAt = now
			run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
		})
		webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)
		zap.L().Error("Agent run failed",
			zap.String("agentic_scan_uuid", agenticScanUUID),
			zap.Error(err))
		return
	}

	h.persistAgenticScanCompleted(agenticScanUUID, &statusSnapshot)

	if uploadResults && sessionDir != "" {
		h.uploadAgenticResults(projectUUID, agenticScanUUID, sessionDir)
	}

	webhook.FireAgenticScan(h.settings, h.repo, agenticScanUUID)

	zap.L().Info("Agent run completed",
		zap.String("agentic_scan_uuid", agenticScanUUID),
		zap.String("agent", result.AgentName),
		zap.Int("findings", len(result.Findings)),
		zap.Int("saved", result.SavedCount))
}
