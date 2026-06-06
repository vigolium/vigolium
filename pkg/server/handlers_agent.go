package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
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

// writeSSE marshals an event to JSON and writes it as an SSE data line, then
// flushes. It is the low-level primitive: callers with a single writer
// goroutine (e.g. tailSessionLog, the sequential audit-combined driver mux)
// may use it directly, but any handler with multiple concurrent producers must
// go through an sseSink instead — see sseSink for why.
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

// sseSink serializes SSE writes to a single bufio.Writer. The streaming agent
// handlers have multiple producers feeding one HTTP response: the chunk-drain
// loop (drainAgentPipeToSSE) plus, in swarm, phase/progress callbacks fired
// from the runner's own goroutines. A bufio.Writer is not safe for concurrent
// use, so without serialization those producers race on the writer and can
// interleave a half-written event. Every handler that streams routes all its
// events through one sseSink. Safe for concurrent use.
type sseSink struct {
	mu sync.Mutex
	w  *bufio.Writer
}

// newSSESink wraps w in a concurrency-safe sink.
func newSSESink(w *bufio.Writer) *sseSink { return &sseSink{w: w} }

// send marshals and writes one event under the lock.
func (s *sseSink) send(evt sseEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeSSE(s.w, evt)
}

// drainAgentPipeToSSE forwards bytes from an agent's stream pipe to the SSE
// client as "chunk" events via sink. It is the resilient replacement for a
// naive read→writeSSE→close-and-return-on-error loop: on the first client
// write error (typically a disconnect, or a connection stalled long enough —
// e.g. during a long model "thinking" pause — for a proxy/LB to drop it) it
// stops writing to the client but KEEPS draining pr until the agent goroutine
// closes pw (EOF).
//
// This matters for two reasons:
//   - Callers tee the agent's StreamWriter as io.MultiWriter(logFile, pw) with
//     the log file FIRST, so as long as pr keeps being read, pw.Write never
//     blocks and the agent never stalls. Closing pr early (the old behavior)
//     instead made the agent's pw.Write fail, which short-circuited the
//     MultiWriter before the log file and froze runtime.log mid-run while the
//     agent kept running detached.
//   - Because the loop runs to EOF instead of returning early, the caller's
//     post-loop status finalization (DB row → "completed"/"failed") always
//     runs, even when the client vanished. The old early return left the row
//     stuck on "running" until the detached agent eventually timed out.
//
// onDisconnect, when non-nil, is invoked exactly once the moment the client is
// first detected gone (the first write error). Callers pass their run's
// context cancel here so a closed browser tab stops the run instead of letting
// it burn its full budget against nobody — while the loop still drains pr to
// EOF so pw.Write never blocks and finalization still runs.
//
// Never closes pr; the agent goroutine owns pw and closes it on completion.
// Returns true if the client stayed connected for the whole stream (no write
// error), so the caller can skip the trailing done/error event.
func drainAgentPipeToSSE(sink *sseSink, pr *io.PipeReader, onDisconnect func()) (clientConnected bool) {
	clientConnected = true
	buf := make([]byte, 4096)
	for {
		n, readErr := pr.Read(buf)
		if n > 0 && clientConnected {
			if writeErr := sink.send(sseEvent{Type: "chunk", Text: string(buf[:n])}); writeErr != nil {
				clientConnected = false
				if onDisconnect != nil {
					onDisconnect()
				}
			}
		}
		if readErr != nil {
			return clientConnected
		}
	}
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

// HandleAgentCancel handles POST /api/agent/scans/:uuid/cancel — aborts an
// in-flight agent run (autopilot/swarm/query/audit). It cancels the run's
// context, which unwinds the run and lets its finalization record the terminal
// "cancelled" status. Returns 404 when no run with that UUID is currently
// running in this process (already finished, never started, or unknown).
func (h *Handlers) HandleAgentCancel(c fiber.Ctx) error {
	agenticScanUUID := c.Params("uuid")
	if agenticScanUUID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{Error: "missing run uuid"})
	}
	if !h.cancelRun(agenticScanUUID) {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "run not found or already finished",
		})
	}
	return c.JSON(AgenticScanResponse{
		AgenticScanUUID: agenticScanUUID,
		Status:          "cancelling",
		Message:         "cancellation requested",
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
	if walkErr != nil && !errors.Is(walkErr, errArtifactCapHit) {
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

// terminalStatusForRunErr maps a streaming run's terminal error to its status
// label. A context cancellation — a client disconnect (the run is cancelled to
// stop burning budget for a vanished client) or a server shutdown — is recorded
// as "cancelled", not "failed", so an operator-initiated stop isn't surfaced as
// an error. Anything else stays "failed". Best-effort: it relies on the run
// propagating context.Canceled; an unwrapped error just falls back to "failed".
func terminalStatusForRunErr(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "failed"
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

	ctx, cancel := context.WithTimeout(h.runContext(), 10*time.Minute)
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
