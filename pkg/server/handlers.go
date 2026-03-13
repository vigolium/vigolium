package server

import (
	"context"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/queue"
	"go.uber.org/zap"
)

// countCache caches expensive COUNT(*) query results with a TTL.
type countCache struct {
	mu        sync.Mutex
	records   int64
	findings  int64
	updatedAt time.Time
	ttl       time.Duration
}

func newCountCache(ttl time.Duration) *countCache {
	return &countCache{ttl: ttl}
}

// Get returns cached counts, refreshing from the database if expired.
func (cc *countCache) Get(db *database.DB) (records, findings int64) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if time.Since(cc.updatedAt) < cc.ttl {
		return cc.records, cc.findings
	}

	ctx := context.Background()
	if recordCount, err := db.NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx); err == nil {
		cc.records = int64(recordCount)
	}
	if findingCount, err := db.NewSelect().Model((*database.Finding)(nil)).Count(ctx); err == nil {
		cc.findings = int64(findingCount)
	}
	cc.updatedAt = time.Now()

	return cc.records, cc.findings
}

// scanState tracks a running scan for a specific project.
type scanState struct {
	running  bool
	runner   *runner.Runner
	scanID   string
}

// queuedScan represents a scan waiting in a per-project queue.
type queuedScan struct {
	scanID      string
	runner      *runner.Runner
	projectUUID string
	enqueued    time.Time
}

// Handlers holds the HTTP handlers and their dependencies.
type Handlers struct {
	queue         queue.Queue
	db            *database.DB
	repo          *database.Repository
	recordWriter  *database.RecordWriter
	config        ServerConfig
	settings      *config.Settings
	httpRequester *http.Requester
	configWatcher *config.ConfigWatcher
	startTime     time.Time

	// Per-project scan state for API-triggered scans
	scanMu     sync.Mutex
	scanStates map[string]*scanState // keyed by projectUUID

	// Scan queue: when ScanQueueCapacity > 0, scans are queued instead of rejected
	scanQueues map[string]chan *queuedScan

	// Cached scope matcher (lazy-initialized, invalidated on config change)
	scopeMatcherMu sync.RWMutex
	scopeMatcher   *config.ScopeMatcher

	// Prometheus metrics handler
	metricsHandler fiber.Handler

	// Long-lived agent engine (shared across requests for warm session reuse)
	agentEngine *agent.Engine

	// Agent run state for API-triggered agent runs
	agentMu           sync.Mutex
	agentHeavyRunning bool // pipeline, swarm (only 1 at a time)
	agentLightRunning bool // query, autopilot, chat completions (only 1 at a time)
	agentRunStatus    map[string]*AgentRunStatusResponse

	// Background cleanup for completed agent run statuses
	agentCleanupStop chan struct{}

	// Cached COUNT query results for server-info endpoint
	counts *countCache
}

// NewHandlers creates a new Handlers instance.
// Starts a background goroutine to clean up old agent run records from the database.
func NewHandlers(q queue.Queue, db *database.DB, repo *database.Repository, rw *database.RecordWriter, cfg ServerConfig, settings *config.Settings, httpRequester *http.Requester) *Handlers {
	h := &Handlers{
		queue:            q,
		db:               db,
		repo:             repo,
		recordWriter:     rw,
		config:           cfg,
		settings:         settings,
		httpRequester:    httpRequester,
		startTime:        time.Now(),
		scanStates:       make(map[string]*scanState),
		scanQueues:       make(map[string]chan *queuedScan),
		agentEngine:      agent.NewEngine(settings, repo),
		agentRunStatus:   make(map[string]*AgentRunStatusResponse),
		agentCleanupStop: make(chan struct{}),
		counts:           newCountCache(10 * time.Second),
	}
	go h.agentDBCleanupLoop()
	return h
}

// agentDBCleanupLoop periodically removes old completed/failed agent runs from the
// database and prunes the in-memory map for completed runs.
func (h *Handlers) agentDBCleanupLoop() {
	const ttl = 24 * time.Hour
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-h.agentCleanupStop:
			return
		case <-ticker.C:
			// Prune in-memory map (completed runs older than 1h)
			now := time.Now()
			h.agentMu.Lock()
			for id, status := range h.agentRunStatus {
				if status.CompletedAt != nil && now.Sub(*status.CompletedAt) > time.Hour {
					delete(h.agentRunStatus, id)
				}
			}
			h.agentMu.Unlock()

			// Prune DB (completed/failed runs older than 24h)
			if h.repo != nil {
				if n, err := h.repo.DeleteOldAgentRuns(context.Background(), ttl); err == nil && n > 0 {
					zap.L().Debug("Cleaned up old agent runs", zap.Int("count", n))
				}
			}

			// Clean up old agent session directories
			if h.settings != nil {
				sessDir := h.settings.Agent.EffectiveSessionsDir()
				if n, err := agent.CleanupSessionDirs(sessDir, 48*time.Hour); err == nil && n > 0 {
					zap.L().Debug("Cleaned up old session directories", zap.Int("count", n))
				}
			}
		}
	}
}

// persistAgentRun creates an agent_runs DB record for a new agent run.
func (h *Handlers) persistAgentRun(runID, mode, agentName string) {
	if h.repo == nil {
		return
	}
	run := &database.AgentRun{
		UUID:      runID,
		Mode:      mode,
		AgentName: agentName,
		Status:    "running",
		StartedAt: time.Now(),
	}
	if err := h.repo.CreateAgentRun(context.Background(), run); err != nil {
		zap.L().Debug("Failed to persist agent run", zap.String("run_id", runID), zap.Error(err))
	}
}

// persistAgentRunCompleted updates the DB record for a completed agent run.
func (h *Handlers) persistAgentRunCompleted(runID string, status *AgentRunStatusResponse) {
	if h.repo == nil {
		return
	}
	run := &database.AgentRun{
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
	_ = h.repo.UpdateAgentRun(context.Background(), run)
}

// HandleHealth handles GET /health.
func (h *Handlers) HandleHealth(c fiber.Ctx) error {
	return c.JSON(HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().Format(time.RFC3339),
	})
}

// HandleAppInfo handles GET /api/info — returns basic app info.
func (h *Handlers) HandleAppInfo(c fiber.Ctx) error {
	commit := h.config.Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}
	return c.JSON(AppInfoResponse{
		Name:      "vigolium",
		Version:   h.config.Version,
		Author:    h.config.Author,
		Docs:      "https://docs.vigolium.io",
		BuildTime: h.config.BuildTime,
		Commit:    commit,
	})
}

// HandleServerInfo handles GET /server-info.
func (h *Handlers) HandleServerInfo(c fiber.Ctx) error {
	metrics := h.queue.Metrics()
	if metrics == nil {
		metrics = &queue.QueueMetrics{}
	}

	commit := h.config.Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}

	resp := ServerInfoResponse{
		Name:        "vigolium",
		Version:     h.config.Version,
		Author:      h.config.Author,
		Docs:        "https://docs.vigolium.io",
		BuildTime:   h.config.BuildTime,
		Commit:      commit,
		Uptime:      time.Since(h.startTime).Round(time.Second).String(),
		ServiceAddr: h.config.ServiceAddr,
		ProxyAddr:   h.config.IngestProxyAddr,
		QueueDepth:  metrics.Depth,
	}

	if h.db != nil {
		resp.DBDriver = h.db.Driver()
		resp.TotalRecords, resp.TotalFindings = h.counts.Get(h.db)
	}

	return c.JSON(resp)
}

// getScopeMatcher returns the cached ScopeMatcher, creating it lazily on first call.
func (h *Handlers) getScopeMatcher() *config.ScopeMatcher {
	h.scopeMatcherMu.RLock()
	m := h.scopeMatcher
	h.scopeMatcherMu.RUnlock()
	if m != nil {
		return m
	}

	// Double-check under write lock
	h.scopeMatcherMu.Lock()
	defer h.scopeMatcherMu.Unlock()
	if h.scopeMatcher != nil {
		return h.scopeMatcher
	}
	if h.settings != nil {
		h.scopeMatcher = config.NewScopeMatcher(h.settings.Scope)
	}
	return h.scopeMatcher
}

// resetScopeMatcher invalidates the cached ScopeMatcher so it is rebuilt on next use.
func (h *Handlers) resetScopeMatcher() {
	h.scopeMatcherMu.Lock()
	h.scopeMatcher = nil
	h.scopeMatcherMu.Unlock()
}

// IsScanRunning reports whether any scan is currently running (across all projects).
// Implements metrics.ScanStateProvider.
func (h *Handlers) IsScanRunning() bool {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	for _, st := range h.scanStates {
		if st.running {
			return true
		}
	}
	return false
}

// getProjectScanState returns the scan state for a project, creating it if needed.
// Must be called with scanMu held.
func (h *Handlers) getProjectScanState(projectUUID string) *scanState {
	st, ok := h.scanStates[projectUUID]
	if !ok {
		st = &scanState{}
		h.scanStates[projectUUID] = st
	}
	return st
}

// scanQueueWorker processes queued scans for a project sequentially.
func (h *Handlers) scanQueueWorker(projectUUID string, ch chan *queuedScan) {
	for qs := range ch {
		h.scanMu.Lock()
		st := h.getProjectScanState(qs.projectUUID)
		st.running = true
		st.runner = qs.runner
		st.scanID = qs.scanID
		h.scanMu.Unlock()

		h.runBackgroundScan(qs.scanID, qs.runner, qs.projectUUID)
	}
}

// HandleScanQueue handles GET /api/scans/queue — returns scan queue status.
func (h *Handlers) HandleScanQueue(c fiber.Ctx) error {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()

	type queueInfo struct {
		ProjectUUID string `json:"project_uuid"`
		Depth       int    `json:"depth"`
	}
	var queues []queueInfo
	for project, ch := range h.scanQueues {
		queues = append(queues, queueInfo{
			ProjectUUID: project,
			Depth:       len(ch),
		})
	}
	return c.JSON(fiber.Map{
		"queues": queues,
	})
}

// Close releases handler resources including the agent engine pool.
func (h *Handlers) Close() {
	close(h.agentCleanupStop)
	h.scanMu.Lock()
	for _, ch := range h.scanQueues {
		close(ch)
	}
	h.scanQueues = make(map[string]chan *queuedScan)
	h.scanMu.Unlock()
	if h.agentEngine != nil {
		h.agentEngine.Close()
	}
}

// HandleMetrics handles GET /metrics — serves Prometheus metrics.
func (h *Handlers) HandleMetrics(c fiber.Ctx) error {
	if h.metricsHandler != nil {
		return h.metricsHandler(c)
	}
	return c.Status(fiber.StatusNotFound).SendString("metrics not configured")
}
