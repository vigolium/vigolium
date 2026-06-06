package server

import (
	"context"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/piolium"
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

	// Shared cross-request cache refresh — not owned by any single request, so it
	// uses a background context rather than one caller's request context.
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
	running bool
	runner  *runner.Runner
	scanID  string
}

// queuedScan represents a scan waiting in a per-project queue.
type queuedScan struct {
	scanID        string
	runner        *runner.Runner
	projectUUID   string
	enqueued      time.Time
	uploadResults bool
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
	services      *services.Services // shared with httpRequester; may be nil
	configWatcher *config.ConfigWatcher
	startTime     time.Time

	// Domain handler groups extracted from this struct. Composed here and
	// wired in NewHandlers; the routes call e.g. h.findings.HandleListFindings.
	findings *findingsHandlers

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
	agentHeavySem     chan struct{} // counting semaphore for heavy runs (autopilot/swarm)
	agentLightSem     chan struct{} // counting semaphore for light runs (query/chat)
	agenticScanStatus map[string]*AgenticScanStatusResponse

	// projectHeavyMu guards projectHeavyActive. The map tallies currently-
	// running heavy agent runs per project so a single tenant can be
	// capped (AgentHeavyPerProject) below the cluster-wide limit
	// (AgentHeavyMax). Entries are deleted when the count drops to 0
	// so an idle project doesn't keep an empty map row.
	projectHeavyMu     sync.Mutex
	projectHeavyActive map[string]int

	// Background cleanup for completed agent run statuses
	agentCleanupStop chan struct{}

	// runCtx is the server-lifecycle context for background agent runs.
	// Autopilot/swarm/audit/query handlers derive their per-run timeout
	// contexts from it (instead of a detached context.Background()) so a server
	// shutdown — which cancels runCtx via Close() — stops in-flight scans and
	// lets their streaming connections go idle, rather than leaving them to run
	// against a context that nothing can cancel.
	runCtx    context.Context
	runCancel context.CancelFunc

	// runCancels holds the per-run cancel func for each in-flight agent run,
	// keyed by agenticScanUUID, so POST /api/agent/scans/:uuid/cancel can abort
	// one specific run (vs runCancel, which stops every run on shutdown). Entries
	// are registered when a run acquires its context and removed when it returns.
	runCancelMu sync.Mutex
	runCancels  map[string]context.CancelFunc

	// Cached COUNT query results for server-info endpoint
	counts *countCache

	// Cached piolium availability — `pi` install state doesn't change
	// mid-process, so the per-request audit-harness picker reuses this
	// instead of re-probing PATH and reading ~/.pi/agent/settings.json.
	pioliumAvailableOnce sync.Once
	pioliumAvailable     bool
}

// pioliumAvailableCached wraps piolium.IsAvailable with a sync.Once so the
// PATH lookup + settings.json read happens at most once per server process.
func (h *Handlers) pioliumAvailableCached() bool {
	h.pioliumAvailableOnce.Do(func() {
		h.pioliumAvailable = piolium.IsAvailable()
	})
	return h.pioliumAvailable
}

// NewHandlers creates a new Handlers instance.
// Starts a background goroutine to clean up old agent run records from the database.
func NewHandlers(q queue.Queue, db *database.DB, repo *database.Repository, rw *database.RecordWriter, cfg ServerConfig, settings *config.Settings, httpRequester *http.Requester, svc *services.Services) *Handlers {
	heavyMax := cfg.AgentHeavyMax
	if heavyMax <= 0 {
		heavyMax = 5
	}
	lightMax := cfg.AgentLightMax
	if lightMax <= 0 {
		lightMax = 10
	}

	runCtx, runCancel := context.WithCancel(context.Background())

	h := &Handlers{
		queue:              q,
		db:                 db,
		repo:               repo,
		recordWriter:       rw,
		config:             cfg,
		settings:           settings,
		httpRequester:      httpRequester,
		services:           svc,
		startTime:          time.Now(),
		scanStates:         make(map[string]*scanState),
		scanQueues:         make(map[string]chan *queuedScan),
		agentHeavySem:      make(chan struct{}, heavyMax),
		agentLightSem:      make(chan struct{}, lightMax),
		agenticScanStatus:  make(map[string]*AgenticScanStatusResponse),
		projectHeavyActive: make(map[string]int),
		agentCleanupStop:   make(chan struct{}),
		counts:             newCountCache(10 * time.Second),
		runCtx:             runCtx,
		runCancel:          runCancel,
		runCancels:         make(map[string]context.CancelFunc),
	}
	h.findings = &findingsHandlers{db: db, repo: repo}
	if !cfg.NoAgent {
		h.agentEngine = agent.NewEngine(settings, repo)
		go h.agentDBCleanupLoop()
	}
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
			for id, status := range h.agenticScanStatus {
				if status.CompletedAt != nil && now.Sub(*status.CompletedAt) > time.Hour {
					delete(h.agenticScanStatus, id)
				}
			}
			h.agentMu.Unlock()

			// Prune DB (completed/failed runs older than 24h)
			if h.repo != nil {
				if n, err := h.repo.DeleteOldAgenticScans(context.Background(), ttl); err == nil && n > 0 {
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
		Name:        "vigolium",
		Version:     h.config.Version,
		Author:      h.config.Author,
		Docs:        "https://docs.vigolium.com",
		LicenseSPDX: "AGPL-3.0-or-later",
		Source:      "https://github.com/vigolium/vigolium",
		BuildTime:   h.config.BuildTime,
		Commit:      commit,
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
		Docs:        "https://docs.vigolium.com",
		BuildTime:   h.config.BuildTime,
		Commit:      commit,
		Uptime:      time.Since(h.startTime).Round(time.Second).String(),
		ServiceAddr: h.config.ServiceAddr,
		ProxyAddr:   h.config.IngestProxyAddr,
		QueueDepth:  metrics.Depth,
		License:     h.config.License,
		LicenseSPDX: "AGPL-3.0-or-later",
		Source:      "https://github.com/vigolium/vigolium",
		DemoOnly:    h.config.DemoOnly,
		ViewOnly:    h.config.ViewOnly,
	}

	if h.db != nil {
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

		h.runBackgroundScan(qs.scanID, qs.runner, qs.projectUUID, qs.uploadResults)
	}
}

// Close releases handler resources including the agent engine pool.
// runContext returns the server-lifecycle context that background agent runs
// derive their per-run timeouts from. It falls back to context.Background()
// when the handler was constructed directly (e.g. in tests) without NewHandlers
// wiring runCtx, so callers never pass a nil parent to context.WithTimeout.
func (h *Handlers) runContext() context.Context {
	if h.runCtx != nil {
		return h.runCtx
	}
	return context.Background()
}

// registerRunCancel records a run's cancel func so it can be aborted by UUID via
// the cancel endpoint. Pair every call with a deferred unregisterRunCancel.
func (h *Handlers) registerRunCancel(uuid string, cancel context.CancelFunc) {
	if uuid == "" || cancel == nil {
		return
	}
	h.runCancelMu.Lock()
	if h.runCancels == nil {
		h.runCancels = make(map[string]context.CancelFunc)
	}
	h.runCancels[uuid] = cancel
	h.runCancelMu.Unlock()
}

// unregisterRunCancel drops a run's cancel func once it has finished.
func (h *Handlers) unregisterRunCancel(uuid string) {
	if uuid == "" {
		return
	}
	h.runCancelMu.Lock()
	delete(h.runCancels, uuid)
	h.runCancelMu.Unlock()
}

// cancelRun aborts an in-flight run by UUID and returns true if one was found.
// It also flips the in-memory status to "cancelling" for immediate feedback;
// the run's own finalization writes the terminal "cancelled" as it unwinds.
func (h *Handlers) cancelRun(uuid string) bool {
	h.runCancelMu.Lock()
	cancel := h.runCancels[uuid]
	h.runCancelMu.Unlock()
	if cancel == nil {
		return false
	}
	h.agentMu.Lock()
	if st := h.agenticScanStatus[uuid]; st != nil && !isTerminalAgentStatus(st.Status) {
		st.Status = "cancelling"
	}
	h.agentMu.Unlock()
	cancel()
	return true
}

func (h *Handlers) Close() {
	// Cancel in-flight agent runs first so their streaming connections drain
	// and go idle before the HTTP server's graceful shutdown waits on them.
	if h.runCancel != nil {
		h.runCancel()
	}
	close(h.agentCleanupStop)
	h.scanMu.Lock()
	for _, ch := range h.scanQueues {
		close(ch)
	}
	h.scanQueues = make(map[string]chan *queuedScan)
	h.scanMu.Unlock()
	// Agent engine is in-process (olium); no resources to release.
}

// HandleMetrics handles GET /metrics — serves Prometheus metrics.
func (h *Handlers) HandleMetrics(c fiber.Ctx) error {
	if h.metricsHandler != nil {
		return h.metricsHandler(c)
	}
	return c.Status(fiber.StatusNotFound).SendString("metrics not configured")
}
