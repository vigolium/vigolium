package server

import (
	"context"
	"sync"
	"sync/atomic"
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

// maxConcurrentNativeScans bounds how many url/request background scans can run
// at once, so a burst of POST /api/scan-url|scan-request calls can't spawn an
// unbounded number of detached scan goroutines. Excess calls are rejected with
// 503 rather than queued.
const maxConcurrentNativeScans = 8

// countCache caches expensive COUNT(*) query results with a TTL.
type countCache struct {
	mu         sync.Mutex
	records    int64
	findings   int64
	updatedAt  time.Time
	ttl        time.Duration
	refreshing bool // a bounded refresh is already in flight
}

func newCountCache(ttl time.Duration) *countCache {
	return &countCache{ttl: ttl}
}

// Get returns cached counts using a stale-while-revalidate policy: a fresh value
// is served directly, and a stale value is served immediately while a single
// bounded refresh runs in the background. The mutex is never held across the
// COUNT(*) queries, so a slow count can't block every concurrent /server-info
// caller (the previous behavior). The very first call (no cached value yet)
// refreshes synchronously so it returns real counts.
func (cc *countCache) Get(db *database.DB) (records, findings int64) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	stale := cc.updatedAt.IsZero() || time.Since(cc.updatedAt) >= cc.ttl
	if stale && !cc.refreshing {
		cc.refreshing = true
		if cc.updatedAt.IsZero() {
			// No value yet: block this first caller on a bounded refresh so it
			// returns real counts rather than zeros.
			cc.mu.Unlock()
			cc.refresh(db)
			cc.mu.Lock()
		} else {
			// Serve the stale value now; refresh off the request path.
			go cc.refresh(db)
		}
	}
	// Fresh, stale-while-revalidating, or refresh-in-flight: serve what we have.
	return cc.records, cc.findings
}

// refresh recomputes the counts under a bounded timeout and republishes them.
// Runs without holding cc.mu across the queries; clears the refreshing flag when
// done. A failed count keeps the previous value rather than zeroing it.
func (cc *countCache) refresh(db *database.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var rec, find int64
	recOK, findOK := false, false
	if c, err := db.NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx); err == nil {
		rec, recOK = int64(c), true
	}
	if c, err := db.NewSelect().Model((*database.Finding)(nil)).Count(ctx); err == nil {
		find, findOK = int64(c), true
	}

	cc.mu.Lock()
	if recOK {
		cc.records = rec
	}
	if findOK {
		cc.findings = find
	}
	cc.updatedAt = time.Now()
	cc.refreshing = false
	cc.mu.Unlock()
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

	// nativeScanSem bounds concurrent url/request background scans (POST
	// /api/scan-url and /api/scan-request), which otherwise spawned unbounded
	// detached goroutines. nativeScanWG lets Close wait for them; they derive their
	// context from runCtx, so runCancel stops them first.
	nativeScanSem chan struct{}
	nativeScanWG  sync.WaitGroup

	// shuttingDown is set at the start of Close so per-project queue workers stop
	// starting newly-dequeued scans (they discard them instead) once the server is
	// tearing down.
	shuttingDown atomic.Bool

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

	// Invariant: a repository is always derived from a db (NewRepository(db)), so a
	// non-nil db paired with a nil repo is a half-initialized state — e.g. the
	// connection opened but schema creation failed. Repo-backed handlers guard only
	// on h.db == nil before dereferencing h.repo, so admitting that state would turn
	// each into a nil-pointer panic (HTTP 500). NewHandlers is the single path every
	// server (CLI, tests, any future entry point) is constructed through, so this is
	// the universal place to normalize the pairing: drop to a consistent no-DB mode
	// by nil-ing db, and the h.db == nil guards then return a clean 503. The reverse
	// pairing (db == nil, repo != nil) is a legitimate, tested config (repo-backed
	// agent endpoints with no traffic DB) and is deliberately left untouched.
	if db != nil && repo == nil {
		zap.L().Warn("database handle present without a repository; disabling database-backed endpoints")
		db = nil
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
		nativeScanSem:      make(chan struct{}, maxConcurrentNativeScans),
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

// HandleHealth handles GET /health — a liveness probe. It reports that the
// process/event loop is alive and intentionally does NOT touch the database, so
// it never fails just because the DB is momentarily slow.
func (h *Handlers) HandleHealth(c fiber.Ctx) error {
	return c.JSON(HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().Format(time.RFC3339),
	})
}

// HandleReady handles GET /ready — a readiness probe distinct from liveness. It
// reports 200 only when the server can actually serve work: the database
// responds to a lightweight ping within a short timeout and the record writer is
// still accepting writes. Otherwise it returns 503 so an orchestrator routes
// traffic elsewhere without killing the (live) process.
func (h *Handlers) HandleReady(c fiber.Ctx) error {
	notReady := func(reason string) error {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status":    "not_ready",
			"reason":    reason,
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	if h.db != nil {
		ctx, cancel := context.WithTimeout(c.Context(), 2*time.Second)
		defer cancel()
		if err := h.db.SQLDB().PingContext(ctx); err != nil {
			return notReady("database unavailable: " + err.Error())
		}
	}

	return c.JSON(fiber.Map{
		"status":    "ready",
		"timestamp": time.Now().Format(time.RFC3339),
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

// effectiveConfigPath returns the config file the server actually loaded
// settings from, honoring the --config flag (ServerConfig.ConfigPath). Config
// mutations from the API must write here — and the watcher watches this same
// file — so a custom config isn't silently shadowed by writes to the default
// ~/.vigolium/vigolium-configs.yaml. Empty falls back to the default path.
func (h *Handlers) effectiveConfigPath() string {
	if h.config.ConfigPath != "" {
		return h.config.ConfigPath
	}
	return config.ConfigFilePath()
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
		// Read the Scope section under the config-watcher read lock so a live
		// hot-reload swapping settings.Scope in place can't tear the slice/map
		// headers we copy into the matcher here.
		h.scopeMatcher = config.NewScopeMatcher(h.readReloadableScope())
	}
	return h.scopeMatcher
}

// readReloadableScope returns a copy of the Scope section taken under the config
// watcher's reload read lock (a no-op when no watcher is active), coordinating
// with reload()'s in-place section swaps to avoid a torn read.
func (h *Handlers) readReloadableScope() config.ScopeConfig {
	if h.configWatcher != nil {
		h.configWatcher.RLock()
		defer h.configWatcher.RUnlock()
	}
	return h.settings.Scope
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
		// Server is tearing down: don't start a scan that was still queued. Release
		// its runner and mark the record terminal so it doesn't linger as "queued".
		if h.shuttingDown.Load() {
			qs.runner.Discard()
			if h.repo != nil {
				_ = h.repo.CompleteScan(context.Background(), qs.scanID, "cancelled: server shutdown")
			}
			continue
		}

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
	// Mark shutdown first so queue workers stop starting newly-dequeued scans
	// (they discard them) as soon as their channels are closed below.
	h.shuttingDown.Store(true)

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
	// Snapshot the runners of in-flight full (target) scans. These are launched as
	// detached goroutines and are NOT tracked by nativeScanWG, so without this they
	// would neither be cancelled nor awaited on shutdown.
	var fullScanRunners []*runner.Runner
	for _, st := range h.scanStates {
		if st.running && st.runner != nil {
			fullScanRunners = append(fullScanRunners, st.runner)
		}
	}
	h.scanMu.Unlock()

	// Cancel + release each in-flight full scan concurrently (Runner.Close cancels
	// its context and waits, bounded by ShutdownTimeout; it's idempotent, so a
	// concurrent runBackgroundScan.Close is harmless).
	var fullScanWG sync.WaitGroup
	for _, r := range fullScanRunners {
		fullScanWG.Add(1)
		go func(r *runner.Runner) {
			defer fullScanWG.Done()
			r.Close()
		}(r)
	}

	// Wait for all background scans to unwind. runCancel above cancelled runCtx
	// (url/request scans) and the runners above were cancelled; bound the wait so a
	// wedged scan can't hang shutdown.
	done := make(chan struct{})
	go func() {
		h.nativeScanWG.Wait()
		fullScanWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		zap.L().Warn("Shutdown: scans did not drain within 30s; proceeding")
	}
	// Agent engine is in-process (olium); no resources to release.
}

// HandleMetrics handles GET /metrics — serves Prometheus metrics.
func (h *Handlers) HandleMetrics(c fiber.Ctx) error {
	if h.metricsHandler != nil {
		return h.metricsHandler(c)
	}
	return c.Status(fiber.StatusNotFound).SendString("metrics not configured")
}
