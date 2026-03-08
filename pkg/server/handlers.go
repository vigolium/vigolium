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

	// Scan state for API-triggered scans
	scanMu       sync.Mutex
	scanRunning  bool
	scanRunner   *runner.Runner
	activeScanID string

	// Cached scope matcher (lazy-initialized, invalidated on config change)
	scopeMatcherMu sync.RWMutex
	scopeMatcher   *config.ScopeMatcher

	// Prometheus metrics handler
	metricsHandler fiber.Handler

	// Long-lived agent engine (shared across requests for warm session reuse)
	agentEngine *agent.Engine

	// Agent run state for API-triggered agent runs
	agentMu        sync.Mutex
	agentRunning   bool
	agentRunStatus map[string]*AgentRunStatusResponse

	// Background cleanup for completed agent run statuses
	agentCleanupStop chan struct{}

	// Cached COUNT query results for server-info endpoint
	counts *countCache
}

// NewHandlers creates a new Handlers instance.
// Starts a background goroutine to clean up completed agent run statuses after 1 hour.
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
		agentEngine:      agent.NewEngine(settings, repo),
		agentRunStatus:   make(map[string]*AgentRunStatusResponse),
		agentCleanupStop: make(chan struct{}),
		counts:           newCountCache(10 * time.Second),
	}
	go h.agentStatusCleanupLoop()
	return h
}

// agentStatusCleanupLoop periodically removes completed/failed agent run statuses
// older than 1 hour to prevent unbounded map growth.
func (h *Handlers) agentStatusCleanupLoop() {
	const ttl = 1 * time.Hour
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-h.agentCleanupStop:
			return
		case <-ticker.C:
			now := time.Now()
			h.agentMu.Lock()
			for id, status := range h.agentRunStatus {
				if status.CompletedAt != nil && now.Sub(*status.CompletedAt) > ttl {
					delete(h.agentRunStatus, id)
				}
			}
			h.agentMu.Unlock()
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

// IsScanRunning reports whether a scan is currently running.
// Implements metrics.ScanStateProvider.
func (h *Handlers) IsScanRunning() bool {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	return h.scanRunning
}

// Close releases handler resources including the agent engine pool.
func (h *Handlers) Close() {
	close(h.agentCleanupStop)
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
