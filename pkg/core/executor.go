package core

import (
	"context"
	"fmt"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// Tiered response buffer pools reduce GC pressure across response sizes.
// Three tiers cover the common response size distribution:
//   - small:  responses up to 1 MiB  (most responses)
//   - medium: responses up to 4 MiB  (large pages, API responses)
//   - large:  responses up to 16 MiB (very large payloads)
//
// Responses exceeding 16 MiB are allocated directly and not pooled.
const (
	poolTierSmall  = 1 << 20  // 1 MiB
	poolTierMedium = 4 << 20  // 4 MiB
	poolTierLarge  = 16 << 20 // 16 MiB
)

var (
	smallResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 32*1024) // 32 KiB initial cap
			return &b
		},
	}
	mediumResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 1<<20) // 1 MiB initial cap
			return &b
		},
	}
	largeResponsePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 4<<20) // 4 MiB initial cap
			return &b
		},
	}
)

func getResponseBuffer(n int) []byte {
	var pool *sync.Pool
	switch {
	case n <= poolTierSmall:
		pool = &smallResponsePool
	case n <= poolTierMedium:
		pool = &mediumResponsePool
	case n <= poolTierLarge:
		pool = &largeResponsePool
	default:
		return make([]byte, n) // Too large for any pool
	}
	bp := pool.Get().(*[]byte)
	b := *bp
	if cap(b) >= n {
		return b[:n]
	}
	return make([]byte, n)
}

func putResponseBuffer(buf []byte) {
	c := cap(buf)
	buf = buf[:0]
	switch {
	case c <= poolTierSmall:
		smallResponsePool.Put(&buf)
	case c <= poolTierMedium:
		mediumResponsePool.Put(&buf)
	case c <= poolTierLarge:
		largeResponsePool.Put(&buf)
		// c > poolTierLarge: let GC collect it
	}
}

// moduleFindingTracker tracks finding count and one-time warning for a single module.
type moduleFindingTracker struct {
	count  atomic.Int64
	warned sync.Once
}

// HookRunner transforms requests before scanning and filters results after scanning.
type HookRunner interface {
	RunPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error)
	RunPostHooks(result *output.ResultEvent) (*output.ResultEvent, error)
}

// OASTFlusher is implemented by the OAST service to allow the executor to flush
// pending interactions after scanning completes.
type OASTFlusher interface {
	Flush()
	Close()
}

// ExecutorConfig configures the Executor behavior.
type ExecutorConfig struct {
	Workers              int
	OnResult             func(*output.ResultEvent)
	OnTraffic            func(method, url string, statusCode int, contentType string) // Optional: called for each processed item
	Services             *services.Services
	HTTPRequester        *http.Requester
	Repository           *database.Repository   // Optional: database storage
	RecordWriter         *database.RecordWriter // Optional: batched record writer (preferred over Repository.SaveRecord)
	ScanUUID             string
	ProjectUUID          string                                                                                                    // Optional: scan session UUID
	Hooks                HookRunner                                                                                                // Optional: pre/post hooks
	ScopeMatcher         *config.ScopeMatcher                                                                                      // Optional: scope filtering
	ScopeOnIngest        bool                                                                                                      // When true, skip both save and scan for out-of-scope items
	StaticFileMatcher    *config.ScopeMatcher                                                                                      // Optional: always-on static file filtering (independent of ScopeMatcher)
	SkipBaseline         bool                                                                                                      // When true, skip HTTP fetch if response already attached (Phase 3 DB source)
	OASTProvider         modkit.OASTProvider                                                                                       // Optional: OAST callback URL generator for blind vuln detection
	OASTService          OASTFlusher                                                                                               // Optional: OAST service to flush after scanning
	PauseCtrl            *PauseController                                                                                          // Optional: cooperative pause/resume controller
	MaxFindingsPerModule int                                                                                                       // When > 0, suppress findings after this many per module
	MaxDuration          time.Duration                                                                                             // When > 0, cancel execution after this duration
	FeedbackDrainTimeout time.Duration                                                                                             // Idle timeout for draining feedback after source EOF (default: 100ms)
	IPCacheSize          int                                                                                                       // LRU cache size for parsed insertion points (default: 4096)
	IPCache              *lru.Cache[string, []httpmsg.InsertionPoint]                                                              // Optional: shared IP cache (if nil, a new one is created)
	ParallelPassive      bool                                                                                                      // When true, run passive per-request modules concurrently
	PassiveModuleTimeout time.Duration                                                                                             // Timeout per passive module call (default: 5s). 0 uses default.
	ActiveModuleTimeout  time.Duration                                                                                             // Timeout per active module call (default: 90s). 0 uses default. Modules may raise via TimeoutHinter.
	AdaptiveWorkers      bool                                                                                                      // When true, dynamically scale worker count based on queue depth
	MinWorkers           int                                                                                                       // Floor for adaptive scaling (default: 2)
	MaxWorkers           int                                                                                                       // Ceiling for adaptive scaling (default: Workers*4)
	ActiveTaskLimit      int                                                                                                       // Max concurrent active module tasks across host/request/IP scopes
	OnStatus             func(processed, total, findings, distinctModules, activeCount, passiveCount int64, elapsed time.Duration) // Optional: periodic status callback
	StatusInterval       time.Duration                                                                                             // Interval for OnStatus callback (default: 30s)
	// FirstStatusInterval, when > 0 and shorter than StatusInterval, fires the
	// very first status tick after this duration instead of waiting a full
	// StatusInterval. Useful for long-cadence status (e.g., 2m) where users
	// shouldn't have to stare at silence before the first line appears.
	FirstStatusInterval time.Duration
	// DisableFeedback drops every URL discovered by passive modules instead of
	// re-injecting it into the scan. With this flag the executor scans exactly
	// the items the input source delivers and nothing more — matching the
	// shallow per-request semantics of `vigolium scan-request`. Used by
	// scan-on-receive's default mode to avoid the cascade of new HTTP records
	// that link extractors and redirect followers would otherwise generate.
	DisableFeedback bool
	// TechFilterDisabled bypasses the tech-stack allowlist gate (see modules.TechAware).
	// Set by --no-tech-filter and automatically by --intensity=deep so deep scans
	// run every module regardless of detected stack.
	TechFilterDisabled bool
	// OnTechDetected fires once per (host, tag) when a passive fingerprint
	// module first publishes a stack detection.
	OnTechDetected func(host, tag string)
}

// DefaultExecutorConfig returns sensible defaults.
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		Workers: goruntime.NumCPU(),
	}
}

// SuggestWorkerCount returns a heuristic worker count for rescans.
// It scales with the number of active modules but caps at maxWorkers.
// The floor is 2 to ensure at least minimal parallelism.
func SuggestWorkerCount(moduleCount, maxWorkers int) int {
	suggested := moduleCount * 2
	if suggested < 2 {
		suggested = 2
	}
	if suggested > maxWorkers {
		suggested = maxWorkers
	}
	return suggested
}

// Executor orchestrates scanning with worker pool.
type Executor struct {
	cfg            ExecutorConfig
	source         source.InputSource
	activeModules  []modules.ActiveModule
	passiveModules []modules.PassiveModule
	httpClient     *http.Requester
	scanCtx        *modules.ScanContext
	hooks          HookRunner // Optional: pre/post hooks

	// Grouped modules for efficient routing
	perHostActive     []modules.ActiveModule
	perRequestActive  []modules.ActiveModule
	perIPActive       []modules.ActiveModule
	perHostPassive    []modules.PassiveModule
	perRequestPassive []modules.PassiveModule

	running       atomic.Bool
	results       atomic.Bool
	statsTracker  *stats.Tracker
	moduleMetrics *stats.ModuleMetrics

	// Insertion point cache: keyed by request SHA-256 hash, bounded LRU.
	// Avoids redundant AnalyzeRequest() calls for repeated/retried requests.
	ipCache *lru.Cache[string, []httpmsg.InsertionPoint]

	// Database storage (optional)
	repo         *database.Repository
	recordWriter *database.RecordWriter // batched record writer (preferred over repo.SaveRecord)
	scanUUID     string
	projectUUID  string
	// Map to track record UUID for each HttpRequestResponse (for linking findings)
	requestUUIDs *shardedMap // key: request hash, value: database record UUID

	// Per-module finding cap
	moduleFindingCount sync.Map // key: module ID → *moduleFindingTracker

	// Per-host module claim maps: ensures per-host modules run exactly once
	// per (module, host) pair even with concurrent workers.
	perHostActiveClaimed  sync.Map // key: "moduleID:host" → struct{}
	perHostPassiveClaimed sync.Map // key: "moduleID:host" → struct{}

	// In-flight counter: tracks workers currently processing items.
	// Used by the feedback drain loop to wait for all workers to complete.
	inFlight atomic.Int64

	// Adaptive worker scaling
	activeWorkers atomic.Int32 // current number of active workers
	minWorkers    int
	maxWorkers    int

	// Feedback channel: modules can inject discovered requests back into the pipeline
	feedbackCh    chan *work.WorkItem
	feeder        *executorFeeder // tracks feedback drop metrics
	activeTaskSem chan struct{}

	// Per-module required-tech cache. Populated lazily by passesTechFilter
	// since module tags are immutable for the scan's lifetime. Stored
	// pre-normalized (lowercased, trimmed) so the registry lookup can skip
	// re-normalizing on each call.
	moduleTechReq sync.Map // key: module ID → []string (nil = always-runs)
}

// NewExecutor creates a new Executor with the given configuration.
func NewExecutor(
	cfg ExecutorConfig,
	src source.InputSource,
	activeModules []modules.ActiveModule,
	passiveModules []modules.PassiveModule,
) *Executor {
	if cfg.Workers <= 0 {
		cfg.Workers = goruntime.NumCPU()
	}

	// Create ScanContext from Services
	var scanCtx *modules.ScanContext
	if cfg.Services != nil && cfg.Services.DedupManager != nil {
		scanCtx = &modules.ScanContext{
			DedupManager: cfg.Services.DedupManager,
		}
	}

	var ipCache *lru.Cache[string, []httpmsg.InsertionPoint]
	if cfg.IPCache != nil {
		ipCache = cfg.IPCache
	} else {
		ipCacheSize := cfg.IPCacheSize
		if ipCacheSize <= 0 {
			// Auto-size based on input source count for better cache utilization
			total := getKnownTotal(src)
			switch {
			case total > 0 && total <= 500:
				ipCacheSize = int(total) + 100
			case total > 500 && total <= 50000:
				ipCacheSize = int(total / 2)
			case total > 50000:
				ipCacheSize = 25000
			default:
				ipCacheSize = 4096
			}
		}
		ipCache, _ = lru.New[string, []httpmsg.InsertionPoint](ipCacheSize)
	}

	e := &Executor{
		cfg:            cfg,
		source:         src,
		activeModules:  activeModules,
		passiveModules: passiveModules,
		httpClient:     cfg.HTTPRequester,
		scanCtx:        scanCtx,
		hooks:          cfg.Hooks,
		repo:           cfg.Repository,
		recordWriter:   cfg.RecordWriter,
		scanUUID:       cfg.ScanUUID,
		projectUUID:    cfg.ProjectUUID,
		requestUUIDs:   newShardedMap(cfg.Workers),
		ipCache:        ipCache,
		feedbackCh:     make(chan *work.WorkItem, cfg.Workers*16),
	}

	activeTaskLimit := cfg.ActiveTaskLimit
	if activeTaskLimit <= 0 {
		activeTaskLimit = cfg.Workers * 8
		if activeTaskLimit < 32 {
			activeTaskLimit = 32
		}
	}
	e.activeTaskSem = make(chan struct{}, activeTaskLimit)

	// Wire risk score updater, remarks annotator, and request UUID resolver into ScanContext
	if e.scanCtx != nil && cfg.Repository != nil {
		e.scanCtx.RiskScoreUpdater = &repoRiskScoreUpdater{repo: cfg.Repository}
		e.scanCtx.RemarksAnnotator = &repoRemarksAnnotator{repo: cfg.Repository}
		e.scanCtx.RequestUUIDResolver = e
	}

	// Wire OAST provider into ScanContext
	if cfg.OASTProvider != nil {
		if e.scanCtx == nil {
			e.scanCtx = &modules.ScanContext{}
		}
		e.scanCtx.OASTProvider = cfg.OASTProvider
	}

	// Wire feedback feeder and cross-module finding dedup into ScanContext
	if e.scanCtx == nil {
		e.scanCtx = &modules.ScanContext{}
	}
	if cfg.DisableFeedback {
		// Shallow mode: modules can still call Feed() but it's a no-op. The
		// feedback channel is still allocated (cheap) but stays empty, so the
		// drain loop exits as soon as in-flight workers finish.
		e.scanCtx.RequestFeeder = nopFeederInstance
	} else {
		e.feeder = &executorFeeder{ch: e.feedbackCh}
		e.scanCtx.RequestFeeder = e.feeder
	}
	e.scanCtx.ParamFindings = &modkit.ParameterFindingRegistry{}
	e.scanCtx.TechStack = modkit.NewTechRegistry()
	e.scanCtx.TechStack.OnDetect = cfg.OnTechDetected

	// Wire insertion point provider for module reuse of cached IPs
	e.scanCtx.InsertionPoints = &executorIPProvider{cache: e.ipCache}

	// Pre-group modules by scan type
	e.perHostActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeHost)
	e.perRequestActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeRequest)
	e.perIPActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeInsertionPoint)
	e.perHostPassive = filterPassiveModulesByScanScope(passiveModules, modules.ScanScopeHost)
	e.perRequestPassive = filterPassiveModulesByScanScope(passiveModules, modules.ScanScopeRequest)

	// Sort active modules by priority within each scope group.
	// Higher priority (lower number) modules are spawned first,
	// getting earlier access to rate-limit slots.
	sortActiveByPriority(e.perHostActive)
	sortActiveByPriority(e.perRequestActive)
	sortActiveByPriority(e.perIPActive)

	// Always create stats tracker for counting processed items.
	// Periodic printing is only started when ShowStats is enabled (see Execute).
	total := getKnownTotal(src)
	e.statsTracker = stats.New(total, false)
	e.moduleMetrics = &stats.ModuleMetrics{}

	return e
}

// Processed returns the number of items processed by the executor.
func (e *Executor) Processed() int64 {
	if e.statsTracker != nil {
		return e.statsTracker.Processed()
	}
	return 0
}

// ModuleMetrics returns a point-in-time snapshot of per-module performance metrics.
func (e *Executor) ModuleMetrics() map[string]stats.ModuleStatsSnapshot {
	if e.moduleMetrics != nil {
		return e.moduleMetrics.Snapshot()
	}
	return nil
}

// FeedbackDropped returns the number of feedback items dropped due to channel capacity.
func (e *Executor) FeedbackDropped() int64 {
	if e.feeder != nil {
		return e.feeder.Dropped()
	}
	return 0
}

// InFlight returns the number of worker goroutines currently processing items.
// Zero means the executor is quiescent (all workers idle, no items in flight).
// Exposed for status reporting — callers typically combine this with source-level
// idle signals to distinguish "still doing work" from "waiting for input."
func (e *Executor) InFlight() int64 {
	return e.inFlight.Load()
}

// ConsideredModuleCount returns the number of distinct modules whose CanProcess
// has been evaluated at least once during this scan. Reaches parity with the
// total enabled-module count once every module has been seen — including those
// whose CanProcess always rejects the input shape (e.g., POST-only modules in
// a GET-only scan). Use this for "modules scanned X/Y" status displays.
func (e *Executor) ConsideredModuleCount() int64 {
	if e.moduleMetrics == nil {
		return 0
	}
	return e.moduleMetrics.ConsideredCount()
}

// Execute runs the scan. Blocks until all inputs are processed or context is cancelled.
func (e *Executor) Execute(ctx context.Context) (bool, error) {
	if !e.running.CompareAndSwap(false, true) {
		return false, fmt.Errorf("executor already running")
	}
	defer e.running.Store(false)

	// Enforce per-phase timeout when configured
	if e.cfg.MaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.cfg.MaxDuration)
		defer cancel()
	}

	// Start periodic stats printing only when ShowStats is enabled
	if e.cfg.Services != nil && e.cfg.Services.Options != nil &&
		e.cfg.Services.Options.ShowStats && !e.cfg.Services.Options.Silent {
		e.statsTracker.Start(ctx)
		defer e.statsTracker.Stop()
	}

	// Start periodic status callback when configured
	if e.cfg.OnStatus != nil {
		statusInterval := e.cfg.StatusInterval
		if statusInterval <= 0 {
			statusInterval = 30 * time.Second
		}
		statusStart := time.Now()
		statusTicker := time.NewTicker(statusInterval)
		activeCount := int64(len(e.activeModules))
		passiveCount := int64(len(e.passiveModules))

		// Optional early-tick: fire a single status before the regular cadence
		// kicks in. Helpful for long StatusInterval (e.g. 2m) where the user
		// would otherwise wait the full interval to see anything.
		var firstTickCh <-chan time.Time
		if e.cfg.FirstStatusInterval > 0 && e.cfg.FirstStatusInterval < statusInterval {
			t := time.NewTimer(e.cfg.FirstStatusInterval)
			firstTickCh = t.C
		}

		fireStatus := func() {
			e.cfg.OnStatus(
				e.statsTracker.Processed(),
				e.statsTracker.Total(),
				e.statsTracker.Findings(),
				e.moduleMetrics.DistinctCount(),
				activeCount,
				passiveCount,
				time.Since(statusStart),
			)
		}

		go func() {
			defer statusTicker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-firstTickCh:
					fireStatus()
					firstTickCh = nil // one-shot
				case <-statusTicker.C:
					fireStatus()
				}
			}
		}()
	}

	var wg conc.WaitGroup
	itemCh := make(chan *work.WorkItem, e.cfg.Workers*2)

	e.activeWorkers.Store(int32(e.cfg.Workers))
	for i := 0; i < e.cfg.Workers; i++ {
		workerID := i
		wg.Go(func() {
			e.worker(ctx, workerID, itemCh)
			e.activeWorkers.Add(-1)
		})
	}

	// Start adaptive worker controller if enabled
	var controllerCancel context.CancelFunc
	if e.cfg.AdaptiveWorkers {
		e.minWorkers = e.cfg.MinWorkers
		if e.minWorkers <= 0 {
			e.minWorkers = 2
		}
		e.maxWorkers = e.cfg.MaxWorkers
		if e.maxWorkers <= 0 {
			e.maxWorkers = e.cfg.Workers * 4
		}
		var controllerCtx context.Context
		controllerCtx, controllerCancel = context.WithCancel(ctx)
		go e.workerController(controllerCtx, itemCh, &wg)
	}

	e.feedItems(ctx, itemCh)

	// After source EOF, drain remaining feedback items from in-flight workers.
	// Wait until all workers finish (inFlight == 0) and the feedback channel is empty.
	// When FeedbackDrainTimeout is configured, require the executor to remain idle
	// for that duration before completing the drain.
	drainTick := time.NewTicker(50 * time.Millisecond)
	defer drainTick.Stop()
	idleTimeout := e.cfg.FeedbackDrainTimeout
	var idleSince time.Time
drainLoop:
	for {
		select {
		case <-ctx.Done():
			break drainLoop
		case fb := <-e.feedbackCh:
			idleSince = time.Time{}
			if !e.sendItem(ctx, fb, itemCh) {
				break drainLoop
			}
		case <-drainTick.C:
			if e.inFlight.Load() != 0 || len(e.feedbackCh) != 0 {
				idleSince = time.Time{}
				continue
			}
			if idleTimeout <= 0 {
				break drainLoop
			}
			if idleSince.IsZero() {
				idleSince = time.Now()
				continue
			}
			if time.Since(idleSince) >= idleTimeout {
				break drainLoop
			}
		}
	}

	// Stop the adaptive worker controller before closing the channel
	if controllerCancel != nil {
		controllerCancel()
	}

	close(itemCh)
	wg.Wait()

	// Flush passive modules that buffer data (e.g., anomaly ranking)
	for _, pm := range e.passiveModules {
		if flusher, ok := pm.(modules.Flusher); ok {
			flusher.Flush(e.scanCtx)
		}
	}

	// Flush batch passive modules that produce deferred findings (e.g., secret detection)
	for _, pm := range e.passiveModules {
		if bf, ok := pm.(modules.BatchFlusher); ok {
			results, err := bf.FlushFindings(e.scanCtx)
			if err != nil {
				zap.L().Warn("BatchFlusher error",
					zap.String("module", pm.ID()),
					zap.Error(err))
				continue
			}
			for _, r := range results {
				if !e.moduleFindingAllowed(pm.ID()) {
					continue
				}
				r.ModuleType = database.ModuleTypePassive
				r.FindingSource = database.FindingSourceDynamicAssessment
				e.emitResult(ctx, r)
			}
		}
	}

	// Flush OAST service: wait for grace period to catch late callbacks
	if e.cfg.OASTService != nil {
		e.cfg.OASTService.Flush()
	}

	return e.results.Load(), nil
}

func (e *Executor) feedItems(ctx context.Context, itemCh chan<- *work.WorkItem) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Drain any pending feedback items (non-blocking) before pulling from source
		e.drainFeedback(ctx, itemCh)

		// Block feeding while paused
		if e.cfg.PauseCtrl != nil {
			if !e.cfg.PauseCtrl.WaitIfPaused(ctx) {
				return
			}
		}

		item, err := e.source.Next(ctx)
		if err != nil {
			if source.IsEOF(err) {
				return
			}
			if ctx.Err() != nil {
				return
			}
			zap.L().Warn("Error reading from source", zap.Error(err))
			continue
		}

		if !e.sendItem(ctx, item, itemCh) {
			return
		}
	}
}

// drainFeedback non-blocking drains all pending feedback items into itemCh.
func (e *Executor) drainFeedback(ctx context.Context, itemCh chan<- *work.WorkItem) {
	for {
		select {
		case fb := <-e.feedbackCh:
			if !e.sendItem(ctx, fb, itemCh) {
				return
			}
		default:
			return
		}
	}
}

// sendItem applies scope/static filters and sends the item to itemCh.
// Returns false if context is cancelled.
func (e *Executor) sendItem(ctx context.Context, item *work.WorkItem, itemCh chan<- *work.WorkItem) bool {
	// Always filter static files before HTTP fetch (unconditional)
	if e.cfg.StaticFileMatcher != nil &&
		e.cfg.StaticFileMatcher.IsStaticFile(item.Request.Request().Path()) {
		item.Complete()
		return true
	}

	// Pre-request scope check (host/path only — avoids HTTP call)
	if e.cfg.ScopeMatcher != nil && item.Request.Service() != nil {
		if !e.cfg.ScopeMatcher.InScopeRequest(
			item.Request.Service().Host(),
			item.Request.Request().Path(), "", "") {
			item.Complete()
			return true
		}
	}

	// Per-module filtering via CanProcess() replaces global ShouldSkip
	if e.cfg.Services != nil && e.cfg.Services.HostErrors != nil &&
		e.cfg.Services.HostErrors.Check(item.Request.ID()) {
		item.Complete()
		return true
	}

	select {
	case <-ctx.Done():
		return false
	case itemCh <- item:
		return true
	}
}

func (e *Executor) worker(ctx context.Context, _ int, itemCh <-chan *work.WorkItem) {
	for {
		// Block if paused, abort if context cancelled
		if e.cfg.PauseCtrl != nil {
			if !e.cfg.PauseCtrl.WaitIfPaused(ctx) {
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case item, ok := <-itemCh:
			if !ok {
				return
			}
			e.inFlight.Add(1)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.AcquireWorker()
			}
			e.processItem(ctx, item)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.ReleaseWorker()
			}
			e.inFlight.Add(-1)
			item.Complete()
			if e.statsTracker != nil {
				e.statsTracker.Increment()
			}
		}
	}
}

// workerController monitors queue depth and scales workers up or down.
// Only active when AdaptiveWorkers is enabled.
func (e *Executor) workerController(ctx context.Context, itemCh chan *work.WorkItem, wg *conc.WaitGroup) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	nextID := e.cfg.Workers // start IDs after initial workers

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			queueDepth := len(itemCh)
			queueCap := cap(itemCh)
			active := int(e.activeWorkers.Load())

			// Scale up: queue > 75% full and we have headroom
			if queueDepth > queueCap*3/4 && active < e.maxWorkers {
				workerID := nextID
				nextID++
				e.activeWorkers.Add(1)
				wg.Go(func() {
					e.worker(ctx, workerID, itemCh)
					e.activeWorkers.Add(-1)
				})
				zap.L().Debug("Adaptive scaling: spawned worker",
					zap.Int("worker_id", workerID),
					zap.Int("active_workers", int(e.activeWorkers.Load())))
			}

			// Note: scaling down is handled naturally — when itemCh is closed,
			// excess workers exit on their own. We don't preemptively kill workers
			// to avoid complexity of per-worker cancellation and potential data loss.
		}
	}
}

func (e *Executor) processItem(ctx context.Context, item *work.WorkItem) {
	defer e.recoverFromPanic("processItem")

	// Bail out early if context is cancelled (graceful shutdown)
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Track pooled response buffer for deferred return.
	// Must be declared before recoverFromPanic defer so it runs first (LIFO).
	var pooledBuf []byte
	defer func() {
		if pooledBuf != nil {
			putResponseBuffer(pooledBuf)
		}
	}()

	req := item.Request
	enableModules := item.EnableModules

	zap.L().Debug("Processing item",
		zap.String("url", req.Target()),
		zap.Strings("enable_modules", enableModules))

	// Check context before expensive HTTP fetch
	select {
	case <-ctx.Done():
		return
	default:
	}

	var httpResp *httpmsg.HttpResponse
	req, httpResp, pooledBuf, ok := e.fetchBaselineResponse(ctx, req)
	if !ok {
		return
	}

	// Notify traffic callback
	if e.cfg.OnTraffic != nil {
		ct := getHeaderValue(httpResp.Headers(), "Content-Type")
		e.cfg.OnTraffic(req.Request().Method(), req.Target(), httpResp.StatusCode(), ct)
	}

	req, ok = e.applyPreHooks(req)
	if !ok {
		return
	}

	// Body size enforcement — truncate oversized bodies but defer drop/skip
	// decisions until after passive modules run (they are read-only).
	var bodySizeAction config.BodySizeAction
	if e.cfg.ScopeMatcher != nil {
		reqBodyLen := len(req.Request().Body())
		respBodyLen := len(httpResp.Body())
		var maxReq, maxResp int
		bodySizeAction, maxReq, maxResp = e.cfg.ScopeMatcher.CheckBodySize(reqBodyLen, respBodyLen)

		if bodySizeAction != config.BodySizeOK {
			if reqBodyLen > maxReq {
				req.Request().TruncateBody(maxReq)
				zap.L().Debug("Request body truncated",
					zap.String("url", req.Target()),
					zap.Int("original", reqBodyLen),
					zap.Int("truncated_to", maxReq))
			}
			if respBodyLen > maxResp {
				httpResp.TruncateBody(maxResp)
				zap.L().Debug("Response body truncated",
					zap.String("url", req.Target()),
					zap.Int("original", respBodyLen),
					zap.Int("truncated_to", maxResp))
			}
		}
	}

	// Module filter setup (needed by passive modules below)
	var filter moduleFilter
	if len(enableModules) == 0 {
		filter = allModulesFilter
	} else {
		filter = newModuleFilter(enableModules)
	}

	// Pre-register requestUUIDs for DB-sourced items so passive module
	// findings can link to the existing http_record instead of creating
	// duplicate "finding" records.
	if item.RecordUUID != "" && e.repo != nil {
		e.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)
	}

	// Pre-compute scope status before passive modules so scope-aware
	// passive modules can be skipped for out-of-scope items.
	inScope := true
	if e.cfg.ScopeMatcher != nil && req.Service() != nil {
		inScope = e.cfg.ScopeMatcher.InScopeBytes(
			req.Service().Host(),
			req.Request().Path(),
			httpResp.StatusCode(),
			getHeaderValue(req.Request().Headers(), "Content-Type"),
			getHeaderValue(httpResp.Headers(), "Content-Type"),
			req.Request().Raw(),
			httpResp.Body(),
		)
	}

	e.runPassiveStage(ctx, req, &filter, inScope)

	// Body size gate — drop/skip only affects active modules
	if bodySizeAction == config.BodySizeDrop {
		zap.L().Debug("Body size exceeded, dropping item (active scan skipped)",
			zap.String("url", req.Target()))
		return
	}
	if bodySizeAction == config.BodySizeSkipScan {
		e.saveToDatabase(ctx, item, req)
		return
	}
	skipActive := bodySizeAction == config.BodySizePassiveOnly

	if !e.persistAndCheckScope(ctx, item, req, inScope) {
		return
	}

	elig := computeEligibility(req)

	if !skipActive {
		e.runActiveStage(ctx, req, &filter, &elig)
	}
}

func (e *Executor) fetchBaselineResponse(ctx context.Context, req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, *httpmsg.HttpResponse, []byte, bool) {
	if e.cfg.SkipBaseline && req.Response() != nil {
		return req, req.Response(), nil, true
	}

	respChain, _, err := e.httpClient.Execute(req, http.Options{})
	if err != nil {
		zap.L().Debug("Failed to fetch baseline response, skipping item",
			zap.String("url", req.Target()),
			zap.Error(err))
		return nil, nil, nil, false
	}

	if blockErr := infra.GetBlockDetectionValidator().Validate(respChain); blockErr != nil {
		respChain.Close()
		zap.L().Debug("Block detected, skipping item",
			zap.String("url", req.Target()),
			zap.Error(blockErr))
		if e.statsTracker != nil {
			e.statsTracker.IncrementBlocked()
		}
		return nil, nil, nil, false
	}

	fullResp := respChain.FullResponse().Bytes()
	rawResponseCopy := getResponseBuffer(len(fullResp))
	copy(rawResponseCopy, fullResp)
	respChain.Close()

	httpResp := httpmsg.NewHttpResponse(rawResponseCopy)
	return req.WithResponse(httpResp), httpResp, rawResponseCopy, true
}

func (e *Executor) applyPreHooks(req *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, bool) {
	if e.hooks == nil {
		return req, true
	}

	hooked, err := e.hooks.RunPreHooks(req)
	if err != nil {
		zap.L().Debug("Pre-hook error, skipping item",
			zap.String("url", req.Target()), zap.Error(err))
		return nil, false
	}
	if hooked == nil {
		zap.L().Debug("Pre-hook filtered out item",
			zap.String("url", req.Target()))
		return nil, false
	}
	return hooked, true
}

func (e *Executor) runPassiveStage(ctx context.Context, req *httpmsg.HttpRequestResponse, filter *moduleFilter, inScope bool) {
	eligiblePerHost := e.filterEligiblePassive(e.perHostPassive, req, filter)
	eligiblePerRequest := e.filterEligiblePassive(e.perRequestPassive, req, filter)
	if !inScope {
		eligiblePerHost = filterNonScopeAware(eligiblePerHost)
		eligiblePerRequest = filterNonScopeAware(eligiblePerRequest)
	}
	e.runPassivePerHostFiltered(ctx, req, eligiblePerHost)
	e.runPassivePerRequestFiltered(ctx, req, eligiblePerRequest)
}

func (e *Executor) persistAndCheckScope(ctx context.Context, item *work.WorkItem, req *httpmsg.HttpRequestResponse, inScope bool) bool {
	if e.cfg.ScopeMatcher != nil {
		if req.Service() == nil {
			return false
		}

		if !inScope && e.cfg.ScopeOnIngest {
			return false
		}

		e.saveToDatabase(ctx, item, req)
		return inScope
	}

	e.saveToDatabase(ctx, item, req)
	return true
}

func (e *Executor) runActiveStage(ctx context.Context, req *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility) {
	// conc.WaitGroup automatically catches panics per goroutine and re-panics
	// on Wait(), which is caught by the top-level recoverFromPanic("processItem").
	var g conc.WaitGroup
	e.runActivePerHost(ctx, req, filter, elig, &g)
	e.runActivePerRequest(ctx, req, filter, elig, &g)
	e.runActivePerInsertionPoint(ctx, req, filter, elig, &g)
	g.Wait()
}

// saveToDatabase stores the request/response record in the database if enabled.
func (e *Executor) saveToDatabase(ctx context.Context, item *work.WorkItem, req *httpmsg.HttpRequestResponse) {
	if e.repo == nil {
		return
	}
	if item.RecordUUID != "" {
		// Item came from DB watcher — use existing record UUID, skip insert
		e.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)
		return
	}

	// Prefer batched writer for throughput; fall back to individual SaveRecord
	var recordUUID string
	var err error
	if e.recordWriter != nil {
		recordUUID, err = e.recordWriter.Write(ctx, req, "scanner", e.projectUUID)
	} else {
		recordUUID, err = e.repo.SaveRecord(ctx, req, "scanner", e.projectUUID)
	}
	if err != nil {
		zap.L().Debug("Failed to save record to database", zap.Error(err))
		return
	}
	e.requestUUIDs.Store(req.Request().ID(), recordUUID)
}

// filterEligiblePassive pre-filters passive modules by CanProcess and module filter,
// computing eligibility once per request instead of per-module in each run method.
func (e *Executor) filterEligiblePassive(mods []modules.PassiveModule, item *httpmsg.HttpRequestResponse, filter *moduleFilter) []modules.PassiveModule {
	if len(mods) == 0 {
		return nil
	}
	eligible := make([]modules.PassiveModule, 0, len(mods))
	for _, m := range mods {
		if !filter.allows(m.ID()) {
			continue
		}
		if !e.passesTechFilter(m, item) {
			continue
		}
		// Mark considered before CanProcess so modules that always reject this
		// input shape still count toward the "modules scanned" status counter.
		e.moduleMetrics.MarkConsidered(m.ID())
		if m.CanProcess(item) {
			eligible = append(eligible, m)
		}
	}
	return eligible
}

// defaultPassiveModuleTimeout limits how long a single passive module can take per request.
const defaultPassiveModuleTimeout = 5 * time.Second

// defaultActiveModuleTimeout limits how long a single active module can take per
// (record / insertion-point) call. Active modules run multi-probe injection so this
// is much higher than the passive default; modules that legitimately need longer
// (e.g. diffscan behavioral timing analysis) opt in via modules.TimeoutHinter.
const defaultActiveModuleTimeout = 300 * time.Second

// passiveModuleTimeout returns the effective passive module timeout.
func (e *Executor) passiveModuleTimeout() time.Duration {
	if e.cfg.PassiveModuleTimeout > 0 {
		return e.cfg.PassiveModuleTimeout
	}
	return defaultPassiveModuleTimeout
}

// activeModuleTimeout returns the effective active module timeout.
func (e *Executor) activeModuleTimeout() time.Duration {
	if e.cfg.ActiveModuleTimeout > 0 {
		return e.cfg.ActiveModuleTimeout
	}
	return defaultActiveModuleTimeout
}

// runPassiveWithTimeout executes a passive module scan function with a timeout guard.
func (e *Executor) runPassiveWithTimeout(
	ctx context.Context,
	scanFn func(context.Context) ([]*output.ResultEvent, error),
	module modules.PassiveModule,
	item *httpmsg.HttpRequestResponse,
) []*output.ResultEvent {
	timeout := e.passiveModuleTimeout()
	// Allow modules to override with a per-module timeout hint
	if hinter, ok := module.(modules.TimeoutHinter); ok {
		if hint := hinter.TimeoutHint(); hint > 0 {
			timeout = hint
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		events []*output.ResultEvent
		err    error
	}

	start := time.Now()
	ch := make(chan result, 1)
	go func() {
		events, err := scanFn(callCtx)
		ch <- result{events, err}
	}()

	select {
	case r := <-ch:
		e.moduleMetrics.Record(module.ID(), time.Since(start), len(r.events), r.err)
		if r.err != nil {
			zap.L().Debug("Passive module error",
				zap.String("module", module.ID()),
				zap.Error(r.err))
			return nil
		}
		return r.events
	case <-callCtx.Done():
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		zap.L().Warn("Passive module timed out — skipping",
			zap.String("module", module.ID()),
			zap.String("url", item.Target()),
			zap.Duration("timeout", timeout))
		return nil
	}
}

// runActiveWithTimeout executes an active module scan function under a timeout
// derived from the phase context. It returns the module's results and whether
// the call completed within the bound. When the per-module timeout fires OR the
// phase deadline (ctx) is reached, it returns (nil, false) immediately so the
// worker stops blocking on g.Wait() and the phase ends on time. The scan function
// receives callCtx for explicit use. The executor also hands the module a
// requester bound to the PHASE context (http.Requester.WithContext), so
// context-less Execute calls abort in-flight requests on scan shutdown / phase
// deadline. It deliberately is NOT bound to callCtx: the request clusterer
// shares one in-flight request across modules, so a single module's per-module
// timeout must not cancel a request other modules deduped onto. The per-module
// timeout is still enforced here — a timed-out call returns (nil, false) and the
// caller skips processResults — it just doesn't sever the shared socket early.
func (e *Executor) runActiveWithTimeout(
	ctx context.Context,
	scanFn func(context.Context) ([]*output.ResultEvent, error),
	module modules.Module,
	item *httpmsg.HttpRequestResponse,
) ([]*output.ResultEvent, bool) {
	timeout := e.activeModuleTimeout()
	// Allow modules to override with a per-module timeout hint (e.g. diffscan
	// timing analysis legitimately needs longer than the global default).
	if hinter, ok := module.(modules.TimeoutHinter); ok {
		if hint := hinter.TimeoutHint(); hint > timeout {
			timeout = hint
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		events []*output.ResultEvent
		err    error
	}

	start := time.Now()
	ch := make(chan result, 1)
	go func() {
		events, err := scanFn(callCtx)
		ch <- result{events, err}
	}()

	select {
	case r := <-ch:
		e.moduleMetrics.Record(module.ID(), time.Since(start), len(r.events), r.err)
		if r.err != nil {
			if isLevelDBClosed(r.err) {
				zap.L().Debug("Active module error (shutdown)",
					zap.String("module", module.ID()),
					zap.Error(r.err))
			} else {
				zap.L().Warn("Active module error",
					zap.String("module", module.ID()),
					zap.Error(r.err))
			}
			return nil, true
		}
		return r.events, true
	case <-callCtx.Done():
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		zap.L().Warn("Active module timed out — skipping",
			zap.String("module", module.ID()),
			zap.String("url", item.Target()),
			zap.Duration("timeout", timeout))
		return nil, false
	}
}

// isLevelDBClosed returns true if the error is caused by a closed LevelDB instance,
// which happens during shutdown when the dedup manager is closed before workers finish.
func isLevelDBClosed(err error) bool {
	return strings.Contains(err.Error(), "leveldb: closed")
}

// moduleFilter provides O(1) module-enable lookups via a map.
type moduleFilter struct {
	all bool
	set map[string]struct{}
}

// allModulesFilter is a pre-allocated filter that allows all modules,
// avoiding a new moduleFilter allocation on the common path.
var allModulesFilter = moduleFilter{all: true}

// newModuleFilter builds a filter from the enableModules slice.
// Empty slice or "all" sentinel means all modules are enabled.
func newModuleFilter(enableModules []string) moduleFilter {
	if len(enableModules) == 0 {
		return moduleFilter{all: true}
	}
	set := make(map[string]struct{}, len(enableModules))
	for _, id := range enableModules {
		if id == "all" {
			return moduleFilter{all: true}
		}
		set[id] = struct{}{}
	}
	return moduleFilter{set: set}
}

// allows returns true if the module should run.
func (f *moduleFilter) allows(moduleID string) bool {
	if f.all {
		return true
	}
	_, ok := f.set[moduleID]
	return ok
}

// getKnownTotal returns the total count from source if known, otherwise 0.
func getKnownTotal(src source.InputSource) int64 {
	return source.GetTotal(src)
}

// getHeaderValue extracts the first matching header value by name (case-insensitive).
func getHeaderValue(headers []httpmsg.HttpHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// ResolveRequestUUID resolves a request hash to its database record UUID.
// Implements modkit.RequestUUIDResolver.
func (e *Executor) ResolveRequestUUID(requestHash string) string {
	val, _ := e.requestUUIDs.Load(requestHash)
	return val
}
