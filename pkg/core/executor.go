package core

import (
	"context"
	"errors"
	"fmt"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sourcegraph/conc"
	"github.com/syndtr/goleveldb/leveldb"
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
	"github.com/vigolium/vigolium/pkg/storagesig"
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
	Workers               int
	OnResult              func(*output.ResultEvent)
	OnTraffic             func(method, url string, statusCode int, contentType string) // Optional: called for each processed item
	Services              *services.Services
	HTTPRequester         *http.Requester
	Repository            *database.Repository    // Optional: database storage
	RecordWriter          *database.RecordWriter  // Optional: batched record writer (preferred over Repository.SaveRecord)
	FindingWriter         *database.FindingWriter // Optional: batched finding writer (preferred over Repository.SaveFinding)
	ScanUUID              string
	ProjectUUID           string                                                                                                              // Optional: scan session UUID
	Hooks                 HookRunner                                                                                                          // Optional: pre/post hooks
	ScopeMatcher          *config.ScopeMatcher                                                                                                // Optional: scope filtering
	ScopeOnIngest         bool                                                                                                                // When true, skip both save and scan for out-of-scope items
	StaticFileMatcher     *config.ScopeMatcher                                                                                                // Optional: always-on static file filtering (independent of ScopeMatcher)
	FollowSubdomains      bool                                                                                                                // When true, subdomain_harvest adds discovered subdomains to scope and feeds them (needs ScopeMatcher + feedback)
	SkipBaseline          bool                                                                                                                // When true, skip HTTP fetch if response already attached (Phase 3 DB source)
	OASTProvider          modkit.OASTProvider                                                                                                 // Optional: OAST callback URL generator for blind vuln detection
	OASTService           OASTFlusher                                                                                                         // Optional: OAST service to flush after scanning
	PauseCtrl             *PauseController                                                                                                    // Optional: cooperative pause/resume controller
	MaxFindingsPerModule  int                                                                                                                 // When > 0, suppress findings after this many per module
	MaxDuration           time.Duration                                                                                                       // When > 0, cancel execution after this duration
	FeedbackDrainTimeout  time.Duration                                                                                                       // Idle timeout for draining feedback after source EOF (default: 100ms)
	FeedbackDrainMaxStall time.Duration                                                                                                       // Hard cap on draining with workers in-flight but making no progress (0 = 2x active module timeout). Guards against a module that ignores cancellation.
	IPCacheSize           int                                                                                                                 // LRU cache size for parsed insertion points (default: 4096)
	IPCache               *lru.Cache[string, []httpmsg.InsertionPoint]                                                                        // Optional: shared IP cache (if nil, a new one is created)
	ParallelPassive       bool                                                                                                                // When true, run passive per-request modules concurrently
	PassiveModuleTimeout  time.Duration                                                                                                       // Timeout per passive module call (default: 5s). 0 uses default.
	ActiveModuleTimeout   time.Duration                                                                                                       // Timeout per active module call (default: 90s). 0 uses default. Modules may raise via TimeoutHinter.
	AdaptiveWorkers       bool                                                                                                                // When true, dynamically scale worker count based on queue depth
	MinWorkers            int                                                                                                                 // Floor for adaptive scaling (default: 2)
	MaxWorkers            int                                                                                                                 // Ceiling for adaptive scaling (default: Workers*4)
	ActiveTaskLimit       int                                                                                                                 // Max concurrent active module tasks across host/request/IP scopes
	OnStatus              func(processed, total, findings, distinctModules, activeCount, passiveCount, timedOut int64, elapsed time.Duration) // Optional: periodic status callback
	StatusInterval        time.Duration                                                                                                       // Interval for OnStatus callback (default: 30s)
	// ModuleTimeouts, when non-nil, is an externally-owned counter the executor
	// increments on each active-module timeout (instead of its own private one).
	// A multi-round phase passes one shared counter so the timed-out total in the
	// status line accumulates across the per-round executors it creates.
	ModuleTimeouts *atomic.Int64
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
	// DeepScan mirrors --intensity=deep into ScanContext so modules can unlock
	// heavier probing (e.g. dashboard_exposure's full mount-path sweep).
	DeepScan bool
	// ContentClassByHost seeds the per-host content-class registry from the
	// heuristics root probe (host → modkit.ContentClass string). It is the
	// fallback consulted by the content-class gate when a record's own
	// Content-Type is indeterminate. Honors the same TechFilterDisabled switch.
	ContentClassByHost map[string]string
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

	// moduleTimeouts counts active-module invocations that hit the per-module
	// timeout and were skipped. Surfaced via the OnStatus callback so the status
	// line can show how many modules are timing out without flooding stderr with
	// a WARN per skip (those are logged at debug level instead). This is the
	// executor's own tally; a multi-round phase can instead supply a shared
	// counter via ExecutorConfig.ModuleTimeouts so the total accumulates across
	// rounds — see recordModuleTimeout / timedOutCount, which pick the right one.
	moduleTimeouts atomic.Int64

	// suppressedFindings counts candidate findings that were dropped by the
	// body-differential safety net (the payload-vs-baseline re-confirmation could
	// not establish a real, reproducible difference). Surfaced via
	// SuppressedFindings() so a quiet target doesn't look identical to a
	// confirmed-clean one — re-confirmation never truncates silently.
	suppressedFindings atomic.Int64

	// Database storage (optional)
	repo          *database.Repository
	recordWriter  *database.RecordWriter  // batched record writer (preferred over repo.SaveRecord)
	findingWriter *database.FindingWriter // batched finding writer (preferred over repo.SaveFinding)
	scanUUID      string
	projectUUID   string

	// caches groups the per-scan lookup/dedup bookkeeping; pool groups the
	// worker-pool concurrency state. Both are split out of Executor to keep
	// this struct focused on orchestration rather than implementation state.
	caches scanCaches
	pool   workerPool

	// storageHosts records hosts observed to front object storage (a response
	// carried a storage backend signal) so the static-file carve-out keeps
	// sibling static assets on the same host. Key: host → struct{}. Bounded LRU
	// (not an unbounded sync.Map) so a long-lived executor can't accumulate one
	// entry per distinct storage-fronting host for the process lifetime.
	storageHosts *lru.Cache[string, struct{}]
}

// markStorageHost records that host fronts object storage.
func (e *Executor) markStorageHost(host string) {
	if host != "" {
		e.storageHosts.Add(host, struct{}{})
	}
}

// isLearnedStorageHost reports whether host was previously seen fronting
// object storage this scan.
func (e *Executor) isLearnedStorageHost(host string) bool {
	if host == "" {
		return false
	}
	return e.storageHosts.Contains(host)
}

// staticStorageCandidate reports whether a static-file request looks like an
// object-storage asset worth keeping (recorded metadata-only) rather than
// dropping: a /obj/<bucket>/<object> path shape, or a host already learned to
// front object storage.
func (e *Executor) staticStorageCandidate(rr *httpmsg.HttpRequestResponse) bool {
	if rr == nil || rr.Request() == nil {
		return false
	}
	if storagesig.LooksLikeStorageObjectPath(rr.Request().Path()) {
		return true
	}
	return rr.Service() != nil && e.isLearnedStorageHost(rr.Service().Host())
}

// perHostClaimCacheSize bounds each per-host claim LRU. With ~31 per-host
// modules this covers roughly 500 distinct hosts before the oldest claims
// evict — large enough that re-firing is rare during a single host's scan
// window, small enough that the maps can't grow unbounded over a multi-day
// server run.
const perHostClaimCacheSize = 16384

// hostClaimKey identifies a (module, host) per-host claim. Using a struct key
// instead of a "moduleID:host" string avoids allocating a fresh string on every
// request for every per-host module (the claim is checked per request but only
// won once per pair) — the struct is hashed/compared in place by the LRU's map.
type hostClaimKey struct {
	moduleID string
	host     string
}

// scanCaches groups the Executor's per-scan lookup and dedup state. Every field
// is safe for concurrent use (bounded LRU / sharded map / sync.Map).
type scanCaches struct {
	// ipCache is an insertion-point cache keyed by request SHA-256 hash, bounded
	// LRU. Avoids redundant AnalyzeRequest() calls for repeated/retried requests.
	ipCache *lru.Cache[string, []httpmsg.InsertionPoint]

	// requestUUIDs tracks the database record UUID for each HttpRequestResponse
	// (for linking findings). Key: request hash, value: database record UUID.
	requestUUIDs *shardedMap

	// moduleFindingCount enforces the per-module finding cap.
	// Key: module ID → *moduleFindingTracker.
	moduleFindingCount sync.Map

	// perHostActiveClaimed / perHostPassiveClaimed ensure per-host modules run
	// exactly once per (module, host) pair even with concurrent workers.
	// Key: hostClaimKey{moduleID, host} → struct{}. Bounded LRUs rather than
	// unbounded sync.Maps: in a long-lived scan-on-receive executor the (module,
	// host) key space grows with every distinct host ingested, so an unbounded
	// map leaks for the process lifetime. The LRU caps that growth and, by
	// evicting the least-recently-claimed pairs, lets per-host modules re-fire
	// for a host whose claim has aged out — restoring coverage on hosts seen long
	// ago.
	perHostActiveClaimed  *lru.Cache[hostClaimKey, struct{}]
	perHostPassiveClaimed *lru.Cache[hostClaimKey, struct{}]

	// moduleTechReq is a per-module required-tech cache. Populated lazily by
	// passesTechFilter since module tags are immutable for the scan's lifetime.
	// Stored pre-normalized (lowercased, trimmed) so the registry lookup can skip
	// re-normalizing on each call. Key: module ID → []string (nil = always-runs).
	moduleTechReq sync.Map

	// moduleContentClassReq is the analogous per-module required-content-class
	// cache for passesContentClassFilter. Key: module ID → []string (nil = runs
	// on any content type).
	moduleContentClassReq sync.Map
}

// workerPool groups the Executor's worker-pool concurrency state.
type workerPool struct {
	// inFlight counts workers currently processing items. Used by the feedback
	// drain loop to wait for all workers to complete.
	inFlight atomic.Int64

	// Adaptive worker scaling: current count plus the lower/upper bounds.
	activeWorkers atomic.Int32
	minWorkers    int
	maxWorkers    int

	// feedbackCh lets modules inject discovered requests back into the pipeline;
	// feeder wraps it to track drop metrics. activeTaskSem bounds concurrent
	// active-module tasks.
	feedbackCh    chan *work.WorkItem
	feeder        *executorFeeder
	activeTaskSem chan struct{}
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
		// Guard the size so lru.New cannot fail: it only errors on a
		// non-positive size, which would otherwise leave ipCache nil and
		// nil-panic on the first Get/Add. With size >= 1 the ignored error is
		// provably nil.
		if ipCacheSize < 1 {
			ipCacheSize = 4096
		}
		ipCache, _ = lru.New[string, []httpmsg.InsertionPoint](ipCacheSize)
	}

	// Bounded LRUs for the per-host run-once claims (size <= 0 is the only error
	// lru.New returns, and perHostClaimCacheSize is a positive constant, so the
	// ignored error is provably nil).
	perHostActiveClaimed, _ := lru.New[hostClaimKey, struct{}](perHostClaimCacheSize)
	perHostPassiveClaimed, _ := lru.New[hostClaimKey, struct{}](perHostClaimCacheSize)
	storageHosts, _ := lru.New[string, struct{}](perHostClaimCacheSize)

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
		findingWriter:  cfg.FindingWriter,
		scanUUID:       cfg.ScanUUID,
		projectUUID:    cfg.ProjectUUID,
		storageHosts:   storageHosts,
		caches: scanCaches{
			requestUUIDs:          newShardedMap(cfg.Workers),
			ipCache:               ipCache,
			perHostActiveClaimed:  perHostActiveClaimed,
			perHostPassiveClaimed: perHostPassiveClaimed,
		},
		pool: workerPool{
			feedbackCh: make(chan *work.WorkItem, cfg.Workers*16),
		},
	}

	activeTaskLimit := cfg.ActiveTaskLimit
	if activeTaskLimit <= 0 {
		activeTaskLimit = cfg.Workers * 8
		if activeTaskLimit < 32 {
			activeTaskLimit = 32
		}
	}
	e.pool.activeTaskSem = make(chan struct{}, activeTaskLimit)

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
		e.pool.feeder = &executorFeeder{ch: e.pool.feedbackCh}
		e.scanCtx.RequestFeeder = e.pool.feeder
	}
	// Wire scope expander + follow-subdomains toggle (subdomain_harvest feed-back).
	// Requires a real scope matcher and live feedback; otherwise the module stays
	// recon-only because ShouldFollowSubdomains() sees no expander/feeder.
	if cfg.FollowSubdomains && cfg.ScopeMatcher != nil && !cfg.DisableFeedback {
		e.scanCtx.ScopeExpander = &executorScopeExpander{matcher: cfg.ScopeMatcher}
		e.scanCtx.FollowSubdomains = true
	}
	e.scanCtx.DeepScan = cfg.DeepScan
	e.scanCtx.ParamFindings = &modkit.ParameterFindingRegistry{}
	e.scanCtx.TechStack = modkit.NewTechRegistry()
	e.scanCtx.TechStack.OnDetect = cfg.OnTechDetected
	e.scanCtx.WAFStack = modkit.NewWAFRegistry()
	e.scanCtx.ContentClass = modkit.NewContentClassRegistry()
	for host, class := range cfg.ContentClassByHost {
		e.scanCtx.ContentClass.Set(host, modkit.ContentClass(class))
	}

	// Wire insertion point provider for module reuse of cached IPs
	e.scanCtx.InsertionPoints = &executorIPProvider{cache: e.caches.ipCache}

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
	if e.pool.feeder != nil {
		return e.pool.feeder.Dropped()
	}
	return 0
}

// SuppressedFindings returns the number of candidate findings dropped by the
// body-differential safety net because a real payload-vs-baseline difference
// could not be re-confirmed.
func (e *Executor) SuppressedFindings() int64 {
	return e.suppressedFindings.Load()
}

// InFlight returns the number of worker goroutines currently processing items.
// Zero means the executor is quiescent (all workers idle, no items in flight).
// Exposed for status reporting — callers typically combine this with source-level
// idle signals to distinguish "still doing work" from "waiting for input."
func (e *Executor) InFlight() int64 {
	return e.pool.inFlight.Load()
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
				e.timedOutCount(),
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

	e.pool.activeWorkers.Store(int32(e.cfg.Workers))
	for i := 0; i < e.cfg.Workers; i++ {
		workerID := i
		wg.Go(func() {
			e.worker(ctx, workerID, itemCh)
			e.pool.activeWorkers.Add(-1)
		})
	}

	// Start adaptive worker controller if enabled
	var controllerCancel context.CancelFunc
	if e.cfg.AdaptiveWorkers {
		e.pool.minWorkers = e.cfg.MinWorkers
		if e.pool.minWorkers <= 0 {
			e.pool.minWorkers = 2
		}
		e.pool.maxWorkers = e.cfg.MaxWorkers
		if e.pool.maxWorkers <= 0 {
			e.pool.maxWorkers = e.cfg.Workers * 4
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
	// stallTimeout bounds the drain when workers stay in-flight but make no
	// forward progress. The idle branch below only fires once inFlight hits 0, so
	// a module that ignores cancellation would otherwise pin inFlight > 0 and hang
	// the drain forever. lastProgress is reset whenever a feedback item arrives or
	// an in-flight item completes (inFlight decreases), so a healthy long-running
	// drain is never truncated — only a genuine no-progress stall trips the cap.
	stallTimeout := e.feedbackDrainMaxStall()
	var idleSince time.Time
	lastProgress := time.Now()
	prevInFlight := e.pool.inFlight.Load()
drainLoop:
	for {
		select {
		case <-ctx.Done():
			break drainLoop
		case fb := <-e.pool.feedbackCh:
			idleSince = time.Time{}
			lastProgress = time.Now()
			if !e.sendItem(ctx, fb, itemCh) {
				break drainLoop
			}
		case <-drainTick.C:
			cur := e.pool.inFlight.Load()
			if cur < prevInFlight {
				lastProgress = time.Now() // a worker completed an item
			}
			prevInFlight = cur
			if cur != 0 || len(e.pool.feedbackCh) != 0 {
				idleSince = time.Time{}
				if stallTimeout > 0 && time.Since(lastProgress) >= stallTimeout {
					zap.L().Warn("feedback drain abandoned: workers still in flight but no progress within stall timeout (a module may be ignoring cancellation)",
						zap.Int64("in_flight", cur),
						zap.Int("feedback_queued", len(e.pool.feedbackCh)),
						zap.Duration("stall_timeout", stallTimeout))
					break drainLoop
				}
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

	// Bound the wait for workers to exit. Healthy workers return immediately once
	// itemCh is closed; only a worker stuck in a code path that ignores
	// cancellation lingers. Without a bound, that single worker would hang Wait()
	// — and the whole scan — forever (the drain stall cap above only breaks the
	// drain loop; this is where an unresponsive worker would otherwise re-block).
	// We run Wait() in a goroutine and forward any captured panic so conc's
	// re-panic semantics are preserved on the normal path; on timeout we log
	// loudly and proceed, leaking the stuck goroutine rather than hanging.
	waitDone := make(chan struct{})
	var waitPanic atomic.Value
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Never silently swallow a worker panic. Log it here so it stays
				// visible even when the main goroutine has already abandoned the
				// wait (the timeout branch below never reads waitPanic); also stash
				// it so the normal path re-raises it with conc's semantics.
				zap.L().Error("recovered panic while waiting for scan workers to exit",
					zap.Any("panic", r))
				waitPanic.Store(r)
			}
			close(waitDone)
		}()
		wg.Wait()
	}()
	maxStall := e.feedbackDrainMaxStall()
	workersExited := true
	select {
	case <-waitDone:
		if r := waitPanic.Load(); r != nil {
			panic(r)
		}
	case <-time.After(maxStall):
		workersExited = false
		zap.L().Warn("abandoning scan worker(s) that did not exit within the stall timeout to avoid hanging the scan; leaking goroutine(s)",
			zap.Int64("in_flight", e.pool.inFlight.Load()),
			zap.Duration("stall_timeout", maxStall))
	}

	// Passive-module flush must only run once every worker has exited. Flusher /
	// BatchFlusher modules aggregate cross-request state that a worker mutates
	// from ScanPerRequest; if we abandoned a still-running worker above, flushing
	// here would race that worker on the module's buffer and the result pipeline.
	// In that (pathological, already-degraded) case we skip the flush rather than
	// risk corrupted findings — deferred findings may be incomplete.
	if workersExited {
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
					// Deferred batch findings carry their own request; no baseline
					// item is in scope here, so take the standard parse/save path.
					e.emitResult(ctx, r, nil)
				}
			}
		}
	} else {
		zap.L().Warn("skipping passive-module flush after abandoning workers; deferred findings (e.g. secret detection, anomaly ranking) may be incomplete")
	}

	// Flush OAST service: wait for grace period to catch late callbacks
	if e.cfg.OASTService != nil {
		e.cfg.OASTService.Flush()
	}

	return e.results.Load(), nil
}

func (e *Executor) feedItems(ctx context.Context, itemCh chan<- *work.WorkItem) {
	// Sources report per-item failures by returning a non-EOF error from Next();
	// we log and skip the bad item, then keep reading. This must NOT abort the
	// feed: e.g. TargetSource advances its cursor before validating a URL, so a
	// malformed entry returns an error but the next call yields the next valid
	// target — bailing out here would silently drop the rest of the input.
	// Exhaustion is signalled by io.EOF (a source that can't make progress, like
	// a FileSource whose parse failed, reports its error once and then EOFs).
	//
	// The only hazard is a source that returns the same error on every call
	// without ever yielding an item or EOF; an unconditional retry would peg a
	// CPU. We guard against that with a small backoff once errors arrive
	// back-to-back with no item in between — a spin guard only, never a reason
	// to drop input. A source that interleaves errors with items resets the
	// streak and never pays the cost.
	const spinGuardThreshold = 4
	consecutiveErrors := 0
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
			consecutiveErrors++
			zap.L().Warn("Error reading from source",
				zap.Error(err),
				zap.Int("consecutive_errors", consecutiveErrors))
			// Spin guard: only sleep once errors come back-to-back with no item
			// in between (a source stuck returning the same error). This never
			// fires for sources that keep making progress between errors.
			if consecutiveErrors >= spinGuardThreshold {
				select {
				case <-ctx.Done():
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
			continue
		}
		consecutiveErrors = 0

		if !e.sendItem(ctx, item, itemCh) {
			return
		}
	}
}

// drainFeedback non-blocking drains all pending feedback items into itemCh.
func (e *Executor) drainFeedback(ctx context.Context, itemCh chan<- *work.WorkItem) {
	for {
		select {
		case fb := <-e.pool.feedbackCh:
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
	// Always filter static files before HTTP fetch — EXCEPT object-storage
	// assets, which are kept and recorded metadata-only (HEAD, body stripped)
	// so the CDN traversal modules can probe storage-fronted static URLs.
	if e.cfg.StaticFileMatcher != nil &&
		e.cfg.StaticFileMatcher.IsStaticFile(item.Request.Request().Path()) {
		if e.staticStorageCandidate(item.Request) {
			item.StaticMeta = true
		} else {
			item.Complete()
			return true
		}
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
			e.pool.inFlight.Add(1)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.AcquireWorker()
			}
			e.processItem(ctx, item)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.ReleaseWorker()
			}
			e.pool.inFlight.Add(-1)
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
			active := int(e.pool.activeWorkers.Load())

			// Scale up: queue > 75% full and we have headroom
			if queueDepth > queueCap*3/4 && active < e.pool.maxWorkers {
				workerID := nextID
				nextID++
				e.pool.activeWorkers.Add(1)
				wg.Go(func() {
					e.worker(ctx, workerID, itemCh)
					e.pool.activeWorkers.Add(-1)
				})
				zap.L().Debug("Adaptive scaling: spawned worker",
					zap.Int("worker_id", workerID),
					zap.Int("active_workers", int(e.pool.activeWorkers.Load())))
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
	var ok bool
	if item.StaticMeta {
		// Object-storage metadata items record the URL + headers (status,
		// content-type, content-length), never the (large/binary) object body:
		// a HEAD, falling back to a ranged GET for origins that reject HEAD.
		req, httpResp, pooledBuf, ok = e.fetchStaticMetaResponse(ctx, req)
	} else {
		req, httpResp, pooledBuf, ok = e.fetchBaselineResponse(ctx, req)
	}
	if !ok {
		return
	}

	// Learn object-storage-backed hosts from any storage-signalled response so
	// the static-file carve-out keeps sibling assets on the same host.
	if req.Service() != nil && storagesig.ResponseHasStorageSignal(httpResp) {
		e.markStorageHost(req.Service().Host())
	}

	// Static metadata items: keep only genuine storage assets, body stripped.
	if item.StaticMeta {
		if !storagesig.ResponseHasStorageSignal(httpResp) &&
			!storagesig.LooksLikeStorageObjectPath(req.Request().Path()) {
			return // storage hint did not pan out; drop without recording
		}
		httpResp.TruncateBody(0)
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
		e.caches.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)
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

// fetchStaticMetaResponse fetches headers-only metadata for an object-storage
// static asset: a HEAD request, falling back to a ranged GET (Range: bytes=0-0)
// when the origin rejects HEAD (405/501). The full object body is never
// downloaded; callers still strip whatever minimal body returns.
func (e *Executor) fetchStaticMetaResponse(ctx context.Context, base *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, *httpmsg.HttpResponse, []byte, bool) {
	req, httpResp, pooledBuf, ok := e.fetchBaselineResponse(ctx, staticMetaProbe(base, "HEAD", ""))
	if ok && !headRejectedStatus(httpResp.StatusCode()) {
		return req, httpResp, pooledBuf, true
	}
	// Release the HEAD buffer before retrying with a ranged GET.
	if pooledBuf != nil {
		putResponseBuffer(pooledBuf)
	}
	return e.fetchBaselineResponse(ctx, staticMetaProbe(base, "GET", "bytes=0-0"))
}

// staticMetaProbe builds a header-only probe request from base: a method
// override plus an optional Range header. Returns base unchanged on parse error.
func staticMetaProbe(base *httpmsg.HttpRequestResponse, method, rangeHdr string) *httpmsg.HttpRequestResponse {
	raw := base.Request().Raw()
	if m, err := httpmsg.SetMethod(raw, method); err == nil {
		raw = m
	}
	if rangeHdr != "" {
		if h, err := httpmsg.AddHeader(raw, "Range", rangeHdr); err == nil {
			raw = h
		}
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return base
	}
	return req.WithService(base.Service())
}

// headRejectedStatus reports whether a status indicates the origin refused the
// HEAD method, so a ranged GET retry is warranted.
func headRejectedStatus(status int) bool {
	return status == 405 || status == 501
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

	// Compose headers+body directly into one pooled buffer. Using
	// FullResponseBytes() here would allocate a throwaway full-size copy that we
	// then copy *again* into the pooled buffer — two full-size allocations per
	// record on the hot path. HeadersBytes()/BodyBytes() alias the chain's own
	// buffers (valid until Close()), so a single splice into the pool suffices.
	headers := respChain.HeadersBytes()
	body := respChain.BodyBytes()
	rawResponseCopy := getResponseBuffer(len(headers) + len(body))
	copy(rawResponseCopy, headers)
	copy(rawResponseCopy[len(headers):], body)
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
	// One context-bound requester clone per item, shared by every active-module
	// task below — they all run under the same PHASE ctx. Cloning inside each task
	// (the old behavior) allocated a Requester copy on the hottest fan-out loop.
	// Bound to the phase context, NOT any per-module timeout, so the shared request
	// clusterer isn't poisoned by one module's timeout (see runActiveWithTimeout).
	var reqClient *http.Requester
	if e.httpClient != nil {
		reqClient = e.httpClient.WithContext(ctx)
	}

	// conc.WaitGroup automatically catches panics per goroutine and re-panics
	// on Wait(), which is caught by the top-level recoverFromPanic("processItem").
	var g conc.WaitGroup
	e.runActivePerHost(ctx, reqClient, req, filter, elig, &g)
	e.runActivePerRequest(ctx, reqClient, req, filter, elig, &g)
	e.runActivePerInsertionPoint(ctx, reqClient, req, filter, elig, &g)
	g.Wait()
}

// saveToDatabase stores the request/response record in the database if enabled.
func (e *Executor) saveToDatabase(ctx context.Context, item *work.WorkItem, req *httpmsg.HttpRequestResponse) {
	if e.repo == nil {
		return
	}
	if item.RecordUUID != "" {
		// Item maps to an existing DB record — reuse its UUID (skip insert) so
		// findings link to it instead of creating a duplicate record.
		e.caches.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)

		// Backfill the response for records stored as request-only stubs (e.g.
		// endpoints synthesized from a discovered OpenAPI/Swagger spec). The
		// executor just fetched a real baseline to scan the endpoint; persist it
		// so the route shows its actual status/body instead of staying at
		// status 0 with an empty response in the traffic view. item.Request is
		// the untouched stub (fetchBaselineResponse returns a copy via
		// WithResponse), so a nil response there marks a stub even though req now
		// carries one. The repo update is a no-op once the record has a response.
		if item.Request != nil && item.Request.Response() == nil && req.Response() != nil {
			if err := e.repo.BackfillRecordResponse(ctx, item.RecordUUID, req); err != nil {
				zap.L().Debug("Failed to backfill stub record response",
					zap.String("uuid", item.RecordUUID), zap.Error(err))
			}
		}
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
	e.caches.requestUUIDs.Store(req.Request().ID(), recordUUID)
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
		if !e.passesContentClassFilter(m, item) {
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

// maxModuleTimeout returns the longest a single module call can legitimately
// run: the larger of the base active/passive timeouts and the largest
// TimeoutHint any registered module advertises (both scan wrappers raise their
// per-call timeout to the hint via modules.TimeoutHinter). The drain stall cap
// is derived from this so a legitimately slow module — e.g. diffscan timing
// analysis that raises its bound past the base timeout — running during the
// post-EOF drain is not mistaken for a wedged worker.
func (e *Executor) maxModuleTimeout() time.Duration {
	maxT := e.activeModuleTimeout()
	if pt := e.passiveModuleTimeout(); pt > maxT {
		maxT = pt
	}
	consider := func(m modules.Module) {
		if hinter, ok := m.(modules.TimeoutHinter); ok {
			if hint := hinter.TimeoutHint(); hint > maxT {
				maxT = hint
			}
		}
	}
	for _, m := range e.activeModules {
		consider(m)
	}
	for _, m := range e.passiveModules {
		consider(m)
	}
	return maxT
}

// feedbackDrainMaxStall returns the hard cap on how long the post-EOF feedback
// drain will wait while workers are still in flight but making no forward
// progress. The idle-detection branch in the drain loop only fires once
// inFlight reaches 0, so without this bound a module that ignores context
// cancellation (and never returns) would hang the drain — and the whole scan —
// indefinitely. Defaults to twice the longest legitimate module call
// (maxModuleTimeout, which includes per-module TimeoutHints) so a slow-but-not-
// wedged module isn't abandoned, while a truly stuck worker still trips the cap.
func (e *Executor) feedbackDrainMaxStall() time.Duration {
	if e.cfg.FeedbackDrainMaxStall > 0 {
		return e.cfg.FeedbackDrainMaxStall
	}
	return 2 * e.maxModuleTimeout()
}

// timerPool recycles the watchdog timers used by the per-module timeout wrappers
// so each module call doesn't allocate a fresh runtime timer — these wrappers run
// on the hottest per-module dispatch loop (every active and passive call). A
// timer taken from the pool is always Reset before use and Stopped/drained before
// being returned, so a recycled timer never carries a stale fire.
var timerPool = sync.Pool{
	New: func() any {
		t := time.NewTimer(time.Hour)
		t.Stop()
		return t
	},
}

// acquireTimer returns a pooled timer armed to fire after d.
func acquireTimer(d time.Duration) *time.Timer {
	t := timerPool.Get().(*time.Timer)
	t.Reset(d)
	return t
}

// releaseTimer stops t and returns it to the pool, draining a pending fire so the
// next Reset starts clean.
func releaseTimer(t *time.Timer) {
	if !t.Stop() {
		// Already fired (or was already stopped): drain a queued value if the
		// select didn't consume it. The non-blocking default handles the case
		// where the firing value was already received.
		select {
		case <-t.C:
		default:
		}
	}
	timerPool.Put(t)
}

// callGuard sets up the per-module timeout guard shared by the active and passive
// wrappers: a cancel-only child context plus a pooled watchdog timer armed for
// timeout. It returns the child context to hand the scan function, the timer's
// fire channel (the genuine per-call timeout — selected separately from
// ctx.Done(), which is parent cancellation), and a stop func the caller defers to
// cancel the context and return the timer to the pool. WithCancel + a pooled timer
// avoids the fresh runtime timer that context.WithTimeout allocates on every call
// (these wrappers run on the hottest per-module dispatch loop). The child context
// is intentionally NOT bound into the requester — that is phase-context-bound in
// runActiveStage — so one module's timeout never cancels a request the clusterer
// shares with others.
func callGuard(ctx context.Context, timeout time.Duration, needCancel bool) (callCtx context.Context, timeoutC <-chan time.Time, stop func()) {
	t := acquireTimer(timeout)
	if !needCancel {
		// Non-contextual module: its scanFn ignores the handed context (it runs
		// against the phase-bound requester / e.scanCtx), so the WithCancel child
		// would never be observed. Skip that per-call heap allocation; the pooled
		// timer still enforces the per-module timeout via timeoutC.
		return ctx, t.C, func() { releaseTimer(t) }
	}
	callCtx, cancel := context.WithCancel(ctx)
	return callCtx, t.C, func() {
		cancel()
		releaseTimer(t)
	}
}

// moduleCallResult carries a module scan function's return across the watchdog
// goroutine. Shared by the active and passive wrappers so they can use one
// channel pool.
type moduleCallResult struct {
	events []*output.ResultEvent
	err    error
}

// moduleResultChanPool recycles the 1-slot result channels used by the per-module
// timeout wrappers — the single highest-frequency allocation site in the
// dispatch loop (one per active and passive module call). A channel is returned
// to the pool ONLY on the normal completion path, where the watchdog goroutine
// has finished sending and will never touch it again; on the timeout / parent-
// cancel paths the abandoned goroutine still owns the channel (it sends when the
// slow scanFn eventually returns), so those channels are left for the GC.
var moduleResultChanPool = sync.Pool{
	New: func() any { return make(chan moduleCallResult, 1) },
}

// runPassiveWithTimeout executes a passive module scan function with a timeout guard.
func (e *Executor) runPassiveWithTimeout(
	ctx context.Context,
	scanFn func(context.Context) ([]*output.ResultEvent, error),
	module modules.PassiveModule,
	item *httpmsg.HttpRequestResponse,
) []*output.ResultEvent {
	// Fast exit when the scan/phase context is already cancelled: skip the
	// watchdog goroutine + pooled timer + result channel entirely. During
	// shutdown or after a phase deadline, many modules are still dispatched and
	// would each otherwise spawn a doomed goroutine.
	if ctx.Err() != nil {
		return nil
	}

	timeout := e.passiveModuleTimeout()
	// Allow modules to override with a per-module timeout hint
	if hinter, ok := module.(modules.TimeoutHinter); ok {
		if hint := hinter.TimeoutHint(); hint > 0 {
			timeout = hint
		}
	}

	// Only contextual passive modules observe the handed context, so only they
	// need a cancellable child (see callGuard).
	_, needCancel := module.(modules.ContextualPassiveModule)
	callCtx, timeoutC, stop := callGuard(ctx, timeout, needCancel)
	defer stop()

	start := time.Now()
	ch := moduleResultChanPool.Get().(chan moduleCallResult)
	go func() {
		events, err := scanFn(callCtx)
		ch <- moduleCallResult{events, err}
	}()

	select {
	case r := <-ch:
		moduleResultChanPool.Put(ch) // goroutine done; channel drained and safe to reuse
		e.moduleMetrics.Record(module.ID(), time.Since(start), len(r.events), r.err)
		if r.err != nil {
			zap.L().Debug("Passive module error",
				zap.String("module", module.ID()),
				zap.Error(r.err))
			return nil
		}
		return r.events
	case <-timeoutC:
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		zap.L().Warn("Passive module timed out — skipping",
			zap.String("module", module.ID()),
			zap.String("url", item.Target()),
			zap.Duration("timeout", timeout))
		return nil
	case <-ctx.Done():
		// Parent cancellation (scan shutdown / phase deadline) — not a per-module
		// timeout, so stay quiet; the scan is ending.
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
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
	// Fast exit when the scan/phase context is already cancelled: skip the
	// watchdog goroutine + pooled timer + result channel entirely (mirrors the
	// <-ctx.Done() arm below). Avoids spawning doomed goroutines for the many
	// modules still dispatched during shutdown or after a phase deadline.
	if ctx.Err() != nil {
		return nil, false
	}

	timeout := e.activeModuleTimeout()
	// Allow modules to override with a per-module timeout hint (e.g. diffscan
	// timing analysis legitimately needs longer than the global default).
	if hinter, ok := module.(modules.TimeoutHinter); ok {
		if hint := hinter.TimeoutHint(); hint > timeout {
			timeout = hint
		}
	}

	// Only contextual active modules observe the handed context, so only they
	// need a cancellable child (see callGuard).
	_, needCancel := module.(modules.ContextualActiveModule)
	callCtx, timeoutC, stop := callGuard(ctx, timeout, needCancel)
	defer stop()

	start := time.Now()
	ch := moduleResultChanPool.Get().(chan moduleCallResult)
	go func() {
		events, err := scanFn(callCtx)
		ch <- moduleCallResult{events, err}
	}()

	select {
	case r := <-ch:
		moduleResultChanPool.Put(ch) // goroutine done; channel drained and safe to reuse
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
	case <-timeoutC:
		// Genuine per-module timeout. Count it only when the parent is still alive,
		// so cancelling a scan with many modules in flight doesn't inflate the
		// status-line count with modules that were merely interrupted at the same
		// instant.
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		if ctx.Err() == nil {
			e.recordModuleTimeout()
		}
		// Logged at debug level: a per-skip WARN floods stderr on slow targets.
		// The running count is surfaced in the status line via OnStatus instead.
		zap.L().Debug("Active module timed out — skipping",
			zap.String("module", module.ID()),
			zap.String("url", item.Target()),
			zap.Duration("timeout", timeout))
		return nil, false
	case <-ctx.Done():
		// Parent cancellation (Ctrl-C, --scanning-max-duration, phase deadline) —
		// an interruption, not a timed-out module, so it is not counted.
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		return nil, false
	}
}

// recordModuleTimeout increments the active-module timeout counter — the shared
// phase counter when one was supplied via ExecutorConfig.ModuleTimeouts (so the
// total accumulates across a multi-round phase's per-round executors), otherwise
// this executor's own tally.
func (e *Executor) recordModuleTimeout() {
	if e.cfg.ModuleTimeouts != nil {
		e.cfg.ModuleTimeouts.Add(1)
		return
	}
	e.moduleTimeouts.Add(1)
}

// timedOutCount returns the active-module timeout total reported in the status
// line: the shared phase counter when present, else this executor's own tally.
func (e *Executor) timedOutCount() int64 {
	if e.cfg.ModuleTimeouts != nil {
		return e.cfg.ModuleTimeouts.Load()
	}
	return e.moduleTimeouts.Load()
}

// isLevelDBClosed returns true if the error is caused by a closed LevelDB instance,
// which happens during shutdown when the dedup manager is closed before workers finish.
//
// The typed sentinel (errors.Is) is the primary check and survives any future
// change to goleveldb's error message, but we keep a string fallback because the
// error reaches us through module/storage call chains that may format it with %v
// (non-wrapping), which defeats errors.Is. Matching both is strictly more robust
// than either alone.
func isLevelDBClosed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, leveldb.ErrClosed) || strings.Contains(err.Error(), "leveldb: closed")
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
	val, _ := e.caches.requestUUIDs.Load(requestHash)
	return val
}
