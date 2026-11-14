package core

import (
	"context"
	"fmt"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// Bounds on the post-EOF drain's poll interval. The drain starts at
// drainPollMin and doubles up to drainPollMax, so a phase whose workers have
// already finished notices immediately instead of waiting out a fixed tick,
// while a long drain settles onto a cheap interval. See the drain loop in
// Execute.
const (
	drainPollMin = time.Millisecond
	drainPollMax = 50 * time.Millisecond
)

// Executor orchestrates scanning with worker pool.
type Executor struct {
	cfg ExecutorConfig
	// methodPolicySkips counts records kept out of the active stage by the
	// traffic policy (SAFE-8, skip reason method_policy).
	methodPolicySkips atomic.Int64
	source            source.InputSource
	activeModules     []modules.ActiveModule
	passiveModules    []modules.PassiveModule
	httpClient        *http.Requester
	scanCtx           *modules.ScanContext
	hooks             HookRunner // Optional: pre/post hooks

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
	// moduleErrs counts this executor's failed module calls per module id
	// (see noteModuleError).
	moduleErrs moduleErrorCounts

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

	// stored and storeFailed count what became of each item's PRIMARY record:
	// stored is one that is in the database when the item is done with (newly
	// written, or matched to the row it came from), storeFailed is one whose
	// write returned an error. Redirect hops and finding evidence are not
	// counted — the question these answer is "how many of my inputs are in the
	// store", and a chain is one input.
	//
	// They exist because neither Processed() nor Responded() can answer it, and
	// `vigolium ingest` reported Processed() as "records ingested": against a
	// host that no longer resolves that printed a full count over an empty
	// table. Attempted, answered and stored are three different numbers and the
	// only honest one for an ingest is the third.
	stored      atomic.Int64
	storeFailed atomic.Int64

	// drops says WHY an item stored nothing: one counter per DropReason plus the
	// first few examples. Without it an ingest that stored 0 of 40 could only
	// say "no response to store" whether the host was dead, every answer was a
	// WAF page, or the budget ran out — and each of those has a different fix.
	drops dropLedger

	// responded counts input items for which an HTTP response was actually
	// received - one per item, not per redirect hop or retry.
	//
	// It exists because Processed() cannot answer that question: the stats
	// tracker counts every item that completes, and processItemDetached
	// returns early on a transport failure, a dropped storage-metadata probe, or
	// a pre-hook rejection. On a normal scan the difference is noise; on a host
	// sweep, where dead hosts are a large fraction of the input, reporting
	// Processed() as "targets answered" reports every unreachable host as a
	// success. An HTTP error status is an answer; a connection failure is not.
	responded atomic.Int64

	// scopeRejected counts input items the scope matcher dropped: before the
	// request was sent (sendItem's pre-send check) or after the baseline came
	// back (persistAndCheckScope). One per item. Without it a scan whose every
	// input was out of scope looked exactly like one whose inputs were all
	// scanned clean.
	scopeRejected atomic.Int64

	// baselineFailures keeps the most recent baseline-fetch transport failures,
	// classified, so "nothing answered" can say why. Bounded; see
	// recordBaselineFailure.
	baselineFailures baselineFailureRing

	// quarantine counts input items dropped because their host:port was
	// quarantined by the dead-host breaker. Per run: reset by Execute.
	quarantine quarantineSkips

	// reportBase holds the cumulative counters' values at the start of the
	// current Execute, so Report() describes this run only (see Execute).
	reportBase struct{ responded, scopeRejected int64 }

	// Database storage (optional)
	repo          *database.Repository
	recordWriter  *database.RecordWriter  // batched record writer (preferred over repo.SaveRecord)
	findingWriter *database.FindingWriter // batched finding writer (preferred over repo.SaveFinding)
	scanUUID      string
	projectUUID   string

	// corroboration collects database-error leaks observed in any active module's
	// 5xx probe response (via the requester response observer), emitted at phase end.
	corroboration *probeCorroboration

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

	// report records whether this Execute call covered its whole input. Written
	// only by the Execute goroutine (the drain loop and the shutdown sequence all
	// run there), read by Report() after Execute returns — so the return itself is
	// the synchronisation. unacked is the exception: workers write it, so it is
	// atomic and lives outside the struct.
	report  ExecutionReport
	unacked atomic.Int64
}

// perHostClaimCacheSize bounds each per-host claim LRU. With ~31 per-host
// modules this covers roughly 500 distinct hosts before the oldest claims
// evict — large enough that re-firing is rare during a single host's scan
// window, small enough that the maps can't grow unbounded over a multi-day
// server run.
const perHostClaimCacheSize = 16384

// hostClaimKey identifies a (module, origin) per-host claim, where origin is the
// canonical scheme://host:port identity (see originKeyFromItem) rather than a
// bare hostname — so the same hostname exposed on multiple ports/schemes doesn't
// collapse into one claim and suppress a ScanPerHost module on the other origins.
// Using a struct key instead of a "moduleID:origin" string avoids allocating a
// fresh string on every request for every per-host module (the claim is checked
// per request but only won once per pair) — the struct is hashed/compared in
// place by the LRU's map.
type hostClaimKey struct {
	moduleID string
	origin   string
}

// scanCaches groups the Executor's per-scan lookup and dedup state. Every field
// is safe for concurrent use (bounded LRU / sharded map / sync.Map).
type scanCaches struct {
	// ipCache is an insertion-point cache keyed by request SHA-256 hash, bounded
	// by both entry count and retained bytes. Avoids redundant AnalyzeRequest()
	// calls for repeated/retried requests.
	ipCache *InsertionPointCache

	// requestUUIDs tracks the database record UUID for each HttpRequestResponse
	// (for linking findings). Key: request hash, value: database record UUID.
	requestUUIDs *shardedMap

	// admission holds the per-module finding cap and the set of already-admitted
	// root-cause identities. Executor-local unless the caller supplies a shared
	// one through ExecutorConfig.FindingAdmission — see FindingAdmission.
	admission FindingAdmission

	// perHostActiveClaimed / perHostPassiveClaimed ensure per-host modules run
	// exactly once per (module, host) pair even with concurrent workers.
	// Key: hostClaimKey{moduleID, origin} → struct{}. Bounded LRUs rather than
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
	// inFlight counts OUTSTANDING items: incremented when a worker dequeues an
	// item, decremented when the item's last active task finishes (see
	// itemTracker). Not busy workers — a worker hands its item's tasks off and
	// goes back to the queue. The feedback drain loop treats inFlight == 0 plus
	// an empty feedback channel as idle, which still holds because feedback
	// only comes from items that are outstanding.
	inFlight atomic.Int64

	// itemSlots caps outstanding items (ExecutorConfig.MaxOutstandingItems).
	// A worker takes a slot before it dequeues and the item's tracker gives it
	// back on completion, so slow detached tasks turn into backpressure on
	// itemCh instead of an unbounded number of open items (each holding a live
	// response buffer).
	itemSlots chan struct{}

	// taskWG tracks every detached active-module task so Execute can join them
	// at shutdown (bounded by workerExitGrace).
	taskWG sync.WaitGroup

	// feedbackCh lets modules inject discovered requests back into the pipeline;
	// feeder wraps it to track drop metrics. activeTaskSem bounds concurrent
	// active-module tasks.
	feedbackCh    chan *work.WorkItem
	feeder        *executorFeeder
	activeTaskSem chan struct{}
	// passiveTaskSem bounds concurrent parallel-passive goroutines GLOBALLY across
	// all record workers. Without it, ParallelPassive spawns one goroutine per
	// eligible passive module for every in-flight record (workers × modules), which
	// can reach thousands; this caps the fan-out to a fixed budget.
	passiveTaskSem chan struct{}
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

	var ipCache *InsertionPointCache
	if cfg.IPCache != nil {
		ipCache = cfg.IPCache
	} else {
		ipCacheSize := cfg.IPCacheSize
		if ipCacheSize <= 0 {
			// Auto-size based on input source count for better cache utilization.
			// This is an entry cap only — retained bytes are bounded separately by
			// the cache itself (ipCacheMaxBytes), since entry size varies by four
			// orders of magnitude between a short GET and a large nested body.
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
		ipCache = NewInsertionPointCache(ipCacheSize)
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
		corroboration:  newProbeCorroboration(),
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

	maxOutstanding := cfg.MaxOutstandingItems
	if maxOutstanding <= 0 {
		maxOutstanding = cfg.Workers * defaultOutstandingItemsPerWorker
	}
	e.pool.itemSlots = make(chan struct{}, maxOutstanding)

	// Global budget for parallel-passive goroutines. Passive work is CPU-bound, so
	// the bound only needs to keep cores busy — sized like the active budget so the
	// fan-out is capped to hundreds instead of workers × registered-modules.
	passiveTaskLimit := cfg.Workers * 8
	if passiveTaskLimit < 64 {
		passiveTaskLimit = 64
	}
	e.pool.passiveTaskSem = make(chan struct{}, passiveTaskLimit)

	// Wire risk/surface score updaters, remarks and technology annotators,
	// record-response rewriter, and request UUID resolver into ScanContext
	if e.scanCtx != nil && cfg.Repository != nil {
		e.scanCtx.RiskScoreUpdater = &repoRiskScoreUpdater{repo: cfg.Repository}
		e.scanCtx.SurfaceScoreUpdater = &repoSurfaceScoreUpdater{repo: cfg.Repository}
		e.scanCtx.RemarksAnnotator = &repoRemarksAnnotator{repo: cfg.Repository}
		e.scanCtx.TechAnnotator = &repoTechnologyAnnotator{repo: cfg.Repository}
		e.scanCtx.RecordRewriter = &repoRecordResponseRewriter{repo: cfg.Repository}
		e.scanCtx.ArtifactWriter = &repoDerivedArtifactWriter{repo: cfg.Repository}
		e.scanCtx.RequestUUIDResolver = e
	}

	// Expose a read-only scope check so modules can tell a scan-target host from a
	// third-party one (e.g. js-beautify only skips vendor scripts that are not the
	// target). Independent of Repository (works for stateless scans too).
	if e.scanCtx != nil && cfg.ScopeMatcher != nil {
		e.scanCtx.Scope = &executorScopeChecker{matcher: cfg.ScopeMatcher}
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
	e.scanCtx.AllowRiskyPayloads = cfg.AllowRiskyPayloads
	e.scanCtx.NoParamDedup = cfg.NoParamDedup
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

// Execute runs the scan. Blocks until all inputs are processed or context is cancelled.
func (e *Executor) Execute(ctx context.Context) (bool, error) {
	if !e.running.CompareAndSwap(false, true) {
		return false, fmt.Errorf("executor already running")
	}
	defer e.running.Store(false)
	notifyExecutorObserver(ctx, e)

	// Fresh report per run. An executor is normally single-use (dynamic
	// assessment builds one per feedback round), but a reused one must not
	// inherit a previous run's abandonment.
	e.report = ExecutionReport{}
	e.unacked.Store(0)
	// Responded() and the scopeRejected counter stay cumulative for the
	// executor's lifetime; the report's copies are this run's share.
	e.reportBase.responded = e.responded.Load()
	e.reportBase.scopeRejected = e.scopeRejected.Load()
	e.quarantine.reset()

	// Observe server-error probe responses so a leaked database error surfaced by
	// ANY module's probe is corroborated even when the sending module didn't check
	// for it. Installed for this run only; cleared on return so a later phase's
	// traffic on the shared requester isn't observed into a stale collector.
	if e.httpClient != nil {
		e.httpClient.SetResponseObserver(e.observeProbeResponse)
		defer e.httpClient.SetResponseObserver(nil)
	}

	// Give this execution its own cancellation scope, ALWAYS — not only when a
	// phase timeout is configured. Background loops below (the status callback)
	// used to exit on the caller's ctx alone, so with MaxDuration == 0 a normal
	// EOF return left them running: dynamic assessment builds one executor per
	// round against a phase-long context, so each finished round leaked a ticker
	// goroutine that kept firing OnStatus — reporting a completed executor's
	// metrics, and reading the database — until the whole phase ended.
	execCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	ctx = execCtx

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
			firstTickCh = time.NewTimer(e.cfg.FirstStatusInterval).C
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

		statusDone := make(chan struct{})
		go func() {
			defer close(statusDone)
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
		// Join before returning, so no status line can be emitted after Execute
		// has handed back its result. cancelExec runs first (defers are LIFO
		// relative to this one being registered later), releasing the loop.
		defer func() {
			cancelExec()
			<-statusDone
		}()
	}

	var wg conc.WaitGroup
	itemCh := make(chan *work.WorkItem, e.cfg.Workers*2)

	// stopWorkers is closed right after itemCh so a worker parked waiting for
	// an outstanding-item slot (every slot held by a stuck task) still exits.
	stopWorkers := make(chan struct{})
	for i := 0; i < e.cfg.Workers; i++ {
		workerID := i
		wg.Go(func() {
			e.worker(ctx, workerID, itemCh, stopWorkers)
		})
	}

	e.report.StoppedEarly = !e.feedItems(ctx, itemCh)

	// After source EOF, drain remaining feedback items from in-flight workers.
	// Wait until all workers finish (inFlight == 0) and the feedback channel is empty.
	// When FeedbackDrainTimeout is configured, require the executor to remain idle
	// for that duration before completing the drain.
	// Backing-off poll rather than a fixed tick; see drainPollMin/drainPollMax.
	drainDelay := drainPollMin
	drainTimer := time.NewTimer(drainDelay)
	defer drainTimer.Stop()
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
		case <-drainTimer.C:
			// Monotonic backoff. Resetting the delay whenever feedback arrives
			// looks like "poll tightly again while there is work", but it is the
			// opposite of what the drain wants: a busy drain would knock the
			// interval back to 1ms on every item and settle near 500 wakeups a
			// second, where the fixed tick it replaced did 20. The fast-finish
			// win is entirely in the first few ticks, which monotonic backoff
			// already gives.
			drainDelay = min(drainDelay*2, drainPollMax)
			drainTimer.Reset(drainDelay)
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
					e.report.DrainStalled = true
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

	close(itemCh)
	close(stopWorkers)

	// Bound the wait for workers, then their detached tasks, to exit. Healthy
	// workers return immediately once itemCh is closed, and on a clean drain
	// every task has already finished (inFlight reached 0); on cancellation a
	// task returns as soon as its module wrapper observes ctx.Done. Only code
	// that ignores cancellation lingers. Without a bound, that single goroutine
	// would hang the wait — and the whole scan — forever (the drain stall cap
	// above only breaks the drain loop; this is where an unresponsive worker or
	// task would otherwise re-block). Tasks are joined only AFTER the workers,
	// because workers are the only goroutines that start tasks (taskWG.Add must
	// not race Wait). We wait in a goroutine and forward any captured panic so
	// conc's re-panic semantics are preserved on the normal path; on timeout we
	// log loudly and proceed, leaking the stuck goroutines rather than hanging.
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
		e.pool.taskWG.Wait()
	}()
	exitGrace := e.workerExitGrace()
	workersExited := true
	select {
	case <-waitDone:
		if r := waitPanic.Load(); r != nil {
			panic(r)
		}
	case <-time.After(exitGrace):
		workersExited = false
		e.report.WorkersAbandoned = true
		zap.L().Warn("abandoning scan worker(s) or active task(s) that did not exit within the shutdown grace to avoid hanging the scan; leaking goroutine(s)",
			zap.Int64("in_flight", e.pool.inFlight.Load()),
			zap.Duration("worker_exit_grace", exitGrace))
	}

	// Passive-module flush must only run once every worker and task has exited.
	// Flusher / BatchFlusher modules aggregate cross-request state that a worker
	// mutates from ScanPerRequest, and tasks feed the result pipeline; if we
	// abandoned a still-running one above, flushing here would race it on the
	// module's buffer and the result pipeline.
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
					r.ModuleType = database.ModuleTypePassive
					r.FindingSource = database.FindingSourceDynamicAssessment
					// Deferred batch findings carry their own request; no baseline
					// item is in scope here, so take the standard parse/save path.
					// The per-module cap is enforced once inside emitResult →
					// admitFinding; do NOT pre-check moduleFindingAllowed here or each
					// finding would consume the cap twice (a cap of 15 admits ~7).
					e.emitResult(ctx, r, nil, nil)
				}
			}
		}
		// Emit corroboration observations harvested from probe traffic. Same
		// workers-exited guard as the passive flush: the observer runs on request
		// goroutines, so draining before they exit could race a live append.
		e.drainProbeCorroboration(ctx)
	} else {
		e.report.DeferredFlushSkipped = true
		zap.L().Warn("skipping passive-module flush after abandoning workers; deferred findings (e.g. secret detection, anomaly ranking) may be incomplete")
	}

	// Flush OAST service: wait for grace period to catch late callbacks
	if e.cfg.OASTService != nil {
		e.cfg.OASTService.Flush()
	}

	e.logInsertionPointCacheStats()

	return e.results.Load(), nil
}

// logInsertionPointCacheStats reports the insertion-point cache's behaviour once
// the scan is done. Byte evictions and size rejections are the interesting
// signals: they mean the byte budget, not the entry cap, was the binding limit —
// i.e. this scan's requests were heavy enough to re-derive insertion points that
// a larger budget would have kept.
func (e *Executor) logInsertionPointCacheStats() {
	s := e.caches.ipCache.Stats()
	if s.Hits == 0 && s.Misses == 0 {
		return
	}

	zap.L().Debug("Insertion-point cache",
		zap.Int("entries", s.Entries),
		zap.Int64("retained_mib", s.RetainedBytes>>20),
		zap.Int64("hits", s.Hits),
		zap.Int64("misses", s.Misses),
		zap.Int64("byte_evictions", s.Evictions),
		zap.Int64("size_rejections", s.Rejected))
}
