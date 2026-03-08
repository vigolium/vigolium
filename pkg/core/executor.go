package core

import (
	"context"
	"fmt"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/vigolium/vigolium/pkg/work"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/sourcegraph/conc"
	"go.uber.org/zap"
)

const maxPooledResponseSize = 1 << 20 // 1 MiB

// responseBufferPool recycles byte slices for baseline HTTP response copies,
// reducing GC pressure on the hot path. Buffers larger than maxPooledResponseSize
// are not returned to the pool to prevent bloat.
var responseBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 32*1024) // 32 KiB initial cap
		return &b
	},
}

func getResponseBuffer(n int) []byte {
	bp := responseBufferPool.Get().(*[]byte)
	b := *bp
	if cap(b) >= n {
		return b[:n]
	}
	// Discard too-small buffer; allocate exact size
	return make([]byte, n)
}

func putResponseBuffer(buf []byte) {
	if cap(buf) > maxPooledResponseSize {
		return // Too large — let GC collect it
	}
	buf = buf[:0]
	responseBufferPool.Put(&buf)
}

// moduleFindingTracker tracks finding count and one-time warning for a single module.
type moduleFindingTracker struct {
	count   atomic.Int64
	warned  sync.Once
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
	Workers           int
	OnResult          func(*output.ResultEvent)
	OnTraffic         func(method, url string, statusCode int, contentType string) // Optional: called for each processed item
	Services          *services.Services
	HTTPRequester     *http.Requester
	Repository        *database.Repository // Optional: database storage
	ScanUUID          string
	ProjectUUID       string// Optional: scan session UUID
	Hooks             HookRunner           // Optional: pre/post hooks
	ScopeMatcher      *config.ScopeMatcher // Optional: scope filtering
	ScopeOnIngest     bool                 // When true, skip both save and scan for out-of-scope items
	StaticFileMatcher *config.ScopeMatcher // Optional: always-on static file filtering (independent of ScopeMatcher)
	SkipBaseline      bool                 // When true, skip HTTP fetch if response already attached (Phase 3 DB source)
	OASTProvider          modkit.OASTProvider  // Optional: OAST callback URL generator for blind vuln detection
	OASTService           OASTFlusher          // Optional: OAST service to flush after scanning
	PauseCtrl             *PauseController     // Optional: cooperative pause/resume controller
	MaxFindingsPerModule  int                  // When > 0, suppress findings after this many per module
}

// DefaultExecutorConfig returns sensible defaults.
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		Workers: goruntime.NumCPU(),
	}
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

	running      atomic.Bool
	results      atomic.Bool
	statsTracker *stats.Tracker

	// Insertion point cache: keyed by request SHA-256 hash, bounded LRU.
	// Avoids redundant AnalyzeRequest() calls for repeated/retried requests.
	ipCache *lru.Cache[string, []httpmsg.InsertionPoint]

	// Database storage (optional)
	repo        *database.Repository
	scanUUID    string
	projectUUID string
	// Map to track record UUID for each HttpRequestResponse (for linking findings)
	requestUUIDs *shardedMap // key: request hash, value: database record UUID

	// Per-module finding cap
	moduleFindingCount sync.Map // key: module ID → *moduleFindingTracker
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

	ipCache, _ := lru.New[string, []httpmsg.InsertionPoint](4096)

	e := &Executor{
		cfg:            cfg,
		source:         src,
		activeModules:  activeModules,
		passiveModules: passiveModules,
		httpClient:     cfg.HTTPRequester,
		scanCtx:        scanCtx,
		hooks:          cfg.Hooks,
		repo:           cfg.Repository,
		scanUUID:       cfg.ScanUUID,
		projectUUID:    cfg.ProjectUUID,
		requestUUIDs:   newShardedMap(cfg.Workers),
		ipCache:        ipCache,
	}

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

	// Pre-group modules by scan type
	e.perHostActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeHost)
	e.perRequestActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeRequest)
	e.perIPActive = filterActiveModulesByScanScope(activeModules, modules.ScanScopeInsertionPoint)
	e.perHostPassive = filterPassiveModulesByScanScope(passiveModules, modules.ScanScopeHost)
	e.perRequestPassive = filterPassiveModulesByScanScope(passiveModules, modules.ScanScopeRequest)

	// Always create stats tracker for counting processed items.
	// Periodic printing is only started when ShowStats is enabled (see Execute).
	total := getKnownTotal(src)
	e.statsTracker = stats.New(total, false)

	return e
}

// Processed returns the number of items processed by the executor.
func (e *Executor) Processed() int64 {
	if e.statsTracker != nil {
		return e.statsTracker.Processed()
	}
	return 0
}

// Execute runs the scan. Blocks until all inputs are processed or context is cancelled.
func (e *Executor) Execute(ctx context.Context) (bool, error) {
	if !e.running.CompareAndSwap(false, true) {
		return false, fmt.Errorf("executor already running")
	}
	defer e.running.Store(false)

	// Start periodic stats printing only when ShowStats is enabled
	if e.cfg.Services != nil && e.cfg.Services.Options != nil &&
		e.cfg.Services.Options.ShowStats && !e.cfg.Services.Options.Silent {
		e.statsTracker.Start(ctx)
		defer e.statsTracker.Stop()
	}

	var wg conc.WaitGroup
	itemCh := make(chan *work.WorkItem, e.cfg.Workers*2)

	for i := 0; i < e.cfg.Workers; i++ {
		workerID := i
		wg.Go(func() {
			e.worker(ctx, workerID, itemCh)
		})
	}

	e.feedItems(ctx, itemCh)
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
				e.emitResult(r)
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

		// Always filter static files before HTTP fetch (unconditional)
		if e.cfg.StaticFileMatcher != nil &&
			e.cfg.StaticFileMatcher.IsStaticFile(item.Request.Request().Path()) {
			item.Complete()
			continue
		}

		// Pre-request scope check (host/path only — avoids HTTP call)
		if e.cfg.ScopeMatcher != nil && item.Request.Service() != nil {
			if !e.cfg.ScopeMatcher.InScopeRequest(
				item.Request.Service().Host(),
				item.Request.Request().Path(), "", "") {
				item.Complete()
				continue
			}
		}

		// Per-module filtering via CanProcess() replaces global ShouldSkip
		if e.cfg.Services != nil && e.cfg.Services.HostErrors != nil &&
			e.cfg.Services.HostErrors.Check(item.Request.ID()) {
			item.Complete()
			continue
		}

		select {
		case <-ctx.Done():
			return
		case itemCh <- item:
		}
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
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.AcquireWorker()
			}
			e.processItem(ctx, item)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.ReleaseWorker()
			}
			item.Complete()
			if e.statsTracker != nil {
				e.statsTracker.Increment()
			}
		}
	}
}

// requestEligibility caches common CanProcess checks for a single request.
// This avoids re-parsing the URL and re-checking media/method filters for every module.
type requestEligibility struct {
	baseEligible bool // true when URL parses OK, not media, not skip-method
}

// computeEligibility pre-computes the base CanProcess checks once per request.
func computeEligibility(item *httpmsg.HttpRequestResponse) requestEligibility {
	if item == nil || item.Request() == nil {
		return requestEligibility{}
	}
	urlx, err := item.URL()
	if err != nil {
		return requestEligibility{}
	}
	if utils.IsMediaAndJSURL(urlx.Path) {
		return requestEligibility{}
	}
	method := item.Request().Method()
	switch method {
	case "OPTIONS", "CONNECT", "HEAD", "TRACE":
		return requestEligibility{}
	}
	return requestEligibility{baseEligible: true}
}

// includesBaseCanProcess is an optional interface for active modules.
// Modules whose CanProcess includes the base URL/media/method checks return true (default).
// Modules with fully custom CanProcess override this to return false.
type includesBaseCanProcess interface {
	IncludesBaseCanProcess() bool
}

// includesBase returns true if the module's CanProcess includes the standard base checks.
func includesBase(m modules.ActiveModule) bool {
	if checker, ok := m.(includesBaseCanProcess); ok {
		return checker.IncludesBaseCanProcess()
	}
	return true // default: assumes base is included
}

// activeModuleCanProcess checks whether a module can process the request, using
// the cached eligibility to skip redundant CanProcess calls when the base checks
// would reject the request.
func activeModuleCanProcess(m modules.ActiveModule, item *httpmsg.HttpRequestResponse, elig *requestEligibility) bool {
	if elig.baseEligible {
		// Base passes — still call CanProcess for modules with extra checks
		return m.CanProcess(item)
	}
	// Base fails — only call CanProcess for modules that don't include base checks
	if includesBase(m) {
		return false // base would reject, skip without calling CanProcess
	}
	return m.CanProcess(item)
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

	// Fetch baseline response (skip if SkipBaseline and response already attached)
	var httpResp *httpmsg.HttpResponse
	if e.cfg.SkipBaseline && req.Response() != nil {
		// Response already present from DB source — skip HTTP fetch
		httpResp = req.Response()
	} else {
		respChain, _, err := e.httpClient.Execute(req, http.Options{})
		if err != nil {
			zap.L().Debug("Failed to fetch baseline response, skipping item",
				zap.String("url", req.Target()),
				zap.Error(err))
			return // Skip item - httpClient already tracked host error
		}

		// Extract full response (headers + body) and close immediately
		// CRITICAL: Copy bytes before Close() - buffer is returned to pool
		fullResp := respChain.FullResponse().Bytes()
		rawResponseCopy := getResponseBuffer(len(fullResp))
		copy(rawResponseCopy, fullResp)
		respChain.Close()

		pooledBuf = rawResponseCopy // Track for deferred return to pool

		httpResp = httpmsg.NewHttpResponse(rawResponseCopy)
		req = req.WithResponse(httpResp)
	}

	// Notify traffic callback
	if e.cfg.OnTraffic != nil {
		ct := getHeaderValue(httpResp.Headers(), "Content-Type")
		e.cfg.OnTraffic(req.Request().Method(), req.Target(), httpResp.StatusCode(), ct)
	}

	// Run pre-hooks (may transform request or signal to skip)
	if e.hooks != nil {
		hooked, err := e.hooks.RunPreHooks(req)
		if err != nil {
			zap.L().Debug("Pre-hook error, skipping item",
				zap.String("url", req.Target()), zap.Error(err))
			return
		}
		if hooked == nil {
			zap.L().Debug("Pre-hook filtered out item",
				zap.String("url", req.Target()))
			return
		}
		req = hooked
	}

	// Body size enforcement
	if e.cfg.ScopeMatcher != nil {
		reqBodyLen := len(req.Request().Body())
		respBodyLen := len(httpResp.Body())
		action, maxReq, maxResp := e.cfg.ScopeMatcher.CheckBodySize(reqBodyLen, respBodyLen)

		switch action {
		case config.BodySizeDrop:
			zap.L().Debug("Body size exceeded, dropping item",
				zap.String("url", req.Target()),
				zap.Int("req_body", reqBodyLen),
				zap.Int("resp_body", respBodyLen))
			return
		case config.BodySizeTruncate, config.BodySizeSkipScan:
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

		if action == config.BodySizeSkipScan {
			e.saveToDatabase(item, req)
			return
		}
	}

	// Scope check + database save (single pass)
	if e.cfg.ScopeMatcher != nil {
		// Defensive nil guard — Service() can be nil during shutdown
		if req.Service() == nil {
			return
		}
		inScope := e.cfg.ScopeMatcher.InScopeBytes(
			req.Service().Host(),
			req.Request().Path(),
			httpResp.StatusCode(),
			getHeaderValue(req.Request().Headers(), "Content-Type"),
			getHeaderValue(httpResp.Headers(), "Content-Type"),
			req.Request().Raw(),
			httpResp.Body(),
		)

		if !inScope && e.cfg.ScopeOnIngest {
			return // ScopeOnIngest: drop entirely (no save, no scan)
		}

		e.saveToDatabase(item, req)

		if !inScope {
			return // Saved but not scanned
		}
	} else {
		e.saveToDatabase(item, req)
	}

	elig := computeEligibility(req)
	var filter moduleFilter
	if len(enableModules) == 0 {
		filter = allModulesFilter
	} else {
		filter = newModuleFilter(enableModules)
	}

	// Phase 1: Passive modules (no network I/O — run sequentially)
	e.runPassivePerHost(req, &filter)
	e.runPassivePerRequest(req, &filter)

	// Phase 2: Active modules (network I/O — run categories in parallel)
	// conc.WaitGroup automatically catches panics per goroutine and re-panics
	// on Wait(), which is caught by the top-level recoverFromPanic("processItem").
	var g conc.WaitGroup

	g.Go(func() {
		e.runActivePerHost(req, &filter, &elig)
	})
	g.Go(func() {
		e.runActivePerRequest(req, &filter, &elig)
	})
	g.Go(func() {
		e.runActivePerInsertionPoint(req, &filter, &elig)
	})

	g.Wait()
}

// saveToDatabase stores the request/response record in the database if enabled.
func (e *Executor) saveToDatabase(item *work.WorkItem, req *httpmsg.HttpRequestResponse) {
	if e.repo == nil {
		return
	}
	if item.RecordUUID != "" {
		// Item came from DB watcher — use existing record UUID, skip insert
		e.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)
		return
	}
	recordUUID, err := e.repo.SaveRecord(context.Background(), req, "scanner", e.projectUUID)
	if err != nil {
		zap.L().Debug("Failed to save record to database", zap.Error(err))
		return
	}
	e.requestUUIDs.Store(req.Request().ID(), recordUUID)
}

func (e *Executor) runPassivePerHost(item *httpmsg.HttpRequestResponse, filter *moduleFilter) {
	if len(e.perHostPassive) == 0 {
		return
	}

	for _, module := range e.perHostPassive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !module.CanProcess(item) {
			continue
		}

		results, err := module.ScanPerHost(item, e.scanCtx)
		if err != nil {
			zap.L().Warn("Passive module error",
				zap.String("module", module.ID()),
				zap.Error(err))
			continue
		}

		e.processResults(results, module)
	}
}

func (e *Executor) runPassivePerRequest(item *httpmsg.HttpRequestResponse, filter *moduleFilter) {
	if len(e.perRequestPassive) == 0 {
		return
	}

	for _, module := range e.perRequestPassive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !module.CanProcess(item) {
			continue
		}

		results, err := module.ScanPerRequest(item, e.scanCtx)
		if err != nil {
			zap.L().Warn("Passive module error",
				zap.String("module", module.ID()),
				zap.Error(err))
			continue
		}

		e.processResults(results, module)
	}
}

func (e *Executor) runActivePerHost(item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility) {
	if len(e.perHostActive) == 0 {
		return
	}

	var g conc.WaitGroup
	for _, module := range e.perHostActive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !activeModuleCanProcess(module, item, elig) {
			continue
		}

		mod := module // capture loop variable
		g.Go(func() {
			results, err := mod.ScanPerHost(item, e.httpClient, e.scanCtx)
			if err != nil {
				zap.L().Warn("Active module error",
					zap.String("module", mod.ID()),
					zap.Error(err))
				return
			}
			e.processResults(results, mod)
		})
	}
	g.Wait()
}

func (e *Executor) runActivePerRequest(item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility) {
	if len(e.perRequestActive) == 0 {
		return
	}

	var g conc.WaitGroup
	for _, module := range e.perRequestActive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !activeModuleCanProcess(module, item, elig) {
			continue
		}

		mod := module // capture loop variable
		g.Go(func() {
			results, err := mod.ScanPerRequest(item, e.httpClient, e.scanCtx)
			if err != nil {
				zap.L().Warn("Active module error",
					zap.String("module", mod.ID()),
					zap.Error(err))
				return
			}
			e.processResults(results, mod)
		})
	}
	g.Wait()
}

func (e *Executor) runActivePerInsertionPoint(item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility) {
	if len(e.perIPActive) == 0 {
		return
	}

	if item.Request() == nil || len(item.Request().Raw()) == 0 {
		return
	}

	// Cache lookup by request hash (same SHA-256 used by HttpRequest.ID())
	key := item.Request().ID()
	allPoints, ok := e.ipCache.Get(key)
	if !ok {
		var err error
		allPoints, err = httpmsg.CreateAllInsertionPoints(item.Request().Raw(), true)
		if err != nil {
			zap.L().Debug("Failed to create insertion points", zap.Error(err))
			return
		}
		e.ipCache.Add(key, allPoints)
	}

	// Single WaitGroup for all (module × insertion-point) pairs.
	// This removes N-1 synchronization barriers (where N = number of IPs),
	// allowing cross-IP parallelism bounded by the worker pool.
	var g conc.WaitGroup

	for _, ip := range allPoints {
		for _, module := range e.perIPActive {
			if !filter.allows(module.ID()) {
				continue
			}
			if !activeModuleCanProcess(module, item, elig) {
				continue
			}
			if !module.AllowedInsertionPointTypes().Contains(ip.Type()) {
				continue
			}

			mod, pt := module, ip // capture loop variables
			g.Go(func() {
				results, err := mod.ScanPerInsertionPoint(item, pt, e.httpClient, e.scanCtx)
				if err != nil {
					zap.L().Warn("Active module error",
						zap.String("module", mod.ID()),
						zap.String("param", pt.Name()),
						zap.Error(err))
					return
				}
				e.processResults(results, mod)
			})
		}
	}

	g.Wait()
}

func (e *Executor) processResults(results []*output.ResultEvent, m modules.Module) {
	moduleType := database.ModuleTypeActive
	if _, ok := m.(modules.PassiveModule); ok {
		moduleType = database.ModuleTypePassive
	}
	for _, result := range results {
		if !e.moduleFindingAllowed(m.ID()) {
			continue
		}
		result.ModuleType = moduleType
		result.FindingSource = database.FindingSourceDynamicAssessment
		e.assignModuleInfo(result, m)
		e.emitResult(result)
	}
}

// moduleFindingAllowed returns true if the module has not exceeded its finding cap.
func (e *Executor) moduleFindingAllowed(moduleID string) bool {
	cap := e.cfg.MaxFindingsPerModule
	if cap <= 0 {
		return true
	}
	val, _ := e.moduleFindingCount.LoadOrStore(moduleID, &moduleFindingTracker{})
	tracker := val.(*moduleFindingTracker)
	n := tracker.count.Add(1)
	if n > int64(cap) {
		tracker.warned.Do(func() {
			zap.L().Warn("Module finding cap reached, suppressing further findings",
				zap.String("module", moduleID),
				zap.Int("cap", cap))
		})
		return false
	}
	return true
}

func (e *Executor) emitResult(result *output.ResultEvent) {
	// Run post-hooks (may modify or drop result)
	if e.hooks != nil {
		hooked, err := e.hooks.RunPostHooks(result)
		if err != nil {
			zap.L().Debug("Post-hook error", zap.Error(err))
		}
		if hooked == nil {
			return // Post-hook dropped this result
		}
		result = hooked
	}

	e.results.Store(true)

	// Store finding in database (if enabled)
	if e.repo != nil {
		var recordUUIDs []string

		if result.Request != "" {
			// Create a temporary HttpRequest to get the hash
			tempReq := httpmsg.NewHttpRequest([]byte(result.Request))
			reqHash := tempReq.ID()

			// Look up the database record UUID
			recordUUID, exists := e.requestUUIDs.Load(reqHash)

			if !exists {
				// Fuzzed request — save it as a new http_record
				fuzzedRR := httpmsg.NewHttpRequestResponse(
					httpmsg.NewHttpRequest([]byte(result.Request)),
					httpmsg.NewHttpResponse([]byte(result.Response)),
				)
				var err error
				recordUUID, err = e.repo.SaveRecord(context.Background(), fuzzedRR, "scanner-fuzz", e.projectUUID)
				if err != nil {
					zap.L().Debug("Failed to save fuzzed record", zap.Error(err))
				} else {
					exists = true
				}
			}

			if exists {
				recordUUIDs = []string{recordUUID}
			}
		}

		if err := e.repo.SaveFinding(context.Background(), result, recordUUIDs, e.scanUUID, e.projectUUID); err != nil {
			zap.L().Debug("Failed to save finding to database", zap.Error(err))
		}
	}

	if e.cfg.OnResult != nil {
		e.cfg.OnResult(result)
	}

	if e.cfg.Services != nil && e.cfg.Services.Notifier != nil && !result.DisableNotify {
		_ = e.cfg.Services.Notifier.Send(result)
	}
}

func (e *Executor) assignModuleInfo(result *output.ResultEvent, m modules.Module) {
	result.ModuleID = m.ID()

	if result.ModuleShort == "" {
		result.ModuleShort = m.ShortDescription()
	}

	if result.Info.Name == "" {
		result.Info.Name = m.Name()
	}
	if result.Info.Description == "" {
		result.Info.Description = m.Description()
	}
	if result.Info.Severity == severity.Undefined {
		result.Info.Severity = m.Severity()
	}
	if result.Info.Confidence == severity.ConfidenceUndefined {
		result.Info.Confidence = m.Confidence()
	}

	if result.Type == "" {
		result.Type = "http"
	}

	if result.Matched == "" && result.URL != "" {
		result.Matched = result.URL
	}

	if result.URL == "" && result.Request != "" {
		result.URL = httpmsg.GetURLFromRequest("https", []byte(result.Request))
		if result.Matched == "" {
			result.Matched = result.URL
		}
	}

	if result.Host == "" {
		e.fillHostFromResult(result)
	}
}

func (e *Executor) fillHostFromResult(result *output.ResultEvent) {
	if result.URL != "" {
		urlx, err := urlutil.ParseURL(result.URL, true)
		if err == nil {
			result.Host = urlx.Host
			result.Scheme = urlx.Scheme
			return
		}
	}
	if result.Request != "" {
		host, _ := httpmsg.GetHeaderValue([]byte(result.Request), "Host")
		if host != "" {
			result.Host = host
			return
		}
	}
	result.Host = "unknown"
}

func (e *Executor) recoverFromPanic(ctx string) {
	if r := recover(); r != nil {
		stack := make([]byte, 4096)
		length := goruntime.Stack(stack, false)
		stackTrace := string(stack[:length])

		errorMessage := fmt.Sprintf(
			"Recovered from panic in %s: %+v\nStack Trace:\n%s",
			ctx, r, stackTrace,
		)
		zap.L().Error(errorMessage)

		if e.cfg.Services != nil && e.cfg.Services.Notifier != nil {
			_ = e.cfg.Services.Notifier.SendRaw(errorMessage)
		}
	}
}

func filterActiveModulesByScanScope(mods []modules.ActiveModule, scope modules.ScanScope) []modules.ActiveModule {
	var result []modules.ActiveModule
	for _, m := range mods {
		if m.ScanScopes().Has(scope) {
			result = append(result, m)
		}
	}
	return result
}

func filterPassiveModulesByScanScope(mods []modules.PassiveModule, scope modules.ScanScope) []modules.PassiveModule {
	var result []modules.PassiveModule
	for _, m := range mods {
		if m.ScanScopes().Has(scope) {
			result = append(result, m)
		}
	}
	return result
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

// repoRiskScoreUpdater adapts *database.Repository to modkit.RiskScoreUpdater.
type repoRiskScoreUpdater struct {
	repo *database.Repository
}

func (u *repoRiskScoreUpdater) UpdateRiskScores(ctx context.Context, scores map[string]int) error {
	return u.repo.UpdateRiskScores(ctx, scores)
}

// repoRemarksAnnotator adapts *database.Repository to modkit.RemarksAnnotator.
type repoRemarksAnnotator struct {
	repo *database.Repository
}

func (u *repoRemarksAnnotator) AppendRemarks(ctx context.Context, annotations map[string][]string) error {
	return u.repo.AppendRemarks(ctx, annotations)
}
