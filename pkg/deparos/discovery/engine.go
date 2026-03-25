package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"runtime"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/casesense"
	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module/builtin"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/tracker"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
	"github.com/vigolium/vigolium/pkg/toolexec/kingfisher"
	"github.com/vigolium/vigolium/pkg/deparos/reqcache"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/deparos/scope"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/deparos/tag"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/deparos/wordlist"
	"github.com/sourcegraph/conc"
	"go.uber.org/zap"
)

var logger *zap.Logger

// SetLogger configures the global logger for the discovery package
func SetLogger(l *zap.Logger) {
	if l == nil {
		logger = zap.NewNop()
	} else {
		logger = l
	}
}

func init() {
	logger = zap.NewNop()
}

// newDiskSet creates a DiskSet with a unique base path.
func newDiskSet(basePath, namespace string) (*dedup.DiskSet, error) {
	return dedup.NewDiskSet(&dedup.Config{
		BasePath:  basePath,
		Namespace: namespace,
		Cleanup:   true,
	})
}

// Engine orchestrates content discovery workflow.
// Manages state machine, task queue, coordinator, and HTTP execution.
//
// Architecture (payload-level parallelism):
// - Tasks are configuration + PayloadProvider
// - PayloadCoordinator runs ONE task at a time
// - N workers consume payloads concurrently from the current task
// - Uses sync.Cond for efficient waiting (no polling)
//
// State transitions:
//
//	IDLE → RUNNING (Start)
//	RUNNING → PAUSED (Pause)
//	PAUSED → RUNNING (Resume/Start)
//	Any → STOPPED (Stop) - terminal
type Engine struct {
	config *config.Config

	// State management
	state       atomic.Int32
	stateMu     sync.RWMutex
	stateNotify chan struct{}

	// Task queue and coordinator
	taskQueue   *queue.TaskQueue
	coordinator *PayloadCoordinator
	factory     *Factory

	// HTTP infrastructure
	httpClient *pkghttp.Client
	analyzer   *pkghttp.Analyzer

	// Fingerprint infrastructure
	fpCache      *fingerprint.Cache
	fpComparator *fingerprint.Comparator
	fpLearner    *fingerprint.Learner

	// Spider infrastructure
	spiderCoordinator *spider.ExtractionCoordinator
	spiderResolver    *spider.URLResolver
	spiderScope       *scope.Checker

	// Redirect detection
	redirectDetector *RedirectDetector

	// Result storage
	storage storage.Storage

	// Observed collections
	observedNames      *payload.ObservedProvider
	observedExtensions *payload.ObservedProvider
	observedPaths      *payload.ObservedProvider
	observedFiles      *payload.ObservedProvider

	// Task deduplication
	taskHashes         *dedup.DiskSet
	seenExtensions     *dedup.DiskSet
	seenDiscoveredURLs *dedup.DiskSet // Global dedup for all discovered URLs
	formStructureCounter *dedup.Counter // Dedup form submissions by structure (max N per endpoint+structure)
	seenJSURLs         *dedup.DiskSet // Dedup JS URLs across batches
	seenBodyHashes     *dedup.DiskSet // Dedup response body content for jsscan on script tags

	// Tested directories/files tracking (centralized for deduplication)
	testedDirectories *tracker.URLTracker
	testedFiles       *tracker.URLTracker

	// Request deduplication
	requestCache  *reqcache.HMapCache
	dedupBasePath string // Temp directory for dedup stores

	// Lifecycle control
	ctx    context.Context
	cancel context.CancelFunc
	wg     conc.WaitGroup // Tracks coordinator goroutine for graceful shutdown

	// Metrics
	metrics   EngineMetrics
	metricsMu sync.Mutex

	// Display callback
	displayCallback func(result *Result)

	// Module system
	moduleRegistry *module.Registry
	moduleExecutor *module.Executor
	taskFilter     *module.TaskFilter

	// Network error tracking for early exit
	errorTracker *NetworkErrorTracker

	// WAF block tracking for early exit
	wafBlockTracker *waf.BlockTracker
	wafDetector     waf.Detector

	// Case sensitivity detection (lazy detection on first valid discovery)
	caseSenseManager *CaseSensitivityManager

	// Wordlist extraction from response bodies
	wordlistExtractor *wordlist.Extractor

	// Tag analysis
	tagAnalyzer *tag.Analyzer

	// Secret scanning (batch mode: buffer during crawl, scan after completion)
	kingfisherScanner  *kingfisher.Scanner
	kingfisherBatchDir string
	kingfisherBatchMu  sync.Mutex
	kingfisherBatchSeq atomic.Int64
	kingfisherBatchMap map[string]string // filename → URL for mapping findings back

	// JSScan infrastructure for endpoint extraction from JS files
	jsscanScanner          *jsscan.Scanner
	jsscanSem              chan struct{}             // Semaphore to limit concurrent scans
	extractedRequests      []jsscan.ExtractedRequest // Collected requests for future task generation
	extractedRequestsMu    sync.Mutex                // Protects extractedRequests slice
	extractedRequestsDedup *dedup.DiskSet            // Deduplication using hash
}

// EngineMetrics tracks discovery statistics.
type EngineMetrics struct {
	TasksGenerated   uint64
	TasksDeduped     uint64
	TasksBlocked     uint64
	TasksCompleted   uint64
	TasksFailed      uint64
	RequestsSent     uint64
	URLsDiscovered   uint64
	UniqueTaskHashes int
	ActiveWorkers    int32
	InFlightItems    int32
	QueueSize        int
}

// NewEngine creates discovery engine with configuration.
func NewEngine(cfg *config.Config, st storage.Storage) (*Engine, error) {
	return NewEngineWithContext(context.Background(), cfg, st)
}

// NewEngineWithContext creates discovery engine with external context for cancellation.
func NewEngineWithContext(parentCtx context.Context, cfg *config.Config, st storage.Storage) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	ctx, cancel := context.WithCancel(parentCtx)

	engineCreated := false
	defer func() {
		if !engineCreated {
			cancel()
		}
	}()

	// Create cookie jar if enabled
	var cookieJar nethttp.CookieJar
	if cfg.Engine.EnableCookieJar {
		jar, err := responsechain.NewCookieJar()
		if err != nil {
			return nil, fmt.Errorf("failed to create cookie jar: %w", err)
		}
		cookieJar = jar
		logger.Info("Cookie jar enabled for session persistence")
	}

	poolConfig := pkghttp.DefaultPoolConfig()
	if cfg.Engine.ProxyURL != "" {
		poolConfig.ProxyURL = cfg.Engine.ProxyURL
	}

	httpClient := pkghttp.NewClient(&pkghttp.ClientConfig{
		PoolConfig: poolConfig,
		Middleware: []pkghttp.Middleware{
			pkghttp.RetryMiddleware(pkghttp.DefaultRetryConfig()),
		},
		RequestTimeout:      cfg.Engine.Timeout,
		DisableAutoRedirect: true,
		MaxRedirects:        0,
		Jar:                 cookieJar,
	})

	fingerprint.SetLogger(logger)
	fpLearner := fingerprint.NewLearner(httpClient.HTTPClient(), cfg.Engine.CustomHeaders)
	fpCache := fingerprint.NewCache(fpLearner)
	fpComparator := fingerprint.NewComparator(fpCache, fpLearner)

	analyzer := pkghttp.NewAnalyzer(fpComparator)

	startURL, err := url.Parse(cfg.Target.StartURL)
	if err != nil {
		return nil, fmt.Errorf("invalid start URL: %w", err)
	}

	spiderResolver := spider.NewURLResolver()
	spiderScope := scope.NewChecker(scope.Config{
		TargetHost: startURL.Host,
		Mode:       scope.Mode(cfg.Target.ScopeMode),
	})

	spiderFactory := spider.NewExtractorFactory(spiderResolver)
	spiderCoordinatorInstance := spiderFactory.CreateCoordinator()

	redirectDetector := NewRedirectDetector()
	taskQueue := queue.New()

	// Create unique temp directory for all engine's disk-backed stores
	// All caches consolidated under one directory for simpler cleanup
	dedupBasePath, err := os.MkdirTemp("", "deparos-dedup-*")
	if err != nil {
		return nil, fmt.Errorf("create dedup temp dir: %w", err)
	}

	// Create request cache for deduplication under dedupBasePath
	reqCache, err := reqcache.NewHMapCache(&reqcache.Config{
		Path:    filepath.Join(dedupBasePath, "reqcache"),
		Cleanup: true,
	})
	if err != nil {
		_ = os.RemoveAll(dedupBasePath)
		return nil, fmt.Errorf("create request cache: %w", err)
	}

	taskHashesDS, err := newDiskSet(dedupBasePath, "task-hashes")
	if err != nil {
		_ = reqCache.Close()
		_ = os.RemoveAll(dedupBasePath)
		return nil, fmt.Errorf("create task hashes: %w", err)
	}

	seenExtensionsDS, err := newDiskSet(dedupBasePath, "seen-extensions")
	if err != nil {
		_ = taskHashesDS.Close()
		_ = reqCache.Close()
		_ = os.RemoveAll(dedupBasePath)
		return nil, fmt.Errorf("create seen extensions: %w", err)
	}

	seenDiscoveredURLsDS, err := newDiskSet(dedupBasePath, "seen-discovered-urls")
	if err != nil {
		_ = seenExtensionsDS.Close()
		_ = taskHashesDS.Close()
		_ = reqCache.Close()
		_ = os.RemoveAll(dedupBasePath)
		return nil, fmt.Errorf("create seen discovered urls: %w", err)
	}

	seenJSURLsDS, err := newDiskSet(dedupBasePath, "seen-js-urls")
	if err != nil {
		_ = seenDiscoveredURLsDS.Close()
		_ = seenExtensionsDS.Close()
		_ = taskHashesDS.Close()
		_ = reqCache.Close()
		_ = os.RemoveAll(dedupBasePath)
		return nil, fmt.Errorf("create seen JS URLs: %w", err)
	}

	seenBodyHashesDS, err := newDiskSet(dedupBasePath, "seen-body-hashes")
	if err != nil {
		_ = seenJSURLsDS.Close()
		_ = seenDiscoveredURLsDS.Close()
		_ = seenExtensionsDS.Close()
		_ = taskHashesDS.Close()
		_ = reqCache.Close()
		_ = os.RemoveAll(dedupBasePath)
		return nil, fmt.Errorf("create seen body hashes: %w", err)
	}

	testedDirsTracker, err := tracker.NewWithConfig(&tracker.Config{
		BasePath:  dedupBasePath,
		Namespace: "tested-directories",
		Cleanup:   true,
	})
	if err != nil {
		_ = seenBodyHashesDS.Close()
		_ = seenJSURLsDS.Close()
		_ = seenDiscoveredURLsDS.Close()
		_ = seenExtensionsDS.Close()
		_ = taskHashesDS.Close()
		_ = reqCache.Close()
		_ = os.RemoveAll(dedupBasePath)
		return nil, fmt.Errorf("create tested directories tracker: %w", err)
	}

	testedFilesTracker, err := tracker.NewWithConfig(&tracker.Config{
		BasePath:  dedupBasePath,
		Namespace: "tested-files",
		Cleanup:   true,
	})
	if err != nil {
		_ = testedDirsTracker.Close()
		_ = seenBodyHashesDS.Close()
		_ = seenJSURLsDS.Close()
		_ = seenDiscoveredURLsDS.Close()
		_ = seenExtensionsDS.Close()
		_ = taskHashesDS.Close()
		_ = reqCache.Close()
		_ = os.RemoveAll(dedupBasePath)
		return nil, fmt.Errorf("create tested files tracker: %w", err)
	}

	engine := &Engine{
		config:             cfg,
		stateNotify:        make(chan struct{}),
		taskQueue:          taskQueue,
		coordinator:        nil, // Initialized after engine creation
		httpClient:         httpClient,
		analyzer:           analyzer,
		fpCache:            fpCache,
		fpComparator:       fpComparator,
		fpLearner:          fpLearner,
		spiderCoordinator:  spiderCoordinatorInstance,
		spiderResolver:     spiderResolver,
		spiderScope:        spiderScope,
		redirectDetector:   redirectDetector,
		storage:            st,
		observedNames:      payload.NewObservedProviderWithLimit(cfg.Engine.CaseSensitivity == config.CaseSensitive, cfg.Engine.ObservedMaxItems),
		observedExtensions: payload.NewObservedProviderWithLimit(cfg.Engine.CaseSensitivity == config.CaseSensitive, cfg.Engine.ObservedMaxItems),
		observedPaths:      payload.NewObservedProviderWithLimit(true, cfg.Engine.ObservedMaxItems), // Always case-sensitive for REST API paths
		observedFiles:      payload.NewObservedProviderWithLimit(cfg.Engine.CaseSensitivity == config.CaseSensitive, cfg.Engine.ObservedMaxItems),
		testedDirectories:  testedDirsTracker,
		testedFiles:        testedFilesTracker,
		taskHashes:         taskHashesDS,
		seenExtensions:     seenExtensionsDS,
		seenDiscoveredURLs: seenDiscoveredURLsDS,
		formStructureCounter: dedup.NewCounter(),
		seenJSURLs:         seenJSURLsDS,
		seenBodyHashes:     seenBodyHashesDS,
		dedupBasePath:      dedupBasePath,
		requestCache:       reqCache,
		ctx:                ctx,
		cancel:             cancel,
	}

	engine.state.Store(int32(StateIdle))

	if cfg.Modules.Enabled {
		engine.initModuleSystem(&cfg.Modules)
	}

	// Initialize network error tracker if threshold configured
	if cfg.Engine.MaxConsecutiveErrors > 0 {
		engine.errorTracker = NewNetworkErrorTracker(cfg.Engine.MaxConsecutiveErrors, cancel)
		logger.Info("Network error tracking enabled",
			zap.Int("threshold", cfg.Engine.MaxConsecutiveErrors))
	}

	// Initialize WAF block tracker if threshold configured
	if cfg.Engine.MaxConsecutiveWAFBlocks > 0 {
		waf.SetLogger(logger)
		engine.wafDetector = waf.NewDetector()
		engine.wafBlockTracker = waf.NewBlockTracker(cfg.Engine.MaxConsecutiveWAFBlocks, cancel)
		logger.Info("WAF block tracking enabled",
			zap.Int("threshold", cfg.Engine.MaxConsecutiveWAFBlocks))
	}

	// Initialize kingfisher scanner for batch secret detection
	if !cfg.Engine.DisableKingfisher {
		kfScanner, err := kingfisher.NewScanner(kingfisher.DefaultConfig())
		if err != nil {
			logger.Warn("Failed to initialize kingfisher scanner", zap.Error(err))
		} else {
			if err := kfScanner.EnsureBinary(context.Background()); err != nil {
				logger.Error("Kingfisher EnsureBinary error", zap.Error(err))
			} else {
				batchDir, err := os.MkdirTemp("", "kingfisher-deparos-batch-*")
				if err != nil {
					logger.Error("Failed to create kingfisher batch dir", zap.Error(err))
				} else {
					engine.kingfisherScanner = kfScanner
					engine.kingfisherBatchDir = batchDir
					engine.kingfisherBatchMap = make(map[string]string)
					logger.Info("Using kingfisher (batch mode)",
						zap.String("version", kfScanner.Version()))
				}
			}
		}
	} else {
		logger.Info("Kingfisher secret scanning disabled by user")
	}

	// Initialize jsscan scanner for JS endpoint extraction
	// IMPORTANT: Must be initialized BEFORE coordinator so callbacks capture non-nil scanner
	jsScanScanner, err := jsscan.NewScanner(jsscan.DefaultConfig())
	if err != nil {
		logger.Warn("Failed to initialize jsscan scanner", zap.Error(err))
	} else {
		engine.jsscanScanner = jsScanScanner
		jsscanConc := cfg.Engine.JSScanConcurrency
		if jsscanConc <= 0 {
			jsscanConc = runtime.NumCPU()
		}
		engine.jsscanSem = make(chan struct{}, jsscanConc)
		if err := jsScanScanner.EnsureBinary(); err != nil {
			logger.Error("jsscan EnsureBinary error", zap.Error(err))
		}
		logger.Info("Using jsscan", zap.String("checksum", jsScanScanner.Checksum()))
	}

	// Initialize coordinator with callbacks (after scanners are set)
	engine.coordinator = NewPayloadCoordinator(taskQueue, cfg.Engine.DiscoveryThreads, engine.newCallbacks())

	// Initialize factory (stateless - reused for all task creation)
	engine.factory = NewFactory(cfg)

	// Initialize case sensitivity detection manager
	caseSenseDetector := casesense.NewDetector(fpLearner)
	engine.caseSenseManager = NewCaseSensitivityManager(caseSenseDetector, cfg.Engine.CaseSensitivity)
	if cfg.Engine.CaseSensitivity == config.CaseAutoDetect {
		logger.Info("Case sensitivity auto-detection enabled")
	} else {
		logger.Info("Case sensitivity mode set",
			zap.String("mode", string(cfg.Engine.CaseSensitivity)))
	}

	// Initialize wordlist extraction from response bodies
	if cfg.Filenames.WordlistExtraction.Enabled {
		wlCfg := &wordlist.Config{
			MinLength:       cfg.Filenames.WordlistExtraction.MinLength,
			MaxLength:       cfg.Filenames.WordlistExtraction.MaxLength,
			DelimExceptions: cfg.Filenames.WordlistExtraction.DelimExceptions,
			MaxCombine:      cfg.Filenames.WordlistExtraction.MaxCombine,
			AlphaNumOnly:    true,
			AutoURLDecode:   true,
			FilterKeywords:  true, // Always filter content-type specific keywords
		}
		// Apply defaults if not set
		if wlCfg.MinLength == 0 {
			wlCfg.MinLength = 3
		}
		if wlCfg.MaxLength == 0 {
			wlCfg.MaxLength = 64
		}
		if wlCfg.MaxCombine == 0 {
			wlCfg.MaxCombine = 2
		}
		engine.wordlistExtractor = wordlist.NewExtractor(wlCfg)
		logger.Info("Wordlist extraction enabled",
			zap.String("delim_exceptions", wlCfg.DelimExceptions),
			zap.Int("max_combine", wlCfg.MaxCombine))
	}

	// Initialize tag analyzer for response tagging
	engine.tagAnalyzer = tag.NewAnalyzer()

	// Create dedup set for extracted requests
	extractedReqDedup, err := newDiskSet(dedupBasePath, "extracted-requests")
	if err != nil {
		logger.Warn("Failed to create extracted requests dedup", zap.Error(err))
	} else {
		engine.extractedRequestsDedup = extractedReqDedup
	}

	engineCreated = true
	return engine, nil
}

// Start initiates discovery from IDLE or resumes from PAUSED.
func (e *Engine) Start() error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	currentState := State(e.state.Load())

	switch currentState {
	case StateIdle:
		logger.Info("Starting discovery engine", zap.String("target", e.config.Target.StartURL))

		if err := e.initSession(); err != nil {
			logger.Error("Session initialization failed", zap.Error(err))
			return fmt.Errorf("session init failed: %w", err)
		}

		e.setState(StateRunning)
		logger.Info("Engine state transition", zap.String("from", "IDLE"), zap.String("to", "RUNNING"))

		logger.Info("Starting payload coordinator",
			zap.Int("discovery_threads", e.config.Engine.DiscoveryThreads))

		e.wg.Go(func() {
			if err := e.coordinator.Run(e.ctx); err != nil {
				if err != context.Canceled {
					logger.Error("Coordinator error", zap.Error(err))
				}
			}
		})

		targetURL, err := url.Parse(e.config.Target.StartURL)
		if err != nil {
			return fmt.Errorf("invalid start URL: %w", err)
		}

		// Fetch and parse robots.txt for initial URL discovery
		logger.Info("Fetching robots.txt")
		e.fetchRobotsTxt(targetURL)

		go e.generateInitialTasks()

		return nil

	case StatePaused:
		logger.Info("Resuming discovery engine from pause")
		e.setState(StateRunning)
		logger.Info("Engine state transition", zap.String("from", "PAUSED"), zap.String("to", "RUNNING"))
		return nil

	case StateRunning:
		return fmt.Errorf("already running")

	case StateStopped:
		return fmt.Errorf("cannot start from stopped state")

	default:
		return fmt.Errorf("unknown state: %v", currentState)
	}
}

// Pause pauses active discovery.
func (e *Engine) Pause() error {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()

	currentState := State(e.state.Load())
	if currentState != StateRunning {
		return fmt.Errorf("cannot pause from state %v", currentState)
	}

	logger.Info("Pausing discovery engine")
	e.setState(StatePaused)
	logger.Info("Engine state transition", zap.String("from", "RUNNING"), zap.String("to", "PAUSED"))

	return nil
}

// Stop terminates discovery session (irreversible).
func (e *Engine) Stop() {
	e.stateMu.Lock()
	currentState := State(e.state.Load())

	if currentState == StateStopped {
		e.stateMu.Unlock()
		logger.Debug("Stop called on already-stopped engine, ignoring")
		return
	}

	e.setState(StateStopped)
	e.stateMu.Unlock()

	coordMetrics := e.coordinator.Metrics()
	logger.Info("Stopping discovery engine",
		zap.String("from_state", currentState.String()),
		zap.Int32("active_workers", coordMetrics.ActiveWorkers.Load()))

	e.cancel()

	logger.Debug("Stopping coordinator")
	e.coordinator.Stop()

	// Wait for coordinator goroutine to finish before cleanup
	logger.Debug("Waiting for coordinator to finish")
	func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in coordinator goroutine", zap.Any("panic", r))
			}
		}()
		e.wg.Wait()
	}()

	logger.Debug("Cleaning up engine resources")
	e.cleanup()

	logger.Info("Discovery engine stopped")
}

// GetState returns current engine state.
func (e *Engine) GetState() State {
	return State(e.state.Load())
}

// IsIdle returns true if queue is empty and coordinator has no work pending.
// Used by TUI to detect completion.
func (e *Engine) IsIdle() bool {
	return e.taskQueue.IsEmpty() && e.coordinator.IsIdle()
}

// Done returns a channel that is closed when the engine's context is cancelled.
// This happens when:
// - The parent context is cancelled (SIGINT, timeout)
// - WAF block threshold is reached
// - Network error threshold is reached
func (e *Engine) Done() <-chan struct{} {
	return e.ctx.Done()
}

// setState updates state and broadcasts notification.
func (e *Engine) setState(newState State) {
	e.state.Store(int32(newState))
	close(e.stateNotify)
	e.stateNotify = make(chan struct{})
}

// newCallbacks creates a Callbacks struct with engine's handlers.
func (e *Engine) newCallbacks() *Callbacks {
	return &Callbacks{
		OnDirectoryDiscovered: e.OnDirectoryDiscovered,
		OnFileDiscovered:      e.OnFileDiscovered,
		OnResult:              e.onResult,
		AddObservedName:       e.AddObservedNameTrusted,
		AddObservedPath:       e.AddObservedPathTrusted,
		HTTPClient:            e.httpClient,
		Analyzer:              e.analyzer,
		RedirectDetector:      NewRedirectDetector(),
		MaxDepth:              uint16(e.config.Target.Recursion.MaxDepth),
		RequestCache:          e.requestCache,
		ErrorTracker:          e.errorTracker,
		WAFBlockTracker:       e.wafBlockTracker,
		WAFDetector:           e.wafDetector,
		CustomHeaders:         e.config.Engine.CustomHeaders,
		JSScanScanner:         e.jsscanScanner,
		JSScanSem:             e.jsscanSem,
		AddExtractedRequest:   e.AddExtractedRequest,
		StoreJSScanRequests:   e.storeJSScanRequests,
		ScopeChecker:          e.spiderScope,
	}
}

// SetDisplayCallback sets the real-time display callback.
func (e *Engine) SetDisplayCallback(cb func(result *Result)) {
	e.displayCallback = cb
}

// initModuleSystem initializes the module system from config.
func (e *Engine) initModuleSystem(cfg *config.ModuleConfig) {
	registry := builtin.NewRegistry(cfg)
	e.moduleRegistry = registry
	e.taskFilter = module.NewTaskFilter(registry, logger)
	e.moduleExecutor = module.NewExecutor(registry, e.taskFilter, logger)

	logger.Info("Module system initialized",
		zap.Int("modules", registry.Count()),
		zap.Int("enabled", len(registry.Enabled())))
}

// ModuleRegistry returns the module registry (may be nil).
func (e *Engine) ModuleRegistry() *module.Registry {
	return e.moduleRegistry
}

// getStateNotify returns the current state notification channel.
func (e *Engine) getStateNotify() <-chan struct{} {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.stateNotify
}

// WaitForState blocks until engine reaches target state or context cancels.
func (e *Engine) WaitForState(ctx context.Context, target State) error {
	for {
		if e.GetState() == target {
			return nil
		}

		notifyCh := e.getStateNotify()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-notifyCh:
			// State changed, check again
		}
	}
}

// AddTask enqueues a task for execution.
func (e *Engine) AddTask(task Task) bool {
	hash := task.Hash()
	priority := task.Priority()
	description := task.Description()

	if e.taskFilter != nil && !e.taskFilter.ShouldAdd(task) {
		e.incrementTasksBlocked()
		logger.Debug("Task blocked by module filter",
			zap.String("baseURL", string(task.FullURL())),
			zap.String("description", description))
		return false
	}

	hashKey := fmt.Sprintf("%x", hash)
	if e.taskHashes.IsSeen(hashKey) {
		dedupedCount := e.incrementTasksDeduped()
		logger.Debug("Task deduplicated - hash already exists",
			zap.Uint64("hash", hash),
			zap.Uint8("priority", priority),
			zap.String("description", description),
			zap.Uint64("total_deduped", dedupedCount))
		return false
	}

	taskCount := e.incrementTasksGenerated()
	logger.Debug("Task created and enqueued",
		zap.Uint64("hash", hash),
		zap.Uint8("priority", priority),
		zap.String("description", description),
		zap.Uint64("task_count", taskCount))

	e.taskQueue.Enqueue(task)
	return true
}

// AddObservedName records filename seen in discovered URLs.
// Used for secondary sources (wordlist extraction from response bodies).
func (e *Engine) AddObservedName(name string) {
	e.observedNames.Add([]byte(name))
}

// AddObservedNameTrusted records filename from trusted sources (URLs, spider links, JS paths).
// Trusted sources get higher frequency to survive eviction over wordlist extraction items.
func (e *Engine) AddObservedNameTrusted(name string) {
	e.observedNames.AddWithFrequency([]byte(name), payload.TrustedFrequencyBoost)
}

// AddObservedExtension records file extension seen in discovered URLs.
func (e *Engine) AddObservedExtension(extension string) {
	e.observedExtensions.Add([]byte(extension))
}

// addObservedExtensionIfNew adds extension to observed collection and returns true if new.
// Only extensions in config.AllowedObservedExtensions whitelist are accepted.
func (e *Engine) addObservedExtensionIfNew(extension string) bool {
	// Normalize to lowercase for consistent comparison
	normalizedExt := strings.ToLower(extension)

	// Check if extension is in the allowed whitelist
	if _, allowed := config.AllowedObservedExtensions[normalizedExt]; !allowed {
		return false
	}

	// Check deduplication with normalized extension
	if e.seenExtensions.IsSeen(normalizedExt) {
		return false
	}

	e.AddObservedExtension(normalizedExt)
	logger.Debug("New extension observed for dynamic task generation",
		zap.String("extension", normalizedExt))

	return true
}

// GetObservedNames returns the observed names provider.
func (e *Engine) GetObservedNames() *payload.ObservedProvider {
	return e.observedNames
}

// GetObservedExtensions returns the observed extensions provider.
func (e *Engine) GetObservedExtensions() *payload.ObservedProvider {
	return e.observedExtensions
}

// sanitizeObservedName strips path and query from observed name.
// Used to clean legacy data that may contain full paths with query params.
// Example: "register?app=appskl0001&utm_content__c=academy" → "register"
// Example: "/api/users" → "users"
func sanitizeObservedName(name string) string {
	if name == "" {
		return ""
	}
	// Strip query params
	if idx := strings.IndexByte(name, '?'); idx >= 0 {
		name = name[:idx]
	}
	// Extract just filename (after last slash)
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		name = name[idx+1:]
	}
	return name
}

// sanitizeObservedPath extracts the path portion from a URL string.
// For absolute URLs (https://example.com/path), returns just the path (/path).
// For paths containing embedded URLs (e.g., /L0/https://domain/path from malformed data),
// extracts and returns only the valid path portion.
// Query parameters and fragments are ALWAYS stripped from all paths.
// This prevents malformed URLs from polluting the observed paths collection.
func sanitizeObservedPath(path string) string {
	if path == "" {
		return ""
	}

	// Use url.Parse for clean URL handling
	u, err := url.Parse(path)
	if err != nil {
		// Fallback: manual strip for unparseable paths
		if idx := strings.IndexByte(path, '?'); idx >= 0 {
			path = path[:idx]
		}
		if idx := strings.IndexByte(path, '#'); idx >= 0 {
			path = path[:idx]
		}
		return path
	}

	// Case 1: Absolute URL (has scheme and host)
	// e.g., "https://capital.com/risk-disclosure-policy" → "/risk-disclosure-policy"
	if u.Scheme != "" && u.Host != "" {
		p := u.Path
		if p == "" {
			p = "/"
		}
		return p
	}

	// Case 2: Protocol-relative URL (no scheme but has host)
	// e.g., "//cdn.example.com/assets/app.js" → "/assets/app.js"
	// BUT: "//double//slash" also parses with Host="double"
	// Real hostnames contain dots, path segments usually don't
	if u.Host != "" {
		if strings.Contains(u.Host, ".") {
			p := u.Path
			if p == "" {
				p = "/"
			}
			return p
		}
		// No dot = not a real hostname, just double slashes in path
		// Fall through to strip query/fragment below
	}

	// Case 3: Path with embedded URL
	// url.Parse treats "/L0/https://capital.com/path" as just a path
	// Detect and extract the embedded URL
	if idx := strings.Index(u.Path, "://"); idx > 0 {
		afterScheme := u.Path[idx+3:]
		slashIdx := strings.Index(afterScheme, "/")
		if slashIdx > 0 {
			return sanitizeObservedPath(afterScheme[slashIdx:])
		}
		return "/"
	}

	// Case 4: Relative path - strip query params and fragments
	// e.g., "/files/bob/ios/hk/6.0/?javax.portlet.tpst=..." → "/files/bob/ios/hk/6.0/"
	// u.Path already has the path without query/fragment parsed out
	p := u.Path
	if p == "" {
		p = "/"
	}
	return p
}

// AddObservedPath records a URL path seen in discovered URLs.
// Used for secondary sources (wordlist extraction from response bodies).
func (e *Engine) AddObservedPath(path string) {
	path = sanitizeObservedPath(path)
	if path == "" {
		return
	}
	e.observedPaths.Add([]byte(path))
}

// AddObservedPathTrusted records URL path from trusted sources (URLs, spider links, JS paths).
// Trusted sources get higher frequency to survive eviction over wordlist extraction items.
func (e *Engine) AddObservedPathTrusted(path string) {
	path = sanitizeObservedPath(path)
	if path == "" {
		return
	}
	e.observedPaths.AddWithFrequency([]byte(path), payload.TrustedFrequencyBoost)
}

// GetObservedPaths returns the observed paths provider.
func (e *Engine) GetObservedPaths() *payload.ObservedProvider {
	return e.observedPaths
}

// AddObservedFile records a full filename seen in discovered URLs.
// Used for secondary sources (wordlist extraction from response bodies).
func (e *Engine) AddObservedFile(filename string) {
	if filename == "" {
		return
	}
	e.observedFiles.Add([]byte(filename))
}

// AddObservedFileTrusted records full filename from trusted sources (URLs, spider links, JS paths).
// Trusted sources get higher frequency to survive eviction over wordlist extraction items.
func (e *Engine) AddObservedFileTrusted(filename string) {
	if filename == "" {
		return
	}
	e.observedFiles.AddWithFrequency([]byte(filename), payload.TrustedFrequencyBoost)
}

// GetObservedFiles returns the observed files provider.
func (e *Engine) GetObservedFiles() *payload.ObservedProvider {
	return e.observedFiles
}

// AddExtractedRequest adds an extracted request to the collection with deduplication.
// Returns true if the request was new (not a duplicate).
func (e *Engine) AddExtractedRequest(req *jsscan.ExtractedRequest) bool {
	if e.extractedRequestsDedup == nil || req == nil {
		return false
	}

	hash := HashExtractedRequest(req)
	if e.extractedRequestsDedup.IsSeen(hash) {
		return false // Duplicate
	}

	e.extractedRequestsMu.Lock()
	e.extractedRequests = append(e.extractedRequests, *req)
	e.extractedRequestsMu.Unlock()

	logger.Debug("Added extracted request",
		zap.String("url", req.URL),
		zap.String("method", req.Method))

	return true
}

// GetExtractedRequests returns collected requests (for future task generation).
// Returns a copy to avoid race conditions.
func (e *Engine) GetExtractedRequests() []jsscan.ExtractedRequest {
	e.extractedRequestsMu.Lock()
	defer e.extractedRequestsMu.Unlock()

	result := make([]jsscan.ExtractedRequest, len(e.extractedRequests))
	copy(result, e.extractedRequests)
	return result
}

// ExtractedRequestsCount returns the number of extracted requests collected.
func (e *Engine) ExtractedRequestsCount() int {
	e.extractedRequestsMu.Lock()
	defer e.extractedRequestsMu.Unlock()
	return len(e.extractedRequests)
}

// OnValidDiscovery is the callback function for case sensitivity detection.
// Called by coordinator when executing CaseSenseDetectionTask.
func (e *Engine) OnValidDiscovery(ctx context.Context, url *url.URL, sample *fingerprint.Sample, isDirectory bool) {
	if e.caseSenseManager == nil {
		return
	}
	e.caseSenseManager.OnValidDiscovery(ctx, url, sample, isDirectory)
}

// GetMetrics returns current engine metrics.
func (e *Engine) GetMetrics() EngineMetrics {
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()

	metrics := e.metrics

	coordMetrics := e.coordinator.Metrics()
	metrics.ActiveWorkers = coordMetrics.ActiveWorkers.Load()
	metrics.InFlightItems = coordMetrics.InFlightItems.Load()
	metrics.TasksCompleted = coordMetrics.TasksCompleted.Load()
	metrics.RequestsSent = coordMetrics.RequestsSent.Load()

	metrics.QueueSize = e.taskQueue.Size()
	metrics.UniqueTaskHashes = int(e.taskHashes.Size())

	// Get actual count from storage
	if e.storage != nil {
		metrics.URLsDiscovered = uint64(e.storage.Count())
	}

	return metrics
}

// WaitForQueues blocks until queue is idle, stopped, or context is cancelled.
func (e *Engine) WaitForQueues(ctx context.Context) error {
	const idleTimeout = 2 * time.Second

	var idleStart time.Time
	idleDetected := false

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Exit immediately if queue was stopped (e.g., by WAF threshold or network errors)
			if e.taskQueue.IsStopped() {
				logger.Info("Queue stopped, exiting wait")
				return nil
			}

			taskQueueEmpty := e.taskQueue.IsEmpty()
			coordinatorIdle := e.coordinator.IsIdle()

			allIdle := taskQueueEmpty && coordinatorIdle

			if allIdle {
				if !idleDetected {
					idleStart = time.Now()
					idleDetected = true
					logger.Debug("Queue idle, starting idle timeout",
						zap.Duration("timeout", idleTimeout))
				} else {
					if time.Since(idleStart) >= idleTimeout {
						logger.Info("Discovery complete - queue idle",
							zap.Duration("idle_duration", time.Since(idleStart)))
						e.taskQueue.Stop()
						return nil
					}
				}
			} else {
				if idleDetected {
					logger.Debug("Queue activity detected, resetting idle timer",
						zap.Bool("task_queue_empty", taskQueueEmpty),
						zap.Bool("coordinator_idle", coordinatorIdle))
				}
				idleDetected = false
			}
		}
	}
}

// TaskQueue returns the task queue (for UI integration).
func (e *Engine) TaskQueue() *queue.TaskQueue {
	return e.taskQueue
}

// Storage returns the storage backend (for UI integration).
func (e *Engine) Storage() storage.Storage {
	return e.storage
}

// Config returns the engine configuration.
func (e *Engine) Config() *config.Config {
	return e.config
}

// PersistObservedData saves all observed data to database.
// Call this after Stop() but before storage.Close().
// Uses MAX frequency strategy for duplicates from previous runs.
func (e *Engine) PersistObservedData() error {
	if e.storage == nil {
		return nil
	}

	repo := e.storage.Observed()
	if repo == nil {
		return nil
	}

	hostname := e.storage.Hostname()
	if hostname == "" {
		return nil
	}

	logger.Info("Persisting observed data to database",
		zap.String("hostname", hostname))

	var errs []error

	if items := e.observedNames.GetAllItemsWithFrequencies(); len(items) > 0 {
		if err := repo.BatchUpsertObserved(hostname, storage.ObservedTypeName, items); err != nil {
			errs = append(errs, fmt.Errorf("names: %w", err))
		}
	}

	if items := e.observedExtensions.GetAllItemsWithFrequencies(); len(items) > 0 {
		if err := repo.BatchUpsertObserved(hostname, storage.ObservedTypeExtension, items); err != nil {
			errs = append(errs, fmt.Errorf("extensions: %w", err))
		}
	}

	if items := e.observedPaths.GetAllItemsWithFrequencies(); len(items) > 0 {
		if err := repo.BatchUpsertObserved(hostname, storage.ObservedTypePath, items); err != nil {
			errs = append(errs, fmt.Errorf("paths: %w", err))
		}
	}

	if items := e.observedFiles.GetAllItemsWithFrequencies(); len(items) > 0 {
		if err := repo.BatchUpsertObserved(hostname, storage.ObservedTypeFile, items); err != nil {
			errs = append(errs, fmt.Errorf("files: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("persist observed data: %v", errs)
	}

	logger.Info("Observed data persisted",
		zap.Int("names", e.observedNames.Count()),
		zap.Int("extensions", e.observedExtensions.Count()),
		zap.Int("paths", e.observedPaths.Count()),
		zap.Int("files", e.observedFiles.Count()))

	return nil
}

// cleanup releases engine resources.
// Note: storage is NOT closed here - it's owned by the caller (runner) who passed it in.
// The caller is responsible for closing storage after reading results.
func (e *Engine) cleanup() {
	// Storage is intentionally NOT closed here - caller owns it
	if e.requestCache != nil {
		if err := e.requestCache.Close(); err != nil {
			logger.Warn("Failed to close request cache", zap.Error(err))
		}
	}
	if e.testedDirectories != nil {
		if err := e.testedDirectories.Close(); err != nil {
			logger.Warn("Failed to close tested directories tracker", zap.Error(err))
		}
	}
	if e.testedFiles != nil {
		if err := e.testedFiles.Close(); err != nil {
			logger.Warn("Failed to close tested files tracker", zap.Error(err))
		}
	}
	if e.taskHashes != nil {
		if err := e.taskHashes.Close(); err != nil {
			logger.Warn("Failed to close task hashes", zap.Error(err))
		}
	}
	if e.seenExtensions != nil {
		if err := e.seenExtensions.Close(); err != nil {
			logger.Warn("Failed to close seen extensions", zap.Error(err))
		}
	}
	if e.seenDiscoveredURLs != nil {
		if err := e.seenDiscoveredURLs.Close(); err != nil {
			logger.Warn("Failed to close seen spider links", zap.Error(err))
		}
	}
	if e.formStructureCounter != nil {
		_ = e.formStructureCounter.Close()
	}
	if e.seenJSURLs != nil {
		if err := e.seenJSURLs.Close(); err != nil {
			logger.Warn("Failed to close seen JS URLs", zap.Error(err))
		}
	}
	if e.seenBodyHashes != nil {
		if err := e.seenBodyHashes.Close(); err != nil {
			logger.Warn("Failed to close seen body hashes", zap.Error(err))
		}
	}
	if e.extractedRequestsDedup != nil {
		if err := e.extractedRequestsDedup.Close(); err != nil {
			logger.Warn("Failed to close extracted requests dedup", zap.Error(err))
		}
	}
	if e.dedupBasePath != "" {
		_ = os.RemoveAll(e.dedupBasePath)
	}
	if e.kingfisherBatchDir != "" {
		_ = os.RemoveAll(e.kingfisherBatchDir)
	}
}

// bufferForKingfisher writes an eligible response body to the batch directory
// for deferred scanning. Thread-safe for concurrent use from callbacks.
func (e *Engine) bufferForKingfisher(body []byte, mimeType, urlPath, urlStr string) {
	if e.kingfisherScanner == nil || len(body) == 0 {
		return
	}
	if pkghttp.IsMediaContent(mimeType, urlPath) {
		return
	}
	if !isTextBasedMIME(mimeType) {
		return
	}

	seq := e.kingfisherBatchSeq.Add(1)
	filename := fmt.Sprintf("%d.txt", seq)
	filePath := filepath.Join(e.kingfisherBatchDir, filename)

	if err := os.WriteFile(filePath, body, 0600); err != nil {
		logger.Debug("Kingfisher: failed to buffer body",
			zap.String("path", urlPath),
			zap.Error(err))
		return
	}

	e.kingfisherBatchMu.Lock()
	e.kingfisherBatchMap[filename] = urlStr
	e.kingfisherBatchMu.Unlock()
}

// FlushKingfisher batch-scans all buffered response bodies using a single
// kingfisher invocation and updates the corresponding DB records.
// Must be called after crawling completes (WaitForQueues) but before Stop.
func (e *Engine) FlushKingfisher() {
	if e.kingfisherScanner == nil || e.kingfisherBatchDir == "" {
		return
	}

	e.kingfisherBatchMu.Lock()
	batchMap := e.kingfisherBatchMap
	e.kingfisherBatchMu.Unlock()

	if len(batchMap) == 0 {
		logger.Debug("Kingfisher batch: no bodies buffered")
		return
	}

	logger.Info("Kingfisher batch scan starting",
		zap.Int("buffered_responses", len(batchMap)))

	result, err := e.kingfisherScanner.ScanDir(context.Background(), e.kingfisherBatchDir)
	if err != nil {
		logger.Warn("Kingfisher batch scan failed", zap.Error(err))
		return
	}

	if !result.HasFindings() {
		logger.Info("Kingfisher batch scan: no findings",
			zap.Duration("duration", result.ScanDuration))
		return
	}

	// Group findings by URL
	type kfFinding = storage.KingfisherFinding
	urlFindings := make(map[string][]kfFinding)
	for _, f := range result.Findings {
		basename := filepath.Base(f.Finding.Path)
		urlStr, ok := batchMap[basename]
		if !ok {
			continue
		}
		urlFindings[urlStr] = append(urlFindings[urlStr], kfFinding{
			RuleID:     f.RuleID(),
			RuleName:   f.RuleName(),
			Snippet:    f.Snippet(),
			Confidence: f.Finding.Confidence,
			Validated:  f.IsValidated(),
		})
	}

	// Batch update DB records
	if e.storage != nil {
		jsonMap := make(map[string]string, len(urlFindings))
		for url, findings := range urlFindings {
			data, err := json.Marshal(findings)
			if err != nil {
				continue
			}
			jsonMap[url] = string(data)
		}
		if err := e.storage.BatchUpdateKingfisherFindings(jsonMap); err != nil {
			logger.Warn("Kingfisher batch: DB update failed", zap.Error(err))
		}
	}

	totalFindings := 0
	for _, fs := range urlFindings {
		totalFindings += len(fs)
	}
	logger.Info("Kingfisher batch scan completed",
		zap.Int("findings", totalFindings),
		zap.Int("urls_with_findings", len(urlFindings)),
		zap.Duration("duration", result.ScanDuration))
}
