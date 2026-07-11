package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	nethttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/deparos/casesense"
	"github.com/vigolium/vigolium/pkg/deparos/config"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module/builtin"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/tracker"
	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle/linkfinder"
	"github.com/vigolium/vigolium/pkg/deparos/reqcache"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"github.com/vigolium/vigolium/pkg/deparos/scope"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/deparos/tag"
	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/deparos/wordlist"
	"github.com/vigolium/vigolium/pkg/secretscan"
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
	taskHashes           *dedup.DiskSet
	seenExtensions       *dedup.DiskSet
	seenDiscoveredURLs   *dedup.DiskSet // Global dedup for all discovered URLs
	formStructureCounter *dedup.Counter // Dedup form submissions by structure (max N per endpoint+structure)
	seenJSURLs           *dedup.DiskSet // Dedup JS URLs across batches
	seenBodyHashes       *dedup.DiskSet // Dedup response body content for jstangle on script tags

	// Tested directories/files tracking (centralized for deduplication)
	testedDirectories *tracker.URLTracker
	testedFiles       *tracker.URLTracker

	// Per-prefix circuit breaker for soft-404 / trap directories
	prefixBreaker *tracker.PrefixBreaker

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

	// Extension-confirm pipeline: callback fired (once per host) when a
	// server-side extension is confirmed as a valid route and queued for
	// wordlist fuzzing; confirmedExtensions dedups confirmations.
	extensionConfirmCallback func(ExtensionConfirmEvent)
	confirmedExtensions      map[string]struct{}
	confirmedExtMu           sync.Mutex
	candidateExtSet          map[string]struct{}
	candidateExtOnce         sync.Once
	// extCatchAll caches, per candidate extension, whether the host answers a
	// random <nonce>.<ext> as a genuine resource (a catch-all/SPA/CDN that 200s
	// and reflects any path). The observed/fingerprint confirmation sources
	// consult it before trusting a .<ext> URL as proof the server runs that
	// stack; probed once per extension. See extensionServedByCatchAll.
	extCatchAll   map[string]bool
	extCatchAllMu sync.Mutex
	// startURLHeader is a snapshot of the start URL's response headers, captured
	// during probeStartURL for fingerprint-based extension confirmation.
	startURLHeader nethttp.Header
	// startURLStatus is the start URL's HTTP status code and startURLIsLogin
	// records whether its landing page is a login/SSO wall. Both gate the
	// fingerprint-based extension-confirm source: a stack fingerprint is only
	// trustworthy on a genuine 2xx app page, not a 3xx redirect (often an
	// off-host SSO bounce), a 4xx/5xx error, or an auth interstitial whose
	// headers describe the gateway/IdP rather than the application. Captured in
	// probeStartURL. See startURLIsGenuineLanding.
	startURLStatus  int
	startURLIsLogin bool
	// startURLIsHTML / startURLIsModernApp capture the start page's shape for the
	// JS-bundle sweep, which runs only on an HTML, non-SPA landing page (SPA
	// bundles are content-hashed and unguessable). observedJSDirs collects the
	// app's real JS mount directories seen while crawling the start page, so the
	// sweep probes them in addition to root + the start directory. Guarded
	// because queueJSFetch is also called from concurrent spider workers.
	// See js_bundle_sweep.go.
	startURLIsHTML         bool
	startURLIsModernApp    bool
	observedJSDirs         map[string]struct{}
	observedJSDirsMu       sync.Mutex
	observedJSDirsConsumed atomic.Bool // set once the start-of-scan sweep has read observedJSDirs

	// hashedAssetDirs records directories observed to hold content-hash
	// fingerprinted asset bundles (e.g. main-5cf96b0d57f7f579.js). Recursion into
	// such a build-output directory is skipped — brute-forcing there only replays
	// harvested chunk names back at the server. Keyed by
	// dedup.NormalizeURL(cleanedDirURL) so lookups match testedDirectories' keys.
	// See looksLikeHashedAsset / recordHashedAssetParent / OnDirectoryDiscovered.
	hashedAssetDirs   map[string]struct{}
	hashedAssetDirsMu sync.Mutex

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

	// Secret scanning (native in-process detector; matches accumulated per URL
	// during the crawl, persisted by FlushSecretFindings afterwards)
	secretDetector *secretscan.Detector
	secretMu       sync.Mutex
	secretFindings map[string][]storage.SecretFinding // URL → secret findings

	// JSTangle infrastructure for endpoint extraction from JS files. Admission,
	// caching, and worker concurrency are owned by the shared service.
	jstangleService        *jstangle.Service
	jstangleStatsBaseline  jstangle.ServiceStats
	requestTemplatesOnce   sync.Once
	requestTemplates       RequestTemplateRegistry
	jsAssetGraphOnce       sync.Once
	jsAssetGraph           *JSAssetGraph
	extractedRequests      []jstangle.ExtractedRequest // Collected requests for future task generation
	extractedRequestsMu    sync.Mutex                  // Protects extractedRequests slice
	extractedRequestsDedup *dedup.DiskSet              // Deduplication using hash

	// End-of-scan JS replay flush accounting (see tryFlushPendingJSReplay).
	// Touched only from the single WaitForQueues goroutine.
	jsReplayFlushCount     int
	jsReplayFlushCapLogged bool

	// vendorJSFetched counts vendor/CDN/library JS bundles admitted for jstangle
	// endpoint extraction, bounding them under a per-scan asset budget (see
	// admitVendorJSFetch).
	vendorJSFetched atomic.Int32
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
	PrefixesBroken   int // Number of path prefixes tripped by the breaker
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
		config:              cfg,
		stateNotify:         make(chan struct{}),
		taskQueue:           taskQueue,
		coordinator:         nil, // Initialized after engine creation
		httpClient:          httpClient,
		analyzer:            analyzer,
		fpCache:             fpCache,
		fpComparator:        fpComparator,
		fpLearner:           fpLearner,
		spiderCoordinator:   spiderCoordinatorInstance,
		spiderResolver:      spiderResolver,
		spiderScope:         spiderScope,
		redirectDetector:    redirectDetector,
		storage:             st,
		observedNames:       payload.NewObservedProviderWithLimit(cfg.Engine.CaseSensitivity == config.CaseSensitive, cfg.Engine.ObservedMaxItems),
		observedExtensions:  payload.NewObservedProviderWithLimit(cfg.Engine.CaseSensitivity == config.CaseSensitive, cfg.Engine.ObservedMaxItems),
		confirmedExtensions: make(map[string]struct{}),
		observedPaths:       payload.NewObservedProviderWithLimit(true, cfg.Engine.ObservedMaxItems), // Always case-sensitive for REST API paths
		observedFiles:       payload.NewObservedProviderWithLimit(cfg.Engine.CaseSensitivity == config.CaseSensitive, cfg.Engine.ObservedMaxItems),
		testedDirectories:   testedDirsTracker,
		testedFiles:         testedFilesTracker,
		prefixBreaker: tracker.NewPrefixBreaker(tracker.BreakerConfig{
			Enabled:        cfg.Engine.PrefixBreaker.Enabled,
			MinSamples:     cfg.Engine.PrefixBreaker.MinSamples,
			TripRatio:      cfg.Engine.PrefixBreaker.TripRatio,
			PrefixSegments: cfg.Engine.PrefixBreaker.PrefixSegments,
			LengthBucket:   cfg.Engine.PrefixBreaker.LengthBucket,
		}),
		taskHashes:           taskHashesDS,
		seenExtensions:       seenExtensionsDS,
		seenDiscoveredURLs:   seenDiscoveredURLsDS,
		formStructureCounter: dedup.NewCounter(),
		seenJSURLs:           seenJSURLsDS,
		seenBodyHashes:       seenBodyHashesDS,
		dedupBasePath:        dedupBasePath,
		requestCache:         reqCache,
		requestTemplates:     NewRequestTemplateRegistry(),
		ctx:                  ctx,
		cancel:               cancel,
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

	// Initialize the native in-process secret detector.
	if !cfg.Engine.DisableSecretScan {
		det, err := secretscan.Default()
		if err != nil {
			logger.Warn("Failed to initialize native secret detector", zap.Error(err))
		} else {
			engine.secretDetector = det
			engine.secretFindings = make(map[string][]storage.SecretFinding)
			logger.Info("Using native secret detector",
				zap.Int("rules", det.RuleCount()))
		}
	} else {
		logger.Info("Secret scanning disabled by user")
	}

	// Initialize the process-wide jstangle service before coordinator callbacks.
	// Discovery and passive modules deliberately share one admission/cache path.
	if cfg.JSTangle.Enabled {
		serviceConfig := jstangle.DefaultServiceConfig()
		if cfg.JSTangle.MemoryBudgetMB > 0 {
			serviceConfig.MemoryBudgetBytes = int64(cfg.JSTangle.MemoryBudgetMB) * 1024 * 1024
		}
		if cfg.JSTangle.CacheMB > 0 {
			serviceConfig.CacheBytes = int64(cfg.JSTangle.CacheMB) * 1024 * 1024
		}
		serviceConfig.WorkerCount = cfg.JSTangle.WorkerCount
		if serviceConfig.WorkerCount <= 0 && cfg.Engine.JSTangleConcurrency > 0 {
			serviceConfig.WorkerCount = cfg.Engine.JSTangleConcurrency
		}
		serviceConfig.WorkerMaxJobs = cfg.JSTangle.WorkerMaxJobs
		if cfg.JSTangle.WorkerMaxRSSMB > 0 {
			serviceConfig.WorkerMaxRSSBytes = int64(cfg.JSTangle.WorkerMaxRSSMB) * 1024 * 1024
		}
		if cfg.JSTangle.NormalInputMB > 0 {
			serviceConfig.NormalInputBytes = int64(cfg.JSTangle.NormalInputMB) * 1024 * 1024
		}
		if cfg.JSTangle.MaxASTInputMB > 0 {
			serviceConfig.MaxASTInputBytes = int64(cfg.JSTangle.MaxASTInputMB) * 1024 * 1024
		}
		if cfg.JSTangle.HardInputMB > 0 {
			serviceConfig.HardInputBytes = int64(cfg.JSTangle.HardInputMB) * 1024 * 1024
		}
		if configureErr := jstangle.ConfigureDefaultService(serviceConfig); configureErr != nil {
			logger.Debug("Shared jstangle service already configured", zap.Error(configureErr))
		}
		jsTangleService, serviceErr := jstangle.DefaultService()
		if serviceErr != nil {
			logger.Warn("Failed to initialize jstangle service", zap.Error(serviceErr))
		} else {
			engine.jstangleService = jsTangleService
			engine.jstangleStatsBaseline = jsTangleService.Stats()
			if readyErr := jsTangleService.EnsureReady(); readyErr != nil {
				logger.Error("jstangle EnsureBinary error", zap.Error(readyErr))
			}
			logger.Info("Using shared jstangle service", zap.String("checksum", jsTangleService.Checksum()))
		}
	} else {
		logger.Info("JavaScript intelligence disabled by configuration")
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
				if !errors.Is(err, context.Canceled) {
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

	e.logJSTangleSummary()

	logger.Debug("Cleaning up engine resources")
	e.cleanup()

	logger.Info("Discovery engine stopped")
}

func (e *Engine) logJSTangleSummary() {
	if e.jstangleService == nil {
		return
	}
	current := e.jstangleService.Stats()
	baseline := e.jstangleStatsBaseline
	delta := func(now, before int64) int64 {
		if now < before {
			return now
		}
		return now - before
	}
	high, medium, hints := 0, 0, 0
	if e.requestTemplates != nil {
		for _, template := range e.requestTemplates.All() {
			switch template.Confidence {
			case "high":
				high++
			case "medium":
				medium++
			default:
				hints++
			}
		}
	}
	cacheHits := delta(current.CacheHits, baseline.CacheHits)
	cacheMisses := delta(current.CacheMisses, baseline.CacheMisses)
	rejected := delta(current.RejectedJobs, baseline.RejectedJobs)
	logger.Info("JavaScript analysis summary",
		zap.Int64("files", cacheHits+cacheMisses+rejected),
		zap.Int64("cache_hits", cacheHits),
		zap.Int64("worker_jobs", delta(current.WorkerStarted, baseline.WorkerStarted)),
		zap.Int64("coalesced_jobs", delta(current.Coalesced, baseline.Coalesced)),
		zap.Int("high_confidence_requests", high),
		zap.Int("conservative_requests", medium),
		zap.Int("hints", hints),
		zap.Int64("degraded_files", delta(current.DegradedJobs, baseline.DegradedJobs)),
		zap.Int64("lexical_fallbacks", delta(current.FallbackJobs, baseline.FallbackJobs)),
		zap.Int64("rejected_files", rejected),
		zap.Int64("worker_restarts", delta(current.WorkerRestarts, baseline.WorkerRestarts)),
		zap.Uint64("exact_replays", e.coordinator.Metrics().JSReplayExact.Load()),
		zap.Uint64("conservative_replays", e.coordinator.Metrics().JSReplayConservative.Load()),
		zap.Uint64("successful_replays", e.coordinator.Metrics().JSReplaySucceeded.Load()),
		zap.Uint64("failed_replays", e.coordinator.Metrics().JSReplayFailed.Load()),
		zap.Uint64("deduplicated_replays", e.coordinator.Metrics().JSReplayDeduped.Load()))
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
		OnDirectoryDiscovered:       e.OnDirectoryDiscovered,
		OnFileDiscovered:            e.OnFileDiscovered,
		OnResult:                    e.onResult,
		AddObservedName:             e.AddObservedNameTrusted,
		AddObservedPath:             e.AddObservedPathTrusted,
		QueueJSFetch:                func(urls []*url.URL) { e.queueJSFetch(urls, 0) },
		HTTPClient:                  e.httpClient,
		Analyzer:                    e.analyzer,
		RedirectDetector:            NewRedirectDetector(),
		MaxDepth:                    uint16(e.config.Target.Recursion.MaxDepth),
		RequestCache:                e.requestCache,
		ErrorTracker:                e.errorTracker,
		WAFBlockTracker:             e.wafBlockTracker,
		WAFDetector:                 e.wafDetector,
		CustomHeaders:               e.config.Engine.CustomHeaders,
		JSTangleService:             e.jstangleService,
		JSTangleOptions:             e.jsTangleOptions,
		AddExtractedRequest:         e.AddExtractedRequest,
		AddRequestFact:              e.AddRequestFact,
		RequeueReplayTemplate:       e.RequeueReplayTemplate,
		StoreJSTangleRequests:       e.storeJSTangleRequests,
		StoreJSTangleFacts:          e.storeJSTangleFacts,
		ProcessJSTangleCapabilities: e.processJSTangleCapabilityFacts,
		ProcessAssetFacts:           e.processAssetFacts,
		ProcessSourceMap:            e.processSourceMapResponse,
		ScopeChecker:                e.spiderScope,
		PrefixBreaker:               e.prefixBreaker,
	}
}

// SetDisplayCallback sets the real-time display callback.
func (e *Engine) SetDisplayCallback(cb func(result *Result)) {
	e.displayCallback = cb
}

// SetExtensionConfirmCallback sets the callback fired when a server-side
// extension is confirmed as a valid route and queued for wordlist fuzzing.
// Used to surface a console line; safe to leave nil.
func (e *Engine) SetExtensionConfirmCallback(cb func(ExtensionConfirmEvent)) {
	e.extensionConfirmCallback = cb
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

	hashKey := strconv.FormatUint(hash, 16)
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
	// A JS/manifest path that carries a reflected query parameter (e.g. a
	// Salesforce Aura captcha iframe src "/apex/APP_Login_NewCaptcha?source=x",
	// or an SPA route "/search?q=") must be fetched WITH its query so the
	// parameter becomes a scannable insertion point. sanitizeObservedPath strips
	// the query for directory discovery, so first route the full URL through the
	// extracted-request channel (resolveRequestURL preserves RawQuery).
	e.preserveQueryParamAsRequest(path)

	path = sanitizeObservedPath(path)
	if path == "" {
		return
	}
	e.observedPaths.Add([]byte(path))
}

// preserveQueryParamAsRequest queues a query-bearing extracted path as a GET
// request so the discovery fetch keeps the query string (and thus the reflected
// parameter) instead of dropping it. No-op for paths without a query param;
// duplicates are coalesced by the extracted-request dedup set.
func (e *Engine) preserveQueryParamAsRequest(path string) {
	if linkfinder.PathHasQuery(path) {
		e.AddExtractedRequest(&jstangle.ExtractedRequest{URL: path, Method: "GET"})
	}
}

// AddObservedPathTrusted records URL path from trusted sources (URLs, spider links, JS paths).
// Trusted sources get higher frequency to survive eviction over wordlist extraction items.
func (e *Engine) AddObservedPathTrusted(path string) {
	clean := sanitizeObservedPath(path)
	if clean == "" {
		return
	}
	e.observedPaths.AddWithFrequency([]byte(clean), payload.TrustedFrequencyBoost)

	// App Router route recovery: a page/route-handler chunk path encodes its
	// route in the directory structure (app/<segments>/page-<hash>.js). Derive
	// the addressable route so it gets probed, recorded, and scanned — App Router
	// routes are otherwise absent from _buildManifest.js.
	for _, route := range deriveAppRouterRoutes(clean) {
		if r := sanitizeObservedPath(route); r != "" && r != clean {
			e.observedPaths.AddWithFrequency([]byte(r), payload.TrustedFrequencyBoost)
		}
	}
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
func (e *Engine) AddExtractedRequest(req *jstangle.ExtractedRequest) bool {
	return e.addExtractedRequest(req, true)
}

func (e *Engine) addExtractedRequest(req *jstangle.ExtractedRequest, registerTemplate bool) bool {
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
	if registerTemplate {
		e.templateRegistry().AddLegacy("", *req)
	}

	logger.Debug("Added extracted request",
		zap.String("url", req.URL),
		zap.String("method", req.Method))

	return true
}

// AddRequestFact retains typed provenance and source URL while maintaining the
// legacy request view used by existing reporting consumers.
func (e *Engine) AddRequestFact(sourceURL string, fact jstangle.HTTPRequestFact) bool {
	if !e.templateRegistry().Add(sourceURL, fact) {
		return false
	}
	if fact.Provenance.Confidence == "low" || strings.HasPrefix(strings.TrimSpace(fact.URL.Rendered), "${") {
		if hint := staticTemplatePath(fact.URL.Rendered); hint != "" && hint != "/" {
			e.observedPaths.Add([]byte(hint))
		}
	}
	legacy := jstangle.LegacyRequestFromFact(fact)
	e.addExtractedRequest(&legacy, false)
	logger.Debug("Added typed JS request template",
		zap.String("source_url", sourceURL), zap.String("fact_id", fact.ID),
		zap.String("confidence", fact.Provenance.Confidence), zap.String("extractor", fact.Provenance.Extractor))
	return true
}

func (e *Engine) GetRequestTemplates() []ExtractedRequestTemplate {
	return e.templateRegistry().All()
}

func (e *Engine) PendingRequestTemplates() []ExtractedRequestTemplate {
	mode := strings.ToLower(strings.TrimSpace(e.config.JSTangle.ReplayMode))
	if mode == "off" {
		return nil
	}
	templates := e.templateRegistry().PendingReplay()

	// Single filter pass applying two orthogonal gates in place (PendingReplay
	// already drained the pending set, so a fully-filtered result still lets
	// end-of-scan quiescence proceed):
	//   - confidence: exact (default) replays only high-confidence facts;
	//     conservative also replays medium;
	//   - safety: withhold templates whose method/GraphQL operation the replay
	//     safety policy forbids from being sent during discovery. Withheld
	//     templates remain in the registry (items) for controlled consumers via
	//     All(); they are simply not auto-replayed here.
	requireHigh := mode != "conservative"
	policy := ParseReplaySafety(e.config.JSTangle.ReplaySafety)
	safe := templates[:0]
	withheld := 0
	for _, template := range templates {
		if requireHigh && template.Confidence != "high" {
			continue
		}
		if !policy.AllowsFact(&template.Request) {
			withheld++
			continue
		}
		safe = append(safe, template)
	}
	if withheld > 0 {
		logger.Debug("Replay safety policy withheld JS-extracted templates",
			zap.String("policy", strings.TrimSpace(e.config.JSTangle.ReplaySafety)),
			zap.Int("withheld", withheld), zap.Int("allowed", len(safe)))
	}
	return safe
}

// RequeueReplayTemplate returns a claimed JS-replay template to the pending set
// so a later end-of-scan flush round retries it. Wired into Callbacks so the
// coordinator can recover a template whose replay failed to send or was cut off
// by cancellation, rather than losing it to PendingReplay's destructive claim.
func (e *Engine) RequeueReplayTemplate(sourceURL, id string) bool {
	reg := e.templateRegistry()
	if reg == nil {
		return false
	}
	return reg.Requeue(sourceURL, id)
}

func (e *Engine) templateRegistry() RequestTemplateRegistry {
	e.requestTemplatesOnce.Do(func() {
		if e.requestTemplates == nil {
			e.requestTemplates = NewRequestTemplateRegistry()
		}
	})
	return e.requestTemplates
}

func (e *Engine) assetGraph() *JSAssetGraph {
	e.jsAssetGraphOnce.Do(func() {
		if e.jsAssetGraph == nil {
			e.jsAssetGraph = NewJSAssetGraph(JSAssetGraphConfig{
				MaxDepth:           e.config.JSTangle.MaxAssetDepth,
				MaxAssetsPerParent: e.config.JSTangle.MaxAssetsPerParent,
				MaxAssetsPerHost:   e.config.JSTangle.MaxAssetsPerHost,
				MaxAssetsTotal:     e.config.JSTangle.MaxAssetsTotal,
			})
		}
	})
	return e.jsAssetGraph
}

func staticTemplatePath(raw string) string {
	for {
		start := strings.Index(raw, "${")
		if start < 0 {
			break
		}
		end := strings.IndexByte(raw[start+2:], '}')
		if end < 0 {
			return ""
		}
		end += start + 2
		raw = raw[:start] + raw[end+1:]
	}
	return sanitizeObservedPath(raw)
}

// GetExtractedRequests returns collected requests (for future task generation).
// Returns a copy to avoid race conditions.
func (e *Engine) GetExtractedRequests() []jstangle.ExtractedRequest {
	e.extractedRequestsMu.Lock()
	defer e.extractedRequestsMu.Unlock()

	result := make([]jstangle.ExtractedRequest, len(e.extractedRequests))
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
	metrics.PrefixesBroken = e.prefixBreaker.TrippedCount()

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
						// Before declaring completion, drain any JS request facts
						// that slow tail bundles registered after the last replay
						// task already ran (the directory-scoped replay task is
						// deduped, so no further replay would otherwise fire).
						if e.tryFlushPendingJSReplay() {
							idleDetected = false
							continue
						}
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

// jsReplayFlushCap bounds how many end-of-scan JS replay rounds we schedule.
// Each round can register fresh facts (recursive discovery), so we loop — but
// cap it so a pathological bundle that keeps emitting new facts can't wedge
// quiescence indefinitely.
const jsReplayFlushCap = 8

// tryFlushPendingJSReplay enqueues one final JS-extracted replay task when the
// queue has otherwise gone idle but the template registry still holds pending
// facts. This closes the race where a slow tail JS bundle finishes analysis and
// registers request facts AFTER the last directory-scheduled replay task has
// already drained the pending set — the replay task identity is directory-based
// and deduped, so without this no further replay would be scheduled and those
// late-discovered routes would never reach dynamic assessment.
//
// It enqueues directly on the task queue (bypassing AddTask's hash dedup, which
// would suppress a second root replay) and returns true when a replay was
// scheduled, signalling the caller to keep waiting. Called only from the single
// WaitForQueues goroutine, so jsReplayFlushCount needs no synchronization.
func (e *Engine) tryFlushPendingJSReplay() bool {
	if e.jstangleService == nil {
		return false
	}
	reg := e.templateRegistry()
	if reg == nil {
		return false
	}
	pending := reg.PendingLen()
	if pending == 0 {
		return false
	}
	if e.jsReplayFlushCount >= jsReplayFlushCap {
		if !e.jsReplayFlushCapLogged {
			logger.Warn("JS replay flush cap reached; leftover pending templates will not be replayed",
				zap.Int("pending", pending),
				zap.Int("cap", jsReplayFlushCap))
			e.jsReplayFlushCapLogged = true
		}
		return false
	}
	targetURL, err := url.Parse(e.config.Target.StartURL)
	if err != nil {
		return false
	}
	task := e.factory.CreateJSExtractedRequestTask(
		targetURL, e.GetExtractedRequests, 0, e.PendingRequestTemplates,
	)
	if task == nil {
		return false
	}
	e.jsReplayFlushCount++
	e.taskQueue.Enqueue(task)
	logger.Info("Scheduled end-of-scan JS replay flush",
		zap.Int("pending", pending),
		zap.Int("round", e.jsReplayFlushCount))
	return true
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
}

// scanBodyForSecrets scans an eligible response body for secrets inline and
// accumulates the matches under its URL. Thread-safe for concurrent use from
// callbacks (the crawler runs many worker goroutines).
func (e *Engine) scanBodyForSecrets(body []byte, mimeType, urlPath, urlStr string) {
	if e.secretDetector == nil {
		return
	}
	// Shared secret-scan eligibility (size cap + media + text MIME) so the crawl
	// agrees with the passive module and the known-issue batch on what reaches the
	// detector — the crawl previously had no upper size cap.
	if !pkghttp.ShouldScanBodyForSecrets(mimeType, urlPath, len(body)) {
		return
	}

	matches := e.secretDetector.Detect(body)
	if len(matches) == 0 {
		return
	}
	findings := make([]storage.SecretFinding, 0, len(matches))
	for _, mt := range matches {
		findings = append(findings, storage.SecretFinding{
			RuleID:     mt.RuleID,
			RuleName:   mt.RuleName,
			Snippet:    mt.Secret,
			Confidence: mt.Confidence,
			Validated:  false, // native detector performs no live verification
		})
	}

	e.secretMu.Lock()
	e.secretFindings[urlStr] = append(e.secretFindings[urlStr], findings...)
	e.secretMu.Unlock()
}

// FlushSecretFindings persists the secret matches accumulated during the crawl to
// the corresponding DB records. Must be called after crawling completes
// (WaitForQueues) but before Stop.
func (e *Engine) FlushSecretFindings() {
	if e.secretDetector == nil {
		return
	}

	e.secretMu.Lock()
	urlFindings := e.secretFindings
	e.secretFindings = make(map[string][]storage.SecretFinding)
	e.secretMu.Unlock()

	if len(urlFindings) == 0 {
		logger.Debug("Secret scan: no findings")
		return
	}

	// Batch update DB records.
	if e.storage != nil {
		jsonMap := make(map[string]string, len(urlFindings))
		for url, findings := range urlFindings {
			data, err := json.Marshal(findings)
			if err != nil {
				continue
			}
			jsonMap[url] = string(data)
		}
		if err := e.storage.BatchUpdateSecretFindings(jsonMap); err != nil {
			logger.Warn("Secret scan: DB update failed", zap.Error(err))
		}
	}

	totalFindings := 0
	for _, fs := range urlFindings {
		totalFindings += len(fs)
	}
	logger.Info("Secret scan completed",
		zap.Int("findings", totalFindings),
		zap.Int("urls_with_findings", len(urlFindings)))
}
