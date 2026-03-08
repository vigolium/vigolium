package crawler

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/condition"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/fragment"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/mab"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/metrics"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// Crawler is the main web crawler engine.
type Crawler struct {
	config      *config.Config
	graph       *state.Graph
	candidates  *action.UnfiredFragmentCandidates // CRAWLJAX PARITY: UnfiredFragmentCandidates
	browserPool *browser.Pool
	extractor   *action.CandidateElementExtractor
	comparator  *state.Comparator
	formHandler *form.Handler
	fragManager *fragment.Manager

	// Conditions
	crawlConditions []*condition.Condition
	waitConditions  []*condition.WaitCondition

	// Invariants - conditions that must always hold
	invariants []*condition.Condition

	// Invariant checker (optional) - structured invariant management
	invariantChecker *condition.InvariantChecker

	// Form input cache - stores successful form inputs per action
	// Uses DetectedInput for Go extension metadata (value rotation, etc.)
	formCache map[string][]*form.DetectedInput

	// Form trainer (optional) - for reproducible form testing
	formTrainer *form.FormTrainer

	// ND Cluster manager (optional) - for near-duplicate state clustering
	clusterMgr *state.NDClusterManager

	// CRAWLJAX PARITY: StateMachine (LOCAL per crawler, RESET on backtrack)
	// Contains currentState, initialState, onURLSet
	// Reference to graph is shared (GLOBAL)
	stateMachine *state.StateMachine

	// CRAWLJAX PARITY: CrawlPath - tracks current backtrack attempt
	// NEW instance created on each reset()
	crawlPath *state.CrawlPath

	// CRAWLJAX PARITY: CrawlSession - stores all crawl paths
	session *CrawlSession

	// CRAWLJAX PARITY: EventableConditionChecker for form-to-element linking
	// Used to generate action combinations with different form input values.
	eventableConditions *condition.EventableConditionChecker

	// CRAWLJAX PARITY: Tracks if reset() was ever called during this crawl.
	// Used to determine if we need to add final reload edge when crawl finishes.
	resetCalled bool

	// CRAWLJAX PARITY: crawlDepth counter - reset to 0 on each reset()
	// Java: Crawler.java line 318: crawlDepth.set(0)
	crawlDepth int

	// Metrics collector for benchmark tracking (optional)
	metricsCollector *metrics.Collector

	// MAB policy for adaptive action selection (optional, used when strategy=adaptive)
	// RLCRAWLER PARITY: Exp3.1 Multi-Armed Bandit algorithm
	mabPolicy *mab.MABExp3Policy

	// Writer for network traffic capture output
	writer network.Writer

	mu      sync.Mutex
	stats   Stats
	running bool
}

// Stats holds crawl statistics.
type Stats struct {
	StatesDiscovered    int
	StatesDuplicate     int
	ActionsExecuted     int
	ActionsFailed       int
	ConsecutiveFailures int // Current streak of consecutive failures
	FormsSubmitted      int
	BacktrackCount      int
	InvariantFails      int
	StartTime           time.Time
	EndTime             time.Time
}

// New creates a new crawler.
func New(cfg *config.Config) (*Crawler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// CRAWLJAX PARITY: Create UnfiredFragmentCandidates with config
	candidatesConfig := &action.UnfiredFragmentCandidatesConfig{
		MaxRepeat:             action.DefaultMaxRepeat,
		SkipExploredActions:   true,
		ApplyNonSelAdvantage:  false,
		RestoreConnectedEdges: false,
		QueueBufferSize:       1000,
	}

	c := &Crawler{
		config:              cfg,
		graph:               state.NewGraph(),
		candidates:          action.NewUnfiredFragmentCandidates(candidatesConfig, nil), // StateProvider set after graph init
		extractor:           action.NewCandidateElementExtractor(cfg),
		comparator:          state.NewComparator(cfg),
		formHandler:         form.NewHandler(cfg),
		fragManager:         fragment.NewManager(),
		crawlConditions:     make([]*condition.Condition, 0),
		waitConditions:      make([]*condition.WaitCondition, 0),
		invariants:          make([]*condition.Condition, 0),
		formCache:           make(map[string][]*form.DetectedInput),
		eventableConditions: condition.NewEventableConditionChecker(),
		writer:              network.NopWriter{}, // Default no-op; override with SetWriter()
		stats:               Stats{},
		// NOTE: stateMachine, crawlPath, session initialized in initializeIndexState()
	}

	// Convert config conditions
	for _, cc := range cfg.CrawlConditions {
		c.crawlConditions = append(c.crawlConditions, condition.NewFromConfig(cc))
	}

	for _, wc := range cfg.WaitConditions {
		c.waitConditions = append(c.waitConditions, condition.NewWaitConditionFromConfig(wc))
	}

	// Initialize MAB policy if strategy is adaptive
	// RLCRAWLER PARITY: Use DefaultK=100 for Exp3.1 algorithm
	if cfg.CrawlStrategy == config.CrawlStrategyAdaptive {
		c.mabPolicy = mab.NewMABExp3Policy(mab.DefaultK)
		c.candidates.SetMABPolicy(c.mabPolicy)
		zap.L().Debug("MAB Exp3.1 policy initialized",
			zap.Int("K", mab.DefaultK),
			zap.String("strategy", string(cfg.CrawlStrategy)))
	}

	return c, nil
}

// SetWriter sets the network traffic writer used during crawling.
// Must be called before Run().
func (c *Crawler) SetWriter(w network.Writer) {
	c.writer = w
}

// AddInvariant adds an invariant condition that must always hold.
func (c *Crawler) AddInvariant(inv *condition.Condition) {
	c.invariants = append(c.invariants, inv)
}

// SetInvariantChecker sets the invariant checker for structured invariant management.
func (c *Crawler) SetInvariantChecker(checker *condition.InvariantChecker) {
	c.invariantChecker = checker
}

// SetFormTrainer sets the form trainer for reproducible form testing.
func (c *Crawler) SetFormTrainer(trainer *form.FormTrainer) {
	c.formTrainer = trainer
}

// GetFormTrainer returns the form trainer.
func (c *Crawler) GetFormTrainer() *form.FormTrainer {
	return c.formTrainer
}

// SetMetricsCollector sets the metrics collector for benchmark tracking.
func (c *Crawler) SetMetricsCollector(collector *metrics.Collector) {
	c.metricsCollector = collector
}

// GetMetricsCollector returns the metrics collector.
func (c *Crawler) GetMetricsCollector() *metrics.Collector {
	return c.metricsCollector
}

// SetClusterManager sets the ND cluster manager for near-duplicate state clustering.
func (c *Crawler) SetClusterManager(mgr *state.NDClusterManager) {
	c.clusterMgr = mgr
}

// GetClusterManager returns the ND cluster manager.
func (c *Crawler) GetClusterManager() *state.NDClusterManager {
	return c.clusterMgr
}

// AddEventableCondition adds an eventable condition for form-to-element linking.
// This enables generating multiple action variants with different form input values.
func (c *Crawler) AddEventableCondition(ec *condition.EventableCondition) {
	c.eventableConditions.Add(ec)
}

// GetEventableConditions returns the eventable condition checker.
func (c *Crawler) GetEventableConditions() *condition.EventableConditionChecker {
	return c.eventableConditions
}

// Run starts the crawl.
func (c *Crawler) Run(ctx context.Context) (*Result, error) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil, fmt.Errorf("crawler is already running")
	}
	c.running = true
	c.stats.StartTime = time.Now()
	c.mu.Unlock()

	zap.L().Debug("Crawler starting",
		zap.String("url", c.config.URL.String()),
		zap.Int("max_states", c.config.MaxStates),
		zap.Int("max_depth", c.config.MaxDepth),
		zap.String("strategy", string(c.config.CrawlStrategy)))

	defer func() {
		c.mu.Lock()
		c.running = false
		c.stats.EndTime = time.Now()
		c.mu.Unlock()
	}()

	// Create browser pool FIRST (needed for browser-level capture)
	pool, err := browser.NewPool(c.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create browser pool: %w", err)
	}
	c.browserPool = pool
	zap.L().Debug("Browser pool created", zap.Int("size", c.config.BrowserCount))
	defer func() { _ = pool.Close() }()

	// Create traffic capture with the configured writer
	capture := network.New(c.writer, c.config.NoColor, c.config.Silent, c.config.Verbose, c.config.IncludeResponseBody, c.config.IncludeResponseHeaders, c.config.URL.Hostname(), "spider")
	defer func() { _ = capture.Close() }()

	// Start capture at BROWSER level (captures ALL pages)
	br := pool.Get()
	zap.L().Debug("Starting network capture",
		zap.Bool("include_body", c.config.IncludeResponseBody),
		zap.Bool("include_headers", c.config.IncludeResponseHeaders))
	if err := capture.Start(br.RodBrowser()); err != nil {
		return nil, fmt.Errorf("failed to start traffic capture: %w", err)
	}
	zap.L().Debug("Traffic capture enabled")

	// CRAWLJAX PARITY: Wire eventable conditions to extractor for form input combinations
	if c.eventableConditions != nil && c.eventableConditions.Count() > 0 {
		c.extractor.SetFormHandler(&formHandlerAdapter{checker: c.eventableConditions})
	}

	// Initialize
	if err := c.initializeIndexState(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize: %w", err)
	}

	// Main crawl loop
	if err := c.crawlLoop(ctx); err != nil {
		zap.L().Debug("Crawl loop ended", zap.Error(err))
	}

	// Log final MAB summary
	c.logMABFinalSummary()

	return c.buildResult(), nil
}

// logMABFinalSummary logs comprehensive MAB policy state at end of crawl.
func (c *Crawler) logMABFinalSummary() {
	if c.mabPolicy == nil {
		return
	}

	k, r, gThr, eta, globalR := c.mabPolicy.GetGlobalParams()
	stateCount := c.mabPolicy.GetStateCount()
	actionCount := c.mabPolicy.GetActionCount()

	zap.L().Debug("=== MAB FINAL SUMMARY ===",
		zap.Int("K", k),
		zap.Int("round", r),
		zap.Float64("G_thr", gThr),
		zap.Float64("eta", eta),
		zap.Float64("global_R", globalR),
		zap.Int("total_states", stateCount),
		zap.Int("total_actions", actionCount))
}

// initializeIndexState loads the initial page and captures the index state.
func (c *Crawler) initializeIndexState(ctx context.Context) error {
	zap.L().Debug("Initializing index state")

	br := c.browserPool.Get()
	if br == nil {
		return fmt.Errorf("no browser available")
	}

	page, err := br.NewPage()
	if err != nil {
		return err
	}

	// Set as current page so executeActionDFS can access it
	br.SetCurrentPage(page)

	// Set initial cookies if provided (from auth bootstrap)
	if len(c.config.InitialCookies) > 0 {
		zap.L().Debug("Setting initial cookies", zap.Int("count", len(c.config.InitialCookies)))
		if err := page.SetCookies(c.config.InitialCookies); err != nil {
			zap.L().Warn("Failed to set initial cookies", zap.Error(err))
		}
	}

	// Navigate to target URL
	url := c.config.URL.String()
	if c.config.BasicAuthUser != "" {
		url = c.config.GetBasicAuthURL()
	}

	zap.L().Debug("Navigating to target", zap.String("url", c.config.URL.String()))
	zap.L().Debug("Navigation URL prepared", zap.String("url", url))

	if err := page.NavigateCtx(ctx, url); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to navigate: %w", err)
	}

	// Check wait conditions
	c.checkWaitConditions(page)

	// Wait for DOM to stabilize
	zap.L().Debug("Waiting for DOM to stabilize", zap.Duration("wait_time", c.config.DOMStableTime))
	if err := page.WaitStable(c.config.DOMStableTime); err != nil {
		if ctxErr := sleepWithContext(ctx, c.config.DOMStableTime); ctxErr != nil {
			return ctxErr
		}
	}

	// Fill forms if present
	if c.config.FormFillEnabled {
		zap.L().Debug("Form filling enabled, detecting forms")
		c.fillFormsIfPresent(page, "")
	}

	// Capture index state
	zap.L().Debug("Capturing index state")
	indexState, err := c.captureState(ctx, page, 0)
	if err != nil {
		return fmt.Errorf("failed to capture index state: %w", err)
	}
	zap.L().Debug("Index state captured",
		zap.String("state_id", indexState.ID),
		zap.String("url", indexState.URL),
		zap.Int("dom_size", len(indexState.StrippedDOM)))

	// Add to graph
	c.graph.AddState(indexState)
	c.candidates.RecordStateCreation(indexState.ID) // CRAWLJAX PARITY: Track state order for OLDEST_FIRST mode
	c.stats.StatesDiscovered++

	// RLCRAWLER PARITY: Register index state with MAB policy
	if c.mabPolicy != nil {
		c.mabPolicy.AddState(indexState.ID)
	}

	// CRAWLJAX PARITY: Initialize StateMachine with index state
	c.stateMachine = state.NewStateMachine(c.graph, indexState)

	// CRAWLJAX PARITY: Initialize session
	c.session = NewCrawlSession(c.config, indexState)

	// CRAWLJAX PARITY: Initialize first crawl path (for initial exploration)
	c.crawlPath = state.NewCrawlPath(indexState.ID)

	zap.L().Debug("Index state captured", zap.String("state", indexState.Name))

	// Extract fragments
	c.extractFragments(page, indexState)

	// Extract initial actions (check crawl conditions first)
	if c.shouldCrawl(page) {
		actions, err := c.extractor.Extract(ctx, page)
		if err != nil {
			zap.L().Debug("Failed to extract actions", zap.Error(err))
		} else {
			c.candidates.AddActions(actions, indexState.ID)
			added := len(actions)
			zap.L().Debug("Extracted actions from index state", zap.Int("count", added))
		}

		// NOTE: Frame extraction is already handled by c.extractor.Extract() which
		// recursively processes frames with correct framePath. No separate call needed.
	}

	return nil
}

// crawlLoop is the main crawl loop.
// CRAWLJAX PARITY: This now matches Crawljax's CrawlTaskConsumer architecture:
//  1. Poll a STATE (not action) from the queue
//  2. Call execute(state) which:
//     a. If not at state, reset() to index (adds reload edge) then reachFromHome()
//     b. crawlThroughActions() - DFS through all actions from current state
//  3. TaskDone(state) - re-add state to queue if it still has actions
func (c *Crawler) crawlLoop(ctx context.Context) error {
	iteration := 0
	for {
		iteration++
		// Log queue stats every iteration for debugging
		stats := c.candidates.Stats()
		isEmpty := c.candidates.IsEmpty()
		zap.L().Debug("CrawlLoop iteration",
			zap.Int("iteration", iteration),
			zap.Int("pending_states", stats.TotalPending),
			zap.Int("total_seen", stats.TotalSeen))

		// Check termination conditions
		if c.shouldTerminate(ctx) {
			zap.L().Debug("Termination condition met")
			c.addFinalReloadEdge()
			return nil
		}

		// Check if queue is empty
		if isEmpty {
			zap.L().Debug("No more states to crawl")
			c.addFinalReloadEdge()
			return nil
		}

		// Poll a STATE (not action) from the queue based on crawl strategy
		stateID := c.candidates.PollStateByPriority(c.config.CrawlStrategy)
		if stateID == "" {
			zap.L().Debug("No more states with pending actions")
			c.addFinalReloadEdge()
			return nil
		}

		zap.L().Debug("Processing state", zap.String("state_id", stateID))

		// Get the state to crawl
		crawlTask, ok := c.graph.GetState(stateID)
		if !ok {
			zap.L().Warn("State not found, skipping", zap.String("state_id", stateID))
			continue
		}

		// CRAWLJAX PARITY: Execute the crawl task for this state
		c.execute(ctx, crawlTask)

		zap.L().Debug("Execute completed for state", zap.String("state_id", stateID))

		// CRAWLJAX PARITY: Check if state still has actions (for re-adding to queue)
		c.candidates.TaskDone(stateID)

		// Log MAB summary every 5 iterations for debugging
		if c.mabPolicy != nil && iteration%5 == 0 {
			c.logMABSummary()
		}
	}
}

// logMABSummary logs a summary of MAB policy state for debugging.
func (c *Crawler) logMABSummary() {
	if c.mabPolicy == nil {
		return
	}

	k, r, gThr, eta, globalR := c.mabPolicy.GetGlobalParams()
	stateCount := c.mabPolicy.GetStateCount()
	actionCount := c.mabPolicy.GetActionCount()

	zap.L().Debug("MAB Summary",
		zap.Int("K", k),
		zap.Int("round", r),
		zap.Float64("G_thr", gThr),
		zap.Float64("eta", eta),
		zap.Float64("global_R", globalR),
		zap.Int("states_tracked", stateCount),
		zap.Int("actions_tracked", actionCount))
}

// execute crawls all actions from a target state.
// CRAWLJAX PARITY: This matches Java Crawljax Crawler.execute(StateVertex crawlTask) exactly.
// Java Flow (Crawler.java:378-422):
//  1. If at crawlTask state -> setBTStatus(true, -1) + crawlThroughActions() (NO EARLY RETURN!)
//  2. ALWAYS: reset() + reachFromHome() + crawlThroughActions()
func (c *Crawler) execute(ctx context.Context, crawlTask *state.State) {
	zap.L().Debug("Execute task for state",
		zap.String("state", crawlTask.Name),
		zap.String("state_id", crawlTask.ID))

	currentState := c.stateMachine.GetCurrentState()

	// CRAWLJAX PARITY: BLOCK 1 - If at crawlTask, crawl first (NO EARLY RETURN!)
	// Java: if (crawlTask.getId() == stateMachine.getCurrentState().getId())
	if currentState != nil && currentState.ID == crawlTask.ID {
		zap.L().Debug("Already at target state, crawling through actions first")
		c.crawlPath.MarkSuccess()
		c.crawlThroughActions(ctx)
		zap.L().Debug("crawlThroughActions completed (same state)")
		// CRITICAL: Java does NOT return here! It continues to reset+reachFromHome+crawlThroughActions
	}

	// CRAWLJAX PARITY: BLOCK 2 - ALWAYS execute (Java lines 403-421)
	// Java: LOG.info("Resetting the crawler and Going to state {}", crawlTask.getName());
	//       reset(crawlTask.getId());
	//       reachFromHome(crawlTask);
	//       crawlThroughActions();

	if c.shouldTerminate(ctx) {
		return
	}

	currentStateName := "none"
	if currentState != nil {
		currentStateName = currentState.Name
	}
	zap.L().Debug("Resetting the crawler and going to state",
		zap.String("current_state", currentStateName),
		zap.String("target_state", crawlTask.Name))

	if err := c.reset(ctx, crawlTask.ID); err != nil {
		zap.L().Debug("Reset failed", zap.Error(err))
		c.crawlPath.MarkFailed()
		return
	}
	zap.L().Debug("Reset completed")

	if c.shouldTerminate(ctx) {
		return
	}

	// CRAWLJAX PARITY: reachFromHome() - if fails -> purge and return
	zap.L().Debug("Reaching target state from home", zap.String("target", crawlTask.Name))
	if err := c.reachFromHome(ctx, crawlTask); err != nil {
		zap.L().Debug("State unreachable, removing from candidate actions",
			zap.String("state", crawlTask.Name), zap.Error(err))
		c.candidates.PurgeState(crawlTask.ID)
		return
	}

	if c.shouldTerminate(ctx) {
		return
	}

	// CRAWLJAX PARITY: crawlThroughActions() after reachFromHome
	c.crawlThroughActions(ctx)
	zap.L().Debug("crawlThroughActions completed")
}

// reset navigates to the index URL and creates a NEW StateMachine.
// CRAWLJAX PARITY: This matches Java Crawljax Crawler.reset(int nextTarget) exactly.
// CRITICAL: Order matches Java exactly (Crawler.java:266-319):
// 1. browser.handlePopups() - FIRST THING!
// 2. Save crawlPath to session
// 3. Get onURLSet + previousState from OLD StateMachine
// 4. Create NEW StateMachine BEFORE navigate
// 5. Create NEW CrawlPath
// 6. Navigate to URL
// 7. checkOnURLState() using NEW StateMachine
// 8. crawlDepth.set(0) - LAST THING!
func (c *Crawler) reset(ctx context.Context, nextTarget string) error {
	// CRAWLJAX PARITY: Step 1 - handlePopups() FIRST (Java line 268)
	br := c.browserPool.Get()
	page := br.CurrentPage()
	if page != nil {
		_ = page.HandlePopups()
	}

	// CRAWLJAX PARITY: Step 2 - Save current crawlPath to session
	if c.crawlPath != nil {
		c.crawlPath.Close()
		c.session.AddCrawlPath(c.crawlPath.ImmutableCopy())
	}

	// CRAWLJAX PARITY: Step 2 - Get onURLSet + previousState from OLD StateMachine
	var onURLSet map[string]*state.State
	var previousState *state.State
	if c.stateMachine != nil {
		onURLSet = c.stateMachine.GetOnURLSet()
		previousState = c.stateMachine.GetCurrentState()
	} else {
		onURLSet = make(map[string]*state.State)
	}

	// CRAWLJAX PARITY: Step 3 - Create NEW StateMachine BEFORE navigate
	// Java: stateMachine = new StateMachine(graphProvider.get(), ..., onURLSetTemp)
	indexState := c.graph.GetIndexState()
	c.stateMachine = state.NewStateMachineWithOnURLSet(c.graph, indexState, onURLSet)
	zap.L().Debug("Reset: created NEW StateMachine BEFORE navigate",
		zap.String("initial_state", indexState.Name),
		zap.Int("onURLSet_size", c.stateMachine.OnURLSetSize()))

	// CRAWLJAX PARITY: Step 4 - Create NEW CrawlPath
	c.crawlPath = state.NewCrawlPath(nextTarget)

	// CRAWLJAX PARITY: Step 5 - Navigate to URL (AFTER creating StateMachine)
	resetURL := c.config.URL.String()
	if c.config.BasicAuthUser != "" {
		resetURL = c.config.GetBasicAuthURL()
	}

	// Reuse br/page from Step 1, or get new if needed
	if page == nil {
		br = c.browserPool.Get()
		page = br.CurrentPage()
	}
	if page == nil {
		var err error
		page, err = br.NewPage()
		if err != nil {
			return err
		}
		br.SetCurrentPage(page)
	}

	if err := page.NavigateCtx(ctx, resetURL); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("reset navigation failed: %w", err)
	}

	// Wait for page to stabilize
	if err := page.WaitStable(c.config.WaitAfterReload); err != nil {
		if ctxErr := sleepWithContext(ctx, c.config.WaitAfterReload); ctxErr != nil {
			return ctxErr
		}
	}
	c.checkWaitConditions(page)

	// CRAWLJAX PARITY: Step 7 - checkOnURLState() using NEW StateMachine
	// Java: checkOnURLState(previousState) - uses stateMachine.newStateFor(browser)
	c.checkOnURLState(ctx, page, previousState, resetURL)

	// CRAWLJAX PARITY: Step 8 - Reset crawlDepth (Java line 318: crawlDepth.set(0))
	c.crawlDepth = 0

	c.resetCalled = true
	c.stats.BacktrackCount++
	return nil
}

// reachFromHome navigates from current state to target state.
// CRAWLJAX PARITY: Matches Java Crawljax Crawler.reachFromHome() exactly.
// Java flow:
// 1. Try shortest path from CURRENT state to target
// 2. If fails, try from each onURLSet state
// 3. Navigate to onURL state, then follow path
func (c *Crawler) reachFromHome(ctx context.Context, target *state.State) error {
	zap.L().Debug("Reaching target state", zap.String("target", target.Name))

	indexState := c.graph.GetIndexState()
	if indexState == nil {
		return fmt.Errorf("no index state")
	}

	br := c.browserPool.Get()
	page := br.CurrentPage()

	// CRAWLJAX PARITY: Track already tried starting points
	alreadyTried := make(map[string]bool)

	// CRAWLJAX PARITY: First try from CURRENT state (after reset, this is index)
	// Java: path = shortestPathTo(crawlTask);
	currentState := c.stateMachine.GetCurrentState()
	if currentState != nil {
		alreadyTried[currentState.ID] = true
		path := c.graph.ShortestPath(currentState.ID, target.ID)
		if path != nil {
			zap.L().Debug("Path found from current state",
				zap.String("from", currentState.Name),
				zap.Int("path_length", len(path)))
			err := c.followPath(ctx, path, target)
			if err == nil {
				// CRAWLJAX PARITY: Check if reached near-duplicate instead of target
				// Java lines 447-459: if (!crawlTask.equals(stateMachine.getCurrentState()))
				reachedState := c.stateMachine.GetCurrentState()
				if reachedState.ID != target.ID {
					zap.L().Debug("Tried reaching target but reached near-duplicate",
						zap.String("target", target.Name),
						zap.String("reached", reachedState.Name))
					c.crawlPath.SetBacktrackSuccess(false)
					c.crawlPath.SetReachedNearDup(reachedState.ID)
					c.candidates.StateUpdated(target.ID) // CRAWLJAX PARITY: Java line 455
				} else {
					zap.L().Debug("Reached the correct target", zap.String("target", target.Name))
					c.crawlPath.SetBacktrackSuccess(true)
				}
				return nil
			}
			// CRAWLJAX PARITY: Path failed - reset before trying onURLSet states
			// Java lines 467-470: setBTStatus(false, -1); reset(crawlTask.getId());
			zap.L().Debug("Path from current state failed, resetting before trying onURLSet",
				zap.String("from", currentState.Name),
				zap.Error(err))
			c.crawlPath.SetBacktrackSuccess(false)
			_ = c.reset(ctx, target.ID) // CRITICAL: Reset on first path failure!
		}
	}

	// CRAWLJAX PARITY: Try from each onURLSet state (Java lines 479-539)
	// Java: for (int i = 0; i < size; i++) { StateVertex onURL = stateMachine.getOnURLSet().get(i); ... }
	onURLStates := c.stateMachine.GetOnURLSetSlice()
	for _, onURLState := range onURLStates {
		if c.shouldTerminate(ctx) {
			return ctx.Err()
		}
		if alreadyTried[onURLState.ID] {
			zap.L().Debug("Skipping already tried onURL state", zap.String("state", onURLState.Name))
			continue
		}
		alreadyTried[onURLState.ID] = true

		// Find path from this onURL state to target
		path := c.graph.ShortestPath(onURLState.ID, target.ID)
		if path == nil {
			zap.L().Debug("No path from onURL state to target",
				zap.String("from", onURLState.Name),
				zap.String("to", target.Name))
			continue
		}

		zap.L().Debug("Trying path from onURL state",
			zap.String("from", onURLState.Name),
			zap.String("to", target.Name),
			zap.Int("path_length", len(path)))

		// CRAWLJAX PARITY: Navigate to onURL state first (browser.goToUrl(onURL.getUrl()))
		if err := page.NavigateCtx(ctx, onURLState.URL); err != nil {
			zap.L().Debug("Failed to navigate to onURL state",
				zap.String("state", onURLState.Name),
				zap.Error(err))
			if c.shouldTerminate(ctx) {
				return ctx.Err()
			}
			continue
		}
		if err := page.WaitStable(c.config.WaitAfterReload); err != nil {
			if ctxErr := sleepWithContext(ctx, c.config.WaitAfterReload); ctxErr != nil {
				return ctxErr
			}
		}
		c.checkWaitConditions(page)
		c.stateMachine.SetCurrentState(onURLState)

		// Follow path from onURL to target
		err := c.followPath(ctx, path, target)
		if err == nil {
			// CRAWLJAX PARITY: Check if reached near-duplicate instead of target
			// Java lines 512-524: same check as first attempt
			reachedState := c.stateMachine.GetCurrentState()
			if reachedState.ID != target.ID {
				zap.L().Debug("Tried reaching target but reached near-duplicate",
					zap.String("from", onURLState.Name),
					zap.String("target", target.Name),
					zap.String("reached", reachedState.Name))
				c.crawlPath.SetBacktrackSuccess(false)
				c.crawlPath.SetReachedNearDup(reachedState.ID)
				c.candidates.StateUpdated(target.ID)
			} else {
				zap.L().Debug("Reached the correct target",
					zap.String("from", onURLState.Name),
					zap.String("target", target.Name))
				c.crawlPath.SetBacktrackSuccess(true)
			}
			return nil
		}

		// CRAWLJAX PARITY: Path failed - reset and try next (Java line 534)
		zap.L().Debug("Path from onURL state failed, resetting",
			zap.String("from", onURLState.Name),
			zap.Error(err))
		c.crawlPath.SetBacktrackSuccess(false)
		_ = c.reset(ctx, target.ID)
	}

	return fmt.Errorf("cannot reach state %s from any starting point", target.Name)
}

// followPath executes actions along a path to reach the target state.
// CRAWLJAX PARITY: This matches Java Crawljax Crawler.follow()
func (c *Crawler) followPath(ctx context.Context, path []*action.Eventable, target *state.State) error {
	br := c.browserPool.Get()
	page := br.CurrentPage()

	for _, edge := range path {
		if c.shouldTerminate(ctx) {
			return ctx.Err()
		}
		// Check crawl conditions
		if !c.shouldCrawl(page) {
			return fmt.Errorf("crawl condition not met during path follow")
		}

		zap.L().Debug("Following edge", zap.String("source", edge.SourceStateID), zap.String("target", edge.TargetStateID))

		// Skip if edge has no identification
		if edge.Identification == nil {
			return fmt.Errorf("edge has no identification")
		}

		// CRAWLJAX PARITY: Form input handling from candidates
		// Java lines 591-601: shouldDisableInput + getInput check
		if c.config.FormFillEnabled {
			if !c.candidates.ShouldDisableInputForPath(edge) {
				// Try to get cached input from candidates
				cachedInputs := c.candidates.GetInput(edge)
				if len(cachedInputs) > 0 {
					// Use cached form inputs
					zap.L().Debug("Used cached form input for backtracking", zap.Int64("eventable_id", edge.ID))
					c.fillFormsWithInputs(page, cachedInputs)
				} else {
					// CRAWLJAX PARITY: No cached input, use getInputElements to merge
					// eventable.RelatedFormInputs with DOM-detected inputs
					zap.L().Debug("No cached input, using getInputElements", zap.Int64("eventable_id", edge.ID))
					handled := c.handleInputElements(page, edge)
					// Cache the handled inputs for future backtracking
					if len(handled) > 0 {
						c.candidates.MapInput(edge, handled)
					}
				}
			}
			// If shouldDisableInput is true, skip form filling entirely
		}

		// Execute the event based on EventType
		// CRITICAL: Check How to determine if selector is XPath or CSS
		selector := edge.GetSelector()
		isXPath := edge.Identification != nil && edge.Identification.How == action.HowXPath
		switch edge.EventType {
		case action.EventTypeClick:
			var err error
			if isXPath {
				// Use XPath-based element finding
				elem, findErr := page.ElementX(selector)
				if findErr != nil {
					return fmt.Errorf("click failed during path follow (XPath): %w", findErr)
				}
				err = elem.Click()
			} else {
				err = page.Click(selector)
			}
			if err != nil {
				return fmt.Errorf("click failed during path follow: %w", err)
			}
		case action.EventTypeReload:
			// Reload events just navigate, already handled
			continue
		default:
			// Default to click for other event types
			var err error
			if isXPath {
				elem, findErr := page.ElementX(selector)
				if findErr != nil {
					return fmt.Errorf("action failed during path follow (XPath): %w", findErr)
				}
				err = elem.Click()
			} else {
				err = page.Click(selector)
			}
			if err != nil {
				return fmt.Errorf("action failed during path follow: %w", err)
			}
		}

		// Wait for state change
		if err := page.WaitStable(c.config.DOMStableTime); err != nil {
			if ctxErr := sleepWithContext(ctx, c.config.DOMStableTime); ctxErr != nil {
				return ctxErr
			}
		}

		// Update current state to edge target
		targetState, ok := c.graph.GetState(edge.TargetStateID)
		if ok {
			c.stateMachine.SetCurrentState(targetState)
		}
	}

	// Verify we reached the target
	currentState := c.stateMachine.GetCurrentState()
	if currentState == nil || currentState.ID != target.ID {
		currentName := "nil"
		if currentState != nil {
			currentName = currentState.Name
		}
		return fmt.Errorf("path didn't reach target state %s, at %s", target.Name, currentName)
	}

	return nil
}

// DUPLICATE_EVENT_SEED is used to encode equivalentAccess in eventable IDs.
// CRAWLJAX PARITY: Java Crawler.java line 65: private static final int DUPLICATE_EVENT_SEED = 100000;
const DUPLICATE_EVENT_SEED = 100000

// crawlThroughActions crawls through all actions for current state using DFS.
// CRAWLJAX PARITY: Matches Java Crawljax Crawler.crawlThroughActionsNew() 100% exactly.
// Java Flow (Crawler.java:1275-1344):
//  1. afterBacktrack=true for first poll
//  2. Poll action with afterBacktrack parameter
//  3. Check allConditionsSatisfied(browser) BEFORE firing
//  4. If wasExplored(): eventableId = equivalentAccess * DUPLICATE_EVENT_SEED + eventableId
//  5. On success: fragmentManager.recordAccess(), inspectNewState()
//  6. On failure: setDirectAccess(true), disableInputsForAction(), re-add action if disableInputsForAction returns true
//  7. afterBacktrack=false for subsequent polls
//  8. Check crawlerNotInScope() after each action
func (c *Crawler) crawlThroughActions(ctx context.Context) {
	afterBacktrack := true // CRAWLJAX PARITY: First poll is "after backtrack" (Java line 1276)

	for {
		// Check termination conditions (Go-specific, Java uses Thread.interrupted())
		if c.shouldTerminate(ctx) {
			return
		}

		// Poll action for current state only
		currentState := c.stateMachine.GetCurrentState()
		if currentState == nil {
			return
		}

		// CRAWLJAX PARITY: Poll with afterBacktrack parameter (Java line 1278-1279, 1324)
		act := c.candidates.PollByMode(currentState.ID, c.config.CrawlStrategy, afterBacktrack)
		if act == nil {
			// No more actions for current state, exit DFS
			zap.L().Debug("No more actions for state", zap.String("state", currentState.Name))
			return
		}

		element := act.GetCandidateElement()

		// CRAWLJAX PARITY: Check allConditionsSatisfied BEFORE firing (Java lines 1284, 1319-1321)
		// Java: if (element.allConditionsSatisfied(browser)) { ... } else { LOG.info("Element not clicked...") }
		br := c.browserPool.Get()
		page := br.CurrentPage()
		if !c.checkAllConditionsSatisfied(page, element) {
			zap.L().Debug("Element not clicked because not all crawl conditions were satisfied",
				zap.String("xpath", element.GetIdentification().Value))
			// CRAWLJAX PARITY: Java still updates afterBacktrack even when conditions not satisfied
			afterBacktrack = false
			continue
		}

		// CRAWLJAX PARITY: Generate eventable ID with DUPLICATE_EVENT_SEED logic (Java lines 1286-1293)
		// Java:
		//   long eventableId = getEventableId();
		//   if (element.wasExplored()) {
		//       eventableId = (long) (element.getEquivalentAccess()) * DUPLICATE_EVENT_SEED + eventableId;
		//   }
		eventableID := action.NextEventableID()
		if element.WasExplored() {
			eventableID = int64(element.GetEquivalentAccess())*DUPLICATE_EVENT_SEED + eventableID
			zap.L().Debug("Duplicate access for element",
				zap.String("xpath", element.GetIdentification().Value),
				zap.Int64("seed_id", eventableID))
		}

		// CRAWLJAX PARITY: Record source state before action execution
		sourceStateID := currentState.ID

		// CRAWLJAX PARITY: Create Eventable BEFORE execution (Java line 1294)
		// Java: Eventable event = new Eventable(element, action.getEventType(), eventableId);
		// This allows us to use eventable.getRelatedFormInputs() in fireEventWithInputs
		eventable := action.NewEventableFromCandidateCrawlActionWithID(act, eventableID)
		eventable.SourceStateID = sourceStateID

		// Execute the action with eventable (for proper form input handling)
		newActionsCount, filledFormInputs, err := c.executeActionWithEventable(ctx, act, eventable)

		// CRAWLJAX PARITY: Record target state after execution
		targetStateID := sourceStateID
		if newState := c.stateMachine.GetCurrentState(); newState != nil {
			targetStateID = newState.ID
		}
		eventable.TargetStateID = targetStateID

		if err != nil {
			// RLCRAWLER PARITY: Skip MAB update entirely when crawl condition not met
			// Action was not actually executed, so we shouldn't update MAB or count as failure
			if errors.Is(err, ErrCrawlConditionNotMet) {
				zap.L().Debug("Action skipped (crawl condition not met)",
					zap.String("state", sourceStateID))
				// Don't count as failure, don't update MAB, just continue
				afterBacktrack = false
				continue
			}

			// CRAWLJAX PARITY: On failure - setDirectAccess + disableInputsForAction + re-add
			// Java lines 1305-1318:
			//   LOG.info("Could not fire event. Putting back the actions on the todo list and disabling input next time");
			//   LOG.info("Recording direct access to the action to avoid picking in the same state again");
			//   element.setDirectAccess(true);
			//   if (action != null) {
			//       boolean added = candidateActionCache.disableInputsForAction(action);
			//       if (added) {
			//           List<CandidateCrawlAction> actions = new ArrayList<>();
			//           actions.add(action);
			//           candidateActionCache.addActions(actions, stateMachine.getCurrentState());
			//       }
			//   }
			zap.L().Debug("Could not fire event. Putting back on todo list and disabling input next time",
				zap.Error(err))
			zap.L().Debug("Recording direct access to avoid picking in the same state again")
			element.SetDirectAccess(true) // Java line 1309
			added := c.candidates.DisableInputsForAction(act)
			if added {
				// CRAWLJAX PARITY: Re-add action for retry without form inputs (Java lines 1312-1316)
				c.candidates.ReAddAction(act, currentState.ID)
			}
			c.stats.ActionsFailed++
			c.stats.ConsecutiveFailures++
			// Record failed action to metrics (only when benchmark mode)
			if c.metricsCollector != nil {
				c.recordMetrics(act, false, false, false, 0)
			}
			// RLCRAWLER PARITY: Update MAB with zero reward for failed actions
			// This allows MAB to learn that certain actions are unreliable
			if c.mabPolicy != nil {
				actionID := element.GetIdentification().Value
				rewardEnv := 0.0
				reward := mab.TransformReward(rewardEnv)
				c.mabPolicy.Update(sourceStateID, actionID, reward)
				// Spitolas ADAPTATION: Remove executed action from MAB (click-once semantics)
				c.mabPolicy.RemoveAction(sourceStateID, actionID)
				zap.L().Debug("MAB updated for failed action",
					zap.String("state", sourceStateID),
					zap.String("action", actionID),
					zap.Float64("reward", reward))
			}
			// CRAWLJAX PARITY: Java does NOT update afterBacktrack on failure
			// It's set to false AFTER the if-else block (line 1323)
			// But since we continue here, we need to set it too
			afterBacktrack = false
			continue
		}

		// CRAWLJAX PARITY: On success - cache form inputs for backtracking (Java fireEventWithInputs line 1098)
		// Java: candidateActionCache.mapInput(event, handled);
		if len(filledFormInputs) > 0 {
			c.candidates.MapInput(eventable, filledFormInputs)
		}

		// CRAWLJAX PARITY: On success - recordAccess() (Java lines 1297-1301)
		// Java: fragmentManager.recordAccess(action.getCandidateElement(), stateMachine.getCurrentState());
		if c.fragManager != nil {
			c.fragManager.RecordElementAccess(element, currentState.ID)
		}

		// Record successful event in crawl path
		c.crawlPath.Add(eventable)

		c.candidates.MarkExecuted(act)
		c.stats.ActionsExecuted++
		c.stats.ConsecutiveFailures = 0 // Reset on success

		// Record successful action to metrics (only when benchmark mode)
		if c.metricsCollector != nil {
			isFormSubmit := act.GetEventType() == action.EventTypeEnter
			c.recordMetrics(act, true, newActionsCount > 0, isFormSubmit, newActionsCount)
		}

		// RLCRAWLER PARITY: Update MAB policy with coverage-based reward
		// reward_env = newActionsCount, transformed via 1-exp(-reward_env)
		if c.mabPolicy != nil {
			actionID := element.GetIdentification().Value
			rewardEnv := float64(newActionsCount)
			reward := mab.TransformReward(rewardEnv)
			reset := c.mabPolicy.Update(sourceStateID, actionID, reward)
			// Spitolas ADAPTATION: Remove executed action from MAB (click-once semantics)
			c.mabPolicy.RemoveAction(sourceStateID, actionID)
			zap.L().Debug("MAB policy updated",
				zap.String("state", sourceStateID),
				zap.String("action", actionID),
				zap.Float64("reward_env", rewardEnv),
				zap.Float64("reward", reward),
				zap.Bool("round_reset", reset))
			if reset {
				zap.L().Debug("MAB round reset",
					zap.Int("new_round", c.mabPolicy.GetRound()))
			}
		}

		// CRAWLJAX PARITY: afterBacktrack = false for subsequent polls (Java line 1323)
		afterBacktrack = false

		// CRAWLJAX PARITY: Check if crawler left scope after action (Java lines 1327-1333)
		// Java:
		//   if (!interrupted && crawlerNotInScope()) {
		//       throw new CrawlerLeftDomainException(browser.getCurrentUrl());
		//   }
		// Note: Go doesn't throw exceptions, we just return to let reset handle it
		if page != nil && !c.isInScope(page) {
			zap.L().Warn("Crawler left domain scope during action crawl")
			return // Let the main loop handle reset
		}

		// After action, currentState may have changed (if new state discovered)
		// Continue DFS from the new current state
	}
}

// checkAllConditionsSatisfied checks if all conditions are satisfied for an element.
// CRAWLJAX PARITY: Matches Java CandidateElement.allConditionsSatisfied(EmbeddedBrowser).
// Java: Returns true if eventableCondition is null OR condition.checkCondition(browser) returns true.
func (c *Crawler) checkAllConditionsSatisfied(page *browser.Page, element *action.CandidateElement) bool {
	// Check page-level crawl conditions first
	if !c.shouldCrawl(page) {
		return false
	}

	// CRAWLJAX PARITY: Check element-specific eventable condition
	// Java CandidateElement.java:
	//   public boolean allConditionsSatisfied(EmbeddedBrowser browser) {
	//       return eventableCondition == null || eventableCondition.checkCondition(browser);
	//   }
	eventableCondition := element.GetEventableCondition()
	if eventableCondition == nil {
		return true
	}

	// If we have an eventable condition checker, use it
	if c.eventableConditions != nil {
		// Get element XPath for condition check
		elementXPath := ""
		if element.GetIdentification() != nil {
			elementXPath = element.GetIdentification().Value
		}
		// Check all conditions for this element
		return c.eventableConditions.Check(elementXPath, page)
	}

	// If no specific condition or checker, assume satisfied
	return true
}

// executeActionWithEventable executes an action with proper Eventable-based form handling.
// CRAWLJAX PARITY: This matches Java Crawler.fireEventWithInputs() flow exactly.
// Returns (newActionsCount, filledFormInputs, error) where:
// - newActionsCount is the number of new actions discovered
// - filledFormInputs are the form inputs that were filled (for caching in candidates)
func (c *Crawler) executeActionWithEventable(ctx context.Context, crawlAction *action.CandidateCrawlAction, eventable *action.Eventable) (newActionsCount int, filledInputs []*action.FormInput, err error) {
	// CRITICAL: General panic recovery - catch all runtime panics during action execution.
	// Prevents entire crawl from crashing when an action encounters problems
	// (cross-origin frames, detached elements, nil pointer dereferences, etc.)
	defer func() {
		if r := recover(); r != nil {
			candidate := crawlAction.GetCandidateElement()
			identification := candidate.GetIdentification()
			xpath := ""
			if identification != nil {
				xpath = identification.Value
			}
			zap.L().Warn("PANIC in executeActionWithEventable - recovering",
				zap.String("xpath", xpath),
				zap.String("event_type", string(crawlAction.GetEventType())),
				zap.String("frame", candidate.RelatedFrame),
				zap.Any("panic", r),
				zap.Stack("stack"))

			// Convert panic to error, action will be marked as failed and may be retried
			newActionsCount = 0
			filledInputs = nil
			err = fmt.Errorf("action execution panicked: %v", r)
		}
	}()

	candidate := crawlAction.GetCandidateElement()
	eventType := crawlAction.GetEventType()
	identification := candidate.GetIdentification()

	// Get XPath from identification
	xpath := ""
	if identification != nil && identification.How == action.HowXPath {
		xpath = identification.Value
	}

	zap.L().Debug("Event xpath", zap.String("xpath", xpath))

	br := c.browserPool.Get()
	page := br.CurrentPage()
	if page == nil {
		return 0, nil, fmt.Errorf("no page available")
	}

	// Handle frame context if action is inside a frame
	targetPage := page
	if candidate.RelatedFrame != "" {
		zap.L().Debug("Navigating to frame", zap.String("frame_path", candidate.RelatedFrame))
		framePage, err := c.navigateToFrame(page, candidate.RelatedFrame)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to navigate to frame %s: %w", candidate.RelatedFrame, err)
		}
		targetPage = framePage
	}

	// Check crawl conditions
	if !c.shouldCrawl(targetPage) {
		zap.L().Warn("Crawl condition not met, skipping action")
		return 0, nil, ErrCrawlConditionNotMet
	}

	// CRAWLJAX PARITY: Fill forms before action using handleInputElements
	// Java fireEventWithInputs() flow (line 1087-1111):
	//   1. List<FormInput> available = getInputElements(event);  // merge related + DOM
	//   2. List<FormInput> handled = formHandler.handleFormElements(available);  // fill
	//   3. candidateActionCache.mapInput(event, handled);  // cache (done in caller)
	shouldDisableInputs := c.candidates.ShouldDisableInputForAction(crawlAction)
	if c.config.FormFillEnabled && !shouldDisableInputs {
		// CRAWLJAX PARITY: Use handleInputElements which merges:
		// 1. eventable.getRelatedFormInputs() (inputs linked from CandidateElement)
		// 2. formHandler.getFormInputs() (all inputs on current DOM)
		filledInputs = c.handleInputElements(targetPage, eventable)
	} else if shouldDisableInputs {
		zap.L().Debug("Form inputs disabled for this action (retry without inputs)")
	}

	// Execute the action using identification selector
	// CRAWLJAX PARITY: Use XPath or CSS selector based on identification.How
	selector := ""
	useXPath := false
	if identification != nil {
		selector = identification.Value
		useXPath = identification.How == action.HowXPath
	}
	frameInfo := ""
	if candidate.RelatedFrame != "" {
		frameInfo = candidate.RelatedFrame
	}
	zap.L().Debug("Executing action",
		zap.String("type", string(eventType)),
		zap.String("selector", selector),
		zap.Bool("useXPath", useXPath),
		zap.String("frame", frameInfo),
		zap.String("tagName", candidate.TagName))

	// Helper to get element with proper selector type (XPath vs CSS)
	getElement := func() (*browser.Element, error) {
		if useXPath {
			return targetPage.ElementX(selector)
		}
		return targetPage.Element(selector)
	}

	switch eventType {
	case action.EventTypeClick:
		elem, err := getElement()
		if err != nil {
			zap.L().Debug("Click failed: element not found",
				zap.String("selector", selector),
				zap.Bool("useXPath", useXPath),
				zap.Error(err))
			// CRAWLJAX PARITY: If click fails and crawlHiddenAnchors is enabled,
			// try to navigate directly to href for anchor elements (visitAnchorHrefIfPossible)
			if c.config.CrawlHiddenAnchors && strings.EqualFold(candidate.TagName, "a") && candidate.Href != "" {
				zap.L().Debug("Click failed on hidden anchor, navigating to href", zap.String("href", candidate.Href))
				if navErr := c.visitAnchorHref(page, candidate.Href); navErr != nil {
					return 0, nil, fmt.Errorf("click failed and href navigation failed: %w", navErr)
				}
			} else {
				return 0, nil, fmt.Errorf("click failed: element not found: %w", err)
			}
		} else if err := elem.Click(); err != nil {
			zap.L().Debug("Click action failed",
				zap.String("selector", selector),
				zap.Error(err))
			if c.config.CrawlHiddenAnchors && strings.EqualFold(candidate.TagName, "a") && candidate.Href != "" {
				zap.L().Debug("Click failed on hidden anchor, navigating to href", zap.String("href", candidate.Href))
				if navErr := c.visitAnchorHref(page, candidate.Href); navErr != nil {
					return 0, nil, fmt.Errorf("click failed and href navigation failed: %w", navErr)
				}
			} else {
				return 0, nil, fmt.Errorf("click failed: %w", err)
			}
		}
	case action.EventTypeHover:
		elem, err := getElement()
		if err != nil {
			return 0, nil, fmt.Errorf("hover failed: element not found: %w", err)
		}
		if err := elem.Hover(); err != nil {
			return 0, nil, fmt.Errorf("hover failed: %w", err)
		}
	case action.EventTypeEnter:
		// Enter key event - typically used for form submission
		elem, err := getElement()
		if err != nil {
			return 0, nil, fmt.Errorf("enter failed: element not found: %w", err)
		}
		if err := elem.Click(); err != nil {
			return 0, nil, fmt.Errorf("enter failed: %w", err)
		}
		c.stats.FormsSubmitted++
	default:
		return 0, nil, fmt.Errorf("unknown event type: %s", eventType)
	}

	// Wait after action (matches Java Crawljax crawlWaitEvent)
	zap.L().Debug("Waiting after action", zap.Duration("wait_time", c.config.WaitAfterEvent))
	if err := sleepWithContext(ctx, c.config.WaitAfterEvent); err != nil {
		return 0, nil, err
	}

	// CRAWLJAX PARITY: Handle popups before proceeding (matches Java Crawljax handlePopups())
	_ = page.HandlePopups()

	// CRAWLJAX PARITY: Close other windows to prevent memory issues
	// This is CRITICAL for target="_blank" and window.open() links
	// Matches Java Crawljax Crawler.java:1170 - browser.closeOtherWindows()
	if err := br.CloseOtherWindows(); err != nil {
		// Log but don't fail the crawl - this is a cleanup operation
		zap.L().Warn("Failed to close other windows, continuing crawl", zap.Error(err))
	}

	// Wait for potential state change
	zap.L().Debug("Waiting for DOM stability after action")
	if err := page.WaitStable(c.config.DOMStableTime); err != nil {
		if ctxErr := sleepWithContext(ctx, c.config.DOMStableTime); ctxErr != nil {
			return 0, nil, ctxErr
		}
	}

	// CRAWLJAX PARITY: Inspect new state (inspectNewState in Java)
	zap.L().Debug("Inspecting new state after action")
	newActionsCount = c.inspectNewState(ctx, page, crawlAction)

	return newActionsCount, filledInputs, nil
}

// inspectNewState checks if the DOM changed after an action and handles new/clone states.
// CRAWLJAX PARITY: This matches Java Crawljax Crawler.inspectNewState()
// Returns the number of new actions discovered (for MAK reward and metrics).
func (c *Crawler) inspectNewState(ctx context.Context, page *browser.Page, crawlAction *action.CandidateCrawlAction) int {
	// CRAWLJAX PARITY: handlePopups() as FIRST operation
	// Java line 1372: browser.handlePopups()
	_ = page.HandlePopups()

	currentState := c.stateMachine.GetCurrentState()

	// CRAWLJAX PARITY: Check if browser left scope FIRST (like Java inspectNewState)
	// This MUST be checked before capturing state to prevent out-of-scope states
	if !c.isInScope(page) {
		zap.L().Warn("Browser left crawl scope, going back")
		// Go back to previous state
		if err := page.NavigateBack(); err != nil {
			zap.L().Debug("Failed to navigate back", zap.Error(err))
			// If back fails, navigate to current state URL
			if currentState != nil {
				if err := page.Navigate(currentState.URL); err != nil {
					zap.L().Debug("Failed to navigate to current state", zap.Error(err))
				}
			}
		}
		// NavigateBack() already waits for navigation to complete, no need for additional WaitStable()
		return 0 // Don't capture out-of-scope state
	}

	// Capture current DOM state
	zap.L().Debug("Capturing DOM state for comparison")
	newState, err := c.captureState(ctx, page, currentState.Depth+1)
	if err != nil {
		zap.L().Debug("Failed to capture state", zap.Error(err))
		return 0
	}
	zap.L().Debug("State captured",
		zap.String("state_id", newState.ID),
		zap.Int("dom_size", len(newState.StrippedDOM)))

	// Check if this is the same as current state (DOM unchanged)
	comparison := c.comparator.Compare(currentState, newState)
	comparisonStr := "different"
	if comparison == state.ResultDuplicate {
		comparisonStr = "duplicate"
	}
	zap.L().Debug("DOM comparison result",
		zap.String("current_state", currentState.ID),
		zap.String("new_state", newState.ID),
		zap.String("result", comparisonStr))

	if comparison == state.ResultDuplicate {
		zap.L().Debug("DOM unchanged after action")
		return 0
	}

	// Check if this state already exists (clone detection)
	// CRAWLJAX PARITY: Use StateMachine.SwitchToStateAndCheckIfClone
	existingState, isClone := c.stateMachine.SwitchToStateAndCheckIfClone(newState)
	if isClone {
		// Clone state - add edge but don't discover new state
		zap.L().Debug("State already exists (clone detected)",
			zap.String("state", existingState.Name),
			zap.String("state_id", existingState.ID))
		c.graph.AddEdge(currentState.ID, existingState.ID, action.NewEventableFromCandidateCrawlAction(crawlAction))

		// CRAWLJAX PARITY: Rediscover and restore logic
		// Java line 1442: candidateActionCache.rediscoveredState(stateMachine.getCurrentState())
		// Java line 1443: graphProvider.get().restoreState(stateMachine.getCurrentState())
		c.candidates.RediscoveredState(existingState.ID)
		if c.graph.RestoreState(existingState.ID) {
			zap.L().Debug("Restored expired state and its incoming edges", zap.String("state_id", existingState.ID))
		}

		c.stateMachine.SetCurrentState(existingState)
		c.stats.StatesDuplicate++
		return 0
	}

	// New state discovered!
	zap.L().Debug("New state discovered", zap.String("state", newState.Name), zap.Int("depth", newState.Depth))
	c.graph.AddState(newState)
	c.candidates.RecordStateCreation(newState.ID) // CRAWLJAX PARITY: Track state order for OLDEST_FIRST mode
	c.graph.AddEdge(currentState.ID, newState.ID, action.NewEventableFromCandidateCrawlAction(crawlAction))

	// RLCRAWLER PARITY: Register new state with MAB policy
	if c.mabPolicy != nil {
		c.mabPolicy.AddState(newState.ID)
	}
	c.stats.StatesDiscovered++

	// Update current state to the new state (DFS)
	c.stateMachine.SetCurrentState(newState)
	zap.L().Debug("Current state updated to new state", zap.String("state_id", newState.ID))

	// Extract fragments
	c.extractFragments(page, newState)

	// Check max depth
	if c.config.MaxDepth > 0 && newState.Depth >= c.config.MaxDepth {
		zap.L().Debug("Max depth reached, not extracting actions",
			zap.Int("depth", newState.Depth),
			zap.Int("max_depth", c.config.MaxDepth))
		return 0
	}

	// Extract actions from new state (if crawl conditions allow)
	if !c.shouldCrawl(page) {
		zap.L().Debug("Crawl conditions not met, skipping action extraction")
		return 0
	}

	zap.L().Debug("Extracting actions from new state")
	actions, err := c.extractor.Extract(ctx, page)
	if err != nil {
		zap.L().Debug("Failed to extract actions", zap.Error(err))
		return 0
	}

	c.candidates.AddActions(actions, newState.ID)
	added := len(actions)
	zap.L().Debug("Extracted actions from state", zap.Int("count", added), zap.String("state", newState.Name))

	// NOTE: Frame extraction is already handled by c.extractor.Extract() which
	// recursively processes frames with correct framePath. No separate call needed.

	return added
}

// checkOnURLState checks DOM after URL reload and handles state changes.
// CRAWLJAX PARITY: Matches Java Crawljax Crawler.checkOnURLState() exactly.
// Java flow:
// 1. newState = stateMachine.newStateFor(browser)
// 2. clone = stateFlowGraph.putIfAbsent(newState)
// 3. if (clone == null): setCurrentState(newState), add to onURLSet
// 4. else: setCurrentState(clone), add clone to onURLSet if not index
// 5. Always try to add reload edge (graph handles duplicate)
func (c *Crawler) checkOnURLState(ctx context.Context, page *browser.Page, previousState *state.State, resetURL string) {
	// CRAWLJAX PARITY: Get DOM (like Java stateMachine.newStateFor(browser))
	var combinedDOM string
	var err error
	if c.config.CrawlFrames {
		combinedDOM, err = page.HTMLWithFramesFiltered(true, c.config.ExcludeFrames)
	} else {
		combinedDOM, err = page.HTML()
	}
	if err != nil {
		zap.L().Debug("checkOnURLState: failed to get DOM", zap.Error(err))
		return
	}

	// Strip DOM for comparison
	strippedDOM := state.StripDOMDefault(combinedDOM)
	currentURL, _ := page.URL()

	// Create new state object (like Java stateFlowGraph.newStateFor())
	newState := state.New(currentURL, combinedDOM, strippedDOM, 1)

	// CRAWLJAX PARITY: Check if clone (like Java putIfAbsent)
	existingState, isClone := c.stateMachine.SwitchToStateAndCheckIfClone(newState)

	if !isClone {
		// NEW STATE discovered after URL reload!
		c.graph.AddState(newState)
		c.candidates.RecordStateCreation(newState.ID)

		// RLCRAWLER PARITY: Register new state with MAB policy
		if c.mabPolicy != nil {
			c.mabPolicy.AddState(newState.ID)
		}

		// CRAWLJAX PARITY: Java - stateMachine.setCurrentState(newState)
		c.stateMachine.SetCurrentState(newState)

		// CRAWLJAX PARITY: Java - stateMachine.getOnURLSet().add(newState)
		c.stateMachine.AddToOnURLSet(newState)

		// CRAWLJAX PARITY: Java line 340 - newState.setOnURL(true)
		newState.SetOnURL(true)

		zap.L().Debug("checkOnURLState: NEW state discovered after reload", zap.String("state", newState.Name))

		// Extract actions from this new state (like Java parseCurrentPageForCandidateElements)
		actions, err := c.extractor.Extract(ctx, page)
		if err == nil && len(actions) > 0 {
			c.candidates.AddActions(actions, newState.ID)
			zap.L().Debug("Extracted actions from new onURL state",
				zap.Int("count", len(actions)),
				zap.String("state", newState.Name))
		}

		c.stats.StatesDiscovered++
	} else {
		// EXISTING STATE (clone)
		// CRAWLJAX PARITY: Java - stateMachine.setCurrentState(clone)
		c.stateMachine.SetCurrentState(existingState)

		// CRAWLJAX PARITY: Java - if (!clone.getName().equalsIgnoreCase("index"))
		//                         if (!onURLSet.contains(clone)) onURLSet.add(clone)
		if existingState.Name != "index" {
			c.stateMachine.AddToOnURLSet(existingState)
			zap.L().Debug("checkOnURLState: index has changed to", zap.String("state", existingState.Name))
		}
	}

	// CRAWLJAX PARITY: Always try to add reload edge (let graph handle duplicate)
	// Java Crawler.java:352-372 - addEdge called regardless of state equality
	// Graph.AddEdge() handles duplicate detection via Eventable.Equals()
	if previousState != nil {
		currentState := c.stateMachine.GetCurrentState()
		if currentState != nil {
			c.graph.AddEdge(previousState.ID, currentState.ID, action.NewReloadEventable(resetURL))
			zap.L().Debug("Added reload edge",
				zap.String("from", previousState.Name),
				zap.String("to", currentState.Name))
		}
	}
}

// addFinalReloadEdge adds a reload edge from current state to index when crawl finishes.
// CRAWLJAX PARITY: This is only needed when reset() was never called during the crawl.
// If reset() was called at least once, all intermediate states already have reload edges.
// The final leaf state does NOT get a reload edge because the crawl just terminates.
func (c *Crawler) addFinalReloadEdge() {
	// CRAWLJAX PARITY: Only add final reload edge if reset was never called during the crawl.
	// This handles simple DFS crawls (like SimpleInputSite: index → state, end).
	// For complex crawls where reset() was called, reload edges are already added during processing.
	if c.resetCalled {
		return
	}

	indexState := c.graph.GetIndexState()
	currentState := c.stateMachine.GetCurrentState()
	if indexState == nil || currentState == nil {
		return
	}
	// Only add if we're not already at index
	if currentState.ID == indexState.ID {
		return
	}
	// CRAWLJAX PARITY: Always try to add, let graph handle duplicate
	resetURL := c.config.URL.String()
	c.graph.AddEdge(currentState.ID, indexState.ID, action.NewReloadEventable(resetURL))
	zap.L().Debug("Added final reload edge", zap.String("from", currentState.Name), zap.String("to", indexState.Name))
}

// captureState captures the current page state.
// CRAWLJAX PARITY: Uses HTMLWithFramesFiltered to include iframe content in state comparison.
// This matches Java Crawljax getDomTreeWithFrames() behavior which embeds frame content
// into the DOM so that state changes within iframes are detected.
func (c *Crawler) captureState(ctx context.Context, page *browser.Page, depth int) (*state.State, error) {
	url, err := page.URL()
	if err != nil {
		return nil, err
	}

	// CRAWLJAX PARITY: Get DOM with iframe content for proper state comparison
	// Respects CrawlFrames and ExcludeFrames configuration
	zap.L().Debug("Retrieving HTML",
		zap.Bool("crawl_frames", c.config.CrawlFrames),
		zap.Int("exclude_frames_count", len(c.config.ExcludeFrames)))
	html, err := page.HTMLWithFramesFiltered(c.config.CrawlFrames, c.config.ExcludeFrames)
	if err != nil {
		return nil, err
	}

	rawSize := len(html)
	zap.L().Debug("HTML retrieved", zap.Int("size_bytes", rawSize))

	// Create state (stripping is done internally)
	s := c.comparator.CreateState(url, html, depth)

	strippedSize := len(s.StrippedDOM)
	zap.L().Debug("State created",
		zap.String("state_id", s.ID),
		zap.String("state_name", s.Name),
		zap.String("url", s.URL),
		zap.Int("depth", s.Depth),
		zap.Int("raw_size", rawSize),
		zap.Int("stripped_size", strippedSize))

	return s, nil
}

// shouldTerminate checks if crawl should terminate.
func (c *Crawler) shouldTerminate(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		zap.L().Debug("Context cancelled, terminating")
		return true
	default:
	}

	// Check max states
	if c.config.MaxStates > 0 {
		currentStates := c.graph.StateCount()
		if currentStates >= c.config.MaxStates {
			zap.L().Debug("Max states reached",
				zap.Int("current", currentStates),
				zap.Int("max", c.config.MaxStates))
			return true
		}
		zap.L().Debug("State count check",
			zap.Int("current", currentStates),
			zap.Int("max", c.config.MaxStates))
	}

	// Check max consecutive failures
	if c.config.MaxConsecutiveFails > 0 {
		c.mu.Lock()
		consecutiveFails := c.stats.ConsecutiveFailures
		c.mu.Unlock()
		if consecutiveFails >= c.config.MaxConsecutiveFails {
			zap.L().Debug("Max consecutive failures reached",
				zap.Int("current", consecutiveFails),
				zap.Int("max", c.config.MaxConsecutiveFails))
			return true
		}
	}

	return false
}

// sleepWithContext sleeps for duration d but returns early if ctx is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// isInScope checks if the current page URL is within the crawl scope.
// This matches Java Crawljax's crawlerNotInScope() behavior.
// Returns true if in scope, false if out of scope.
func (c *Crawler) isInScope(page *browser.Page) bool {
	currentURL, err := page.URL()
	if err != nil {
		return false // Can't determine, assume out of scope
	}

	// CRAWLJAX PARITY: Check custom CrawlScope first (like setCrawlScope())
	if c.config.CrawlScope != nil {
		return c.config.CrawlScope(currentURL)
	}

	// Default: same domain or subdomain check
	parsedCurrent, err := url.Parse(currentURL)
	if err != nil {
		return false
	}

	parsedTarget, err := url.Parse(c.config.URL.String())
	if err != nil {
		return true // Can't parse config URL, allow
	}

	// Check same domain or subdomain
	currentHost := strings.ToLower(parsedCurrent.Host)
	targetHost := strings.ToLower(parsedTarget.Host)

	return currentHost == targetHost ||
		strings.HasSuffix(currentHost, "."+targetHost)
}

// visitAnchorHref navigates directly to an anchor's href URL.
// CRAWLJAX PARITY: This matches Java Crawljax's visitAnchorHrefIfPossible() method.
// Used when crawlHiddenAnchors is enabled and clicking a hidden anchor fails.
func (c *Crawler) visitAnchorHref(page *browser.Page, href string) error {
	// Resolve relative URL against current page URL
	currentURL, err := page.URL()
	if err != nil {
		return fmt.Errorf("failed to get current URL: %w", err)
	}

	// Parse and resolve the href
	baseURL, err := url.Parse(currentURL)
	if err != nil {
		return fmt.Errorf("failed to parse current URL: %w", err)
	}

	hrefURL, err := url.Parse(href)
	if err != nil {
		return fmt.Errorf("failed to parse href: %w", err)
	}

	// Resolve relative URL
	resolvedURL := baseURL.ResolveReference(hrefURL)

	zap.L().Debug("Navigating to anchor href", zap.String("url", resolvedURL.String()))
	return page.Navigate(resolvedURL.String())
}

// shouldCrawl checks if page should be crawled based on conditions.
func (c *Crawler) shouldCrawl(page *browser.Page) bool {
	if len(c.crawlConditions) == 0 {
		return true
	}

	for _, cond := range c.crawlConditions {
		if !cond.Check(page) {
			return false
		}
	}

	return true
}

// checkWaitConditions applies wait conditions to the page.
func (c *Crawler) checkWaitConditions(page *browser.Page) {
	for _, wc := range c.waitConditions {
		result := wc.Wait(page)
		if result == condition.WaitTimeout {
			zap.L().Warn("Wait condition timed out", zap.String("selector", wc.Selector))
		}
	}
}

// getInputElements merges related form inputs with DOM-detected inputs.
// CRAWLJAX PARITY: Matches Java Crawler.getInputElements(Eventable) exactly.
// Java flow (line 917-942):
//  1. Start with eventable.getRelatedFormInputs() (inputs linked to this action)
//  2. Add formHandler.getFormInputs() (inputs detected on current DOM)
//  3. Remove duplicates (based on Identification)
//  4. Order by FormFillOrder (NORMAL, DOM, VISUAL) - not implemented yet
//
// Returns DetectedInput for Go extension (value rotation, detection metadata).
func (c *Crawler) getInputElements(page *browser.Page, eventable *action.Eventable) []*form.DetectedInput {
	// Step 1: Start with related inputs from eventable
	formInputs := make([]*form.DetectedInput, 0)
	existingInputs := eventable.GetRelatedFormInputs()

	// Convert action.FormInput to DetectedInput
	for _, actionInput := range existingInputs {
		detected := form.FromFormInput(actionInput)
		if detected != nil {
			formInputs = append(formInputs, detected)
		}
	}

	existingCount := len(formInputs)

	// Step 2: Merge with all inputs detected on current DOM
	domInputs, _ := c.formHandler.DetectInputs(page)
	for _, domInput := range domInputs {
		// Check if already exists (by Identification)
		exists := false
		for _, existing := range formInputs {
			if c.detectedInputEquals(existing, domInput) {
				exists = true
				break
			}
		}
		if !exists {
			formInputs = append(formInputs, domInput)
		}
	}

	zap.L().Debug("Changing related inputs",
		zap.Int64("eventable_id", eventable.ID),
		zap.Int("existing", existingCount),
		zap.Int("total", len(formInputs)))

	// TODO: Step 3 - Order by FormFillOrder (VISUAL ordering)
	// For now, use DOM order (default)

	return formInputs
}

// detectedInputEquals checks if two detected inputs are equal based on Identification.
// CRAWLJAX PARITY: Matches Java FormInput.equals() - based on Identification
func (c *Crawler) detectedInputEquals(a, b *form.DetectedInput) bool {
	if a == nil || b == nil || a.FormInput == nil || b.FormInput == nil {
		return false
	}

	// Compare by Identification first
	if a.Identification != nil && b.Identification != nil {
		return a.Identification.How == b.Identification.How &&
			a.Identification.Value == b.Identification.Value
	}

	// Fallback: compare by ID or Name (from DetectedInput metadata)
	if a.ID != "" && a.ID == b.ID {
		return true
	}
	if a.Name != "" && a.Name == b.Name {
		return true
	}

	return false
}

// handleInputElements fills form inputs and returns the handled list.
// CRAWLJAX PARITY: Matches Java Crawler.handleInputElements(Eventable) exactly.
// Java flow (line 912-914):
//  1. List<FormInput> formInputs = getInputElements(eventable);
//  2. return formHandler.handleFormElements(formInputs);
//
// Returns action.FormInput for Crawljax parity (used in candidates cache).
func (c *Crawler) handleInputElements(page *browser.Page, eventable *action.Eventable) []*action.FormInput {
	formInputs := c.getInputElements(page, eventable)
	return c.formHandler.HandleFormElements(page, formInputs)
}

// fillFormsIfPresent detects and fills forms on the page.
// If actionID is provided, caches the form inputs for reuse.
// CRAWLJAX PARITY: Returns the form inputs that were filled for caching in UnfiredFragmentCandidates.
func (c *Crawler) fillFormsIfPresent(page *browser.Page, actionID string) []*action.FormInput {
	// Check if we have cached inputs for this action
	if actionID != "" {
		if cached, ok := c.formCache[actionID]; ok && len(cached) > 0 {
			zap.L().Debug("Using cached form inputs for action", zap.String("action_id", actionID))
			result := c.formHandler.FillInputs(page, cached)
			if result.HasErrors() {
				zap.L().Debug("Form fill had failures", zap.Int("failed", result.Failed), zap.Int("total", len(cached)))
			}
			// Return as action.FormInput for Crawljax parity
			return form.ToFormInputs(cached)
		}
	}

	inputs, err := c.formHandler.DetectInputs(page)
	if err != nil {
		return nil
	}

	if len(inputs) > 0 {
		// Form trainer replay mode: use trained inputs
		if c.formTrainer != nil && c.formTrainer.GetMode() == form.FillReplay {
			for _, input := range inputs {
				inputType := ""
				if input.FormInput != nil {
					inputType = string(input.Type)
				}
				trained := c.formTrainer.MatchInput(input.XPath, input.ID, input.Name, inputType)
				if trained != nil && trained.Value != "" {
					input.SetValues([]string{trained.Value})
				}
			}
		}

		zap.L().Debug("Found form inputs, filling...", zap.Int("count", len(inputs)))

		// CRAWLJAX PARITY: Use HandleFormElements instead of FillInputs
		// This returns list with XPath-based identification for backtracking
		handled := c.formHandler.HandleFormElements(page, inputs)

		// CRAWLJAX PARITY: Auto-pairwise fallback when normal fill fails
		// Check if we have failures by comparing handled vs inputs
		if len(handled) < len(inputs) {
			zap.L().Debug("Normal form fill had failures, trying pairwise",
				zap.Int("handled", len(handled)),
				zap.Int("total", len(inputs)))
			success, worked := c.formHandler.FillInputsPairwise(page, inputs)
			if success && len(worked) > 0 {
				zap.L().Debug("Pairwise form fill succeeded", zap.Int("worked", len(worked)))
				// Update inputs with worked inputs for caching
				inputs = worked
				handled = form.ToFormInputs(worked)
			} else {
				zap.L().Debug("Pairwise form fill also failed")
			}
		}

		// Form trainer training mode: record inputs from DetectedInput (has metadata)
		if c.formTrainer != nil && (c.formTrainer.GetMode() == form.FillTraining || c.formTrainer.GetMode() == form.FillXPathTraining) {
			for _, input := range inputs {
				value := ""
				values := input.GetValues()
				if len(values) > 0 {
					value = values[0]
				}
				inputType := ""
				if input.FormInput != nil {
					inputType = string(input.Type)
				}
				c.formTrainer.RecordInput(&form.TrainedInput{
					XPath:  input.XPath,
					Type:   inputType,
					Name:   input.Name,
					ID:     input.ID,
					Value:  value,
					Values: values,
				})
			}
		}

		// Cache the DetectedInput for this action (has metadata for value rotation)
		if actionID != "" {
			c.formCache[actionID] = inputs
		}

		return handled
	}

	return nil
}

// fillFormsWithInputs fills forms using cached action.FormInput data.
// CRAWLJAX PARITY: Used during path following to replay form inputs from candidates cache.
func (c *Crawler) fillFormsWithInputs(page *browser.Page, inputs []*action.FormInput) {
	for _, formInput := range inputs {
		if formInput.Identification == nil {
			continue
		}

		selector := formInput.Identification.Value
		if selector == "" {
			continue
		}

		// Get value to fill
		var value string
		if len(formInput.InputValues) > 0 {
			value = formInput.InputValues[0].Value
		}

		if value == "" {
			continue
		}

		// Fill the input by finding element based on selector type
		var elem *browser.Element
		var err error
		isXPath := formInput.Identification.How == action.HowXPath
		if isXPath {
			elem, err = page.ElementX(selector)
		} else {
			elem, err = page.Element(selector)
		}
		if err != nil {
			zap.L().Debug("Failed to find cached form input element",
				zap.String("selector", selector),
				zap.Bool("is_xpath", isXPath),
				zap.Error(err))
			continue
		}
		if err := elem.Input(value); err != nil {
			zap.L().Debug("Failed to fill cached form input",
				zap.String("selector", selector),
				zap.Error(err))
		} else {
			zap.L().Debug("Filled cached form input",
				zap.String("selector", selector),
				zap.String("value", value))
		}
	}
}

// navigateToFrame navigates to a specific frame by its path (e.g., "frame1.frame2").
// Returns the Page object for the target frame.
// CRAWLJAX PARITY: Uses FramesWithInfo for proper frame identification (id before name).
func (c *Crawler) navigateToFrame(page *browser.Page, framePath string) (*browser.Page, error) {
	if framePath == "" {
		return page, nil
	}

	// Split frame path into segments
	segments := strings.Split(framePath, ".")
	currentPage := page

	for _, segment := range segments {
		// CRAWLJAX PARITY: Use FramesWithInfo for proper frame identification
		frameInfos, err := currentPage.FramesWithInfo()
		if err != nil {
			return nil, fmt.Errorf("failed to get frames: %w", err)
		}

		found := false
		for _, fi := range frameInfos {
			// Get frame identifier (FramesWithInfo already uses id before name)
			frameID := fi.ID
			if frameID == "" {
				frameID = fmt.Sprintf("frame%d", fi.Index)
			}
			if frameID == segment {
				currentPage = fi.Page
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("frame %q not found", segment)
		}
	}

	return currentPage, nil
}

// extractFragments extracts fragments from the page.
// Uses the configured fragmentation mode: landmark (default, fast) or vips (Crawljax-style).
func (c *Crawler) extractFragments(page *browser.Page, s *state.State) {
	var frags []*fragment.Fragment
	var err error

	switch c.config.FragmentationMode {
	case config.FragmentationVIPS:
		vips := fragment.NewVIPS().
			WithPDoC(c.config.VIPSPDoC).
			WithIterations(c.config.VIPSIterations)
		frags, err = vips.Extract(page)
	default: // config.FragmentationLandmark or empty
		extractor := fragment.NewExtractor()
		frags, err = extractor.Extract(page)
	}

	if err != nil {
		zap.L().Debug("Failed to extract fragments", zap.Error(err))
		return
	}

	c.fragManager.AddFragments(s.ID, frags)
	zap.L().Debug("Extracted fragments from state", zap.Int("count", len(frags)), zap.String("state", s.Name), zap.String("mode", string(c.config.FragmentationMode)))
}

// buildResult builds the crawl result.
func (c *Crawler) buildResult() *Result {
	// CRAWLJAX PARITY: Save final crawl path to session before building resulss
	if c.crawlPath != nil {
		c.crawlPath.Close()
		c.session.AddCrawlPath(c.crawlPath.ImmutableCopy())
	}
	if c.session != nil {
		c.session.MarkEnd()
	}

	return &Result{
		Config:    c.config,
		Graph:     c.graph,
		Stats:     c.stats,
		Fragments: c.fragManager.GetStats(),
		Session:   c.session,
	}
}

// Stats returns current statistics.
func (c *Crawler) GetStats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// IsRunning returns true if crawler is running.
func (c *Crawler) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// Graph returns the state graph.
func (c *Crawler) Graph() *state.Graph {
	return c.graph
}

// formHandlerAdapter adapts EventableConditionChecker to action.FormHandler interface.
// CRAWLJAX PARITY: This breaks the import cycle between action and condition packages.
// Matches Java FormHandler behavior for generating CandidateElement variants with form inputs.
type formHandlerAdapter struct {
	checker *condition.EventableConditionChecker
}

// GetCandidateElementsForInputs implements action.FormHandler.
// CRAWLJAX PARITY: Generates candidate element variants with different form input values.
func (a *formHandlerAdapter) GetCandidateElementsForInputs(elementXPath string, baseCandidate *action.CandidateElement) []*action.CandidateElement {
	if a.checker == nil || a.checker.Count() == 0 {
		return []*action.CandidateElement{baseCandidate}
	}
	return a.checker.GetCandidateElementsForInputs(elementXPath, baseCandidate)
}

// GetFormInputs implements action.FormHandler.
// Returns all form inputs from the EventableConditions.
func (a *formHandlerAdapter) GetFormInputs() []*action.FormInput {
	if a.checker == nil {
		return nil
	}
	return a.checker.GetFormInputs()
}

// HandleFormElements implements action.FormHandler.
// This is a no-op in this adapter as form filling is handled elsewhere.
func (a *formHandlerAdapter) HandleFormElements(formInputs []*action.FormInput) []*action.FormInput {
	return formInputs
}

// recordMetrics records step metrics to the metrics collector.
// Called only when metricsCollector is set (benchmark mode).
func (c *Crawler) recordMetrics(crawlAction *action.CandidateCrawlAction, succeeded, stateDiscovered, formSubmitted bool, newActionsCount int) {
	// Get action ID from identification
	actionID := ""
	if crawlAction != nil && crawlAction.GetCandidateElement() != nil {
		ident := crawlAction.GetCandidateElement().GetIdentification()
		if ident != nil {
			actionID = ident.Value
		}
	}

	// Build step context
	ctx := &metrics.StepContext{
		ActionID:        actionID,
		ActionSucceeded: succeeded,
		StateDiscovered: stateDiscovered,
		FormSubmitted:   formSubmitted,
	}

	// Set reward based on new actions discovered
	ctx.RewardEnv = float64(newActionsCount)

	// Extract links from current page for link coverage
	if c.browserPool != nil {
		br := c.browserPool.Get()
		if page := br.CurrentPage(); page != nil {
			links := c.extractLinksFromPage(page)
			ctx.NewLinks = links
		}
	}

	// Record to collector
	if err := c.metricsCollector.OnStepComplete(ctx); err != nil {
		zap.L().Warn("Failed to record metrics", zap.Error(err))
	}
}

// extractLinksFromPage extracts all links from the current page for metrics tracking.
func (c *Crawler) extractLinksFromPage(page *browser.Page) []string {
	if page == nil {
		return nil
	}

	// Use the page's current URL as base
	baseURL, err := page.URL()
	if err != nil || baseURL == "" {
		return nil
	}

	// Extract all anchor hrefs as JSON array
	result, err := page.Eval(`(() => {
		const links = [];
		const anchors = document.querySelectorAll('a[href]');
		for (const a of anchors) {
			const href = a.getAttribute('href');
			if (href && !href.startsWith('javascript:') && !href.startsWith('#')) {
				try {
					const url = new URL(href, window.location.href);
					links.push(url.href);
				} catch (e) {
					// Invalid URL, skip
				}
			}
		}
		return JSON.stringify(links);
	})()`)
	if err != nil {
		return nil
	}

	// Parse result as JSON string
	jsonStr, ok := result.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return nil
	}

	// Parse JSON array
	var links []string
	if err := parseJSONLinks(jsonStr, &links); err != nil {
		return nil
	}

	return links
}

// parseJSONLinks parses a JSON array string into a slice of strings.
func parseJSONLinks(jsonStr string, links *[]string) error {
	// Simple JSON array parsing (avoid importing encoding/json for this)
	// Format: ["url1", "url2", ...]
	if len(jsonStr) < 2 || jsonStr[0] != '[' || jsonStr[len(jsonStr)-1] != ']' {
		return fmt.Errorf("invalid JSON array")
	}

	// Empty array
	if jsonStr == "[]" {
		return nil
	}

	// Remove brackets
	inner := jsonStr[1 : len(jsonStr)-1]

	// Split by comma (simple approach, doesn't handle escaped quotes)
	inQuote := false
	start := 0
	for i := 0; i < len(inner); i++ {
		if inner[i] == '"' {
			inQuote = !inQuote
		} else if inner[i] == ',' && !inQuote {
			s := strings.TrimSpace(inner[start:i])
			if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
				*links = append(*links, s[1:len(s)-1])
			}
			start = i + 1
		}
	}

	// Last element
	s := strings.TrimSpace(inner[start:])
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		*links = append(*links, s[1:len(s)-1])
	}

	return nil
}
