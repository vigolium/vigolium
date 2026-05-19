package crawler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/mab"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// ErrCrawlConditionNotMet is returned when crawl conditions are not satisfied.
// This is used to skip MAB updates when an action was not actually executed.
var ErrCrawlConditionNotMet = errors.New("crawl condition not met")

// ConsumerConfig holds configuration for parallel crawling.
type ConsumerConfig struct {
	NumConsumers int // Number of parallel consumers (default: 1)
}

// ParallelCrawler extends Crawler with parallel crawling capabilities.
type ParallelCrawler struct {
	*Crawler

	numConsumers int
	runningCount int32 // Atomic counter for running consumers
	pendingCount int32 // Atomic counter for pending work
	consumerWg   sync.WaitGroup
	workChan     chan *workItem
	resultChan   chan *workResult
	shutdownChan chan struct{}
	stateLocks   sync.Map // Per-state locks using stripe pattern
}

// workItem represents a unit of work for a consumer.
type workItem struct {
	action  *action.CandidateCrawlAction
	stateID string
}

// workResult represents the result of processing a work item.
type workResult struct {
	action        *action.CandidateCrawlAction
	sourceStateID string // State where action was executed
	newState      *state.State
	err           error
}

// NewParallelCrawler creates a new parallel crawler.
func NewParallelCrawler(crawler *Crawler, numConsumers int) *ParallelCrawler {
	if numConsumers < 1 {
		numConsumers = 1
	}

	return &ParallelCrawler{
		Crawler:      crawler,
		numConsumers: numConsumers,
		workChan:     make(chan *workItem, numConsumers*10),
		resultChan:   make(chan *workResult, numConsumers*10),
		shutdownChan: make(chan struct{}),
	}
}

// RunParallel starts the parallel crawl.
func (pc *ParallelCrawler) RunParallel(ctx context.Context) (*Result, error) {
	pc.mu.Lock()
	if pc.running {
		pc.mu.Unlock()
		return nil, fmt.Errorf("crawler is already running")
	}
	pc.running = true
	pc.mu.Unlock()

	defer func() {
		pc.mu.Lock()
		pc.running = false
		pc.mu.Unlock()
	}()

	// Initialize index state
	if err := pc.initializeIndexState(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize index state: %w", err)
	}

	// Start consumer workers
	for i := 0; i < pc.numConsumers; i++ {
		pc.consumerWg.Add(1)
		go pc.consumer(ctx, i)
	}

	// Start result processor
	go pc.resultProcessor(ctx)

	// Start work distributor
	go pc.workDistributor(ctx)

	// Wait for all consumers to finish
	pc.consumerWg.Wait()

	// Close channels
	close(pc.resultChan)

	return pc.buildResult(), nil
}

// consumer is a worker that processes actions.
func (pc *ParallelCrawler) consumer(ctx context.Context, id int) {
	defer pc.consumerWg.Done()

	// Create child logger with consumer context
	consumerLog := zap.L().With(zap.Int("consumer_id", id))
	consumerLog.Info("Consumer starting")

	// Get a browser from the pool
	br := pc.browserPool.Get()
	page, err := br.NewPage()
	if err != nil {
		consumerLog.Error("Failed to create page", zap.Error(err))
		return
	}
	defer func() { _ = page.Close() }()

	for {
		select {
		case <-ctx.Done():
			consumerLog.Info("Context cancelled")
			return
		case <-pc.shutdownChan:
			consumerLog.Info("Shutdown signal received")
			return
		case work, ok := <-pc.workChan:
			if !ok {
				consumerLog.Info("Work channel closed")
				return
			}

			atomic.AddInt32(&pc.runningCount, 1)

			// Process the work item
			result := pc.processWork(ctx, page, work, id)

			// Send result
			select {
			case pc.resultChan <- result:
			case <-ctx.Done():
				atomic.AddInt32(&pc.runningCount, -1)
				return
			}

			atomic.AddInt32(&pc.runningCount, -1)
		}
	}
}

// processWork processes a single work item.
func (pc *ParallelCrawler) processWork(ctx context.Context, page *browser.Page, work *workItem, consumerID int) *workResult {
	result := &workResult{
		action:        work.action,
		sourceStateID: work.stateID,
	}

	// Get action ID from identification
	actionID := ""
	if work.action != nil && work.action.GetCandidateElement() != nil {
		ident := work.action.GetCandidateElement().GetIdentification()
		if ident != nil {
			actionID = ident.Value
		}
	}

	zap.L().Debug("Processing action",
		zap.Int("consumer_id", consumerID),
		zap.String("action_id", actionID),
		zap.String("state_id", work.stateID))

	// Acquire lock for the state
	lock := pc.getStateLock(work.stateID)
	lock.Lock()
	defer lock.Unlock()

	// Navigate to the state
	targetState, exists := pc.graph.GetState(work.stateID)
	if !exists {
		result.err = fmt.Errorf("state %s not found", work.stateID)
		return result
	}

	// Navigate to the target state
	if err := pc.navigateToStateForConsumer(ctx, page, targetState); err != nil {
		result.err = fmt.Errorf("failed to navigate to state: %w", err)
		return result
	}

	// Execute the action
	if err := pc.executeActionOnPage(ctx, page, work.action); err != nil {
		result.err = err
		pc.candidates.MarkFailed(work.action, err)
		return result
	}

	// Capture the resulting state
	newState, err := pc.captureState(ctx, page, targetState.Depth+1)
	if err != nil {
		result.err = fmt.Errorf("failed to capture state: %w", err)
		return result
	}

	result.newState = newState
	pc.candidates.MarkExecuted(work.action)

	return result
}

// navigateToStateForConsumer navigates to a state using browser reset and path replay.
func (pc *ParallelCrawler) navigateToStateForConsumer(ctx context.Context, page *browser.Page, target *state.State) error {
	// Navigate to index URL first
	resetURL := pc.config.URL.String()
	if pc.config.BasicAuthUser != "" {
		resetURL = pc.config.GetBasicAuthURL()
	}

	if err := page.Navigate(resetURL); err != nil {
		return fmt.Errorf("failed to navigate to index: %w", err)
	}

	// Ignore wait errors
	_ = page.WaitStable(pc.config.WaitAfterReload)

	// Get index state
	indexState := pc.graph.GetIndexState()
	if indexState == nil {
		return fmt.Errorf("index state not found")
	}

	// If target is index, we're done
	if target.ID == indexState.ID {
		return nil
	}

	// Find path to target
	path := pc.graph.ShortestPath(indexState.ID, target.ID)
	if path == nil {
		// Try direct navigation
		return page.Navigate(target.URL)
	}

	// Replay the path
	for _, edge := range path {
		// Skip if edge has no identification
		if edge.Identification == nil {
			continue
		}

		selector := edge.GetSelector()
		isXPath := edge.Identification.How == action.HowXPath
		if isXPath {
			elem, err := page.ElementX(selector)
			if err != nil {
				return fmt.Errorf("failed to find element (XPath) during replay: %w", err)
			}
			if err := elem.Click(); err != nil {
				return fmt.Errorf("failed to replay action (XPath): %w", err)
			}
		} else {
			if err := page.Click(selector); err != nil {
				return fmt.Errorf("failed to replay action: %w", err)
			}
		}

		_ = page.WaitStable(pc.config.DOMStableTime)
	}

	return nil
}

// executeActionOnPage executes an action on a specific page.
func (pc *ParallelCrawler) executeActionOnPage(ctx context.Context, page *browser.Page, crawlAction *action.CandidateCrawlAction) error {
	candidate := crawlAction.GetCandidateElement()
	eventType := crawlAction.GetEventType()

	// Handle frame navigation if needed
	targetPage := page
	if candidate.RelatedFrame != "" {
		framePage, err := pc.navigateToFrame(page, candidate.RelatedFrame)
		if err != nil {
			return fmt.Errorf("failed to navigate to frame %s: %w", candidate.RelatedFrame, err)
		}
		targetPage = framePage
	}

	// Check crawl conditions
	if !pc.shouldCrawl(targetPage) {
		return ErrCrawlConditionNotMet
	}

	// Fill forms if enabled
	if pc.config.FormFillEnabled {
		// Use selector as action ID for form cache
		actionID := ""
		if ident := candidate.GetIdentification(); ident != nil {
			actionID = ident.Value
		}
		pc.fillFormsIfPresent(targetPage, actionID)
	}

	// Execute the action
	ident := candidate.GetIdentification()
	if ident == nil {
		return fmt.Errorf("no identification for candidate element")
	}
	selector := ident.Value
	isXPath := ident.How == action.HowXPath

	// Helper to get element based on XPath or CSS
	getElement := func() (*browser.Element, error) {
		if isXPath {
			return targetPage.ElementX(selector)
		}
		return targetPage.Element(selector)
	}

	switch eventType {
	case action.EventTypeClick:
		if isXPath {
			elem, err := targetPage.ElementX(selector)
			if err != nil {
				return err
			}
			return elem.Click()
		}
		return targetPage.Click(selector)
	case action.EventTypeHover:
		elem, err := getElement()
		if err != nil {
			return err
		}
		return elem.Hover()
	default:
		if isXPath {
			elem, err := targetPage.ElementX(selector)
			if err != nil {
				return err
			}
			return elem.Click()
		}
		return targetPage.Click(selector)
	}
}

// resultProcessor processes results from consumers.
func (pc *ParallelCrawler) resultProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-pc.resultChan:
			if !ok {
				return
			}

			pc.processResult(ctx, result)
		}
	}
}

// processResult processes a single work result.
// RLCRAWLER PARITY: Updates MAB policy with rewards for parallel execution.
func (pc *ParallelCrawler) processResult(ctx context.Context, result *workResult) {
	// Get action ID from identification
	actionID := ""
	if result.action != nil && result.action.GetCandidateElement() != nil {
		ident := result.action.GetCandidateElement().GetIdentification()
		if ident != nil {
			actionID = ident.Value
		}
	}

	if result.err != nil {
		// RLCRAWLER PARITY: Skip MAB update entirely when crawl condition not met
		// Action was not actually executed, so we shouldn't update MAB
		if errors.Is(result.err, ErrCrawlConditionNotMet) {
			zap.L().Debug("Action skipped (crawl condition not met)",
				zap.String("action_id", actionID),
				zap.String("state", result.sourceStateID))
			// Don't count as failure, don't update MAB
			return
		}

		zap.L().Debug("Action failed", zap.String("action_id", actionID), zap.Error(result.err))
		pc.mu.Lock()
		pc.stats.ActionsFailed++
		pc.stats.ConsecutiveFailures++
		pc.mu.Unlock()

		// RLCRAWLER PARITY: Update MAB with zero reward for failed actions
		if pc.mabPolicy != nil && actionID != "" {
			reward := mab.TransformReward(0.0)
			pc.mabPolicy.Update(result.sourceStateID, actionID, reward)
			zap.L().Debug("MAB updated for failed action (parallel)",
				zap.String("state", result.sourceStateID),
				zap.String("action", actionID),
				zap.Float64("reward", reward))
		}
		return
	}

	pc.mu.Lock()
	pc.stats.ActionsExecuted++
	pc.stats.ConsecutiveFailures = 0 // Reset on success
	pc.mu.Unlock()

	// Calculate newActionsCount for MAB reward
	newActionsCount := 0

	if result.newState == nil {
		// RLCRAWLER PARITY: Update MAB with zero reward (no new state)
		if pc.mabPolicy != nil && actionID != "" {
			reward := mab.TransformReward(0.0)
			pc.mabPolicy.Update(result.sourceStateID, actionID, reward)
			zap.L().Debug("MAB updated for action with no new state (parallel)",
				zap.String("state", result.sourceStateID),
				zap.String("action", actionID),
				zap.Float64("reward", reward))
		}
		return
	}

	// Check if this is a new state
	pc.mu.Lock()
	existingState := pc.graph.FindStateByDOM(result.newState.StrippedDOM)

	if existingState != nil {
		// Duplicate state - no new actions discovered
		pc.stats.StatesDuplicate++
		pc.mu.Unlock()

		// Add edge to existing state
		pc.graph.AddEdge(result.sourceStateID, existingState.ID, action.NewEventableFromCandidateCrawlAction(result.action))
	} else {
		// New state discovered
		pc.graph.AddState(result.newState)
		pc.stats.StatesDiscovered++

		// RLCRAWLER PARITY: Register new state with MAB
		if pc.mabPolicy != nil {
			pc.mabPolicy.AddState(result.newState.ID)
		}

		pc.mu.Unlock()

		// Add edge to new state
		pc.graph.AddEdge(result.sourceStateID, result.newState.ID, action.NewEventableFromCandidateCrawlAction(result.action))

		zap.L().Debug("New state discovered", zap.String("state", result.newState.Name))

		// Queue new state for exploration
		atomic.AddInt32(&pc.pendingCount, 1)

		// RLCRAWLER PARITY: For new states, reward = 1 (new discovery)
		// Note: We can't count exact actions here as we'd need to extract them
		// Use 1 as a simple reward for discovering a new state
		newActionsCount = 1
	}

	// RLCRAWLER PARITY: Update MAB with coverage-based reward
	if pc.mabPolicy != nil && actionID != "" {
		rewardEnv := float64(newActionsCount)
		reward := mab.TransformReward(rewardEnv)
		reset := pc.mabPolicy.Update(result.sourceStateID, actionID, reward)
		zap.L().Debug("MAB policy updated (parallel)",
			zap.String("state", result.sourceStateID),
			zap.String("action", actionID),
			zap.Float64("reward_env", rewardEnv),
			zap.Float64("reward", reward),
			zap.Bool("round_reset", reset))
		if reset {
			zap.L().Debug("MAB round reset (parallel)",
				zap.Int("new_round", pc.mabPolicy.GetRound()))
		}
	}
}

// workDistributor distributes work to consumers.
func (pc *ParallelCrawler) workDistributor(ctx context.Context) {
	defer close(pc.workChan)
	defer close(pc.shutdownChan)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Check termination conditions
			if pc.shouldTerminate(ctx) {
				return
			}

			// Get the next action to process
			act, stateID := pc.candidates.PollAny()
			if act == nil {
				// No work available, check if consumers are still working
				if atomic.LoadInt32(&pc.runningCount) == 0 && !pc.candidates.HasPending() {
					// All done
					return
				}

				// Wait a bit before checking again
				continue
			}

			// Send work to consumers
			select {
			case pc.workChan <- &workItem{action: act, stateID: stateID}:
				// Work sent
			case <-ctx.Done():
				return
			}
		}
	}
}

// getStateLock returns a lock for a specific state.
func (pc *ParallelCrawler) getStateLock(stateID string) *sync.Mutex {
	lock, _ := pc.stateLocks.LoadOrStore(stateID, &sync.Mutex{})
	return lock.(*sync.Mutex)
}
