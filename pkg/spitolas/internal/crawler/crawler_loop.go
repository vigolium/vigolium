package crawler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/mab"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// errCrawlTerminated is returned by a tab's consume loop when a termination
// condition (budget, state cap, failure streak, cancellation) ended the crawl.
// It cancels the sibling tabs' wait for work; crawlLoop reports it as nil.
var errCrawlTerminated = errors.New("crawl terminated")

// crawlLoop is the main crawl loop. Every tab (spidering.tabs, default 1) runs
// consume against the one shared frontier:
//  1. Claim a STATE (not action) from the queue
//  2. Call execute(state) which:
//     a. If not at state, reset() to index (adds reload edge) then reachFromHome()
//     b. crawlThroughActions() - DFS through all actions from current state
//  3. TaskDone(state) - release the claim and re-add the state if it still has actions
//
// The loop ends when the queue is empty AND no tab is crawling (a tab still
// crawling can add states), or when any tab hits a termination condition.
func (c *Crawler) crawlLoop(ctx context.Context) error {
	if c.shouldTerminate(ctx) {
		zap.L().Debug("Termination condition met")
		c.addFinalReloadEdge(c.primary)
		return nil
	}

	workers := c.tabWorkers(ctx)
	var err error
	if len(workers) == 1 {
		err = c.consume(ctx, ctx, workers[0])
	} else {
		// gctx only bounds the wait for work: when one tab stops the crawl the
		// others stop waiting. In-flight browser work stays on ctx and ends at
		// the next shouldTerminate, which sees the same global condition.
		g, gctx := errgroup.WithContext(ctx)
		for _, w := range workers {
			g.Go(func() error { return c.consume(ctx, gctx, w) })
		}
		err = g.Wait()
	}
	if errors.Is(err, errCrawlTerminated) {
		return nil
	}
	return err
}

// consume is one tab's share of the crawl loop: claim a state, crawl it,
// release it, until the frontier drains or the crawl terminates.
func (c *Crawler) consume(ctx, waitCtx context.Context, w *tabWorker) error {
	for iteration := 1; ; iteration++ {
		// Log queue stats every iteration for debugging
		stats := c.candidates.Stats()
		zap.L().Debug("CrawlLoop iteration",
			zap.Int("tab", w.id),
			zap.Int("iteration", iteration),
			zap.Int("pending_states", stats.TotalPending),
			zap.Int("total_seen", stats.TotalSeen))

		// Check termination conditions
		if c.shouldTerminate(ctx) {
			zap.L().Debug("Termination condition met", zap.Int("tab", w.id))
			c.addFinalReloadEdge(w)
			return errCrawlTerminated
		}

		// Claim a STATE (not action) from the queue based on crawl strategy.
		// Blocks while other tabs hold every pending state and may add more.
		stateID, err := c.candidates.AwaitState(waitCtx, c.config.CrawlStrategy)
		if err != nil || stateID == "" {
			// Drained (nothing pending, no tab crawling), or a sibling tab
			// stopped the crawl.
			zap.L().Debug("No more states to crawl", zap.Int("tab", w.id), zap.Error(err))
			c.addFinalReloadEdge(w)
			return nil
		}

		c.runTask(ctx, w, stateID)

		// Log MAB summary every 5 iterations for debugging
		if c.mabPolicy != nil && iteration%5 == 0 {
			c.logMABSummary()
		}
	}
}

// runTask crawls one claimed state and always releases the claim: a claim
// that is never released keeps the active count above zero and would leave the
// other tabs waiting for work forever.
func (c *Crawler) runTask(ctx context.Context, w *tabWorker, stateID string) {
	defer c.candidates.TaskDone(stateID)
	defer func() {
		if r := recover(); r != nil {
			zap.L().Error("Crawl task panicked, recovering",
				zap.Int("tab", w.id), zap.String("state_id", stateID),
				zap.Any("panic", r), zap.Stack("stack"))
		}
	}()

	zap.L().Debug("Processing state", zap.Int("tab", w.id), zap.String("state_id", stateID))

	// Get the state to crawl
	crawlTask, ok := c.graph.GetState(stateID)
	if !ok {
		zap.L().Warn("State not found, skipping", zap.String("state_id", stateID))
		c.candidates.PurgeState(stateID)
		return
	}

	c.execute(ctx, w, crawlTask)

	zap.L().Debug("Execute completed for state", zap.Int("tab", w.id), zap.String("state_id", stateID))
}

// execute crawls all actions from a target state.
//  1. If at crawlTask state -> setBTStatus(true, -1) + crawlThroughActions() (NO EARLY RETURN!)
//  2. ALWAYS: reset() + reachFromHome() + crawlThroughActions()
func (c *Crawler) execute(ctx context.Context, w *tabWorker, crawlTask *state.State) {
	zap.L().Debug("Execute task for state",
		zap.String("state", crawlTask.Name),
		zap.String("state_id", crawlTask.ID))

	currentState := w.stateMachine.GetCurrentState()

	if currentState != nil && currentState.ID == crawlTask.ID && w.crawlPath != nil {
		zap.L().Debug("Already at target state, crawling through actions first")
		w.crawlPath.MarkSuccess()
		func() {
			defer func() {
				if r := recover(); r != nil {
					zap.L().Error("crawlThroughActions panicked in same-state block, recovering",
						zap.Any("panic", r))
				}
			}()
			c.crawlThroughActions(ctx, w)
		}()
		zap.L().Debug("crawlThroughActions completed (same state)")
	}

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

	if err := c.reset(ctx, w, crawlTask.ID); err != nil {
		zap.L().Debug("Reset failed", zap.Error(err))
		if w.crawlPath != nil {
			w.crawlPath.MarkFailed()
		}
		return
	}
	zap.L().Debug("Reset completed")

	if c.shouldTerminate(ctx) {
		return
	}

	zap.L().Debug("Reaching target state from home", zap.String("target", crawlTask.Name))
	if err := c.reachFromHome(ctx, w, crawlTask); err != nil {
		zap.L().Debug("State unreachable, removing from candidate actions",
			zap.String("state", crawlTask.Name), zap.Error(err))
		c.candidates.PurgeState(crawlTask.ID)
		return
	}

	if c.shouldTerminate(ctx) {
		return
	}

	c.crawlThroughActions(ctx, w)
	zap.L().Debug("crawlThroughActions completed")
}

// reset navigates to the index URL and creates a NEW StateMachine.
// 1. browser.handlePopups() - FIRST THING!
// 2. Save crawlPath to session
// 3. Get onURLSet + previousState from OLD StateMachine
// 4. Create NEW StateMachine BEFORE navigate
// 5. Create NEW CrawlPath
// 6. Navigate to URL
// 7. checkOnURLState() using NEW StateMachine
// 8. crawlDepth.set(0) - LAST THING!
func (c *Crawler) reset(ctx context.Context, w *tabWorker, nextTarget string) error {
	br := c.browser
	if br == nil {
		return fmt.Errorf("crawler browser not initialized")
	}
	page := w.page
	if page != nil {
		_ = page.HandlePopups()
	}

	if w.crawlPath != nil {
		w.crawlPath.Close()
		c.session.AddCrawlPath(w.crawlPath.ImmutableCopy())
	}

	var onURLSet []*state.State
	var previousState *state.State
	if w.stateMachine != nil {
		onURLSet = w.stateMachine.GetOnURLSet()
		previousState = w.stateMachine.GetCurrentState()
	} else {
		onURLSet = make([]*state.State, 0)
	}

	indexState := c.graph.GetIndexState()
	w.stateMachine = state.NewStateMachineWithOnURLSet(c.graph, indexState, onURLSet)
	zap.L().Debug("Reset: created NEW StateMachine BEFORE navigate",
		zap.String("initial_state", indexState.Name),
		zap.Int("onURLSet_size", w.stateMachine.OnURLSetSize()))

	w.crawlPath = state.NewCrawlPath(nextTarget)

	resetURL := c.config.URL.String()
	if c.config.BasicAuthUser != "" {
		resetURL = c.config.GetBasicAuthURL()
	}

	// Reuse br/page from Step 1, or create a new page on the same browser.
	// Only the first tab can lack a page: an extra tab is opened with one and
	// keeps it (the popup cleanup's keep-list holds its page).
	if page == nil {
		if w != c.primary {
			return fmt.Errorf("crawl tab %d has no page", w.id)
		}
		var err error
		page, err = br.NewPage()
		if err != nil {
			return err
		}
		br.SetCurrentPage(page)
		w.page = page
		// Extra headers are set per-page in CDP, so a freshly created reset page
		// needs them re-applied (cookies persist in the browser jar). The outcome
		// lands in Stats.AuthState.
		_ = c.applyPageAuth(page)
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
	c.checkWaitConditions(ctx, page)

	c.checkOnURLState(ctx, w, page, previousState, resetURL)

	// Go uses newState.Depth for maxDepth check instead of a per-crawler counter.

	w.resetCalled = true
	c.mu.Lock()
	c.stats.BacktrackCount++
	c.mu.Unlock()
	return nil
}

// reachFromHome navigates from current state to target state.
// 1. Try shortest path from CURRENT state to target
// 2. If fails, try from each onURLSet state
// 3. Navigate to onURL state, then follow path
func (c *Crawler) reachFromHome(ctx context.Context, w *tabWorker, target *state.State) error {
	zap.L().Debug("Reaching target state", zap.String("target", target.Name))

	indexState := c.graph.GetIndexState()
	if indexState == nil {
		return fmt.Errorf("no index state")
	}

	page := w.page
	if page == nil {
		return fmt.Errorf("no page on crawl tab %d", w.id)
	}

	alreadyTried := make(map[string]bool)

	currentState := w.stateMachine.GetCurrentState()
	if currentState != nil {
		alreadyTried[currentState.ID] = true
		path := c.graph.ShortestPath(currentState.ID, target.ID)
		if path != nil {
			zap.L().Debug("Path found from current state",
				zap.String("from", currentState.Name),
				zap.Int("path_length", len(path)))
			err := c.followPath(ctx, w, path, target)
			if err == nil {
				reachedState := w.stateMachine.GetCurrentState()
				if reachedState.ID != target.ID {
					zap.L().Debug("Tried reaching target but reached near-duplicate",
						zap.String("target", target.Name),
						zap.String("reached", reachedState.Name))
					w.crawlPath.SetBacktrackSuccess(false)
					w.crawlPath.SetReachedNearDup(reachedState.ID)
					c.candidates.StateUpdated(target.ID)
				} else {
					zap.L().Debug("Reached the correct target", zap.String("target", target.Name))
					w.crawlPath.SetBacktrackSuccess(true)
				}
				return nil
			}
			zap.L().Debug("Path from current state failed, resetting before trying onURLSet",
				zap.String("from", currentState.Name),
				zap.Error(err))
			w.crawlPath.SetBacktrackSuccess(false)
			_ = c.reset(ctx, w, target.ID) // CRITICAL: Reset on first path failure!
		}
	}

	onURLStates := w.stateMachine.GetOnURLSetSlice()
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
		c.checkWaitConditions(ctx, page)
		w.stateMachine.SetCurrentState(onURLState)

		// Follow path from onURL to target
		err := c.followPath(ctx, w, path, target)
		if err == nil {
			reachedState := w.stateMachine.GetCurrentState()
			if reachedState.ID != target.ID {
				zap.L().Debug("Tried reaching target but reached near-duplicate",
					zap.String("from", onURLState.Name),
					zap.String("target", target.Name),
					zap.String("reached", reachedState.Name))
				w.crawlPath.SetBacktrackSuccess(false)
				w.crawlPath.SetReachedNearDup(reachedState.ID)
				c.candidates.StateUpdated(target.ID)
			} else {
				zap.L().Debug("Reached the correct target",
					zap.String("from", onURLState.Name),
					zap.String("target", target.Name))
				w.crawlPath.SetBacktrackSuccess(true)
			}
			return nil
		}

		zap.L().Debug("Path from onURL state failed, resetting",
			zap.String("from", onURLState.Name),
			zap.Error(err))
		w.crawlPath.SetBacktrackSuccess(false)
		_ = c.reset(ctx, w, target.ID)
	}

	return fmt.Errorf("cannot reach state %s from any starting point", target.Name)
}

// followPath executes actions along a path to reach the target state.
func (c *Crawler) followPath(ctx context.Context, w *tabWorker, path []*action.Eventable, target *state.State) error {
	page := w.page
	if page == nil {
		return fmt.Errorf("no page on crawl tab %d", w.id)
	}
	// Replaying a path after a re-login must send the new credentials.
	c.refreshAuthIfChanged(page)

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

		if c.config.FormFillEnabled {
			if !c.candidates.ShouldDisableInputForPath(edge) {
				// Try to get cached input from candidates
				cachedInputs := c.candidates.GetInput(edge)
				if len(cachedInputs) > 0 {
					// Use cached form inputs
					zap.L().Debug("Used cached form input for backtracking", zap.Int64("eventable_id", edge.ID))
					c.fillFormsWithInputs(page, cachedInputs)
				} else {
					// eventable.RelatedFormInputs with DOM-detected inputs
					zap.L().Debug("No cached input, using getInputElements", zap.Int64("eventable_id", edge.ID))
					handled := c.handleInputElements(w, page, edge)
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

		// If ChangeState returns false, the path is invalid (edge no longer exists).
		targetState, ok := c.graph.GetState(edge.TargetStateID)
		if !ok {
			return fmt.Errorf("target state %s not found in graph during path follow", edge.TargetStateID)
		}
		if !w.stateMachine.ChangeState(targetState) {
			return fmt.Errorf("could not switch states during path follow: %s -> %s", edge.SourceStateID, edge.TargetStateID)
		}

		// crawlpath.add(clickable);
		if w.crawlPath != nil {
			w.crawlPath.Add(edge)
		}
	}

	// Verify we reached the target
	currentState := w.stateMachine.GetCurrentState()
	if currentState == nil || currentState.ID != target.ID {
		currentName := "nil"
		if currentState != nil {
			currentName = currentState.Name
		}
		return fmt.Errorf("path didn't reach target state %s, at %s", target.Name, currentName)
	}

	// The state machine only tracks which edges were replayed; the page itself
	// may have changed server-side, so stored XPaths would now fire against a
	// different DOM (MISS-28d). Compare the live stripped DOM with the target's.
	if len(path) > 0 && target.StrippedDOM != "" {
		if html, err := page.HTMLWithFramesFiltered(c.config.CrawlFrames, c.config.ExcludeFrames); err == nil {
			if !state.SameStructure(c.comparator.PrepareForComparison(html), target) {
				return fmt.Errorf("%w: replay reached a page that is not state %s", errPathDiverged, target.Name)
			}
		}
	}

	return nil
}

// errPathDiverged is followPath's error when the replayed path lands on a DOM
// that is not the target state's (a server-side state change, MISS-28d).
var errPathDiverged = errors.New("path diverged")

// DUPLICATE_EVENT_SEED is used to encode equivalentAccess in eventable IDs.
const DUPLICATE_EVENT_SEED = 100000

// crawlThroughActions crawls through all actions for current state using DFS.
//  1. afterBacktrack=true for first poll
//  2. Poll action with afterBacktrack parameter
//  3. Check allConditionsSatisfied(browser) BEFORE firing
//  4. If wasExplored(): eventableId = equivalentAccess * DUPLICATE_EVENT_SEED + eventableId
//  5. On success: fragmentManager.recordAccess(), inspectNewState()
//  6. On failure: setDirectAccess(true), disableInputsForAction(), re-add action if disableInputsForAction returns true
//  7. afterBacktrack=false for subsequent polls
//  8. Check crawlerNotInScope() after each action
func (c *Crawler) crawlThroughActions(ctx context.Context, w *tabWorker) {
	afterBacktrack := true

	for {
		if c.shouldTerminate(ctx) {
			return
		}

		// Poll action for current state only
		currentState := w.stateMachine.GetCurrentState()
		if currentState == nil {
			return
		}

		// A re-login elsewhere in the scan minted new credentials: put them on
		// the page before the next action (MISS-26).
		c.refreshAuthIfChanged(w.page)

		act := c.candidates.PollByMode(currentState.ID, c.config.CrawlStrategy, afterBacktrack)
		if act == nil {
			// No more actions for current state, exit DFS
			zap.L().Debug("No more actions for state", zap.String("state", currentState.Name))
			return
		}

		element := act.GetCandidateElement()

		page := w.page
		if page == nil {
			zap.L().Debug("No current page available, exiting crawl loop")
			return
		}
		if !c.checkAllConditionsSatisfied(page, element) {
			zap.L().Debug("Element not clicked because not all crawl conditions were satisfied",
				zap.String("xpath", element.GetIdentification().Value))
			afterBacktrack = false
			continue
		}

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

		sourceStateID := currentState.ID

		// This allows us to use eventable.getRelatedFormInputs() in fireEventWithInputs
		eventable := action.NewEventableFromCandidateCrawlActionWithID(act, eventableID)
		eventable.SourceStateID = sourceStateID

		// Execute the action with eventable (for proper form input handling)
		newActionsCount, filledFormInputs, err := c.executeActionWithEventable(ctx, w, act, eventable)

		targetStateID := sourceStateID
		if newState := w.stateMachine.GetCurrentState(); newState != nil {
			targetStateID = newState.ID
		}
		eventable.TargetStateID = targetStateID

		if err != nil {
			// A policy-denied action is consumed, not failed: re-queueing or
			// retrying it would only be denied again, and counting it toward
			// ConsecutiveFailures could end a crawl that is working as configured.
			if errors.Is(err, ErrActionNotPermitted) {
				c.candidates.MarkExecuted(act)
				if c.mabPolicy != nil {
					c.mabPolicy.RemoveAction(sourceStateID, element.GetIdentification().Value)
				}
				afterBacktrack = false
				continue
			}
			// RLCRAWLER PARITY: Skip MAB update entirely when crawl condition not met
			// Action was not actually executed, so we shouldn't update MAB or count as failure
			if errors.Is(err, ErrCrawlConditionNotMet) {
				zap.L().Debug("Action skipped (crawl condition not met)",
					zap.String("state", sourceStateID))
				// Don't count as failure, don't update MAB, just continue
				afterBacktrack = false
				continue
			}

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
			element.SetDirectAccess(true)
			added := c.candidates.DisableInputsForAction(act)
			if added {
				c.candidates.ReAddAction(act, currentState.ID)
			} else {
				// The normal path has run out of re-queues for this action, so it
				// is about to be dropped for good. Hand it to the retry sweep
				// instead: most of these failed on a transient page condition that
				// will not still be true at the end of the crawl.
				c.recordFailedAction(act, currentState.ID)
			}
			c.mu.Lock()
			c.stats.ActionsFailed++
			c.mu.Unlock()
			c.consecutiveFails.Add(1)
			// Record failed action to metrics (only when benchmark mode)
			if c.metricsCollector != nil {
				c.recordMetrics(w, act, false, false, false, 0)
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
			// It's set to false AFTER the if-else block (line 1323)
			// But since we continue here, we need to set it too
			afterBacktrack = false
			continue
		}

		if len(filledFormInputs) > 0 {
			c.candidates.MapInput(eventable, filledFormInputs)
		}

		if c.fragManager != nil {
			c.fragManager.RecordElementAccess(element, currentState.ID)
		}

		// ONLY when DOM actually changed. NOT here unconditionally.

		c.candidates.MarkExecuted(act)
		c.mu.Lock()
		c.stats.ActionsExecuted++
		c.mu.Unlock()
		c.consecutiveFails.Store(0) // Reset on success

		// An authenticated crawl that just landed on a login page lost its
		// session (a logout control, an expired token): re-apply once, then
		// report honestly (MISS-26).
		c.checkLoggedOut(ctx, page)

		// Record successful action to metrics (only when benchmark mode)
		if c.metricsCollector != nil {
			isFormSubmit := act.GetEventType() == action.EventTypeEnter
			c.recordMetrics(w, act, true, newActionsCount > 0, isFormSubmit, newActionsCount)
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

		afterBacktrack = false

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

// shouldTerminate checks if crawl should terminate.
func (c *Crawler) shouldTerminate(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		zap.L().Debug("Context cancelled, terminating")
		return true
	default:
	}

	// The start URL lands on a denied login wall: nothing in scope is reachable,
	// so keep the remaining budget instead of oscillating against the provider.
	if c.startWalled.Load() {
		return true
	}

	// Drain window: within DrainGrace of the context's deadline, schedule no
	// new state. The crawl returns while its in-flight navigation and the
	// capture writer can still finish, instead of being cut off mid-page by the
	// deadline itself.
	if grace := c.config.DrainGrace; grace > 0 {
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= grace {
			zap.L().Debug("Within the drain grace of the deadline, terminating",
				zap.Duration("grace", grace))
			return true
		}
	}
	// DOM-XSS lead (MISS-29c): the probe runs after the crawl, on what is left
	// of the deadline — at most the drain grace, often seconds. When the
	// prefilter already has reflected candidates, stop scheduling states early
	// enough to leave the probe min(domXssBudget, MaxDuration/10).
	if deadline, ok := ctx.Deadline(); ok {
		if lead := c.domXssLead(); lead > 0 && time.Until(deadline) <= c.config.DrainGrace+lead && c.domXssCandidatesPending() {
			zap.L().Debug("Leaving the DOM-XSS probe its budget, terminating",
				zap.Duration("lead", lead))
			return true
		}
	}

	// Check max duration. This is a backstop: the caller normally enforces the
	// budget via a context deadline (which also propagates into browser ops via
	// the bound page context), but checking elapsed time here makes MaxDuration
	// meaningful even when the caller passes a context without a deadline, and
	// guarantees the loop stops promptly at the boundary regardless. The drain
	// grace applies here too.
	if c.config.MaxDuration > 0 {
		c.mu.Lock()
		start := c.stats.StartTime
		c.mu.Unlock()
		if !start.IsZero() {
			lead := time.Duration(0)
			if l := c.domXssLead(); l > 0 && time.Since(start) >= c.config.MaxDuration-c.config.DrainGrace-l && c.domXssCandidatesPending() {
				lead = l
			}
			if elapsed := time.Since(start); elapsed >= c.config.MaxDuration-c.config.DrainGrace-lead {
				zap.L().Debug("Max duration reached, terminating",
					zap.Duration("elapsed", elapsed),
					zap.Duration("max", c.config.MaxDuration))
				return true
			}
		}
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

	// Check max consecutive failures. The streak is crawl-wide: every tab's
	// failure extends it and any tab's success resets it.
	if c.config.MaxConsecutiveFails > 0 {
		consecutiveFails := int(c.consecutiveFails.Load())
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
