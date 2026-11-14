package crawler

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/metrics"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// checkAllConditionsSatisfied checks if all conditions are satisfied for an element.
func (c *Crawler) checkAllConditionsSatisfied(page *browser.Page, element *action.CandidateElement) bool {
	// Check page-level crawl conditions first
	if !c.shouldCrawl(page) {
		return false
	}

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
// Returns (newActionsCount, filledFormInputs, error) where:
// - newActionsCount is the number of new actions discovered
// - filledFormInputs are the form inputs that were filled (for caching in candidates)
func (c *Crawler) executeActionWithEventable(ctx context.Context, w *tabWorker, crawlAction *action.CandidateCrawlAction, eventable *action.Eventable) (newActionsCount int, filledInputs []*action.FormInput, err error) {
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

	// The interaction policy is checked before anything is filled or clicked.
	if err := c.checkSubmitPermitted(candidate, eventType); err != nil {
		return 0, nil, err
	}

	if c.browser == nil {
		return 0, nil, fmt.Errorf("crawler browser not initialized")
	}
	page := w.page
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

	//   1. List<FormInput> available = getInputElements(event);  // merge related + DOM
	//   2. List<FormInput> handled = formHandler.handleFormElements(available);  // fill
	//   3. candidateActionCache.mapInput(event, handled);  // cache (done in caller)
	shouldDisableInputs := c.candidates.ShouldDisableInputForAction(crawlAction)
	if c.config.FormFillEnabled && !shouldDisableInputs {
		// 1. eventable.getRelatedFormInputs() (inputs linked from CandidateElement)
		// 2. formHandler.getFormInputs() (all inputs on current DOM)
		filledInputs = c.handleInputElements(w, targetPage, eventable)
	} else if shouldDisableInputs {
		zap.L().Debug("Form inputs disabled for this action (retry without inputs)")
	}

	// Execute the action using identification selector
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
		} else if submitLikeCandidate(candidate) {
			c.countSubmitDispatched(submitMechClick, 1)
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
		c.countSubmitDispatched(submitMechEnter, 1)
	default:
		return 0, nil, fmt.Errorf("unknown event type: %s", eventType)
	}

	// Wait after action
	zap.L().Debug("Waiting after action", zap.Duration("wait_time", c.config.WaitAfterEvent))
	if err := sleepWithContext(ctx, c.config.WaitAfterEvent); err != nil {
		return 0, nil, err
	}

	_ = page.HandlePopups()

	// Popups opened by this action get a bounded moment to load — their
	// requests are captured browser-wide — and their in-scope URLs are kept
	// for the caller to crawl, before CloseOtherWindows closes them.
	c.recordPopups(c.browser.PopupURLs(page, popupLoadWait))

	// This is CRITICAL for target="_blank" and window.open() links. The crawl's
	// other tabs are not popups: they are kept.
	if err := c.browser.CloseOtherWindows(c.extraTabPages()...); err != nil {
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

	zap.L().Debug("Inspecting new state after action")
	newActionsCount = c.inspectNewState(ctx, w, page, eventable)

	return newActionsCount, filledInputs, nil
}

// inspectNewState checks if the DOM changed after an action and handles new/clone states.
// Returns the number of new actions discovered (for MAB reward and metrics).
// The eventable parameter is the FIRED eventable with correct ID (including DUPLICATE_EVENT_SEED).
func (c *Crawler) inspectNewState(ctx context.Context, w *tabWorker, page *browser.Page, eventable *action.Eventable) int {
	_ = page.HandlePopups()

	currentState := w.stateMachine.GetCurrentState()

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

	// Wait out an in-progress render before snapshotting. The snapshot decides
	// whether this is a new state at all, so a half-rendered DOM here compares as
	// a duplicate of the state we came from and the route is discarded — the
	// settle that runs further down would never be reached. Gated on cheap
	// signals, so a click that changed nothing costs nothing.
	settled := c.settleBeforeCapture(ctx, page, currentState.URL)

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

	if eventable.ID <= 0 {
		zap.L().Warn("Adding Eventable to Crawlpath has id less than zero", zap.Int64("id", eventable.ID))
	}
	w.crawlPath.Add(eventable)

	// This handles: AddState (putIfAbsent), AddEdge, and ChangeState all in one call.
	existingState, isClone, graphEdge := w.stateMachine.SwitchToStateAndCheckIfClone(newState, eventable)
	if isClone {
		// Clone state detected
		zap.L().Debug("State already exists (clone detected)",
			zap.String("state", existingState.Name),
			zap.String("state_id", existingState.ID))

		// When addEdge detects a duplicate, it sets eventable.ID = -1 and returns
		// the pre-existing graph edge. We must fix the crawlPath by replacing the
		// clone edge with that real graph edge.
		//
		// The edge comes back from the state machine rather than being searched
		// for: this branch is the common case in a crawl (revisiting a known
		// state), and scanning c.graph.AllEdges() to re-find an edge AddEdge just
		// returned costs a full materialization of every edge in the graph plus an
		// Equals per edge, growing with the graph on every duplicate transition.
		if eventable.ID == -1 {
			zap.L().Debug("Removing Clone Edge from crawlPath")
			w.crawlPath.RemoveLast()

			replacement := eventable // fallback: re-add the original eventable
			if graphEdge != nil && graphEdge != eventable {
				replacement = graphEdge
				zap.L().Debug("CrawlPath fixed with existing graph edge", zap.Int64("edge_id", graphEdge.ID))
			} else {
				zap.L().Debug("Crawlpath could not be fixed with graph, using removed eventable")
			}
			w.crawlPath.Add(replacement)
		}

		c.candidates.RediscoveredState(existingState.ID)
		if c.graph.RestoreState(existingState.ID) {
			zap.L().Debug("Restored expired state and its incoming edges", zap.String("state_id", existingState.ID))
		}

		c.mu.Lock()
		c.stats.StatesDuplicate++
		c.mu.Unlock()
		return 0
	}

	// New state discovered!
	zap.L().Debug("New state discovered", zap.String("state", newState.Name), zap.Int("depth", newState.Depth))
	c.candidates.RecordStateCreation(newState.ID)

	// Harvest iframe sources mounted in this newly reached state — a click/form
	// (e.g. opening a registration step) can inject a frame whose URL the served
	// HTML never contained. Deduped across the crawl so a recurring frame is
	// fetched once.
	c.primeIframeAssets(ctx, page)

	// A login form can surface anywhere mid-crawl (a "Sign in" link, a gated
	// section). If this newly reached state is a confirmed local login form, try
	// common credentials once per host (when the policy permits) so the crawl can
	// continue into the now-unlocked area.
	c.attemptLoginCredentials(ctx, page)

	// RLCRAWLER PARITY: Register new state with MAB policy
	if c.mabPolicy != nil {
		c.mabPolicy.AddState(newState.ID)
	}
	c.mu.Lock()
	c.stats.StatesDiscovered++
	c.mu.Unlock()
	zap.L().Debug("Current state updated to new state", zap.String("state_id", newState.ID))

	// Let this newly reached state settle and (if it has content below the fold)
	// scroll to trigger lazy loads BEFORE extracting its fragments/actions, so a
	// deep SPA route contributes its lazy content and data fetches instead of just
	// its above-the-fold shell. The pre-snapshot settle above already quiesced the
	// page on a navigating action, so this skips its own wait in that case.
	c.settleNewState(ctx, page, settled)

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
	w.extractor.SetCurrentState(newState.ID)
	actions, err := w.extractor.Extract(ctx, page)
	if err != nil {
		zap.L().Debug("Failed to extract actions", zap.Error(err))
		return 0
	}

	c.candidates.AddActions(actions, newState.ID)
	added := len(actions)
	zap.L().Debug("Extracted actions from state", zap.Int("count", added), zap.String("state", newState.Name))

	// NOTE: Frame extraction is already handled by w.extractor.Extract() which
	// recursively processes frames with correct framePath. No separate call needed.

	// Submit any GET forms this newly reached state introduced (a per-route search
	// or filter box), deduped across the crawl so a form present on every page is
	// only fetched once. This state's forms weren't pre-filled, so submitGetForms
	// fills them.
	c.submitGetForms(ctx, page, false)

	// Trigger any POST forms this state introduced (a per-route stock/quote/action
	// form), deduped across the crawl. submitGetForms above just filled the page's
	// forms, so skip a repeat fill.
	c.submitPostForms(ctx, page, true)

	// Fetch any parameterized <a href> links this state introduced (client-rendered
	// category/filter/pagination links), deduped + per-shape capped across the crawl.
	c.primeAnchorLinks(ctx, page)

	// Scrape this state's own comments and inline script for URL-like strings. A
	// route reached mid-crawl frequently injects its own config/endpoint block
	// (a per-section API base, a feature-flagged admin path) that the landing
	// page never carried.
	c.harvestSpeculativeLinks(ctx, page)

	return added
}

// checkOnURLState checks DOM after URL reload and handles state changes.
// 1. newState = stateMachine.newStateFor(browser)
// 2. clone = stateFlowGraph.putIfAbsent(newState)
// 3. if (clone == null): setCurrentState(newState), add to onURLSet
// 4. else: setCurrentState(clone), add clone to onURLSet if not index
// 5. Always try to add reload edge (graph handles duplicate)
func (c *Crawler) checkOnURLState(ctx context.Context, w *tabWorker, page *browser.Page, previousState *state.State, resetURL string) {
	// Same reason as inspectNewState: this DOM read mints a state identity, so it
	// must not be taken while the reloaded page is still rendering. This path
	// always follows an explicit navigation, so there is no URL to compare
	// against — passing none makes the busy probe the sole gate, which is what
	// keeps a once-per-crawl-loop-iteration call from settling unconditionally.
	c.settleBeforeCapture(ctx, page, "")

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

	// Strip DOM for comparison via the comparator so this state's identity uses
	// the exact same stripping + volatile-content normalization as every other
	// state (otherwise a clock/nonce here would still mint a fresh state, and a
	// config-customized strip set would be ignored on this path).
	strippedDOM := c.comparator.PrepareForComparison(combinedDOM)
	currentURL, _ := page.URL()

	newState := state.New(currentURL, combinedDOM, strippedDOM, 1)
	// Marked before the insert: once in the graph the state is visible to the
	// other tabs, and a later write would race their reads. A clone discards
	// this copy, so the mark only sticks on a state this call adds.
	newState.SetOnURL(true)

	// checkOnURLState does NOT use switchToStateAndCheckIfClone — it's a direct
	// putIfAbsent, atomic against another tab capturing the same DOM.
	canonical, isNew := c.graph.PutIfAbsent(newState)

	if isNew {
		// NEW STATE discovered after URL reload!
		c.candidates.RecordStateCreation(newState.ID)

		// RLCRAWLER PARITY: Register new state with MAB policy
		if c.mabPolicy != nil {
			c.mabPolicy.AddState(newState.ID)
		}

		w.stateMachine.SetCurrentState(newState)

		w.stateMachine.AddToOnURLSet(newState)

		zap.L().Debug("checkOnURLState: NEW state discovered after reload", zap.String("state", newState.Name))

		w.extractor.SetCurrentState(newState.ID)
		actions, err := w.extractor.Extract(ctx, page)
		if err == nil && len(actions) > 0 {
			c.candidates.AddActions(actions, newState.ID)
			zap.L().Debug("Extracted actions from new onURL state",
				zap.Int("count", len(actions)),
				zap.String("state", newState.Name))
		}

		c.mu.Lock()
		c.stats.StatesDiscovered++
		c.mu.Unlock()
	} else {
		// EXISTING STATE (clone)
		existingState := canonical

		w.stateMachine.SetCurrentState(existingState)

		//                         if (!onURLSet.contains(clone)) onURLSet.add(clone)
		if existingState.Name != "index" {
			w.stateMachine.AddToOnURLSet(existingState)
			zap.L().Debug("checkOnURLState: index has changed to", zap.String("state", existingState.Name))
		}
	}

	// Graph.AddEdge() handles duplicate detection via Eventable.Equals()
	if previousState != nil {
		currentState := w.stateMachine.GetCurrentState()
		if currentState != nil {
			c.graph.AddEdge(previousState.ID, currentState.ID, action.NewReloadEventable(resetURL))
			zap.L().Debug("Added reload edge",
				zap.String("from", previousState.Name),
				zap.String("to", currentState.Name))
		}
	}
}

// addFinalReloadEdge adds a reload edge from current state to index when crawl finishes.
// If reset() was called at least once, all intermediate states already have reload edges.
// The final leaf state does NOT get a reload edge because the crawl just terminates.
func (c *Crawler) addFinalReloadEdge(w *tabWorker) {
	// This handles simple DFS crawls (like SimpleInputSite: index → state, end).
	// For complex crawls where reset() was called, reload edges are already added during processing.
	if w == nil || w.resetCalled || w.stateMachine == nil {
		return
	}

	indexState := c.graph.GetIndexState()
	currentState := w.stateMachine.GetCurrentState()
	if indexState == nil || currentState == nil {
		return
	}
	// Only add if we're not already at index
	if currentState.ID == indexState.ID {
		return
	}
	resetURL := c.config.URL.String()
	c.graph.AddEdge(currentState.ID, indexState.ID, action.NewReloadEventable(resetURL))
	zap.L().Debug("Added final reload edge", zap.String("from", currentState.Name), zap.String("to", indexState.Name))
}

// captureState captures the current page state.
// into the DOM so that state changes within iframes are detected.
func (c *Crawler) captureState(ctx context.Context, page *browser.Page, depth int) (*state.State, error) {
	url, err := page.URL()
	if err != nil {
		return nil, err
	}

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

// recordMetrics records step metrics to the metrics collector.
// Called only when metricsCollector is set (benchmark mode).
func (c *Crawler) recordMetrics(w *tabWorker, crawlAction *action.CandidateCrawlAction, succeeded, stateDiscovered, formSubmitted bool, newActionsCount int) {
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
	if page := w.page; page != nil {
		ctx.NewLinks = c.extractLinksFromPage(page)
	}

	// Record to collector
	if err := c.metricsCollector.OnStepComplete(ctx); err != nil {
		zap.L().Warn("Failed to record metrics", zap.Error(err))
	}
}

// popupLoadWait bounds how long a popup may load before it is closed.
const popupLoadWait = 2 * time.Second

// maxPopupURLs caps Stats.PopupURLs.
const maxPopupURLs = 200

// recordPopups keeps in-scope popup URLs (deduped, capped) in Stats.PopupURLs.
func (c *Crawler) recordPopups(urls []string) {
	if len(urls) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, u := range urls {
		if !c.inScopeURL(u) || len(c.stats.PopupURLs) >= maxPopupURLs || slices.Contains(c.stats.PopupURLs, u) {
			continue
		}
		c.stats.PopupURLs = append(c.stats.PopupURLs, u)
	}
}
