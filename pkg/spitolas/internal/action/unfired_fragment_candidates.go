// Package action provides web crawling action types and handling.
package action

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// stateQueue is an unbounded blocking queue for state IDs.
type stateQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []string
	closed bool
}

func newStateQueue() *stateQueue {
	q := &stateQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// Add appends a state ID to the queue and signals one waiter.
func (q *stateQueue) Add(stateID string) {
	q.mu.Lock()
	q.items = append(q.items, stateID)
	q.mu.Unlock()
	q.cond.Signal()
}

// Take blocks until a state ID is available or context is cancelled.
func (q *stateQueue) Take(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Watch for context cancellation
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			q.cond.Broadcast()
		case <-stopWatch:
		}
	}()

	for len(q.items) == 0 && !q.closed {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		q.cond.Wait()
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	if q.closed && len(q.items) == 0 {
		return "", fmt.Errorf("queue closed")
	}

	item := q.items[0]
	q.items = q.items[1:]
	return item, nil
}

// RemoveAll removes all occurrences of stateID from the queue.
// Returns the number of items removed.
func (q *stateQueue) RemoveAll(stateID string) int {
	q.mu.Lock()
	defer q.mu.Unlock()

	removed := 0
	filtered := make([]string, 0, len(q.items))
	for _, id := range q.items {
		if id == stateID {
			removed++
		} else {
			filtered = append(filtered, id)
		}
	}
	q.items = filtered
	return removed
}

// Contains checks if a state ID is in the queue.
func (q *stateQueue) Contains(stateID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, id := range q.items {
		if id == stateID {
			return true
		}
	}
	return false
}

// Snapshot returns a copy of all items currently in the queue.
func (q *stateQueue) Snapshot() []string {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := make([]string, len(q.items))
	copy(result, q.items)
	return result
}

// Close closes the queue, waking all waiters.
func (q *stateQueue) Close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

// DefaultMaxRepeat is the default maximum times an explored action can be repeated.
const DefaultMaxRepeat = 2

// FragmentPrioritizer interface for fragment-based prioritization.
// This is used to avoid import cycle with fragment package.
type FragmentPrioritizer interface {
	// CalculateCandidateInfluence calculates the influence score for a candidate element.
	CalculateCandidateInfluence(element *CandidateElement) float64

	// CalculateDuplicationFactor calculates the duplication factor for a candidate element.
	CalculateDuplicationFactor(element *CandidateElement, stateID string) float64

	// GetClosestUnexploredState returns the closest state with unexplored actions.
	// Returns empty string if no unexplored states found.
	GetClosestUnexploredState(currentStateID string, onURLSet map[string]bool, statesWithCandidates []string, applyNonSelAdvantage bool) string

	// SetAccess sets access for the state's root fragment.
	SetAccess(stateID string)

	// SeenState marks a state as seen for prioritization.
	SeenState(stateID string)
}

// StateProvider interface to get state information.
// This is used to avoid import cycle with state package.
type StateProvider interface {
	// GetByID returns a state by its ID.
	GetByID(id string) interface{}

	// GetOutgoingStates returns IDs of states connected via outgoing edges.
	GetOutgoingStates(stateID string) []string

	// HasNearDuplicate returns true if a state has a near-duplicate.
	HasNearDuplicate(stateID string) bool
}

// MABPolicy interface for Multi-Armed Bandit action selection.
// This is used to avoid import cycle with mab package.
type MABPolicy interface {
	// AddState adds a new state to the policy.
	AddState(stateID string)

	// AddAction adds a new action to a state.
	AddAction(stateID, actionID string)

	// RemoveAction removes an executed action from a state (for click-once semantics).
	RemoveAction(stateID, actionID string)

	// GetProbability returns the probability for an action in a state.
	GetProbability(stateID, actionID string) float64

	// SelectAction selects an action based on probabilities.
	SelectAction(stateID string, availableActionIDs []string) string
}

// UnfiredFragmentCandidates contains all CandidateCrawlActions that still have to be fired.
type UnfiredFragmentCandidates struct {
	mu sync.RWMutex

	// Main cache: stateID -> list of unfired actions.
	cache map[string][]*CandidateCrawlAction

	// Unbounded blocking queue for state IDs with pending actions.
	statesWithCandidates *stateQueue

	// Unreachable cache: actions that were purged but can be restored.
	unreachableCache map[string][]*CandidateCrawlAction

	// Form input caching.
	inputMap map[int64][]*FormInput

	// Actions to skip inputs for (by action).
	skipInputs map[*CandidateCrawlAction]bool

	// Eventables to skip inputs for (by eventable ID).
	skipInputsForPath map[int64]bool

	// Configuration.
	skipExploredActions bool

	maxRepeat int

	applyNonSelAdvantage bool

	restoreConnectedEdges bool

	unexploredStates bool

	// Consumer state tracking.
	runningConsumers int32
	pendingStates    int32

	// State flow graph provider for state lookups.
	stateProvider StateProvider

	// Metrics counters.
	crawlerLostCount    int64
	unfiredActionsCount int64

	// Lock for consumer state.
	consumersLock sync.RWMutex

	// Closed flag.
	closed bool

	// MAB policy for adaptive action selection (MAK strategy).
	mabPolicy MABPolicy
}

// UnfiredFragmentCandidatesConfig holds configuration for UnfiredFragmentCandidates.
type UnfiredFragmentCandidatesConfig struct {
	MaxRepeat             int
	SkipExploredActions   bool
	ApplyNonSelAdvantage  bool
	RestoreConnectedEdges bool
}

// DefaultUnfiredFragmentCandidatesConfig returns default configuration.
func DefaultUnfiredFragmentCandidatesConfig() *UnfiredFragmentCandidatesConfig {
	return &UnfiredFragmentCandidatesConfig{
		MaxRepeat:             DefaultMaxRepeat,
		SkipExploredActions:   true,
		ApplyNonSelAdvantage:  false,
		RestoreConnectedEdges: false,
	}
}

// NewUnfiredFragmentCandidates creates a new UnfiredFragmentCandidates.
func NewUnfiredFragmentCandidates(config *UnfiredFragmentCandidatesConfig, stateProvider StateProvider) *UnfiredFragmentCandidates {
	if config == nil {
		config = DefaultUnfiredFragmentCandidatesConfig()
	}

	return &UnfiredFragmentCandidates{
		cache:                 make(map[string][]*CandidateCrawlAction),
		statesWithCandidates:  newStateQueue(),
		unreachableCache:      make(map[string][]*CandidateCrawlAction),
		inputMap:              make(map[int64][]*FormInput),
		skipInputs:            make(map[*CandidateCrawlAction]bool),
		skipInputsForPath:     make(map[int64]bool),
		skipExploredActions:   config.SkipExploredActions,
		maxRepeat:             config.MaxRepeat,
		applyNonSelAdvantage:  config.ApplyNonSelAdvantage,
		restoreConnectedEdges: config.RestoreConnectedEdges,
		unexploredStates:      true,
		stateProvider:         stateProvider,
	}
}

// getBestAction returns the best action using fragment-based prioritization.
func (u *UnfiredFragmentCandidates) getBestAction(
	availableActions []*CandidateCrawlAction,
	stateID string,
	fragmentManager FragmentPrioritizer,
) *CandidateCrawlAction {
	if fragmentManager != nil {
		fragmentManager.SetAccess(stateID)
	}

	unexploredActionFound := false
	maxInfluence := 0.0
	maxExploredInfluence := 0.0
	var bestExploredAction *CandidateCrawlAction
	var bestAction *CandidateCrawlAction

	for _, action := range availableActions {
		element := action.GetCandidateElement()

		// Skip if directAccess or equivalentAccess >= MAX_REPEAT
		if element.IsDirectAccess() || element.GetEquivalentAccess() >= u.maxRepeat {
			continue
		}

		// Skip explored actions if we already found unexplored ones
		if unexploredActionFound && element.WasExplored() {
			continue
		}

		// Calculate influence and duplication factor
		var influence, duplicationFactor float64
		if fragmentManager != nil {
			influence = fragmentManager.CalculateCandidateInfluence(element)
			duplicationFactor = fragmentManager.CalculateDuplicationFactor(element, stateID)
		} else {
			influence = 1.0
			duplicationFactor = 1.0
		}

		score := influence * duplicationFactor

		if !element.WasExplored() {
			unexploredActionFound = true
			if score > maxInfluence {
				maxInfluence = score
				bestAction = action
			}
		} else {
			if score > maxExploredInfluence {
				maxExploredInfluence = score
				bestExploredAction = action
			}
		}
	}

	if bestAction != nil {
		zap.L().Debug("Best action found (unexplored)", zap.Float64("influence", maxInfluence))
	} else if bestExploredAction != nil {
		zap.L().Debug("Best action found (explored)", zap.Float64("influence", maxExploredInfluence))
	}

	if bestAction != nil {
		return bestAction
	}
	return bestExploredAction
}

// PollActionOrNull polls the best action for a state.
// Returns (action, switchToStateID) where switchToStateID is non-empty if crawler should switch states.
func (u *UnfiredFragmentCandidates) PollActionOrNull(
	stateID string,
	onURLSet map[string]bool,
	fragmentManager FragmentPrioritizer,
	afterBacktrack bool,
) (*CandidateCrawlAction, string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	var bestStateID string
	var bestAction *CandidateCrawlAction

	zap.L().Debug("Polling action for state", zap.String("state_id", stateID))

	// Check if state was in unreachable cache and restore it
	if _, ok := u.unreachableCache[stateID]; ok {
		u.rediscoveredStateLocked(stateID)
	}

	queue := u.cache[stateID]
	if len(queue) == 0 {
		return nil, ""
	}

	// Get best action using prioritization
	bestAction = u.getBestAction(queue, stateID, fragmentManager)

	if bestAction != nil {
		element := bestAction.GetCandidateElement()

		if element.WasExplored() {
			// Found explored action as best - check if we should switch to unexplored state
			if u.unexploredStates && !afterBacktrack && fragmentManager != nil {
				// Get states with candidates as slice
				statesWithCandidates := u.getStatesWithCandidatesLocked()

				switchStateID := fragmentManager.GetClosestUnexploredState(
					stateID, onURLSet, statesWithCandidates, u.applyNonSelAdvantage)

				if switchStateID != "" && switchStateID != stateID {
					// Switch to unexplored state
					if u.skipExploredActions {
						zap.L().Debug("Best action explored, purging state and switching",
							zap.String("from", stateID), zap.String("to", switchStateID))
						u.cache[stateID] = nil
						delete(u.cache, stateID)
						u.removeStateFromQueueLocked(stateID)
					}
					return nil, switchStateID
				}
			} else {
				// No unexplored states or after backtrack
				zap.L().Debug("Element already explored",
					zap.Int("equivalent_access", element.GetEquivalentAccess()))
				bestStateID = stateID
			}
		} else {
			bestStateID = stateID
		}
	} else {
		// No actions available
		zap.L().Debug("No actions available, purging state", zap.String("state_id", stateID))
		u.cache[stateID] = nil
		delete(u.cache, stateID)
		return nil, ""
	}

	if bestAction != nil {
		// Remove action from queue
		u.removeActionFromQueueLocked(stateID, bestAction)

		// Check if we should skip and clear queue
		if (u.skipExploredActions && bestAction.GetCandidateElement().WasExplored()) ||
			(bestAction.GetCandidateElement().GetEquivalentAccess() >= u.maxRepeat) {
			zap.L().Debug("Best action explored, purging state", zap.String("state_id", stateID))
			u.cache[stateID] = nil
			delete(u.cache, stateID)
			u.removeStateFromQueueLocked(stateID)
			return nil, ""
		}
	}

	// Check if queue is empty after removal
	if len(u.cache[stateID]) == 0 {
		zap.L().Debug("All actions polled for state", zap.String("state_id", stateID))
		delete(u.cache, stateID)
		u.removeStateFromQueueLocked(stateID)
	}

	// Mark state as seen if we have a valid action
	if bestStateID != "" && bestAction != nil && fragmentManager != nil {
		fragmentManager.SeenState(bestStateID)
	}

	return bestAction, ""
}

// PollActionOrNullSimple polls action without prioritization (FIFO).
func (u *UnfiredFragmentCandidates) PollActionOrNullSimple(stateID string) *CandidateCrawlAction {
	u.mu.Lock()
	defer u.mu.Unlock()

	zap.L().Debug("Polling action for state (simple)", zap.String("state_id", stateID))

	queue := u.cache[stateID]
	if len(queue) == 0 {
		return nil
	}

	// FIFO - take first action
	action := queue[0]
	u.cache[stateID] = queue[1:]

	// Check if queue is empty
	if len(u.cache[stateID]) == 0 {
		zap.L().Debug("All actions polled for state", zap.String("state_id", stateID))
		delete(u.cache, stateID)
		u.removeStateFromQueueLocked(stateID)
	}

	return action
}

// GetNextNonDuplicate finds the next state in the queue that is not a near-duplicate.
// then consumes tasks from queue until reaching that state.
func (u *UnfiredFragmentCandidates) GetNextNonDuplicate(ctx context.Context) (string, error) {
	if u.stateProvider == nil {
		return "", fmt.Errorf("no state provider")
	}

	// Iterate queue snapshot to find first non-near-duplicate
	snapshot := u.statesWithCandidates.Snapshot()
	var nextUniqueID string
	for _, id := range snapshot {
		if !u.stateProvider.HasNearDuplicate(id) {
			nextUniqueID = id
			break
		}
	}

	if nextUniqueID == "" {
		return "", nil
	}

	// Consume tasks from queue until we reach the unique state
	for {
		stateID, err := u.statesWithCandidates.Take(ctx)
		if err != nil {
			return "", err
		}

		u.consumersLock.Lock()
		atomic.AddInt32(&u.runningConsumers, 1)
		atomic.AddInt32(&u.pendingStates, -1)
		u.consumersLock.Unlock()

		if stateID == nextUniqueID {
			return stateID, nil
		}
	}
}

// getStatesWithCandidatesLocked returns slice of state IDs with pending actions.
// Must be called with lock held.
func (u *UnfiredFragmentCandidates) getStatesWithCandidatesLocked() []string {
	result := make([]string, 0, len(u.cache))
	for stateID := range u.cache {
		if len(u.cache[stateID]) > 0 {
			result = append(result, stateID)
		}
	}
	return result
}

// removeActionFromQueueLocked removes a specific action from the queue.
// Must be called with lock held.
func (u *UnfiredFragmentCandidates) removeActionFromQueueLocked(stateID string, action *CandidateCrawlAction) {
	queue := u.cache[stateID]
	for i, a := range queue {
		if a == action {
			u.cache[stateID] = append(queue[:i], queue[i+1:]...)
			return
		}
	}
}

// removeStateFromQueueLocked removes ALL occurrences of a state from the queue.
// Must be called with lock held.
//
//	while(statesWithCandidates.remove(id)) { pendingStates--; }
func (u *UnfiredFragmentCandidates) removeStateFromQueueLocked(stateID string) {
	removed := u.statesWithCandidates.RemoveAll(stateID)
	if removed > 0 {
		atomic.AddInt32(&u.pendingStates, -int32(removed))
		zap.L().Debug("Removed state from queue",
			zap.String("state_id", stateID),
			zap.Int("removed_count", removed),
			zap.Int32("pending_states", atomic.LoadInt32(&u.pendingStates)))
	}
}

// RediscoveredState handles a rediscovered state (public API).
// Called from Crawler.inspectNewState() when a clone state is detected.
func (u *UnfiredFragmentCandidates) RediscoveredState(stateID string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rediscoveredStateLocked(stateID)
}

// rediscoveredStateLocked handles a rediscovered state.
// Must be called with lock held.
func (u *UnfiredFragmentCandidates) rediscoveredStateLocked(stateID string) {
	u.restoreStateLocked(stateID)

	if u.restoreConnectedEdges && u.stateProvider != nil {
		connectedStates := u.stateProvider.GetOutgoingStates(stateID)
		for _, connectedID := range connectedStates {
			zap.L().Debug("Restoring connected state",
				zap.String("connected", connectedID),
				zap.String("rediscovered", stateID))
			u.restoreStateLocked(connectedID)
		}
	}
}

// restoreStateLocked restores a state from unreachable cache.
// Must be called with lock held.
func (u *UnfiredFragmentCandidates) restoreStateLocked(stateID string) {
	removed, ok := u.unreachableCache[stateID]
	if !ok || len(removed) == 0 {
		return
	}

	zap.L().Debug("Restoring state from unreachable cache",
		zap.String("state_id", stateID),
		zap.Int("actions", len(removed)))

	// Add back to cache
	u.cache[stateID] = append(u.cache[stateID], removed...)
	atomic.AddInt64(&u.unfiredActionsCount, -int64(len(removed)))
	delete(u.unreachableCache, stateID)

	// Check if state has unexplored actions
	hasUnexplored := false
	for _, action := range u.cache[stateID] {
		if !action.GetCandidateElement().WasExplored() {
			hasUnexplored = true
			break
		}
	}

	if hasUnexplored && !u.unexploredStates {
		zap.L().Debug("Unexplored states available again", zap.String("state_id", stateID))
		u.unexploredStates = true
	}

	// Signal state has candidates
	u.addPendingStateLocked(stateID)
}

// addPendingStateLocked adds a state to the pending queue.
// Must be called with lock held.
// Uses unbounded queue — never drops states.
func (u *UnfiredFragmentCandidates) addPendingStateLocked(stateID string) {
	atomic.AddInt32(&u.pendingStates, 1)
	u.statesWithCandidates.Add(stateID)
	zap.L().Debug("Added state to queue",
		zap.String("state_id", stateID),
		zap.Int32("pending_states", atomic.LoadInt32(&u.pendingStates)))
}

// AddActions adds candidate elements for a state.
func (u *UnfiredFragmentCandidates) AddActions(candidates []*CandidateElement, stateID string) {
	if len(candidates) == 0 {
		zap.L().Debug("Received empty candidates list, ignoring")
		return
	}

	actions := make([]*CandidateCrawlAction, len(candidates))
	for i, candidate := range candidates {
		actions[i] = NewCandidateCrawlAction(candidate, candidate.GetEventType())
	}

	u.AddCrawlActions(actions, stateID)
}

// AddCrawlActions adds crawl actions for a state.
func (u *UnfiredFragmentCandidates) AddCrawlActions(actions []*CandidateCrawlAction, stateID string) {
	if len(actions) == 0 {
		zap.L().Debug("Received empty actions list, ignoring")
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	zap.L().Debug("Adding crawl actions",
		zap.Int("count", len(actions)),
		zap.String("state_id", stateID))

	if existing, ok := u.cache[stateID]; ok {
		u.cache[stateID] = append(existing, actions...)
	} else {
		u.cache[stateID] = actions
	}

	u.addPendingStateLocked(stateID)
}

// ReAddAction re-adds a single action back to the queue for retry.
//
//	boolean added = candidateActionCache.disableInputsForAction(action);
//	if (added) {
//	    List<CandidateCrawlAction> actions = new ArrayList<>();
//	    actions.add(action);
//	    candidateActionCache.addActions(actions, stateMachine.getCurrentState());
//	}
func (u *UnfiredFragmentCandidates) ReAddAction(action *CandidateCrawlAction, stateID string) {
	if action == nil {
		return
	}
	u.AddCrawlActions([]*CandidateCrawlAction{action}, stateID)
	zap.L().Debug("Re-added action for retry without form inputs",
		zap.String("state_id", stateID),
		zap.String("xpath", action.GetCandidateElement().GetIdentification().Value))
}

// IsEmpty returns true if there are no pending actions.
func (u *UnfiredFragmentCandidates) IsEmpty() bool {
	u.consumersLock.RLock()
	running := atomic.LoadInt32(&u.runningConsumers)
	pending := atomic.LoadInt32(&u.pendingStates)
	u.consumersLock.RUnlock()

	empty := running == 0 && pending == 0

	zap.L().Debug("isEmpty check",
		zap.Bool("empty", empty),
		zap.Int32("running_consumers", running),
		zap.Int32("pending_states", pending))

	return empty
}

// AwaitNewTask blocks until a state with pending actions is available.
func (u *UnfiredFragmentCandidates) AwaitNewTask(ctx context.Context) (string, error) {
	stateID, err := u.statesWithCandidates.Take(ctx)
	if err != nil {
		return "", err
	}

	u.consumersLock.Lock()
	atomic.AddInt32(&u.runningConsumers, 1)
	atomic.AddInt32(&u.pendingStates, -1)
	zap.L().Debug("Consumed task",
		zap.String("state_id", stateID),
		zap.Int32("running_consumers", atomic.LoadInt32(&u.runningConsumers)),
		zap.Int32("pending_states", atomic.LoadInt32(&u.pendingStates)))
	u.consumersLock.Unlock()
	return stateID, nil
}

// TaskDone indicates that a task is done.
func (u *UnfiredFragmentCandidates) TaskDone(stateID string) {
	u.consumersLock.Lock()
	defer u.consumersLock.Unlock()

	atomic.AddInt32(&u.runningConsumers, -1)

	u.mu.RLock()
	queue := u.cache[stateID]
	hasMore := len(queue) > 0
	u.mu.RUnlock()

	if hasMore {
		u.mu.Lock()
		u.addPendingStateLocked(stateID)
		u.mu.Unlock()
	}

	zap.L().Debug("Task done",
		zap.String("state_id", stateID),
		zap.Int32("running_consumers", atomic.LoadInt32(&u.runningConsumers)),
		zap.Int32("pending_states", atomic.LoadInt32(&u.pendingStates)))
}

// PurgeActionsForState removes all actions for a state and moves to unreachable cache.
func (u *UnfiredFragmentCandidates) PurgeActionsForState(stateID string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	zap.L().Debug("Purging actions for state", zap.String("state_id", stateID))

	u.removeStateFromQueueLocked(stateID)
	removed := u.cache[stateID]
	delete(u.cache, stateID)

	if len(removed) > 0 {
		atomic.AddInt64(&u.unfiredActionsCount, int64(len(removed)))
		zap.L().Debug("Moving purged actions to unreachable cache",
			zap.String("state_id", stateID),
			zap.Int("count", len(removed)))
		u.unreachableCache[stateID] = removed
	}

	atomic.AddInt64(&u.crawlerLostCount, 1)
}

// StateUpdated handles a state being updated.
func (u *UnfiredFragmentCandidates) StateUpdated(stateID string) {
	zap.L().Debug("Purging actions for updated state", zap.String("state_id", stateID))
	u.PurgeActionsForState(stateID)
}

// RemoveAction removes a specific candidate element from a state's queue.
func (u *UnfiredFragmentCandidates) RemoveAction(candidate *CandidateElement, stateID string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if _, ok := u.unreachableCache[stateID]; ok {
		u.rediscoveredStateLocked(stateID)
	}

	if !u.statesWithCandidates.Contains(stateID) {
		return
	}

	queue := u.cache[stateID]
	if queue == nil {
		return
	}

	// Go pointer comparison is the equivalent.
	var toRemove *CandidateCrawlAction
	for _, action := range queue {
		if action.GetCandidateElement() == candidate {
			toRemove = action
			break
		}
	}

	if toRemove != nil {
		u.removeActionFromQueueLocked(stateID, toRemove)
	}

	if len(u.cache[stateID]) == 0 {
		zap.L().Debug("All actions removed for state", zap.String("state_id", stateID))
		delete(u.cache, stateID)
		u.removeStateFromQueueLocked(stateID)
	}
}

// Form input caching methods

// MapInput stores worked form inputs for an eventable.
func (u *UnfiredFragmentCandidates) MapInput(event *Eventable, worked []*FormInput) {
	u.mu.Lock()
	defer u.mu.Unlock()

	zap.L().Debug("Mapping worked inputs",
		zap.Int64("event_id", event.ID),
		zap.Int("count", len(worked)))

	event.SetRelatedFormInputs(worked)
	u.inputMap[event.ID] = worked
}

// GetInput returns cached form inputs for an eventable.
func (u *UnfiredFragmentCandidates) GetInput(event *Eventable) []*FormInput {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.inputMap[event.ID]
}

// DisableInputsForAction marks an action to skip form inputs.
func (u *UnfiredFragmentCandidates) DisableInputsForAction(action *CandidateCrawlAction) bool {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.skipInputs[action] {
		return false
	}
	u.skipInputs[action] = true
	return true
}

// ShouldDisableInputForAction checks if form inputs should be skipped for an action.
func (u *UnfiredFragmentCandidates) ShouldDisableInputForAction(action *CandidateCrawlAction) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.skipInputs[action]
}

// DisableInputsForPath marks an eventable to skip form inputs.
func (u *UnfiredFragmentCandidates) DisableInputsForPath(event *Eventable) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.skipInputsForPath[event.ID] {
		return
	}

	zap.L().Debug("Disabling related inputs for eventable",
		zap.Int64("event_id", event.ID),
		zap.Int("inputs_before", len(event.RelatedFormInputs)))

	event.SetRelatedFormInputs(make([]*FormInput, 0))
	u.skipInputsForPath[event.ID] = true

	zap.L().Debug("Disabled inputs",
		zap.Int64("event_id", event.ID),
		zap.Int("inputs_after", len(event.RelatedFormInputs)))
}

// ShouldDisableInputForPath checks if form inputs should be skipped for an eventable.
func (u *UnfiredFragmentCandidates) ShouldDisableInputForPath(event *Eventable) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.skipInputsForPath[event.ID]
}

// Statistics and utility methods

// GetCacheSize returns the number of states with pending actions.
func (u *UnfiredFragmentCandidates) GetCacheSize() int {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return len(u.cache)
}

// GetTotalPendingActions returns the total number of pending actions across all states.
func (u *UnfiredFragmentCandidates) GetTotalPendingActions() int {
	u.mu.RLock()
	defer u.mu.RUnlock()

	total := 0
	for _, actions := range u.cache {
		total += len(actions)
	}
	return total
}

// GetUnreachableCount returns the number of actions in unreachable cache.
func (u *UnfiredFragmentCandidates) GetUnreachableCount() int {
	u.mu.RLock()
	defer u.mu.RUnlock()

	total := 0
	for _, actions := range u.unreachableCache {
		total += len(actions)
	}
	return total
}

// GetCrawlerLostCount returns the crawler lost counter.
func (u *UnfiredFragmentCandidates) GetCrawlerLostCount() int64 {
	return atomic.LoadInt64(&u.crawlerLostCount)
}

// GetUnfiredActionsCount returns the unfired actions counter.
func (u *UnfiredFragmentCandidates) GetUnfiredActionsCount() int64 {
	return atomic.LoadInt64(&u.unfiredActionsCount)
}

// GetPendingForState returns pending actions for a specific state.
func (u *UnfiredFragmentCandidates) GetPendingForState(stateID string) []*CandidateCrawlAction {
	u.mu.RLock()
	defer u.mu.RUnlock()

	actions := u.cache[stateID]
	result := make([]*CandidateCrawlAction, len(actions))
	copy(result, actions)
	return result
}

// HasPendingForState returns true if a state has pending actions.
func (u *UnfiredFragmentCandidates) HasPendingForState(stateID string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return len(u.cache[stateID]) > 0
}

// Close closes the candidates manager.
func (u *UnfiredFragmentCandidates) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.closed {
		u.closed = true
		u.statesWithCandidates.Close()
	}
}

// IsClosed returns true if closed.
func (u *UnfiredFragmentCandidates) IsClosed() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.closed
}

// SetUnexploredStates sets the unexploredStates flag.
func (u *UnfiredFragmentCandidates) SetUnexploredStates(value bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.unexploredStates = value
}

// HasUnexploredStates returns the unexploredStates flag.
func (u *UnfiredFragmentCandidates) HasUnexploredStates() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.unexploredStates
}

// Stats represents queue statistics.
type Stats struct {
	TotalPending int
	TotalSeen    int
}

// Stats returns queue statistics.
func (u *UnfiredFragmentCandidates) Stats() Stats {
	u.mu.RLock()
	defer u.mu.RUnlock()

	pending := u.GetTotalPendingActions()
	return Stats{
		TotalPending: len(u.cache),
		TotalSeen:    pending,
	}
}

// RecordStateCreation records when a state was created (for OLDEST_FIRST mode).
// Discovery order is already captured by the statesWithCandidates FIFO queue
// (a state is enqueued when its actions are added), which PollStateByPriority
// selects from — so this needs no separate bookkeeping and stays a no-op.
func (u *UnfiredFragmentCandidates) RecordStateCreation(stateID string) {
	// No-op: statesWithCandidates already preserves discovery order.
}

// PollStateByPriority polls the next state to work on based on crawl strategy.
// Returns empty string if no states available.
// Note: strategy is interface{} to avoid import cycle with config package.
func (u *UnfiredFragmentCandidates) PollStateByPriority(strategy interface{}) string {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Select in the deterministic order states were discovered — the FIFO
	// statesWithCandidates queue — NOT Go's randomized map iteration. The old
	// map-range made state scheduling nondeterministic (a different order every
	// run) and silently ignored the configured strategy; FIFO gives the BFS-style
	// progression "normal"/"oldest_first" intend, while adaptive/MAB still drives
	// ACTION selection within a state via PollByMode.
	for _, stateID := range u.statesWithCandidates.Snapshot() {
		if len(u.cache[stateID]) > 0 {
			return stateID
		}
	}
	// Fallback: the queue and cache can drift (e.g. a state whose actions were
	// restored directly into the cache). Scan the cache so a state with pending
	// actions is never stranded just because it is missing from the queue.
	for stateID, actions := range u.cache {
		if len(actions) > 0 {
			return stateID
		}
	}
	return ""
}

// PurgeState removes all actions for a state.
// Alias for PurgeActionsForState for API compatibility.
func (u *UnfiredFragmentCandidates) PurgeState(stateID string) {
	u.PurgeActionsForState(stateID)
}

// CrawlStrategyAdaptive is the adaptive strategy constant to avoid import cycle.
// Must match config.CrawlStrategyAdaptive value.
const CrawlStrategyAdaptive = "adaptive"

// PollByMode polls an action using the specified mode.
// - afterBacktrack=true: Use fragment-based prioritization (just after backtrack)
// - afterBacktrack=false: Use simple FIFO (during normal DFS)
// Note: strategy is any to avoid import cycle with config package.
// When strategy is "adaptive" and mabPolicy is set, uses MAB-based selection.
func (u *UnfiredFragmentCandidates) PollByMode(stateID string, strategy any, afterBacktrack bool) *CandidateCrawlAction {
	// Check if adaptive strategy with MAB policy
	// Handle both string and config.CrawlStrategy types (which is a string alias)
	var isAdaptive bool
	switch s := strategy.(type) {
	case string:
		isAdaptive = s == CrawlStrategyAdaptive
	default:
		// config.CrawlStrategy is a string type alias, use fmt.Sprint
		isAdaptive = fmt.Sprint(s) == CrawlStrategyAdaptive
	}

	if isAdaptive && u.mabPolicy != nil {
		return u.pollByMAB(stateID)
	}

	// Default: simple FIFO mode
	return u.PollActionOrNullSimple(stateID)
}

// pollByMAB selects an action using Multi-Armed Bandit policy.
// RLCRAWLER PARITY: Matches Stateless_RL_algorithm.py choose_action()
func (u *UnfiredFragmentCandidates) pollByMAB(stateID string) *CandidateCrawlAction {
	u.mu.Lock()
	defer u.mu.Unlock()

	actions := u.cache[stateID]
	if len(actions) == 0 {
		return nil
	}

	// Register actions with MAB and collect IDs
	actionIDs := make([]string, len(actions))
	for i, act := range actions {
		actionID := act.GetCandidateElement().GetIdentification().Value
		actionIDs[i] = actionID
		u.mabPolicy.AddAction(stateID, actionID)
	}

	// Trigger probability calculation (firstCall logic)
	probs := make([]float64, len(actionIDs))
	for i, aid := range actionIDs {
		probs[i] = u.mabPolicy.GetProbability(stateID, aid)
	}

	// Log all action probabilities for debugging
	zap.L().Debug("MAB action probabilities",
		zap.String("state", stateID),
		zap.Int("num_actions", len(actionIDs)),
		zap.Float64s("probabilities", probs))

	// MAB selection using probabilities
	selectedID := u.mabPolicy.SelectAction(stateID, actionIDs)
	if selectedID == "" {
		zap.L().Debug("MAB returned empty selection, falling back to FIFO")
		// Fallback to FIFO
		act := actions[0]
		u.cache[stateID] = actions[1:]
		if len(u.cache[stateID]) == 0 {
			delete(u.cache, stateID)
			u.removeStateFromQueueLocked(stateID)
		}
		return act
	}

	// Find selected probability for logging
	selectedProb := 0.0
	for i, aid := range actionIDs {
		if aid == selectedID {
			selectedProb = probs[i]
			break
		}
	}

	// Find and remove selected action from cache
	for i, act := range actions {
		if actionIDs[i] == selectedID {
			zap.L().Debug("MAB selected action",
				zap.String("state", stateID),
				zap.String("action", selectedID),
				zap.Float64("probability", selectedProb),
				zap.Int("index", i),
				zap.Int("total", len(actions)))
			u.cache[stateID] = append(actions[:i], actions[i+1:]...)
			if len(u.cache[stateID]) == 0 {
				delete(u.cache, stateID)
				u.removeStateFromQueueLocked(stateID)
			}
			return act
		}
	}

	// Should not reach here, but fallback to FIFO
	zap.L().Warn("MAB selected ID not found, falling back to FIFO",
		zap.String("selectedID", selectedID))
	act := actions[0]
	u.cache[stateID] = actions[1:]
	if len(u.cache[stateID]) == 0 {
		delete(u.cache, stateID)
		u.removeStateFromQueueLocked(stateID)
	}
	return act
}

// SetMABPolicy sets the MAB policy for adaptive action selection.
func (u *UnfiredFragmentCandidates) SetMABPolicy(policy MABPolicy) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.mabPolicy = policy
}

// GetMABPolicy returns the current MAB policy.
func (u *UnfiredFragmentCandidates) GetMABPolicy() MABPolicy {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.mabPolicy
}

// MarkFailed marks an action as failed.
// Currently a no-op as UnfiredFragmentCandidates doesn't track failure state.
func (u *UnfiredFragmentCandidates) MarkFailed(action *CandidateCrawlAction, err error) {
	zap.L().Debug("Action marked as failed",
		zap.String("action", action.String()),
		zap.Error(err))
}

// MarkExecuted marks an action as executed.
// Currently a no-op as UnfiredFragmentCandidates doesn't track execution state.
func (u *UnfiredFragmentCandidates) MarkExecuted(action *CandidateCrawlAction) {
	zap.L().Debug("Action marked as executed",
		zap.String("action", action.String()))
}

// PollAny polls the next action from any state.
// Returns (action, stateID) or (nil, "") if no actions available.
func (u *UnfiredFragmentCandidates) PollAny() (*CandidateCrawlAction, string) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Get first available action from any state
	for stateID, actions := range u.cache {
		if len(actions) > 0 {
			act := actions[0]
			u.cache[stateID] = actions[1:]
			if len(u.cache[stateID]) == 0 {
				delete(u.cache, stateID)
			}
			return act, stateID
		}
	}
	return nil, ""
}

// HasPending returns true if there are any pending actions.
func (u *UnfiredFragmentCandidates) HasPending() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	for _, actions := range u.cache {
		if len(actions) > 0 {
			return true
		}
	}
	return false
}
