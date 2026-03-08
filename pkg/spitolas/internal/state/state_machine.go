package state

import (
	"sync"

	"go.uber.org/zap"
)

// StateMachine manages state transitions for a single crawler.
// CRAWLJAX PARITY: Each Crawler has its own StateMachine that gets RESET on backtrack.
// The StateMachine holds a reference to the GLOBAL StateFlowGraph (Graph).
// When reset() is called, a NEW StateMachine instance is created, but the Graph is preserved.
type StateMachine struct {
	mu sync.RWMutex

	// Core state tracking (LOCAL to this crawler)
	currentState *State
	initialState *State // State after reset() - may differ from index due to session changes

	// onURLSet - states reachable by direct URL navigation
	// CRAWLJAX PARITY: Inherited from previous StateMachine on reset()
	onURLSet map[string]*State // URL -> State

	// Reference to GLOBAL graph (shared across all crawlers)
	// NOTE: Graph is NOT reset - it persists across all backtrack attempts
	graph *Graph
}

// NewStateMachine creates a new state machine with initial state.
// CRAWLJAX PARITY: This is called during crawler initialization.
func NewStateMachine(graph *Graph, initialState *State) *StateMachine {
	sm := &StateMachine{
		graph:        graph,
		initialState: initialState,
		currentState: initialState,
		onURLSet:     make(map[string]*State),
	}

	// CRAWLJAX PARITY: Add initial state to onURLSet if it has a URL
	if initialState != nil && initialState.URL != "" {
		sm.onURLSet[initialState.URL] = initialState
	}

	zap.L().Debug("StateMachine created",
		zap.String("initial_state", initialState.Name))

	return sm
}

// NewStateMachineWithOnURLSet creates a new state machine inheriting onURLSet from previous.
// CRAWLJAX PARITY: Used during reset() to preserve URL-reachable states.
func NewStateMachineWithOnURLSet(graph *Graph, initialState *State, onURLSet map[string]*State) *StateMachine {
	sm := &StateMachine{
		graph:        graph,
		initialState: initialState,
		currentState: initialState,
		onURLSet:     make(map[string]*State),
	}

	// Copy onURLSet from previous StateMachine
	for url, state := range onURLSet {
		sm.onURLSet[url] = state
	}

	// Ensure initial state is in onURLSet
	if initialState != nil && initialState.URL != "" {
		if _, exists := sm.onURLSet[initialState.URL]; !exists {
			sm.onURLSet[initialState.URL] = initialState
		}
	}

	zap.L().Debug("StateMachine created with inherited onURLSet",
		zap.String("initial_state", initialState.Name),
		zap.Int("onURLSet_size", len(sm.onURLSet)))

	return sm
}

// GetCurrentState returns the current state.
func (sm *StateMachine) GetCurrentState() *State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentState
}

// SetCurrentState updates the current state.
func (sm *StateMachine) SetCurrentState(s *State) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.currentState != nil && s != nil {
		zap.L().Debug("StateMachine state changed",
			zap.String("from", sm.currentState.Name),
			zap.String("to", s.Name))
	}

	sm.currentState = s
}

// GetInitialState returns the initial state (state after reset).
func (sm *StateMachine) GetInitialState() *State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.initialState
}

// GetGraph returns the global graph.
func (sm *StateMachine) GetGraph() *Graph {
	return sm.graph
}

// GetOnURLSet returns a copy of the onURLSet map.
// CRAWLJAX PARITY: Returns copy to prevent external modification.
func (sm *StateMachine) GetOnURLSet() map[string]*State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make(map[string]*State, len(sm.onURLSet))
	for url, state := range sm.onURLSet {
		result[url] = state
	}
	return result
}

// GetOnURLSetSlice returns onURLSet as a slice of states.
func (sm *StateMachine) GetOnURLSetSlice() []*State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	states := make([]*State, 0, len(sm.onURLSet))
	for _, state := range sm.onURLSet {
		states = append(states, state)
	}
	return states
}

// AddToOnURLSet adds a state to the URL-reachable set.
// CRAWLJAX PARITY: Only states that can be directly navigated to via URL are added.
func (sm *StateMachine) AddToOnURLSet(s *State) {
	if s == nil || s.URL == "" {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.onURLSet[s.URL]; !exists {
		sm.onURLSet[s.URL] = s
		zap.L().Debug("State added to onURLSet",
			zap.String("state", s.Name),
			zap.String("url", s.URL))
	}
}

// IsInOnURLSet checks if a state is in the onURLSet.
func (sm *StateMachine) IsInOnURLSet(s *State) bool {
	if s == nil || s.URL == "" {
		return false
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	_, exists := sm.onURLSet[s.URL]
	return exists
}

// ChangeState attempts to change to a new state.
// CRAWLJAX PARITY: Returns true if state change was successful.
// The target state must exist in the graph and be reachable from current state.
func (sm *StateMachine) ChangeState(target *State) bool {
	if target == nil {
		zap.L().Debug("ChangeState: target is nil")
		return false
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if target exists in graph
	if !sm.graph.HasState(target.ID) {
		zap.L().Debug("ChangeState: target not in graph",
			zap.String("target", target.Name))
		return false
	}

	// Check if we can go from current to target (edge exists)
	if sm.currentState != nil && sm.currentState.ID != target.ID {
		canGo := sm.canGoTo(sm.currentState.ID, target.ID)
		if !canGo {
			zap.L().Debug("ChangeState: cannot go to target",
				zap.String("from", sm.currentState.Name),
				zap.String("to", target.Name))
			return false
		}
	}

	zap.L().Debug("ChangeState: success",
		zap.String("from", sm.currentState.Name),
		zap.String("to", target.Name))

	sm.currentState = target
	return true
}

// canGoTo checks if there's a direct edge from source to target.
func (sm *StateMachine) canGoTo(sourceID, targetID string) bool {
	edges := sm.graph.OutgoingEdges(sourceID)
	for _, edge := range edges {
		if edge.TargetStateID == targetID {
			return true
		}
	}
	return false
}

// SwitchToStateAndCheckIfClone checks if newState is a clone of existing state.
// CRAWLJAX PARITY: This matches Java Crawljax StateMachine.switchToStateAndCheckIfClone()
// Returns (existingState, isClone):
//   - If newState is a clone, returns the existing state and true
//   - If newState is new, returns nil and false
func (sm *StateMachine) SwitchToStateAndCheckIfClone(newState *State) (*State, bool) {
	if newState == nil {
		return nil, false
	}

	// Check if state already exists in graph (by ID which is hash of stripped DOM)
	existingState, exists := sm.graph.GetState(newState.ID)
	if exists {
		zap.L().Debug("Clone state detected",
			zap.String("new_state", newState.Name),
			zap.String("existing_state", existingState.Name))
		return existingState, true
	}

	return nil, false
}

// Rewind resets the state machine to initial state (internal state only).
// CRAWLJAX PARITY: Does NOT create new instance - use NewStateMachineWithOnURLSet for full reset.
func (sm *StateMachine) Rewind() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.initialState != nil {
		zap.L().Debug("StateMachine rewound to initial state",
			zap.String("state", sm.initialState.Name))
	}

	sm.currentState = sm.initialState
}

// FindClosestOnURLState finds the closest URL-reachable state to the target.
// CRAWLJAX PARITY: Used for optimized backtracking.
// Returns nil if no URL-reachable state can reach the target.
func (sm *StateMachine) FindClosestOnURLState(target *State) *State {
	if target == nil {
		return nil
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// First check if target itself is URL-reachable
	if _, exists := sm.onURLSet[target.URL]; exists {
		return target
	}

	// Find the URL-reachable state with shortest path to target
	var closestState *State
	shortestPath := -1

	for _, urlState := range sm.onURLSet {
		path := sm.graph.ShortestPath(urlState.ID, target.ID)
		if path != nil {
			pathLen := len(path)
			if shortestPath < 0 || pathLen < shortestPath {
				shortestPath = pathLen
				closestState = urlState
			}
		}
	}

	return closestState
}

// OnURLSetSize returns the number of URL-reachable states.
func (sm *StateMachine) OnURLSetSize() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.onURLSet)
}
