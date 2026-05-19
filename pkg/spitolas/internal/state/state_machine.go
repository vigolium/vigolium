package state

import (
	"sync"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// StateMachine manages state transitions for a single crawler.
// The StateMachine holds a reference to the GLOBAL StateFlowGraph (Graph).
// When reset() is called, a NEW StateMachine instance is created, but the Graph is preserved.
type StateMachine struct {
	mu sync.RWMutex

	// Core state tracking (LOCAL to this crawler)
	currentState *State
	initialState *State // State after reset() - may differ from index due to session changes

	// onURLSet - states reachable by direct URL navigation
	// dedup by equals() (strippedDom comparison). Inherited from previous StateMachine on reset().
	onURLSet []*State

	// Reference to GLOBAL graph (shared across all crawlers)
	// NOTE: Graph is NOT reset - it persists across all backtrack attempts
	graph *Graph
}

// NewStateMachine creates a new state machine with initial state.
func NewStateMachine(graph *Graph, initialState *State) *StateMachine {
	sm := &StateMachine{
		graph:        graph,
		initialState: initialState,
		currentState: initialState,
		onURLSet:     make([]*State, 0),
	}

	if initialState != nil {
		sm.onURLSet = append(sm.onURLSet, initialState)
	}

	zap.L().Debug("StateMachine created",
		zap.String("initial_state", initialState.Name))

	return sm
}

// NewStateMachineWithOnURLSet creates a new state machine inheriting onURLSet from previous.
func NewStateMachineWithOnURLSet(graph *Graph, initialState *State, onURLSet []*State) *StateMachine {
	sm := &StateMachine{
		graph:        graph,
		initialState: initialState,
		currentState: initialState,
		onURLSet:     make([]*State, 0, len(onURLSet)),
	}

	// Copy onURLSet from previous StateMachine
	sm.onURLSet = append(sm.onURLSet, onURLSet...)

	if len(sm.onURLSet) == 0 && initialState != nil {
		sm.onURLSet = append(sm.onURLSet, initialState)
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

// GetOnURLSet returns a copy of the onURLSet slice.
func (sm *StateMachine) GetOnURLSet() []*State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make([]*State, len(sm.onURLSet))
	copy(result, sm.onURLSet)
	return result
}

// GetOnURLSetSlice returns onURLSet as a slice of states (same as GetOnURLSet).
func (sm *StateMachine) GetOnURLSetSlice() []*State {
	return sm.GetOnURLSet()
}

// AddToOnURLSet adds a state to the URL-reachable set.
func (sm *StateMachine) AddToOnURLSet(s *State) {
	if s == nil {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Our state ID is SHA-256(strippedDom), so dedup by ID
	for _, existing := range sm.onURLSet {
		if existing.ID == s.ID {
			return // Already in set
		}
	}

	sm.onURLSet = append(sm.onURLSet, s)
	zap.L().Debug("State added to onURLSet",
		zap.String("state", s.Name),
		zap.String("url", s.URL))
}

// IsInOnURLSet checks if a state is in the onURLSet.
func (sm *StateMachine) IsInOnURLSet(s *State) bool {
	if s == nil {
		return false
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, existing := range sm.onURLSet {
		if existing.ID == s.ID {
			return true
		}
	}
	return false
}

// ChangeState attempts to change to a new state.
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

	// Check if we can go from current to target (edge exists in either direction)
	if sm.currentState != nil && sm.currentState.ID != target.ID {
		canGo := sm.canGoTo(sm.currentState.ID, target.ID)
		if !canGo {
			zap.L().Debug("ChangeState: cannot go to target",
				zap.String("from", sm.currentState.Name),
				zap.String("to", target.Name))
			return false
		}
	}

	fromName := "<nil>"
	if sm.currentState != nil {
		fromName = sm.currentState.Name
	}
	zap.L().Debug("ChangeState: success",
		zap.String("from", fromName),
		zap.String("to", target.Name))

	sm.currentState = target
	return true
}

// canGoTo checks if there's a direct edge between source and target in EITHER direction.
//
//	sfg.containsEdge(source, target) || sfg.containsEdge(target, source)
func (sm *StateMachine) canGoTo(sourceID, targetID string) bool {
	// Check source -> target
	for _, edge := range sm.graph.OutgoingEdges(sourceID) {
		if edge.TargetStateID == targetID {
			return true
		}
	}
	for _, edge := range sm.graph.OutgoingEdges(targetID) {
		if edge.TargetStateID == sourceID {
			return true
		}
	}
	return false
}

// addStateToCurrentState adds a new state and edge to the graph.
// Returns the existing clone state if the state already existed, nil if new.
func (sm *StateMachine) addStateToCurrentState(newState *State, eventable *action.Eventable) *State {
	// putIfAbsent — add state to graph if not already present
	isNew := sm.graph.AddState(newState)

	if !isNew {
		// State already exists — it's a clone
		cloneState, _ := sm.graph.GetState(newState.ID)
		// Add edge from current state to clone
		if sm.currentState != nil && cloneState != nil && eventable != nil {
			sm.graph.AddEdge(sm.currentState.ID, cloneState.ID, eventable)
		}
		return cloneState
	}

	// New state — add edge from current state to new state
	if sm.currentState != nil && eventable != nil {
		sm.graph.AddEdge(sm.currentState.ID, newState.ID, eventable)
	}
	return nil
}

// SwitchToStateAndCheckIfClone adds newState to graph, adds edge, and switches.
// Returns (existingState, isClone):
//   - If newState is a clone, switches to existing state and returns (existing, true)
//   - If newState is new, switches to new state and returns (nil, false)
func (sm *StateMachine) SwitchToStateAndCheckIfClone(newState *State, eventable *action.Eventable) (*State, bool) {
	if newState == nil {
		return nil, false
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	cloneState := sm.addStateToCurrentState(newState, eventable)

	// TODO: runOnInvariantViolationPlugins(context) — requires invariant checker

	if cloneState == nil {
		// New state
		sm.currentState = newState
		zap.L().Debug("Switched to new state",
			zap.String("state", newState.Name))
		return nil, false
	}

	// Clone — switch to the existing clone
	sm.currentState = cloneState
	zap.L().Debug("Switched to clone state",
		zap.String("new_state", newState.Name),
		zap.String("clone_state", cloneState.Name))
	return cloneState, true
}

// Rewind resets the state machine to initial state (internal state only).
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
// Returns nil if no URL-reachable state can reach the target.
func (sm *StateMachine) FindClosestOnURLState(target *State) *State {
	if target == nil {
		return nil
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// First check if target itself is URL-reachable
	for _, s := range sm.onURLSet {
		if s.ID == target.ID {
			return target
		}
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
