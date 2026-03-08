package crawler

import (
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// Backtracker handles navigation back to states with pending actions.
type Backtracker struct {
	graph *state.Graph
}

// NewBacktracker creates a new backtracker.
func NewBacktracker(g *state.Graph) *Backtracker {
	return &Backtracker{graph: g}
}

// FindPathToState finds the shortest path from current state to target.
func (b *Backtracker) FindPathToState(currentID, targetID string) []*action.Eventable {
	return b.graph.ShortestPath(currentID, targetID)
}

// FindNearestStateWithActions finds the nearest state that has pending actions.
func (b *Backtracker) FindNearestStateWithActions(currentID string, statesWithActions []string) (string, []*action.Eventable) {
	if len(statesWithActions) == 0 {
		return "", nil
	}

	var nearestState string
	var shortestPath []*action.Eventable

	for _, targetID := range statesWithActions {
		if targetID == currentID {
			// Already at this state
			return targetID, []*action.Eventable{}
		}

		path := b.graph.ShortestPath(currentID, targetID)
		if path == nil {
			continue
		}

		if shortestPath == nil || len(path) < len(shortestPath) {
			shortestPath = path
			nearestState = targetID
		}
	}

	return nearestState, shortestPath
}

// GetPathToIndex returns the path from current state back to index.
func (b *Backtracker) GetPathToIndex(currentID string) []*action.Eventable {
	indexState := b.graph.GetIndexState()
	if indexState == nil {
		return nil
	}

	return b.graph.ShortestPath(currentID, indexState.ID)
}

// CanReach checks if target state is reachable from current state.
func (b *Backtracker) CanReach(currentID, targetID string) bool {
	if currentID == targetID {
		return true
	}
	path := b.graph.ShortestPath(currentID, targetID)
	return path != nil
}

// PathLength returns the length of the shortest path between two states.
func (b *Backtracker) PathLength(currentID, targetID string) int {
	if currentID == targetID {
		return 0
	}

	path := b.graph.ShortestPath(currentID, targetID)
	if path == nil {
		return -1 // Unreachable
	}

	return len(path)
}

// GetReachableStates returns all states reachable from the given state.
func (b *Backtracker) GetReachableStates(stateID string) []string {
	reachable := make([]string, 0)
	visited := make(map[string]bool)

	b.dfs(stateID, visited)

	for id := range visited {
		reachable = append(reachable, id)
	}

	return reachable
}

func (b *Backtracker) dfs(stateID string, visited map[string]bool) {
	if visited[stateID] {
		return
	}

	visited[stateID] = true

	edges := b.graph.OutgoingEdges(stateID)
	for _, edge := range edges {
		b.dfs(edge.TargetStateID, visited)
	}
}

// GetStateDepthFromIndex calculates the depth of a state from index.
func (b *Backtracker) GetStateDepthFromIndex(stateID string) int {
	indexState := b.graph.GetIndexState()
	if indexState == nil {
		return -1
	}

	if stateID == indexState.ID {
		return 0
	}

	path := b.graph.ShortestPath(indexState.ID, stateID)
	if path == nil {
		return -1
	}

	return len(path)
}

// OptimalBacktrackSequence returns an optimal sequence of states to visit
// to maximize coverage while minimizing backtracking.
func (b *Backtracker) OptimalBacktrackSequence(statesWithActions []string) []string {
	if len(statesWithActions) == 0 {
		return nil
	}

	if len(statesWithActions) == 1 {
		return statesWithActions
	}

	// Use a greedy approach: always go to the nearest state with actions
	sequence := make([]string, 0, len(statesWithActions))
	remaining := make(map[string]bool)
	for _, s := range statesWithActions {
		remaining[s] = true
	}

	// Start from index
	indexState := b.graph.GetIndexState()
	current := ""
	if indexState != nil {
		current = indexState.ID
	}

	for len(remaining) > 0 {
		// Find nearest remaining state
		var nearest string
		shortestDist := -1

		for stateID := range remaining {
			var dist int
			if current == "" || current == stateID {
				dist = 0
			} else {
				path := b.graph.ShortestPath(current, stateID)
				if path == nil {
					continue
				}
				dist = len(path)
			}

			if shortestDist < 0 || dist < shortestDist {
				shortestDist = dist
				nearest = stateID
			}
		}

		if nearest == "" {
			break // No reachable states
		}

		sequence = append(sequence, nearest)
		delete(remaining, nearest)
		current = nearest
	}

	return sequence
}
