package state

import (
	"container/heap"
	"sync"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// Graph represents the state-flow graph.
type Graph struct {
	mu sync.RWMutex

	states     map[string]*State              // ID -> State
	edges      map[string][]*action.Eventable // sourceID -> outgoing edges
	inEdges    map[string][]*action.Eventable // targetID -> incoming edges
	stateOrder []string                       // Discovery order
	indexState *State                         // Initial state

	expiredEdges  []*action.Eventable // Edges that have been "removed" but can be restored
	expiredStates []*State            // States that have been "removed" but can be restored

	// Default threshold for distance-based near-duplicate detection
	nearDuplicateThreshold float64

	// Only HybridStateVertexImpl computes real distances.
	// When compareMode == CompareModeExact, skip near-dup computation.
	compareMode CompareMode
}

// NewGraph creates a new state graph.
func NewGraph() *Graph {
	return &Graph{
		states:                 make(map[string]*State),
		edges:                  make(map[string][]*action.Eventable),
		inEdges:                make(map[string][]*action.Eventable),
		stateOrder:             make([]string, 0),
		expiredEdges:           make([]*action.Eventable, 0),
		expiredStates:          make([]*State, 0),
		nearDuplicateThreshold: 0.1,
	}
}

// AddState adds a state to the graph.
// Returns true if state was added, false if it already exists.
func (g *Graph) AddState(s *State) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.states[s.ID]; exists {
		zap.L().Debug("State already exists in graph", zap.String("state_id", s.ID))
		return false
	}

	g.setNearDuplicateLocked(s)

	g.states[s.ID] = s
	g.stateOrder = append(g.stateOrder, s.ID)

	if s.IsIndex() {
		g.indexState = s
	}

	zap.L().Debug("State added to graph",
		zap.String("state_id", s.ID),
		zap.String("state_name", s.Name),
		zap.Int("total_states", len(g.states)),
		zap.String("nearest_state", s.NearestStateID),
		zap.Float64("dist_to_nearest", s.DistToNearest),
		zap.Bool("is_near_duplicate", s.IsNearDuplicate))

	return true
}

// setNearDuplicateLocked calculates and sets the nearest state information.
// Only HybridStateVertexImpl overrides these with real distance computation.
// Therefore, skip near-dup computation for CompareModeExact (the default).
// Must be called with lock held.
func (g *Graph) setNearDuplicateLocked(vertex *State) {
	// Only compute near-duplicates when using distance or fragment comparison mode.
	if g.compareMode == CompareModeExact {
		return
	}

	var minDistance = -1.0
	var closestVertex *State

	for _, existingState := range g.states {
		dist := g.calculateDistanceLocked(vertex, existingState)

		if minDistance == -1 || dist < minDistance {
			minDistance = dist
			closestVertex = existingState
		}
	}

	if closestVertex != nil {
		vertex.DistToNearest = minDistance
		vertex.NearestStateID = closestVertex.ID

		// Default: distance <= threshold means it's a near-duplicate
		vertex.IsNearDuplicate = g.inThresholdLocked(vertex, closestVertex)

		zap.L().Debug("Near-duplicate calculation completed",
			zap.String("state_id", vertex.ID),
			zap.String("nearest_id", closestVertex.ID),
			zap.Float64("distance", minDistance),
			zap.Bool("is_near_duplicate", vertex.IsNearDuplicate))
	}
}

// calculateDistanceLocked calculates distance between two states.
// Uses Levenshtein distance on stripped DOM (normalized to 0-1).
// Must be called with lock held.
func (g *Graph) calculateDistanceLocked(s1, s2 *State) float64 {
	if s1 == nil || s2 == nil {
		return 1.0
	}

	if s1.ID == s2.ID {
		return 0.0
	}

	dom1 := s1.StrippedDOM
	dom2 := s2.StrippedDOM

	if len(dom1) == 0 && len(dom2) == 0 {
		return 0.0
	}

	if len(dom1) == 0 || len(dom2) == 0 {
		return 1.0
	}

	// Use sampling for very long strings
	const maxCompareLen = 10000
	if len(dom1) > maxCompareLen || len(dom2) > maxCompareLen {
		return g.calculateDistanceSampledLocked(dom1, dom2, maxCompareLen)
	}

	// Calculate Levenshtein distance
	distance := levenshteinDistance(dom1, dom2)

	// Normalize to 0-1 range
	maxLen := max(len(dom1), len(dom2))
	return float64(distance) / float64(maxLen)
}

// calculateDistanceSampledLocked calculates distance using sampling for long strings.
// Must be called with lock held.
func (g *Graph) calculateDistanceSampledLocked(s1, s2 string, sampleSize int) float64 {
	samples := 3
	chunkSize := sampleSize / samples

	totalDistance := 0
	totalLen := 0

	for i := 0; i < samples; i++ {
		var start1, start2 int
		switch i {
		case 0: // Beginning
			start1, start2 = 0, 0
		case 1: // Middle
			start1 = (len(s1) - chunkSize) / 2
			start2 = (len(s2) - chunkSize) / 2
		case 2: // End
			start1 = len(s1) - chunkSize
			start2 = len(s2) - chunkSize
		}

		if start1 < 0 {
			start1 = 0
		}
		if start2 < 0 {
			start2 = 0
		}

		end1 := min(start1+chunkSize, len(s1))
		end2 := min(start2+chunkSize, len(s2))

		chunk1 := s1[start1:end1]
		chunk2 := s2[start2:end2]

		if len(chunk1) > 0 && len(chunk2) > 0 {
			distance := levenshteinDistance(chunk1, chunk2)
			totalDistance += distance
			totalLen += max(len(chunk1), len(chunk2))
		}
	}

	if totalLen == 0 {
		return 1.0
	}

	return float64(totalDistance) / float64(totalLen)
}

// inThresholdLocked checks if the distance between two states is within threshold.
// Must be called with lock held.
func (g *Graph) inThresholdLocked(s1, s2 *State) bool {
	dist := g.calculateDistanceLocked(s1, s2)
	return dist <= g.nearDuplicateThreshold
}

// SetNearDuplicateThreshold sets the threshold for near-duplicate detection.
// Values should be between 0 and 1 (default 0.1 = 10% difference allowed).
func (g *Graph) SetNearDuplicateThreshold(threshold float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nearDuplicateThreshold = threshold
}

// SetCompareMode sets the comparison mode for the graph.
func (g *Graph) SetCompareMode(mode CompareMode) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.compareMode = mode
}

// AddEdge adds an Eventable edge between two states.
// Only adds if no equivalent edge exists (based on Eventable.equals()).
// Returns the edge (existing or new).
func (g *Graph) AddEdge(sourceID, targetID string, eventable *action.Eventable) *action.Eventable {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Set source/target on the eventable
	eventable.SourceStateID = sourceID
	eventable.TargetStateID = targetID

	// Check for existing equivalent edge
	for _, edge := range g.edges[sourceID] {
		if edge.TargetStateID == targetID && edge.Equals(eventable) {
			// Set ID to -1 on duplicate edge — checked in inspectNewDom to fix the crawlPath.
			eventable.ID = -1
			zap.L().Debug("Edge already exists (marked ID=-1)",
				zap.String("source", sourceID),
				zap.String("target", targetID))
			return edge
		}
	}

	g.edges[sourceID] = append(g.edges[sourceID], eventable)
	g.inEdges[targetID] = append(g.inEdges[targetID], eventable)

	zap.L().Debug("Edge added to graph",
		zap.Int64("eventable_id", eventable.ID),
		zap.String("source", sourceID),
		zap.String("target", targetID))

	return eventable
}

// GetState returns a state by ID.
func (g *Graph) GetState(id string) (*State, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	s, ok := g.states[id]
	if !ok {
		return nil, false
	}
	return s.Clone(), true
}

// GetIndexState returns the index (initial) state.
func (g *Graph) GetIndexState() *State {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.indexState == nil {
		return nil
	}
	return g.indexState.Clone()
}

// FindStateByDOM finds a state by its stripped DOM.
func (g *Graph) FindStateByDOM(strippedDOM string) *State {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Generate the expected ID
	target := New("", "", strippedDOM, 0)

	if s, ok := g.states[target.ID]; ok {
		return s.Clone()
	}
	return nil
}

// StateCount returns the number of states.
func (g *Graph) StateCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return len(g.states)
}

// EdgeCount returns the number of edges.
func (g *Graph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	count := 0
	for _, edges := range g.edges {
		count += len(edges)
	}
	return count
}

// AllStates returns all states in discovery order.
func (g *Graph) AllStates() []*State {
	g.mu.RLock()
	defer g.mu.RUnlock()

	states := make([]*State, 0, len(g.stateOrder))
	for _, id := range g.stateOrder {
		if s, ok := g.states[id]; ok {
			states = append(states, s.Clone())
		}
	}
	return states
}

// AllEdges returns all edges.
func (g *Graph) AllEdges() []*action.Eventable {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edges := make([]*action.Eventable, 0)
	for _, edgeList := range g.edges {
		edges = append(edges, edgeList...)
	}
	return edges
}

// OutgoingEdges returns outgoing edges from a state.
func (g *Graph) OutgoingEdges(stateID string) []*action.Eventable {
	g.mu.RLock()
	defer g.mu.RUnlock()

	src := g.edges[stateID]
	if len(src) == 0 {
		return nil
	}
	result := make([]*action.Eventable, len(src))
	copy(result, src)
	return result
}

// IncomingEdges returns incoming edges to a state.
func (g *Graph) IncomingEdges(stateID string) []*action.Eventable {
	g.mu.RLock()
	defer g.mu.RUnlock()

	src := g.inEdges[stateID]
	if len(src) == 0 {
		return nil
	}
	result := make([]*action.Eventable, len(src))
	copy(result, src)
	return result
}

// HasState checks if a state exists.
func (g *Graph) HasState(id string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	_, ok := g.states[id]
	return ok
}

// RemoveEdge removes an edge from the graph and adds it to expired edges.
// The edge is tracked in expiredEdges for potential restoration.
func (g *Graph) RemoveEdge(sourceID, targetID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	var removedEdge *action.Eventable

	// Remove from outgoing edges
	if edges, ok := g.edges[sourceID]; ok {
		for i, edge := range edges {
			if edge.TargetStateID == targetID {
				removedEdge = edge
				g.edges[sourceID] = append(edges[:i], edges[i+1:]...)
				break
			}
		}
	}

	// Remove from incoming edges
	if inEdges, ok := g.inEdges[targetID]; ok {
		for i, edge := range inEdges {
			if edge.SourceStateID == sourceID {
				g.inEdges[targetID] = append(inEdges[:i], inEdges[i+1:]...)
				break
			}
		}
	}

	if removedEdge != nil {
		g.expiredEdges = append(g.expiredEdges, removedEdge)
		zap.L().Debug("Edge removed and added to expired list",
			zap.Int64("eventable_id", removedEdge.ID),
			zap.String("source", sourceID),
			zap.String("target", targetID))
		return true
	}

	return false
}

// RemoveSpecificEdge removes a specific edge from the graph by matching eventable identity.
// Unlike RemoveEdge(sourceID, targetID) which removes ALL edges between two nodes.
func (g *Graph) RemoveSpecificEdge(eventable *action.Eventable) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	sourceID := eventable.SourceStateID
	targetID := eventable.TargetStateID

	// Remove from outgoing edges
	found := false
	if edges, ok := g.edges[sourceID]; ok {
		for i, edge := range edges {
			if edge.ID == eventable.ID && edge.TargetStateID == targetID {
				g.edges[sourceID] = append(edges[:i], edges[i+1:]...)
				found = true
				break
			}
		}
	}

	if !found {
		return false
	}

	// Remove from incoming edges
	if inEdges, ok := g.inEdges[targetID]; ok {
		for i, edge := range inEdges {
			if edge.ID == eventable.ID && edge.SourceStateID == sourceID {
				g.inEdges[targetID] = append(inEdges[:i], inEdges[i+1:]...)
				break
			}
		}
	}

	// Track expired edge
	g.expiredEdges = append(g.expiredEdges, eventable)
	zap.L().Debug("Specific edge removed and added to expired list",
		zap.Int64("eventable_id", eventable.ID),
		zap.String("source", sourceID),
		zap.String("target", targetID))

	return true
}

// RestoreEdge restores a previously removed edge.
func (g *Graph) RestoreEdge(edge *action.Eventable) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Find and remove from expired edges
	found := false
	for i, expired := range g.expiredEdges {
		if expired.ID == edge.ID {
			g.expiredEdges = append(g.expiredEdges[:i], g.expiredEdges[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return false
	}

	// Re-add the edge
	g.edges[edge.SourceStateID] = append(g.edges[edge.SourceStateID], edge)
	g.inEdges[edge.TargetStateID] = append(g.inEdges[edge.TargetStateID], edge)

	zap.L().Debug("Edge restored from expired list",
		zap.Int64("eventable_id", edge.ID),
		zap.String("source", edge.SourceStateID),
		zap.String("target", edge.TargetStateID))

	return true
}

// RemoveState removes a state by adding it to expired states.
// Also removes all incoming edges to this state.
func (g *Graph) RemoveState(stateID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	state, exists := g.states[stateID]
	if !exists {
		return false
	}

	// Check if already expired
	for _, expired := range g.expiredStates {
		if expired.ID == stateID {
			zap.L().Warn("Trying to remove already expired state", zap.String("state_id", stateID))
			return false
		}
	}

	g.expiredStates = append(g.expiredStates, state)

	if inEdges, ok := g.inEdges[stateID]; ok {
		for _, inEdge := range inEdges {
			// Remove from source's outgoing edges
			if outEdges, ok := g.edges[inEdge.SourceStateID]; ok {
				for i, e := range outEdges {
					if e.ID == inEdge.ID {
						g.edges[inEdge.SourceStateID] = append(outEdges[:i], outEdges[i+1:]...)
						break
					}
				}
			}
			// Add to expired edges
			g.expiredEdges = append(g.expiredEdges, inEdge)
		}
		// Clear incoming edges
		delete(g.inEdges, stateID)
	}

	zap.L().Debug("State removed and added to expired list",
		zap.String("state_name", state.Name),
		zap.String("state_id", stateID))

	return true
}

// RestoreState restores a previously removed state and its incoming edges.
func (g *Graph) RestoreState(stateID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Find and remove from expired states
	var restoredState *State
	for i, expired := range g.expiredStates {
		if expired.ID == stateID {
			restoredState = expired
			g.expiredStates = append(g.expiredStates[:i], g.expiredStates[i+1:]...)
			break
		}
	}

	if restoredState == nil {
		zap.L().Debug("No need to restore unexpired state", zap.String("state_id", stateID))
		return false
	}

	edgesToRestore := make([]*action.Eventable, 0)
	for _, expired := range g.expiredEdges {
		if expired.TargetStateID == stateID {
			edgesToRestore = append(edgesToRestore, expired)
		}
	}

	for _, edge := range edgesToRestore {
		// Remove from expired list
		for i, e := range g.expiredEdges {
			if e.ID == edge.ID {
				g.expiredEdges = append(g.expiredEdges[:i], g.expiredEdges[i+1:]...)
				break
			}
		}
		// Re-add to graph
		g.edges[edge.SourceStateID] = append(g.edges[edge.SourceStateID], edge)
		g.inEdges[edge.TargetStateID] = append(g.inEdges[edge.TargetStateID], edge)
	}

	zap.L().Debug("State restored with incoming edges",
		zap.String("state_name", restoredState.Name),
		zap.String("state_id", stateID),
		zap.Int("restored_edges", len(edgesToRestore)))

	return true
}

// GetExpiredEdges returns all expired edges.
func (g *Graph) GetExpiredEdges() []*action.Eventable {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*action.Eventable, len(g.expiredEdges))
	copy(result, g.expiredEdges)
	return result
}

// GetExpiredStates returns all expired states.
func (g *Graph) GetExpiredStates() []*State {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*State, len(g.expiredStates))
	copy(result, g.expiredStates)
	return result
}

// GetMeanStateStringSize returns the mean DOM string size across all states.
func (g *Graph) GetMeanStateStringSize() int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.states) == 0 {
		return 0
	}

	total := 0
	for _, s := range g.states {
		total += len(s.StrippedDOM)
	}
	return total / len(g.states)
}

// ShortestPath finds the shortest path between two states using Dijkstra.
// Returns nil if no path exists.
func (g *Graph) ShortestPath(sourceID, targetID string) []*action.Eventable {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if sourceID == targetID {
		return []*action.Eventable{}
	}

	// Dijkstra's algorithm
	dist := make(map[string]int)
	prev := make(map[string]*action.Eventable)

	for id := range g.states {
		dist[id] = int(^uint(0) >> 1) // Max int
	}
	dist[sourceID] = 0

	// Priority queue
	pq := &priorityQueue{}
	heap.Init(pq)
	heap.Push(pq, &pqItem{stateID: sourceID, distance: 0})

	for pq.Len() > 0 {
		item := heap.Pop(pq).(*pqItem)
		current := item.stateID

		if current == targetID {
			break
		}

		if item.distance > dist[current] {
			continue
		}

		for _, edge := range g.edges[current] {
			newDist := dist[current] + 1
			if newDist < dist[edge.TargetStateID] {
				dist[edge.TargetStateID] = newDist
				prev[edge.TargetStateID] = edge
				heap.Push(pq, &pqItem{stateID: edge.TargetStateID, distance: newDist})
			}
		}
	}

	// Reconstruct path
	if _, ok := prev[targetID]; !ok && sourceID != targetID {
		return nil // No path
	}

	path := make([]*action.Eventable, 0)
	current := targetID
	for current != sourceID {
		edge := prev[current]
		if edge == nil {
			break
		}
		path = append([]*action.Eventable{edge}, path...)
		current = edge.SourceStateID
	}

	return path
}

// GetNeighbors returns states reachable from the given state (deduplicated).
func (g *Graph) GetNeighbors(stateID string) []*State {
	g.mu.RLock()
	defer g.mu.RUnlock()

	seen := make(map[string]bool)
	neighbors := make([]*State, 0)
	for _, edge := range g.edges[stateID] {
		if seen[edge.TargetStateID] {
			continue
		}
		if s, ok := g.states[edge.TargetStateID]; ok {
			seen[edge.TargetStateID] = true
			neighbors = append(neighbors, s.Clone())
		}
	}
	return neighbors
}

// GetParents returns states that can reach the given state.
func (g *Graph) GetParents(stateID string) []*State {
	g.mu.RLock()
	defer g.mu.RUnlock()

	parents := make([]*State, 0)
	for _, edge := range g.inEdges[stateID] {
		if s, ok := g.states[edge.SourceStateID]; ok {
			parents = append(parents, s.Clone())
		}
	}
	return parents
}

// Priority queue implementation for Dijkstra

type pqItem struct {
	stateID  string
	distance int
	index    int
}

type priorityQueue []*pqItem

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	return pq[i].distance < pq[j].distance
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*pqItem)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

// ResetEventableIDCounter resets the eventable ID counter (for testing).
func ResetEventableIDCounter() {
	action.ResetEventableIDCounter()
}

// KShortestPaths finds up to k shortest paths between two states using Yen's algorithm.
// Returns paths in order of increasing length. Returns nil if no path exists.
func (g *Graph) KShortestPaths(sourceID, targetID string, k int) [][]*action.Eventable {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if k <= 0 {
		return nil
	}

	if sourceID == targetID {
		return [][]*action.Eventable{{}}
	}

	// Find the first shortest path using Dijkstra
	paths := make([][]*action.Eventable, 0, k)
	firstPath := g.shortestPathUnlocked(sourceID, targetID)
	if firstPath == nil {
		return nil
	}
	paths = append(paths, firstPath)

	if k == 1 {
		return paths
	}

	// Candidates for next shortest paths
	candidates := &pathCandidateHeap{}
	heap.Init(candidates)

	// Yen's algorithm: find k-1 more paths
	for i := 1; i < k; i++ {
		// The spur node ranges from first to next-to-last node of previous path
		prevPath := paths[i-1]
		for spurIdx := 0; spurIdx < len(prevPath); spurIdx++ {
			spurNode := prevPath[spurIdx].SourceStateID
			rootPath := prevPath[:spurIdx]

			// Create a copy of edges for temporary removal
			removedEdges := make(map[int64]bool)

			// Remove edges that would lead to already-found paths with same root
			for _, path := range paths {
				if len(path) > spurIdx && pathRootEquals(path, rootPath) {
					edge := path[spurIdx]
					removedEdges[edge.ID] = true
				}
			}

			// Find shortest path from spur to target, avoiding removed edges
			spurPath := g.shortestPathAvoidingEdges(spurNode, targetID, removedEdges, rootPath)
			if spurPath != nil {
				// Combine root path with spur path
				totalPath := append(copyEdges(rootPath), spurPath...)
				totalLen := len(totalPath)

				// Add to candidates if not already found
				if !pathExists(candidates, totalPath) {
					heap.Push(candidates, &pathCandidate{path: totalPath, length: totalLen})
				}
			}
		}

		if candidates.Len() == 0 {
			break
		}

		// Get shortest candidate
		best := heap.Pop(candidates).(*pathCandidate)
		paths = append(paths, best.path)
	}

	return paths
}

// shortestPathUnlocked finds shortest path without acquiring lock.
func (g *Graph) shortestPathUnlocked(sourceID, targetID string) []*action.Eventable {
	if sourceID == targetID {
		return []*action.Eventable{}
	}

	dist := make(map[string]int)
	prev := make(map[string]*action.Eventable)

	for id := range g.states {
		dist[id] = int(^uint(0) >> 1)
	}
	dist[sourceID] = 0

	pq := &priorityQueue{}
	heap.Init(pq)
	heap.Push(pq, &pqItem{stateID: sourceID, distance: 0})

	for pq.Len() > 0 {
		item := heap.Pop(pq).(*pqItem)
		current := item.stateID

		if current == targetID {
			break
		}

		if item.distance > dist[current] {
			continue
		}

		for _, edge := range g.edges[current] {
			newDist := dist[current] + 1
			if newDist < dist[edge.TargetStateID] {
				dist[edge.TargetStateID] = newDist
				prev[edge.TargetStateID] = edge
				heap.Push(pq, &pqItem{stateID: edge.TargetStateID, distance: newDist})
			}
		}
	}

	if _, ok := prev[targetID]; !ok && sourceID != targetID {
		return nil
	}

	path := make([]*action.Eventable, 0)
	current := targetID
	for current != sourceID {
		edge := prev[current]
		if edge == nil {
			break
		}
		path = append([]*action.Eventable{edge}, path...)
		current = edge.SourceStateID
	}

	return path
}

// shortestPathAvoidingEdges finds shortest path avoiding certain edges and nodes in rootPath.
func (g *Graph) shortestPathAvoidingEdges(sourceID, targetID string, removedEdges map[int64]bool, rootPath []*action.Eventable) []*action.Eventable {
	// Create set of nodes to avoid (from root path, except last)
	avoidNodes := make(map[string]bool)
	for _, edge := range rootPath {
		avoidNodes[edge.SourceStateID] = true
	}

	if sourceID == targetID {
		return []*action.Eventable{}
	}

	dist := make(map[string]int)
	prev := make(map[string]*action.Eventable)

	for id := range g.states {
		dist[id] = int(^uint(0) >> 1)
	}
	dist[sourceID] = 0

	pq := &priorityQueue{}
	heap.Init(pq)
	heap.Push(pq, &pqItem{stateID: sourceID, distance: 0})

	for pq.Len() > 0 {
		item := heap.Pop(pq).(*pqItem)
		current := item.stateID

		if current == targetID {
			break
		}

		if item.distance > dist[current] {
			continue
		}

		for _, edge := range g.edges[current] {
			// Skip removed edges
			if removedEdges[edge.ID] {
				continue
			}
			// Skip nodes in root path (except target)
			if avoidNodes[edge.TargetStateID] && edge.TargetStateID != targetID {
				continue
			}

			newDist := dist[current] + 1
			if newDist < dist[edge.TargetStateID] {
				dist[edge.TargetStateID] = newDist
				prev[edge.TargetStateID] = edge
				heap.Push(pq, &pqItem{stateID: edge.TargetStateID, distance: newDist})
			}
		}
	}

	if _, ok := prev[targetID]; !ok && sourceID != targetID {
		return nil
	}

	path := make([]*action.Eventable, 0)
	current := targetID
	for current != sourceID {
		edge := prev[current]
		if edge == nil {
			break
		}
		path = append([]*action.Eventable{edge}, path...)
		current = edge.SourceStateID
	}

	return path
}

// Helper types and functions for K-shortest paths

type pathCandidate struct {
	path   []*action.Eventable
	length int
	index  int
}

type pathCandidateHeap []*pathCandidate

func (h pathCandidateHeap) Len() int           { return len(h) }
func (h pathCandidateHeap) Less(i, j int) bool { return h[i].length < h[j].length }
func (h pathCandidateHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *pathCandidateHeap) Push(x interface{}) {
	n := len(*h)
	item := x.(*pathCandidate)
	item.index = n
	*h = append(*h, item)
}

func (h *pathCandidateHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[0 : n-1]
	return item
}

func pathRootEquals(path []*action.Eventable, root []*action.Eventable) bool {
	if len(path) < len(root) {
		return false
	}
	for i, edge := range root {
		if path[i].ID != edge.ID {
			return false
		}
	}
	return true
}

func copyEdges(edges []*action.Eventable) []*action.Eventable {
	result := make([]*action.Eventable, len(edges))
	copy(result, edges)
	return result
}

func pathExists(candidates *pathCandidateHeap, path []*action.Eventable) bool {
	for _, c := range *candidates {
		if len(c.path) != len(path) {
			continue
		}
		match := true
		for i, edge := range path {
			if c.path[i].ID != edge.ID {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
