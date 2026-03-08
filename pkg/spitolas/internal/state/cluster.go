package state

import (
	"sort"
	"sync"
)

// StateComparison defines the relationship between two states.
// This matches Java Crawljax's near-duplicate detection system.
type StateComparison int

const (
	// StateIdentical - states have identical DOM and visual appearance
	StateIdentical StateComparison = iota

	// StateNearDuplicate1 - same DOM structure, minor visual differences
	// (e.g., dynamic timestamps, counters, ads)
	StateNearDuplicate1

	// StateNearDuplicate2 - related fragments cover all DOM differences
	// (changes are contained within known dynamic fragments)
	StateNearDuplicate2

	// StateDifferent - states are meaningfully different
	StateDifferent
)

// String returns string representation of comparison result.
func (sc StateComparison) String() string {
	switch sc {
	case StateIdentical:
		return "IDENTICAL"
	case StateNearDuplicate1:
		return "ND1"
	case StateNearDuplicate2:
		return "ND2"
	case StateDifferent:
		return "DIFFERENT"
	default:
		return "UNKNOWN"
	}
}

// NDCluster represents a cluster of near-duplicate states.
type NDCluster struct {
	ID int

	// Representative is the canonical state for this cluster
	Representative *State

	// Members contains all states in this cluster (including representative)
	Members []*State

	// Type indicates the ND relationship type within the cluster
	Type StateComparison

	// DynamicFragmentHashes identifies which fragments vary within cluster
	DynamicFragmentHashes []string
}

// NewNDCluster creates a new cluster with the given representative.
func NewNDCluster(id int, representative *State) *NDCluster {
	return &NDCluster{
		ID:             id,
		Representative: representative,
		Members:        []*State{representative},
		Type:           StateIdentical,
	}
}

// AddMember adds a state to the cluster.
func (c *NDCluster) AddMember(state *State, comparison StateComparison) {
	c.Members = append(c.Members, state)
	// Cluster type is the "weakest" relationship among members
	if comparison > c.Type {
		c.Type = comparison
	}
}

// Size returns the number of states in the cluster.
func (c *NDCluster) Size() int {
	return len(c.Members)
}

// ContainsState checks if a state is in this cluster.
func (c *NDCluster) ContainsState(stateID string) bool {
	for _, member := range c.Members {
		if member.ID == stateID {
			return true
		}
	}
	return false
}

// NDClusterManager manages near-duplicate state clustering.
// CRAWLJAX PARITY: Matches Java FragmentManager's near-duplicate handling.
type NDClusterManager struct {
	mu sync.RWMutex

	// clusters holds all ND clusters
	clusters []*NDCluster

	// stateToCluster maps state ID to cluster
	stateToCluster map[string]*NDCluster

	// CRAWLJAX PARITY: List of near-duplicate state sets
	// Each set contains states that are near-duplicates of each other
	// In Java: List<Set<StateVertex>> nearDuplicates
	nearDuplicateSets []map[string]*State

	// nextClusterID for generating cluster IDs
	nextClusterID int

	// Configuration
	nd1Threshold float64 // Similarity threshold for ND1 (default 0.95)
	nd2Threshold float64 // Similarity threshold for ND2 (default 0.80)

	// CRAWLJAX PARITY: State comparison cache
	// Maps "stateID1:stateID2" -> comparison result
	comparisonCache map[string]StateComparison
}

// NewNDClusterManager creates a new cluster manager.
func NewNDClusterManager() *NDClusterManager {
	return &NDClusterManager{
		clusters:          make([]*NDCluster, 0),
		stateToCluster:    make(map[string]*NDCluster),
		nearDuplicateSets: make([]map[string]*State, 0),
		nextClusterID:     1,
		nd1Threshold:      0.95,
		nd2Threshold:      0.80,
		comparisonCache:   make(map[string]StateComparison),
	}
}

// SetThresholds configures similarity thresholds.
func (m *NDClusterManager) SetThresholds(nd1, nd2 float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nd1Threshold = nd1
	m.nd2Threshold = nd2
}

// CompareStates compares two states and returns their relationship.
func (m *NDClusterManager) CompareStates(s1, s2 *State) StateComparison {
	// Identical check
	if s1.ID == s2.ID {
		return StateIdentical
	}

	// Compare DOM content
	domSimilarity := calculateDOMSimilarity(s1.StrippedDOM, s2.StrippedDOM)

	if domSimilarity >= 1.0 {
		// Same DOM content = identical (StrippedDOM already normalized)
		return StateIdentical
	}

	if domSimilarity >= m.nd1Threshold {
		return StateNearDuplicate1
	}

	if domSimilarity >= m.nd2Threshold {
		return StateNearDuplicate2
	}

	return StateDifferent
}

// calculateDOMSimilarity calculates similarity between two DOM strings.
// Uses a combination of structural and content comparison.
func calculateDOMSimilarity(dom1, dom2 string) float64 {
	if dom1 == dom2 {
		return 1.0
	}

	if len(dom1) == 0 || len(dom2) == 0 {
		return 0.0
	}

	// Use shingle-based Jaccard similarity for DOM comparison
	shingles1 := extractShingles(dom1, 5)
	shingles2 := extractShingles(dom2, 5)

	return jaccardSimilarity(shingles1, shingles2)
}

// extractShingles extracts k-shingles from text.
func extractShingles(text string, k int) map[string]bool {
	shingles := make(map[string]bool)
	if len(text) < k {
		shingles[text] = true
		return shingles
	}

	for i := 0; i <= len(text)-k; i++ {
		shingles[text[i:i+k]] = true
	}
	return shingles
}

// jaccardSimilarity calculates Jaccard similarity between two sets.
func jaccardSimilarity(set1, set2 map[string]bool) float64 {
	if len(set1) == 0 && len(set2) == 0 {
		return 1.0
	}

	intersection := 0
	for k := range set1 {
		if set2[k] {
			intersection++
		}
	}

	union := len(set1) + len(set2) - intersection
	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

// AddState adds a state and clusters it with existing states.
func (m *NDClusterManager) AddState(state *State) *NDCluster {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already clustered
	if cluster := m.stateToCluster[state.ID]; cluster != nil {
		return cluster
	}

	// Find best matching cluster
	var bestCluster *NDCluster
	bestComparison := StateDifferent

	for _, cluster := range m.clusters {
		comparison := m.compareUnlocked(state, cluster.Representative)
		if comparison < bestComparison {
			bestComparison = comparison
			bestCluster = cluster
		}
		if comparison == StateIdentical {
			break
		}
	}

	// Add to existing cluster or create new one
	if bestCluster != nil && bestComparison != StateDifferent {
		bestCluster.AddMember(state, bestComparison)
		m.stateToCluster[state.ID] = bestCluster
		return bestCluster
	}

	// Create new cluster
	cluster := NewNDCluster(m.nextClusterID, state)
	m.nextClusterID++
	m.clusters = append(m.clusters, cluster)
	m.stateToCluster[state.ID] = cluster
	return cluster
}

// compareUnlocked compares states without locking.
func (m *NDClusterManager) compareUnlocked(s1, s2 *State) StateComparison {
	if s1.ID == s2.ID {
		return StateIdentical
	}

	domSimilarity := calculateDOMSimilarity(s1.StrippedDOM, s2.StrippedDOM)

	if domSimilarity >= 1.0 {
		// Same DOM content = identical (StrippedDOM already normalized)
		return StateIdentical
	}

	if domSimilarity >= m.nd1Threshold {
		return StateNearDuplicate1
	}

	if domSimilarity >= m.nd2Threshold {
		return StateNearDuplicate2
	}

	return StateDifferent
}

// GetCluster returns the cluster for a state.
func (m *NDClusterManager) GetCluster(stateID string) *NDCluster {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stateToCluster[stateID]
}

// GetAllClusters returns all clusters.
func (m *NDClusterManager) GetAllClusters() []*NDCluster {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*NDCluster, len(m.clusters))
	copy(result, m.clusters)
	return result
}

// GetClusterCount returns the number of clusters.
func (m *NDClusterManager) GetClusterCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clusters)
}

// GetUniqueStates returns representative states from all clusters.
// This effectively deduplicates states by returning only unique ones.
func (m *NDClusterManager) GetUniqueStates() []*State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make([]*State, len(m.clusters))
	for i, cluster := range m.clusters {
		states[i] = cluster.Representative
	}
	return states
}

// GetND1States returns states that are ND1 (same structure, visual diff).
func (m *NDClusterManager) GetND1States() []*State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var states []*State
	for _, cluster := range m.clusters {
		if cluster.Type == StateNearDuplicate1 {
			states = append(states, cluster.Members...)
		}
	}
	return states
}

// GetND2States returns states that are ND2 (related fragments differ).
func (m *NDClusterManager) GetND2States() []*State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var states []*State
	for _, cluster := range m.clusters {
		if cluster.Type == StateNearDuplicate2 {
			states = append(states, cluster.Members...)
		}
	}
	return states
}

// AreNearDuplicates checks if two states are near-duplicates.
func (m *NDClusterManager) AreNearDuplicates(stateID1, stateID2 string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cluster1 := m.stateToCluster[stateID1]
	cluster2 := m.stateToCluster[stateID2]

	return cluster1 != nil && cluster2 != nil && cluster1.ID == cluster2.ID
}

// MergeClusters merges two clusters into one.
func (m *NDClusterManager) MergeClusters(clusterID1, clusterID2 int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var cluster1, cluster2 *NDCluster
	var idx2 int

	for i, c := range m.clusters {
		if c.ID == clusterID1 {
			cluster1 = c
		}
		if c.ID == clusterID2 {
			cluster2 = c
			idx2 = i
		}
	}

	if cluster1 == nil || cluster2 == nil || cluster1 == cluster2 {
		return
	}

	// Merge cluster2 into cluster1
	for _, member := range cluster2.Members {
		cluster1.Members = append(cluster1.Members, member)
		m.stateToCluster[member.ID] = cluster1
	}

	// Update cluster type
	if cluster2.Type > cluster1.Type {
		cluster1.Type = cluster2.Type
	}

	// Remove cluster2
	m.clusters = append(m.clusters[:idx2], m.clusters[idx2+1:]...)
}

// RemoveState removes a state from its cluster.
func (m *NDClusterManager) RemoveState(stateID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cluster := m.stateToCluster[stateID]
	if cluster == nil {
		return
	}

	// Remove from cluster members
	for i, member := range cluster.Members {
		if member.ID == stateID {
			cluster.Members = append(cluster.Members[:i], cluster.Members[i+1:]...)
			break
		}
	}

	// Remove from map
	delete(m.stateToCluster, stateID)

	// If cluster is empty, remove it
	if len(cluster.Members) == 0 {
		for i, c := range m.clusters {
			if c.ID == cluster.ID {
				m.clusters = append(m.clusters[:i], m.clusters[i+1:]...)
				break
			}
		}
	} else if cluster.Representative.ID == stateID && len(cluster.Members) > 0 {
		// Need new representative
		cluster.Representative = cluster.Members[0]
	}
}

// Recluster forces reclustering of all states.
func (m *NDClusterManager) Recluster() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Collect all states
	var allStates []*State
	for _, cluster := range m.clusters {
		allStates = append(allStates, cluster.Members...)
	}

	// Clear existing clusters
	m.clusters = nil
	m.stateToCluster = make(map[string]*NDCluster)
	m.nextClusterID = 1

	// Sort states by ID for deterministic clustering
	sort.Slice(allStates, func(i, j int) bool {
		return allStates[i].ID < allStates[j].ID
	})

	// Re-add all states
	for _, state := range allStates {
		m.addStateUnlocked(state)
	}
}

func (m *NDClusterManager) addStateUnlocked(state *State) *NDCluster {
	// Check if already clustered
	if cluster := m.stateToCluster[state.ID]; cluster != nil {
		return cluster
	}

	// Find best matching cluster
	var bestCluster *NDCluster
	bestComparison := StateDifferent

	for _, cluster := range m.clusters {
		comparison := m.compareUnlocked(state, cluster.Representative)
		if comparison < bestComparison {
			bestComparison = comparison
			bestCluster = cluster
		}
		if comparison == StateIdentical {
			break
		}
	}

	// Add to existing cluster or create new one
	if bestCluster != nil && bestComparison != StateDifferent {
		bestCluster.AddMember(state, bestComparison)
		m.stateToCluster[state.ID] = bestCluster
		return bestCluster
	}

	// Create new cluster
	cluster := NewNDCluster(m.nextClusterID, state)
	m.nextClusterID++
	m.clusters = append(m.clusters, cluster)
	m.stateToCluster[state.ID] = cluster
	return cluster
}

// Stats returns clustering statistics.
func (m *NDClusterManager) Stats() ClusterStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := ClusterStats{
		TotalClusters: len(m.clusters),
		TotalStates:   len(m.stateToCluster),
	}

	for _, cluster := range m.clusters {
		switch cluster.Type {
		case StateIdentical:
			stats.IdenticalClusters++
		case StateNearDuplicate1:
			stats.ND1Clusters++
		case StateNearDuplicate2:
			stats.ND2Clusters++
		}

		if len(cluster.Members) > stats.LargestClusterSize {
			stats.LargestClusterSize = len(cluster.Members)
		}
	}

	if stats.TotalClusters > 0 {
		stats.AvgClusterSize = float64(stats.TotalStates) / float64(stats.TotalClusters)
	}

	return stats
}

// ClusterStats holds clustering statistics.
type ClusterStats struct {
	TotalClusters      int
	TotalStates        int
	IdenticalClusters  int
	ND1Clusters        int
	ND2Clusters        int
	LargestClusterSize int
	AvgClusterSize     float64
}

// GetClusterRepresentatives returns all cluster representatives.
func (m *NDClusterManager) GetClusterRepresentatives() []*State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	reps := make([]*State, len(m.clusters))
	for i, cluster := range m.clusters {
		reps[i] = cluster.Representative
	}
	return reps
}

// FindSimilarStates returns states similar to the given state.
func (m *NDClusterManager) FindSimilarStates(state *State, minSimilarity float64) []*State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var similar []*State

	for _, cluster := range m.clusters {
		for _, member := range cluster.Members {
			if member.ID == state.ID {
				continue
			}
			similarity := calculateDOMSimilarity(state.StrippedDOM, member.StrippedDOM)
			if similarity >= minSimilarity {
				similar = append(similar, member)
			}
		}
	}

	return similar
}

// DOMDiff represents differences between two DOM strings.
type DOMDiff struct {
	Added   []string
	Removed []string
	Changed []string
}

// GetDOMDiff computes DOM differences between two states.
func GetDOMDiff(s1, s2 *State) *DOMDiff {
	shingles1 := extractShingles(s1.StrippedDOM, 20)
	shingles2 := extractShingles(s2.StrippedDOM, 20)

	diff := &DOMDiff{
		Added:   make([]string, 0),
		Removed: make([]string, 0),
	}

	for shingle := range shingles2 {
		if !shingles1[shingle] {
			diff.Added = append(diff.Added, shingle)
		}
	}

	for shingle := range shingles1 {
		if !shingles2[shingle] {
			diff.Removed = append(diff.Removed, shingle)
		}
	}

	return diff
}

// IsEmpty returns true if diff has no changes.
func (d *DOMDiff) IsEmpty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Size returns total number of differences.
func (d *DOMDiff) Size() int {
	return len(d.Added) + len(d.Removed) + len(d.Changed)
}

// CRAWLJAX PARITY: Near-duplicate management methods

// AddToNearDuplicates adds two states as near-duplicates.
// CRAWLJAX PARITY: Matches Java FragmentManager.addToNearDuplicates().
func (m *NDClusterManager) AddToNearDuplicates(newState, expectedState *State) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addToNearDuplicatesLocked(newState, expectedState)
}

// addToNearDuplicatesLocked adds two states as near-duplicates (must hold lock).
func (m *NDClusterManager) addToNearDuplicatesLocked(newState, expectedState *State) {
	if newState == nil || expectedState == nil {
		return
	}

	// CRAWLJAX PARITY: Mark both states as having near-duplicates
	newState.IsNearDuplicate = true
	expectedState.IsNearDuplicate = true

	// CRAWLJAX PARITY: Use the smallest cluster ID
	// In Java: if (newState.getCluster() < expectedState.getCluster())
	if newState.ClusterID > 0 && expectedState.ClusterID > 0 {
		if newState.ClusterID < expectedState.ClusterID {
			expectedState.ClusterID = newState.ClusterID
		} else {
			newState.ClusterID = expectedState.ClusterID
		}
	} else if newState.ClusterID > 0 {
		expectedState.ClusterID = newState.ClusterID
	} else if expectedState.ClusterID > 0 {
		newState.ClusterID = expectedState.ClusterID
	}

	// CRAWLJAX PARITY: Find existing set containing either state
	for _, set := range m.nearDuplicateSets {
		if _, ok := set[newState.ID]; ok {
			set[expectedState.ID] = expectedState
			return
		}
		if _, ok := set[expectedState.ID]; ok {
			set[newState.ID] = newState
			return
		}
	}

	// CRAWLJAX PARITY: Create new set
	newSet := make(map[string]*State)
	newSet[newState.ID] = newState
	newSet[expectedState.ID] = expectedState
	m.nearDuplicateSets = append(m.nearDuplicateSets, newSet)
}

// AddSingleToNearDuplicates adds a single state to near-duplicates (creates its own set).
// CRAWLJAX PARITY: Matches Java FragmentManager.addToNearDuplicates(StateVertex).
func (m *NDClusterManager) AddSingleToNearDuplicates(state *State) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state == nil {
		return
	}

	// Check if already in a set
	for _, set := range m.nearDuplicateSets {
		if _, ok := set[state.ID]; ok {
			return
		}
	}

	// Create new set with just this state
	newSet := make(map[string]*State)
	newSet[state.ID] = state
	m.nearDuplicateSets = append(m.nearDuplicateSets, newSet)
}

// GetNearDuplicatesOf returns all states that are near-duplicates of the given state.
// CRAWLJAX PARITY: Matches Java FragmentManager.getNearDuplicates(StateVertex).
func (m *NDClusterManager) GetNearDuplicatesOf(state *State) []*State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state == nil {
		return nil
	}

	for _, set := range m.nearDuplicateSets {
		if _, ok := set[state.ID]; ok {
			result := make([]*State, 0, len(set))
			for _, s := range set {
				result = append(result, s)
			}
			return result
		}
	}

	return nil
}

// GetNearDuplicateSets returns all near-duplicate sets.
func (m *NDClusterManager) GetNearDuplicateSets() []map[string]*State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]map[string]*State, len(m.nearDuplicateSets))
	for i, set := range m.nearDuplicateSets {
		copied := make(map[string]*State)
		for k, v := range set {
			copied[k] = v
		}
		result[i] = copied
	}
	return result
}

// CacheStateComparison caches the comparison result between two states.
// CRAWLJAX PARITY: Matches Java FragmentManager.cacheStateComparision().
func (m *NDClusterManager) CacheStateComparison(state1, state2 *State, result StateComparison) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getComparisonKey(state1.ID, state2.ID)
	m.comparisonCache[key] = result
}

// GetCachedComparison returns cached comparison result, or StateDifferent if not cached.
func (m *NDClusterManager) GetCachedComparison(stateID1, stateID2 string) (StateComparison, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.getComparisonKey(stateID1, stateID2)
	result, ok := m.comparisonCache[key]
	return result, ok
}

// getComparisonKey creates a consistent key for two state IDs.
func (m *NDClusterManager) getComparisonKey(id1, id2 string) string {
	// Sort to ensure consistent key regardless of order
	if id1 < id2 {
		return id1 + ":" + id2
	}
	return id2 + ":" + id1
}

// CompareStatesWithFragments compares two states using fragment-based analysis.
// CRAWLJAX PARITY: Matches Java FragmentManager.cacheStateComparision() logic.
// This is the main comparison method that should be used.
func (m *NDClusterManager) CompareStatesWithFragments(
	newState, expectedState *State,
	getRelatedFragments func(stateID string) []string,
	getRootFragmentHash func(stateID string) string,
) StateComparison {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check cache first
	key := m.getComparisonKey(newState.ID, expectedState.ID)
	if cached, ok := m.comparisonCache[key]; ok {
		return cached
	}

	var comp StateComparison

	// CRAWLJAX PARITY: Step 1 - Check if strippedDOM equals
	if newState.StrippedDOM == expectedState.StrippedDOM {
		// Same stripped DOM = DUPLICATE or NEARDUPLICATE1
		// Since we skip visual comparison, treat as DUPLICATE
		comp = StateIdentical
		m.addToNearDuplicatesLocked(newState, expectedState)
		m.comparisonCache[key] = comp
		return comp
	}

	// CRAWLJAX PARITY: Step 2 - Check if root fragments are related
	if getRelatedFragments != nil && getRootFragmentHash != nil {
		newRootHash := getRootFragmentHash(newState.ID)
		expectedRootHash := getRootFragmentHash(expectedState.ID)

		if newRootHash != "" && expectedRootHash != "" {
			// Check if root fragments are related (duplicate or equivalent)
			newRelated := getRelatedFragments(newState.ID)
			for _, relatedHash := range newRelated {
				if relatedHash == expectedRootHash {
					comp = StateNearDuplicate1
					m.addToNearDuplicatesLocked(newState, expectedState)
					m.comparisonCache[key] = comp
					return comp
				}
			}
		}
	}

	// CRAWLJAX PARITY: Step 3 - Fall back to DOM similarity
	domSimilarity := calculateDOMSimilarity(newState.StrippedDOM, expectedState.StrippedDOM)

	if domSimilarity >= m.nd1Threshold {
		comp = StateNearDuplicate1
		m.addToNearDuplicatesLocked(newState, expectedState)
	} else if domSimilarity >= m.nd2Threshold {
		comp = StateNearDuplicate2
		m.addToNearDuplicatesLocked(newState, expectedState)
	} else {
		comp = StateDifferent
		// Add individually to near-duplicate sets
		m.addSingleToNearDuplicatesLocked(newState)
		m.addSingleToNearDuplicatesLocked(expectedState)
	}

	m.comparisonCache[key] = comp
	return comp
}

// addSingleToNearDuplicatesLocked adds a single state (must hold lock).
func (m *NDClusterManager) addSingleToNearDuplicatesLocked(state *State) {
	if state == nil {
		return
	}

	// Check if already in a set
	for _, set := range m.nearDuplicateSets {
		if _, ok := set[state.ID]; ok {
			return
		}
	}

	// Create new set with just this state
	newSet := make(map[string]*State)
	newSet[state.ID] = state
	m.nearDuplicateSets = append(m.nearDuplicateSets, newSet)
}

// HasExploredNearDuplicate checks if a state has an explored near-duplicate.
// CRAWLJAX PARITY: Matches Java FragmentManager.hasExploredNearDuplicate().
func (m *NDClusterManager) HasExploredNearDuplicate(state *State, hasUnexploredActions func(*State) bool) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if state == nil {
		return false
	}

	// If state itself is explored, return true
	if hasUnexploredActions != nil && !hasUnexploredActions(state) {
		return true
	}

	// Check near-duplicate sets
	if state.IsNearDuplicate {
		for _, set := range m.nearDuplicateSets {
			if _, ok := set[state.ID]; ok {
				for _, nd := range set {
					if hasUnexploredActions != nil && !hasUnexploredActions(nd) {
						return true
					}
				}
				break
			}
		}
	}

	return false
}

// ClearCache clears the comparison cache.
func (m *NDClusterManager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.comparisonCache = make(map[string]StateComparison)
}
