package fragment

import (
	"sync"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
)

// Manager tracks fragments across states and manages their lifecycle.
type Manager struct {
	mu sync.RWMutex

	// All known fragments by their DOM hash
	fragments map[string]*Fragment

	// Only contains global (unique) fragments, not duplicates
	globalFragments []*Fragment

	// HIGH PRIORITY FIX: Add index by ID for O(1) lookup instead of O(N²)
	// Fragment ID -> DOM hash mapping for reverse lookup
	fragmentIDToHash map[int]string

	// State ID -> Fragment IDs mapping
	stateFragments map[string][]int

	// DOM hash -> change count (for dynamic detection)
	changeCount map[string]int

	// Dynamic threshold - if a fragment changes more than this many times,
	// it's marked as dynamic
	dynamicThreshold int

	// Maps "stateID1|stateID2" -> StatePairResult
	stateComparisonCache map[string]*StatePairResult

	// Each entry is a set of state IDs that are near-duplicates of each other
	nearDuplicates []map[string]bool

	hops map[int]float64

	numNonSelections map[int]float64
}

// StatePairResult holds the result of comparing two states.
type StatePairResult struct {
	State1ID   string
	State2ID   string
	Comparison StateComparison
}

// StateComparison defines the result of comparing two states.
type StateComparison int

const (
	// StateComparisonDifferent - States are completely different.
	StateComparisonDifferent StateComparison = iota
	// StateComparisonDuplicate - States are exact duplicates.
	StateComparisonDuplicate
	// StateComparisonNearDuplicate1 - Root fragments are related.
	StateComparisonNearDuplicate1
	// StateComparisonNearDuplicate2 - Affected fragments are covered.
	StateComparisonNearDuplicate2
	// StateComparisonError - Error comparing states.
	StateComparisonError
)

// String returns string representation of StateComparison.
func (sc StateComparison) String() string {
	switch sc {
	case StateComparisonDifferent:
		return "DIFFERENT"
	case StateComparisonDuplicate:
		return "DUPLICATE"
	case StateComparisonNearDuplicate1:
		return "NEARDUPLICATE1"
	case StateComparisonNearDuplicate2:
		return "NEARDUPLICATE2"
	case StateComparisonError:
		return "ERRORCOMPARING"
	default:
		return "UNKNOWN"
	}
}

// NewManager creates a new fragment manager.
func NewManager() *Manager {
	return &Manager{
		fragments:            make(map[string]*Fragment),
		globalFragments:      make([]*Fragment, 0),
		fragmentIDToHash:     make(map[int]string),
		stateFragments:       make(map[string][]int),
		changeCount:          make(map[string]int),
		dynamicThreshold:     3,
		stateComparisonCache: make(map[string]*StatePairResult),
		nearDuplicates:       make([]map[string]bool, 0),
		hops:                 make(map[int]float64),
		numNonSelections:     make(map[int]float64),
	}
}

// SetDynamicThreshold sets the threshold for marking fragments as dynamic.
func (m *Manager) SetDynamicThreshold(threshold int) {
	m.dynamicThreshold = threshold
}

// AddFragment adds a fragment to the global fragment list.
// This method compares the new fragment with all existing fragments
// and classifies it as EQUAL (duplicate), EQUIVALENT, ND2, or DIFFERENT (global).
func (m *Manager) AddFragment(fragment *Fragment, fast bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	equivalentFragments := make([]*Fragment, 0)
	nd2Fragments := make([]*Fragment, 0)

	// Compare with all existing global fragments
	for _, existing := range m.globalFragments {
		var comp FragmentComparison
		if fast {
			comp = existing.CompareFast(fragment)
		} else {
			comp = existing.Compare(fragment)
		}

		switch comp {
		case FragmentEqual:
			// Add bidirectional duplicate links
			existing.AddDuplicateFragment(fragment)
			fragment.AddDuplicateFragment(existing)
			fragment.SetIsGlobal(false)

			// Check if fragment is useful
			fragment.IsUseful()

			// Don't add to global list - it's a duplicate
			// Track in map for fast lookup
			if fragment.DOMHash != "" {
				m.fragments[fragment.DOMHash] = fragment
				m.fragmentIDToHash[fragment.ID] = fragment.DOMHash
			}
			return

		case FragmentEquivalent:
			// Same DOM but different visual (skip visual = same as EQUAL for us)
			// Since we skip visual comparison, this case won't happen
			// but keep for completeness
			equivalentFragments = append(equivalentFragments, existing)

		case FragmentND2:
			// Near-duplicate type 2
			nd2Fragments = append(nd2Fragments, existing)

		case FragmentDifferent:
			// Continue checking other fragments
			continue
		}
	}

	fragment.SetIsGlobal(true)
	m.globalFragments = append(m.globalFragments, fragment)

	// Track in map for fast lookup
	if fragment.DOMHash != "" {
		m.fragments[fragment.DOMHash] = fragment
		m.fragmentIDToHash[fragment.ID] = fragment.DOMHash
	}

	for _, existing := range equivalentFragments {
		existing.AddEquivalentFragment(fragment)
		fragment.AddEquivalentFragment(existing)
	}

	for _, existing := range nd2Fragments {
		existing.AddND2FragmentRef(fragment)
		fragment.AddND2FragmentRef(existing)
	}

	if fragment.IsUseful() && len(fragment.CandidateElements) > 0 {
		m.setAccessLocked(fragment)
		m.setCoverageLocked(fragment)
		fragment.SetAccessTransferred(true)
	}
}

// setAccessLocked transfers access info from related fragments.
// Must be called with lock held.
func (m *Manager) setAccessLocked(fragment *Fragment) {
	if fragment.IsGlobal {
		// Global fragment: transfer from equivalents
		for _, equiv := range fragment.EquivalentFragments {
			if equiv == fragment {
				continue
			}
			fragment.transferEquivalentAccess(equiv)
		}
	} else {
		// Duplicate fragment: transfer from global + all duplicates + equivalents
		for _, dup := range m.getDuplicateFragmentsLocked(fragment) {
			if dup == fragment {
				continue
			}
			fragment.transferDuplicateAccess(dup)
		}
		for _, equiv := range m.getEquivalentFragmentsLocked(fragment) {
			if equiv == fragment {
				continue
			}
			fragment.transferEquivalentAccess(equiv)
		}
	}

	// Transfer from ND2 fragments
	for _, nd2 := range fragment.ND2FragmentRefs {
		fragment.transferEquivalentAccess(nd2)
	}
}

// setCoverageLocked transfers coverage info from related fragments.
// Must be called with lock held.
func (m *Manager) setCoverageLocked(fragment *Fragment) {
	if fragment.AccessTransferred {
		return
	}

	if fragment.IsGlobal {
		for _, equiv := range fragment.EquivalentFragments {
			if equiv == fragment {
				continue
			}
			fragment.transferCoverage(equiv)
		}
	} else {
		for _, dup := range m.getDuplicateFragmentsLocked(fragment) {
			if dup == fragment {
				continue
			}
			fragment.transferCoverage(dup)
		}
	}
}

// Helper methods for Fragment access transfer

func (f *Fragment) transferDuplicateAccess(other *Fragment) {
	// Transfer access info from duplicate fragment
	if other.DirectAccess {
		f.DirectAccess = true
	}
	f.DuplicateCount += other.DuplicateCount
}

func (f *Fragment) transferEquivalentAccess(other *Fragment) {
	// Transfer access info from equivalent fragment (less weight)
	f.EquivalentCount += other.EquivalentCount
}

func (f *Fragment) transferCoverage(other *Fragment) {
	// Transfer coverage info from other fragment
	if other.AccessCount > 0 {
		f.AccessCount += other.AccessCount
	}
}

// getDuplicateFragmentsLocked returns all duplicate fragments for the given fragment.
// Must be called with lock held.
func (m *Manager) getDuplicateFragmentsLocked(fragment *Fragment) []*Fragment {
	if fragment == nil {
		return []*Fragment{}
	}

	if fragment.IsGlobal {
		// If global, return all duplicates
		result := make([]*Fragment, 0, len(fragment.DuplicateFragments)+1)
		result = append(result, fragment) // Include self
		result = append(result, fragment.DuplicateFragments...)
		return result
	}

	// If not global, get the global fragment first
	if len(fragment.DuplicateFragments) == 0 {
		return []*Fragment{fragment}
	}

	globalFragment := fragment.DuplicateFragments[0]
	result := make([]*Fragment, 0, len(globalFragment.DuplicateFragments)+1)
	result = append(result, globalFragment)
	result = append(result, globalFragment.DuplicateFragments...)
	return result
}

// getEquivalentFragmentsLocked returns all equivalent fragments for the given fragment.
// Must be called with lock held.
func (m *Manager) getEquivalentFragmentsLocked(fragment *Fragment) []*Fragment {
	if fragment == nil {
		return []*Fragment{}
	}

	// If not global, get equivalents from global fragment
	var target *Fragment
	if !fragment.IsGlobal && len(fragment.DuplicateFragments) > 0 {
		target = fragment.DuplicateFragments[0]
	} else {
		target = fragment
	}

	// Get all equivalents and their duplicates
	seen := make(map[*Fragment]bool)
	result := make([]*Fragment, 0)

	for _, equiv := range target.EquivalentFragments {
		if !seen[equiv] {
			seen[equiv] = true
			result = append(result, equiv)
		}
		// Also add duplicates of equivalent
		for _, dup := range equiv.DuplicateFragments {
			if !seen[dup] {
				seen[dup] = true
				result = append(result, dup)
			}
		}
	}

	return result
}

// GetDuplicateFragments returns all duplicate fragments for the given fragment.
// Thread-safe public version.
func (m *Manager) GetDuplicateFragments(fragment *Fragment) []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getDuplicateFragmentsLocked(fragment)
}

// GetEquivalentFragments returns all equivalent fragments for the given fragment.
// Thread-safe public version.
func (m *Manager) GetEquivalentFragments(fragment *Fragment) []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getEquivalentFragmentsLocked(fragment)
}

// GetRelatedFragmentsForFragment returns all related fragments (duplicates + equivalents).
func (m *Manager) GetRelatedFragmentsForFragment(fragment *Fragment) []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	related := make([]*Fragment, 0)
	related = append(related, m.getDuplicateFragmentsLocked(fragment)...)
	related = append(related, m.getEquivalentFragmentsLocked(fragment)...)
	return related
}

// GetGlobalFragments returns all unique global fragments.
func (m *Manager) GetGlobalFragments() []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Fragment, len(m.globalFragments))
	copy(result, m.globalFragments)
	return result
}

// AddFragments registers fragments for a state.
func (m *Manager) AddFragments(stateID string, frags []*Fragment) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ids := make([]int, len(frags))
	for i, frag := range frags {
		ids[i] = frag.ID

		// Track by DOM hash
		if existing, ok := m.fragments[frag.DOMHash]; ok {
			existing.AccessCount++
		} else {
			m.fragments[frag.DOMHash] = frag.Clone()
		}

		// HIGH PRIORITY FIX: Maintain ID -> hash index for O(1) lookup
		m.fragmentIDToHash[frag.ID] = frag.DOMHash
	}

	m.stateFragments[stateID] = ids
}

// GetFragments returns fragments for a state.
func (m *Manager) GetFragments(stateID string) []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids, ok := m.stateFragments[stateID]
	if !ok {
		return nil
	}

	frags := make([]*Fragment, 0, len(ids))
	for _, id := range ids {
		// HIGH PRIORITY FIX: O(1) lookup via ID -> hash index instead of O(N²)
		if hash, ok := m.fragmentIDToHash[id]; ok {
			if frag, ok := m.fragments[hash]; ok {
				frags = append(frags, frag.Clone())
			}
		}
	}

	return frags
}

// GetFragmentByHash returns a fragment by its DOM hash.
func (m *Manager) GetFragmentByHash(domHash string) *Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if frag, ok := m.fragments[domHash]; ok {
		return frag.Clone()
	}
	return nil
}

// GetChangedFragments compares fragments between two states.
// Returns fragments that differ between the states.
func (m *Manager) GetChangedFragments(stateID1, stateID2 string) []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	frags1 := m.getStateFragmentHashes(stateID1)
	frags2 := m.getStateFragmentHashes(stateID2)

	changed := make([]*Fragment, 0)

	// Find fragments in state1 but not in state2
	for hash := range frags1 {
		if _, ok := frags2[hash]; !ok {
			if frag, ok := m.fragments[hash]; ok {
				changed = append(changed, frag.Clone())
			}
		}
	}

	// Find fragments in state2 but not in state1
	for hash := range frags2 {
		if _, ok := frags1[hash]; !ok {
			if frag, ok := m.fragments[hash]; ok {
				changed = append(changed, frag.Clone())
			}
		}
	}

	return changed
}

func (m *Manager) getStateFragmentHashes(stateID string) map[string]bool {
	hashes := make(map[string]bool)

	ids, ok := m.stateFragments[stateID]
	if !ok {
		return hashes
	}

	// HIGH PRIORITY FIX: O(1) lookup via ID -> hash index instead of O(N²)
	for _, id := range ids {
		if hash, ok := m.fragmentIDToHash[id]; ok {
			hashes[hash] = true
		}
	}

	return hashes
}

// MarkDynamic marks a fragment as dynamic by its DOM hash.
func (m *Manager) MarkDynamic(domHash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.changeCount[domHash]++

	if m.changeCount[domHash] >= m.dynamicThreshold {
		if frag, ok := m.fragments[domHash]; ok {
			m.setDynamicLocked(frag)
		}
	}
}

// setDynamicLocked marks a fragment and all its related fragments as dynamic.
// Must be called with lock held.
func (m *Manager) setDynamicLocked(fragment *Fragment) {
	related := m.getRelatedFragmentsForFragmentLocked(fragment)
	for _, rel := range related {
		rel.IsDynamic = true
	}
}

// SetDynamic marks a fragment and all related fragments as dynamic.
// Thread-safe public version.
func (m *Manager) SetDynamic(fragment *Fragment) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setDynamicLocked(fragment)
}

// getRelatedFragmentsForFragmentLocked returns all related fragments (duplicates + equivalents).
// Must be called with lock held.
func (m *Manager) getRelatedFragmentsForFragmentLocked(fragment *Fragment) []*Fragment {
	related := make([]*Fragment, 0)
	related = append(related, m.getDuplicateFragmentsLocked(fragment)...)
	related = append(related, m.getEquivalentFragmentsLocked(fragment)...)
	return related
}

// IsDynamic checks if a fragment is known to be dynamic.
func (m *Manager) IsDynamic(domHash string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if frag, ok := m.fragments[domHash]; ok {
		return frag.IsDynamic
	}

	return m.changeCount[domHash] >= m.dynamicThreshold
}

// GetDynamicFragments returns all fragments marked as dynamic.
func (m *Manager) GetDynamicFragments() []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	dynamic := make([]*Fragment, 0)
	for _, frag := range m.fragments {
		if frag.IsDynamic {
			dynamic = append(dynamic, frag.Clone())
		}
	}

	return dynamic
}

// GetStaticFragments returns all fragments NOT marked as dynamic.
func (m *Manager) GetStaticFragments() []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	static := make([]*Fragment, 0)
	for _, frag := range m.fragments {
		if !frag.IsDynamic {
			static = append(static, frag.Clone())
		}
	}

	return static
}

// GetFragmentCount returns the total number of unique fragments.
func (m *Manager) GetFragmentCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.fragments)
}

// GetStateCount returns the number of states with fragments.
func (m *Manager) GetStateCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.stateFragments)
}

// ========================================================================
// ========================================================================

// statePairKey generates a canonical key for two state IDs.
func statePairKey(stateID1, stateID2 string) string {
	if stateID1 < stateID2 {
		return stateID1 + "|" + stateID2
	}
	return stateID2 + "|" + stateID1
}

// GetCachedComparison returns a cached comparison result, or nil if not cached.
func (m *Manager) GetCachedComparison(stateID1, stateID2 string) *StatePairResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stateComparisonCache[statePairKey(stateID1, stateID2)]
}

// CacheStateComparison caches a state comparison result and handles dynamic fragment assignment.
// When assignDynamic=true and ND detected, marks changed fragments as dynamic using
// the fragments from state1 that differ from state2.
func (m *Manager) CacheStateComparison(result *StatePairResult, assignDynamic bool, dynamicFragments ...*Fragment) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := statePairKey(result.State1ID, result.State2ID)
	if _, exists := m.stateComparisonCache[key]; exists {
		return // Already cached
	}

	m.stateComparisonCache[key] = result

	// mark changed fragments as dynamic.
	if assignDynamic &&
		(result.Comparison == StateComparisonNearDuplicate1 || result.Comparison == StateComparisonNearDuplicate2) {
		for _, dyn := range dynamicFragments {
			m.setDynamicLocked(dyn)
		}
	}
}

// AddToNearDuplicates adds states to near-duplicate tracking.
// Also links ND2 fragments between root fragments when applicable.
// The caller is responsible for calling state.SetHasNearDuplicate(true) and
// merging cluster IDs on both states (lowest cluster wins).
func (m *Manager) AddToNearDuplicates(stateID1, stateID2 string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find existing set containing either state
	for _, set := range m.nearDuplicates {
		if set[stateID1] || set[stateID2] {
			set[stateID1] = true
			set[stateID2] = true
			m.linkND2RootFragmentsLocked(stateID1, stateID2)
			return
		}
	}

	// No existing set — create new one
	newSet := map[string]bool{stateID1: true, stateID2: true}
	m.nearDuplicates = append(m.nearDuplicates, newSet)

	m.linkND2RootFragmentsLocked(stateID1, stateID2)
}

// linkND2RootFragmentsLocked links root fragments of two ND states as ND2.
// if both states have root fragments and newState's root is not accessTransferred,
// add ND2 link between root fragments.
func (m *Manager) linkND2RootFragmentsLocked(stateID1, stateID2 string) {
	root1 := m.getRootFragmentForStateLocked(stateID1)
	root2 := m.getRootFragmentForStateLocked(stateID2)
	if root1 != nil && root2 != nil && !root1.AccessTransferred {
		root1.AddND2FragmentRef(root2)
	}
}

// getRootFragmentForStateLocked finds the root fragment for a state.
func (m *Manager) getRootFragmentForStateLocked(stateID string) *Fragment {
	ids, ok := m.stateFragments[stateID]
	if !ok {
		return nil
	}
	for _, id := range ids {
		if hash, ok := m.fragmentIDToHash[id]; ok {
			if frag, ok := m.fragments[hash]; ok {
				if frag.ParentID == 0 || frag.Parent == nil {
					return frag
				}
			}
		}
	}
	return nil
}

// AddToNearDuplicatesSingle adds a state to near-duplicate tracking (solo).
func (m *Manager) AddToNearDuplicatesSingle(stateID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, set := range m.nearDuplicates {
		if set[stateID] {
			return // Already tracked
		}
	}

	newSet := map[string]bool{stateID: true}
	m.nearDuplicates = append(m.nearDuplicates, newSet)
}

// GetNearDuplicateStates returns all states that are near-duplicates of the given state.
func (m *Manager) GetNearDuplicateStates(stateID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0)
	for _, set := range m.nearDuplicates {
		if set[stateID] {
			for id := range set {
				result = append(result, id)
			}
		}
	}
	return result
}

// HasExploredNearDuplicate checks if a state has a near-duplicate that has been fully explored.
// hasUnexploredFunc: returns true if the state still has unexplored actions.
func (m *Manager) HasExploredNearDuplicate(stateID string, hasUnexploredFunc func(string) bool) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if hasUnexploredFunc != nil && !hasUnexploredFunc(stateID) {
		return true // The state itself is fully explored
	}

	for _, set := range m.nearDuplicates {
		if !set[stateID] {
			continue
		}
		for ndID := range set {
			if ndID == stateID {
				continue
			}
			if hasUnexploredFunc != nil && !hasUnexploredFunc(ndID) {
				return true
			}
		}
		break
	}

	return false
}

// SeenState updates non-selection counters for state selection.
func (m *Manager) SeenState(stateID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	currentInt := hashStringToInt(stateID)

	if _, exists := m.numNonSelections[currentInt]; !exists {
		m.numNonSelections[currentInt] = 0.0
	}

	for key := range m.numNonSelections {
		if key == currentInt {
			m.numNonSelections[key] = 0.0
		} else {
			m.numNonSelections[key]++
		}
	}
}

// StopCrawling clears all manager state to free memory.
func (m *Manager) StopCrawling() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fragments = nil
	m.globalFragments = nil
	m.hops = nil
	m.nearDuplicates = nil
	m.stateComparisonCache = nil
}

// Clear removes all fragments.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fragments = make(map[string]*Fragment)
	m.globalFragments = make([]*Fragment, 0)
	m.fragmentIDToHash = make(map[int]string)
	m.stateFragments = make(map[string][]int)
	m.changeCount = make(map[string]int)
	m.stateComparisonCache = make(map[string]*StatePairResult)
	m.hops = make(map[int]float64)
	m.numNonSelections = make(map[int]float64)
}

// GetStats returns fragment statistics.
func (m *Manager) GetStats() FragmentStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := FragmentStats{
		TotalFragments:   len(m.fragments),
		GlobalFragments:  len(m.globalFragments),
		TotalStates:      len(m.stateFragments),
		DynamicFragments: 0,
		StaticFragments:  0,
	}

	for _, frag := range m.fragments {
		if frag.IsDynamic {
			stats.DynamicFragments++
		} else {
			stats.StaticFragments++
		}
	}

	return stats
}

// FragmentStats holds fragment statistics.
type FragmentStats struct {
	TotalFragments   int
	GlobalFragments  int
	TotalStates      int
	DynamicFragments int
	StaticFragments  int
}

// updateInfluenceLocked updates the influence of a fragment and recursively propagates
// UP the entire parent chain.
// Must be called with lock held.
func (m *Manager) updateInfluenceLocked(fragment *Fragment, accessType AccessType) {
	if fragment == nil {
		return
	}

	parent := fragment.Parent
	if parent == nil && fragment.ParentID >= 0 {
		// Fallback: resolve via ParentID + hash lookup (for cloned fragments without pointers)
		if parentHash, ok := m.fragmentIDToHash[fragment.ParentID]; ok {
			parent = m.fragments[parentHash]
		}
	}
	if parent != nil {
		m.updateInfluenceLocked(parent, accessType)
	}

	if fragment.InfluencePtr == nil {
		return
	}

	switch accessType {
	case AccessTypeDirect:
		fragment.Influence -= 1.0
	case AccessTypeDuplicate:
		fragment.Influence -= 0.5
	case AccessTypeEquivalent:
		fragment.Influence -= 0.25
	}
}

// UpdateInfluence updates the influence of a fragment based on access type.
// Thread-safe public version.
func (m *Manager) UpdateInfluence(domHash string, accessType AccessType) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if frag, ok := m.fragments[domHash]; ok {
		m.updateInfluenceLocked(frag, accessType)
	}
}

// PropagateInfluence propagates influence changes to parent fragments.
// Thread-safe public version.
func (m *Manager) PropagateInfluence(domHash string, accessType AccessType) {
	m.mu.Lock()
	defer m.mu.Unlock()

	frag, ok := m.fragments[domHash]
	if !ok {
		return
	}
	m.updateInfluenceLocked(frag, accessType)
}

// GetFragmentInfluence returns the influence score for a fragment.
func (m *Manager) GetFragmentInfluence(domHash string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if frag, ok := m.fragments[domHash]; ok {
		return frag.GetInfluence()
	}
	return 1.0 // Default influence for unknown fragments
}

// GetHighInfluenceFragments returns fragments with influence above threshold.
func (m *Manager) GetHighInfluenceFragments(threshold float64) []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Fragment, 0)
	for _, frag := range m.fragments {
		if frag.GetInfluence() >= threshold {
			result = append(result, frag.Clone())
		}
	}
	return result
}

// CalculateCandidateInfluence calculates influence for a candidate element.
// This considers the fragment it belongs to and its access history.
func (m *Manager) CalculateCandidateInfluence(xpath string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Find fragment that contains this xpath
	for _, frag := range m.fragments {
		// Simple containment check - element xpath should start with fragment xpath
		if len(frag.XPath) > 0 && len(xpath) >= len(frag.XPath) {
			if xpath[:len(frag.XPath)] == frag.XPath {
				return frag.GetInfluence()
			}
		}
	}

	return 1.0 // Default influence for elements not in any fragment
}

// GetParentFragment returns the parent fragment of a given fragment.
func (m *Manager) GetParentFragment(domHash string) *Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	frag, ok := m.fragments[domHash]
	if !ok || frag.ParentID < 0 {
		return nil
	}

	if parentHash, ok := m.fragmentIDToHash[frag.ParentID]; ok {
		if parent, ok := m.fragments[parentHash]; ok {
			return parent.Clone()
		}
	}
	return nil
}

// AreRelated checks if two fragments are related (same ND cluster or ND2 relationship).
// This is used during backtracking to verify fragment equivalence.
func (m *Manager) AreRelated(hash1, hash2 string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Same hash = same fragment
	if hash1 == hash2 {
		return true
	}

	frag1, ok1 := m.fragments[hash1]
	frag2, ok2 := m.fragments[hash2]
	if !ok1 || !ok2 {
		return false
	}

	// Check if in same ND cluster
	if frag1.ClusterID != 0 && frag1.ClusterID == frag2.ClusterID {
		return true
	}

	// Check ND2 relationship (bidirectional)
	if frag1.HasND2Relation(hash2) || frag2.HasND2Relation(hash1) {
		return true
	}

	return false
}

// GetRelatedFragments returns all fragments related to the given one.
// Related = same ND cluster or ND2 relationship.
func (m *Manager) GetRelatedFragments(domHash string) []*Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	related := make([]*Fragment, 0)
	frag, ok := m.fragments[domHash]
	if !ok {
		return related
	}

	// Same cluster fragments
	if frag.ClusterID != 0 {
		for hash, f := range m.fragments {
			if hash != domHash && f.ClusterID == frag.ClusterID {
				related = append(related, f.Clone())
			}
		}
	}

	// ND2 fragments
	for _, nd2Hash := range frag.ND2Fragments {
		if f, ok := m.fragments[nd2Hash]; ok {
			// Avoid duplicates
			found := false
			for _, r := range related {
				if r.DOMHash == nd2Hash {
					found = true
					break
				}
			}
			if !found {
				related = append(related, f.Clone())
			}
		}
	}

	return related
}

// SetFragmentCluster assigns a fragment to an ND cluster.
func (m *Manager) SetFragmentCluster(domHash string, clusterID int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if frag, ok := m.fragments[domHash]; ok {
		frag.ClusterID = clusterID
	}
}

// AddND2Relationship creates an ND2 relationship between two fragments.
func (m *Manager) AddND2Relationship(hash1, hash2 string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if frag1, ok := m.fragments[hash1]; ok {
		frag1.AddND2Fragment(hash2)
	}
	if frag2, ok := m.fragments[hash2]; ok {
		frag2.AddND2Fragment(hash1)
	}
}

// GetFragmentByXPath finds the fragment that best matches the given XPath.
func (m *Manager) GetFragmentByXPath(xpath string) *Fragment {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var bestMatch *Fragment
	bestLength := 0

	for _, frag := range m.fragments {
		if len(frag.XPath) > 0 && len(xpath) >= len(frag.XPath) {
			if xpath[:len(frag.XPath)] == frag.XPath {
				if len(frag.XPath) > bestLength {
					bestMatch = frag
					bestLength = len(frag.XPath)
				}
			}
		}
	}

	if bestMatch != nil {
		return bestMatch.Clone()
	}
	return nil
}

// ========================================================================
// ========================================================================

// RecordAccess records access to a candidate element and propagates to related fragments.
// Returns true if access was successfully recorded.
func (m *Manager) RecordAccess(element *CandidateElement, stateFragments []*Fragment, rootFragment *Fragment) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Set access if root fragment exists and access not yet transferred
	if rootFragment != nil && !rootFragment.AccessTransferred {
		m.setAccessForStateLocked(stateFragments)
	}

	// Mark element as directly accessed
	element.SetDirectAccess(true)

	coveredCandidates := make([]*CandidateElement, 0)
	closestFragment := m.getClosestFragmentLocked(element, stateFragments)

	if closestFragment == nil {
		return false
	}

	m.updateInfluenceLocked(closestFragment, AccessTypeDirect)

	// Record duplicate access
	m.recordDuplicateAccessLocked(element, &coveredCandidates, closestFragment)

	// Record equivalent access
	m.recordEquivalentAccessLocked(element, &coveredCandidates, closestFragment)

	// domAccessNeed = closestFragment.getFragmentParentNode() == null
	//     || state.getClosestDomFragment(element).getId() != state.getClosestFragment(element).getId()
	closestDomFragment := m.getClosestDomFragmentLocked(element, stateFragments)
	// In Go, we check if Parent is nil (fragment has no single parent DOM node)
	domAccessNeed := closestFragment.Parent == nil ||
		(closestDomFragment != nil && closestDomFragment.ID != closestFragment.ID)

	if domAccessNeed && closestDomFragment != nil {
		// Second round of duplicate + equivalent access via DOM fragment
		m.recordDuplicateAccessLocked(element, &coveredCandidates, closestDomFragment)
		m.recordEquivalentAccessLocked(element, &coveredCandidates, closestDomFragment)
	}

	// which has access to stateID for near-duplicate lookup.
	return true
}

// recordNearDuplicateAccessLocked records equivalent access on near-duplicate partner states.
// Must be called with lock held.
func (m *Manager) recordNearDuplicateAccessLocked(element *CandidateElement, stateID string, rootFragment *Fragment) {
	if rootFragment == nil {
		return
	}

	// Check if state has near-duplicates
	ndStates := m.getNearDuplicateStatesLocked(stateID)
	if len(ndStates) == 0 {
		return
	}

	coveredCandidates := make([]*CandidateElement, 0)

	for _, ndStateID := range ndStates {
		if ndStateID == stateID {
			continue
		}

		// Get root fragment of the ND partner state
		ndFragments := m.getFragmentsForStateLocked(ndStateID)
		var ndRootFragment *Fragment
		for _, frag := range ndFragments {
			if frag.ParentID == 0 || frag.Parent == nil {
				ndRootFragment = frag
				break
			}
		}
		if ndRootFragment == nil {
			continue
		}

		// via DOM node matching. In Go, we match by XPath/selector since we lack live DOM nodes.
		found := false
		for _, candidate := range ndRootFragment.CandidateElements {
			if candidate == nil {
				continue
			}
			// Check if this candidate is already covered
			alreadyCovered := false
			for _, existing := range coveredCandidates {
				if existing == candidate {
					alreadyCovered = true
					break
				}
			}
			if alreadyCovered {
				continue
			}
			// Match by XPath or selector
			if (element.XPath != "" && candidate.XPath == element.XPath) ||
				(element.Selector != "" && candidate.Selector == element.Selector) {
				candidate.EquivalentAccess++
				coveredCandidates = append(coveredCandidates, candidate)
				m.updateInfluenceLocked(ndRootFragment, AccessTypeEquivalent)
				found = true
			}
		}
		_ = found
	}
}

// getNearDuplicateStatesLocked returns all ND partner state IDs (lock held).
func (m *Manager) getNearDuplicateStatesLocked(stateID string) []string {
	var result []string
	for _, set := range m.nearDuplicates {
		if set[stateID] {
			for id := range set {
				result = append(result, id)
			}
			return result
		}
	}
	return nil
}

// getFragmentsForStateLocked returns fragments for a state (lock held).
func (m *Manager) getFragmentsForStateLocked(stateID string) []*Fragment {
	ids, ok := m.stateFragments[stateID]
	if !ok {
		return nil
	}
	result := make([]*Fragment, 0, len(ids))
	for _, id := range ids {
		if hash, ok := m.fragmentIDToHash[id]; ok {
			if frag, ok := m.fragments[hash]; ok {
				result = append(result, frag)
			}
		}
	}
	return result
}

// RecordElementAccess records access to an action.CandidateElement for a state.
// This is the primary API called from Crawler after firing an action.
func (m *Manager) RecordElementAccess(element *action.CandidateElement, stateID string) bool {
	if element == nil {
		return false
	}

	// Get fragments for this state
	stateFragments := m.GetFragments(stateID)
	if len(stateFragments) == 0 {
		return false
	}

	// Find root fragment (first fragment with no parent or the largest one)
	var rootFragment *Fragment
	for _, frag := range stateFragments {
		if frag.ParentID == 0 {
			rootFragment = frag
			break
		}
	}
	if rootFragment == nil && len(stateFragments) > 0 {
		rootFragment = stateFragments[0]
	}

	// Convert action.CandidateElement to fragment.CandidateElement for internal use
	fragElement := &CandidateElement{
		XPath:            "",
		Selector:         "",
		TagName:          element.TagName,
		Text:             element.Text,
		DirectAccess:     false,
		DuplicateAccess:  0,
		EquivalentAccess: 0,
	}

	// Get identification for selector/xpath
	if ident := element.GetIdentification(); ident != nil {
		if ident.How == action.HowXPath {
			fragElement.XPath = ident.Value
			fragElement.Selector = "" // Clear CSS when XPath is used
		} else {
			fragElement.Selector = ident.Value
			fragElement.XPath = "" // Clear XPath when CSS/other is used
		}
	}

	// Call the internal RecordAccess with converted element
	result := m.RecordAccess(fragElement, stateFragments, rootFragment)

	m.mu.Lock()
	m.recordNearDuplicateAccessLocked(fragElement, stateID, rootFragment)
	m.mu.Unlock()

	return result
}

// setAccessForStateLocked transfers access info for all fragments in a state.
// Must be called with lock held.
func (m *Manager) setAccessForStateLocked(stateFragments []*Fragment) {
	for _, fragment := range stateFragments {
		if !fragment.IsUseful() {
			continue
		}
		m.setAccessLocked(fragment)
		m.setCoverageLocked(fragment)
		fragment.SetAccessTransferred(true)
	}
}

// getClosestFragmentLocked finds the closest fragment containing the element.
// Must be called with lock held.
func (m *Manager) getClosestFragmentLocked(element *CandidateElement, stateFragments []*Fragment) *Fragment {
	if element.ClosestFragment != nil {
		return element.ClosestFragment
	}

	var closestFragment *Fragment
	smallestArea := float64(-1)

	for _, frag := range stateFragments {
		// Check if element is within fragment bounds
		if m.fragmentContainsElementLocked(frag, element) {
			area := frag.Rect.Width * frag.Rect.Height
			if smallestArea < 0 || area < smallestArea {
				smallestArea = area
				closestFragment = frag
			}
		}
	}

	if closestFragment != nil {
		element.ClosestFragment = closestFragment
	}

	return closestFragment
}

// getClosestDomFragmentLocked finds the closest DOM-tree fragment containing the element.
// DOM fragments use XPath-based containment (DOM tree hierarchy) rather than visual bounds.
// Must be called with lock held.
func (m *Manager) getClosestDomFragmentLocked(element *CandidateElement, stateFragments []*Fragment) *Fragment {
	if element.ClosestDomFragment != nil {
		return element.ClosestDomFragment
	}

	var closestDomFragment *Fragment
	longestXPath := 0

	for _, frag := range stateFragments {
		// Check DOM tree containment via XPath prefix matching
		if len(frag.XPath) > 0 && len(element.XPath) >= len(frag.XPath) {
			if element.XPath[:len(frag.XPath)] == frag.XPath {
				// Prefer the deepest (most specific) fragment in DOM tree
				if len(frag.XPath) > longestXPath {
					longestXPath = len(frag.XPath)
					closestDomFragment = frag
				}
			}
		}
	}

	if closestDomFragment != nil {
		element.ClosestDomFragment = closestDomFragment
	}

	return closestDomFragment
}

// fragmentContainsElementLocked checks if a fragment contains the element.
// Must be called with lock held.
func (m *Manager) fragmentContainsElementLocked(frag *Fragment, element *CandidateElement) bool {
	// Check XPath containment
	if len(frag.XPath) > 0 && len(element.XPath) >= len(frag.XPath) {
		if element.XPath[:len(frag.XPath)] == frag.XPath {
			return true
		}
	}

	// Check rect containment
	fragRect := frag.Rect
	elemRect := element.Rect

	return elemRect.X >= fragRect.X &&
		elemRect.Y >= fragRect.Y &&
		elemRect.X+elemRect.Width <= fragRect.X+fragRect.Width &&
		elemRect.Y+elemRect.Height <= fragRect.Y+fragRect.Height
}

// recordDuplicateAccessLocked records duplicate access for related fragments.
// Must be called with lock held.
func (m *Manager) recordDuplicateAccessLocked(element *CandidateElement, coveredCandidates *[]*CandidateElement, closestFragment *Fragment) {
	duplicateFragments := m.getDuplicateFragmentsLocked(closestFragment)

	for _, dupFragment := range duplicateFragments {
		if dupFragment == closestFragment {
			continue
		}

		// Find equivalent candidate in duplicate fragment
		dupCandidates := m.recordDuplicateCandidateAccessLocked(element, closestFragment, dupFragment, *coveredCandidates)

		for _, dupCandidate := range dupCandidates {
			if !containsCandidate(*coveredCandidates, dupCandidate) {
				*coveredCandidates = append(*coveredCandidates, dupCandidate)
				dupFragment.RecordAccess(AccessTypeDuplicate)
			}
		}
	}
}

// recordEquivalentAccessLocked records equivalent access for related fragments.
// Must be called with lock held.
func (m *Manager) recordEquivalentAccessLocked(element *CandidateElement, coveredCandidates *[]*CandidateElement, closestFragment *Fragment) {
	equivalentFragments := m.getEquivalentFragmentsLocked(closestFragment)

	for _, equivFragment := range equivalentFragments {
		if equivFragment == closestFragment || !equivFragment.IsUseful() {
			continue
		}

		// Find equivalent candidate in equivalent fragment
		equivCandidates := m.recordEquivalentCandidateAccessLocked(element, closestFragment, equivFragment, *coveredCandidates)

		for _, equivCandidate := range equivCandidates {
			if !containsCandidate(*coveredCandidates, equivCandidate) {
				*coveredCandidates = append(*coveredCandidates, equivCandidate)
				equivFragment.RecordAccess(AccessTypeEquivalent)
			}
		}
	}
}

// recordDuplicateCandidateAccessLocked finds and records equivalent candidates in duplicate fragment.
// Must be called with lock held.
func (m *Manager) recordDuplicateCandidateAccessLocked(element *CandidateElement, sourceFragment, targetFragment *Fragment, coveredCandidates []*CandidateElement) []*CandidateElement {
	result := make([]*CandidateElement, 0)

	// For duplicates, find candidate with same relative position
	for _, candidate := range targetFragment.CandidateElements {
		if containsCandidate(coveredCandidates, candidate) {
			continue
		}

		// Match by relative XPath position within fragment
		if m.matchCandidateByPositionLocked(element, candidate, sourceFragment, targetFragment) {
			candidate.IncrementDuplicateAccess()
			result = append(result, candidate)
		}
	}

	return result
}

// recordEquivalentCandidateAccessLocked finds and records equivalent candidates in equivalent fragment.
// Must be called with lock held.
func (m *Manager) recordEquivalentCandidateAccessLocked(element *CandidateElement, sourceFragment, targetFragment *Fragment, coveredCandidates []*CandidateElement) []*CandidateElement {
	result := make([]*CandidateElement, 0)

	// For equivalents, match by tag + text similarity
	for _, candidate := range targetFragment.CandidateElements {
		if containsCandidate(coveredCandidates, candidate) {
			continue
		}

		// Match by tag and similar properties
		if m.matchCandidateBySimilarityLocked(element, candidate) {
			candidate.IncrementEquivalentAccess()
			result = append(result, candidate)
		}
	}

	return result
}

// matchCandidateByPositionLocked matches candidates by position within their fragments.
// Must be called with lock held.
func (m *Manager) matchCandidateByPositionLocked(source, target *CandidateElement, sourceFragment, targetFragment *Fragment) bool {
	// Same relative XPath structure
	if len(sourceFragment.XPath) == 0 || len(targetFragment.XPath) == 0 {
		return false
	}

	// Check if same tag and relative position
	if source.TagName != target.TagName {
		return false
	}

	// Extract relative XPath (suffix after fragment XPath)
	var sourceRelative, targetRelative string
	if len(source.XPath) > len(sourceFragment.XPath) {
		sourceRelative = source.XPath[len(sourceFragment.XPath):]
	}
	if len(target.XPath) > len(targetFragment.XPath) {
		targetRelative = target.XPath[len(targetFragment.XPath):]
	}

	return sourceRelative == targetRelative
}

// matchCandidateBySimilarityLocked matches candidates by content similarity.
// Must be called with lock held.
func (m *Manager) matchCandidateBySimilarityLocked(source, target *CandidateElement) bool {
	// Same tag name
	if source.TagName != target.TagName {
		return false
	}

	// Similar text content (for links/buttons)
	if source.Text == target.Text && source.Text != "" {
		return true
	}

	// Similar selector structure
	if source.Selector == target.Selector && source.Selector != "" {
		return true
	}

	return false
}

// containsCandidate checks if a candidate is in the list.
func containsCandidate(list []*CandidateElement, candidate *CandidateElement) bool {
	for _, c := range list {
		if c == candidate || (c.XPath == candidate.XPath && c.XPath != "") {
			return true
		}
	}
	return false
}

// ========================================================================
// ========================================================================

// StateInfo holds information about a state for selection purposes.
type StateInfo struct {
	StateID            string
	HasUnexploredCands bool
	RootFragment       *Fragment
}

// GetClosestUnexploredState selects the best state to explore next.
// Parameters:
//   - currentStateID: The current state we're in
//   - onURLStates: List of states reachable via URL navigation
//   - statesWithCandidates: Set of state IDs that have unexplored candidates
//   - applyNonSelAdvantage: Whether to apply non-selection advantage
//   - shortestPathFunc: Function to get shortest path length between states
//   - hasExploredNearDuplicateFunc: Function to check if state has explored near-duplicate
//
// Returns the state ID with highest influence, or empty string if none found.
func (m *Manager) GetClosestUnexploredState(
	currentStateID string,
	onURLStates []string,
	statesWithCandidates map[string]bool,
	allStates []StateInfo,
	applyNonSelAdvantage bool,
	shortestPathFunc func(source, target string) int,
	hasExploredNearDuplicateFunc func(stateID string) bool,
) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	maxInfluence := float64(-1000000)
	var maxStateID string

	unexploredStateFound := false
	unexploredNearDuplicateFound := false

	for _, state := range allStates {
		// Skip states without candidates
		if !statesWithCandidates[state.StateID] {
			continue
		}

		// Prioritize states with unexplored actions
		if !unexploredStateFound && state.HasUnexploredCands {
			unexploredStateFound = true
			maxInfluence = float64(-1000000)
			maxStateID = ""
		}

		// Further prioritize states without explored near-duplicates
		if unexploredStateFound && !unexploredNearDuplicateFound && !hasExploredNearDuplicateFunc(state.StateID) {
			unexploredNearDuplicateFound = true
			maxInfluence = float64(-1000000)
			maxStateID = ""
		}

		// Skip explored states if we found unexplored ones
		if unexploredStateFound && !state.HasUnexploredCands {
			continue
		}

		// Skip states with explored near-duplicates if we found ones without
		if unexploredNearDuplicateFound && hasExploredNearDuplicateFunc(state.StateID) {
			continue
		}

		// Calculate influence for this state
		candidateInfluence := m.calculateFragmentCandidateInfluenceLocked(state.RootFragment)
		hopInfluence := m.calculateHopsLocked(state.RootFragment, currentStateID, onURLStates, shortestPathFunc)

		// Initialize non-selection counter if needed
		stateIDInt := hashStringToInt(state.StateID)
		if _, exists := m.numNonSelections[stateIDInt]; !exists {
			m.numNonSelections[stateIDInt] = 1.0
		}
		nonSelectionAdvantage := m.numNonSelections[stateIDInt]

		influence := candidateInfluence - hopInfluence
		if applyNonSelAdvantage {
			influence += nonSelectionAdvantage
		}

		if influence > maxInfluence {
			maxInfluence = influence
			maxStateID = state.StateID
		}
	}

	return maxStateID
}

// calculateFragmentCandidateInfluenceLocked calculates the candidate influence for a fragment.
// Must be called with lock held.
func (m *Manager) calculateFragmentCandidateInfluenceLocked(fragment *Fragment) float64 {
	if fragment == nil {
		return 0.0
	}

	// Check if cached
	// null means "not yet computed". InfluencePtr != nil means it has been computed
	// (including the case where the computed value is 0.0).
	if fragment.InfluencePtr != nil {
		return fragment.Influence
	}

	fragmentInfluence := 0.0

	// Sum up children's influence
	for _, child := range fragment.Children {
		fragmentInfluence += m.calculateFragmentCandidateInfluenceLocked(child)
	}

	// Add influence from candidates in this fragment
	for _, candidate := range fragment.CandidateElements {
		if candidate.ClosestFragment == fragment {
			candidateInfluence := m.calculateCandidateInfluenceLocked(candidate)
			fragmentInfluence += candidateInfluence
		}
	}

	fragment.Influence = fragmentInfluence
	fragment.InfluencePtr = &fragmentInfluence
	return fragmentInfluence
}

// calculateCandidateInfluenceLocked calculates influence for a single candidate.
// Must be called with lock held.
func (m *Manager) calculateCandidateInfluenceLocked(candidate *CandidateElement) float64 {
	candidateInfluence := 1.0

	if candidate.DirectAccess {
		candidateInfluence = 0.0
	}

	// candidateInfluence = candidateInfluence - (0.5 * duplicateAccess + 0.25 * equivalentAccess)
	candidateInfluence -= (0.5*float64(candidate.DuplicateAccess) + 0.25*float64(candidate.EquivalentAccess))

	return candidateInfluence
}

// calculateHopsLocked calculates the average hops needed to reach a state.
// Must be called with lock held.
func (m *Manager) calculateHopsLocked(
	fragment *Fragment,
	currentStateID string,
	onURLStates []string,
	shortestPathFunc func(source, target string) int,
) float64 {
	if fragment == nil {
		return 0.0
	}

	targetStateID := fragment.ReferenceStateID
	if targetStateID == currentStateID {
		return 0.0
	}

	// Check cache
	targetStateInt := hashStringToInt(targetStateID)
	if cached, exists := m.hops[targetStateInt]; exists {
		return cached
	}

	// Calculate average hops from URL-loaded states
	averageHops := 0.0
	validStates := 0

	for _, onURLState := range onURLStates {
		pathLen := shortestPathFunc(onURLState, targetStateID)
		if pathLen >= 0 {
			averageHops += float64(pathLen)
			validStates++
		}
	}

	if validStates <= 0 {
		// State seems unreachable
		return -1.0
	}

	// +1 hop to load the URL
	averageHops = averageHops/float64(validStates) + 1.0

	// Cache the result
	m.hops[targetStateInt] = averageHops

	return averageHops
}

// CalculateCandidateInfluenceForElement calculates influence for a candidate element.
// Thread-safe public version.
func (m *Manager) CalculateCandidateInfluenceForElement(candidate *CandidateElement) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.calculateCandidateInfluenceLocked(candidate)
}

// CalculateDuplicationFactor calculates the duplication factor for a candidate.
// Higher factor = more duplicate/equivalent fragments = less valuable to explore.
func (m *Manager) CalculateDuplicationFactor(element *CandidateElement, stateFragments []*Fragment) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	closestFragment := m.getClosestFragmentLocked(element, stateFragments)
	if closestFragment == nil {
		return 1.0
	}

	factor := 0.0
	factor += 2*float64(len(m.getDuplicateFragmentsLocked(closestFragment))) - 1
	factor += float64(len(m.getEquivalentFragmentsLocked(closestFragment)))

	return factor
}

// IncrementNonSelection increments the non-selection counter for a state.
// This is called when a state is NOT selected for exploration.
func (m *Manager) IncrementNonSelection(stateID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stateInt := hashStringToInt(stateID)
	m.numNonSelections[stateInt]++
}

// ResetNonSelection resets the non-selection counter for a state.
// This is called when a state IS selected for exploration.
func (m *Manager) ResetNonSelection(stateID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stateInt := hashStringToInt(stateID)
	m.numNonSelections[stateInt] = 0
}

// hashStringToInt converts a string to an int (for map keys).
// Simple hash function for string -> int conversion.
func hashStringToInt(s string) int {
	h := 0
	for _, c := range s {
		h = 31*h + int(c)
	}
	return h
}
