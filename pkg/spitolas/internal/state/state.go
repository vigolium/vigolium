package state

import (
	"crypto/sha256"
	"fmt"
	"sync/atomic"
	"time"
)

var stateCounter uint64

// State represents a crawl state (DOM snapshot).
// CRAWLJAX PARITY: Matches Java StateVertex structure.
type State struct {
	ID          string    // SHA256(strippedDOM)[:16]
	Name        string    // "state_001", etc
	URL         string    // Page URL when captured
	StrippedDOM string    // Normalized DOM for comparison
	RawHTML     string    // Original HTML
	Depth       int       // Crawl depth from index
	CreatedAt   time.Time // When state was discovered

	// Near-duplicate tracking
	NearestStateID  string  // ID of most similar state
	DistToNearest   float64 // Distance to nearest state
	IsNearDuplicate bool    // True if differs only in dynamic content

	// CRAWLJAX PARITY: Cluster ID for grouping near-duplicates
	// In Java: int cluster (initially set to state id)
	ClusterID int

	// CRAWLJAX PARITY: Unexplored actions flag
	// In Java: boolean unexploredActions = true
	HasUnexploredActions bool

	// CRAWLJAX PARITY: URL navigation flag
	// In Java: boolean onURL
	OnURL bool

	// CRAWLJAX PARITY: Root fragment hash for fragment-based comparison
	RootFragmentHash string
}

// New creates a new state from URL, raw HTML, and stripped DOM.
func New(url, rawHTML, strippedDOM string, depth int) *State {
	// Generate ID from stripped DOM hash
	hash := sha256.Sum256([]byte(strippedDOM))
	id := fmt.Sprintf("%x", hash[:8])

	// Generate sequential name
	num := atomic.AddUint64(&stateCounter, 1)
	name := fmt.Sprintf("state_%03d", num)

	// CRAWLJAX PARITY: ClusterID initially set to sequential number
	// In Java: cluster = id (but id is int in Java)
	clusterID := int(num)

	return &State{
		ID:                   id,
		Name:                 name,
		URL:                  url,
		StrippedDOM:          strippedDOM,
		RawHTML:              rawHTML,
		Depth:                depth,
		CreatedAt:            time.Now(),
		NearestStateID:       "",
		DistToNearest:        0,
		IsNearDuplicate:      false,
		ClusterID:            clusterID,
		HasUnexploredActions: true, // CRAWLJAX PARITY: Default true
		OnURL:                false,
		RootFragmentHash:     "",
	}
}

// NewIndex creates the index (initial) state.
func NewIndex(url, rawHTML, strippedDOM string) *State {
	s := New(url, rawHTML, strippedDOM, 0)
	s.Name = "index"
	return s
}

// IsIndex returns true if this is the index state.
func (s *State) IsIndex() bool {
	return s.Depth == 0 || s.Name == "index"
}

// SetNearestState sets the nearest state information.
func (s *State) SetNearestState(stateID string, distance float64) {
	s.NearestStateID = stateID
	s.DistToNearest = distance
}

// MarkAsNearDuplicate marks this state as a near-duplicate.
func (s *State) MarkAsNearDuplicate() {
	s.IsNearDuplicate = true
}

// Clone creates a copy of the state.
func (s *State) Clone() *State {
	return &State{
		ID:                   s.ID,
		Name:                 s.Name,
		URL:                  s.URL,
		StrippedDOM:          s.StrippedDOM,
		RawHTML:              s.RawHTML,
		Depth:                s.Depth,
		CreatedAt:            s.CreatedAt,
		NearestStateID:       s.NearestStateID,
		DistToNearest:        s.DistToNearest,
		IsNearDuplicate:      s.IsNearDuplicate,
		ClusterID:            s.ClusterID,
		HasUnexploredActions: s.HasUnexploredActions,
		OnURL:                s.OnURL,
		RootFragmentHash:     s.RootFragmentHash,
	}
}

// CRAWLJAX PARITY: Additional methods for state management

// SetCluster sets the cluster ID for this state.
func (s *State) SetCluster(clusterID int) {
	s.ClusterID = clusterID
}

// GetCluster returns the cluster ID.
func (s *State) GetCluster() int {
	return s.ClusterID
}

// SetHasNearDuplicate sets the near-duplicate flag.
func (s *State) SetHasNearDuplicate(hasND bool) {
	s.IsNearDuplicate = hasND
}

// SetUnexploredActions sets whether state has unexplored actions.
func (s *State) SetUnexploredActions(hasUnexplored bool) {
	s.HasUnexploredActions = hasUnexplored
}

// SetOnURL sets whether state was reached via URL navigation.
func (s *State) SetOnURL(onURL bool) {
	s.OnURL = onURL
}

// SetRootFragmentHash sets the root fragment hash for comparison.
func (s *State) SetRootFragmentHash(hash string) {
	s.RootFragmentHash = hash
}

// String returns a string representation of the state.
func (s *State) String() string {
	return fmt.Sprintf("State{ID:%s, Name:%s, URL:%s, Depth:%d}",
		s.ID, s.Name, s.URL, s.Depth)
}

// Equals returns true if two states have the same ID.
func (s *State) Equals(other *State) bool {
	if other == nil {
		return false
	}
	return s.ID == other.ID
}

// DOMSize returns the length of the stripped DOM.
func (s *State) DOMSize() int {
	return len(s.StrippedDOM)
}

// RawSize returns the length of the raw HTML.
func (s *State) RawSize() int {
	return len(s.RawHTML)
}

// ResetCounter resets the state counter (for testing).
func ResetCounter() {
	atomic.StoreUint64(&stateCounter, 0)
}
