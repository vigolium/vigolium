package fragment

import (
	"crypto/sha256"
	"fmt"
)

// Rect represents a bounding rectangle.
type Rect struct {
	X      float64
	Y      float64
	Width  float64
	Height float64
}

// Contains returns true if this rect contains the other rect.
func (r Rect) Contains(other Rect) bool {
	return r.X <= other.X &&
		r.Y <= other.Y &&
		r.X+r.Width >= other.X+other.Width &&
		r.Y+r.Height >= other.Y+other.Height
}

// Overlaps returns true if this rect overlaps with the other rect.
func (r Rect) Overlaps(other Rect) bool {
	return r.X < other.X+other.Width &&
		r.X+r.Width > other.X &&
		r.Y < other.Y+other.Height &&
		r.Y+r.Height > other.Y
}

// Area returns the area of the rect.
func (r Rect) Area() float64 {
	return r.Width * r.Height
}

// FragmentComparison defines the result of comparing two fragments.
// CRAWLJAX PARITY: Matches Java FragmentComparision enum exactly.
type FragmentComparison int

const (
	// FragmentEqual - Fragments have identical DOM structure.
	// Note: In Java Crawljax, EQUAL means DOM + visual same.
	// Since we skip visual comparison, EQUAL means APTED distance = 0.
	FragmentEqual FragmentComparison = iota

	// FragmentEquivalent - Same DOM structure but different visual appearance.
	// Since we skip visual comparison, this is not used - treated as FragmentEqual.
	FragmentEquivalent

	// FragmentDifferent - Fragments have different DOM structure.
	FragmentDifferent

	// FragmentND2 - Near-duplicate type 2 (partial structural similarity).
	FragmentND2
)

// String returns string representation of FragmentComparison.
func (fc FragmentComparison) String() string {
	switch fc {
	case FragmentEqual:
		return "EQUAL"
	case FragmentEquivalent:
		return "EQUIVALENT"
	case FragmentDifferent:
		return "DIFFERENT"
	case FragmentND2:
		return "ND2"
	default:
		return "UNKNOWN"
	}
}

// Fragment represents a DOM region on the page.
// CRAWLJAX PARITY: Matches Java Fragment class structure.
type Fragment struct {
	ID       int
	ParentID int
	ChildIDs []int

	// DOM info
	XPath       string // XPath to fragment root node
	Selector    string // CSS selector
	TagName     string // Root element tag
	SubtreeSize int    // Number of nodes in subtree

	// Bounding rect (from element.getBoundingClientRect)
	Rect Rect

	// State tracking
	IsDynamic   bool // Changes frequently between states
	AccessCount int  // How many times visited

	// For comparison
	DOMHash     string // Hash of subtree structure
	ContentHash string // Hash of text content

	// CRAWLJAX PARITY: Fragment relationships (matches Java Fragment.java)
	// These are bidirectional links maintained by FragmentManager
	EquivalentFragments []*Fragment // Fragments with same DOM but different visual (skip visual = same as duplicates)
	DuplicateFragments  []*Fragment // Exact duplicate fragments
	ND2FragmentRefs     []*Fragment // Near-duplicate type 2 related fragments

	// CRAWLJAX PARITY: Fragment hierarchy
	Parent      *Fragment   // Parent fragment in hierarchy
	Children    []*Fragment // Child fragments
	DOMParent   *Fragment   // Parent in DOM tree (may differ from visual hierarchy)
	DOMChildren []*Fragment // Children in DOM tree

	// CRAWLJAX PARITY: Global fragment status
	IsGlobal          bool // True if this is a unique global fragment (not a duplicate)
	AccessTransferred bool // True if access info has been transferred from related fragments

	// CRAWLJAX PARITY: Cached usefulness check
	usefulCached *bool // Cached result of IsUseful()

	// Reference to the state containing this fragment
	ReferenceStateID string // ID of the state this fragment belongs to

	// CRAWLJAX PARITY: Influence tracking for prioritization
	// Higher influence = more likely to reveal new content
	Influence       float64  // Current influence score (nil = not computed)
	InfluencePtr    *float64 // Pointer for nil check (Java uses Double object)
	DirectAccess    bool     // Was directly accessed (clicked/submitted)
	DuplicateCount  int      // Times led to duplicate state
	EquivalentCount int      // Times was equivalent to another fragment

	// CRAWLJAX PARITY: Near-duplicate clustering
	ClusterID    int      // ND cluster ID (0 = not clustered)
	ND2Fragments []string // DOM hashes of ND2-related fragments (legacy, use ND2FragmentRefs instead)

	// CRAWLJAX PARITY: APTED tree cache
	aptedTree *APTEDNode // Cached APTED tree representation

	// CRAWLJAX PARITY: Candidate elements contained in this fragment
	// In Java: ArrayList<CandidateElement> candidates
	CandidateElements []*CandidateElement
}

// NewFragment creates a new fragment.
func NewFragment(id int, xpath string, rect Rect, subtreeSize int) *Fragment {
	influence := 1.0
	return &Fragment{
		ID:                  id,
		ParentID:            -1,
		ChildIDs:            []int{},
		XPath:               xpath,
		Rect:                rect,
		SubtreeSize:         subtreeSize,
		IsDynamic:           false,
		AccessCount:         0,
		Influence:           influence,
		InfluencePtr:        &influence, // CRAWLJAX PARITY: Non-nil means computed
		IsGlobal:            false,      // Will be set by FragmentManager.addFragment()
		EquivalentFragments: []*Fragment{},
		DuplicateFragments:  []*Fragment{},
		ND2FragmentRefs:     []*Fragment{},
		Children:            []*Fragment{},
		DOMChildren:         []*Fragment{},
	}
}

// FragmentRules defines thresholds for determining useful fragments.
// CRAWLJAX PARITY: Matches Java FragmentRules class exactly.
type FragmentRules struct {
	ThresholdWidth  float64 // Minimum width for useful fragment (default: 50)
	ThresholdHeight float64 // Minimum height for useful fragment (default: 50)
	SubtreeWidthAnd int     // Minimum nodes when width/height pass (AND condition, default: 1)
	SubtreeWidthOr  int     // Minimum nodes regardless of size (OR condition, default: 4)
}

// DefaultFragmentRules returns the default fragment rules matching Java Crawljax.
func DefaultFragmentRules() *FragmentRules {
	return &FragmentRules{
		ThresholdWidth:  50,
		ThresholdHeight: 50,
		SubtreeWidthAnd: 1,
		SubtreeWidthOr:  4,
	}
}

// Global fragment rules (can be overridden via SetFragmentRules)
var globalFragmentRules = DefaultFragmentRules()

// SetFragmentRules sets the global fragment rules.
func SetFragmentRules(rules *FragmentRules) {
	globalFragmentRules = rules
}

// GetFragmentRules returns the current global fragment rules.
func GetFragmentRules() *FragmentRules {
	return globalFragmentRules
}

// IsUseful returns true if the fragment is large enough to be useful.
// CRAWLJAX PARITY: Matches Java usefulFragment() logic exactly:
// (width > threshold AND height > threshold AND nodes >= subtreeWidthAnd)
// OR (nodes >= subtreeWidthOr)
func (f *Fragment) IsUseful() bool {
	// Check cached result
	if f.usefulCached != nil {
		return *f.usefulCached
	}

	rules := globalFragmentRules
	subtreeWidth := f.SubtreeSize

	// CRAWLJAX PARITY: Java condition exactly:
	// (width > 50 AND height > 50 AND nodes >= 1) OR nodes >= 4
	useful := (f.Rect.Width > rules.ThresholdWidth &&
		f.Rect.Height > rules.ThresholdHeight &&
		subtreeWidth >= rules.SubtreeWidthAnd) ||
		subtreeWidth >= rules.SubtreeWidthOr

	// Cache the result
	f.usefulCached = &useful
	return useful
}

// IsUsefulWithRules checks usefulness with custom rules.
func (f *Fragment) IsUsefulWithRules(rules *FragmentRules) bool {
	subtreeWidth := f.SubtreeSize
	return (f.Rect.Width > rules.ThresholdWidth &&
		f.Rect.Height > rules.ThresholdHeight &&
		subtreeWidth >= rules.SubtreeWidthAnd) ||
		subtreeWidth >= rules.SubtreeWidthOr
}

// ClearUsefulCache clears the cached usefulness result.
func (f *Fragment) ClearUsefulCache() {
	f.usefulCached = nil
}

// Contains returns true if this fragment contains another fragment.
func (f *Fragment) Contains(other *Fragment) bool {
	return f.Rect.Contains(other.Rect)
}

// SetDOMHash sets the DOM hash from content.
func (f *Fragment) SetDOMHash(content string) {
	hash := sha256.Sum256([]byte(content))
	f.DOMHash = fmt.Sprintf("%x", hash[:8])
}

// SetContentHash sets the content hash from text content.
func (f *Fragment) SetContentHash(content string) {
	hash := sha256.Sum256([]byte(content))
	f.ContentHash = fmt.Sprintf("%x", hash[:8])
}

// AddChild adds a child fragment ID.
func (f *Fragment) AddChild(childID int) {
	f.ChildIDs = append(f.ChildIDs, childID)
}

// SetParent sets the parent fragment ID.
func (f *Fragment) SetParent(parentID int) {
	f.ParentID = parentID
}

// HasParent returns true if fragment has a parent.
func (f *Fragment) HasParent() bool {
	return f.ParentID >= 0
}

// HasChildren returns true if fragment has children.
func (f *Fragment) HasChildren() bool {
	return len(f.ChildIDs) > 0
}

// IsRoot returns true if fragment has no parent.
func (f *Fragment) IsRoot() bool {
	return f.ParentID < 0
}

// IsLeaf returns true if fragment has no children.
func (f *Fragment) IsLeaf() bool {
	return len(f.ChildIDs) == 0
}

// MarkDynamic marks this fragment as dynamic.
func (f *Fragment) MarkDynamic() {
	f.IsDynamic = true
}

// IncrementAccess increments the access count.
func (f *Fragment) IncrementAccess() {
	f.AccessCount++
}

// Clone creates a copy of the fragment.
// Note: Relationship pointers (EquivalentFragments, DuplicateFragments, etc.)
// are NOT deep copied - they point to the same fragments.
func (f *Fragment) Clone() *Fragment {
	childIDs := make([]int, len(f.ChildIDs))
	copy(childIDs, f.ChildIDs)

	nd2Fragments := make([]string, len(f.ND2Fragments))
	copy(nd2Fragments, f.ND2Fragments)

	influence := f.Influence
	return &Fragment{
		ID:                  f.ID,
		ParentID:            f.ParentID,
		ChildIDs:            childIDs,
		XPath:               f.XPath,
		Selector:            f.Selector,
		TagName:             f.TagName,
		SubtreeSize:         f.SubtreeSize,
		Rect:                f.Rect,
		IsDynamic:           f.IsDynamic,
		AccessCount:         f.AccessCount,
		DOMHash:             f.DOMHash,
		ContentHash:         f.ContentHash,
		Influence:           influence,
		InfluencePtr:        &influence,
		DirectAccess:        f.DirectAccess,
		DuplicateCount:      f.DuplicateCount,
		EquivalentCount:     f.EquivalentCount,
		ClusterID:           f.ClusterID,
		ND2Fragments:        nd2Fragments,
		IsGlobal:            f.IsGlobal,
		AccessTransferred:   f.AccessTransferred,
		ReferenceStateID:    f.ReferenceStateID,
		EquivalentFragments: f.EquivalentFragments, // Shallow copy
		DuplicateFragments:  f.DuplicateFragments,  // Shallow copy
		ND2FragmentRefs:     f.ND2FragmentRefs,     // Shallow copy
		Parent:              f.Parent,              // Shallow copy
		Children:            f.Children,            // Shallow copy
		DOMParent:           f.DOMParent,           // Shallow copy
		DOMChildren:         f.DOMChildren,         // Shallow copy
	}
}

// String returns a string representation of the fragment.
func (f *Fragment) String() string {
	hashStr := f.DOMHash
	if len(hashStr) > 8 {
		hashStr = hashStr[:8]
	}
	return fmt.Sprintf("Fragment{ID:%d, Tag:%s, Size:%d, Hash:%s, Dynamic:%v}",
		f.ID, f.TagName, f.SubtreeSize, hashStr, f.IsDynamic)
}

// CRAWLJAX PARITY: Influence tracking methods

// AccessType defines how a fragment was accessed (matches Java Crawljax).
type AccessType int

const (
	// AccessTypeDirect - fragment was directly accessed (action executed).
	AccessTypeDirect AccessType = iota
	// AccessTypeDuplicate - action led to already known state.
	AccessTypeDuplicate
	// AccessTypeEquivalent - action was equivalent to another.
	AccessTypeEquivalent
)

// RecordAccess updates influence based on access type.
// This matches Java Crawljax's influence tracking for prioritization.
func (f *Fragment) RecordAccess(accessType AccessType) {
	switch accessType {
	case AccessTypeDirect:
		f.DirectAccess = true
		f.Influence -= 1.0
	case AccessTypeDuplicate:
		f.DuplicateCount++
		f.Influence -= 0.5
	case AccessTypeEquivalent:
		f.EquivalentCount++
		f.Influence -= 0.25
	}

	// Clamp to minimum 0
	if f.Influence < 0 {
		f.Influence = 0
	}
}

// GetInfluence returns the current influence score.
func (f *Fragment) GetInfluence() float64 {
	return f.Influence
}

// ResetInfluence resets influence to default (1.0).
func (f *Fragment) ResetInfluence() {
	f.Influence = 1.0
	f.DirectAccess = false
	f.DuplicateCount = 0
	f.EquivalentCount = 0
}

// CRAWLJAX PARITY: Near-duplicate clustering methods

// SetCluster sets the ND cluster ID for this fragment.
func (f *Fragment) SetCluster(clusterID int) {
	f.ClusterID = clusterID
}

// AddND2Fragment adds an ND2-related fragment hash.
func (f *Fragment) AddND2Fragment(domHash string) {
	// Avoid duplicates
	for _, existing := range f.ND2Fragments {
		if existing == domHash {
			return
		}
	}
	f.ND2Fragments = append(f.ND2Fragments, domHash)
}

// HasND2Relation checks if this fragment has an ND2 relationship with another.
func (f *Fragment) HasND2Relation(domHash string) bool {
	for _, nd2Hash := range f.ND2Fragments {
		if nd2Hash == domHash {
			return true
		}
	}
	return false
}

// CRAWLJAX PARITY: Fragment relationship methods (matches Java Fragment.java)

// AddDuplicateFragment adds a duplicate fragment (bidirectional link).
func (f *Fragment) AddDuplicateFragment(other *Fragment) {
	// Avoid duplicates
	for _, existing := range f.DuplicateFragments {
		if existing == other {
			return
		}
	}
	f.DuplicateFragments = append(f.DuplicateFragments, other)
}

// AddEquivalentFragment adds an equivalent fragment (bidirectional link).
func (f *Fragment) AddEquivalentFragment(other *Fragment) {
	// Avoid duplicates
	for _, existing := range f.EquivalentFragments {
		if existing == other {
			return
		}
	}
	f.EquivalentFragments = append(f.EquivalentFragments, other)
}

// AddND2FragmentRef adds an ND2-related fragment reference (bidirectional link).
func (f *Fragment) AddND2FragmentRef(other *Fragment) {
	// Avoid duplicates
	for _, existing := range f.ND2FragmentRefs {
		if existing == other {
			return
		}
	}
	f.ND2FragmentRefs = append(f.ND2FragmentRefs, other)
	// Also add hash for legacy compatibility
	if other.DOMHash != "" {
		f.AddND2Fragment(other.DOMHash)
	}
}

// GetDuplicateFragments returns all duplicate fragments.
func (f *Fragment) GetDuplicateFragments() []*Fragment {
	return f.DuplicateFragments
}

// GetEquivalentFragments returns all equivalent fragments.
func (f *Fragment) GetEquivalentFragments() []*Fragment {
	return f.EquivalentFragments
}

// GetND2FragmentRefs returns all ND2-related fragment references.
func (f *Fragment) GetND2FragmentRefs() []*Fragment {
	return f.ND2FragmentRefs
}

// SetIsGlobal sets whether this fragment is a unique global fragment.
func (f *Fragment) SetIsGlobal(isGlobal bool) {
	f.IsGlobal = isGlobal
}

// SetAccessTransferred marks that access info has been transferred.
func (f *Fragment) SetAccessTransferred(transferred bool) {
	f.AccessTransferred = transferred
}

// SetReferenceState sets the state ID that contains this fragment.
func (f *Fragment) SetReferenceState(stateID string) {
	f.ReferenceStateID = stateID
}

// GetReferenceState returns the state ID containing this fragment.
func (f *Fragment) GetReferenceState() string {
	return f.ReferenceStateID
}

// SetParentFragment sets the parent fragment reference.
func (f *Fragment) SetParentFragment(parent *Fragment) {
	f.Parent = parent
}

// GetParentFragment returns the parent fragment.
func (f *Fragment) GetParentFragment() *Fragment {
	return f.Parent
}

// AddChildFragment adds a child fragment reference.
func (f *Fragment) AddChildFragment(child *Fragment) {
	for _, existing := range f.Children {
		if existing == child {
			return
		}
	}
	f.Children = append(f.Children, child)
}

// GetChildFragments returns all child fragments.
func (f *Fragment) GetChildFragments() []*Fragment {
	return f.Children
}

// SetDOMParent sets the DOM parent fragment.
func (f *Fragment) SetDOMParent(parent *Fragment) {
	f.DOMParent = parent
}

// AddDOMChild adds a DOM child fragment.
func (f *Fragment) AddDOMChild(child *Fragment) {
	for _, existing := range f.DOMChildren {
		if existing == child {
			return
		}
	}
	f.DOMChildren = append(f.DOMChildren, child)
}

// GetCandidateInfluence returns the cached candidate influence.
// Returns nil if not computed yet (matches Java Double behavior).
func (f *Fragment) GetCandidateInfluence() *float64 {
	return f.InfluencePtr
}

// SetCandidateInfluence sets the candidate influence.
func (f *Fragment) SetCandidateInfluence(influence float64) {
	f.Influence = influence
	f.InfluencePtr = &influence
}

// CRAWLJAX PARITY: APTED-based comparison methods

// Compare compares this fragment with another using APTED algorithm.
// CRAWLJAX PARITY: Matches Java Fragment.compare() but skips visual comparison.
// Since we skip visual comparison, EQUAL and EQUIVALENT are treated the same.
func (f *Fragment) Compare(other *Fragment) FragmentComparison {
	if f == nil || other == nil {
		return FragmentDifferent
	}

	// Fast path: if DOMHash matches exactly, they're equal
	if f.DOMHash != "" && other.DOMHash != "" && f.DOMHash == other.DOMHash {
		return FragmentEqual
	}

	// Build APTED trees from fragments
	thisTree := f.GetAPTEDTree()
	otherTree := other.GetAPTEDTree()

	if thisTree == nil || otherTree == nil {
		// Cannot build trees, fall back to hash comparison
		if f.DOMHash == other.DOMHash {
			return FragmentEqual
		}
		return FragmentDifferent
	}

	// Compute APTED distance
	apted := NewAPTED()
	distance := apted.Distance(thisTree, otherTree)

	// CRAWLJAX PARITY: If structural distance = 0, fragments are equal
	// Java Crawljax would check visual (compareImage) here, but we skip it
	if distance == 0 {
		return FragmentEqual
	}

	return FragmentDifferent
}

// CompareFast performs fast comparison by checking size first.
// CRAWLJAX PARITY: Matches Java Fragment.compareFast().
func (f *Fragment) CompareFast(other *Fragment) FragmentComparison {
	if f == nil || other == nil {
		return FragmentDifferent
	}

	// Fast path: check size first
	if f.SubtreeSize >= 0 && other.SubtreeSize >= 0 {
		if f.SubtreeSize != other.SubtreeSize {
			return FragmentDifferent // Size differs = different
		}
	}

	// Size matches, do full comparison
	return f.Compare(other)
}

// GetAPTEDTree builds or returns cached APTED tree for this fragment.
func (f *Fragment) GetAPTEDTree() *APTEDNode {
	if f.aptedTree != nil {
		return f.aptedTree
	}

	// Build tree from fragment info
	// This creates a simple tree from tag name and structure
	if f.TagName == "" {
		return nil
	}

	f.aptedTree = NewAPTEDNode(f.TagName)
	return f.aptedTree
}

// SetAPTEDTree sets the cached APTED tree.
func (f *Fragment) SetAPTEDTree(tree *APTEDNode) {
	f.aptedTree = tree
}

// ClearAPTEDTree clears the cached APTED tree.
func (f *Fragment) ClearAPTEDTree() {
	f.aptedTree = nil
}

// GetSize returns the subtree size (matches Java getSize()).
func (f *Fragment) GetSize() int {
	return f.SubtreeSize
}
