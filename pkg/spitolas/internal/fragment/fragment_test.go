package fragment

import (
	"testing"
)

// =============================================================================
// =============================================================================

func TestRectContains(t *testing.T) {
	tests := []struct {
		name     string
		outer    Rect
		inner    Rect
		expected bool
	}{
		{
			name:     "exact same rect contains itself",
			outer:    Rect{X: 0, Y: 0, Width: 100, Height: 100},
			inner:    Rect{X: 0, Y: 0, Width: 100, Height: 100},
			expected: true,
		},
		{
			name:     "larger rect contains smaller",
			outer:    Rect{X: 0, Y: 0, Width: 100, Height: 100},
			inner:    Rect{X: 10, Y: 10, Width: 50, Height: 50},
			expected: true,
		},
		{
			name:     "smaller rect does not contain larger",
			outer:    Rect{X: 10, Y: 10, Width: 50, Height: 50},
			inner:    Rect{X: 0, Y: 0, Width: 100, Height: 100},
			expected: false,
		},
		{
			name:     "rect does not contain overlapping rect",
			outer:    Rect{X: 0, Y: 0, Width: 100, Height: 100},
			inner:    Rect{X: 50, Y: 50, Width: 100, Height: 100},
			expected: false,
		},
		{
			name:     "rect does not contain adjacent rect",
			outer:    Rect{X: 0, Y: 0, Width: 100, Height: 100},
			inner:    Rect{X: 100, Y: 0, Width: 100, Height: 100},
			expected: false,
		},
		{
			name:     "rect contains inner touching edges",
			outer:    Rect{X: 0, Y: 0, Width: 100, Height: 100},
			inner:    Rect{X: 0, Y: 0, Width: 50, Height: 100},
			expected: true,
		},
		{
			name:     "zero size rect contained in any rect",
			outer:    Rect{X: 0, Y: 0, Width: 100, Height: 100},
			inner:    Rect{X: 50, Y: 50, Width: 0, Height: 0},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.outer.Contains(tt.inner)
			if result != tt.expected {
				t.Errorf("Contains() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRectOverlaps(t *testing.T) {
	tests := []struct {
		name     string
		r1       Rect
		r2       Rect
		expected bool
	}{
		{
			name:     "same rect overlaps",
			r1:       Rect{X: 0, Y: 0, Width: 100, Height: 100},
			r2:       Rect{X: 0, Y: 0, Width: 100, Height: 100},
			expected: true,
		},
		{
			name:     "overlapping rects",
			r1:       Rect{X: 0, Y: 0, Width: 100, Height: 100},
			r2:       Rect{X: 50, Y: 50, Width: 100, Height: 100},
			expected: true,
		},
		{
			name:     "contained rect overlaps",
			r1:       Rect{X: 0, Y: 0, Width: 100, Height: 100},
			r2:       Rect{X: 25, Y: 25, Width: 50, Height: 50},
			expected: true,
		},
		{
			name:     "adjacent rects do not overlap",
			r1:       Rect{X: 0, Y: 0, Width: 100, Height: 100},
			r2:       Rect{X: 100, Y: 0, Width: 100, Height: 100},
			expected: false,
		},
		{
			name:     "separated rects do not overlap",
			r1:       Rect{X: 0, Y: 0, Width: 50, Height: 50},
			r2:       Rect{X: 100, Y: 100, Width: 50, Height: 50},
			expected: false,
		},
		{
			name:     "vertical adjacent do not overlap",
			r1:       Rect{X: 0, Y: 0, Width: 100, Height: 100},
			r2:       Rect{X: 0, Y: 100, Width: 100, Height: 100},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.r1.Overlaps(tt.r2)
			if result != tt.expected {
				t.Errorf("Overlaps() = %v, want %v", result, tt.expected)
			}
			// Test symmetry
			reverse := tt.r2.Overlaps(tt.r1)
			if reverse != tt.expected {
				t.Errorf("Overlaps() (reverse) = %v, want %v", reverse, tt.expected)
			}
		})
	}
}

func TestRectArea(t *testing.T) {
	tests := []struct {
		name     string
		rect     Rect
		expected float64
	}{
		{
			name:     "100x100 rect",
			rect:     Rect{X: 0, Y: 0, Width: 100, Height: 100},
			expected: 10000,
		},
		{
			name:     "50x200 rect",
			rect:     Rect{X: 10, Y: 20, Width: 50, Height: 200},
			expected: 10000,
		},
		{
			name:     "zero width",
			rect:     Rect{X: 0, Y: 0, Width: 0, Height: 100},
			expected: 0,
		},
		{
			name:     "zero height",
			rect:     Rect{X: 0, Y: 0, Width: 100, Height: 0},
			expected: 0,
		},
		{
			name:     "zero size",
			rect:     Rect{X: 50, Y: 50, Width: 0, Height: 0},
			expected: 0,
		},
		{
			name:     "1x1 rect",
			rect:     Rect{X: 0, Y: 0, Width: 1, Height: 1},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rect.Area()
			if result != tt.expected {
				t.Errorf("Area() = %f, want %f", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// =============================================================================

func TestNewFragment(t *testing.T) {
	rect := Rect{X: 100, Y: 200, Width: 300, Height: 400}
	f := NewFragment(42, "/html/body/div[1]", rect, 15)

	if f.ID != 42 {
		t.Errorf("ID = %d, want 42", f.ID)
	}
	if f.ParentID != -1 {
		t.Errorf("ParentID = %d, want -1 (default)", f.ParentID)
	}
	if f.XPath != "/html/body/div[1]" {
		t.Errorf("XPath = %q, want /html/body/div[1]", f.XPath)
	}
	if f.Rect != rect {
		t.Errorf("Rect = %+v, want %+v", f.Rect, rect)
	}
	if f.SubtreeSize != 15 {
		t.Errorf("SubtreeSize = %d, want 15", f.SubtreeSize)
	}
	if f.IsDynamic {
		t.Error("IsDynamic should be false by default")
	}
	if f.AccessCount != 0 {
		t.Errorf("AccessCount = %d, want 0", f.AccessCount)
	}
	if f.Influence != 1.0 {
		t.Errorf("Influence = %f, want 1.0 (default)", f.Influence)
	}
	if len(f.ChildIDs) != 0 {
		t.Errorf("ChildIDs = %v, want empty slice", f.ChildIDs)
	}
}

func TestFragmentIsUseful(t *testing.T) {
	// Formula: (width > 50 AND height > 50 AND nodes >= 1) OR nodes >= 4
	tests := []struct {
		name     string
		rect     Rect
		subtree  int
		expected bool
	}{
		{
			name:     "large fragment with many nodes - both conditions pass",
			rect:     Rect{Width: 100, Height: 100},
			subtree:  10,
			expected: true, // Passes first condition AND second condition
		},
		{
			name:     "exactly at minimum threshold - passes OR condition",
			rect:     Rect{Width: 50, Height: 50},
			subtree:  4,
			expected: true, // Fails first (50 not > 50), passes second (4 >= 4)
		},
		{
			name:     "small width but many nodes - passes OR condition",
			rect:     Rect{Width: 49, Height: 100},
			subtree:  10,
			expected: true, // Fails first (49 not > 50), passes second (10 >= 4)
		},
		{
			name:     "small height but many nodes - passes OR condition",
			rect:     Rect{Width: 100, Height: 49},
			subtree:  10,
			expected: true, // Fails first (49 not > 50), passes second (10 >= 4)
		},
		{
			name:     "large but too few nodes - passes first condition",
			rect:     Rect{Width: 100, Height: 100},
			subtree:  3,
			expected: true, // Passes first (100>50, 100>50, 3>=1), fails second (3<4)
		},
		{
			name:     "all below threshold - both conditions fail",
			rect:     Rect{Width: 30, Height: 30},
			subtree:  2,
			expected: false, // Fails first (30 not > 50), fails second (2 < 4)
		},
		{
			name:     "small size few nodes - both conditions fail",
			rect:     Rect{Width: 49, Height: 49},
			subtree:  3,
			expected: false, // Fails first (49 not > 50), fails second (3 < 4)
		},
		{
			name:     "just below OR threshold - fails both",
			rect:     Rect{Width: 40, Height: 40},
			subtree:  3,
			expected: false, // Fails first (40 not > 50), fails second (3 < 4)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFragment(1, "/html", tt.rect, tt.subtree)
			if result := f.IsUseful(); result != tt.expected {
				t.Errorf("IsUseful() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFragmentContains(t *testing.T) {
	outer := NewFragment(1, "/html/body", Rect{X: 0, Y: 0, Width: 800, Height: 600}, 50)
	inner := NewFragment(2, "/html/body/div", Rect{X: 100, Y: 100, Width: 200, Height: 200}, 10)
	separate := NewFragment(3, "/html/body/aside", Rect{X: 900, Y: 0, Width: 200, Height: 200}, 5)

	if !outer.Contains(inner) {
		t.Error("outer should contain inner")
	}
	if inner.Contains(outer) {
		t.Error("inner should not contain outer")
	}
	if outer.Contains(separate) {
		t.Error("outer should not contain separate")
	}
}

func TestFragmentSetDOMHash(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	f.SetDOMHash("div>p>span")
	if f.DOMHash == "" {
		t.Error("DOMHash should not be empty after SetDOMHash")
	}
	if len(f.DOMHash) != 16 {
		t.Errorf("DOMHash length = %d, want 16", len(f.DOMHash))
	}

	// Same content should produce same hash
	f2 := NewFragment(2, "/html", Rect{}, 5)
	f2.SetDOMHash("div>p>span")
	if f.DOMHash != f2.DOMHash {
		t.Errorf("Same content should produce same hash: %q != %q", f.DOMHash, f2.DOMHash)
	}

	// Different content should produce different hash
	f3 := NewFragment(3, "/html", Rect{}, 5)
	f3.SetDOMHash("div>p>a")
	if f.DOMHash == f3.DOMHash {
		t.Error("Different content should produce different hash")
	}
}

func TestFragmentSetContentHash(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	f.SetContentHash("Hello World")
	if f.ContentHash == "" {
		t.Error("ContentHash should not be empty after SetContentHash")
	}
	if len(f.ContentHash) != 16 {
		t.Errorf("ContentHash length = %d, want 16", len(f.ContentHash))
	}
}

func TestFragmentParentChild(t *testing.T) {
	parent := NewFragment(1, "/html/body", Rect{}, 50)
	child1 := NewFragment(2, "/html/body/div[1]", Rect{}, 10)
	child2 := NewFragment(3, "/html/body/div[2]", Rect{}, 10)

	// Initially no parent
	if parent.HasParent() {
		t.Error("parent should not have parent initially")
	}
	if child1.HasParent() {
		t.Error("child1 should not have parent initially")
	}

	// Set parent
	child1.SetParent(1)
	child2.SetParent(1)

	if !child1.HasParent() {
		t.Error("child1 should have parent after SetParent")
	}
	if child1.ParentID != 1 {
		t.Errorf("child1.ParentID = %d, want 1", child1.ParentID)
	}

	// Add children
	if parent.HasChildren() {
		t.Error("parent should not have children initially")
	}

	parent.AddChild(2)
	parent.AddChild(3)

	if !parent.HasChildren() {
		t.Error("parent should have children after AddChild")
	}
	if len(parent.ChildIDs) != 2 {
		t.Errorf("len(ChildIDs) = %d, want 2", len(parent.ChildIDs))
	}
	if parent.ChildIDs[0] != 2 || parent.ChildIDs[1] != 3 {
		t.Errorf("ChildIDs = %v, want [2, 3]", parent.ChildIDs)
	}
}

func TestFragmentIsRootIsLeaf(t *testing.T) {
	root := NewFragment(1, "/html", Rect{}, 100)
	middle := NewFragment(2, "/html/body", Rect{}, 50)
	leaf := NewFragment(3, "/html/body/p", Rect{}, 1)

	middle.SetParent(1)
	leaf.SetParent(2)
	root.AddChild(2)
	middle.AddChild(3)

	// Root tests
	if !root.IsRoot() {
		t.Error("root.IsRoot() should be true")
	}
	if root.IsLeaf() {
		t.Error("root.IsLeaf() should be false")
	}

	// Middle tests
	if middle.IsRoot() {
		t.Error("middle.IsRoot() should be false")
	}
	if middle.IsLeaf() {
		t.Error("middle.IsLeaf() should be false")
	}

	// Leaf tests
	if leaf.IsRoot() {
		t.Error("leaf.IsRoot() should be false")
	}
	if !leaf.IsLeaf() {
		t.Error("leaf.IsLeaf() should be true")
	}
}

func TestFragmentMarkDynamic(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	if f.IsDynamic {
		t.Error("should not be dynamic initially")
	}

	f.MarkDynamic()

	if !f.IsDynamic {
		t.Error("should be dynamic after MarkDynamic")
	}
}

func TestFragmentIncrementAccess(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	if f.AccessCount != 0 {
		t.Errorf("AccessCount = %d, want 0", f.AccessCount)
	}

	f.IncrementAccess()
	if f.AccessCount != 1 {
		t.Errorf("AccessCount = %d, want 1", f.AccessCount)
	}

	f.IncrementAccess()
	f.IncrementAccess()
	if f.AccessCount != 3 {
		t.Errorf("AccessCount = %d, want 3", f.AccessCount)
	}
}

func TestFragmentClone(t *testing.T) {
	original := NewFragment(1, "/html/body", Rect{X: 10, Y: 20, Width: 100, Height: 200}, 25)
	original.Selector = "body"
	original.TagName = "body"
	original.SetDOMHash("test hash content")
	original.SetContentHash("text content")
	original.IsDynamic = true
	original.AccessCount = 5
	original.Influence = 0.5
	original.DirectAccess = true
	original.DuplicateCount = 2
	original.EquivalentCount = 1
	original.ClusterID = 10
	original.AddChild(2)
	original.AddChild(3)
	original.AddND2Fragment("hash1")
	original.AddND2Fragment("hash2")

	clone := original.Clone()

	// Verify all fields
	if clone.ID != original.ID {
		t.Errorf("ID = %d, want %d", clone.ID, original.ID)
	}
	if clone.ParentID != original.ParentID {
		t.Errorf("ParentID = %d, want %d", clone.ParentID, original.ParentID)
	}
	if clone.XPath != original.XPath {
		t.Errorf("XPath = %q, want %q", clone.XPath, original.XPath)
	}
	if clone.Selector != original.Selector {
		t.Errorf("Selector = %q, want %q", clone.Selector, original.Selector)
	}
	if clone.TagName != original.TagName {
		t.Errorf("TagName = %q, want %q", clone.TagName, original.TagName)
	}
	if clone.SubtreeSize != original.SubtreeSize {
		t.Errorf("SubtreeSize = %d, want %d", clone.SubtreeSize, original.SubtreeSize)
	}
	if clone.Rect != original.Rect {
		t.Errorf("Rect = %+v, want %+v", clone.Rect, original.Rect)
	}
	if clone.IsDynamic != original.IsDynamic {
		t.Errorf("IsDynamic = %v, want %v", clone.IsDynamic, original.IsDynamic)
	}
	if clone.AccessCount != original.AccessCount {
		t.Errorf("AccessCount = %d, want %d", clone.AccessCount, original.AccessCount)
	}
	if clone.DOMHash != original.DOMHash {
		t.Errorf("DOMHash = %q, want %q", clone.DOMHash, original.DOMHash)
	}
	if clone.ContentHash != original.ContentHash {
		t.Errorf("ContentHash = %q, want %q", clone.ContentHash, original.ContentHash)
	}
	if clone.Influence != original.Influence {
		t.Errorf("Influence = %f, want %f", clone.Influence, original.Influence)
	}
	if clone.DirectAccess != original.DirectAccess {
		t.Errorf("DirectAccess = %v, want %v", clone.DirectAccess, original.DirectAccess)
	}
	if clone.DuplicateCount != original.DuplicateCount {
		t.Errorf("DuplicateCount = %d, want %d", clone.DuplicateCount, original.DuplicateCount)
	}
	if clone.EquivalentCount != original.EquivalentCount {
		t.Errorf("EquivalentCount = %d, want %d", clone.EquivalentCount, original.EquivalentCount)
	}
	if clone.ClusterID != original.ClusterID {
		t.Errorf("ClusterID = %d, want %d", clone.ClusterID, original.ClusterID)
	}

	// Verify slices are deep copied
	if len(clone.ChildIDs) != len(original.ChildIDs) {
		t.Errorf("len(ChildIDs) = %d, want %d", len(clone.ChildIDs), len(original.ChildIDs))
	}
	if len(clone.ND2Fragments) != len(original.ND2Fragments) {
		t.Errorf("len(ND2Fragments) = %d, want %d", len(clone.ND2Fragments), len(original.ND2Fragments))
	}

	// Verify modifications to clone don't affect original
	clone.ChildIDs[0] = 999
	if original.ChildIDs[0] == 999 {
		t.Error("modifying clone.ChildIDs should not affect original")
	}

	clone.ND2Fragments[0] = "modified"
	if original.ND2Fragments[0] == "modified" {
		t.Error("modifying clone.ND2Fragments should not affect original")
	}
}

func TestFragmentString(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 10)
	f.TagName = "div"
	f.SetDOMHash("test content")
	f.IsDynamic = true

	s := f.String()
	if s == "" {
		t.Error("String() should not return empty")
	}
	// Should contain key information
	if len(s) < 20 {
		t.Errorf("String() too short: %q", s)
	}
}

// =============================================================================
// =============================================================================

func TestFragmentRecordAccess(t *testing.T) {
	tests := []struct {
		name             string
		accessType       AccessType
		expectedInf      float64
		expectedDirect   bool
		expectedDupCount int
		expectedEqCount  int
	}{
		{
			name:             "direct access",
			accessType:       AccessTypeDirect,
			expectedInf:      0.0, // 1.0 - 1.0
			expectedDirect:   true,
			expectedDupCount: 0,
			expectedEqCount:  0,
		},
		{
			name:             "duplicate access",
			accessType:       AccessTypeDuplicate,
			expectedInf:      0.5, // 1.0 - 0.5
			expectedDirect:   false,
			expectedDupCount: 1,
			expectedEqCount:  0,
		},
		{
			name:             "equivalent access",
			accessType:       AccessTypeEquivalent,
			expectedInf:      0.75, // 1.0 - 0.25
			expectedDirect:   false,
			expectedDupCount: 0,
			expectedEqCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFragment(1, "/html", Rect{}, 5)
			f.RecordAccess(tt.accessType)

			if f.Influence != tt.expectedInf {
				t.Errorf("Influence = %f, want %f", f.Influence, tt.expectedInf)
			}
			if f.DirectAccess != tt.expectedDirect {
				t.Errorf("DirectAccess = %v, want %v", f.DirectAccess, tt.expectedDirect)
			}
			if f.DuplicateCount != tt.expectedDupCount {
				t.Errorf("DuplicateCount = %d, want %d", f.DuplicateCount, tt.expectedDupCount)
			}
			if f.EquivalentCount != tt.expectedEqCount {
				t.Errorf("EquivalentCount = %d, want %d", f.EquivalentCount, tt.expectedEqCount)
			}
		})
	}
}

func TestFragmentInfluenceClamping(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	// Multiple accesses should clamp to 0
	f.RecordAccess(AccessTypeDirect) // -1.0 -> 0.0
	if f.Influence != 0 {
		t.Errorf("Influence = %f, want 0", f.Influence)
	}

	f.RecordAccess(AccessTypeDirect) // Still 0, clamped
	if f.Influence != 0 {
		t.Errorf("Influence = %f, want 0 (clamped)", f.Influence)
	}

	f.RecordAccess(AccessTypeDuplicate) // Still 0
	if f.Influence != 0 {
		t.Errorf("Influence = %f, want 0 (clamped)", f.Influence)
	}
}

func TestFragmentGetInfluence(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	if f.GetInfluence() != 1.0 {
		t.Errorf("GetInfluence() = %f, want 1.0", f.GetInfluence())
	}

	f.RecordAccess(AccessTypeDuplicate)

	if f.GetInfluence() != 0.5 {
		t.Errorf("GetInfluence() = %f, want 0.5", f.GetInfluence())
	}
}

func TestFragmentResetInfluence(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	// Record some accesses
	f.RecordAccess(AccessTypeDirect)
	f.RecordAccess(AccessTypeDuplicate)
	f.RecordAccess(AccessTypeEquivalent)

	// Verify state changed
	if f.Influence == 1.0 {
		t.Error("influence should have changed")
	}
	if !f.DirectAccess {
		t.Error("DirectAccess should be true")
	}

	// Reset
	f.ResetInfluence()

	if f.Influence != 1.0 {
		t.Errorf("Influence = %f, want 1.0 after reset", f.Influence)
	}
	if f.DirectAccess {
		t.Error("DirectAccess should be false after reset")
	}
	if f.DuplicateCount != 0 {
		t.Errorf("DuplicateCount = %d, want 0 after reset", f.DuplicateCount)
	}
	if f.EquivalentCount != 0 {
		t.Errorf("EquivalentCount = %d, want 0 after reset", f.EquivalentCount)
	}
}

// =============================================================================
// =============================================================================

func TestFragmentSetCluster(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	if f.ClusterID != 0 {
		t.Errorf("ClusterID = %d, want 0 (default)", f.ClusterID)
	}

	f.SetCluster(42)

	if f.ClusterID != 42 {
		t.Errorf("ClusterID = %d, want 42", f.ClusterID)
	}
}

func TestFragmentAddND2Fragment(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)

	if len(f.ND2Fragments) != 0 {
		t.Errorf("ND2Fragments = %v, want empty", f.ND2Fragments)
	}

	f.AddND2Fragment("hash1")
	f.AddND2Fragment("hash2")

	if len(f.ND2Fragments) != 2 {
		t.Errorf("len(ND2Fragments) = %d, want 2", len(f.ND2Fragments))
	}

	// Adding duplicate should be ignored
	f.AddND2Fragment("hash1")
	if len(f.ND2Fragments) != 2 {
		t.Errorf("len(ND2Fragments) = %d, want 2 (no duplicate)", len(f.ND2Fragments))
	}
}

func TestFragmentHasND2Relation(t *testing.T) {
	f := NewFragment(1, "/html", Rect{}, 5)
	f.AddND2Fragment("hash1")
	f.AddND2Fragment("hash2")

	if !f.HasND2Relation("hash1") {
		t.Error("HasND2Relation(hash1) should be true")
	}
	if !f.HasND2Relation("hash2") {
		t.Error("HasND2Relation(hash2) should be true")
	}
	if f.HasND2Relation("hash3") {
		t.Error("HasND2Relation(hash3) should be false")
	}
	if f.HasND2Relation("") {
		t.Error("HasND2Relation('') should be false")
	}
}

// =============================================================================
// AccessType Tests
// =============================================================================

func TestAccessTypeConstants(t *testing.T) {
	// Verify enum values are distinct
	if AccessTypeDirect == AccessTypeDuplicate {
		t.Error("AccessTypeDirect should not equal AccessTypeDuplicate")
	}
	if AccessTypeDuplicate == AccessTypeEquivalent {
		t.Error("AccessTypeDuplicate should not equal AccessTypeEquivalent")
	}
	if AccessTypeDirect == AccessTypeEquivalent {
		t.Error("AccessTypeDirect should not equal AccessTypeEquivalent")
	}
}
