package fragment

import "testing"

func TestFragmentRulesGlobalRoundTrip(t *testing.T) {
	orig := GetFragmentRules()
	t.Cleanup(func() { SetFragmentRules(orig) })

	custom := &FragmentRules{ThresholdWidth: 10, ThresholdHeight: 20, SubtreeWidthAnd: 2, SubtreeWidthOr: 3}
	SetFragmentRules(custom)
	if GetFragmentRules() != custom {
		t.Error("SetFragmentRules/GetFragmentRules round-trip failed")
	}
}

func TestFragmentIsUsefulWithRulesAndCache(t *testing.T) {
	rules := &FragmentRules{ThresholdWidth: 50, ThresholdHeight: 50, SubtreeWidthAnd: 1, SubtreeWidthOr: 4}

	// Big rect, small subtree => useful via AND branch.
	big := NewFragment(1, "/x", Rect{Width: 100, Height: 100}, 1)
	if !big.IsUsefulWithRules(rules) {
		t.Error("big fragment should be useful")
	}

	// Tiny rect but large subtree => useful via OR branch.
	wide := NewFragment(2, "/y", Rect{Width: 1, Height: 1}, 10)
	if !wide.IsUsefulWithRules(rules) {
		t.Error("large-subtree fragment should be useful")
	}

	// Tiny rect, tiny subtree => not useful.
	tiny := NewFragment(3, "/z", Rect{Width: 1, Height: 1}, 1)
	if tiny.IsUsefulWithRules(rules) {
		t.Error("tiny fragment should not be useful")
	}

	// IsUseful caches its result; ClearUsefulCache forces recompute.
	if !big.IsUseful() {
		t.Error("IsUseful should return true for big fragment")
	}
	big.ClearUsefulCache()
	if !big.IsUseful() {
		t.Error("IsUseful should still return true after cache clear")
	}
}

func TestFragmentRecordAccessInfluence(t *testing.T) {
	f := NewFragment(1, "/x", Rect{}, 5)
	if f.GetInfluence() != 1.0 {
		t.Errorf("default influence = %v, want 1.0", f.GetInfluence())
	}

	f.RecordAccess(AccessTypeEquivalent) // -0.25
	if f.EquivalentCount != 1 {
		t.Errorf("EquivalentCount = %d, want 1", f.EquivalentCount)
	}
	if got := f.GetInfluence(); got != 0.75 {
		t.Errorf("influence after equivalent = %v, want 0.75", got)
	}

	f.RecordAccess(AccessTypeDuplicate) // -0.5
	if f.DuplicateCount != 1 {
		t.Errorf("DuplicateCount = %d, want 1", f.DuplicateCount)
	}

	f.RecordAccess(AccessTypeDirect) // -1.0, clamps to 0
	if !f.DirectAccess {
		t.Error("DirectAccess should be true")
	}
	if f.GetInfluence() != 0 {
		t.Errorf("influence should clamp to 0, got %v", f.GetInfluence())
	}

	f.ResetInfluence()
	if f.GetInfluence() != 1.0 || f.DirectAccess || f.DuplicateCount != 0 || f.EquivalentCount != 0 {
		t.Error("ResetInfluence did not restore defaults")
	}
}

func TestFragmentClusterAndND2(t *testing.T) {
	f := NewFragment(1, "/x", Rect{}, 5)
	f.SetCluster(7)
	if f.ClusterID != 7 {
		t.Errorf("ClusterID = %d, want 7", f.ClusterID)
	}

	f.AddND2Fragment("hash1")
	f.AddND2Fragment("hash1") // dedup
	f.AddND2Fragment("hash2")
	if len(f.ND2Fragments) != 2 {
		t.Errorf("ND2Fragments len = %d, want 2", len(f.ND2Fragments))
	}
	if !f.HasND2Relation("hash1") {
		t.Error("HasND2Relation(hash1) should be true")
	}
	if f.HasND2Relation("missing") {
		t.Error("HasND2Relation(missing) should be false")
	}
}

func TestFragmentRelationshipLinks(t *testing.T) {
	a := NewFragment(1, "/a", Rect{}, 5)
	b := NewFragment(2, "/b", Rect{}, 5)
	b.DOMHash = "bbbbbbbb"

	a.AddDuplicateFragment(b)
	a.AddDuplicateFragment(b) // dedup
	if len(a.GetDuplicateFragments()) != 1 {
		t.Errorf("DuplicateFragments len = %d, want 1", len(a.GetDuplicateFragments()))
	}

	a.AddEquivalentFragment(b)
	a.AddEquivalentFragment(b) // dedup
	if len(a.GetEquivalentFragments()) != 1 {
		t.Errorf("EquivalentFragments len = %d, want 1", len(a.GetEquivalentFragments()))
	}

	a.AddND2FragmentRef(b)
	a.AddND2FragmentRef(b) // dedup
	if len(a.GetND2FragmentRefs()) != 1 {
		t.Errorf("ND2FragmentRefs len = %d, want 1", len(a.GetND2FragmentRefs()))
	}
	// AddND2FragmentRef also records the DOM hash for legacy compatibility.
	if !a.HasND2Relation("bbbbbbbb") {
		t.Error("AddND2FragmentRef should record the related fragment's DOM hash")
	}
}

func TestFragmentGlobalAndAccessFlags(t *testing.T) {
	f := NewFragment(1, "/x", Rect{}, 5)

	f.SetIsGlobal(true)
	if !f.IsGlobal {
		t.Error("SetIsGlobal(true) failed")
	}
	f.SetAccessTransferred(true)
	if !f.AccessTransferred {
		t.Error("SetAccessTransferred(true) failed")
	}
	f.SetReferenceState("state-123")
	if f.GetReferenceState() != "state-123" {
		t.Errorf("GetReferenceState = %q, want %q", f.GetReferenceState(), "state-123")
	}
}

func TestFragmentParentChildPointers(t *testing.T) {
	parent := NewFragment(1, "/p", Rect{}, 50)
	child := NewFragment(2, "/p/c", Rect{}, 5)

	child.SetParentFragment(parent)
	if child.GetParentFragment() != parent {
		t.Error("SetParentFragment/GetParentFragment mismatch")
	}

	parent.AddChildFragment(child)
	parent.AddChildFragment(child) // dedup
	if len(parent.GetChildFragments()) != 1 {
		t.Errorf("GetChildFragments len = %d, want 1", len(parent.GetChildFragments()))
	}

	child.SetDOMParent(parent)
	if child.DOMParent != parent {
		t.Error("SetDOMParent failed")
	}
	parent.AddDOMChild(child)
	parent.AddDOMChild(child) // dedup
	if len(parent.DOMChildren) != 1 {
		t.Errorf("DOMChildren len = %d, want 1", len(parent.DOMChildren))
	}
}

func TestFragmentCandidateInfluence(t *testing.T) {
	f := NewFragment(1, "/x", Rect{}, 5)
	// Default candidate influence pointer is set by NewFragment (1.0).
	if ptr := f.GetCandidateInfluence(); ptr == nil || *ptr != 1.0 {
		t.Errorf("default candidate influence = %v, want 1.0", ptr)
	}

	f.SetCandidateInfluence(2.5)
	if f.Influence != 2.5 {
		t.Errorf("Influence = %v, want 2.5", f.Influence)
	}
	if ptr := f.GetCandidateInfluence(); ptr == nil || *ptr != 2.5 {
		t.Errorf("candidate influence ptr = %v, want 2.5", ptr)
	}
}

func TestFragmentAPTEDTreeCache(t *testing.T) {
	// No TagName => GetAPTEDTree returns nil.
	bare := NewFragment(1, "/x", Rect{}, 5)
	if bare.GetAPTEDTree() != nil {
		t.Error("GetAPTEDTree should be nil when TagName is empty")
	}

	f := NewFragment(2, "/y", Rect{}, 5)
	f.TagName = "div"
	tree := f.GetAPTEDTree()
	if tree == nil {
		t.Fatal("GetAPTEDTree should build a tree from TagName")
	}
	// Cached: a second call returns the same instance.
	if f.GetAPTEDTree() != tree {
		t.Error("GetAPTEDTree should cache the built tree")
	}

	custom := NewAPTEDNode("span")
	f.SetAPTEDTree(custom)
	if f.GetAPTEDTree() != custom {
		t.Error("SetAPTEDTree did not replace the cached tree")
	}

	f.ClearAPTEDTree()
	if f.GetAPTEDTree() == custom {
		t.Error("ClearAPTEDTree should drop the cached tree (rebuild expected)")
	}
}

func TestFragmentCompare(t *testing.T) {
	// Nil operands => DIFFERENT.
	var nilFrag *Fragment
	if nilFrag.Compare(NewFragment(1, "/x", Rect{}, 1)) != FragmentDifferent {
		t.Error("nil receiver Compare should be DIFFERENT")
	}
	a := NewFragment(1, "/x", Rect{}, 1)
	if a.Compare(nil) != FragmentDifferent {
		t.Error("Compare(nil) should be DIFFERENT")
	}

	// Matching DOM hashes => EQUAL (fast path).
	a.DOMHash = "samehash"
	b := NewFragment(2, "/y", Rect{}, 1)
	b.DOMHash = "samehash"
	if a.Compare(b) != FragmentEqual {
		t.Error("matching DOM hashes should compare EQUAL")
	}

	// Same tag name, no hash => identical APTED trees => EQUAL.
	c := NewFragment(3, "/c", Rect{}, 1)
	c.TagName = "div"
	d := NewFragment(4, "/d", Rect{}, 1)
	d.TagName = "div"
	if c.Compare(d) != FragmentEqual {
		t.Error("same-tag fragments should compare EQUAL via APTED")
	}

	// Different tag names => DIFFERENT.
	e := NewFragment(5, "/e", Rect{}, 1)
	e.TagName = "div"
	g := NewFragment(6, "/g", Rect{}, 1)
	g.TagName = "section"
	if e.Compare(g) != FragmentDifferent {
		t.Error("different-tag fragments should compare DIFFERENT")
	}
}

func TestFragmentCompareFast(t *testing.T) {
	var nilFrag *Fragment
	if nilFrag.CompareFast(NewFragment(1, "/x", Rect{}, 1)) != FragmentDifferent {
		t.Error("nil receiver CompareFast should be DIFFERENT")
	}

	// Differing subtree sizes short-circuit to DIFFERENT.
	a := NewFragment(1, "/x", Rect{}, 5)
	a.TagName = "div"
	b := NewFragment(2, "/y", Rect{}, 9)
	b.TagName = "div"
	if a.CompareFast(b) != FragmentDifferent {
		t.Error("CompareFast should short-circuit DIFFERENT on size mismatch")
	}

	// Same size, same tag => delegates to Compare => EQUAL.
	c := NewFragment(3, "/c", Rect{}, 5)
	c.TagName = "div"
	d := NewFragment(4, "/d", Rect{}, 5)
	d.TagName = "div"
	if c.CompareFast(d) != FragmentEqual {
		t.Error("CompareFast should return EQUAL for matching size/tag")
	}
}

func TestFragmentGetSize(t *testing.T) {
	f := NewFragment(1, "/x", Rect{}, 17)
	if f.GetSize() != 17 {
		t.Errorf("GetSize() = %d, want 17", f.GetSize())
	}
}

func TestFragmentComparisonString(t *testing.T) {
	tests := []struct {
		fc   FragmentComparison
		want string
	}{
		{FragmentEqual, "EQUAL"},
		{FragmentEquivalent, "EQUIVALENT"},
		{FragmentDifferent, "DIFFERENT"},
		{FragmentND2, "ND2"},
		{FragmentComparison(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.fc.String(); got != tt.want {
			t.Errorf("FragmentComparison(%d).String() = %q, want %q", tt.fc, got, tt.want)
		}
	}
}

func TestFragmentStringTruncatesHash(t *testing.T) {
	f := NewFragment(1, "/x", Rect{}, 5)
	f.TagName = "div"
	f.DOMHash = "0123456789abcdef" // longer than 8
	s := f.String()
	if s == "" {
		t.Fatal("String() returned empty")
	}
	// Hash is truncated to 8 chars in the representation.
	if want := "Hash:01234567"; !contains(s, want) {
		t.Errorf("String() = %q, want it to contain %q", s, want)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
