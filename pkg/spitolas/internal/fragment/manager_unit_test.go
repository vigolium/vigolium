package fragment

import "testing"

// newTaggedFragment builds a fragment with a tag and DOM hash for manager tests.
func newTaggedFragment(id int, tag, domHash string, subtree int) *Fragment {
	f := NewFragment(id, "/x", Rect{Width: 100, Height: 100}, subtree)
	f.TagName = tag
	f.DOMHash = domHash
	return f
}

func TestStateComparisonString(t *testing.T) {
	tests := []struct {
		sc   StateComparison
		want string
	}{
		{StateComparisonDifferent, "DIFFERENT"},
		{StateComparisonDuplicate, "DUPLICATE"},
		{StateComparisonNearDuplicate1, "NEARDUPLICATE1"},
		{StateComparisonNearDuplicate2, "NEARDUPLICATE2"},
		{StateComparisonError, "ERRORCOMPARING"},
		{StateComparison(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.sc.String(); got != tt.want {
			t.Errorf("StateComparison(%d).String() = %q, want %q", tt.sc, got, tt.want)
		}
	}
}

func TestManagerAddFragmentGlobalVsDuplicate(t *testing.T) {
	m := NewManager()

	// First fragment becomes global.
	a := newTaggedFragment(1, "div", "hashA", 5)
	m.AddFragment(a, true)
	if !a.IsGlobal {
		t.Error("first fragment should be global")
	}
	if m.GetFragmentCount() != 1 {
		t.Errorf("GetFragmentCount() = %d, want 1", m.GetFragmentCount())
	}

	// A distinct fragment (different tag => DIFFERENT) becomes a second global.
	b := newTaggedFragment(2, "section", "hashB", 5)
	m.AddFragment(b, true)
	if !b.IsGlobal {
		t.Error("distinct fragment should be global")
	}
	if got := len(m.GetGlobalFragments()); got != 2 {
		t.Errorf("GetGlobalFragments len = %d, want 2", got)
	}

	// An equal fragment (same hash) becomes a duplicate, NOT global.
	dup := newTaggedFragment(3, "div", "hashA", 5)
	m.AddFragment(dup, true)
	if dup.IsGlobal {
		t.Error("equal fragment should be classified as duplicate, not global")
	}
	if got := len(m.GetGlobalFragments()); got != 2 {
		t.Errorf("GetGlobalFragments len = %d, want still 2", got)
	}
	// Bidirectional duplicate links established.
	if len(a.GetDuplicateFragments()) == 0 || len(dup.GetDuplicateFragments()) == 0 {
		t.Error("duplicate links should be bidirectional")
	}
}

func TestManagerGetDuplicateAndRelatedFragments(t *testing.T) {
	m := NewManager()

	// nil fragment => empty slices.
	if len(m.GetDuplicateFragments(nil)) != 0 {
		t.Error("GetDuplicateFragments(nil) should be empty")
	}

	g := newTaggedFragment(1, "div", "h1", 5)
	g.SetIsGlobal(true)
	dup := newTaggedFragment(2, "div", "h1", 5)
	g.AddDuplicateFragment(dup)

	dups := m.GetDuplicateFragments(g)
	if len(dups) != 2 { // self + dup
		t.Errorf("GetDuplicateFragments len = %d, want 2", len(dups))
	}

	related := m.GetRelatedFragmentsForFragment(g)
	if len(related) == 0 {
		t.Error("GetRelatedFragmentsForFragment should include duplicates")
	}
	// Equivalent fragments (none set) — just exercise the path.
	_ = m.GetEquivalentFragments(g)
}

func TestManagerStateComparisonCache(t *testing.T) {
	m := NewManager()

	// Not cached initially.
	if m.GetCachedComparison("s1", "s2") != nil {
		t.Error("comparison should not be cached initially")
	}

	res := &StatePairResult{State1ID: "s1", State2ID: "s2", Comparison: StateComparisonNearDuplicate1}
	m.CacheStateComparison(res, false)

	// Cached and order-independent.
	got := m.GetCachedComparison("s1", "s2")
	if got == nil || got.Comparison != StateComparisonNearDuplicate1 {
		t.Errorf("GetCachedComparison = %v, want ND1", got)
	}
	if m.GetCachedComparison("s2", "s1") == nil {
		t.Error("cache key should be order-independent")
	}

	// Caching the same pair again is a no-op (does not panic / overwrite).
	res2 := &StatePairResult{State1ID: "s1", State2ID: "s2", Comparison: StateComparisonDifferent}
	m.CacheStateComparison(res2, false)
	if again := m.GetCachedComparison("s1", "s2"); again.Comparison != StateComparisonNearDuplicate1 {
		t.Error("re-caching an existing pair should not overwrite the cached result")
	}
}

func TestManagerCacheStateComparisonAssignsDynamic(t *testing.T) {
	m := NewManager()
	dyn := newTaggedFragment(1, "div", "h1", 5)

	res := &StatePairResult{State1ID: "a", State2ID: "b", Comparison: StateComparisonNearDuplicate1}
	m.CacheStateComparison(res, true, dyn)

	if !dyn.IsDynamic {
		t.Error("changed fragment should be marked dynamic when assignDynamic=true on ND result")
	}
}

func TestManagerNearDuplicateTracking(t *testing.T) {
	m := NewManager()

	m.AddToNearDuplicates("s1", "s2")
	got := m.GetNearDuplicateStates("s1")
	if len(got) != 2 {
		t.Fatalf("GetNearDuplicateStates(s1) len = %d, want 2", len(got))
	}

	// Adding a third state linked to an existing one joins the same set.
	m.AddToNearDuplicates("s2", "s3")
	if len(m.GetNearDuplicateStates("s3")) != 3 {
		t.Errorf("GetNearDuplicateStates(s3) len = %d, want 3", len(m.GetNearDuplicateStates("s3")))
	}

	// Unknown state => empty.
	if len(m.GetNearDuplicateStates("unknown")) != 0 {
		t.Error("unknown state should have no near-duplicates")
	}
}

func TestManagerAddToNearDuplicatesSingle(t *testing.T) {
	m := NewManager()
	m.AddToNearDuplicatesSingle("solo")
	if len(m.GetNearDuplicateStates("solo")) != 1 {
		t.Errorf("solo near-dup len = %d, want 1", len(m.GetNearDuplicateStates("solo")))
	}
	// Idempotent.
	m.AddToNearDuplicatesSingle("solo")
	if len(m.GetNearDuplicateStates("solo")) != 1 {
		t.Error("AddToNearDuplicatesSingle should be idempotent")
	}
}

func TestManagerHasExploredNearDuplicate(t *testing.T) {
	m := NewManager()
	m.AddToNearDuplicates("s1", "s2")

	// The state itself is fully explored.
	allExplored := func(string) bool { return false }
	if !m.HasExploredNearDuplicate("s1", allExplored) {
		t.Error("fully-explored state should report explored near-duplicate")
	}

	// s1 unexplored, but its near-duplicate s2 is explored.
	s1Unexplored := func(id string) bool { return id == "s1" }
	if !m.HasExploredNearDuplicate("s1", s1Unexplored) {
		t.Error("should report explored when a near-duplicate is explored")
	}

	// Everything unexplored => false.
	allUnexplored := func(string) bool { return true }
	if m.HasExploredNearDuplicate("s1", allUnexplored) {
		t.Error("should report not explored when everything is unexplored")
	}
}

func TestManagerSeenState(t *testing.T) {
	m := NewManager()
	// Should not panic and should track new states.
	m.SeenState("s1")
	m.SeenState("s2")
	m.SeenState("s1") // re-seen resets its counter
}

func TestManagerSetDynamicAndIsDynamic(t *testing.T) {
	m := NewManager()
	f := newTaggedFragment(1, "div", "h1", 5)
	m.AddFragment(f, true)

	if m.IsDynamic("h1") {
		t.Error("fragment should not be dynamic initially")
	}
	m.SetDynamic(f)
	if !m.IsDynamic("h1") {
		t.Error("fragment should be dynamic after SetDynamic")
	}

	// Unknown hash falls back to changeCount threshold (0 < default 3).
	if m.IsDynamic("unknown") {
		t.Error("unknown hash below threshold should not be dynamic")
	}
}

func TestManagerStopCrawling(t *testing.T) {
	m := NewManager()
	m.AddFragment(newTaggedFragment(1, "div", "h1", 5), true)
	m.AddToNearDuplicates("s1", "s2")

	m.StopCrawling()
	// After StopCrawling the maps are nil; read methods must not panic.
	if got := m.GetGlobalFragments(); len(got) != 0 {
		t.Errorf("GetGlobalFragments after StopCrawling len = %d, want 0", len(got))
	}
	if len(m.GetNearDuplicateStates("s1")) != 0 {
		t.Error("near-duplicates should be cleared after StopCrawling")
	}
}
