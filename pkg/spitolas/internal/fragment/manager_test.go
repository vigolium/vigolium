package fragment

import (
	"sync"
	"testing"
)

// =============================================================================
// Manager Basic Tests
// =============================================================================

func TestNewManager(t *testing.T) {
	m := NewManager()

	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	if m.GetFragmentCount() != 0 {
		t.Errorf("GetFragmentCount() = %d, want 0", m.GetFragmentCount())
	}
	if m.GetStateCount() != 0 {
		t.Errorf("GetStateCount() = %d, want 0", m.GetStateCount())
	}
}

func TestManagerSetDynamicThreshold(t *testing.T) {
	m := NewManager()
	m.SetDynamicThreshold(5)

	// Verify threshold is applied by testing dynamic marking
	f := NewFragment(1, "/html", Rect{}, 10)
	f.DOMHash = "testhash"
	m.AddFragments("state1", []*Fragment{f})

	// Mark 5 times should trigger dynamic
	for i := 0; i < 5; i++ {
		m.MarkDynamic("testhash")
	}

	if !m.IsDynamic("testhash") {
		t.Error("fragment should be dynamic after reaching threshold")
	}
}

// =============================================================================
// AddFragments / GetFragments Tests
// =============================================================================

func TestManagerAddGetFragments(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
		createManagerTestFragment(3, "hash3"),
	}

	m.AddFragments("state1", frags)

	// Verify fragment count
	if m.GetFragmentCount() != 3 {
		t.Errorf("GetFragmentCount() = %d, want 3", m.GetFragmentCount())
	}

	// Verify state count
	if m.GetStateCount() != 1 {
		t.Errorf("GetStateCount() = %d, want 1", m.GetStateCount())
	}

	// Get fragments back
	retrieved := m.GetFragments("state1")
	if len(retrieved) != 3 {
		t.Errorf("len(GetFragments) = %d, want 3", len(retrieved))
	}
}

func TestManagerGetFragmentsUnknownState(t *testing.T) {
	m := NewManager()

	frags := m.GetFragments("unknown")
	if frags != nil {
		t.Errorf("GetFragments(unknown) = %v, want nil", frags)
	}
}

func TestManagerAddFragmentsMultipleStates(t *testing.T) {
	m := NewManager()

	frags1 := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
	}
	frags2 := []*Fragment{
		createManagerTestFragment(3, "hash2"), // Same hash as in state1
		createManagerTestFragment(4, "hash3"),
	}

	m.AddFragments("state1", frags1)
	m.AddFragments("state2", frags2)

	if m.GetStateCount() != 2 {
		t.Errorf("GetStateCount() = %d, want 2", m.GetStateCount())
	}

	// Unique fragments: hash1, hash2, hash3 = 3
	if m.GetFragmentCount() != 3 {
		t.Errorf("GetFragmentCount() = %d, want 3", m.GetFragmentCount())
	}

	// Verify access count for hash2 (appeared in both states)
	f := m.GetFragmentByHash("hash2")
	if f == nil {
		t.Fatal("GetFragmentByHash(hash2) returned nil")
	}
	if f.AccessCount != 1 {
		t.Errorf("AccessCount = %d, want 1 (incremented on second add)", f.AccessCount)
	}
}

// =============================================================================
// GetFragmentByHash Tests
// =============================================================================

func TestManagerGetFragmentByHash(t *testing.T) {
	m := NewManager()

	f := createManagerTestFragment(1, "uniquehash")
	f.TagName = "div"
	m.AddFragments("state1", []*Fragment{f})

	retrieved := m.GetFragmentByHash("uniquehash")
	if retrieved == nil {
		t.Fatal("GetFragmentByHash returned nil")
	}
	if retrieved.TagName != "div" {
		t.Errorf("TagName = %q, want 'div'", retrieved.TagName)
	}

	// Non-existent hash
	if m.GetFragmentByHash("nonexistent") != nil {
		t.Error("GetFragmentByHash(nonexistent) should return nil")
	}
}

func TestManagerGetFragmentByHashReturnsClone(t *testing.T) {
	m := NewManager()

	f := createManagerTestFragment(1, "hash1")
	f.AccessCount = 5
	m.AddFragments("state1", []*Fragment{f})

	retrieved := m.GetFragmentByHash("hash1")
	retrieved.AccessCount = 999

	// Original should be unchanged
	original := m.GetFragmentByHash("hash1")
	if original.AccessCount == 999 {
		t.Error("modifying retrieved fragment should not affect stored fragment")
	}
}

// =============================================================================
// GetChangedFragments Tests
// =============================================================================

func TestManagerGetChangedFragmentsIdentical(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
	}

	m.AddFragments("state1", frags)
	m.AddFragments("state2", frags) // Same fragments

	changed := m.GetChangedFragments("state1", "state2")
	if len(changed) != 0 {
		t.Errorf("len(changed) = %d, want 0", len(changed))
	}
}

func TestManagerGetChangedFragmentsDifferent(t *testing.T) {
	m := NewManager()

	frags1 := []*Fragment{
		createManagerTestFragment(1, "common"),
		createManagerTestFragment(2, "only1"),
	}
	frags2 := []*Fragment{
		createManagerTestFragment(3, "common"),
		createManagerTestFragment(4, "only2"),
	}

	m.AddFragments("state1", frags1)
	m.AddFragments("state2", frags2)

	changed := m.GetChangedFragments("state1", "state2")

	// Changed = only1 (in state1 not state2) + only2 (in state2 not state1)
	if len(changed) != 2 {
		t.Errorf("len(changed) = %d, want 2", len(changed))
	}
}

func TestManagerGetChangedFragmentsUnknownState(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{createManagerTestFragment(1, "hash1")}
	m.AddFragments("state1", frags)

	// Unknown state2
	changed := m.GetChangedFragments("state1", "unknown")
	if len(changed) != 1 {
		t.Errorf("len(changed) = %d, want 1 (all of state1)", len(changed))
	}
}

// =============================================================================
// Dynamic Fragment Tests
// =============================================================================

func TestManagerMarkDynamic(t *testing.T) {
	m := NewManager()
	m.SetDynamicThreshold(3)

	f := createManagerTestFragment(1, "dynamichash")
	m.AddFragments("state1", []*Fragment{f})

	// Not dynamic initially
	if m.IsDynamic("dynamichash") {
		t.Error("should not be dynamic initially")
	}

	// Mark twice - not yet at threshold
	m.MarkDynamic("dynamichash")
	m.MarkDynamic("dynamichash")
	if m.IsDynamic("dynamichash") {
		t.Error("should not be dynamic before reaching threshold")
	}

	// Third mark - reaches threshold
	m.MarkDynamic("dynamichash")
	if !m.IsDynamic("dynamichash") {
		t.Error("should be dynamic after reaching threshold")
	}
}

func TestManagerGetDynamicFragments(t *testing.T) {
	m := NewManager()
	m.SetDynamicThreshold(1)

	frags := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
		createManagerTestFragment(3, "hash3"),
	}
	m.AddFragments("state1", frags)

	// Mark only hash2 as dynamic
	m.MarkDynamic("hash2")

	dynamic := m.GetDynamicFragments()
	if len(dynamic) != 1 {
		t.Errorf("len(dynamic) = %d, want 1", len(dynamic))
	}
	if dynamic[0].DOMHash != "hash2" {
		t.Errorf("dynamic[0].DOMHash = %q, want 'hash2'", dynamic[0].DOMHash)
	}
}

func TestManagerGetStaticFragments(t *testing.T) {
	m := NewManager()
	m.SetDynamicThreshold(1)

	frags := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
		createManagerTestFragment(3, "hash3"),
	}
	m.AddFragments("state1", frags)

	// Mark hash2 as dynamic
	m.MarkDynamic("hash2")

	static := m.GetStaticFragments()
	if len(static) != 2 {
		t.Errorf("len(static) = %d, want 2", len(static))
	}
}

// =============================================================================
// Statistics Tests
// =============================================================================

func TestManagerGetStats(t *testing.T) {
	m := NewManager()
	m.SetDynamicThreshold(1)

	frags1 := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
	}
	frags2 := []*Fragment{
		createManagerTestFragment(3, "hash2"),
		createManagerTestFragment(4, "hash3"),
	}

	m.AddFragments("state1", frags1)
	m.AddFragments("state2", frags2)
	m.MarkDynamic("hash2")

	stats := m.GetStats()

	if stats.TotalFragments != 3 {
		t.Errorf("TotalFragments = %d, want 3", stats.TotalFragments)
	}
	if stats.TotalStates != 2 {
		t.Errorf("TotalStates = %d, want 2", stats.TotalStates)
	}
	if stats.DynamicFragments != 1 {
		t.Errorf("DynamicFragments = %d, want 1", stats.DynamicFragments)
	}
	if stats.StaticFragments != 2 {
		t.Errorf("StaticFragments = %d, want 2", stats.StaticFragments)
	}
}

func TestManagerClear(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{createManagerTestFragment(1, "hash1")}
	m.AddFragments("state1", frags)

	if m.GetFragmentCount() != 1 {
		t.Error("fragment count should be 1 before clear")
	}

	m.Clear()

	if m.GetFragmentCount() != 0 {
		t.Errorf("GetFragmentCount() = %d, want 0 after clear", m.GetFragmentCount())
	}
	if m.GetStateCount() != 0 {
		t.Errorf("GetStateCount() = %d, want 0 after clear", m.GetStateCount())
	}
}

// =============================================================================
// =============================================================================

func TestManagerUpdateInfluence(t *testing.T) {
	m := NewManager()

	f := createManagerTestFragment(1, "hash1")
	m.AddFragments("state1", []*Fragment{f})

	// Initial influence = 1.0
	inf := m.GetFragmentInfluence("hash1")
	if inf != 1.0 {
		t.Errorf("initial influence = %f, want 1.0", inf)
	}

	// Direct access reduces by 1.0
	m.UpdateInfluence("hash1", AccessTypeDirect)
	inf = m.GetFragmentInfluence("hash1")
	if inf != 0.0 {
		t.Errorf("after direct: influence = %f, want 0.0", inf)
	}
}

func TestManagerGetFragmentInfluenceUnknown(t *testing.T) {
	m := NewManager()

	// Unknown fragment should return default 1.0
	if inf := m.GetFragmentInfluence("unknown"); inf != 1.0 {
		t.Errorf("unknown influence = %f, want 1.0", inf)
	}
}

func TestManagerGetHighInfluenceFragments(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{
		createManagerTestFragment(1, "high1"),  // Will stay at 1.0
		createManagerTestFragment(2, "high2"),  // Will stay at 1.0
		createManagerTestFragment(3, "medium"), // Will be 0.5
		createManagerTestFragment(4, "low"),    // Will be 0.0
	}
	m.AddFragments("state1", frags)

	m.UpdateInfluence("medium", AccessTypeDuplicate) // 0.5
	m.UpdateInfluence("low", AccessTypeDirect)       // 0.0

	// High influence (>= 0.8)
	high := m.GetHighInfluenceFragments(0.8)
	if len(high) != 2 {
		t.Errorf("len(high) = %d, want 2", len(high))
	}

	// Medium influence (>= 0.4)
	medium := m.GetHighInfluenceFragments(0.4)
	if len(medium) != 3 {
		t.Errorf("len(medium) = %d, want 3", len(medium))
	}
}

func TestManagerPropagateInfluence(t *testing.T) {
	m := NewManager()

	// Create parent-child relationship
	parent := createManagerTestFragment(1, "parent")
	child := createManagerTestFragment(2, "child")
	child.ParentID = 1

	m.AddFragments("state1", []*Fragment{parent, child})

	// Propagate influence from child
	m.PropagateInfluence("child", AccessTypeDirect)

	// Child should have 0.0 influence
	childInf := m.GetFragmentInfluence("child")
	if childInf != 0.0 {
		t.Errorf("child influence = %f, want 0.0", childInf)
	}

	// DIRECT access (-1.0) propagates to parent, so parent also gets -1.0
	parentInf := m.GetFragmentInfluence("parent")
	if parentInf != 0.0 {
		t.Errorf("parent influence = %f, want 0.0", parentInf)
	}
}

func TestManagerCalculateCandidateInfluence(t *testing.T) {
	m := NewManager()

	f := createManagerTestFragment(1, "hash1")
	f.XPath = "/html/body/div"
	m.AddFragments("state1", []*Fragment{f})

	// Element inside the fragment
	inf := m.CalculateCandidateInfluence("/html/body/div/p")
	if inf != 1.0 {
		t.Errorf("candidate influence = %f, want 1.0", inf)
	}

	// Update fragment influence
	m.UpdateInfluence("hash1", AccessTypeDuplicate)

	inf = m.CalculateCandidateInfluence("/html/body/div/p")
	if inf != 0.5 {
		t.Errorf("candidate influence after update = %f, want 0.5", inf)
	}

	// Element outside any fragment
	inf = m.CalculateCandidateInfluence("/html/head/title")
	if inf != 1.0 {
		t.Errorf("outside fragment influence = %f, want 1.0", inf)
	}
}

// =============================================================================
// =============================================================================

func TestManagerAreRelatedSameHash(t *testing.T) {
	m := NewManager()

	if !m.AreRelated("hash1", "hash1") {
		t.Error("same hash should be related")
	}
}

func TestManagerAreRelatedSameCluster(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
	}
	m.AddFragments("state1", frags)

	// Not related initially
	if m.AreRelated("hash1", "hash2") {
		t.Error("different hashes should not be related initially")
	}

	// Set same cluster
	m.SetFragmentCluster("hash1", 42)
	m.SetFragmentCluster("hash2", 42)

	if !m.AreRelated("hash1", "hash2") {
		t.Error("same cluster should be related")
	}
}

func TestManagerAreRelatedND2(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
	}
	m.AddFragments("state1", frags)

	// Not related initially
	if m.AreRelated("hash1", "hash2") {
		t.Error("should not be related initially")
	}

	// Add ND2 relationship
	m.AddND2Relationship("hash1", "hash2")

	if !m.AreRelated("hash1", "hash2") {
		t.Error("ND2 relationship should make them related")
	}
	if !m.AreRelated("hash2", "hash1") {
		t.Error("ND2 relationship should be bidirectional")
	}
}

func TestManagerGetRelatedFragments(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{
		createManagerTestFragment(1, "center"),
		createManagerTestFragment(2, "cluster1"),
		createManagerTestFragment(3, "cluster2"),
		createManagerTestFragment(4, "nd2"),
		createManagerTestFragment(5, "unrelated"),
	}
	m.AddFragments("state1", frags)

	// Set up relationships
	m.SetFragmentCluster("center", 10)
	m.SetFragmentCluster("cluster1", 10)
	m.SetFragmentCluster("cluster2", 10)
	m.AddND2Relationship("center", "nd2")

	related := m.GetRelatedFragments("center")

	// Should include: cluster1, cluster2, nd2 (not unrelated, not center itself)
	if len(related) != 3 {
		t.Errorf("len(related) = %d, want 3", len(related))
	}
}

func TestManagerSetFragmentCluster(t *testing.T) {
	m := NewManager()

	f := createManagerTestFragment(1, "hash1")
	m.AddFragments("state1", []*Fragment{f})

	m.SetFragmentCluster("hash1", 42)

	retrieved := m.GetFragmentByHash("hash1")
	if retrieved.ClusterID != 42 {
		t.Errorf("ClusterID = %d, want 42", retrieved.ClusterID)
	}
}

func TestManagerAddND2Relationship(t *testing.T) {
	m := NewManager()

	frags := []*Fragment{
		createManagerTestFragment(1, "hash1"),
		createManagerTestFragment(2, "hash2"),
	}
	m.AddFragments("state1", frags)

	m.AddND2Relationship("hash1", "hash2")

	// Check bidirectional
	f1 := m.GetFragmentByHash("hash1")
	f2 := m.GetFragmentByHash("hash2")

	if !f1.HasND2Relation("hash2") {
		t.Error("hash1 should have ND2 relation to hash2")
	}
	if !f2.HasND2Relation("hash1") {
		t.Error("hash2 should have ND2 relation to hash1")
	}
}

func TestManagerGetParentFragment(t *testing.T) {
	m := NewManager()

	parent := createManagerTestFragment(1, "parent")
	child := createManagerTestFragment(2, "child")
	child.ParentID = 1

	m.AddFragments("state1", []*Fragment{parent, child})

	// Get parent of child
	p := m.GetParentFragment("child")
	if p == nil {
		t.Fatal("GetParentFragment returned nil")
	}
	if p.DOMHash != "parent" {
		t.Errorf("parent hash = %q, want 'parent'", p.DOMHash)
	}

	// Root has no parent
	if m.GetParentFragment("parent") != nil {
		t.Error("root fragment should have no parent")
	}

	// Unknown fragment
	if m.GetParentFragment("unknown") != nil {
		t.Error("unknown fragment should return nil")
	}
}

func TestManagerGetFragmentByXPath(t *testing.T) {
	m := NewManager()

	f1 := createManagerTestFragment(1, "hash1")
	f1.XPath = "/html/body"

	f2 := createManagerTestFragment(2, "hash2")
	f2.XPath = "/html/body/div"

	f3 := createManagerTestFragment(3, "hash3")
	f3.XPath = "/html/body/div/p"

	m.AddFragments("state1", []*Fragment{f1, f2, f3})

	// Exact match
	found := m.GetFragmentByXPath("/html/body/div")
	if found == nil || found.DOMHash != "hash2" {
		t.Errorf("exact match failed, got %v", found)
	}

	// Longest prefix match
	found = m.GetFragmentByXPath("/html/body/div/p/span")
	if found == nil || found.DOMHash != "hash3" {
		t.Errorf("longest prefix match failed, got %v", found)
	}

	// No match
	found = m.GetFragmentByXPath("/html/head")
	if found != nil {
		t.Errorf("should return nil for no match, got %v", found)
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestManagerConcurrentAccess(t *testing.T) {
	m := NewManager()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				stateID := string(rune('A' + id))
				f := createManagerTestFragment(id*1000+j, string(rune('a'+j%26)))
				m.AddFragments(stateID, []*Fragment{f})
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				stateID := string(rune('A' + id%numGoroutines))
				_ = m.GetFragments(stateID)
				_ = m.GetStats()
				_ = m.GetFragmentCount()
			}
		}(i)
	}

	wg.Wait()

	// Should complete without deadlock or panic
	if m.GetStateCount() != numGoroutines {
		t.Errorf("GetStateCount() = %d, want %d", m.GetStateCount(), numGoroutines)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func createManagerTestFragment(id int, domHash string) *Fragment {
	f := NewFragment(id, "/html/body", Rect{Width: 100, Height: 100}, 10)
	f.DOMHash = domHash
	return f
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkManagerAddFragments(b *testing.B) {
	m := NewManager()
	frags := make([]*Fragment, 50)
	for i := 0; i < 50; i++ {
		frags[i] = createManagerTestFragment(i, string(rune('a'+i%26)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.AddFragments(string(rune('A'+i%26)), frags)
	}
}

func BenchmarkManagerGetFragments(b *testing.B) {
	m := NewManager()
	frags := make([]*Fragment, 50)
	for i := 0; i < 50; i++ {
		frags[i] = createManagerTestFragment(i, string(rune('a'+i%26)))
	}
	m.AddFragments("state1", frags)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.GetFragments("state1")
	}
}

func BenchmarkManagerGetChangedFragments(b *testing.B) {
	m := NewManager()

	frags1 := make([]*Fragment, 100)
	frags2 := make([]*Fragment, 100)
	for i := 0; i < 100; i++ {
		frags1[i] = createManagerTestFragment(i, string(rune('a'+i%26)))
		frags2[i] = createManagerTestFragment(i+100, string(rune('a'+(i+5)%26)))
	}
	m.AddFragments("state1", frags1)
	m.AddFragments("state2", frags2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.GetChangedFragments("state1", "state2")
	}
}
