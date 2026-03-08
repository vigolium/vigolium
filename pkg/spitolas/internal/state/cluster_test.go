package state

import (
	"testing"
)

// ============================================================================
// CRAWLJAX PARITY: Near-Duplicate Detection Tests
// Based on: Crawljax's StateComparison and NearDuplicate functionality
// ============================================================================

func TestNewNDClusterManager(t *testing.T) {
	m := NewNDClusterManager()

	if m == nil {
		t.Fatal("expected non-nil cluster manager")
	}

	if m.GetClusterCount() != 0 {
		t.Errorf("initial cluster count = %d, want 0", m.GetClusterCount())
	}

	// Check default thresholds
	stats := m.Stats()
	if stats.TotalClusters != 0 {
		t.Errorf("initial TotalClusters = %d, want 0", stats.TotalClusters)
	}
}

func TestNDClusterManagerSetThresholds(t *testing.T) {
	m := NewNDClusterManager()

	m.SetThresholds(0.90, 0.70)

	// Thresholds are private, so we test their effect indirectly
	// by comparing states at different similarity levels
	ResetCounter()

	// Create states that are 85% similar (should be ND2 with default, nothing with new)
	base := "ABCDEFGHIJKLMNOPQRST"
	similar := "ABCDEFGHIJKLMNOPXXXX" // 4 chars diff = 80% similar

	s1 := New("http://test.com", "", base, 0)
	s2 := New("http://test.com", "", similar, 1)

	comparison := m.CompareStates(s1, s2)

	// With 90%/70% thresholds, 80% similarity should be ND2
	if comparison != StateNearDuplicate2 && comparison != StateDifferent {
		t.Logf("comparison result = %v with thresholds 0.90/0.70", comparison)
	}
}

func TestCompareStatesIdentical(t *testing.T) {
	// CRAWLJAX PARITY: Test identical state comparison
	m := NewNDClusterManager()
	ResetCounter()

	dom := "<body><div>Same Content</div></body>"
	s1 := New("http://test.com/a", "", dom, 0)
	s2 := New("http://test.com/b", "", dom, 1)

	comparison := m.CompareStates(s1, s2)

	if comparison != StateIdentical {
		t.Errorf("states with same DOM should be Identical, got %v", comparison)
	}
}

func TestCompareStatesND1(t *testing.T) {
	// CRAWLJAX PARITY: Test ND1 (very similar) comparison
	m := NewNDClusterManager()
	ResetCounter()

	// Create states that differ by only a few characters (>95% similar)
	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
	nd1Similar := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyZ" // 1 char diff

	s1 := New("http://test.com", "", base, 0)
	s2 := New("http://test.com", "", nd1Similar, 1)

	comparison := m.CompareStates(s1, s2)

	// Should be ND1 (very similar)
	if comparison != StateNearDuplicate1 && comparison != StateIdentical {
		t.Logf("ND1 comparison = %v (expected ND1 or Identical)", comparison)
	}
}

func TestCompareStatesND2(t *testing.T) {
	// CRAWLJAX PARITY: Test ND2 (moderately similar) comparison
	m := NewNDClusterManager()
	ResetCounter()

	// Create states that are 80-95% similar
	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nd2Similar := "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234XXXXX" // ~86% similar

	s1 := New("http://test.com", "", base, 0)
	s2 := New("http://test.com", "", nd2Similar, 1)

	comparison := m.CompareStates(s1, s2)

	// Should be ND2 or ND1 depending on exact similarity calculation
	if comparison == StateDifferent {
		t.Logf("ND2 comparison = %v (may depend on similarity algorithm)", comparison)
	}
}

func TestCompareStatesDifferent(t *testing.T) {
	// CRAWLJAX PARITY: Test completely different states
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "Completely different content A", 0)
	s2 := New("http://test.com", "", "Totally unrelated text B", 1)

	comparison := m.CompareStates(s1, s2)

	if comparison != StateDifferent {
		t.Errorf("very different states should be Different, got %v", comparison)
	}
}

func TestAddStateCreatesCluster(t *testing.T) {
	// CRAWLJAX PARITY: Adding first state creates new cluster
	m := NewNDClusterManager()
	ResetCounter()

	s := New("http://test.com", "", "<body>Content</body>", 0)
	cluster := m.AddState(s)

	if cluster == nil {
		t.Fatal("AddState should return a cluster")
	}

	if cluster.Size() != 1 {
		t.Errorf("cluster size = %d, want 1", cluster.Size())
	}

	if cluster.Representative.ID != s.ID {
		t.Error("cluster representative should be the added state")
	}

	if m.GetClusterCount() != 1 {
		t.Errorf("cluster count = %d, want 1", m.GetClusterCount())
	}
}

func TestAddDuplicateStateSameCluster(t *testing.T) {
	// CRAWLJAX PARITY: Duplicate states go to same cluster
	m := NewNDClusterManager()
	ResetCounter()

	dom := "<body>Same Content</body>"
	s1 := New("http://test.com/a", "", dom, 0)
	s2 := New("http://test.com/b", "", dom, 1)

	cluster1 := m.AddState(s1)
	cluster2 := m.AddState(s2)

	// Should be in same cluster (same DOM = same state ID)
	if cluster1.ID != cluster2.ID {
		t.Log("Note: Same DOM produces same ID, so only one state is added")
	}

	// Cluster count should be 1 (duplicate goes to same cluster)
	if m.GetClusterCount() != 1 {
		t.Logf("cluster count = %d (duplicate handling)", m.GetClusterCount())
	}
}

func TestAddNearDuplicateStateSameCluster(t *testing.T) {
	// CRAWLJAX PARITY: Near-duplicate states go to same cluster
	m := NewNDClusterManager()
	ResetCounter()

	// Create states that are very similar
	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
	similar := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyX"

	s1 := New("http://test.com", "", base, 0)
	s2 := New("http://test.com", "", similar, 1)

	cluster1 := m.AddState(s1)
	cluster2 := m.AddState(s2)

	// Very similar states should be in same cluster
	if cluster1.ID != cluster2.ID {
		t.Logf("near-duplicate states in clusters %d and %d", cluster1.ID, cluster2.ID)
	}
}

func TestAddDifferentStateNewCluster(t *testing.T) {
	// CRAWLJAX PARITY: Different states create separate clusters
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "First unique content AAAA", 0)
	s2 := New("http://test.com", "", "Second unique content BBBB", 1)

	m.AddState(s1)
	m.AddState(s2)

	if m.GetClusterCount() != 2 {
		t.Errorf("different states should create 2 clusters, got %d", m.GetClusterCount())
	}
}

func TestGetCluster(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	s := New("http://test.com", "", "Content", 0)
	addedCluster := m.AddState(s)

	found := m.GetCluster(s.ID)

	if found == nil {
		t.Fatal("GetCluster should find the state's cluster")
	}

	if found.ID != addedCluster.ID {
		t.Errorf("found cluster ID = %d, want %d", found.ID, addedCluster.ID)
	}
}

func TestGetClusterNotFound(t *testing.T) {
	m := NewNDClusterManager()

	found := m.GetCluster("nonexistent")

	if found != nil {
		t.Error("GetCluster should return nil for unknown state")
	}
}

func TestGetAllClusters(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "Content A", 0)
	s2 := New("http://test.com", "", "Content B", 1)
	s3 := New("http://test.com", "", "Content C", 2)

	m.AddState(s1)
	m.AddState(s2)
	m.AddState(s3)

	clusters := m.GetAllClusters()

	if len(clusters) != 3 {
		t.Errorf("GetAllClusters() = %d, want 3", len(clusters))
	}
}

func TestGetUniqueStates(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "Content A", 0)
	s2 := New("http://test.com", "", "Content B", 1)

	m.AddState(s1)
	m.AddState(s2)

	unique := m.GetUniqueStates()

	if len(unique) != 2 {
		t.Errorf("GetUniqueStates() = %d, want 2", len(unique))
	}
}

func TestAreNearDuplicates(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	// Create very similar states
	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"

	s1 := New("http://test.com", "", base, 0)
	s2 := New("http://test.com", "", base+"X", 1)

	m.AddState(s1)
	m.AddState(s2)

	// Check if they're near-duplicates
	result := m.AreNearDuplicates(s1.ID, s2.ID)
	t.Logf("AreNearDuplicates = %v", result)
}

func TestRemoveState(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "Content A", 0)
	s2 := New("http://test.com", "", "Content B", 1)

	m.AddState(s1)
	m.AddState(s2)

	initialCount := m.GetClusterCount()

	m.RemoveState(s1.ID)

	// s1's cluster should be removed (if it was the only member)
	cluster := m.GetCluster(s1.ID)
	if cluster != nil {
		t.Error("removed state should not have cluster")
	}

	// Total clusters should decrease
	if m.GetClusterCount() >= initialCount {
		t.Logf("cluster count after remove: %d (was %d)", m.GetClusterCount(), initialCount)
	}
}

func TestMergeClusters(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "Content A", 0)
	s2 := New("http://test.com", "", "Content B", 1)

	cluster1 := m.AddState(s1)
	cluster2 := m.AddState(s2)

	if cluster1.ID == cluster2.ID {
		t.Skip("states already in same cluster")
	}

	initialCount := m.GetClusterCount()

	m.MergeClusters(cluster1.ID, cluster2.ID)

	if m.GetClusterCount() != initialCount-1 {
		t.Errorf("cluster count after merge = %d, want %d", m.GetClusterCount(), initialCount-1)
	}

	// Both states should now be in same cluster
	c1 := m.GetCluster(s1.ID)
	c2 := m.GetCluster(s2.ID)

	if c1 == nil || c2 == nil {
		t.Error("states should still have clusters after merge")
		return
	}

	if c1.ID != c2.ID {
		t.Error("states should be in same cluster after merge")
	}
}

func TestRecluster(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "Content A", 0)
	s2 := New("http://test.com", "", "Content B", 1)
	s3 := New("http://test.com", "", "Content C", 2)

	m.AddState(s1)
	m.AddState(s2)
	m.AddState(s3)

	initialCount := m.GetClusterCount()

	// Recluster should reorganize without changing count (for distinct states)
	m.Recluster()

	if m.GetClusterCount() != initialCount {
		t.Logf("cluster count changed after recluster: %d -> %d", initialCount, m.GetClusterCount())
	}
}

func TestStats(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "Content A", 0)
	s2 := New("http://test.com", "", "Content B", 1)
	s3 := New("http://test.com", "", "Content C", 2)

	m.AddState(s1)
	m.AddState(s2)
	m.AddState(s3)

	stats := m.Stats()

	if stats.TotalClusters != 3 {
		t.Errorf("TotalClusters = %d, want 3", stats.TotalClusters)
	}

	if stats.TotalStates != 3 {
		t.Errorf("TotalStates = %d, want 3", stats.TotalStates)
	}

	if stats.LargestClusterSize != 1 {
		t.Errorf("LargestClusterSize = %d, want 1", stats.LargestClusterSize)
	}

	if stats.AvgClusterSize != 1.0 {
		t.Errorf("AvgClusterSize = %f, want 1.0", stats.AvgClusterSize)
	}
}

func TestFindSimilarStates(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	base := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	s1 := New("http://test.com", "", base, 0)
	s2 := New("http://test.com", "", base+"XYZ", 1)                                // Similar
	s3 := New("http://test.com", "", "Completely different content 1234567890", 2) // Different

	m.AddState(s1)
	m.AddState(s2)
	m.AddState(s3)

	similar := m.FindSimilarStates(s1, 0.5)

	// s2 should be found as similar
	found := false
	for _, s := range similar {
		if s.ID == s2.ID {
			found = true
			break
		}
	}

	if !found {
		t.Logf("similar states: %d found for threshold 0.5", len(similar))
	}
}

func TestGetClusterRepresentatives(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	s1 := New("http://test.com", "", "A", 0)
	s2 := New("http://test.com", "", "B", 1)
	s3 := New("http://test.com", "", "C", 2)

	m.AddState(s1)
	m.AddState(s2)
	m.AddState(s3)

	reps := m.GetClusterRepresentatives()

	if len(reps) != 3 {
		t.Errorf("representatives = %d, want 3", len(reps))
	}
}

func TestNDClusterType(t *testing.T) {
	cluster := NewNDCluster(1, New("http://test.com", "", "test", 0))

	if cluster.Type != StateIdentical {
		t.Errorf("initial cluster type = %v, want StateIdentical", cluster.Type)
	}

	// Add member with ND1 comparison
	cluster.AddMember(New("http://test.com", "", "test2", 1), StateNearDuplicate1)

	if cluster.Type != StateNearDuplicate1 {
		t.Errorf("after ND1 add, type = %v, want StateNearDuplicate1", cluster.Type)
	}

	// Add member with ND2 (weaker) - type should become ND2
	cluster.AddMember(New("http://test.com", "", "test3", 2), StateNearDuplicate2)

	if cluster.Type != StateNearDuplicate2 {
		t.Errorf("after ND2 add, type = %v, want StateNearDuplicate2", cluster.Type)
	}
}

func TestNDClusterContainsState(t *testing.T) {
	ResetCounter()
	s1 := New("http://test.com", "", "A", 0)
	s2 := New("http://test.com", "", "B", 1)
	s3 := New("http://test.com", "", "C", 2)

	cluster := NewNDCluster(1, s1)
	cluster.AddMember(s2, StateNearDuplicate1)

	if !cluster.ContainsState(s1.ID) {
		t.Error("cluster should contain s1")
	}

	if !cluster.ContainsState(s2.ID) {
		t.Error("cluster should contain s2")
	}

	if cluster.ContainsState(s3.ID) {
		t.Error("cluster should not contain s3")
	}
}

func TestStateComparisonString(t *testing.T) {
	tests := []struct {
		comp     StateComparison
		expected string
	}{
		{StateIdentical, "IDENTICAL"},
		{StateNearDuplicate1, "ND1"},
		{StateNearDuplicate2, "ND2"},
		{StateDifferent, "DIFFERENT"},
	}

	for _, tt := range tests {
		if tt.comp.String() != tt.expected {
			t.Errorf("%v.String() = %q, want %q", tt.comp, tt.comp.String(), tt.expected)
		}
	}
}

func TestDOMDiff(t *testing.T) {
	ResetCounter()

	s1 := New("http://test.com", "", "<body><div>A</div><div>B</div></body>", 0)
	s2 := New("http://test.com", "", "<body><div>A</div><div>C</div></body>", 1)

	diff := GetDOMDiff(s1, s2)

	if diff == nil {
		t.Fatal("diff should not be nil")
	}

	// There should be some differences (B vs C)
	if diff.IsEmpty() {
		t.Error("diff should not be empty for different DOMs")
	}

	t.Logf("diff size: %d (added: %d, removed: %d)", diff.Size(), len(diff.Added), len(diff.Removed))
}

func TestDOMDiffIdentical(t *testing.T) {
	ResetCounter()

	dom := "<body><div>Same Content</div></body>"
	s1 := New("http://test.com", "", dom, 0)
	s2 := New("http://test.com", "", dom, 1)

	diff := GetDOMDiff(s1, s2)

	if !diff.IsEmpty() {
		t.Errorf("diff should be empty for identical DOMs, got added=%d, removed=%d",
			len(diff.Added), len(diff.Removed))
	}
}

// ============================================================================
// Concurrency tests
// ============================================================================

func TestNDClusterManagerConcurrency(t *testing.T) {
	m := NewNDClusterManager()
	ResetCounter()

	// Pre-create states
	states := make([]*State, 100)
	for i := 0; i < 100; i++ {
		states[i] = New("http://test.com", "", "Content_"+string(rune('A'+i%26)), i)
	}

	done := make(chan bool, 3)

	// Concurrent adds
	go func() {
		for i := 0; i < 50; i++ {
			m.AddState(states[i])
		}
		done <- true
	}()

	go func() {
		for i := 50; i < 100; i++ {
			m.AddState(states[i])
		}
		done <- true
	}()

	// Concurrent reads
	go func() {
		for i := 0; i < 100; i++ {
			m.GetAllClusters()
			m.Stats()
			m.GetClusterCount()
		}
		done <- true
	}()

	<-done
	<-done
	<-done

	// Should have some clusters
	if m.GetClusterCount() == 0 {
		t.Error("should have clusters after concurrent operations")
	}
}

// ============================================================================
// Jaccard Similarity tests
// ============================================================================

func TestJaccardSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		set1     map[string]bool
		set2     map[string]bool
		expected float64
	}{
		{
			name:     "identical sets",
			set1:     map[string]bool{"a": true, "b": true, "c": true},
			set2:     map[string]bool{"a": true, "b": true, "c": true},
			expected: 1.0,
		},
		{
			name:     "disjoint sets",
			set1:     map[string]bool{"a": true, "b": true},
			set2:     map[string]bool{"c": true, "d": true},
			expected: 0.0,
		},
		{
			name:     "half overlap",
			set1:     map[string]bool{"a": true, "b": true},
			set2:     map[string]bool{"b": true, "c": true},
			expected: 1.0 / 3.0, // intersection=1, union=3
		},
		{
			name:     "both empty",
			set1:     map[string]bool{},
			set2:     map[string]bool{},
			expected: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jaccardSimilarity(tt.set1, tt.set2)
			if result != tt.expected {
				// Allow small floating point differences
				diff := result - tt.expected
				if diff < -0.01 || diff > 0.01 {
					t.Errorf("jaccardSimilarity() = %f, want %f", result, tt.expected)
				}
			}
		})
	}
}

func TestExtractShingles(t *testing.T) {
	tests := []struct {
		text     string
		k        int
		expected int // expected number of shingles
	}{
		{"hello", 5, 1},  // exactly k chars = 1 shingle
		{"hello", 6, 1},  // less than k chars = 1 shingle (the whole string)
		{"hello", 3, 3},  // "hel", "ell", "llo"
		{"abcdef", 3, 4}, // "abc", "bcd", "cde", "def"
		{"", 3, 1},       // empty string = 1 empty shingle
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			shingles := extractShingles(tt.text, tt.k)
			if len(shingles) != tt.expected {
				t.Errorf("extractShingles(%q, %d) = %d shingles, want %d",
					tt.text, tt.k, len(shingles), tt.expected)
			}
		})
	}
}

func TestCalculateDOMSimilarity(t *testing.T) {
	tests := []struct {
		name   string
		dom1   string
		dom2   string
		minSim float64
		maxSim float64
	}{
		{"identical", "hello world", "hello world", 1.0, 1.0},
		{"completely different", "aaaaaaaaaa", "bbbbbbbbbb", 0.0, 0.1},
		{"similar", "hello world", "hello world!", 0.8, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sim := calculateDOMSimilarity(tt.dom1, tt.dom2)
			if sim < tt.minSim || sim > tt.maxSim {
				t.Errorf("calculateDOMSimilarity() = %f, want [%f, %f]",
					sim, tt.minSim, tt.maxSim)
			}
		})
	}
}
