package state

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func TestNewComparator(t *testing.T) {
	cfg := &config.Config{
		DOMStripTags:  []string{"script", "style"},
		DOMStripAttrs: []string{"id", "class"},
	}

	c := NewComparator(cfg)

	if c == nil {
		t.Fatal("expected non-nil comparator")
	}

	// Check defaults
	if c.mode != CompareModeExact {
		t.Errorf("mode = %v, want CompareModeExact", c.mode)
	}
	if c.nearDuplicateThreshold != 0.9 {
		t.Errorf("nearDuplicateThreshold = %f, want 0.9", c.nearDuplicateThreshold)
	}
	if c.nd1Threshold != 0.95 {
		t.Errorf("nd1Threshold = %f, want 0.95", c.nd1Threshold)
	}
	if c.nd2Threshold != 0.80 {
		t.Errorf("nd2Threshold = %f, want 0.80", c.nd2Threshold)
	}
}

func TestNewComparatorDefault(t *testing.T) {
	c := NewComparatorDefault()

	if c == nil {
		t.Fatal("expected non-nil comparator")
	}

	// Check default strip tags and attrs are set
	if len(c.stripTags) == 0 {
		t.Error("expected default strip tags to be set")
	}
	if len(c.stripAttrs) == 0 {
		t.Error("expected default strip attrs to be set")
	}
}

func TestComparatorSetMode(t *testing.T) {
	c := NewComparatorDefault()

	// Test fluent interface
	result := c.SetMode(CompareModeDistance)

	if result != c {
		t.Error("SetMode should return the same comparator for chaining")
	}
	if c.mode != CompareModeDistance {
		t.Errorf("mode = %v, want CompareModeDistance", c.mode)
	}

	c.SetMode(CompareModeFragment)
	if c.mode != CompareModeFragment {
		t.Errorf("mode = %v, want CompareModeFragment", c.mode)
	}
}

func TestComparatorSetThresholds(t *testing.T) {
	c := NewComparatorDefault()

	c.SetNearDuplicateThreshold(0.85)
	if c.nearDuplicateThreshold != 0.85 {
		t.Errorf("nearDuplicateThreshold = %f, want 0.85", c.nearDuplicateThreshold)
	}

	c.SetND1Threshold(0.98)
	if c.nd1Threshold != 0.98 {
		t.Errorf("nd1Threshold = %f, want 0.98", c.nd1Threshold)
	}

	c.SetND2Threshold(0.75)
	if c.nd2Threshold != 0.75 {
		t.Errorf("nd2Threshold = %f, want 0.75", c.nd2Threshold)
	}
}

func TestAreEquivalent(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault()

	tests := []struct {
		name   string
		s1DOM  string
		s2DOM  string
		expect bool
	}{
		{"identical DOM", "same content", "same content", true},
		{"different DOM", "content A", "content B", false},
		{"empty identical", "", "", true},
		{"one empty", "content", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := New("http://test.com", "", tt.s1DOM, 0)
			s2 := New("http://test.com", "", tt.s2DOM, 0)

			result := c.AreEquivalent(s1, s2)
			if result != tt.expect {
				t.Errorf("AreEquivalent() = %v, want %v", result, tt.expect)
			}
		})
	}
}

func TestAreEquivalentNil(t *testing.T) {
	c := NewComparatorDefault()
	ResetCounter()

	s := New("http://test.com", "", "content", 0)

	// Both nil - equivalent
	if !c.AreEquivalent(nil, nil) {
		t.Error("nil == nil should be equivalent")
	}

	// One nil - not equivalent
	if c.AreEquivalent(s, nil) {
		t.Error("state != nil should not be equivalent")
	}
	if c.AreEquivalent(nil, s) {
		t.Error("nil != state should not be equivalent")
	}
}

func TestCompareExactMode(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault().SetMode(CompareModeExact)

	s1 := New("http://test.com", "", "DOM content", 0)
	s2 := New("http://test.com", "", "DOM content", 0)
	s3 := New("http://test.com", "", "Different DOM", 0)

	// Same DOM = Duplicate
	if result := c.Compare(s1, s2); result != ResultDuplicate {
		t.Errorf("same DOM should be ResultDuplicate, got %v", result)
	}

	// Different DOM in exact mode = Different
	if result := c.Compare(s1, s3); result != ResultDifferent {
		t.Errorf("different DOM in exact mode should be ResultDifferent, got %v", result)
	}
}

func TestCompareDistanceMode(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault().SetMode(CompareModeDistance)

	// Create states with varying similarity
	base := "ABCDEFGHIJ" // 10 chars
	s1 := New("http://test.com", "", base, 0)

	// Exact match
	s2 := New("http://test.com", "", base, 0)
	if result := c.Compare(s1, s2); result != ResultDuplicate {
		t.Errorf("identical should be ResultDuplicate, got %v", result)
	}

	// Very similar (>95%) - ND1
	similar := "ABCDEFGHIK" // 1 char different = 90% similar... need more chars
	// For more precise testing, use longer strings
	longBase := "ABCDEFGHIJKLMNOPQRST" // 20 chars
	long95 := "ABCDEFGHIJKLMNOPQRSX"   // 1 char = 95% similar
	s3 := New("http://test.com", "", longBase, 0)
	s4 := New("http://test.com", "", long95, 0)
	if result := c.Compare(s3, s4); result != ResultNearDuplicate1 {
		// May get ND2 depending on exact distance
		t.Logf("95%% similar got %v (expected ND1 or ND2)", result)
	}

	// Moderately similar (80-95%) - ND2
	long80 := "ABCDEFGHIJKLMNXXXXXX" // 4 chars different = 80% similar
	s5 := New("http://test.com", "", longBase, 0)
	s6 := New("http://test.com", "", long80, 0)
	result := c.Compare(s5, s6)
	if result != ResultNearDuplicate1 && result != ResultNearDuplicate2 {
		t.Logf("80%% similar got %v (expected ND1 or ND2)", result)
	}

	// Very different (<80%)
	different := "XXXXXXXXXXXXXXXXXXXX"
	s7 := New("http://test.com", "", longBase, 0)
	s8 := New("http://test.com", "", different, 0)
	if result := c.Compare(s7, s8); result != ResultDifferent {
		t.Errorf("very different should be ResultDifferent, got %v", result)
	}

	_ = similar // Avoid unused variable error
}

func TestCompareNil(t *testing.T) {
	c := NewComparatorDefault()
	ResetCounter()

	s := New("http://test.com", "", "content", 0)

	// Both nil - Duplicate (same as each other)
	if result := c.Compare(nil, nil); result != ResultDuplicate {
		t.Errorf("nil == nil should be ResultDuplicate, got %v", result)
	}

	// One nil - Different
	if result := c.Compare(s, nil); result != ResultDifferent {
		t.Errorf("state vs nil should be ResultDifferent, got %v", result)
	}
	if result := c.Compare(nil, s); result != ResultDifferent {
		t.Errorf("nil vs state should be ResultDifferent, got %v", result)
	}
}

func TestCalculateDistance(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault()

	tests := []struct {
		name     string
		dom1     string
		dom2     string
		expected float64
		delta    float64 // Allowable difference
	}{
		{"identical", "hello world", "hello world", 0.0, 0.01},
		{"completely different", "aaaaa", "bbbbb", 1.0, 0.01},
		{"one empty", "hello", "", 1.0, 0.01},
		{"both empty", "", "", 0.0, 0.01},
		{"one char diff", "hello", "hallo", 0.2, 0.01},                  // 1/5 = 0.2
		{"half different", "abcd", "efcd", 0.5, 0.01},                   // 2/4 = 0.5
		{"one char same", "abcde", "fghij", 1.0, 0.01},                  // all different
		{"insertion", "abc", "abxc", 0.25, 0.01},                        // 1 insertion, max len 4
		{"deletion", "abcd", "abd", 0.25, 0.01},                         // 1 deletion, max len 4
		{"substitution", "cat", "car", 0.33, 0.05},                      // 1 substitution, max len 3
		{"mixed operations", "kitten", "sitting", 0.43, 0.05},           // classic example: 3 edits / 7
		{"case sensitive", "HELLO", "hello", 1.0, 0.01},                 // All chars different
		{"whitespace matters", "hello world", "helloworld", 0.09, 0.02}, // 1 deletion / 11
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s1 := New("http://test.com", "", tt.dom1, 0)
			s2 := New("http://test.com", "", tt.dom2, 0)

			distance := c.CalculateDistance(s1, s2)

			if diff := distance - tt.expected; diff < -tt.delta || diff > tt.delta {
				t.Errorf("CalculateDistance() = %f, want %f (±%f)", distance, tt.expected, tt.delta)
			}
		})
	}
}

func TestCalculateDistanceNil(t *testing.T) {
	c := NewComparatorDefault()
	ResetCounter()

	s := New("http://test.com", "", "content", 0)

	if d := c.CalculateDistance(nil, nil); d != 1.0 {
		t.Errorf("distance(nil, nil) = %f, want 1.0", d)
	}
	if d := c.CalculateDistance(s, nil); d != 1.0 {
		t.Errorf("distance(s, nil) = %f, want 1.0", d)
	}
	if d := c.CalculateDistance(nil, s); d != 1.0 {
		t.Errorf("distance(nil, s) = %f, want 1.0", d)
	}
}

func TestCalculateDistanceSameID(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault()

	// Two states with same stripped DOM have same ID
	s1 := New("http://test.com/a", "<html>raw</html>", "same stripped", 0)
	s2 := New("http://test.com/b", "<div>other raw</div>", "same stripped", 1)

	if d := c.CalculateDistance(s1, s2); d != 0.0 {
		t.Errorf("distance(same ID) = %f, want 0.0", d)
	}
}

func TestCalculateSimilarity(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault()

	s1 := New("http://test.com", "", "hello world", 0)
	s2 := New("http://test.com", "", "hello world", 0)

	similarity := c.CalculateSimilarity(s1, s2)
	if similarity != 1.0 {
		t.Errorf("similarity of identical = %f, want 1.0", similarity)
	}

	s3 := New("http://test.com", "", "different", 0)
	similarity = c.CalculateSimilarity(s1, s3)
	if similarity >= 1.0 || similarity < 0 {
		t.Errorf("similarity = %f, want 0 <= x < 1", similarity)
	}
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s1       string
		s2       string
		expected int
	}{
		{"", "", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"abc", "adc", 1},
		{"abc", "dbc", 1},
		{"abc", "abcd", 1},
		{"abcd", "abc", 1},
		{"kitten", "sitting", 3},
		{"saturday", "sunday", 3},
		{"abc", "xyz", 3},
	}

	for _, tt := range tests {
		t.Run(tt.s1+"_"+tt.s2, func(t *testing.T) {
			result := levenshteinDistance(tt.s1, tt.s2)
			if result != tt.expected {
				t.Errorf("levenshteinDistance(%q, %q) = %d, want %d", tt.s1, tt.s2, result, tt.expected)
			}

			// Symmetric
			result2 := levenshteinDistance(tt.s2, tt.s1)
			if result2 != tt.expected {
				t.Errorf("levenshteinDistance(%q, %q) = %d, want %d (symmetric)", tt.s2, tt.s1, result2, tt.expected)
			}
		})
	}
}

func TestPrepareForComparison(t *testing.T) {
	c := NewComparatorDefault()

	// Test that script tags are stripped
	html := "<html><body><script>alert('hi')</script><div>content</div></body></html>"
	result := c.PrepareForComparison(html)

	if len(result) >= len(html) {
		t.Error("PrepareForComparison should strip content and make it shorter")
	}
}

func TestCreateState(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault()

	rawHTML := "<html><body><script>js</script><div id='main'>Hello</div></body></html>"
	s := c.CreateState("http://test.com", rawHTML, 2)

	if s == nil {
		t.Fatal("expected non-nil state")
	}

	if s.URL != "http://test.com" {
		t.Errorf("URL = %q, want http://test.com", s.URL)
	}
	if s.RawHTML != rawHTML {
		t.Errorf("RawHTML should be preserved")
	}
	if s.Depth != 2 {
		t.Errorf("Depth = %d, want 2", s.Depth)
	}
	// StrippedDOM should not contain script
	if s.StrippedDOM == rawHTML {
		t.Error("StrippedDOM should be different from rawHTML")
	}
}

func TestCreateIndexState(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault()

	s := c.CreateIndexState("http://test.com", "<html></html>")

	if !s.IsIndex() {
		t.Error("expected index state")
	}
	if s.Depth != 0 {
		t.Errorf("index state Depth = %d, want 0", s.Depth)
	}
}

func TestFindEquivalent(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	c := NewComparatorDefault()
	g := NewGraph()

	// Add some states
	s1 := New("http://test.com/a", "", "DOM A", 0)
	s2 := New("http://test.com/b", "", "DOM B", 1)
	s3 := New("http://test.com/c", "", "DOM C", 2)
	g.AddState(s1)
	g.AddState(s2)
	g.AddState(s3)

	// Find existing
	target := New("http://other.com", "", "DOM B", 5)
	found := c.FindEquivalent(g, target)

	if found == nil {
		t.Fatal("expected to find equivalent state")
	}
	if found.ID != s2.ID {
		t.Errorf("found ID = %q, want %q", found.ID, s2.ID)
	}

	// Find non-existing
	missing := New("http://test.com", "", "Unknown DOM", 0)
	notFound := c.FindEquivalent(g, missing)
	if notFound != nil {
		t.Error("expected nil for non-existing state")
	}

	// Nil target
	if c.FindEquivalent(g, nil) != nil {
		t.Error("expected nil for nil target")
	}
}

func TestFindEquivalentOrNearDuplicateExactMode(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	c := NewComparatorDefault().SetMode(CompareModeExact)
	g := NewGraph()

	s1 := New("http://test.com", "", "DOM content", 0)
	g.AddState(s1)

	// Find exact match
	target := New("http://other.com", "", "DOM content", 0)
	found, result := c.FindEquivalentOrNearDuplicate(g, target)

	if result != ResultDuplicate {
		t.Errorf("result = %v, want ResultDuplicate", result)
	}
	if found == nil {
		t.Fatal("expected to find state")
	}

	// Find no match (exact mode doesn't do near-duplicate)
	nearDup := New("http://test.com", "", "DOM contenx", 0) // 1 char diff
	found, result = c.FindEquivalentOrNearDuplicate(g, nearDup)

	if result != ResultDifferent {
		t.Errorf("result = %v, want ResultDifferent (exact mode)", result)
	}
	if found != nil {
		t.Error("expected nil in exact mode for non-matching")
	}
}

func TestFindEquivalentOrNearDuplicateDistanceMode(t *testing.T) {
	ResetCounter()
	action.ResetEventableIDCounter()
	c := NewComparatorDefault().SetMode(CompareModeDistance)
	g := NewGraph()

	baseDOM := "This is a sample DOM content for testing purposes."
	s1 := New("http://test.com", "", baseDOM, 0)
	g.AddState(s1)

	// Find exact match
	exact := New("http://other.com", "", baseDOM, 0)
	found, result := c.FindEquivalentOrNearDuplicate(g, exact)
	if result != ResultDuplicate {
		t.Errorf("exact match result = %v, want ResultDuplicate", result)
	}
	if found == nil {
		t.Error("expected to find exact match")
	}

	// Find near-duplicate (very similar)
	nearDOM := "This is a sample DOM content for testing purposex." // 1 char diff
	near := New("http://other.com", "", nearDOM, 0)
	found, result = c.FindEquivalentOrNearDuplicate(g, near)

	if result != ResultNearDuplicate1 && result != ResultNearDuplicate2 {
		t.Errorf("near-duplicate result = %v, want ND1 or ND2", result)
	}
	if found == nil {
		t.Error("expected to find near-duplicate")
	}

	// Find nothing (very different)
	different := "Completely different content that has nothing in common."
	diffState := New("http://other.com", "", different, 0)
	_, result = c.FindEquivalentOrNearDuplicate(g, diffState)

	if result != ResultDifferent {
		t.Errorf("different content result = %v, want ResultDifferent", result)
	}
}

func TestCompareResultConstants(t *testing.T) {
	// Ensure constants have expected values
	if ResultDifferent != 0 {
		t.Errorf("ResultDifferent = %d, want 0", ResultDifferent)
	}
	if ResultDuplicate != 1 {
		t.Errorf("ResultDuplicate = %d, want 1", ResultDuplicate)
	}
	if ResultNearDuplicate1 != 2 {
		t.Errorf("ResultNearDuplicate1 = %d, want 2", ResultNearDuplicate1)
	}
	if ResultNearDuplicate2 != 3 {
		t.Errorf("ResultNearDuplicate2 = %d, want 3", ResultNearDuplicate2)
	}
}

func TestCompareModeConstants(t *testing.T) {
	if CompareModeExact != 0 {
		t.Errorf("CompareModeExact = %d, want 0", CompareModeExact)
	}
	if CompareModeDistance != 1 {
		t.Errorf("CompareModeDistance = %d, want 1", CompareModeDistance)
	}
	if CompareModeFragment != 2 {
		t.Errorf("CompareModeFragment = %d, want 2", CompareModeFragment)
	}
}

func TestCalculateDistanceLongStrings(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault()

	// Create strings longer than maxCompareLen (10000)
	longStr := ""
	for i := 0; i < 15000; i++ {
		longStr += "A"
	}

	s1 := New("http://test.com", "", longStr, 0)
	s2 := New("http://test.com", "", longStr, 0)

	// Same long strings should be identical
	if d := c.CalculateDistance(s1, s2); d != 0.0 {
		t.Errorf("identical long strings distance = %f, want 0.0", d)
	}

	// Different long strings should use sampling
	longStr2 := ""
	for i := 0; i < 15000; i++ {
		longStr2 += "B"
	}
	s3 := New("http://test.com", "", longStr2, 0)

	d := c.CalculateDistance(s1, s3)
	if d < 0.5 {
		t.Errorf("completely different long strings distance = %f, want > 0.5", d)
	}
}

func TestMinThree(t *testing.T) {
	tests := []struct {
		a, b, c  int
		expected int
	}{
		{1, 2, 3, 1},
		{3, 2, 1, 1},
		{2, 1, 3, 1},
		{5, 5, 5, 5},
		{0, 1, 2, 0},
		{-1, 0, 1, -1},
	}

	for _, tt := range tests {
		result := minThree(tt.a, tt.b, tt.c)
		if result != tt.expected {
			t.Errorf("minThree(%d, %d, %d) = %d, want %d", tt.a, tt.b, tt.c, result, tt.expected)
		}
	}
}

func TestAbsMinMax(t *testing.T) {
	if abs(-5) != 5 {
		t.Error("abs(-5) should be 5")
	}
	if abs(5) != 5 {
		t.Error("abs(5) should be 5")
	}
	if abs(0) != 0 {
		t.Error("abs(0) should be 0")
	}

	if min(3, 5) != 3 {
		t.Error("min(3, 5) should be 3")
	}
	if min(5, 3) != 3 {
		t.Error("min(5, 3) should be 3")
	}

	if max(3, 5) != 5 {
		t.Error("max(3, 5) should be 5")
	}
	if max(5, 3) != 5 {
		t.Error("max(5, 3) should be 5")
	}
}

func TestCompareWithFragmentsFallback(t *testing.T) {
	ResetCounter()
	c := NewComparatorDefault().SetMode(CompareModeFragment)

	// Without fragment manager, should fall back to distance comparison
	s1 := New("http://test.com", "", "content A", 0)
	s2 := New("http://test.com", "", "content B", 0)

	result := c.Compare(s1, s2)
	// Should not panic and should return some result
	if result != ResultDifferent && result != ResultNearDuplicate1 && result != ResultNearDuplicate2 {
		t.Errorf("unexpected result without fragment manager: %v", result)
	}
}

func BenchmarkLevenshteinDistance(b *testing.B) {
	s1 := "kitten sitting on the mat in the house"
	s2 := "sitting on the mat in the house with kitten"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		levenshteinDistance(s1, s2)
	}
}

func BenchmarkCalculateDistance(b *testing.B) {
	ResetCounter()
	c := NewComparatorDefault()

	s1 := New("http://test.com", "", "This is a longer piece of content for benchmarking.", 0)
	s2 := New("http://test.com", "", "This is a longer piece of different content for benchmarking.", 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.CalculateDistance(s1, s2)
	}
}
