package state

import (
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/fragment"
)

// CompareMode defines the state comparison strategy.
type CompareMode int

const (
	// CompareModeExact uses hash-based exact matching (default).
	CompareModeExact CompareMode = iota
	// CompareModeDistance uses Levenshtein distance-based comparison.
	CompareModeDistance
	// CompareModeFragment uses fragment-based near-duplicate detection.
	CompareModeFragment
)

// CompareResult defines the result of state comparison.
type CompareResult int

const (
	// ResultDifferent - states are completely different.
	ResultDifferent CompareResult = iota
	// ResultDuplicate - states are exact duplicates.
	ResultDuplicate
	// ResultNearDuplicate1 - states differ only in dynamic fragments.
	ResultNearDuplicate1
	// ResultNearDuplicate2 - states are structurally similar but content differs.
	ResultNearDuplicate2
)

// Comparator compares states for equivalence.
type Comparator struct {
	stripTags  []string
	stripAttrs []string

	// Fragment-based comparison settings
	mode                   CompareMode
	nearDuplicateThreshold float64 // Threshold for near-duplicate detection (default 0.9)
	fragManager            *fragment.Manager

	nd1Threshold float64 // ND1 threshold (default 0.95 = 95% similarity)
	nd2Threshold float64 // ND2 threshold (default 0.80 = 80% similarity)
}

// NewComparator creates a new state comparator.
func NewComparator(cfg *config.Config) *Comparator {
	return &Comparator{
		stripTags:              cfg.DOMStripTags,
		stripAttrs:             cfg.DOMStripAttrs,
		mode:                   CompareModeExact,
		nearDuplicateThreshold: 0.9,
		nd1Threshold:           0.95,
		nd2Threshold:           0.80,
	}
}

// NewComparatorDefault creates a comparator with default settings.
func NewComparatorDefault() *Comparator {
	return &Comparator{
		stripTags:              DefaultStripTags,
		stripAttrs:             DefaultStripAttrs,
		mode:                   CompareModeExact,
		nearDuplicateThreshold: 0.9,
		nd1Threshold:           0.95,
		nd2Threshold:           0.80,
	}
}

// SetMode sets the comparison mode.
func (c *Comparator) SetMode(mode CompareMode) *Comparator {
	c.mode = mode
	return c
}

// SetNearDuplicateThreshold sets the threshold for near-duplicate detection.
func (c *Comparator) SetNearDuplicateThreshold(threshold float64) *Comparator {
	c.nearDuplicateThreshold = threshold
	return c
}

// SetFragmentManager sets the fragment manager for fragment-based comparison.
func (c *Comparator) SetFragmentManager(fm *fragment.Manager) *Comparator {
	c.fragManager = fm
	return c
}

// SetND1Threshold sets the ND1 (near-duplicate level 1) threshold.
// Default is 0.95 (95% similarity).
func (c *Comparator) SetND1Threshold(threshold float64) *Comparator {
	c.nd1Threshold = threshold
	return c
}

// SetND2Threshold sets the ND2 (near-duplicate level 2) threshold.
// Default is 0.80 (80% similarity).
func (c *Comparator) SetND2Threshold(threshold float64) *Comparator {
	c.nd2Threshold = threshold
	return c
}

// AreEquivalent compares two states for equivalence.
// States are equivalent if they have the same ID (which is derived from stripped DOM hash).
func (c *Comparator) AreEquivalent(s1, s2 *State) bool {
	if s1 == nil || s2 == nil {
		return s1 == s2
	}
	return s1.ID == s2.ID
}

// Compare performs comprehensive state comparison and returns the result type.
// This method uses the configured comparison mode and fragment manager.
func (c *Comparator) Compare(s1, s2 *State) CompareResult {
	if s1 == nil || s2 == nil {
		if s1 == s2 {
			return ResultDuplicate
		}
		return ResultDifferent
	}

	// First check for exact match
	if s1.ID == s2.ID {
		zap.L().Debug("State comparison: exact match by ID",
			zap.String("state_id", s1.ID))
		return ResultDuplicate
	}

	// Use mode-specific comparison
	var result CompareResult
	switch c.mode {
	case CompareModeFragment:
		result = c.compareWithFragments(s1, s2)
	case CompareModeDistance:
		result = c.compareWithDistance(s1, s2)
	default:
		// Exact mode - already checked IDs above
		result = ResultDifferent
	}

	resultStr := "different"
	switch result {
	case ResultDuplicate:
		resultStr = "duplicate"
	case ResultNearDuplicate1:
		resultStr = "near_duplicate_1"
	case ResultNearDuplicate2:
		resultStr = "near_duplicate_2"
	}

	zap.L().Debug("State comparison completed",
		zap.String("state1", s1.ID),
		zap.String("state2", s2.ID),
		zap.String("mode", getModeString(c.mode)),
		zap.String("result", resultStr))

	return result
}

func getModeString(mode CompareMode) string {
	switch mode {
	case CompareModeFragment:
		return "fragment"
	case CompareModeDistance:
		return "distance"
	default:
		return "exact"
	}
}

// compareWithFragments uses fragment-based comparison.
func (c *Comparator) compareWithFragments(s1, s2 *State) CompareResult {
	if c.fragManager == nil {
		// Fallback to distance comparison if no fragment manager
		return c.compareWithDistance(s1, s2)
	}

	frags1 := c.fragManager.GetFragments(s1.ID)
	frags2 := c.fragManager.GetFragments(s2.ID)

	if len(frags1) == 0 || len(frags2) == 0 {
		// No fragments available, use distance comparison
		return c.compareWithDistance(s1, s2)
	}

	// Calculate fragment-based comparison
	summary := fragment.CalculateChangeSummary(frags1, frags2)

	if summary.IsIdentical() {
		return ResultDuplicate
	}

	if summary.IsNearDuplicate() {
		// Only dynamic fragments differ
		return ResultNearDuplicate1
	}

	// Check if static fragment similarity is above threshold
	staticSimilarity := fragment.CompareFragmentsStrict(
		filterStaticFragments(frags1),
		filterStaticFragments(frags2),
	)

	if staticSimilarity >= c.nearDuplicateThreshold {
		// Structural similarity is high, but some static content differs
		return ResultNearDuplicate2
	}

	return ResultDifferent
}

// compareWithDistance uses Levenshtein distance comparison.
//
//	threshold = 2 * max(len1, len2) * (1 - p)
//	isClone = distance <= threshold
//
// Where p is the threshold parameter (e.g., 0.95 for ND1, 0.80 for ND2).
func (c *Comparator) compareWithDistance(s1, s2 *State) CompareResult {
	dom1 := s1.StrippedDOM
	dom2 := s2.StrippedDOM

	if dom1 == dom2 {
		return ResultDuplicate
	}

	// Calculate raw Levenshtein distance
	maxLen := max(len(dom1), len(dom2))
	if maxLen == 0 {
		return ResultDuplicate
	}

	var dist int
	const maxCompareLen = 10000
	if len(dom1) > maxCompareLen || len(dom2) > maxCompareLen {
		// Use sampled distance for very long strings
		sampledNorm := c.calculateDistanceSampled(dom1, dom2, maxCompareLen)
		dist = int(sampledNorm * float64(maxLen))
	} else {
		dist = levenshteinDistance(dom1, dom2)
	}

	if dist == 0 {
		return ResultDuplicate
	}

	//   threshold = 2 * max(len1, len2) * (1 - p)
	//   isClone = distance <= threshold
	nd1Threshold := 2.0 * float64(maxLen) * (1.0 - c.nd1Threshold)
	if float64(dist) <= nd1Threshold {
		return ResultNearDuplicate1
	}

	nd2Threshold := 2.0 * float64(maxLen) * (1.0 - c.nd2Threshold)
	if float64(dist) <= nd2Threshold {
		return ResultNearDuplicate2
	}

	return ResultDifferent
}

// filterStaticFragments returns only non-dynamic fragments.
func filterStaticFragments(frags []*fragment.Fragment) []*fragment.Fragment {
	result := make([]*fragment.Fragment, 0, len(frags))
	for _, f := range frags {
		if !f.IsDynamic {
			result = append(result, f)
		}
	}
	return result
}

// FindEquivalent finds an existing state in the graph that matches the target.
func (c *Comparator) FindEquivalent(g *Graph, target *State) *State {
	if target == nil {
		return nil
	}
	return g.FindStateByDOM(target.StrippedDOM)
}

// FindEquivalentOrNearDuplicate finds an existing state that matches or is near-duplicate.
// This method is more lenient than FindEquivalent and uses the configured comparison mode.
func (c *Comparator) FindEquivalentOrNearDuplicate(g *Graph, target *State) (*State, CompareResult) {
	if target == nil {
		return nil, ResultDifferent
	}

	// First try exact match
	if exact := g.FindStateByDOM(target.StrippedDOM); exact != nil {
		return exact, ResultDuplicate
	}

	// If using fragment or distance mode, search for near-duplicates
	if c.mode == CompareModeExact {
		return nil, ResultDifferent
	}

	// Search all states for near-duplicates
	var bestMatch *State
	bestResult := ResultDifferent

	for _, state := range g.AllStates() {
		result := c.Compare(target, state)
		switch result {
		case ResultNearDuplicate1:
			// Best possible near-duplicate, return immediately
			return state, ResultNearDuplicate1
		case ResultNearDuplicate2:
			// Good near-duplicate, keep searching for better
			if bestResult != ResultNearDuplicate1 {
				bestMatch = state
				bestResult = ResultNearDuplicate2
			}
		}
	}

	return bestMatch, bestResult
}

// PrepareForComparison strips and normalizes raw HTML for comparison. It also
// neutralizes volatile content (tokens/timestamps/counters) so a page carrying a
// live clock, CSRF nonce, or cache-buster does not mint a fresh state each visit.
func (c *Comparator) PrepareForComparison(rawHTML string) string {
	return NormalizeVolatile(StripDOM(rawHTML, c.stripTags, c.stripAttrs))
}

// CreateState creates a state from raw HTML, stripping as configured.
func (c *Comparator) CreateState(url, rawHTML string, depth int) *State {
	strippedDOM := c.PrepareForComparison(rawHTML)
	return New(url, rawHTML, strippedDOM, depth)
}

// CreateIndexState creates the index state from raw HTML.
func (c *Comparator) CreateIndexState(url, rawHTML string) *State {
	strippedDOM := c.PrepareForComparison(rawHTML)
	return NewIndex(url, rawHTML, strippedDOM)
}

// CalculateDistance calculates the normalized Levenshtein distance between two states.
// Returns 0 for identical states, 1 for completely different states.
// MEDIUM PRIORITY: Improved distance calculation using proper Levenshtein algorithm.
func (c *Comparator) CalculateDistance(s1, s2 *State) float64 {
	if s1 == nil || s2 == nil {
		return 1.0
	}

	if s1.ID == s2.ID {
		return 0.0
	}

	dom1 := s1.StrippedDOM
	dom2 := s2.StrippedDOM

	if len(dom1) == 0 && len(dom2) == 0 {
		return 0.0
	}

	if len(dom1) == 0 || len(dom2) == 0 {
		return 1.0
	}

	// For very long strings, use sampling to avoid O(n*m) complexity
	const maxCompareLen = 10000
	if len(dom1) > maxCompareLen || len(dom2) > maxCompareLen {
		return c.calculateDistanceSampled(dom1, dom2, maxCompareLen)
	}

	// Calculate actual Levenshtein distance
	distance := levenshteinDistance(dom1, dom2)

	// Normalize to 0-1 range
	maxLen := max(len(dom1), len(dom2))
	return float64(distance) / float64(maxLen)
}

// calculateDistanceSampled calculates distance using sampling for long strings.
func (c *Comparator) calculateDistanceSampled(s1, s2 string, sampleSize int) float64 {
	// Sample from beginning, middle, and end
	samples := 3
	chunkSize := sampleSize / samples

	totalDistance := 0
	totalLen := 0

	for i := 0; i < samples; i++ {
		// Calculate start position for each sample
		var start1, start2 int
		switch i {
		case 0: // Beginning
			start1, start2 = 0, 0
		case 1: // Middle
			start1 = (len(s1) - chunkSize) / 2
			start2 = (len(s2) - chunkSize) / 2
		case 2: // End
			start1 = len(s1) - chunkSize
			start2 = len(s2) - chunkSize
		}

		// Clamp to valid range
		if start1 < 0 {
			start1 = 0
		}
		if start2 < 0 {
			start2 = 0
		}

		end1 := min(start1+chunkSize, len(s1))
		end2 := min(start2+chunkSize, len(s2))

		chunk1 := s1[start1:end1]
		chunk2 := s2[start2:end2]

		if len(chunk1) > 0 && len(chunk2) > 0 {
			distance := levenshteinDistance(chunk1, chunk2)
			totalDistance += distance
			totalLen += max(len(chunk1), len(chunk2))
		}
	}

	if totalLen == 0 {
		return 1.0
	}

	return float64(totalDistance) / float64(totalLen)
}

// levenshteinDistance calculates the Levenshtein edit distance between two strings.
// Uses optimized single-row implementation for O(n) space complexity.
func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Make s1 the shorter string for space optimization
	if len(s1) > len(s2) {
		s1, s2 = s2, s1
	}

	// Use single row + previous value optimization
	// Space: O(min(m,n)), Time: O(m*n)
	row := make([]int, len(s1)+1)

	// Initialize first row
	for i := range row {
		row[i] = i
	}

	// Fill in the rest of the matrix
	for j := 1; j <= len(s2); j++ {
		prev := row[0]
		row[0] = j

		for i := 1; i <= len(s1); i++ {
			temp := row[i]

			if s1[i-1] == s2[j-1] {
				row[i] = prev
			} else {
				// min of insert, delete, replace
				row[i] = 1 + minThree(row[i-1], row[i], prev)
			}

			prev = temp
		}
	}

	return row[len(s1)]
}

// minThree returns the minimum of three integers.
func minThree(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

// CalculateSimilarity calculates similarity score (1 - distance).
// Returns 1.0 for identical states, 0.0 for completely different states.
func (c *Comparator) CalculateSimilarity(s1, s2 *State) float64 {
	return 1.0 - c.CalculateDistance(s1, s2)
}

// Helper functions

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
