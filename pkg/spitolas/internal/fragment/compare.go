package fragment

// CompareFragments returns similarity score between two fragment sets.
// Returns: 0.0 (completely different) to 1.0 (identical)
func CompareFragments(frags1, frags2 []*Fragment) float64 {
	if len(frags1) == 0 && len(frags2) == 0 {
		return 1.0
	}

	if len(frags1) == 0 || len(frags2) == 0 {
		return 0.0
	}

	// Build hash sets
	hashes1 := make(map[string]*Fragment)
	hashes2 := make(map[string]*Fragment)

	for _, f := range frags1 {
		hashes1[f.DOMHash] = f
	}
	for _, f := range frags2 {
		hashes2[f.DOMHash] = f
	}

	// Count matches
	matches := 0
	dynamicMatches := 0

	for hash, f1 := range hashes1 {
		if f2, ok := hashes2[hash]; ok {
			if f1.IsDynamic || f2.IsDynamic {
				dynamicMatches++
			} else {
				matches++
			}
		}
	}

	// Calculate similarity
	// Dynamic fragments are weighted less (0.5) since they're expected to change
	total := len(hashes1) + len(hashes2)
	matchScore := float64(matches*2 + dynamicMatches)
	similarity := matchScore / float64(total)

	if similarity > 1.0 {
		similarity = 1.0
	}

	return similarity
}

// CompareFragmentsStrict compares fragments strictly, treating all equally.
func CompareFragmentsStrict(frags1, frags2 []*Fragment) float64 {
	if len(frags1) == 0 && len(frags2) == 0 {
		return 1.0
	}

	if len(frags1) == 0 || len(frags2) == 0 {
		return 0.0
	}

	// Build hash sets
	hashes1 := make(map[string]bool)
	hashes2 := make(map[string]bool)

	for _, f := range frags1 {
		hashes1[f.DOMHash] = true
	}
	for _, f := range frags2 {
		hashes2[f.DOMHash] = true
	}

	// Count matches using Jaccard similarity
	intersection := 0
	for hash := range hashes1 {
		if hashes2[hash] {
			intersection++
		}
	}

	union := len(hashes1) + len(hashes2) - intersection
	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

// AreNearDuplicates checks if two fragment sets are near-duplicates.
// Near-duplicates differ only in dynamic fragments.
func AreNearDuplicates(frags1, frags2 []*Fragment, threshold float64) bool {
	// Extract only static fragments
	static1 := filterStatic(frags1)
	static2 := filterStatic(frags2)

	// Compare static fragments only
	similarity := CompareFragmentsStrict(static1, static2)

	return similarity >= threshold
}

// filterStatic returns only non-dynamic fragments.
func filterStatic(frags []*Fragment) []*Fragment {
	result := make([]*Fragment, 0, len(frags))
	for _, f := range frags {
		if !f.IsDynamic {
			result = append(result, f)
		}
	}
	return result
}

// GetDifferingFragments returns fragments that differ between two sets.
func GetDifferingFragments(frags1, frags2 []*Fragment) ([]*Fragment, []*Fragment) {
	hashes1 := make(map[string]*Fragment)
	hashes2 := make(map[string]*Fragment)

	for _, f := range frags1 {
		hashes1[f.DOMHash] = f
	}
	for _, f := range frags2 {
		hashes2[f.DOMHash] = f
	}

	// Fragments in frags1 but not in frags2
	onlyIn1 := make([]*Fragment, 0)
	for hash, f := range hashes1 {
		if _, ok := hashes2[hash]; !ok {
			onlyIn1 = append(onlyIn1, f)
		}
	}

	// Fragments in frags2 but not in frags1
	onlyIn2 := make([]*Fragment, 0)
	for hash, f := range hashes2 {
		if _, ok := hashes1[hash]; !ok {
			onlyIn2 = append(onlyIn2, f)
		}
	}

	return onlyIn1, onlyIn2
}

// GetMatchingFragments returns fragments that match between two sets.
func GetMatchingFragments(frags1, frags2 []*Fragment) []*Fragment {
	hashes2 := make(map[string]bool)
	for _, f := range frags2 {
		hashes2[f.DOMHash] = true
	}

	matching := make([]*Fragment, 0)
	for _, f := range frags1 {
		if hashes2[f.DOMHash] {
			matching = append(matching, f)
		}
	}

	return matching
}

// CalculateChangeSummary provides a detailed comparison summary.
func CalculateChangeSummary(frags1, frags2 []*Fragment) ChangeSummary {
	hashes1 := make(map[string]*Fragment)
	hashes2 := make(map[string]*Fragment)

	for _, f := range frags1 {
		hashes1[f.DOMHash] = f
	}
	for _, f := range frags2 {
		hashes2[f.DOMHash] = f
	}

	summary := ChangeSummary{
		TotalFragments1:  len(frags1),
		TotalFragments2:  len(frags2),
		MatchingCount:    0,
		AddedCount:       0,
		RemovedCount:     0,
		DynamicChanges:   0,
		StaticChanges:    0,
		AddedFragments:   make([]*Fragment, 0),
		RemovedFragments: make([]*Fragment, 0),
	}

	// Count matches and removed
	for hash, f := range hashes1 {
		if _, ok := hashes2[hash]; ok {
			summary.MatchingCount++
		} else {
			summary.RemovedCount++
			summary.RemovedFragments = append(summary.RemovedFragments, f)
			if f.IsDynamic {
				summary.DynamicChanges++
			} else {
				summary.StaticChanges++
			}
		}
	}

	// Count added
	for hash, f := range hashes2 {
		if _, ok := hashes1[hash]; !ok {
			summary.AddedCount++
			summary.AddedFragments = append(summary.AddedFragments, f)
			if f.IsDynamic {
				summary.DynamicChanges++
			} else {
				summary.StaticChanges++
			}
		}
	}

	// Calculate similarity
	if summary.TotalFragments1+summary.TotalFragments2 > 0 {
		summary.Similarity = float64(summary.MatchingCount*2) /
			float64(summary.TotalFragments1+summary.TotalFragments2)
	} else {
		summary.Similarity = 1.0
	}

	return summary
}

// ChangeSummary holds detailed comparison results.
type ChangeSummary struct {
	TotalFragments1  int
	TotalFragments2  int
	MatchingCount    int
	AddedCount       int
	RemovedCount     int
	DynamicChanges   int
	StaticChanges    int
	Similarity       float64
	AddedFragments   []*Fragment
	RemovedFragments []*Fragment
}

// HasSignificantChanges returns true if there are non-dynamic changes.
func (s ChangeSummary) HasSignificantChanges() bool {
	return s.StaticChanges > 0
}

// IsIdentical returns true if the fragment sets are identical.
func (s ChangeSummary) IsIdentical() bool {
	return s.AddedCount == 0 && s.RemovedCount == 0
}

// IsNearDuplicate returns true if only dynamic fragments differ.
func (s ChangeSummary) IsNearDuplicate() bool {
	return s.StaticChanges == 0 && (s.AddedCount > 0 || s.RemovedCount > 0)
}
