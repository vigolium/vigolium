package utils

// SearcherFactory is a factory for creating PatternSearcher instances.
type SearcherFactory struct {
}

// --- PatternSearcher Implementations for Special Cases and Wrappers ---

// nullPatternSearcher implements PatternSearcher for when the search pattern is null.
type nullPatternSearcher struct{}

func (s *nullPatternSearcher) IsPatternSearcher() {}
func (s *nullPatternSearcher) Search(haystack SearchableData, fromIndex int, toIndex int) int {
	return -1
}

// emptyPatternSearcher implements PatternSearcher for when the search pattern is empty.
type emptyPatternSearcher struct{}

func (s *emptyPatternSearcher) IsPatternSearcher() {}
func (s *emptyPatternSearcher) Search(haystack SearchableData, fromIndex int, toIndex int) int {
	// Since this PatternSearcher is returned directly without the SanitizingSearcherWrapper for empty patterns,
	// it needs to perform its own sanitization of fromIndex to match expected indexOf behavior.
	if haystack == nil || haystack.IsEmpty() { // If haystack is null or effectively empty
		// For an empty pattern in an empty/null haystack:
		// If fromIndex is 0 (or less, which gets clamped to 0), result is 0.
		// If fromIndex is > 0, it's past the end of an empty haystack, so effectively should be 0 (length of empty haystack).
		// However, standard library indexOf behavior for empty string in empty string is 0.
		// If fromIndex is non-zero for empty haystack, it is effectively out of bounds.
		// Let's return 0 if fromIndex <=0, and haystackLen (0) if fromIndex > 0 for nil/empty haystack.
		// This means for nil/empty haystack, result is always 0 for empty pattern.
		return 0
	}
	haystackLen := haystack.Length()
	if fromIndex < 0 {
		return 0
	}
	if fromIndex > haystackLen {
		return haystackLen // Consistent with String.indexOf behavior
	}
	return fromIndex
}

// sanitizeIndexInternal clamps a search index to valid bounds within the haystack.
func sanitizeIndexInternal(haystack SearchableData, index int) int {
	// This function assumes haystack is non-nil and not empty (via IsEmpty()) because the
	// NullHaystackCheckingSearcherWrapper should be applied before the SanitizingSearcherWrapper.
	if index < 0 {
		return 0
	}
	// If haystack was indeed nil/empty and this was called, haystack.Length() would be problematic.
	// The design implies wrappers handle these upstream.
	return min(haystack.Length(), index)
}

// SanitizingSearcherWrapperImpl wraps a PatternSearcher to sanitize indices before calling.
type SanitizingSearcherWrapperImpl struct {
	originalSearcher PatternSearcher
}

func NewSanitizingSearcherWrapperImpl(original PatternSearcher) PatternSearcher {
	return &SanitizingSearcherWrapperImpl{originalSearcher: original}
}
func (s *SanitizingSearcherWrapperImpl) IsPatternSearcher() {}
func (s *SanitizingSearcherWrapperImpl) Search(haystack SearchableData, fromIndex int, toIndex int) int {
	// This wrapper assumes it might be called even if haystack is nil/empty,
	// This means `NullHaystackCheckingSearcherWrapperImpl` MUST be the outer wrapper.

	// If this wrapper is called by NullHaystackCheckingSearcherWrapperImpl, haystack is guaranteed non-nil and not empty.
	saneFrom := sanitizeIndexInternal(haystack, fromIndex)
	saneTo := sanitizeIndexInternal(haystack, toIndex)

	if saneFrom > saneTo { // If sanitized range is invalid
		return -1
	}
	return s.originalSearcher.Search(haystack, saneFrom, saneTo)
}

// NullHaystackCheckingSearcherWrapperImpl wraps a PatternSearcher to check for null/empty haystack.
type NullHaystackCheckingSearcherWrapperImpl struct {
	originalSearcher PatternSearcher // This would be the SanitizingSearcherWrapperImpl instance
}

func NewNullHaystackCheckingSearcherWrapperImpl(original PatternSearcher) PatternSearcher {
	return &NullHaystackCheckingSearcherWrapperImpl{originalSearcher: original}
}
func (s *NullHaystackCheckingSearcherWrapperImpl) IsPatternSearcher() {}
func (s *NullHaystackCheckingSearcherWrapperImpl) Search(haystack SearchableData, fromIndex int, toIndex int) int {
	if haystack != nil && !haystack.IsEmpty() { // If haystack is valid
		return s.originalSearcher.Search(haystack, fromIndex, toIndex) // Calls the (Sanitizing) wrapper
	}
	return -1 // Haystack is null or empty
}

// NewSearcherFactory creates a new SearcherFactory instance.
func NewSearcherFactory() *SearcherFactory {
	return &SearcherFactory{}
}

// CreateSearcher creates a PatternSearcher instance based on the pattern and case sensitivity.
func (m1Inst *SearcherFactory) CreateSearcher(pattern []byte, caseSensitive bool) PatternSearcher {
	if pattern == nil {
		return &nullPatternSearcher{}
	}
	if len(pattern) == 0 {
		return &emptyPatternSearcher{}
	}

	coreSearcher := NewBoyerMooreSearcher(pattern, caseSensitive)
	sanitizedCoreSearcher := NewSanitizingSearcherWrapperImpl(coreSearcher)
	nullCheckedAndSanitizedSearcher := NewNullHaystackCheckingSearcherWrapperImpl(
		sanitizedCoreSearcher,
	)
	return nullCheckedAndSanitizedSearcher
}
