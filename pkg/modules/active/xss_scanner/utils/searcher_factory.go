package utils

// SearcherFactory is a factory for creating E0 searcher instances.
type SearcherFactory struct {
}

// --- E0 Implementations for Special Cases and Wrappers ---

// e0ForNullPatternImpl implements E0 for when the search pattern is null.
// Corresponds to lambda m1::lambda$create$0
type e0ForNullPatternImpl struct{}

func (s *e0ForNullPatternImpl) IsE0() {}
func (s *e0ForNullPatternImpl) A(haystack Pc, fromIndex int, toIndex int) int {
	return -1
}

// e0ForEmptyPatternImpl implements E0 for when the search pattern is empty.
// Corresponds to lambda m1::lambda$create$1
type e0ForEmptyPatternImpl struct{}

func (s *e0ForEmptyPatternImpl) IsE0() {}
func (s *e0ForEmptyPatternImpl) A(haystack Pc, fromIndex int, toIndex int) int {
	// Java m1.lambda$create$1 returns `var1` (fromIndex).
	// Since this E0 is returned directly without the SanitizingSearcherWrapper for empty patterns,
	// it needs to perform its own sanitization of fromIndex to match expected indexOf behavior.
	if haystack == nil || haystack.B() { // If haystack is null or effectively empty
		// For an empty pattern in an empty/null haystack:
		// If fromIndex is 0 (or less, which gets clamped to 0), result is 0.
		// If fromIndex is > 0, it's past the end of an empty haystack, so effectively should be 0 (length of empty haystack).
		// However, standard library indexOf behavior for empty string in empty string is 0.
		// If fromIndex is non-zero for empty haystack, it is effectively out of bounds.
		// Let's return 0 if fromIndex <=0, and haystackLen (0) if fromIndex > 0 for nil/empty haystack.
		// This means for nil/empty haystack, result is always 0 for empty pattern.
		return 0
	}
	haystackLen := haystack.A()
	if fromIndex < 0 {
		return 0
	}
	if fromIndex > haystackLen {
		return haystackLen // Consistent with String.indexOf behavior
	}
	return fromIndex
}

// sanitizeIndexInternal is a helper corresponding to m1.a(pc, int).
// It's made unexported as it's internal to this package's logic.
func sanitizeIndexInternal(haystack Pc, index int) int {
	// This function assumes haystack is non-nil and not empty (via pc.B()) because the
	// NullHaystackCheckingSearcherWrapper should be applied before the SanitizingSearcherWrapper.
	if index < 0 {
		return 0
	}
	// If haystack was indeed nil/empty and this was called, haystack.A() would be problematic.
	// The design implies wrappers handle these upstream.
	return min(haystack.A(), index)
}

// SanitizingSearcherWrapperImpl wraps an E0 searcher to sanitize indices before calling.
// Corresponds to the e0 wrapper created by m1.a(e0) using lambda$createSanitisingSearch$3.
type SanitizingSearcherWrapperImpl struct {
	originalSearcher E0
}

func NewSanitizingSearcherWrapperImpl(original E0) E0 {
	return &SanitizingSearcherWrapperImpl{originalSearcher: original}
}
func (s *SanitizingSearcherWrapperImpl) IsE0() {}
func (s *SanitizingSearcherWrapperImpl) A(haystack Pc, fromIndex int, toIndex int) int {
	// This wrapper assumes it might be called even if haystack is nil/empty,
	// because the lambda$createSanitisingSearch$3 in Java is wrapped by lambda$createNullHaystackCheckingSearch$2.
	// However, the lambda$createSanitisingSearch$3 *itself* calls `a(var1, var2)` which is `sanitizeIndexInternal`.
	// `sanitizeIndexInternal` in Java was `Math.min(pc.A(), index)` which would NPE if pc is nil.
	// This means `NullHaystackCheckingSearcherWrapperImpl` MUST be the outer wrapper.

	// If this wrapper is called by NullHaystackCheckingSearcherWrapperImpl, haystack is guaranteed non-nil and not empty.
	saneFrom := sanitizeIndexInternal(haystack, fromIndex)
	saneTo := sanitizeIndexInternal(haystack, toIndex)

	if saneFrom > saneTo { // If sanitized range is invalid
		return -1
	}
	return s.originalSearcher.A(haystack, saneFrom, saneTo)
}

// NullHaystackCheckingSearcherWrapperImpl wraps an E0 searcher to check for null/empty haystack.
// Corresponds to the e0 wrapper created by m1.b(e0) using lambda$createNullHaystackCheckingSearch$2.
type NullHaystackCheckingSearcherWrapperImpl struct {
	originalSearcher E0 // This would be the SanitizingSearcherWrapperImpl instance
}

func NewNullHaystackCheckingSearcherWrapperImpl(original E0) E0 {
	return &NullHaystackCheckingSearcherWrapperImpl{originalSearcher: original}
}
func (s *NullHaystackCheckingSearcherWrapperImpl) IsE0() {}
func (s *NullHaystackCheckingSearcherWrapperImpl) A(haystack Pc, fromIndex int, toIndex int) int {
	// Corresponds to lambda$createNullHaystackCheckingSearch$2
	if haystack != nil && !haystack.B() { // If haystack is valid
		return s.originalSearcher.A(haystack, fromIndex, toIndex) // Calls the (Sanitizing) wrapper
	}
	return -1 // Haystack is null or empty
}

// NewM1 creates a new SearcherFactory instance.
func NewM1() *SearcherFactory {
	return &SearcherFactory{}
}

// CreateSearcher creates an E0 searcher instance based on the pattern and case sensitivity.
func (m1Inst *SearcherFactory) CreateSearcher(pattern []byte, caseSensitive bool) E0 {
	if pattern == nil {
		return &e0ForNullPatternImpl{}
	}
	if len(pattern) == 0 {
		return &e0ForEmptyPatternImpl{}
	}

	coreSearcher := NewKwSearcher(pattern, caseSensitive)
	sanitizedCoreSearcher := NewSanitizingSearcherWrapperImpl(coreSearcher)
	nullCheckedAndSanitizedSearcher := NewNullHaystackCheckingSearcherWrapperImpl(
		sanitizedCoreSearcher,
	)
	return nullCheckedAndSanitizedSearcher
}
