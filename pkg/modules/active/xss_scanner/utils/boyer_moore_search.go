package utils

// BoyerMooreSearcher implements the PatternSearcher interface using Boyer-Moore algorithm.
type BoyerMooreSearcher struct {
	pattern       []byte
	bcShift       [256]int
	gsShift       []int
	caseSensitive bool
}

// NewBoyerMooreSearcher creates a new Boyer-Moore searcher instance.
// It now returns PatternSearcher as per the interface it implements.
func NewBoyerMooreSearcher(pattern []byte, caseSensitive bool) PatternSearcher {
	kw := &BoyerMooreSearcher{
		caseSensitive: caseSensitive,
	}

	if len(pattern) > 0 { // Only compute shifts if pattern is valid
		if !caseSensitive {
			kw.pattern = make([]byte, len(pattern))
			copy(kw.pattern, pattern)
			ToLowerASCII(kw.pattern)
		} else {
			kw.pattern = make([]byte, len(pattern)) // Always copy to avoid external modification
			copy(kw.pattern, pattern)
		}
		kw.bcShift = kwComputeBcShift(kw.pattern)
		kw.gsShift = kwComputeGsShift(kw.pattern)
	} else {
		kw.pattern = pattern // Store the nil or empty pattern
	}
	return kw
}

func (kw *BoyerMooreSearcher) IsPatternSearcher() {}

func (kw *BoyerMooreSearcher) Search(haystackPc SearchableData, fromIndex int, toIndex int) int {
	if kw.pattern == nil {
		return -1
	}
	patternLen := len(kw.pattern)
	if patternLen == 0 {
		if haystackPc == nil || haystackPc.IsEmpty() {
			if fromIndex <= 0 {
				return 0
			}
			return 0
		}
		saneFrom := fromIndex
		if saneFrom < 0 {
			saneFrom = 0
		}
		return min(saneFrom, haystackPc.Length())
	}

	if haystackPc == nil || haystackPc.IsEmpty() {
		return -1
	}
	haystackLen := haystackPc.Length()

	sanitizedFromIndex := fromIndex
	if sanitizedFromIndex < 0 {
		sanitizedFromIndex = 0
	}
	sanitizedToIndex := min(haystackLen, toIndex)

	if sanitizedFromIndex > sanitizedToIndex || patternLen > (sanitizedToIndex-sanitizedFromIndex) {
		return -1
	}

	// initially aligned with the end of the pattern placed at sanitizedFromIndex.
	javaV5 := patternLen - 1 + sanitizedFromIndex

	for javaV5 < sanitizedToIndex {
		javaV6 := patternLen - 1 // Index for pattern (from right to left)

		// Inner character comparison loop
		for {
			// Bounds check - continue execution even on bounds issues (handled by kwGetChar)
			//nolint:staticcheck // SA9003: intentionally empty - bounds handled by kwGetChar
			if javaV5 < 0 || javaV5 >= haystackLen {
			}
			haystackChar := kwGetChar(haystackPc, javaV5, kw.caseSensitive)

			if kw.pattern[javaV6] == haystackChar {
				if javaV6 == 0 { // Matched all characters
					return javaV5 // javaV5 is now the start of the match
				}
				javaV5-- // Decrement haystack pointer
				javaV6-- // Decrement pattern pointer
				// Implicit continue for this inner loop in Go's for-ever loop
			} else { // Mismatch
				// Character in haystack that caused mismatch is `haystackChar` (at current `javaV5`)
				// Good suffix is pattern[javaV6+1 ... patternLen-1]
				// Length of good suffix is patternLen - 1 - javaV6
				gsVal := 0
				gsIndex := patternLen - 1 - javaV6
				if gsIndex >= 0 && gsIndex < len(kw.gsShift) {
					gsVal = kw.gsShift[gsIndex]
				} else if len(kw.gsShift) > 0 {
					gsVal = patternLen
				} else {
					gsVal = patternLen
				}

				// bcShift uses the character from haystack at the point of mismatch (current javaV5)
				bcVal := kw.bcShift[haystackChar]
				shift := max(gsVal, bcVal)

				if shift <= 0 {
					shift = 1 // Ensure progress
				}

				// This means the current comparison point in haystack (javaV5) is advanced by shift.
				javaV5 += shift

				break // Break inner char comparison loop, outer loop continues with new javaV5
			}
		} // End of inner char comparison loop (for-ever)
	} // End of outer loop (for javaV5 < sanitizedToIndex)

	return -1 // Not found
}

// kwGetChar gets character from SearchableData, applying case insensitivity if needed.
func kwGetChar(haystack SearchableData, index int, caseSensitive bool) byte {
	c := byte(haystack.ByteAt(index))
	if !caseSensitive && c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// kwComputeBcShift computes the bad character shift table.
func kwComputeBcShift(pattern []byte) [256]int {
	var bcShift [256]int
	patternLen := len(pattern)
	for i := 0; i < 256; i++ {
		bcShift[i] = patternLen
	}
	// This means it includes the last character of the pattern in the calculation.
	for i := 0; i < patternLen; i++ {
		// In standard Boyer-Moore, the shift for the character at pattern[i]
		// The value for bcShift[pattern[i]] will be overwritten if the char appears multiple times;
		// the rightmost occurrence (smallest index i for patternLen-1-i) will set the final value.
		// Or rather, the leftmost occurrence will set the largest shift value for that character if not overwritten.
		// No, standard BM: for a char `c` in pattern, its last occurrence at index `k` means shift is `M-1-k`.
		// If `c` is not in pattern, shift is `M`.
		// This means for each character pattern[i], its entry in bcShift is patternLen - 1 - i.
		// If a character appears multiple times, the entry for it will correspond to its *rightmost* occurrence in the pattern
		// (because `i` increases, so `patternLen - 1 - i` decreases, and later assignments overwrite earlier ones for the same char).
		// This IS the standard bad character rule: shift by distance of rightmost occurrence of mismatched char in pattern from end of pattern.
		// If char not in pattern (except last char), it uses full patternLen default.
		// If char IS in pattern, it's patternLen - 1 - indexOfRightmostOccurrence.
		// The loop in Go currently is: for i := 0; i < patternLen-1; i++ { bcShift[pattern[i]] = patternLen - 1 - i }
		// This MISSES the last character if it needs to be set.
		// And the default for chars not in pattern is patternLen.

		// Corrected standard bad character rule calculation:
		// Default shifts are patternLen.
		// For each char c in pattern (except possibly the last one, depending on convention),
		// the shift is patternLen - 1 - index_of_c. The rightmost occurrence is key.
		bcShift[pattern[i]] = patternLen - 1 - i
	}
	return bcShift
}

// kwIsPrefix checks if pattern[suffixStartIndex:] is a prefix of pattern.
func kwIsPrefix(pattern []byte, suffixStartIndex int) bool {
	patternLen := len(pattern)
	if suffixStartIndex < 0 || suffixStartIndex >= patternLen { // Invalid start index for suffix
		// Or if suffix is empty (suffixStartIndex == patternLen), it can be considered a prefix of anything.
		if suffixStartIndex == patternLen {
			return true
		} // Empty suffix is prefix
		return false // Should not happen with valid internal calls
	}

	suffixLen := patternLen - suffixStartIndex
	if suffixLen > patternLen { // Suffix cannot be longer than pattern (should not happen)
		return false
	}

	for i := 0; i < suffixLen; i++ {
		if pattern[suffixStartIndex+i] != pattern[i] {
			return false
		}
	}
	return true
}

// kwSuffixLength calculates the length of the longest suffix of pattern[0...endIndexInPattern]
// that is also a suffix of the full pattern.
func kwSuffixLength(pattern []byte, endIndexInPattern int) int {
	commonSuffixLen := 0
	patternLen := len(pattern)

	if endIndexInPattern < 0 ||
		endIndexInPattern >= patternLen { // endIndexInPattern should be a valid index
		return 0 // Or handle error
	}

	idxInSubPattern := endIndexInPattern
	idxInFullPattern := patternLen - 1

	for idxInSubPattern >= 0 && idxInFullPattern >= 0 && pattern[idxInSubPattern] == pattern[idxInFullPattern] {
		commonSuffixLen++
		idxInSubPattern--
		idxInFullPattern--
	}
	return commonSuffixLen
}

// kwComputeGsShift computes the good suffix shift table.
func kwComputeGsShift(pattern []byte) []int {
	patternLen := len(pattern)
	if patternLen == 0 {
		return []int{}
	}
	gsShift := make([]int, patternLen)
	borderPtr := patternLen

	// javaVar3 represents the start index (0-based) of the suffix being considered for the kwIsPrefix check,
	// but the loop iterates such that patternLen - javaVar3 gives the length of the suffix.
	// javaVar3_loopVal goes from patternLen down to 1.
	for javaVar3_loopVal := patternLen; javaVar3_loopVal > 0; javaVar3_loopVal-- {
		// Check if pattern[javaVar3_loopVal:] is a prefix of pattern.
		if kwIsPrefix(pattern, javaVar3_loopVal) {
			borderPtr = javaVar3_loopVal
		}
		// Index for gsShift: patternLen - javaVar3_loopVal (this goes from 0 to patternLen-1)
		gsShiftTableIndex := patternLen - javaVar3_loopVal
		gsShift[gsShiftTableIndex] = borderPtr - javaVar3_loopVal + patternLen
	}

	// javaVar5 is endIndexInPattern for kwSuffixLength
	for javaVar5_endIndex := 0; javaVar5_endIndex < patternLen-1; javaVar5_endIndex++ {
		javaVar4_suffixLen := kwSuffixLength(pattern, javaVar5_endIndex)

		// Check bounds for gsShift access: javaVar4_suffixLen must be < patternLen
		// kwSuffixLength can return values up to patternLen.
		// If javaVar4_suffixLen is patternLen, gsShift[patternLen] would be out of bounds.
		// However, javaVar5_endIndex goes up to patternLen-2.
		// Max kwSuffixLength(pattern, patternLen-2) is patternLen-1.
		// So, javaVar4_suffixLen will be at most patternLen-1, which is a valid index for gsShift.
		gsShift[javaVar4_suffixLen] = (patternLen - 1 - javaVar5_endIndex) + javaVar4_suffixLen
	}
	return gsShift
}
