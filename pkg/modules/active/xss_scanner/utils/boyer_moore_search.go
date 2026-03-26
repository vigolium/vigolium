package utils

// KwSearcher implements the E0 interface using Boyer-Moore algorithm.
type KwSearcher struct {
	pattern       []byte   // Corresponds to 'private final byte[] d;' (the needle)
	bcShift       [256]int // Bad character shift table (Java: c). Size 256 for all byte values.
	gsShift       []int    // Good suffix shift table (Java: b)
	caseSensitive bool     // Corresponds to 'private final boolean a;'
}

// NewKwSearcher creates a new Boyer-Moore searcher instance.
// Corresponds to kw(byte[] var1, boolean var2) constructor.
// It now returns E0 as per the interface it implements.
func NewKwSearcher(pattern []byte, caseSensitive bool) E0 {
	kw := &KwSearcher{
		caseSensitive: caseSensitive,
	}

	if len(pattern) > 0 { // Only compute shifts if pattern is valid
		if !caseSensitive {
			kw.pattern = make([]byte, len(pattern))
			copy(kw.pattern, pattern)
			ToLowerASCII(
				kw.pattern,
			) // Convert pattern to lowercase if case-insensitive (from nk.go)
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

func (kw *KwSearcher) IsE0() {}

// A performs the search using Boyer-Moore, strictly mirroring the logic of kw.a(pc, int, int) from Java.
func (kw *KwSearcher) A(haystackPc Pc, fromIndex int, toIndex int) int {
	if kw.pattern == nil {
		return -1
	}
	patternLen := len(kw.pattern)
	if patternLen == 0 {
		if haystackPc == nil || haystackPc.B() {
			if fromIndex <= 0 {
				return 0
			}
			return 0
		}
		saneFrom := fromIndex
		if saneFrom < 0 {
			saneFrom = 0
		}
		return min(saneFrom, haystackPc.A())
	}

	if haystackPc == nil || haystackPc.B() {
		return -1
	}
	haystackLen := haystackPc.A()

	sanitizedFromIndex := fromIndex
	if sanitizedFromIndex < 0 {
		sanitizedFromIndex = 0
	}
	sanitizedToIndex := min(haystackLen, toIndex)

	if sanitizedFromIndex > sanitizedToIndex || patternLen > (sanitizedToIndex-sanitizedFromIndex) {
		return -1
	}

	// javaV5 mirrors Java's var5: current comparison point in haystack,
	// initially aligned with the end of the pattern placed at sanitizedFromIndex.
	javaV5 := patternLen - 1 + sanitizedFromIndex

	for javaV5 < sanitizedToIndex {
		javaV6 := patternLen - 1 // Index for pattern (from right to left)

		// Inner character comparison loop
		for { // Simulates the `while(true)` then `if/else break/continue` in Java
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

				// Java logic: var5 += shift; (var5 is the one that was already decremented)
				// This means the current comparison point in haystack (javaV5) is advanced by shift.
				javaV5 += shift

				break // Break inner char comparison loop, outer loop continues with new javaV5
			}
		} // End of inner char comparison loop (for-ever)
	} // End of outer loop (for javaV5 < sanitizedToIndex)

	return -1 // Not found
}

// kwGetChar gets character from Pc, applying case insensitivity if needed.
func kwGetChar(haystack Pc, index int, caseSensitive bool) byte {
	c := byte(haystack.AAt(index))
	if !caseSensitive && c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// kwComputeBcShift computes the bad character shift table.
// Mirrors Java: private static int[] b(byte[] var0)
func kwComputeBcShift(pattern []byte) [256]int {
	var bcShift [256]int
	patternLen := len(pattern)
	for i := 0; i < 256; i++ {
		bcShift[i] = patternLen
	}
	// Java loop was: for (int var2 = 0; var2 < var0.length; var2++)
	// This means it includes the last character of the pattern in the calculation.
	for i := 0; i < patternLen; i++ {
		// In standard Boyer-Moore, the shift for the character at pattern[i]
		// is patternLen - 1 - i. Java code does this.
		// The value for bcShift[pattern[i]] will be overwritten if the char appears multiple times;
		// the rightmost occurrence (smallest index i for patternLen-1-i) will set the final value.
		// Or rather, the leftmost occurrence will set the largest shift value for that character if not overwritten.
		// No, standard BM: for a char `c` in pattern, its last occurrence at index `k` means shift is `M-1-k`.
		// If `c` is not in pattern, shift is `M`.
		// The Java loop: var1[var0[var2] & 255] = var0.length - 1 - var2;
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
		// The Java code `var1[var0[var2] & 255] = var0.length - 1 - var2;` correctly implements this
		// by iterating and allowing later occurrences (smaller `var0.length - 1 - var2`) to overwrite.
		bcShift[pattern[i]] = patternLen - 1 - i
	}
	return bcShift
}

// kwIsPrefix checks if pattern[suffixStartIndex:] is a prefix of pattern.
// Corresponds to Java: private static boolean b(byte[] var0, int var1)
// var0 is pattern, var1 is suffixStartIndex
func kwIsPrefix(pattern []byte, suffixStartIndex int) bool {
	// int var2 = var1; // index in suffix part (pattern[var1...])
	// for (int var3 = 0; var2 < var0.length; var3++) { // var3 is index in prefix part (pattern[0...])
	//    if (var0[var2] != var0[var3]) {
	//       return false;
	//    }
	//    var2++;
	// }
	// return true;
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
// Corresponds to Java: private static int a(byte[] var0, int var1)
// var0 is pattern, var1 is endIndexInPattern (for the sub-pattern being considered)
func kwSuffixLength(pattern []byte, endIndexInPattern int) int {
	// int var2 = 0; // length of common suffix
	// int var3 = var1; // current index in pattern[0...var1] (from right)
	// for (int var4 = var0.length - 1; var3 >= 0 && var0[var3] == var0[var4]; var4--) {
	//    var2++;
	//    var3--;
	// }
	// return var2;
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
// Corresponds to Java: private static int[] a(byte[] var0) [the one that computes gsShift]
func kwComputeGsShift(pattern []byte) []int {
	patternLen := len(pattern)
	if patternLen == 0 {
		return []int{}
	}
	gsShift := make([]int, patternLen) // var1 in Java - Java creates new int[var0.length]
	borderPtr := patternLen            // var2 in Java - initialized to pattern.length

	// Loop 1 from Java: for (int javaVar3 = patternLen; javaVar3 > 0; javaVar3--)
	// javaVar3 represents the start index (0-based) of the suffix being considered for the kwIsPrefix check,
	// but the loop iterates such that patternLen - javaVar3 gives the length of the suffix.
	// To match Java's `var1[var0.length - var3_java]`: index is `patternLen - javaVar3_loopVal`
	// javaVar3_loopVal goes from patternLen down to 1.
	for javaVar3_loopVal := patternLen; javaVar3_loopVal > 0; javaVar3_loopVal-- {
		// Check if pattern[javaVar3_loopVal:] is a prefix of pattern.
		// The `var3` passed to `b` in the Java loop is `javaVar3_loopVal` here.
		if kwIsPrefix(pattern, javaVar3_loopVal) {
			borderPtr = javaVar3_loopVal
		}
		// Java: var1[var0.length - var3_java] = var2 - var3_java + var0.length;
		// Index for gsShift: patternLen - javaVar3_loopVal (this goes from 0 to patternLen-1)
		gsShiftTableIndex := patternLen - javaVar3_loopVal
		gsShift[gsShiftTableIndex] = borderPtr - javaVar3_loopVal + patternLen
	}

	// Loop 2 from Java: for (int javaVar5 = 0; javaVar5 < patternLen - 1; javaVar5++)
	// javaVar5 is endIndexInPattern for kwSuffixLength
	for javaVar5_endIndex := 0; javaVar5_endIndex < patternLen-1; javaVar5_endIndex++ {
		// javaVar4 = a(var0, javaVar5_endIndex) -> kwSuffixLength(pattern, javaVar5_endIndex)
		javaVar4_suffixLen := kwSuffixLength(pattern, javaVar5_endIndex)

		// Java: var1[javaVar4_suffixLen] = patternLen - 1 - javaVar5_endIndex + javaVar4_suffixLen;
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
