package utils

// --- Basic Utility Methods ---

// BytesEqual checks if two byte slices are equal.
func BytesEqual(arr1 []byte, arr2 []byte) bool {
	if arr1 == nil && arr2 == nil {
		return true
	}
	if arr1 == nil || arr2 == nil {
		return false // If one is nil and the other isn't, they are not equal.
	}
	if len(arr1) != len(arr2) {
		return false
	}
	for i := 0; i < len(arr1); i++ {
		if arr1[i] != arr2[i] {
			return false
		}
	}
	return true
}

// RegionMatches checks if two byte slice regions are equal.
func RegionMatches(
	haystack []byte,
	offset1 int,
	end1 int,
	needle []byte,
	offset2 int,
	end2 int,
) bool {
	len1 := end1 - offset1
	len2 := end2 - offset2

	if len1 != len2 {
		return false
	}
	if len1 < 0 { // Or len2 < 0, since they are equal
		return false // Invalid region
	}

	// Bounds checks
	if haystack == nil || offset1 < 0 || end1 > len(haystack) || offset1 > end1 {
		return false
	}
	if needle == nil || offset2 < 0 || end2 > len(needle) || offset2 > end2 {
		return false
	}

	for i := 0; i < len1; i++ {
		if haystack[offset1+i] != needle[offset2+i] {
			return false
		}
	}
	return true
}

// FirstDifferenceOffset finds the first offset where two byte slices differ.
// Returns -1 if they are identical up to the length of the shorter slice, or if one/both are nil.
// If lengths differ but content matches up to shorter, it indicates difference at that length.
func FirstDifferenceOffset(arr1 []byte, arr2 []byte) int {
	if arr1 == nil || arr2 == nil {
		diffs := FirstDifferenceOffsets(arr1, 0, len(arr1), arr2, 0, len(arr2))
		if diffs == nil {
			return -1
		}
		return diffs[0]
	}
	minLen := len(arr1)
	if len(arr2) < minLen {
		minLen = len(arr2)
	}
	for i := 0; i < minLen; i++ {
		if arr1[i] != arr2[i] {
			return i
		}
	}
	if len(arr1) != len(arr2) {
		return minLen // Differ at the end of the shorter array
	}
	return -1 // Identical
}

// FirstDifferenceOffsets finds the first pair of differing offsets.
// Returns nil if identical, or []int{offset1, offset2} of the differing characters.
func FirstDifferenceOffsets(
	arr1 []byte,
	offset1 int,
	end1 int,
	arr2 []byte,
	offset2 int,
	end2 int,
) []int {
	// Basic nil checks upfront
	if arr1 == nil || arr2 == nil {
		if arr1 == nil && arr2 == nil {
			return nil
		} // Both nil considered same for this logic
		if arr1 == nil {
			return []int{offset1, offset2}
		} // Effectively, arr1 differs at its start if arr2 is not nil
		return []int{offset1, offset2} // arr2 differs at its start if arr1 is not nil
	}

	// Bound checks (simplified, more robust checks would be needed for production)
	if offset1 < 0 {
		offset1 = 0
	}
	if end1 > len(arr1) {
		end1 = len(arr1)
	}
	if offset2 < 0 {
		offset2 = 0
	}
	if end2 > len(arr2) {
		end2 = len(arr2)
	}

	currentOffset1 := offset1
	currentOffset2 := offset2

	for currentOffset1 < end1 && currentOffset2 < end2 {
		if arr1[currentOffset1] != arr2[currentOffset2] {
			return []int{currentOffset1, currentOffset2}
		}
		currentOffset1++
		currentOffset2++
	}

	// If one array is exhausted but the other is not, they differ at this point.
	if currentOffset1 < end1 || currentOffset2 < end2 {
		return []int{currentOffset1, currentOffset2}
	}

	return nil // Identical within the specified ranges
}

// CommonSuffixLength calculates the length of the common suffix of two byte arrays.
func CommonSuffixLength(arr1 []byte, arr2 []byte) int {
	if arr1 == nil || arr2 == nil {
		return 0
	}
	len1 := len(arr1)
	len2 := len(arr2)
	if len1 == 0 || len2 == 0 {
		return 0
	}

	commonLen := 0
	i1 := len1 - 1
	i2 := len2 - 1

	for i1 >= 0 && i2 >= 0 {
		if arr1[i1] != arr2[i2] {
			return commonLen
		}
		i1--
		i2--
		commonLen++
	}
	return commonLen
}

// ToLowerByte converts an ASCII byte to lowercase.
func ToLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A') // More robust than fixed offset 32
	}
	return b
}

// IsPrintableASCII checks if all bytes in the slice are printable ASCII (>=32 and <127) or LF, CR, TAB.
func IsPrintableASCII(data []byte) bool {
	if data == nil {
		return true
	}
	for _, b := range data {
		isPrintable := (b >= 32 && b < 127) || b == 10 /*LF*/ || b == 13 /*CR*/ || b == 9 /*TAB*/
		if !isPrintable {
			return false
		}
	}
	return true
}

// --- Placeholder for Search-related Interfaces and Structs (to be defined later) ---

// Pc interface wraps a haystack for use in search algorithms.
type Pc interface {
	IsPc()         // Marker method
	B() bool       // Returns true if data is nil/empty
	A() int        // Returns the length of the data
	AAt(i int) int // Returns the unsigned byte value at index i
}

// G3 struct implements Pc, wraps a byte slice
type G3 struct {
	data []byte
}

func NewG3(data []byte) *G3 {
	return &G3{data: data}
}
func (g *G3) IsPc()           {}
func (g *G3) B() bool         { return g.data == nil }
func (g *G3) A() int          { return len(g.data) }
func (g *G3) AAt(idx int) int { return int(g.data[idx] & 0xFF) }

// E0 interface for search algorithms.
type E0 interface {
	IsE0()                                         // Marker method
	A(haystack Pc, fromIndex int, toIndex int) int // Search and return index of match, or -1
}

// --- HashCode Methods ---

// ByteHashCode computes a hash code for a byte slice.
func ByteHashCode(data []byte, caseSensitive bool) int {
	if data == nil {
		return -1 // Java might NPE. Returning -1 for nil data based on original plan.
	}
	return ByteHashCodeRange(data, 0, len(data), caseSensitive, 0)
}

// ByteHashCodeRange computes a hash code for a range within a byte slice.
func ByteHashCodeRange(
	data []byte,
	offset int,
	end int,
	caseSensitive bool,
	seed int,
) int {
	if data == nil {
		// Java behavior for null with seed isn't directly specified but often results in an error or uses seed.
		// Returning seed seems a plausible non-error outcome if data is nil but seed is given.
		return seed
	}
	// Basic bounds checks
	actualOffset := offset
	if actualOffset < 0 {
		actualOffset = 0
	}
	actualEnd := min(end, len(data))

	if actualOffset >= actualEnd { // Empty range
		return seed
	}

	hash := seed
	for i := actualOffset; i < actualEnd; i++ {
		b := data[i]
		if !caseSensitive {
			b = ToLowerByte(b) // Uses the existing toLowerByte helper
		}
		hash = 31*hash + int(b) // Classic hash algorithm component
	}
	return hash
}

// --- Compare Method ---

// CompareBytes compares two byte slices lexicographically.
func CompareBytes(arr1 []byte, arr2 []byte, caseSensitive bool) int {
	if arr1 == nil && arr2 == nil {
		return 0
	}
	if arr1 == nil { // arr2 is not nil
		return 1 // Consistent with some comparisons where null is considered "greater"
	}
	if arr2 == nil { // arr1 is not nil
		return -1
	}

	len1 := len(arr1)
	len2 := len(arr2)
	minLen := min(len1, len2)

	for i := 0; i < minLen; i++ {
		b1 := arr1[i]
		b2 := arr2[i]
		if !caseSensitive {
			b1 = ToLowerByte(b1)
			b2 = ToLowerByte(b2)
		}
		if b1 < b2 {
			return -1
		}
		if b1 > b2 {
			return 1
		}
	}
	// If one is a prefix of the other, the shorter one comes first.
	if len1 < len2 {
		return -1
	}
	if len1 > len2 {
		return 1
	}
	return 0 // Equal
}

// --- indexOf and lastIndexOf Methods (Byte) ---

// IndexOfByte finds the first index of a byte in a slice.
func IndexOfByte(
	data []byte,
	b byte,
	caseSensitive bool,
	fromIndex int,
	toIndex int,
) int {
	if data == nil {
		return -1
	}
	// Bounds
	actualFromIndex := fromIndex
	if actualFromIndex < 0 {
		actualFromIndex = 0
	}
	actualToIndex := min(toIndex, len(data))

	if actualFromIndex >= actualToIndex { // Empty search range
		return -1
	}

	searchByte := b
	if !caseSensitive {
		searchByte = ToLowerByte(b)
	}

	for i := actualFromIndex; i < actualToIndex; i++ {
		haystackByte := data[i]
		if !caseSensitive {
			haystackByte = ToLowerByte(haystackByte)
		}
		if haystackByte == searchByte {
			return i
		}
	}
	return -1
}

// IndexOfByteCS finds the first index of a byte (case-sensitive).
func IndexOfByteCS(data []byte, b byte, fromIndex int, toIndex int) int {
	if data == nil {
		return -1
	}
	// Bounds
	actualFromIndex := fromIndex
	if actualFromIndex < 0 {
		actualFromIndex = 0
	}
	actualToIndex := min(toIndex, len(data))

	if actualFromIndex >= actualToIndex { // Empty search range
		return -1
	}

	for i := actualFromIndex; i < actualToIndex; i++ {
		if data[i] == b {
			return i
		}
	}
	return -1
}

// LastIndexOfByteCS finds the last index of a byte (case-sensitive).
func LastIndexOfByteCS(data []byte, b byte, fromIndex int, toIndex int) int {
	if data == nil {
		return -1
	}
	// Bounds: fromIndex is start, toIndex is exclusive end for search window, iteration is backwards.
	actualFromIndex := fromIndex
	if actualFromIndex < 0 {
		actualFromIndex = 0
	}
	// The loop runs from (actualToIndex - 1) down to actualFromIndex.
	// So, actualToIndex should be len(data) or less.
	actualToIndexEffective := min(toIndex, len(data))

	if actualFromIndex >= actualToIndexEffective { // Empty or invalid range
		return -1
	}

	for i := actualToIndexEffective - 1; i >= actualFromIndex; i-- {
		if data[i] == b {
			return i
		}
	}
	return -1
}

// --- indexOf Methods (Sub-array) ---

// IndexOfCS is a case-sensitive indexOf.
func IndexOfCS(haystack []byte, needle []byte) int {
	if haystack == nil {
		return -1
	} // Explicit nil check for haystack before length call
	return IndexOfPattern(haystack, needle, true, 0, len(haystack))
}

// IndexOfBytes is an indexOf with case sensitivity option.
func IndexOfBytes(haystack []byte, needle []byte, caseSensitive bool) int {
	if haystack == nil {
		return -1
	}
	return IndexOfPattern(haystack, needle, caseSensitive, 0, len(haystack))
}

// IndexOfBytesFrom is an indexOf with case sensitivity and fromIndex.
func IndexOfBytesFrom(
	haystack []byte,
	needle []byte,
	caseSensitive bool,
	fromIndex int,
) int {
	if haystack == nil {
		return -1
	}
	return IndexOfPattern(haystack, needle, caseSensitive, fromIndex, len(haystack))
}

// IndexOfRangeCS is a case-sensitive indexOf within a range.
func IndexOfRangeCS(
	haystack []byte,
	needle []byte,
	fromIndex int,
	toIndex int,
) int {
	return IndexOfPattern(haystack, needle, true, fromIndex, toIndex)
}

// IndexOfPattern is the main indexOf method using Boyer-Moore (via M1 and KwSearcher).
func IndexOfPattern(
	haystack []byte,
	needle []byte,
	caseSensitive bool,
	fromIndex int,
	toIndex int,
) int {
	m1Instance := NewM1()
	searcher := m1Instance.CreateSearcher(needle, caseSensitive)
	haystackWrapper := NewG3(haystack)
	return searcher.A(haystackWrapper, fromIndex, toIndex)
}

// IndexOfSimple is a simple char-by-char case-sensitive indexOf.
func IndexOfSimple(
	haystack []byte,
	needle []byte,
	fromIndex int,
	toIndex int,
) int {
	if haystack == nil || needle == nil {
		return -1
	}
	needleLen := len(needle)
	if needleLen == 0 {
		actualFrom := fromIndex
		if actualFrom < 0 {
			actualFrom = 0
		}
		return min(actualFrom, len(haystack))
	}

	actualToIndex := min(toIndex, len(haystack))
	limit := actualToIndex - needleLen

	if fromIndex < 0 {
		fromIndex = 0
	} // Ensure fromIndex is not negative
	if fromIndex > limit { // If fromIndex is already past where needle can fit
		return -1
	}

	firstNeedleByte := needle[0]
	for i := fromIndex; i <= limit; i++ {
		if haystack[i] == firstNeedleByte {
			match := true
			for k := 1; k < needleLen; k++ {
				if haystack[i+k] != needle[k] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
}

// LastIndexOf finds the last index of a sub-array (case-sensitive).
func LastIndexOf(haystack []byte, needle []byte, fromIndex int, toIndex int) int {
	if haystack == nil || needle == nil {
		return -1
	}
	needleLen := len(needle)
	haystackLen := len(haystack)

	if needleLen == 0 {
		return min(toIndex, haystackLen)
	}

	actualFromIndex := max(0, fromIndex) // Ensure fromIndex is not negative
	// The search window is from actualFromIndex up to (but not including) toIndex.
	// We search backwards from the end of this window.
	// The last possible start position for needle is min(toIndex, haystackLen) - needleLen.
	startSearch := min(toIndex, haystackLen) - needleLen

	for i := startSearch; i >= actualFromIndex; i-- {
		// Check if needle matches at current position i
		if i+needleLen > haystackLen { // Should not happen if startSearch is calculated correctly
			continue
		}
		match := true
		for k := 0; k < needleLen; k++ {
			if haystack[i+k] != needle[k] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// --- Prefix/Suffix and Matching Methods ---

// StartsWithBytes checks if a byte slice starts with a given prefix.
func StartsWithBytes(data []byte, prefix []byte, caseSensitive bool, offset int) bool {
	if data == nil || prefix == nil {
		return data == nil &&
			prefix == nil // True if both nil, false otherwise, aligning with some equals logic
	}
	prefixLen := len(prefix)
	if offset < 0 || offset > len(data)-prefixLen {
		return false
	}

	for i := 0; i < prefixLen; i++ {
		db := data[offset+i]
		pb := prefix[i]
		if !caseSensitive {
			db = ToLowerByte(db)
			pb = ToLowerByte(pb)
		}
		if db != pb {
			return false
		}
	}
	return true
}

// MatchesAt checks if a needle matches the haystack at a specific offset (case-sensitive).
func MatchesAt(haystack []byte, needle []byte, offset int) bool {
	if haystack == nil || needle == nil {
		return false // If either is nil, cannot match
	}
	needleLen := len(needle)
	if offset < 0 || offset > len(haystack)-needleLen {
		return false
	}
	for i := 0; i < needleLen; i++ {
		if haystack[offset+i] != needle[i] {
			return false
		}
	}
	return true
}
