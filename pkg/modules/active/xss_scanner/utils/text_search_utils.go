package utils

// --- Basic Utility Methods ---

// NetPortswiggerLsDBytesEquals checks if two byte slices are equal.
// Corresponds to public static boolean d(byte[] var0, byte[] var1)
func NetPortswiggerLsDBytesEquals(arr1 []byte, arr2 []byte) bool {
	if arr1 == nil && arr2 == nil {
		return true // Consistent with some interpretations, though Java `==` on arrays is reference
		// However, the internal logic of Java d implies content check if not null.
		// If both are nil, they could be considered "equal" in terms of content (no content).
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

// NetPortswiggerLsARegionMatches checks if two byte slice regions are equal.
// Corresponds to public static boolean a(byte[] var0, int var1, int var2, byte[] var3, int var4, int var5)
func NetPortswiggerLsARegionMatches(
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

// NetPortswiggerLsBFirstDifferenceOffset finds the first offset where two byte slices differ.
// Returns -1 if they are identical up to the length of the shorter slice, or if one/both are nil.
// If lengths differ but content matches up to shorter, it indicates difference at that length.
// Corresponds to public static int b(byte[] var0, byte[] var1)
func NetPortswiggerLsBFirstDifferenceOffset(arr1 []byte, arr2 []byte) int {
	if arr1 == nil || arr2 == nil {
		// Java version might throw NPE if not careful. Behavior for nil inputs needs to be defined.
		// The Java code snippet for this specific method isn't fully shown, but usually, direct access would NPE.
		// For robustness, let's return -1 or an error. Given it returns int, -1 is plausible for no common prefix/error.
		// However, the more detailed b(byte[], int, int, byte[], int, int) returns int[] {offset1, offset2}
		// Let's assume the simple version returns the first differing index or length if one is prefix of other.
		// If we follow the more detailed b, it returns the differing indices.
		// For a single int return, it likely means the first index in arr1 that differs.
		diffs := NetPortswiggerLsBFirstDifferenceOffsets(arr1, 0, len(arr1), arr2, 0, len(arr2))
		if diffs == nil { // Identical
			return -1 // Or some indicator they are identical, Java might return a specific value or use length.
		}
		return diffs[0] // Return differing index in the first array
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

// NetPortswiggerLsBFirstDifferenceOffsets finds the first pair of differing offsets.
// Returns nil if identical, or []int{offset1, offset2} of the differing characters.
// Corresponds to public static int[] b(byte[] var0, int var1, int var2, byte[] var3, int var4, int var5)
func NetPortswiggerLsBFirstDifferenceOffsets(
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

// NetPortswiggerLsACommonSuffixLength calculates the length of the common suffix of two byte arrays.
// Corresponds to public static int a(byte[] var0, byte[] var1)
func NetPortswiggerLsACommonSuffixLength(arr1 []byte, arr2 []byte) int {
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

// NetPortswiggerLsAToLowerByte converts an ASCII byte to lowercase.
// Corresponds to public static byte a(byte var0)
func NetPortswiggerLsAToLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A') // More robust than fixed offset 32
	}
	return b
}

// NetPortswiggerLsAIsPrintableAscii checks if all bytes in the slice are printable ASCII (>=32 and <127) or LF, CR, TAB.
// Corresponds to public static boolean a(byte[] var0)
func NetPortswiggerLsAIsPrintableAscii(data []byte) bool {
	if data == nil {
		return true // Or false, depending on how nil is interpreted in Java context. Java might NPE.
		// Assuming true for empty/nil content not being "non-printable".
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

// Pc (Portswigger Comparable?) interface, wrapper for haystack in searches
type Pc interface {
	IsPc()         // Marker method
	B() bool       // Corresponds to b() in Java pc (e.g. g3.a == null)
	A() int        // Corresponds to a() in Java pc (e.g. g3.a.length)
	AAt(i int) int // Corresponds to a(int) in Java pc (e.g. g3.a[var1] & 0xFF)
}

// G3 struct implements Pc, wraps a byte slice
type G3 struct {
	data []byte
}

func NewG3(data []byte) *G3 {
	return &G3{data: data}
}
func (g *G3) IsPc()           {}                                 // Marker
func (g *G3) B() bool         { return g.data == nil }           // Java: this.a == null
func (g *G3) A() int          { return len(g.data) }             // Java: this.a.length
func (g *G3) AAt(idx int) int { return int(g.data[idx] & 0xFF) } // Java: this.a[var1] & 0xFF

// E0 (Executor? Engine?) interface for search algorithms
type E0 interface {
	IsE0()                                         // Marker method
	A(haystack Pc, fromIndex int, toIndex int) int // Corresponds to a(pc, int, int)
}

// --- HashCode Methods ---

// NetPortswiggerLsAHashCode computes a hash code for a byte slice.
// Corresponds to public static int a(byte[] var0, boolean var1)
func NetPortswiggerLsAHashCode(data []byte, caseSensitive bool) int {
	if data == nil {
		return -1 // Java might NPE. Returning -1 for nil data based on original plan.
	}
	return NetPortswiggerLsAHashCodeRange(data, 0, len(data), caseSensitive, 0)
}

// NetPortswiggerLsAHashCodeRange computes a hash code for a range within a byte slice.
// Corresponds to public static int a(byte[] var0, int var1, int var2, boolean var3, int var4)
func NetPortswiggerLsAHashCodeRange(
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
			b = NetPortswiggerLsAToLowerByte(b) // Uses the existing toLowerByte helper
		}
		hash = 31*hash + int(b) // Classic hash algorithm component
	}
	return hash
}

// --- Compare Method ---

// NetPortswiggerLsACompare compares two byte slices lexicographically.
// Corresponds to public static int a(byte[] var0, byte[] var1, boolean var2)
func NetPortswiggerLsACompare(arr1 []byte, arr2 []byte, caseSensitive bool) int {
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
			b1 = NetPortswiggerLsAToLowerByte(b1)
			b2 = NetPortswiggerLsAToLowerByte(b2)
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

// NetPortswiggerLsAIndexOfByte finds the first index of a byte in a slice.
// Corresponds to public static int a(byte[] var0, byte var1, boolean var2, int var3, int var4)
func NetPortswiggerLsAIndexOfByte(
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
		searchByte = NetPortswiggerLsAToLowerByte(b)
	}

	for i := actualFromIndex; i < actualToIndex; i++ {
		haystackByte := data[i]
		if !caseSensitive {
			haystackByte = NetPortswiggerLsAToLowerByte(haystackByte)
		}
		if haystackByte == searchByte {
			return i
		}
	}
	return -1
}

// NetPortswiggerLsBIndexOfByteCS finds the first index of a byte (case-sensitive).
// Corresponds to public static int b(byte[] var0, byte var1, int var2, int var3)
func NetPortswiggerLsBIndexOfByteCS(data []byte, b byte, fromIndex int, toIndex int) int {
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

// NetPortswiggerLsALastIndexOfByteCS finds the last index of a byte (case-sensitive).
// Corresponds to public static int a(byte[] var0, byte var1, int var2, int var3) [this signature was for lastIndexOf in Java]
func NetPortswiggerLsALastIndexOfByteCS(data []byte, b byte, fromIndex int, toIndex int) int {
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

// NetPortswiggerLsCIndexOfCS is a case-sensitive indexOf.
// Corresponds to public static int c(byte[] var0, byte[] var1)
func NetPortswiggerLsCIndexOfCS(haystack []byte, needle []byte) int {
	if haystack == nil {
		return -1
	} // Explicit nil check for haystack before length call
	return NetPortswiggerLsAIndexOf(haystack, needle, true, 0, len(haystack))
}

// NetPortswiggerLsBIndexOf is an indexOf with case sensitivity option.
// Corresponds to public static int b(byte[] var0, byte[] var1, boolean var2)
func NetPortswiggerLsBIndexOf(haystack []byte, needle []byte, caseSensitive bool) int {
	if haystack == nil {
		return -1
	}
	return NetPortswiggerLsAIndexOf(haystack, needle, caseSensitive, 0, len(haystack))
}

// NetPortswiggerLsBIndexOfFrom is an indexOf with case sensitivity and fromIndex.
// Corresponds to public static int b(byte[] var0, byte[] var1, boolean var2, int var3)
func NetPortswiggerLsBIndexOfFrom(
	haystack []byte,
	needle []byte,
	caseSensitive bool,
	fromIndex int,
) int {
	if haystack == nil {
		return -1
	}
	return NetPortswiggerLsAIndexOf(haystack, needle, caseSensitive, fromIndex, len(haystack))
}

// NetPortswiggerLsBIndexOfRangeCS is a case-sensitive indexOf within a range.
// Corresponds to public static int b(byte[] var0, byte[] var1, int var2, int var3)
func NetPortswiggerLsBIndexOfRangeCS(
	haystack []byte,
	needle []byte,
	fromIndex int,
	toIndex int,
) int {
	return NetPortswiggerLsAIndexOf(haystack, needle, true, fromIndex, toIndex)
}

// NetPortswiggerLsAIndexOf is the main indexOf method using Boyer-Moore (via M1 and KwSearcher).
// Corresponds to public static int a(byte[] var0, byte[] var1, boolean var2, int var3, int var4)
func NetPortswiggerLsAIndexOf(
	haystack []byte,
	needle []byte,
	caseSensitive bool,
	fromIndex int,
	toIndex int,
) int {
	// Simulate m1.b.a(needle, caseSensitive).a(new g3(haystack), fromIndex, toIndex)
	// In Java, ls.b is a static final m1 instance, initialized with Executors.newCachedThreadPool()
	// We create a default M1 instance here as we are not handling ExecutorService.
	m1Instance := NewM1() // NewM1Default is from net_portswigger_m1.go

	searcher := m1Instance.CreateSearcher(needle, caseSensitive)
	haystackWrapper := NewG3(haystack) // NewG3 is from this file (net_portswigger_ls.go)

	// The searcher returned by CreateSearcher already includes sanitizing and null/empty haystack checks.
	return searcher.A(haystackWrapper, fromIndex, toIndex)
}

// NetPortswiggerLsAIndexOfSimple is a simple char-by-char indexOf (case-sensitive based on implementation).
// Corresponds to public static int a(byte[] var0, byte[] var1, int var2, int var3) in Java.
// The Java version had a complex `|| a(byte,byte)` which was for whitespace, not general case-insensitivity.
// This Go port is case-sensitive as the primary comparison `var0[var9++] == var1[var10++]` is case-sensitive.
func NetPortswiggerLsAIndexOfSimple(
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

// NetPortswiggerLsCLastIndexOf finds the last index of a sub-array (case-sensitive).
// Corresponds to public static int c(byte[] var0, byte[] var1, int var2, int var3)
func NetPortswiggerLsCLastIndexOf(haystack []byte, needle []byte, fromIndex int, toIndex int) int {
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

// NetPortswiggerLsAStartsWith checks if a byte slice starts with a given prefix.
// Corresponds to public static boolean a(byte[] var0, byte[] var1, boolean var2, int var3)
func NetPortswiggerLsAStartsWith(data []byte, prefix []byte, caseSensitive bool, offset int) bool {
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
			db = NetPortswiggerLsAToLowerByte(db)
			pb = NetPortswiggerLsAToLowerByte(pb)
		}
		if db != pb {
			return false
		}
	}
	return true
}

// NetPortswiggerLsAMatchesAt checks if a needle matches the haystack at a specific offset (case-sensitive).
// Corresponds to public static boolean a(byte[] var0, byte[] var1, int var2)
func NetPortswiggerLsAMatchesAt(haystack []byte, needle []byte, offset int) bool {
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
