package utils

import (
	"fmt" // For Math.min equivalent
)

// cecStaticM1 is the package-level SearcherFactory instance.
var cecStaticM1 = NewM1()

func DecodeUTF16PseudoBE(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if len(data)%2 != 0 {
		// This indicates an improperly formed byte array for UTF-16BE pairs
		// Consider returning an error or handling as per specific requirements.
		// For now, try to process as much as possible.
		// Or, more strictly, return error or empty string.
		// Given the Java code, it always creates data with even length (length * 2).
		// So this case ideally shouldn't happen if called from CecToStringRegion.
		return "" // Or potentially an error
	}

	runes := make([]rune, len(data)/2)
	for i := 0; i < len(data)/2; i++ {
		// byteOrderMark := uint16(data[2*i])<<8 | uint16(data[2*i+1])
		// Based on `var4[2 * var5 + 1] = var0.a(var1 + var5);`, it means:
		// utf16Bytes[0] = 0 (implicitly)
		// utf16Bytes[1] = actual byte from obj
		// utf16Bytes[2] = 0 (implicitly)
		// utf16Bytes[3] = actual byte from obj
		// So, the character code is just the byte at the odd index, with high byte 0.
		charCode := uint16(data[2*i+1]) // High byte is data[2*i] which should be 0
		runes[i] = rune(charCode)
	}
	return string(runes)
}

// --- Implement Pc interface for Ac0 to be used with m1 ---
// This wrapper is equivalent to b_8 in Java.

type B8WrapperForPc struct {
	ac0Data *Ac0
}

func NewB8WrapperForPc(data *Ac0) *B8WrapperForPc {
	return &B8WrapperForPc{ac0Data: data}
}

func (b *B8WrapperForPc) IsPc() {} // Marker for Pc interface

func (b *B8WrapperForPc) B() bool { // Corresponds to Pc.b() - is data null/empty
	return b.ac0Data == nil || b.ac0Data.Length() == 0
}

func (b *B8WrapperForPc) A() int { // Corresponds to Pc.a() - length of data
	if b.ac0Data == nil {
		return 0
	}
	return b.ac0Data.Length()
}

func (b *B8WrapperForPc) AAt(index int) int { // Corresponds to Pc.a(int) - get byte at index
	if b.ac0Data == nil {
		// Or handle error, Java might NPE
		return 0
	}
	// Pc.a(int) in Java seems to return (byte & 0xFF) which is just the byte value for positive bytes.
	return int(b.ac0Data.GetByte(index))
}

// Ensure B8WrapperForPc implements Pc
var _ Pc = (*B8WrapperForPc)(nil)

// Helper for Math.min equivalent if not wanting to import "math" for just one function
// However, it's cleaner to use math.Min. For int, we need a small helper.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CecEqualsBi9 corresponds to public static boolean a(bi9 var0, bi9 var1)
func CecEqualsBi9(obj1 *Ac0, obj2 *Ac0) bool {
	if obj1 != nil && obj2 != nil {
		len1 := obj1.Length()
		if len1 != obj2.Length() {
			return false
		} else {
			i := 0
			for i < len1 {
				if obj1.GetByte(i) != obj2.GetByte(i) {
					return false
				}
				i++

			}
			return true
		}
	} else {
		return false
	}
}

// CecEqualsBi9Region corresponds to public static boolean a(bi9 var0, int var1, int var2, bi9 var3, int var4, int var5)
func CecEqualsBi9Region(obj1 *Ac0, start1 int, end1 int, obj2 *Ac0, start2 int, end2 int) bool {
	if end1-start1 != end2-start2 {
		return false
	} else {
		current1 := start1
		current2 := start2
		for current1 < end1 { // In Java, original var1 (start1) is incremented, so loop is while (var1 < var2)
			// Bounds checks should ideally be done by GetByte or are assumed valid by caller
			if obj1.GetByte(current1) != obj2.GetByte(current2) {
				return false
			}
			current1++
			current2++

		}
		return true
	}
}

// CecFirstDifferenceOffset corresponds to public static int[] b(bi9 var0, int var1, int var2, bi9 var3, int var4, int var5)
func CecFirstDifferenceOffset(
	obj1 *Ac0,
	start1 int,
	end1 int,
	obj2 *Ac0,
	start2 int,
	end2 int,
) []int {
	current1 := start1
	current2 := start2

	for current1 < end1 && current2 < end2 {
		// Bounds checks for GetByte are implicitly handled by Ac0.GetByte or should lead to panic if out of bounds
		if obj1.GetByte(current1) != obj2.GetByte(current2) {
			return []int{current1, current2}
		}
		current1++
		current2++

	}
	// return var1 == var2 && var4 == var5 ? null : new int[] { var1, var4 };
	// Java var1, var2, var4, var5 are the loop-modified indices (current1, end1, current2, end2)
	if current1 == end1 && current2 == end2 {
		return nil // Both regions exhausted simultaneously, means they were equal
	}
	return []int{
		current1,
		current2,
	} // Return the point where one or both ended, or where loop broke
}

// --- IndexOf methods for byte array (needle) ---

// CecIndexOfBytes corresponds to public static int a(bi9 var0, byte[] var1)
func CecIndexOfBytes(obj *Ac0, needle []byte) int {
	if obj == nil {
		return -1
	}
	return CecIndexOfBytesCSFromOffsetRange(obj, needle, true, 0, obj.Length())
}

// CecIndexOfBytesCS corresponds to public static int a(bi9 var0, byte[] var1, boolean var2)
func CecIndexOfBytesCS(obj *Ac0, needle []byte, caseSensitive bool) int {
	if obj == nil {
		return -1
	}
	return CecIndexOfBytesCSFromOffsetRange(obj, needle, caseSensitive, 0, obj.Length())
}

// CecIndexOfBytesCSFromOffset corresponds to public static int a(bi9 var0, byte[] var1, boolean var2, int var3)
func CecIndexOfBytesCSFromOffset(obj *Ac0, needle []byte, caseSensitive bool, fromIndex int) int {
	if obj == nil {
		return -1
	}
	return CecIndexOfBytesCSFromOffsetRange(obj, needle, caseSensitive, fromIndex, obj.Length())
}

// CecIndexOfBytesRange corresponds to public static int b(bi9 var0, byte[] var1, int var2, int var3)
// This Java method calls `a` with caseSensitive = true.
func CecIndexOfBytesRange(obj *Ac0, needle []byte, fromIndex int, toIndex int) int {
	return CecIndexOfBytesCSFromOffsetRange(obj, needle, true, fromIndex, toIndex)
}

// CecIndexOfBytesCSFromOffsetRange is the main implementation for finding a byte slice within Ac0.
// Corresponds to public static int a(bi9 var0, byte[] var1, boolean var2, int var3, int var4)
func CecIndexOfBytesCSFromOffsetRange(
	obj *Ac0,
	needle []byte,
	caseSensitive bool,
	fromIndex int,
	toIndex int,
) int {
	// return a.a(var1, var2).a(new b_8(var0), var3, var4);
	// cecStaticM1 is the package-level SearcherFactory instance
	if cecStaticM1 == nil {
		// This should not happen if init() worked correctly
		return -1
	}
	// CreateSearcher returns an E0 interface instance
	searcher := cecStaticM1.CreateSearcher(needle, caseSensitive)
	if searcher == nil {
		// CreateSearcher might return nil if pattern is nil, though m1 handles this internally by returning specific E0 impl.
		// If it can truly be nil, this is an error path.
		return -1
	}

	// new b_8(var0) -> NewB8WrapperForPc(obj)
	pcWrapper := NewB8WrapperForPc(obj)

	return searcher.A(pcWrapper, fromIndex, toIndex)
}

// --- IndexOf methods for single byte (needle) ---

// CecIndexOfByteCSFromOffsetRange finds the first occurrence of a byte within a range, with case sensitivity.
// Corresponds to public static int a(bi9 var0, byte var1, boolean var2, int var3, int var4)
func CecIndexOfByteCSFromOffsetRange(
	obj *Ac0,
	needle byte,
	caseSensitive bool,
	fromIndex int,
	toIndex int,
) int {
	if obj == nil {
		return -1
	}

	searchByte := needle
	if !caseSensitive {
		searchByte = SingleByteToLower(needle) // nk.a(byte)
	}

	// Math.min(var4, var0.aF());
	actualToIndex := minInt(toIndex, obj.Length()) // Use local minInt or math.Min if types match
	currentIndex := fromIndex

	for currentIndex < actualToIndex {
		haystackByte := obj.GetByte(currentIndex)
		if !caseSensitive {
			haystackByte = ToLowerByte(haystackByte) // ls.a(byte)
		}
		if haystackByte == searchByte {
			return currentIndex
		}
		currentIndex++

	}
	return -1
}

// CecIndexOfByteRange finds the first occurrence of a byte within a range (case-sensitive).
// Corresponds to public static int b(bi9 var0, byte var1, int var2, int var3)
func CecIndexOfByteRange(obj *Ac0, needle byte, fromIndex int, toIndex int) int {
	if obj == nil {
		return -1
	}
	// Math.min(var3, var0.aF());
	actualToIndex := minInt(toIndex, obj.Length())
	currentIndex := fromIndex

	for currentIndex < actualToIndex {
		// if (var1 == var0.a(var2++)) { return var2 - 1; }
		// This loop structure with var2++ inside access and then var2-1 return is tricky.
		// It means if current char matches, return its index, then advance.
		if needle == obj.GetByte(currentIndex) {
			return currentIndex
		}
		currentIndex++
	}
	return -1
}

// CecLastIndexOfByteRange finds the last occurrence of a byte within a range (case-sensitive).
// Corresponds to public static int a(bi9 var0, byte var1, int var2, int var3) - the lastIndexOf version
func CecLastIndexOfByteRange(obj *Ac0, needle byte, fromIndex int, toIndex int) int {
	if obj == nil {
		return -1
	}
	// var3 = Math.min(var3, var0.aF());
	actualToIndex := minInt(
		toIndex,
		obj.Length(),
	) // Loop will go up to, but not include, actualToIndex initially for --var3

	// while (--var3 >= var2)
	// The loop should start checking from actualToIndex-1 down to fromIndex.
	currentIndex := actualToIndex - 1
	for currentIndex >= fromIndex {
		if needle == obj.GetByte(currentIndex) {
			return currentIndex
		}
		currentIndex--
	}
	return -1
}

// --- Other search/matching methods ---

// CecLastIndexOfBytesRange finds the last occurrence of a byte slice within a specified range of Ac0.
// Corresponds to public static int a(bi9 var0, byte[] var1, int var2, int var3)
func CecLastIndexOfBytesRange(obj *Ac0, needle []byte, fromIndex int, toIndex int) int {
	if obj == nil || needle == nil {
		return -1
	}

	needleLen := len(needle)
	if needleLen == 0 {
		// Java logic: return var3 (toIndex). In Go, ensure toIndex is within bounds.
		return minInt(toIndex, obj.Length())
	}

	// int var6 = Math.min(var3, var0.aF()); // toIndex, obj.Length()
	actualToIndex := minInt(toIndex, obj.Length())
	// int var7 = var6 - var5; // var5 is needleLen. This is the last possible start index for needle.
	lastPossibleStart := actualToIndex - needleLen
	firstNeedleByte := needle[0]
	currentIndex := lastPossibleStart // Start searching from the rightmost possible position

	// Java: do { ... } while (var4 != null); which is effectively an infinite loop if var4 is non-null.
	// The break condition is `if (var7 < var2)`, or if a match is found.
	// `var4` is `loopControl`.
	for {
		if currentIndex < fromIndex {
			return -1
		}

		// while (var7 > var2 && var0.a(var7) != var8)
		// Search backwards for the first byte of the needle
		for currentIndex > fromIndex && obj.GetByte(currentIndex) != firstNeedleByte {
			currentIndex--

		}
		// If inner loop broke due to loopControl, and we haven't found the first byte or passed fromIndex
		if currentIndex <= fromIndex && obj.GetByte(currentIndex) != firstNeedleByte {
			// This state can be complex. If loopControl makes the inner loop break early,
			// we might not have found firstNeedleByte. The outer loop will re-evaluate currentIndex < fromIndex.
			// If currentIndex is already < fromIndex, the outer loop terminates.
			// If current byte is not the first needle byte, and currentIndex <= fromIndex, then we can't match.
			if obj.GetByte(
				currentIndex,
			) != firstNeedleByte { // ensure we are not on a match already
				currentIndex-- // continue search from one position left

			}
		}

		// At this point, either obj.GetByte(currentIndex) == firstNeedleByte, or currentIndex <= fromIndex
		if obj.GetByte(currentIndex) == firstNeedleByte {
			matchOffsetInObj := currentIndex // var9 = var7;
			matchOffsetInNeedle := 0         // var10 = 0;
			match := true
			// do { if (var10 >= var5) return var7; } while (var0.a(var9++) == var1[var10++]);
			for {
				if matchOffsetInNeedle >= needleLen {
					return currentIndex // Found full match
				}
				// Check bounds before GetByte
				if matchOffsetInObj >= obj.Length() ||
					obj.GetByte(matchOffsetInObj) != needle[matchOffsetInNeedle] {
					match = false
					break
				}
				matchOffsetInObj++
				matchOffsetInNeedle++
			}
			if match { // Should have returned inside the loop if fully matched
				return currentIndex
			}
		}

		currentIndex-- // Decrement to search at the next position to the left

	}
}
func CecStartsWithSimple(obj *Ac0, prefix []byte, offset int) bool {
	return CecStartsWith(obj, prefix, true, offset)
}

// CecStartsWith checks if Ac0 data starts with a given prefix, with case sensitivity.
// Corresponds to public static boolean b(bi9 var0, byte[] var1, boolean var2, int var3)
func CecStartsWith(obj *Ac0, prefix []byte, caseSensitive bool, offset int) bool {
	if obj == nil || prefix == nil {
		return false // Java might NPE or have specific behavior for nulls.
	}
	// Java: var1.length <= var0.aF() - var3
	if len(prefix) > obj.Length()-offset {
		return false
	}
	if offset < 0 { // Added guard for negative offset
		return false
	}

	for i := 0; i < len(prefix); i++ {
		objByte := obj.GetByte(i + offset)
		prefixByte := prefix[i]
		var currentObjByte byte

		if caseSensitive {
			currentObjByte = objByte
		} else {
			currentObjByte = ToLowerByte(objByte) // ls.a(byte)
			// Note: Java code applies toLower to objByte, but compares with original prefixByte.
			// If prefixByte should also be case-normalized for case-insensitive, it's missing in Java logic.
			// Porting strictly, so prefixByte is not changed here.
		}

		if currentObjByte != prefixByte {
			return false
		}
	}
	return true
}

// CecMatchesAt checks if a needle matches Ac0 data at a specific offset (case-sensitive).
// Corresponds to public static boolean a(bi9 var0, byte[] var1, int var2)
func CecMatchesAt(obj *Ac0, needle []byte, offset int) bool {
	if obj == nil || needle == nil || offset < 0 || offset+len(needle) > obj.Length() {
		return false
	}
	needleLen := len(needle)
	currentObjOffset := offset
	currentNeedleOffset := 0

	// while (var4 < var3)
	for currentNeedleOffset < needleLen {
		// if (var0.a(var2++) != var1[var4++]) { return false; }
		// Java increments after comparison. Go needs explicit increment.
		if obj.GetByte(currentObjOffset) != needle[currentNeedleOffset] {
			return false
		}
		currentObjOffset++
		currentNeedleOffset++
	}
	return true
}

// CecSkipWhitespace finds the index of the first non-whitespace character.
// Corresponds to public static int b(bi9 var0, int var1, int var2)
func CecSkipWhitespace(obj *Ac0, fromIndex int, toIndex int) int {
	if obj == nil {
		return toIndex // Or some other indicator of error/nothing found
	}
	currentIndex := fromIndex
	actualToIndex := minInt(toIndex, obj.Length())

	for currentIndex < actualToIndex {
		if obj.GetByte(
			currentIndex,
		) > 32 { // Character is not a whitespace (space or control char <= 32)
			return currentIndex
		}
		currentIndex++

	}
	return actualToIndex // If all are whitespace, return the original toIndex (or adjusted actualToIndex)
}

// CecToString converts an Ac0 object to a string.
// Corresponds to public static String a(bi9 var0)
func CecToString(obj *Ac0) string {
	if obj == nil {
		return "" // Java: return null; Go: return empty string for nil *Ac0 input
	}
	return CecToStringRegion(obj, 0, obj.Length())
}

// CecToStringRegion converts a region of an Ac0 object to a string.
// Corresponds to public static String a(bi9 var0, int var1, int var2)
func CecToStringRegion(obj *Ac0, fromIndex int, length int) string {
	if obj == nil {
		return "" // Java: return null;
	}
	// Basic bounds checks. Java version directly creates byte[length*2] which could lead to NegativeArraySize if length is negative.
	// And obj.a(fromIndex + i) could lead to ArrayIndexOutOfBounds.
	// Go needs more careful bounds handling here.
	if fromIndex < 0 || length < 0 || fromIndex+length > obj.Length() {
		// Handle invalid range, Java might throw. Return empty string for simplicity.
		// Or panic for stricter error handling.

		return ""
	}
	if length == 0 {
		return ""
	}

	// byte[] var4 = new byte[var2 * 2]; // var2 is length
	utf16Bytes := make([]byte, length*2)
	i := 0
	// while (var5 < var2)
	for i < length {
		// var4[2 * var5 + 1] = var0.a(var1 + var5);
		// (fromIndex + i) must be a valid index in obj.data
		utf16Bytes[2*i+1] = obj.GetByte(fromIndex + i)
		i++

	}
	// If loop did break early due to loopControl == nil, we need to use the actual number of bytes processed.
	actualUtf16Len := i * 2
	// return new String(var4, StandardCharsets.UTF_16);
	// niocharset.NiocharsetUTF16Decode is a placeholder for UTF-16BE decoding.
	// The Java code creates a byte array where high bytes are implicitly zero, then decodes as UTF-16.
	// This is effectively UTF-16BE where low byte is from source, high byte is 0.
	return DecodeUTF16PseudoBE(utf16Bytes[0:actualUtf16Len])
}

// CecAc0FromString creates an Ac0 object from a string.
// Corresponds to public static bi9 a(String var0)
func CecAc0FromString(s string) *Ac0 {
	if s == "" { // Java: var0 == null. Go: empty string as proxy for this specific method's null check.
		return nil
	}
	// return a(var0, ac0.a(new byte[var0.length()]), 0);
	// ac0.a(new byte[var0.length()]) -> NewAc0ByteDataWithCapacity(len(s))
	targetAc0 := NewAc0ByteDataWithCapacity(len(s))
	resultAc0, _ := CecWriteStringToAc0(
		s,
		targetAc0,
		0,
	) // Error from CecWriteStringToAc0 ignored as per Java return type
	return resultAc0
}

// CecWriteStringToAc0 writes a string into an Ac0 object at a given offset.
// Corresponds to public static bi9 a(String var0, bi9 var1, int var2)
func CecWriteStringToAc0(s string, targetObj *Ac0, offset int) (*Ac0, error) {
	if targetObj == nil { // Java: if (var0 == null) return null; - this is for string, targetObj is var1
		return nil, fmt.Errorf("target Ac0 object cannot be nil")
	}
	// Java: if (var0 == null) return null;
	// In Go, string s cannot be nil. If empty string means null result:
	// if s == "" { return nil, nil } // This would match Java `var0 == null`
	// For now, assuming non-empty `s` or that empty `s` writes nothing.

	strLen := len(s)
	// Check if targetObj has enough space from offset
	if offset < 0 || offset+strLen > targetObj.Length() {
		return targetObj, fmt.Errorf(
			"offset/length out of bounds for target Ac0: offset %d, strLen %d, targetLen %d",
			offset,
			strLen,
			targetObj.Length(),
		)
	}

	for i := 0; i < strLen; i++ {
		// var1.a(var2 + var4, (byte) var0.charAt(var4));
		// targetObj.SetByte(offset+i, byte(s[i])) // s[i] is byte in Go for string iteration
		// Java charAt(i) can be > 255. (byte) conversion truncates.
		targetObj.SetByte(
			offset+i,
			byte(rune(s[i])),
		) // Get rune then cast to byte for closer Java char->byte truncation
	}
	return targetObj, nil
}
