package utils

import (
	"fmt" // For Math.min equivalent
)

// defaultSearcherFactory is the package-level SearcherFactory instance.
var defaultSearcherFactory = NewSearcherFactory()

func DecodeUTF16PseudoBE(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if len(data)%2 != 0 {
		// This indicates an improperly formed byte array for UTF-16BE pairs
		// Consider returning an error or handling as per specific requirements.
		// For now, try to process as much as possible.
		// Or, more strictly, return error or empty string.
		// So this case ideally shouldn't happen if called from ByteSequenceToStringRegion.
		return "" // Or potentially an error
	}

	runes := make([]rune, len(data)/2)
	for i := 0; i < len(data)/2; i++ {
		// The character code is just the byte at the odd index, with high byte 0.
		charCode := uint16(data[2*i+1])
		runes[i] = rune(charCode)
	}
	return string(runes)
}

// --- Implement SearchableData interface for ByteSequence to be used with SearcherFactory ---

type ByteSequenceSearchAdapter struct {
	ac0Data *ByteSequence
}

func NewByteSequenceSearchAdapter(data *ByteSequence) *ByteSequenceSearchAdapter {
	return &ByteSequenceSearchAdapter{ac0Data: data}
}

func (b *ByteSequenceSearchAdapter) IsSearchableData() {} // Marker for SearchableData interface

func (b *ByteSequenceSearchAdapter) IsEmpty() bool {
	return b.ac0Data == nil || b.ac0Data.Length() == 0
}

func (b *ByteSequenceSearchAdapter) Length() int {
	if b.ac0Data == nil {
		return 0
	}
	return b.ac0Data.Length()
}

func (b *ByteSequenceSearchAdapter) ByteAt(index int) int {
	if b.ac0Data == nil {
		return 0
	}
	return int(b.ac0Data.GetByte(index))
}

// Ensure ByteSequenceSearchAdapter implements SearchableData
var _ SearchableData = (*ByteSequenceSearchAdapter)(nil)

// Helper for Math.min equivalent if not wanting to import "math" for just one function
// However, it's cleaner to use math.Min. For int, we need a small helper.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ByteSequenceEquals(obj1 *ByteSequence, obj2 *ByteSequence) bool {
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

func ByteSequenceRegionEquals(obj1 *ByteSequence, start1 int, end1 int, obj2 *ByteSequence, start2 int, end2 int) bool {
	if end1-start1 != end2-start2 {
		return false
	} else {
		current1 := start1
		current2 := start2
		for current1 < end1 {
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

func ByteSequenceFirstDifference(
	obj1 *ByteSequence,
	start1 int,
	end1 int,
	obj2 *ByteSequence,
	start2 int,
	end2 int,
) []int {
	current1 := start1
	current2 := start2

	for current1 < end1 && current2 < end2 {
		// Bounds checks for GetByte are implicitly handled by ByteSequence.GetByte or should lead to panic if out of bounds
		if obj1.GetByte(current1) != obj2.GetByte(current2) {
			return []int{current1, current2}
		}
		current1++
		current2++

	}
	if current1 == end1 && current2 == end2 {
		return nil // Both regions exhausted simultaneously, means they were equal
	}
	return []int{
		current1,
		current2,
	} // Return the point where one or both ended, or where loop broke
}

// --- IndexOf methods for byte array (needle) ---

func ByteSequenceIndexOf(obj *ByteSequence, needle []byte) int {
	if obj == nil {
		return -1
	}
	return ByteSequenceIndexOfFull(obj, needle, true, 0, obj.Length())
}

func ByteSequenceIndexOfCS(obj *ByteSequence, needle []byte, caseSensitive bool) int {
	if obj == nil {
		return -1
	}
	return ByteSequenceIndexOfFull(obj, needle, caseSensitive, 0, obj.Length())
}

func ByteSequenceIndexOfFrom(obj *ByteSequence, needle []byte, caseSensitive bool, fromIndex int) int {
	if obj == nil {
		return -1
	}
	return ByteSequenceIndexOfFull(obj, needle, caseSensitive, fromIndex, obj.Length())
}

func ByteSequenceIndexOfRange(obj *ByteSequence, needle []byte, fromIndex int, toIndex int) int {
	return ByteSequenceIndexOfFull(obj, needle, true, fromIndex, toIndex)
}

// ByteSequenceIndexOfFull is the main implementation for finding a byte slice within ByteSequence.
func ByteSequenceIndexOfFull(
	obj *ByteSequence,
	needle []byte,
	caseSensitive bool,
	fromIndex int,
	toIndex int,
) int {
	// defaultSearcherFactory is the package-level SearcherFactory instance
	if defaultSearcherFactory == nil {
		// This should not happen if init() worked correctly
		return -1
	}
	// CreateSearcher returns a PatternSearcher interface instance
	searcher := defaultSearcherFactory.CreateSearcher(needle, caseSensitive)
	if searcher == nil {
		// CreateSearcher might return nil if pattern is nil, though SearcherFactory handles this internally.
		// If it can truly be nil, this is an error path.
		return -1
	}

	pcWrapper := NewByteSequenceSearchAdapter(obj)

	return searcher.Search(pcWrapper, fromIndex, toIndex)
}

// --- IndexOf methods for single byte (needle) ---

// ByteSequenceIndexOfByteRange finds the first occurrence of a byte within a range, with case sensitivity.
func ByteSequenceIndexOfByteRange(
	obj *ByteSequence,
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
		searchByte = SingleByteToLower(needle)
	}

	actualToIndex := minInt(toIndex, obj.Length()) // Use local minInt or math.Min if types match
	currentIndex := fromIndex

	for currentIndex < actualToIndex {
		haystackByte := obj.GetByte(currentIndex)
		if !caseSensitive {
			haystackByte = ToLowerByte(haystackByte)
		}
		if haystackByte == searchByte {
			return currentIndex
		}
		currentIndex++

	}
	return -1
}

// ByteSequenceIndexOfByte finds the first occurrence of a byte within a range (case-sensitive).
func ByteSequenceIndexOfByte(obj *ByteSequence, needle byte, fromIndex int, toIndex int) int {
	if obj == nil {
		return -1
	}
	actualToIndex := minInt(toIndex, obj.Length())
	currentIndex := fromIndex

	for currentIndex < actualToIndex {
		// It means if current char matches, return its index, then advance.
		if needle == obj.GetByte(currentIndex) {
			return currentIndex
		}
		currentIndex++
	}
	return -1
}

// ByteSequenceLastIndexOfByte finds the last occurrence of a byte within a range (case-sensitive).
func ByteSequenceLastIndexOfByte(obj *ByteSequence, needle byte, fromIndex int, toIndex int) int {
	if obj == nil {
		return -1
	}
	actualToIndex := minInt(
		toIndex,
		obj.Length(),
	) // Loop will go up to, but not include, actualToIndex initially for --var3

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

// ByteSequenceLastIndexOf finds the last occurrence of a byte slice within a specified range of ByteSequence.
func ByteSequenceLastIndexOf(obj *ByteSequence, needle []byte, fromIndex int, toIndex int) int {
	if obj == nil || needle == nil {
		return -1
	}

	needleLen := len(needle)
	if needleLen == 0 {
		return minInt(toIndex, obj.Length())
	}

	actualToIndex := minInt(toIndex, obj.Length())
	lastPossibleStart := actualToIndex - needleLen
	firstNeedleByte := needle[0]
	currentIndex := lastPossibleStart // Start searching from the rightmost possible position

	for {
		if currentIndex < fromIndex {
			return -1
		}

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
			matchOffsetInObj := currentIndex
			matchOffsetInNeedle := 0
			match := true
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
func ByteSequenceStartsWith(obj *ByteSequence, prefix []byte, offset int) bool {
	return ByteSequenceStartsWithCS(obj, prefix, true, offset)
}

// ByteSequenceStartsWithCS checks if ByteSequence data starts with a given prefix, with case sensitivity.
func ByteSequenceStartsWithCS(obj *ByteSequence, prefix []byte, caseSensitive bool, offset int) bool {
	if obj == nil || prefix == nil {
		return false
	}
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
			currentObjByte = ToLowerByte(objByte)
			// Porting strictly, so prefixByte is not changed here.
		}

		if currentObjByte != prefixByte {
			return false
		}
	}
	return true
}

// ByteSequenceMatchesAt checks if a needle matches ByteSequence data at a specific offset (case-sensitive).
func ByteSequenceMatchesAt(obj *ByteSequence, needle []byte, offset int) bool {
	if obj == nil || needle == nil || offset < 0 || offset+len(needle) > obj.Length() {
		return false
	}
	needleLen := len(needle)
	currentObjOffset := offset
	currentNeedleOffset := 0

	for currentNeedleOffset < needleLen {
		if obj.GetByte(currentObjOffset) != needle[currentNeedleOffset] {
			return false
		}
		currentObjOffset++
		currentNeedleOffset++
	}
	return true
}

// ByteSequenceSkipWhitespace finds the index of the first non-whitespace character.
func ByteSequenceSkipWhitespace(obj *ByteSequence, fromIndex int, toIndex int) int {
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

// ByteSequenceToString converts an ByteSequence object to a string.
func ByteSequenceToString(obj *ByteSequence) string {
	if obj == nil {
		return ""
	}
	return ByteSequenceToStringRegion(obj, 0, obj.Length())
}

// ByteSequenceToStringRegion converts a region of an ByteSequence object to a string.
func ByteSequenceToStringRegion(obj *ByteSequence, fromIndex int, length int) string {
	if obj == nil {
		return ""
	}
	// And obj.a(fromIndex + i) could lead to ArrayIndexOutOfBounds.
	// Go needs more careful bounds handling here.
	if fromIndex < 0 || length < 0 || fromIndex+length > obj.Length() {
		// Handle invalid range. Return empty string for simplicity.
		// Or panic for stricter error handling.

		return ""
	}
	if length == 0 {
		return ""
	}

	utf16Bytes := make([]byte, length*2)
	i := 0
	for i < length {
		// (fromIndex + i) must be a valid index in obj.data
		utf16Bytes[2*i+1] = obj.GetByte(fromIndex + i)
		i++

	}
	// If loop did break early due to loopControl == nil, we need to use the actual number of bytes processed.
	actualUtf16Len := i * 2
	// Decode pseudo UTF-16BE where low byte is from source, high byte is 0.
	return DecodeUTF16PseudoBE(utf16Bytes[0:actualUtf16Len])
}

// ByteSequenceFromStringEncoded creates an ByteSequence object from a string.
func ByteSequenceFromStringEncoded(s string) *ByteSequence {
	if s == "" {
		return nil
	}
	targetByteSequence := NewByteSequenceWithCapacity(len(s))
	resultByteSequence, _ := WriteStringToByteSequence(
		s,
		targetByteSequence,
		0,
	)
	return resultByteSequence
}

// WriteStringToByteSequence writes a string into an ByteSequence object at a given offset.
func WriteStringToByteSequence(s string, targetObj *ByteSequence, offset int) (*ByteSequence, error) {
	if targetObj == nil {
		return nil, fmt.Errorf("target ByteSequence object cannot be nil")
	}
	// In Go, string s cannot be nil. If empty string means null result:
	// For now, assuming non-empty `s` or that empty `s` writes nothing.

	strLen := len(s)
	// Check if targetObj has enough space from offset
	if offset < 0 || offset+strLen > targetObj.Length() {
		return targetObj, fmt.Errorf(
			"offset/length out of bounds for target ByteSequence: offset %d, strLen %d, targetLen %d",
			offset,
			strLen,
			targetObj.Length(),
		)
	}

	for i := 0; i < strLen; i++ {
		// targetObj.SetByte(offset+i, byte(s[i])) // s[i] is byte in Go for string iteration
		targetObj.SetByte(
			offset+i,
			byte(rune(s[i])),
		)
	}
	return targetObj, nil
}
