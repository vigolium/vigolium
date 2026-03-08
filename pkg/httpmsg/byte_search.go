package httpmsg

// byte_search.go - Byte search and replace utilities
// Ported from: Utilities.java (search/replace operations)
//
// This file contains:
// - Exported: ContainsBytes, CountMatches, GetMatches
// - Internal: countByte, replaceBytes, replaceFirst, replaceBytesN

// ==================== EXPORTED FUNCTIONS ====================

// ContainsBytes checks if data contains the pattern.
// Ported from: Utilities.java containsBytes() (lines 837-842)
//
// Algorithm:
//  1. Use IndexOfBytes to find first occurrence
//  2. Return true if found (index != -1)
//
// Parameters:
//   - data: Byte array to search in
//   - pattern: Byte pattern to find
//
// Returns:
//   - true if pattern is found in data
//   - false if pattern is nil or empty
//
// Example:
//
//	found := ContainsBytes(data, []byte("test"))  // true if "test" found
func ContainsBytes(data, pattern []byte) bool {
	if data == nil || pattern == nil || len(pattern) == 0 {
		return false
	}
	return IndexOfBytes(data, pattern, 0) != -1
}

// CountMatches counts occurrences of pattern in data.
// Ported from: Utilities.java countMatches() (lines 525-542)
//
// Algorithm:
//  1. Start from position 0
//  2. Find each occurrence using IndexOfBytes
//  3. Move past each match and continue searching
//  4. Return total count
//
// Parameters:
//   - data: Byte array to search in
//   - pattern: Byte pattern to count
//
// Returns:
//   - Number of occurrences of pattern in data
//
// Example:
//
//	count := CountMatches(data, []byte("ab"))  // counts all "ab" occurrences
func CountMatches(data, pattern []byte) int {
	if data == nil || pattern == nil || len(pattern) == 0 {
		return 0
	}

	count := 0
	pos := 0

	for {
		idx := IndexOfBytes(data, pattern, pos)
		if idx == -1 {
			break
		}
		count++
		pos = idx + len(pattern)
	}

	return count
}

// GetMatches returns all [start, end] positions of pattern in data.
// Ported from: Utilities.java getMatches() (lines 679-704)
//
// Algorithm:
//  1. Start from position 0
//  2. Find each occurrence using IndexOfBytes
//  3. Record [start, end] for each match
//  4. Continue until no more matches or limit reached
//  5. Return all positions
//
// Parameters:
//   - data: Byte array to search in
//   - pattern: Byte pattern to find
//   - limit: Maximum matches to find (-1 for unlimited)
//
// Returns:
//   - Slice of [2]int{start, end} positions for each match
//
// Example:
//
//	matches := GetMatches(data, []byte("ab"), -1)
//	// For "abcab", returns [][2]int{{0, 2}, {3, 5}}
func GetMatches(data, pattern []byte, limit int) [][2]int {
	if data == nil || pattern == nil || len(pattern) == 0 {
		return nil
	}

	var matches [][2]int
	pos := 0
	count := 0

	for limit < 0 || count < limit {

		idx := IndexOfBytes(data, pattern, pos)
		if idx == -1 {
			break
		}

		matches = append(matches, [2]int{idx, idx + len(pattern)})
		count++
		pos = idx + len(pattern)
	}

	return matches
}

// ==================== INTERNAL FUNCTIONS ====================

// countByte counts occurrences of a single byte (internal helper).
//
// Algorithm:
//  1. Loop through data
//  2. Count matches
//
// replaceBytesN replaces up to n occurrences, -1 for all (internal).
// Core replacement function used by replaceBytes and replaceFirst.
//
// Algorithm:
//  1. If limit is 0, return copy of original
//  2. Find all matches up to limit
//  3. Calculate new size
//  4. Build result with replacements
//
// Parameters:
//   - data: Original byte array
//   - find: Pattern to find
//   - replace: Replacement bytes
//   - limit: Max replacements (-1 for all, 0 for none)
//
// Returns:
//   - New byte array with replacements made
func replaceBytesN(data, find, replace []byte, limit int) []byte {
	if data == nil {
		return nil
	}
	if len(find) == 0 {
		// Nothing to find, return copy
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}
	if limit == 0 {
		// No replacements requested
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}

	// Find all match positions (up to limit)
	matchLimit := limit
	if matchLimit < 0 {
		matchLimit = len(data) // Upper bound
	}
	matches := GetMatches(data, find, matchLimit)

	if len(matches) == 0 {
		// No matches, return copy
		result := make([]byte, len(data))
		copy(result, data)
		return result
	}

	// Calculate new size
	sizeDiff := len(replace) - len(find)
	newSize := len(data) + (sizeDiff * len(matches))

	// Build result
	result := make([]byte, 0, newSize)
	lastEnd := 0

	for _, match := range matches {
		// Copy data before this match
		result = append(result, data[lastEnd:match[0]]...)
		// Add replacement
		result = append(result, replace...)
		lastEnd = match[1]
	}

	// Copy remaining data after last match
	result = append(result, data[lastEnd:]...)

	return result
}
