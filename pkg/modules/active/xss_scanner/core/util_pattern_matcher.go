package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

/* -------------------------------------------------------------------------- */
// db9.java
type ByteSequenceMatcher interface {
	// FindMatch corresponds to Java: cc4 a(byte[] var1, int var2, int var3);
	// var1: data, var2: offset/param, var3: length/param
	FindMatch(data []byte, startIndex int, endIndex int) *ByteMatchPosition
}

// ByteMatchPosition is the Go equivalent of the Java class cc4.
// It holds two integer values.
// cc4.java
type ByteMatchPosition struct {
	MatchStartIndex int // Corresponds to 'public final int b;' (assigned from constructor var1)
	MatchEndIndex   int // Corresponds to 'public final int a;' (assigned from constructor var2)
}

// NewByteMatchPosition creates a new instance of Cc4.
// Original Java constructor: public cc4(int var1, int var2)
// var1 is assigned to this.b, var2 is assigned to this.a
func NewByteMatchPosition(startIndex int, endIndex int) *ByteMatchPosition {
	return &ByteMatchPosition{
		MatchStartIndex: startIndex,
		MatchEndIndex:   endIndex,
	}
}

/* -------------------------------------------------------------------------- */

// ConfigurableBytePatternMatcher is the Go equivalent of the Java class e8u.
// It implements the Db9 interface for pattern matching.
type ConfigurableBytePatternMatcher struct {
	searchPattern            []byte // Corresponds to 'private final byte[] c;'
	shouldUnescapeBackslash  bool   // Corresponds to 'private final boolean b;'
	shouldDecodeHTMLEntities bool   // Corresponds to 'private final boolean a;'
}

// NewConfigurableBytePatternMatcher is the constructor for E8u.
// Corresponds to 'protected e8u(byte[] var1, boolean var2, boolean var3)'
func NewConfigurableBytePatternMatcher(
	pattern []byte,
	unescapeBackslash bool,
	decodeHTMLEntities bool,
) *ConfigurableBytePatternMatcher {
	// In Go, a nil slice is often preferred over an empty slice if it represents "no value" or "not applicable".
	// However, Java initializes final fields, so if var1 (pattern) was null there, it would remain null.
	// For byte[], null and empty are distinct. The Java code checks this.c.length != 0.
	// So, we directly assign the pattern. If it's nil, len(nil) is 0.
	return &ConfigurableBytePatternMatcher{
		searchPattern:            pattern,
		shouldUnescapeBackslash:  unescapeBackslash,
		shouldDecodeHTMLEntities: decodeHTMLEntities,
	}
}

// --- Static Factory Methods --- //

// NewSimpleBytePatternMatcher corresponds to 'public static e8u a(byte[] var0)'
// e8u(var0, false, false)
func NewSimpleBytePatternMatcher(pattern []byte) *ConfigurableBytePatternMatcher {
	return NewConfigurableBytePatternMatcher(pattern, false, false)
}

// NewHtmlDecodingBytePatternMatcher corresponds to 'public static e8u d(byte[] var0)'
// e8u(var0, false, true)
func NewHtmlDecodingBytePatternMatcher(pattern []byte) *ConfigurableBytePatternMatcher {
	return NewConfigurableBytePatternMatcher(pattern, false, true)
}

// NewUnescapingHtmlDecodingBytePatternMatcher corresponds to 'public static e8u b(byte[] var0)'
// e8u(var0, true, true)
func NewUnescapingHtmlDecodingBytePatternMatcher(pattern []byte) *ConfigurableBytePatternMatcher {
	return NewConfigurableBytePatternMatcher(pattern, true, true)
}

// NewUnescapingBytePatternMatcher corresponds to 'public static e8u c(byte[] var0)'
// e8u(var0, true, false)
func NewUnescapingBytePatternMatcher(pattern []byte) *ConfigurableBytePatternMatcher {
	return NewConfigurableBytePatternMatcher(pattern, true, false)
}

// --- Interface Methods (Db9) and Private Helpers --- //

// FindMatch is the Go equivalent of the public Java method a(byte[] var1, int var2, int var3)
// which implements the Db9 interface.
// var1: data, var2: offset, var3: toIndex (exclusive for search operations)
func (e *ConfigurableBytePatternMatcher) FindMatch(
	data []byte,
	startIndex int,
	endIndex int,
) *ByteMatchPosition {
	// Original Java: if (this.c.length != 0 && var2 < var1.length)
	// Note: len(nil slice) is 0 in Go.
	if len(e.searchPattern) != 0 && startIndex < len(data) {
		// cc4 var4 = this.d(var1, var2, var3);
		directMatch := e.findMatchWithTransformations(data, startIndex, endIndex)
		if directMatch != nil {
			return directMatch
		} else {
			// return !this.a && !this.b ? null : this.b(var1, var2, var3);
			// this.a is decodeHtmlEntities, this.b is unescapeBackslash
			if !e.shouldDecodeHTMLEntities && !e.shouldUnescapeBackslash {
				return nil
			}
			return e.findDirectMatch(data, startIndex, endIndex)
		}
	} else {
		return nil
	}
}

// findDirectMatch is the Go equivalent of the private Java method b(byte[] var1, int var2, int var3)
// var1: data, var2: offset, var3: toIndex (exclusive for search operations)
func (e *ConfigurableBytePatternMatcher) findDirectMatch(
	data []byte,
	startIndex int,
	endIndex int,
) *ByteMatchPosition {
	foundAtIndex := utils.IndexOfPattern(
		data,
		e.searchPattern,
		false,
		startIndex,
		endIndex,
	)

	// return var4 < 0 ? null : new cc4(var4, var4 + this.c.length);
	if foundAtIndex < 0 {
		return nil
	}
	return NewByteMatchPosition(
		foundAtIndex,
		foundAtIndex+len(e.searchPattern),
	) // NewCc4 from cc4.go
}

// decodeCharacterAndUpdateState is the Go equivalent of private h85 a(byte[] var1, int var2, int var3, int var4)
// var1: data, var2: initialCurrentIndex, var3: toIndex (boundary), var4: patternMatchOffset (for boundary check)
func (e *ConfigurableBytePatternMatcher) decodeCharacterAndUpdateState(
	data []byte,
	currentIndex int,
	scanEndIndex int,
	currentPatternOffset int,
) *PatternMatchState {
	scanIndex := currentIndex
	if scanIndex >= len(
		data,
	) { // Prevent panic from var1[var2++] if currentIndex is already at end
		return nil
	}
	processedCharByte := data[scanIndex] // Java: byte var5 = var1[var2++];
	scanIndex++

	// Java: if (this.a && var5 == 38)
	if e.shouldDecodeHTMLEntities && processedCharByte == 38 {
		semicolonPos := utils.IndexOfByteCS(
			data,
			59,
			scanIndex+1,
			len(data),
		)

		if semicolonPos > -1 {
			// byte var7 = this.c(var1, var2, var6);
			// var2 here is current index of char after '&', var6 is index of ';'. Entity name is between them.
			decodedEntityChar, err := e.parseHTMLEntity(data, scanIndex, semicolonPos)
			if err == nil {
				processedCharByte = decodedEntityChar
				scanIndex = semicolonPos + 1

				// Java: if (var2 > var3 - this.c.length + var4 + 1)
				if scanIndex > scanEndIndex-len(e.searchPattern)+currentPatternOffset+1 {
					return nil
				}
			}
		}
	}
	// Java: return new h85(var2, var5, null);
	// var2 is the updated currentIndex, var5 is the final character (original or decoded)
	return NewPatternMatchState(scanIndex, processedCharByte, nil) // g0c is nil
}

// isQuoteCharacter is the Go equivalent of private boolean a(byte var1)
func (e *ConfigurableBytePatternMatcher) isQuoteCharacter(char byte) bool {
	// return var1 == 39 || var1 == 34 || var1 == 96;
	return char == 39 || char == 34 || char == 96
}

// Placeholder for cInternalParseHtmlEntity
// func (e *E8u) cInternalParseHtmlEntity(data []byte, entityStart int, entityEnd int) (byte, error) { return 0, nil }

// parseHTMLEntity is the Go equivalent of private byte c(byte[] var1, int var2, int var3)
// var1: data, var2: entityNameStartIdx, var3: entityNameEndIdxExclusive
// Returns (parsedByte, nil) on success, or (0, error) on failure.
func (e *ConfigurableBytePatternMatcher) parseHTMLEntity(
	data []byte,
	nameStartIndex int,
	nameEndIndex int,
) (byte, error) {
	nameLength := nameEndIndex - nameStartIndex
	entityCode := ""

	if nameLength > 0 && nameStartIndex <= len(data) &&
		nameEndIndex <= len(data) &&
		nameStartIndex < nameEndIndex {
		entityCode = utils.BytesToStringInRange(
			data,
			nameStartIndex,
			nameLength,
		)
	} else {
		return 0, errors.New("invalid entity name slice bounds")
	}

	if strings.HasPrefix(entityCode, "#") { // Numerical entity
		if len(entityCode) < 2 { // Catches "#", Java's Byte.parseByte("") would throw NFE
			// strconv.ParseInt("", 10, 8) also errors.
			err := errors.New("numeric entity too short: " + entityCode)
			return 0, err
		}

		// Check if it's hex
		if entityCode[1] == 'x' || entityCode[1] == 'X' {
			if len(
				entityCode,
			) < 3 { // Catches "#x" or "#X", Java's Byte.parseByte("", 16) would throw NFE
				err := errors.New("hex entity too short: " + entityCode)
				return 0, err
			}
			// Try to parse as hex
			numericValue, err := strconv.ParseInt(entityCode[2:], 16, 8)
			if err == nil {
				return byte(numericValue), nil
			}
			// If hex parsing fails
			return 0, fmt.Errorf("hex entity parsing error for '%s': %w", entityCode, err)
		} else {
			// Not hex, try to parse as decimal (already checked len(entityName) >= 2)
			numericValue, err := strconv.ParseInt(entityCode[1:], 10, 8)
			if err == nil {
				return byte(numericValue), nil
			}
			// If decimal parsing fails
			return 0, fmt.Errorf("decimal entity parsing error for '%s': %w", entityCode, err)
		}
	} else { // Named entity
		namedEntityValue, found := utils.HtmlEntitiesMap[strings.ToLower(entityCode)]
		if found {
			return byte(namedEntityValue), nil
		}
		return 0, errors.New("unknown named entity: " + entityCode)
	}
}

// Static helper for NumberFormatException, not directly ported as Go uses error returns.
// private static NumberFormatException b(NumberFormatException var0) {
//    return var0;
// }

// findMatchWithTransformations is the Go equivalent of the private Java method d(byte[] var1, int var2, int var3)
// var1: data, var2: initialCurrentIndex, var3: toIndex (exclusive for search boundary)
func (e *ConfigurableBytePatternMatcher) findMatchWithTransformations(
	data []byte,
	scanStartIndex int,
	scanEndIndex int,
) *ByteMatchPosition {
	currentPatternMatchOffset := 0
	currentMatchStartIndex := -1
	// unescapeThisChar is now determined per pattern character iteration

	scanIndex := scanStartIndex

	for {
		// Determine if unescaping should be attempted for the current state
		tryUnescapeCurrentDataChar := e.shouldUnescapeBackslash

		if scanIndex > scanEndIndex-len(e.searchPattern)+currentPatternMatchOffset {
			return nil
		}

		if currentMatchStartIndex < 0 {
			currentMatchStartIndex = scanIndex
		}

		var dataCharToCompare byte

		if e.shouldDecodeHTMLEntities {
			charState := e.decodeCharacterAndUpdateState(
				data,
				scanIndex,
				scanEndIndex,
				currentPatternMatchOffset,
			)
			if charState == nil {
				return nil
			}
			dataCharToCompare = charState.currentChar
			scanIndex = charState.currentIndex
		} else {
			if scanIndex >= len(data) {
				return nil
			}
			dataCharToCompare = data[scanIndex]
			scanIndex = scanIndex + 1
		}

		if tryUnescapeCurrentDataChar && dataCharToCompare == 92 &&
			currentPatternMatchOffset < len(e.searchPattern) &&
			e.isQuoteCharacter(e.searchPattern[currentPatternMatchOffset]) {

			for lookaheadIndex := 0; lookaheadIndex < 7; lookaheadIndex++ {
				if scanIndex+lookaheadIndex >= scanEndIndex-len(
					e.searchPattern,
				)+currentPatternMatchOffset+1 {
					return nil
				}

				lookaheadCharState := e.decodeCharacterAndUpdateState(
					data,
					scanIndex+lookaheadIndex, // Start scan from char after backslash + lookahead
					scanEndIndex,
					currentPatternMatchOffset,
				)
				if lookaheadCharState == nil {
					return nil
				}

				decodedLookaheadChar := lookaheadCharState.currentChar

				if e.isQuoteCharacter(decodedLookaheadChar) {
					dataCharToCompare = decodedLookaheadChar
					scanIndex = lookaheadCharState.currentIndex
					// tryUnescapeCurrentDataChar is no longer needed after break
					break
				}

				if decodedLookaheadChar != 92 { // If not a quote AND not another backslash
					break // Break from inner unescape for-loop
				}
			}
		}

		// Character matching logic
		isCurrentCharMatch := false
		if currentPatternMatchOffset < len(e.searchPattern) &&
			utils.ToLowerByte(
				dataCharToCompare,
			) == utils.ToLowerByte(
				e.searchPattern[currentPatternMatchOffset],
			) {
			currentPatternMatchOffset++
			isCurrentCharMatch = true
			// If matched, and hpo.b() was 0 (n5==0), Java skips the reset logic (breaks to block26).
			// So, we do nothing here regarding reset, proceed to check full match.
		}

		if !isCurrentCharMatch { // If NO match this iteration (Java block25 logic)
			if currentMatchStartIndex >= 0 {
				scanIndex = currentMatchStartIndex + 1
			}
			currentPatternMatchOffset = 0
			currentMatchStartIndex = -1
		}

		// Check for full pattern match (Java block26 logic after match or after reset)
		if currentPatternMatchOffset == len(e.searchPattern) {
			return NewByteMatchPosition(currentMatchStartIndex, scanIndex)
		}
	}

}
