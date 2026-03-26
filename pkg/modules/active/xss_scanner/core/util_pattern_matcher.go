package core

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

/* -------------------------------------------------------------------------- */
type ByteSequenceMatcher interface {
	FindMatch(data []byte, startIndex int, endIndex int) *ByteMatchPosition
}

// ByteMatchPosition holds the start and end indices of a matched byte pattern.
type ByteMatchPosition struct {
	MatchStartIndex int
	MatchEndIndex   int
}

// NewByteMatchPosition creates a new instance.
func NewByteMatchPosition(startIndex int, endIndex int) *ByteMatchPosition {
	return &ByteMatchPosition{
		MatchStartIndex: startIndex,
		MatchEndIndex:   endIndex,
	}
}

/* -------------------------------------------------------------------------- */

// ConfigurableBytePatternMatcher implements the ByteSequenceMatcher interface for pattern matching.
type ConfigurableBytePatternMatcher struct {
	searchPattern            []byte
	shouldUnescapeBackslash  bool
	shouldDecodeHTMLEntities bool
}

// NewConfigurableBytePatternMatcher creates a new ConfigurableBytePatternMatcher.
func NewConfigurableBytePatternMatcher(
	pattern []byte,
	unescapeBackslash bool,
	decodeHTMLEntities bool,
) *ConfigurableBytePatternMatcher {
	// In Go, a nil slice is often preferred over an empty slice if it represents "no value" or "not applicable".
	// So, we directly assign the pattern. If it's nil, len(nil) is 0.
	return &ConfigurableBytePatternMatcher{
		searchPattern:            pattern,
		shouldUnescapeBackslash:  unescapeBackslash,
		shouldDecodeHTMLEntities: decodeHTMLEntities,
	}
}

// --- Static Factory Methods --- //

func NewSimpleBytePatternMatcher(pattern []byte) *ConfigurableBytePatternMatcher {
	return NewConfigurableBytePatternMatcher(pattern, false, false)
}

func NewHtmlDecodingBytePatternMatcher(pattern []byte) *ConfigurableBytePatternMatcher {
	return NewConfigurableBytePatternMatcher(pattern, false, true)
}

func NewUnescapingHtmlDecodingBytePatternMatcher(pattern []byte) *ConfigurableBytePatternMatcher {
	return NewConfigurableBytePatternMatcher(pattern, true, true)
}

func NewUnescapingBytePatternMatcher(pattern []byte) *ConfigurableBytePatternMatcher {
	return NewConfigurableBytePatternMatcher(pattern, true, false)
}

// --- Interface Methods and Private Helpers --- //

// FindMatch searches for the pattern in the given data range.
func (e *ConfigurableBytePatternMatcher) FindMatch(
	data []byte,
	startIndex int,
	endIndex int,
) *ByteMatchPosition {
	// Note: len(nil slice) is 0 in Go.
	if len(e.searchPattern) != 0 && startIndex < len(data) {
		directMatch := e.findMatchWithTransformations(data, startIndex, endIndex)
		if directMatch != nil {
			return directMatch
		} else {
			if !e.shouldDecodeHTMLEntities && !e.shouldUnescapeBackslash {
				return nil
			}
			return e.findDirectMatch(data, startIndex, endIndex)
		}
	} else {
		return nil
	}
}

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

	if foundAtIndex < 0 {
		return nil
	}
	return NewByteMatchPosition(
		foundAtIndex,
		foundAtIndex+len(e.searchPattern),
	)
}

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
	processedCharByte := data[scanIndex]
	scanIndex++

	if e.shouldDecodeHTMLEntities && processedCharByte == 38 {
		semicolonPos := utils.IndexOfByteCS(
			data,
			59,
			scanIndex+1,
			len(data),
		)

		if semicolonPos > -1 {
			decodedEntityChar, err := e.parseHTMLEntity(data, scanIndex, semicolonPos)
			if err == nil {
				processedCharByte = decodedEntityChar
				scanIndex = semicolonPos + 1

				if scanIndex > scanEndIndex-len(e.searchPattern)+currentPatternOffset+1 {
					return nil
				}
			}
		}
	}
	return NewPatternMatchState(scanIndex, processedCharByte, nil) // g0c is nil
}

func (e *ConfigurableBytePatternMatcher) isQuoteCharacter(char byte) bool {
	return char == charSingleQuote || char == charDoubleQuote || char == charBacktick
}

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
		if len(entityCode) < 2 {
			// strconv.ParseInt("", 10, 8) also errors.
			err := errors.New("numeric entity too short: " + entityCode)
			return 0, err
		}

		// Check if it's hex
		if entityCode[1] == 'x' || entityCode[1] == 'X' {
			if len(
				entityCode,
			) < 3 {
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

		if tryUnescapeCurrentDataChar && dataCharToCompare == charBackslash &&
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
			// So, we do nothing here regarding reset, proceed to check full match.
		}

		if !isCurrentCharMatch {
			if currentMatchStartIndex >= 0 {
				scanIndex = currentMatchStartIndex + 1
			}
			currentPatternMatchOffset = 0
			currentMatchStartIndex = -1
		}

		if currentPatternMatchOffset == len(e.searchPattern) {
			return NewByteMatchPosition(currentMatchStartIndex, scanIndex)
		}
	}

}
