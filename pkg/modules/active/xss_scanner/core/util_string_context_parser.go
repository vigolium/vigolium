package core

import (
	"bytes" // For bytes.Buffer in ncRInternal_HTMLDecodeEntities
	"fmt"
	"strconv" // For strconv.ParseInt in ncRInternal_HTMLDecodeEntities
	"strings" // For string manipulation

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/utils"
)

// ExtractedStringSegment represents an extracted string segment and its starting position,
// corresponding to the Java 'fdl' class.
type ExtractedStringSegment struct {
	Content    string // The content of the string literal (without quotes)
	StartIndex int    // The starting index of the content in the original string
}

// Constants for segment types, mirroring the byte values used in Java's 'var6'.
const (
	segmentTypeDoubleQuote  byte = 0 // "..."
	segmentTypeSingleQuote  byte = 1 // '...'
	segmentTypeNone         byte = 2 // Default state or outside known segments
	segmentTypeLineComment  byte = 3 // //...
	segmentTypeBlockComment byte = 4 // /*...*/
)

// ExtractQuotedStringSegments corresponds to Java: public static List<fdl> a(String var0, int var1, int var2)
// It parses the string 's' from 'startIdx' (inclusive) to 'exclusiveEndIdx' (exclusive).
// Its primary function is to extract the content of single and double-quoted strings.
// Obfuscation related to 'v2.c()' (simulated by V2cValue previously) has been removed,
// and the code now follows the primary functional path.
func ExtractQuotedStringSegments(
	Source string,
	startIndex, endIndexExclusive int,
) ([]ExtractedStringSegment, error) {
	if startIndex < 0 || endIndexExclusive > len(Source) || startIndex > endIndexExclusive {
		return nil, fmt.Errorf(
			"invalid start/end indices: start=%d, end=%d, len=%d",
			startIndex,
			endIndexExclusive,
			len(Source),
		)
	}

	segments := []ExtractedStringSegment{}
	currentIndex := startIndex // Current parsing position

mainLoop: // Label retained for clarity of original structure, though not strictly necessary with removed obfuscation paths
	for currentIndex < endIndexExclusive {
		currentChar := rune(Source[currentIndex])
		currentSegmentType := segmentTypeNone
		isOpenerFound := true

		// Part 1: Identify the start of a segment.
		if currentChar == '\'' {
			currentSegmentType = segmentTypeSingleQuote
		} else if currentChar == '"' {
			currentSegmentType = segmentTypeDoubleQuote
		} else if currentChar == '/' && currentIndex+1 < endIndexExclusive {
			switch Source[currentIndex+1] {
			case '/':
				currentSegmentType = segmentTypeLineComment
			case '*':
				currentSegmentType = segmentTypeBlockComment
			default:
				isOpenerFound = false
			}
		} else {
			isOpenerFound = false
		}

		if !isOpenerFound {
			currentIndex++
			continue mainLoop
		}

		// Determine the starting index of the segment's content.
		// Java: 'int var12 = ++var5;' where var5 was index of opener.
		// Here, 'i' is already at the opener. segmentContentStartIndex will be after the opener.
		segmentContentStartIndex := currentIndex + 1
		if currentSegmentType == segmentTypeLineComment || currentSegmentType == segmentTypeBlockComment {
			segmentContentStartIndex = currentIndex + 2 // Content starts after "//" or "/*".
		}

		// Advance 'i' to the start of the content for the next scanning phase.
		currentIndex = segmentContentStartIndex

		// Part 2: Scan for the end of the identified segment.
		isSegmentEndFound := false
		segmentClosingDelimiterIndex := currentIndex // Will point to the closing delimiter character(s)

		switch currentSegmentType {
		case segmentTypeSingleQuote, segmentTypeDoubleQuote:
			currentQuoteChar := '\''
			if currentSegmentType == segmentTypeDoubleQuote {
				currentQuoteChar = '"'
			}

			innerScanIndex := currentIndex // Use a temporary scanner index for the content
			for innerScanIndex < endIndexExclusive {
				if Source[innerScanIndex] == '\\' { // Handle escape character.
					innerScanIndex += 2 // Skip '\' and the escaped character.
					continue
				}
				if rune(Source[innerScanIndex]) == currentQuoteChar {
					isSegmentEndFound = true
					segmentClosingDelimiterIndex = innerScanIndex // Index of the closing quote
					break
				}
				innerScanIndex++
			}
			// innerScanIndex is used to update currentIndex below based on whether segment end was found

			if isSegmentEndFound {
				// Extracted content is s[contentStartIndex : segmentEndScannerIndex]
				segments = append(segments, ExtractedStringSegment{
					Content:    Source[segmentContentStartIndex:segmentClosingDelimiterIndex],
					StartIndex: segmentContentStartIndex,
				})
				currentIndex = segmentClosingDelimiterIndex + 1 // Move 'i' past the closing quote.
			} else {
				// Unterminated string.
				break mainLoop // Stop parsing, as original Java code would.
			}

		case segmentTypeLineComment:
			// Find newline or end of string
			newlineCharacterIndex := -1
			if idx := strings.IndexAny(Source[currentIndex:], "\n\r"); idx != -1 {
				newlineCharacterIndex = currentIndex + idx
			}

			if newlineCharacterIndex != -1 && newlineCharacterIndex < endIndexExclusive {
				// segmentEndFound = true // Not strictly needed as we don't add Fdl for comments
				currentIndex = newlineCharacterIndex + 1 // Move past newline
			} else {
				// Comment goes to the end of the analyzed range
				currentIndex = endIndexExclusive
			}
			// Line comments are not added to results in the original Java logic for Fdl.

		case segmentTypeBlockComment:
			// Find "*/"
			blockCommentEndIndex := -1
			if idx := strings.Index(Source[currentIndex:], "*/"); idx != -1 {
				blockCommentEndIndex = currentIndex + idx
			}

			if blockCommentEndIndex != -1 && blockCommentEndIndex+1 < endIndexExclusive { // "*/" is 2 chars
				// segmentEndFound = true // Not strictly needed
				currentIndex = blockCommentEndIndex + 2 // Move past "*/"
			} else {
				// Unterminated block comment.
				break mainLoop // Stop parsing.
			}
			// Block comments are not added to results in the original Java logic for Fdl.
		} // End switch identifiedSegmentType
	} // End mainLoop

	return segments, nil
}

// --- Byte-oriented functions ---

// decodeHTMLEntitiesInBytes decodes HTML entities in a byte slice.
// This function decodes HTML entities in a byte slice.
// Obfuscation related to nc.b() (simulated by ncStaticBValue previously) has been removed
// by assuming the functional path where its conditional breaks are not taken.
func decodeHTMLEntitiesInBytes(data []byte) []byte {
	// The original Java code's `String var1 = b();` (where b() returns a static string)
	// was used to control obfuscated `break` statements.
	// This implementation assumes the functional path where those breaks are not taken.

	if len(data) == 0 {
		return data
	}

	changed := false
	outputBuffer := new(bytes.Buffer)
	outputBuffer.Grow(len(data)) // Pre-allocate for efficiency
	currentIndex := 0

	for currentIndex < len(data) {
		currentByte := data[currentIndex]

		if currentByte == '&' {
			semicolonIndex := utils.IndexOfByteCS(
				data,
				';',
				currentIndex+1,
				len(data),
			)

			if semicolonIndex != -1 {
				entityNameLength := semicolonIndex - (currentIndex + 1)
				if entityNameLength < 0 {
					entityNameLength = 0
				}
				entityName := utils.BytesToStringInRange(
					data,
					currentIndex+1,
					entityNameLength,
				)

				decodedByte := byte(0)
				entityDecoded := false

				if strings.HasPrefix(entityName, "#") { // Numeric entity
					var numStr string
					base := 10
					if len(entityName) > 1 &&
						(strings.ToLower(entityName[1:2]) == "x") { // Check for #x or #X
						if len(entityName) > 2 {
							numStr = entityName[2:]
							base = 16
						} else {
							numStr = ""
						} // Invalid: "#x"
					} else if len(entityName) > 1 {
						numStr = entityName[1:]
						base = 10
					} else {
						numStr = ""
					} // Invalid: "#"

					if numStr != "" {
						parsedVal, err := strconv.ParseInt(
							numStr,
							base,
							16,
						) // Parse as short (byte in Java)
						if err == nil {
							decodedByte = byte(parsedVal)
							entityDecoded = true
						}
						// Original Java logs NumberFormatException, ignored here for simplicity.
					}
				} else { // Named entity
					if charVal, ok := utils.HtmlEntitiesMap[strings.ToLower(entityName)]; ok {
						decodedByte = byte(charVal) // Truncate rune to byte
						entityDecoded = true
					}
				}

				if entityDecoded {
					outputBuffer.WriteByte(decodedByte)
					changed = true
					currentIndex = semicolonIndex + 1
					continue // Continue the main loop
				}
			}
		}
		outputBuffer.WriteByte(currentByte)
		currentIndex++
	}

	if changed {
		return outputBuffer.Bytes()
	}
	return data
}

// determineByteContextAtEnd corresponds to Java: private static byte a(byte[] var0, int var1, int var2)
// This function determines the lexical context at the end of the given byte slice.
// This function did not show signs of heavy obfuscation like the string parser.
func determineByteContextAtEnd(data []byte, startIndex, endIndexExclusive int) byte {
	if startIndex < 0 || endIndexExclusive > len(data) || startIndex > endIndexExclusive {
		return segmentTypeNone
	}

	currentContext := segmentTypeNone
	i := startIndex

	for i < endIndexExclusive {
		charByte := data[i]
		segmentOpenerType := segmentTypeNone
		openerLength := 1

		if charByte == '\'' {
			segmentOpenerType = segmentTypeSingleQuote
		} else if charByte == '"' {
			segmentOpenerType = segmentTypeDoubleQuote
		} else if charByte == '/' && i+1 < endIndexExclusive {
			switch data[i+1] {
			case '/':
				segmentOpenerType = segmentTypeLineComment
				openerLength = 2
			case '*':
				segmentOpenerType = segmentTypeBlockComment
				openerLength = 2
			}
		}

		if segmentOpenerType != segmentTypeNone {
			currentContext = segmentOpenerType
			i += openerLength
			segmentEndFound := false

			// Scan for the end of the current segment
			for i < endIndexExclusive {
				scanChar := data[i]
				isEscapedChar := false

				// Handle escape characters within string literals
				if currentContext == segmentTypeSingleQuote ||
					currentContext == segmentTypeDoubleQuote {
					if scanChar == '\\' {
						i += 2 // Skip '\' and the escaped character
						if i > endIndexExclusive {
							i = endIndexExclusive
						} // Adjust if overshoot
						isEscapedChar = true
						if isEscapedChar {
							continue
						} // Continue inner scan loop
					}
				}
				if isEscapedChar && i >= endIndexExclusive {
					break
				} // Break if escape caused out of bounds

				// Check for segment closing conditions
				segmentClosed := false
				switch currentContext {
				case segmentTypeSingleQuote:
					if scanChar == '\'' {
						segmentClosed = true
					}
				case segmentTypeDoubleQuote:
					if scanChar == '"' {
						segmentClosed = true
					}
				case segmentTypeLineComment:
					if scanChar == '\n' || scanChar == '\r' {
						segmentClosed = true
					}
				case segmentTypeBlockComment:
					if i+1 < endIndexExclusive && scanChar == '*' && data[i+1] == '/' {
						segmentClosed = true
					}
				}

				if segmentClosed {
					segmentEndFound = true
					if currentContext == segmentTypeBlockComment {
						i += 2 // Move past "*/"
					} else {
						i += 1 // Move past closing quote or newline
					}
					currentContext = segmentTypeNone // Exited the segment
					break                            // Break from inner scan loop
				}

				if !isEscapedChar { // Only advance if not an escape that already advanced 'i'
					i++
				}
			}

			if !segmentEndFound {
				// Reached end of data while still inside an unclosed segment
				return currentContext
			}
			// If segment was closed, currentContext is SegmentTypeNone.
			// The outer loop will continue from the new 'i'.
		} else { // Character at data[i] is not an opener for any known segment.
			i++
			currentContext = segmentTypeNone // We are in "no specific context" or between segments.
		}
	}
	return currentContext // Context at the very end of iteration
}

// GetByteContextAfterDecoding corresponds to Java: public static byte b(byte[] var0, int var1, int var2)
// Original Java parameters: var0 (byte[]), var1 (start index), var2 (end index).
// The Java code `if (var2 >= var1 && var1 >= 0)` suggests var1 and var2 are inclusive indices.
func GetByteContextAfterDecoding(data []byte, startIndex, endIndex int) byte {
	if endIndex < startIndex || startIndex < 0 {
		return segmentTypeNone // Invalid range based on original Java check
	}

	// Handle empty data array and adjust endIdxInclusive if out of bounds
	if len(data) == 0 {
		// For empty data, only (0,0) or (0,-1) are usually valid for an "empty slice" intention.
		if startIndex != 0 || endIndex < -1 || endIndex > 0 {
			return segmentTypeNone
		}
	} else { // Non-empty data
		// Cap endIdxInclusive to actual data bounds
		if endIndex >= len(data) {
			endIndex = len(data) - 1
		}
		// After capping, check if range is still valid
		if startIndex > endIndex || startIndex >= len(data) {
			return segmentTypeNone
		}
	}

	// For CopyOfRange, end is exclusive.
	exclusiveEndIndexForSlice := endIndex + 1

	dataSegment := utils.CopyOfRange(data, startIndex, exclusiveEndIndexForSlice)

	if dataSegment == nil {
		// CopyOfRange returns nil for invalid ranges.
		// analyzeByteContextInternal can handle an empty slice.
		dataSegment = []byte{}
	}

	// Call the HTML entity decoder
	decodedSegmentBytes := decodeHTMLEntitiesInBytes(dataSegment)

	// Analyze the context of the (potentially decoded) bytes
	return determineByteContextAtEnd(decodedSegmentBytes, 0, len(decodedSegmentBytes))
}
