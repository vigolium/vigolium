package httpmsg

// encoder.go - Encoder interface and all implementations
// Consolidated from: encoder.go, encoder_noop.go, encoder_json_string.go,
//                    encoder_json_escape.go, encoder_url.go, encoder_url_extended.go,
//                    encoder_base64.go, encoder_gzip.go

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
)

// =============================================================================
// Interface
// =============================================================================

// Encoder defines the interface for encoding payloads at insertion points.
// Ported from: burp/egp.java
type Encoder interface {
	// Encode encodes the payload and adjusts offset positions.
	// payload: the bytes to encode
	// offsets: [startOffset, endOffset] pair that will be updated to reflect encoded positions
	// Returns: encoded bytes
	Encode(payload []byte, offsets []int) []byte

	// Decode reverses the encoding to recover original payload.
	// encoded: the encoded bytes
	// Returns: decoded bytes
	Decode(encoded []byte) []byte
}

// Encoder type constants
const (
	EncoderNoop       = iota // Passthrough encoder (no encoding) - burp/czx.java
	EncoderJSONString        // Escapes only double quotes for JSON string values - burp/d1z.java
	EncoderJSONEscape        // Full JSON escaping including control characters - burp/ct7.java
)

// GetEncoder returns an encoder instance for the specified type.
func GetEncoder(encoderType int) Encoder {
	switch encoderType {
	case EncoderNoop:
		return &NoopEncoder{}
	case EncoderJSONString:
		return &JSONStringEncoder{}
	case EncoderJSONEscape:
		return &JSONEscapeEncoder{}
	default:
		return &NoopEncoder{}
	}
}

// =============================================================================
// NoopEncoder - Passthrough encoder
// =============================================================================

// NoopEncoder is a passthrough encoder that returns payloads unchanged.
// Ported from: burp/czx.java
type NoopEncoder struct{}

// Encode returns the payload unchanged.
func (e *NoopEncoder) Encode(payload []byte, offsets []int) []byte {
	return payload
}

// Decode returns the encoded payload unchanged.
func (e *NoopEncoder) Decode(encoded []byte) []byte {
	return encoded
}

// =============================================================================
// JSONStringEncoder - Quote escaping only
// =============================================================================

// JSONStringEncoder escapes double quotes for JSON string values.
// Only handles: " → \"
// Ported from: burp/d1z.java
type JSONStringEncoder struct{}

// Encode escapes double quotes and tracks offset positions.
func (e *JSONStringEncoder) Encode(payload []byte, offsets []int) []byte {
	var buf bytes.Buffer
	updatedOffsets := []int{offsets[0], offsets[1]}

	for i := 0; i < len(payload); i++ {
		e.updateOffsets(offsets, updatedOffsets, buf.Len(), i)
		b := payload[i]

		// Escape double quotes: " → \"
		if b == 34 { // ASCII 34 = "
			buf.WriteByte(92) // ASCII 92 = \
		}
		buf.WriteByte(b)
	}

	e.updateOffsets(offsets, updatedOffsets, buf.Len(), len(payload))
	offsets[0] = updatedOffsets[0]
	offsets[1] = updatedOffsets[1]

	return buf.Bytes()
}

func (e *JSONStringEncoder) updateOffsets(originalOffsets, updatedOffsets []int, bufferSize, inputPos int) {
	if inputPos == originalOffsets[0] {
		updatedOffsets[0] = bufferSize
	}
	if inputPos == originalOffsets[1] {
		updatedOffsets[1] = bufferSize
	}
}

// Decode reverses quote escaping: \" → "
func (e *JSONStringEncoder) Decode(encoded []byte) []byte {
	var buf bytes.Buffer

	for i := 0; i < len(encoded); i++ {
		b := encoded[i]

		// If backslash followed by quote, skip backslash
		if b == 92 && i < len(encoded)-1 && encoded[i+1] == 34 {
			i++
			b = 34
		}
		buf.WriteByte(b)
	}

	return buf.Bytes()
}

// =============================================================================
// JSONEscapeEncoder - Full JSON escaping
// =============================================================================

// JSONEscapeEncoder performs full JSON escaping including all control characters.
// Handles: " → \", / → \/, \ → \\, plus \n, \r, \t, \b, \f, and \u00xx for non-printable
// Ported from: burp/ct7.java
type JSONEscapeEncoder struct{}

// Encode performs full JSON escaping and tracks offset positions.
func (e *JSONEscapeEncoder) Encode(payload []byte, offsets []int) []byte {
	var buf bytes.Buffer
	updatedOffsets := []int{offsets[0], offsets[1]}

	for i := 0; i < len(payload); i++ {
		e.updateOffsets(offsets, updatedOffsets, buf.Len(), i)
		b := payload[i]

		switch b {
		case 34, 47, 92: // ", /, \
			buf.WriteByte(92) // \
			buf.WriteByte(b)
		case 8: // \b
			buf.WriteByte(92)
			buf.WriteByte(98)
		case 12: // \f
			buf.WriteByte(92)
			buf.WriteByte(102)
		case 10: // \n
			buf.WriteByte(92)
			buf.WriteByte(110)
		case 13: // \r
			buf.WriteByte(92)
			buf.WriteByte(114)
		case 9: // \t
			buf.WriteByte(92)
			buf.WriteByte(116)
		default:
			if b < 32 || b > 127 {
				// Non-printable or non-ASCII: encode as \u00xx
				unicodeStr := fmt.Sprintf("\\u00%02x", b)
				buf.WriteString(unicodeStr)
			} else {
				buf.WriteByte(b)
			}
		}
	}

	e.updateOffsets(offsets, updatedOffsets, buf.Len(), len(payload))
	offsets[0] = updatedOffsets[0]
	offsets[1] = updatedOffsets[1]

	return buf.Bytes()
}

func (e *JSONEscapeEncoder) updateOffsets(originalOffsets, updatedOffsets []int, bufferSize, inputPos int) {
	if inputPos == originalOffsets[0] {
		updatedOffsets[0] = bufferSize
	}
	if inputPos == originalOffsets[1] {
		updatedOffsets[1] = bufferSize
	}
}

// Decode reverses full JSON escaping.
func (e *JSONEscapeEncoder) Decode(encoded []byte) []byte {
	var buf bytes.Buffer

	for i := 0; i < len(encoded); i++ {
		b := encoded[i]

		if b == 92 { // \
			i++
			if i < len(encoded) {
				b = encoded[i]
			}

			switch b {
			case 34, 47, 92: // ", /, \
				buf.WriteByte(b)
			case 98: // b
				buf.WriteByte(8) // \b
			case 102: // f
				buf.WriteByte(12) // \f
			case 110: // n
				buf.WriteByte(10) // \n
			case 114: // r
				buf.WriteByte(13) // \r
			case 116: // t
				buf.WriteByte(9) // \t
			case 117: // u (unicode escape)
				if i+4 < len(encoded) {
					// Parse \u00xx format - skip "00" prefix
					i += 3
					hexStr := string(encoded[i : i+2])
					if val, err := strconv.ParseInt(hexStr, 16, 32); err == nil {
						buf.WriteByte(byte(val & 0xFF))
					}
					i++
				} else {
					i--
					buf.Write(encoded[i:])
					i = len(encoded)
				}
			default:
				buf.WriteByte(b)
			}
		} else {
			buf.WriteByte(b)
		}
	}

	return buf.Bytes()
}

// =============================================================================
// URLEncoder - URL percent-encoding with custom charset
// =============================================================================

// hexChars is the lookup table for hex digit encoding (UPPERCASE)
var hexChars = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}

// URLEncoder implements URL percent-encoding with custom charset support.
// Ported from: burp/b_2.java
type URLEncoder struct {
	allowedChars map[byte]bool
}

// NewURLEncoder creates a new URL encoder instance.
func NewURLEncoder() *URLEncoder {
	return &URLEncoder{
		allowedChars: make(map[byte]bool),
	}
}

// Encode performs URL encoding with offset tracking.
func (e *URLEncoder) Encode(input []byte, offsets []int) []byte {
	if len(input) == 0 {
		return input
	}

	if len(offsets) < 2 {
		offsets = []int{0, 0}
	}

	var output bytes.Buffer
	tempOffsets := []int{offsets[0], offsets[1]}

	for i := 0; i < len(input); i++ {
		updateOffsets(offsets, tempOffsets, output.Len(), i)
		b := input[i]

		// Check if byte is in custom allowed set
		if e.allowedChars[b] {
			output.WriteByte(b)
			continue
		}

		// Check special characters that should be encoded
		switch b {
		case ' ', '"', '#', '%', '&', '+', ',', '/', ':', ';', '<', '=', '>', '?', '\\', '^', '`', '{', '|', '}':
			percentEncode(&output, b)
			continue
		}

		// Check if byte is non-printable
		if isNonPrintable(b) {
			percentEncode(&output, b)
			continue
		}

		output.WriteByte(b)
	}

	updateOffsets(offsets, tempOffsets, output.Len(), len(input))
	offsets[0] = tempOffsets[0]
	offsets[1] = tempOffsets[1]

	return output.Bytes()
}

// Decode performs URL decoding.
func (e *URLEncoder) Decode(input []byte) []byte {
	decoded, _ := UrlDecodeBytes(input)
	return decoded
}

// AddAllowedChar adds a character to the allowed set (won't be encoded).
func (e *URLEncoder) AddAllowedChar(c byte) {
	e.allowedChars[c] = true
}

// RemoveAllowedChar removes a character from the allowed set.
func (e *URLEncoder) RemoveAllowedChar(c byte) {
	delete(e.allowedChars, c)
}

// updateOffsets updates offset positions during encoding.
func updateOffsets(originalOffsets []int, tempOffsets []int, currentOutputSize int, currentInputPos int) {
	if currentInputPos == originalOffsets[0] {
		tempOffsets[0] = currentOutputSize
	}
	if currentInputPos == originalOffsets[1] {
		tempOffsets[1] = currentOutputSize
	}
}

// isNonPrintable checks if a byte is non-printable (< 32 or >= 127).
func isNonPrintable(b byte) bool {
	return b < 32 || b >= 127
}

// percentEncode writes a byte as percent-encoded %XX format.
func percentEncode(output *bytes.Buffer, b byte) {
	output.WriteByte('%')
	val := uint8(b)
	output.WriteByte(hexChars[val/16])
	output.WriteByte(hexChars[val%16])
}

// =============================================================================
// URLEncoderExtended - URL encoding with character substitution
// =============================================================================

// URLEncoderExtended implements URL encoding with character substitution.
// Ported from: burp/euc.java
type URLEncoderExtended struct {
	charMap map[byte][]byte
}

// NewURLEncoderExtended creates a new extended URL encoder instance.
func NewURLEncoderExtended() *URLEncoderExtended {
	return &URLEncoderExtended{
		charMap: make(map[byte][]byte),
	}
}

// Encode performs URL encoding with character substitution.
func (e *URLEncoderExtended) Encode(input []byte, offsets []int) []byte {
	if len(input) == 0 {
		return input
	}

	if len(offsets) < 2 {
		offsets = []int{0, 0}
	}

	var output bytes.Buffer
	tempOffsets := []int{offsets[0], offsets[1]}

	for i := 0; i < len(input); i++ {
		e.updateOffsetsExt(offsets, tempOffsets, output.Len(), i)
		b := input[i]

		// Check special characters that should be encoded
		switch b {
		case ' ', '"', '#', '%', '&', '+', ',', ':', ';', '<', '=', '>', '?', '\\', '^', '`', '{', '|', '}':
			e.percentEncodeExt(&output, b)
			continue
		}

		// Look up byte in substitution map
		replacement, found := e.charMap[b]

		if !found {
			if isNonPrintable(b) {
				e.percentEncodeExt(&output, b)
				continue
			}
			output.WriteByte(b)
			continue
		}

		output.Write(replacement)
	}

	e.updateOffsetsExt(offsets, tempOffsets, output.Len(), len(input))
	offsets[0] = tempOffsets[0]
	offsets[1] = tempOffsets[1]

	return output.Bytes()
}

// Decode performs URL decoding.
func (e *URLEncoderExtended) Decode(input []byte) []byte {
	decoded, _ := UrlDecodeBytes(input)
	return decoded
}

// SetCharMapping sets a character substitution in the map.
func (e *URLEncoderExtended) SetCharMapping(char byte, replacement []byte) {
	e.charMap[char] = replacement
}

// RemoveCharMapping removes a character substitution from the map.
func (e *URLEncoderExtended) RemoveCharMapping(char byte) {
	delete(e.charMap, char)
}

// ClearCharMappings removes all character substitutions.
func (e *URLEncoderExtended) ClearCharMappings() {
	e.charMap = make(map[byte][]byte)
}

func (e *URLEncoderExtended) updateOffsetsExt(originalOffsets []int, tempOffsets []int, currentOutputSize int, currentInputPos int) {
	if currentInputPos == originalOffsets[0] {
		tempOffsets[0] = currentOutputSize
	}
	if currentInputPos == originalOffsets[1] {
		tempOffsets[1] = currentOutputSize
	}
}

func (e *URLEncoderExtended) percentEncodeExt(output *bytes.Buffer, b byte) {
	output.WriteByte('%')
	val := uint8(b)
	output.WriteByte(hexChars[val/16])
	output.WriteByte(hexChars[val%16])
}

// =============================================================================
// Base64Encoder - Base64 encoding with offset tracking
// =============================================================================

// Base64Encoder implements standard Base64 encoding with offset tracking.
// Ported from: burp/fo3.java (standard mode), burp/d7a.java (MIME mode)
type Base64Encoder struct {
	mimeMode bool
}

// NewBase64Encoder creates a new Base64 encoder in standard mode.
func NewBase64Encoder() *Base64Encoder {
	return &Base64Encoder{mimeMode: false}
}

// NewBase64MIMEEncoder creates a new Base64 encoder in MIME mode (76-char line breaks).
func NewBase64MIMEEncoder() *Base64Encoder {
	return &Base64Encoder{mimeMode: true}
}

// Encode performs Base64 encoding with offset tracking.
func (e *Base64Encoder) Encode(input []byte, offsets []int) []byte {
	if len(input) == 0 {
		return input
	}

	if len(offsets) < 2 {
		offsets = []int{0, 0}
	}

	origStart := offsets[0]
	origEnd := offsets[1]

	var encoded string
	if e.mimeMode {
		encoded = base64.StdEncoding.EncodeToString(input)
		encoded = addMIMELineBreaks(encoded)
	} else {
		encoded = base64.StdEncoding.EncodeToString(input)
	}

	// Track offsets proportionally
	inputLen := len(input)
	outputLen := len(encoded)

	if inputLen > 0 {
		if origStart > 0 {
			offsets[0] = (origStart * outputLen) / inputLen
		} else {
			offsets[0] = 0
		}

		if origEnd > 0 {
			offsets[1] = (origEnd * outputLen) / inputLen
		} else {
			offsets[1] = outputLen
		}
	}

	return []byte(encoded)
}

// Decode performs Base64 decoding.
func (e *Base64Encoder) Decode(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	cleaned := removeNonBase64(input)
	decoded, err := base64.StdEncoding.DecodeString(string(cleaned))
	if err != nil {
		return input
	}
	return decoded
}

func addMIMELineBreaks(input string) string {
	if len(input) <= 76 {
		return input
	}

	var result bytes.Buffer
	for i := 0; i < len(input); i += 76 {
		end := i + 76
		if end > len(input) {
			end = len(input)
		}
		result.WriteString(input[i:end])
		if end < len(input) {
			result.WriteByte('\n')
		}
	}
	return result.String()
}

func removeNonBase64(input []byte) []byte {
	var cleaned bytes.Buffer
	for _, b := range input {
		if isValidBase64Char(b) {
			cleaned.WriteByte(b)
		}
	}
	return cleaned.Bytes()
}

func isValidBase64Char(b byte) bool {
	if b >= 'A' && b <= 'Z' {
		return true
	}
	if b >= 'a' && b <= 'z' {
		return true
	}
	if b >= '0' && b <= '9' {
		return true
	}
	if b == '+' || b == '/' || b == '=' {
		return true
	}
	return false
}

// =============================================================================
// GzipEncoder - Gzip compression encoder
// =============================================================================

// GzipEncoder implements Gzip compression with offset tracking.
// Ported from: burp/dx7.java
type GzipEncoder struct{}

// NewGzipEncoder creates a new Gzip encoder instance.
func NewGzipEncoder() *GzipEncoder {
	return &GzipEncoder{}
}

// Encode performs Gzip compression with offset tracking.
func (e *GzipEncoder) Encode(input []byte, offsets []int) []byte {
	if input == nil {
		return nil
	}

	if len(offsets) < 2 {
		offsets = []int{0, 0}
	}

	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)

	_, err := gzipWriter.Write(input)
	if err != nil {
		return input
	}

	err = gzipWriter.Close()
	if err != nil {
		return input
	}

	compressed := output.Bytes()

	// Reset offsets for compressed data (opaque)
	offsets[0] = 0
	offsets[1] = len(compressed)

	return compressed
}

// Decode performs Gzip decompression.
func (e *GzipEncoder) Decode(input []byte) []byte {
	if input == nil {
		return nil
	}

	reader := bytes.NewReader(input)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return input
	}
	defer func() { _ = gzipReader.Close() }()

	var output bytes.Buffer
	buffer := make([]byte, 4096)

	for {
		n, err := gzipReader.Read(buffer)
		if n > 0 {
			output.Write(buffer[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if output.Len() > 0 {
				return output.Bytes()
			}
			return input
		}
	}

	return output.Bytes()
}

// =============================================================================
// Convenience functions
// =============================================================================

// CompressBytes is a convenience function for simple gzip compression.
func CompressBytes(input []byte) []byte {
	encoder := NewGzipEncoder()
	offsets := []int{0, 0}
	return encoder.Encode(input, offsets)
}

// DecompressBytes is a convenience function for simple gzip decompression.
func DecompressBytes(input []byte) []byte {
	encoder := NewGzipEncoder()
	return encoder.Decode(input)
}
