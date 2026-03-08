package xss_light_scanner

import (
	"math/rand"
	"strings"
)

// BreakoutChars are the 12 characters tested in primary payload
// Includes: quotes, angle brackets, space, equals, slash, template chars (${}), dash
var BreakoutChars = []byte{'\'', '"', '`', '<', '>', ' ', '=', '/', '$', '{', '}', '-'}

// CanaryPayload represents a payload with canary markers for XSS detection
type CanaryPayload struct {
	FullPayload string       // The complete payload string
	Canary      string       // 4-char random suffix for identification
	Segments    []string     // Random R4 segments used in payload
	CharMap     map[byte]int // Maps breakout char to its preceding segment index
	CharOffsets map[byte]int // Maps breakout char to its offset in the payload
}

// generateRandomSegment creates a 4-character alphanumeric segment
// Format: [a-z][a-z0-9]{3}
func generateRandomSegment() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const alphanumeric = "abcdefghijklmnopqrstuvwxyz0123456789"

	result := make([]byte, 4)
	result[0] = letters[rand.Intn(len(letters))]
	for i := 1; i < 4; i++ {
		result[i] = alphanumeric[rand.Intn(len(alphanumeric))]
	}
	return string(result)
}

// GeneratePrimary creates a primary payload that tests 12 breakout characters
// Template: {R4}'{R4}"{R4}`{R4}<{R4}>{R4} {R4}={R4}/{R4}${R4}{R4}{R4}}{R4}-{R4}
func GeneratePrimary() *CanaryPayload {
	segments := make([]string, len(BreakoutChars)+1)
	for i := range segments {
		segments[i] = generateRandomSegment()
	}

	canary := segments[0]

	// Build the payload: {R4}'{R4}"{R4}`{R4}<{R4}>{R4} {R4}={R4}/{R4}
	var sb strings.Builder
	charOffsets := make(map[byte]int)
	charMap := make(map[byte]int)

	sb.WriteString(segments[0])
	for i, ch := range BreakoutChars {
		charOffsets[ch] = sb.Len()
		sb.WriteByte(ch)
		charMap[ch] = i
		sb.WriteString(segments[i+1])
	}

	return &CanaryPayload{
		FullPayload: sb.String(),
		Canary:      canary,
		Segments:    segments,
		CharMap:     charMap,
		CharOffsets: charOffsets,
	}
}

// ContainsCanary checks if the payload contains a specific canary
func (p *CanaryPayload) ContainsCanary(canary string) bool {
	return p.Canary == canary || strings.Contains(p.FullPayload, canary)
}

// GetCharOffset returns the offset of a breakout character in the payload
func (p *CanaryPayload) GetCharOffset(ch byte) int {
	if offset, ok := p.CharOffsets[ch]; ok {
		return offset
	}
	return -1
}

// GetSegmentBefore returns the segment that appears before a breakout character
func (p *CanaryPayload) GetSegmentBefore(ch byte) string {
	if idx, ok := p.CharMap[ch]; ok && idx < len(p.Segments) {
		return p.Segments[idx]
	}
	return ""
}

// GetSegmentAfter returns the segment that appears after a breakout character
func (p *CanaryPayload) GetSegmentAfter(ch byte) string {
	if idx, ok := p.CharMap[ch]; ok && idx+1 < len(p.Segments) {
		return p.Segments[idx+1]
	}
	return ""
}

// GetSequenceSegmentBefore returns the segment before a sequence (using first char)
func (p *CanaryPayload) GetSequenceSegmentBefore(seq string) string {
	if len(seq) == 0 {
		return ""
	}
	return p.GetSegmentBefore(seq[0])
}

// GetSequenceSegmentAfter returns the segment after a sequence (using first char)
func (p *CanaryPayload) GetSequenceSegmentAfter(seq string) string {
	if len(seq) == 0 {
		return ""
	}
	return p.GetSegmentAfter(seq[0])
}

// GeneratePrimaryWithPrefix creates a primary payload with bypass prefix
// Payload format: {prefix}{R4}'{R4}"{R4}`{R4}<{R4}>{R4} {R4}={R4}/{R4}${R4}{R4}{R4}}{R4}-{R4}
func GeneratePrimaryWithPrefix(prefix BypassPrefix) *CanaryPayload {
	base := GeneratePrimary()

	if prefix.HasPrefix() {
		base.FullPayload = string(prefix.Bytes) + base.FullPayload
		// Adjust offsets for prefix length
		prefixLen := len(prefix.Bytes)
		for ch, offset := range base.CharOffsets {
			base.CharOffsets[ch] = offset + prefixLen
		}
	}

	return base
}

// BuildBatchedSecondaryPayload builds a single payload to test multiple sequences
// Input: sequences like ["\\'", "\\\"", "\\`"]
// Output: {R4}\'{R4}\"{R4}\`{R4}
func BuildBatchedSecondaryPayload(sequences []string) *CanaryPayload {
	if len(sequences) == 0 {
		return nil
	}

	// Generate segments: one before each sequence + one after the last
	segments := make([]string, len(sequences)+1)
	for i := range segments {
		segments[i] = generateRandomSegment()
	}

	canary := segments[0]

	var sb strings.Builder
	charOffsets := make(map[byte]int)
	charMap := make(map[byte]int)
	seqOffsets := make(map[string]int)

	sb.WriteString(segments[0])

	for i, seq := range sequences {
		seqOffsets[seq] = sb.Len()

		// For CharMap and CharOffsets, use the first char of the sequence
		if len(seq) > 0 {
			charOffsets[seq[0]] = sb.Len()
			charMap[seq[0]] = i
		}

		sb.WriteString(seq)
		sb.WriteString(segments[i+1])
	}

	payload := &CanaryPayload{
		FullPayload: sb.String(),
		Canary:      canary,
		Segments:    segments,
		CharMap:     charMap,
		CharOffsets: charOffsets,
	}

	return payload
}

// BuildBatchedSecondaryWithPrefix creates batched payload with bypass prefix
func BuildBatchedSecondaryWithPrefix(sequences []string, prefix BypassPrefix) *CanaryPayload {
	base := BuildBatchedSecondaryPayload(sequences)
	if base == nil {
		return nil
	}

	if prefix.HasPrefix() {
		base.FullPayload = string(prefix.Bytes) + base.FullPayload
		// Adjust offsets
		prefixLen := len(prefix.Bytes)
		for ch, offset := range base.CharOffsets {
			base.CharOffsets[ch] = offset + prefixLen
		}
	}

	return base
}
