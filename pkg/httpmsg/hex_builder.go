package httpmsg

// hex_builder.go - Hex builder for insertion point encoding metadata
//
// This file implements building of hex-encoded insertion point metadata strings.
// These strings encode parameter type mappings and offsets in the format:
// "HEXxOFFSETxOFFSET" (e.g., "5f2x3bx40")
//
// The format encodes:
// - Encoding value: Computed from parameter type mappings
// - Offset1: First offset value
// - Offset2: Second offset value (optional)

import (
	"fmt"
)

// HexBuilder builds hex-encoded insertion point metadata strings.
//
// Algorithm:
// 1. Compute encoding value from parameter types
// 2. Store offset values
// 3. Format as hex string
//
// The encoding value is computed using a mapping table that combines
// current and legacy parameter types with different values for
// same vs. different types.
type HexBuilder struct {
	// encodingValue computed from parameter type mappings
	encodingValue int

	// offset1 is the first offset (-1 if not set)
	offset1 int

	// offset2 is the second offset (-1 if not set)
	offset2 int
}

// NewHexBuilder creates a new HexBuilder from parameter type and legacy type.
//
// Parameters:
//   - paramType: Current parameter type
//   - legacyType: Legacy parameter type
//
// Returns:
//   - New HexBuilder instance
func NewHexBuilder(paramType, legacyType ParamType) *HexBuilder {
	return &HexBuilder{
		encodingValue: computeEncoding(paramType, legacyType),
		offset1:       -1,
		offset2:       -1,
	}
}

// NewHexBuilderSingleType creates a HexBuilder with modified encoding for same type.
// Adds 128 to the computed encoding value.
//
// Parameters:
//   - paramType: Parameter type
//
// Returns:
//   - New HexBuilder instance with modified encoding
func NewHexBuilderSingleType(paramType ParamType) *HexBuilder {
	return &HexBuilder{
		encodingValue: 128 + computeEncoding(paramType, paramType),
		offset1:       -1,
		offset2:       -1,
	}
}

// SetOffset1 sets the first offset value.
func (h *HexBuilder) SetOffset1(offset int) {
	h.offset1 = offset
}

// GetOffset1 returns the first offset value (-1 if not set).
func (h *HexBuilder) GetOffset1() int {
	return h.offset1
}

// SetOffset2 sets the second offset value.
func (h *HexBuilder) SetOffset2(offset int) {
	h.offset2 = offset
}

// GetOffset2 returns the second offset value (-1 if not set).
func (h *HexBuilder) GetOffset2() int {
	return h.offset2
}

// String returns the hex-encoded string representation.
// Format: "HEXxOFFSET1" or "HEXxOFFSET1xOFFSET2" if offset2 is set.
// Panics if offset1 is not set.
func (h *HexBuilder) String() string {
	if h.offset1 == -1 {
		panic("offset1 must be set before calling String()")
	}

	// Conditional format based on offset2
	if h.offset2 != -1 {
		// Format: "HEXxOFFSET1xOFFSET2"
		return fmt.Sprintf("%x%s%x%s%x", h.encodingValue, "x", h.offset1, "x", h.offset2)
	}

	// Format: "HEXxOFFSET1"
	return fmt.Sprintf("%x%s%x", h.encodingValue, "x", h.offset1)
}

// computeEncoding computes the encoding value from parameter types.
//
// This implements a mapping table that assigns different encoding values
// based on combinations of current and legacy parameter types.
//
// Parameters:
//   - currentType: Current parameter type
//   - legacyType: Legacy parameter type
//
// Returns:
//   - Encoding value (integer)
func computeEncoding(currentType, legacyType ParamType) int {
	// Different types
	if currentType != legacyType {
		switch legacyType {
		case ParamURL, ParamBody:
			switch currentType {
			case ParamXML:
				return 12
			case ParamXMLAttr:
				return 9
			default:
				return 0
			}

		case ParamXML:
			switch currentType {
			case ParamURL, ParamBody:
				return 13
			case ParamXMLAttr:
				return 10
			default:
				return 0
			}

		case ParamXMLAttr:
			switch currentType {
			case ParamURL, ParamBody:
				return 8
			case ParamXML:
				return 11
			default:
				return 0
			}

		default:
			return 0
		}
	}

	// Same types
	switch currentType {
	case ParamURL, ParamBody:
		return 2

	case ParamXML:
		return 3

	case ParamXMLAttr:
		return 1

	case ParamJSON:
		return 4

	case ParamCookie:
		return 5

	case ParamMultipartAttr:
		return 6

	case ParamPathFolder:
		return 7

	default:
		return 0
	}
}
