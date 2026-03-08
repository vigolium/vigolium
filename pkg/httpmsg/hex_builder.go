package httpmsg

// hex_builder.go - Hex builder for insertion point encoding metadata
// Ported from: burp/b9l.java (lines 1-113)
//
// This file implements building of hex-encoded insertion point metadata strings.
// These strings encode parameter type mappings and offsets in the format:
// "HEXxOFFSETxOFFSET" (e.g., "5f2x3bx40")
//
// The format encodes:
// - Encoding value: Computed from parameter type mappings
// - Offset1: First offset value (set via SetOffset1/SetOffset2 methods in iav.java)
// - Offset2: Second offset value (optional)
//
// Field mapping from b9l.java:
//   - a (int): encodingValue - computed encoding type
//   - c (int): offset1 - first offset (-1 if not set)
//   - b (int): offset2 - second offset (-1 if not set)

import (
	"fmt"
)

// HexBuilder builds hex-encoded insertion point metadata strings.
// Ported from: burp/b9l.java class (lines 3-113)
//
// Algorithm (from b9l.java):
// 1. Compute encoding value from parameter types (constructor lines 8-14, method lines 33-112)
// 2. Store offset values (methods lines 16-26)
// 3. Format as hex string (method a() lines 28-31)
//
// The encoding value is computed using a complex mapping table that combines:
// - Current parameter type (gji)
// - Legacy parameter type (gji)
// - Different values for same vs. different types
//
// Example encoding values from b9l.java lines 75-106:
//   - Same type URL_PARAM/BODY_ParamURL_ENCODED: 2
//   - Same type COOKIE: 3
//   - Same type XML_PARAM: 1
//   - Different types COOKIE->XML_PARAM: 12
//   - Different types XML_PARAM->COOKIE: 13
type HexBuilder struct {
	// a: encoding value from b9l.java
	encodingValue int

	// c: first offset from b9l.java (called b(int) setter, b() getter)
	offset1 int

	// b: second offset from b9l.java (called a(int) setter)
	offset2 int
}

// NewHexBuilder creates a new HexBuilder from parameter type and legacy type.
// Ported from: b9l.java constructor (lines 8-10)
//
// Algorithm (from b9l.java lines 8-10):
// 1. Call computeEncoding with both types (line 9)
// 2. Initialize offsets to -1 (lines 5-6)
//
// Parameters:
//   - paramType: Current parameter type
//   - legacyType: Legacy parameter type
//
// Returns:
//   - New HexBuilder instance
func NewHexBuilder(paramType, legacyType ParamType) *HexBuilder {
	return &HexBuilder{
		// b9l.java line 9: this.a = this.a(var1, var2)
		encodingValue: computeEncoding(paramType, legacyType),
		// b9l.java lines 5-6: private int c = -1, b = -1
		offset1: -1,
		offset2: -1,
	}
}

// NewHexBuilderSingleType creates a HexBuilder with modified encoding for same type.
// Ported from: b9l.java constructor (lines 12-14)
//
// Algorithm (from b9l.java lines 12-14):
// 1. Call computeEncoding with same type twice (line 13)
// 2. Add 128 to the result (line 13)
// 3. Initialize offsets to -1
//
// Parameters:
//   - paramType: Parameter type
//
// Returns:
//   - New HexBuilder instance with modified encoding
func NewHexBuilderSingleType(paramType ParamType) *HexBuilder {
	return &HexBuilder{
		// b9l.java line 13: this.a = 128 + this.a(var1, var1)
		encodingValue: 128 + computeEncoding(paramType, paramType),
		offset1:       -1,
		offset2:       -1,
	}
}

// SetOffset1 sets the first offset value.
// Ported from: b9l.java b(int) method (lines 16-18)
//
// This is called from iav.java b(int) method (line 167) to set the first offset.
//
// Parameters:
//   - offset: First offset value
func (h *HexBuilder) SetOffset1(offset int) {
	// b9l.java line 17: this.c = var1
	h.offset1 = offset
}

// GetOffset1 returns the first offset value.
// Ported from: b9l.java b() method (lines 20-22)
//
// Returns:
//   - First offset value (-1 if not set)
func (h *HexBuilder) GetOffset1() int {
	// b9l.java line 21: return this.c
	return h.offset1
}

// SetOffset2 sets the second offset value.
// Ported from: b9l.java a(int) method (lines 24-26)
//
// Parameters:
//   - offset: Second offset value
func (h *HexBuilder) SetOffset2(offset int) {
	// b9l.java line 25: this.b = var1
	h.offset2 = offset
}

// GetOffset2 returns the second offset value.
// This method is not in b9l.java but is useful for symmetry.
//
// Returns:
//   - Second offset value (-1 if not set)
func (h *HexBuilder) GetOffset2() int {
	return h.offset2
}

// String returns the hex-encoded string representation.
// Ported from: b9l.java a() method (lines 28-31)
//
// Algorithm (from b9l.java lines 28-31):
// 1. Assert offset1 is set (line 29)
// 2. If offset2 is set: format "HEXxOFFSET1xOFFSET2" (line 30)
// 3. Otherwise: format "HEXxOFFSET1" (line 30)
//
// Returns:
//   - Hex-encoded string in format "HEXxOFFSETxOFFSET"
//   - Panics if offset1 is not set (matches Java assertion)
func (h *HexBuilder) String() string {
	// b9l.java line 29: assert that offset1 is set
	if h.offset1 == -1 {
		panic("offset1 must be set before calling String()")
	}

	// b9l.java line 30: conditional format based on offset2
	if h.offset2 != -1 {
		// Format: "HEXxOFFSET1xOFFSET2"
		return fmt.Sprintf("%x%s%x%s%x", h.encodingValue, "x", h.offset1, "x", h.offset2)
	}

	// Format: "HEXxOFFSET1"
	return fmt.Sprintf("%x%s%x", h.encodingValue, "x", h.offset1)
}

// computeEncoding computes the encoding value from parameter types.
// Ported from: b9l.java a(gji, gji) method (lines 33-112)
//
// This implements a complex mapping table that assigns different encoding values
// based on combinations of current and legacy parameter types.
//
// Algorithm (from b9l.java lines 33-112):
// 1. If types are different (lines 34-73):
//   - Switch on legacy type (line 35)
//   - For each legacy type, switch on current type (lines 36-69)
//   - Return specific encoding value for each combination
//
// 2. If types are same (lines 74-111):
//   - Switch on current type (line 75)
//   - Return type-specific encoding value
//
// Parameters:
//   - currentType: Current parameter type
//   - legacyType: Legacy parameter type
//
// Returns:
//   - Encoding value (integer)
func computeEncoding(currentType, legacyType ParamType) int {
	// b9l.java lines 34-73: different types
	if currentType != legacyType {
		// Switch on legacyType (fa4.a[var2.ordinal()])
		// b9l.java lines 35-72
		switch legacyType {
		case ParamURL, ParamBody: // case 1, 2
			// b9l.java lines 38-46
			switch currentType {
			case ParamXML: // case 3
				return 12 // line 40
			case ParamXMLAttr: // case 4
				return 9 // line 42
			default:
				// b9l.java line 44: assert false
				return 0
			}

		case ParamXML: // case 3
			// b9l.java lines 47-58
			switch currentType {
			case ParamURL, ParamBody: // case 1, 2
				return 13 // line 51
			case ParamXMLAttr: // case 4
				return 10 // line 57
			default:
				// b9l.java line 54: assert false
				return 0
			}

		case ParamXMLAttr: // case 4
			// b9l.java lines 59-69
			switch currentType {
			case ParamURL, ParamBody: // case 1, 2
				return 8 // line 63
			case ParamXML: // case 3
				return 11 // line 65
			default:
				// b9l.java line 67: assert false
				return 0
			}

		default:
			// b9l.java line 71: assert false
			return 0
		}
	}

	// b9l.java lines 74-111: same types
	switch currentType {
	case ParamURL, ParamBody: // case 1, 2, 5, 6, 7, 8
		return 2 // line 82

	case ParamXML: // case 3
		return 3 // line 84

	case ParamXMLAttr: // case 4
		return 1 // line 86

	case ParamJSON: // case 9, 10, 11
		return 4 // line 90

	case ParamCookie: // case 12 (note: enum order differs from Java)
		return 5 // line 92

	case ParamMultipartAttr: // case 13
		return 6 // line 94

	case ParamPathFolder: // case 14
		return 7 // line 96

	// Additional cases from b9l.java lines 97-106
	// These correspond to parameter types not in our basic set:
	// case 15 (unknown): return 18
	// case 16 (unknown): return 14
	// case 17 (unknown): return 17
	// case 18 (unknown): return 15
	// case 19 (unknown): return 16

	default:
		// b9l.java line 108: assert false
		return 0
	}
}
