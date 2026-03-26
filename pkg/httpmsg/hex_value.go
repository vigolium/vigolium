package httpmsg

// hex_value.go - Hex value parser for insertion point encoding metadata
//
// This file implements parsing of hex-encoded insertion point metadata strings.
// These strings have the format: "HEXxOFFSETxOFFSET" (e.g., "5f2x3bx40")
//
// The format encodes:
// - Hex value (first component): Encoding type identifier
// - Offset1 (second component): First offset value
// - Offset2 (third component, optional): Second offset value

import (
	"strconv"
	"strings"
)

// HexValue represents a parsed hex-encoded insertion point metadata string.
//
// Algorithm:
// 1. Split string by 'x' separator
// 2. Validate 2 or 3 components
// 3. Parse first component as hex integer
// 4. Set isValid flag based on parsing success
//
// Example:
//
//	"5f2x3bx40" -> hexValue=0x5f2, offset1=0x3b, offset2=0x40
//	"2x5" -> hexValue=0x2, offset1=0x5, offset2=0 (no third component)
type HexValue struct {
	hexString string
	isValid   bool
	hexValue  int
	offset1   int
	offset2   int
}

// NewHexValue creates a new HexValue by parsing the hex string.
//
// Parameters:
//   - hexStr: Hex-encoded string in format "HEXxOFFSETxOFFSET"
//
// Returns:
//   - New HexValue instance (isValid=false if parse failed)
func NewHexValue(hexStr string) *HexValue {
	hv := &HexValue{
		hexString: hexStr,
		isValid:   true,
		hexValue:  0,
		offset1:   0,
		offset2:   0,
	}

	if hexStr == "" {
		hv.isValid = false
		return hv
	}

	// Split by 'x' separator
	parts := strings.Split(hexStr, "x")

	// Validate: must have 2 or 3 components
	if len(parts) < 2 || len(parts) > 3 {
		hv.isValid = false
		return hv
	}

	// Parse hex value (first component)
	val, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil {
		hv.isValid = false
		return hv
	}
	hv.hexValue = int(val)

	// Parse offset1 (second component)
	if len(parts) >= 2 {
		off1, err := strconv.ParseInt(parts[1], 16, 64)
		if err == nil {
			hv.offset1 = int(off1)
		}
	}

	// Parse offset2 (third component, optional)
	if len(parts) >= 3 {
		off2, err := strconv.ParseInt(parts[2], 16, 64)
		if err == nil {
			hv.offset2 = int(off2)
		}
	}

	return hv
}

// IsValid returns whether the hex string was successfully parsed.
func (h *HexValue) IsValid() bool {
	return h.isValid
}

// Value returns the parsed hex value (first component).
func (h *HexValue) Value() int {
	return h.hexValue
}

// Offset1 returns the first offset value (second component).
func (h *HexValue) Offset1() int {
	return h.offset1
}

// Offset2 returns the second offset value (third component).
// Returns 0 if not present.
func (h *HexValue) Offset2() int {
	return h.offset2
}

// String returns the original hex string.
func (h *HexValue) String() string {
	return h.hexString
}

// Equals compares two HexValue instances for equality.
func (h *HexValue) Equals(other *HexValue) bool {
	if h == other {
		return true
	}
	if other == nil {
		return false
	}
	return h.hexString == other.hexString
}

// HashCode returns a hash code for this HexValue.
func (h *HexValue) HashCode() int {
	hash := 0
	for i := 0; i < len(h.hexString); i++ {
		hash = 31*hash + int(h.hexString[i])
	}
	return hash
}
