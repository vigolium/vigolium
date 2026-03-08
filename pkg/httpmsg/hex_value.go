package httpmsg

// hex_value.go - Hex value parser for insertion point encoding metadata
// Ported from: burp/dha.java (lines 1-72)
//
// This file implements parsing of hex-encoded insertion point metadata strings.
// These strings have the format: "HEXxOFFSETxOFFSET" (e.g., "5f2x3bx40")
//
// The format encodes:
// - Hex value (first component): Encoding type identifier
// - Offset1 (second component): First offset value
// - Offset2 (third component, optional): Second offset value
//
// Field mapping from dha.java:
//   - c (String): hexString - original hex string
//   - d (boolean): isValid - whether parsing succeeded
//   - a (int): hexValue - parsed hex value (first component)
//   - b (static String): static field (not ported)

import (
	"strconv"
	"strings"
)

// HexValue represents a parsed hex-encoded insertion point metadata string.
// Ported from: burp/dha.java class (lines 3-72)
//
// Algorithm (from dha.java constructor lines 9-28):
// 1. Split string by 'x' separator (line 12)
// 2. Validate 2 or 3 components (lines 13-24)
// 3. Parse first component as hex integer (lines 15-19)
// 4. Set isValid flag based on parsing success
//
// Example:
//
//	"5f2x3bx40" -> hexValue=0x5f2, offset1=0x3b, offset2=0x40
//	"2x5" -> hexValue=0x2, offset1=0x5, offset2=0 (no third component)
type HexValue struct {
	// c: original hex string from dha.java
	hexString string

	// d: validity flag from dha.java
	isValid bool

	// a: parsed hex value from dha.java
	hexValue int

	// Additional fields to store offsets (inferred from string format)
	offset1 int
	offset2 int
}

// NewHexValue creates a new HexValue by parsing the hex string.
// Ported from: dha.java constructor (lines 9-28)
//
// Algorithm (from dha.java lines 9-28):
// 1. Store original string (implied by field c)
// 2. Check for null or empty (lines 11-27)
// 3. Split by 'x' separator (line 12)
// 4. Validate length is 2 or 3 (lines 13-24)
// 5. Parse first component as hex (lines 15-19)
// 6. Set isValid=false on error (lines 17-23)
//
// Parameters:
//   - hexStr: Hex-encoded string in format "HEXxOFFSETxOFFSET"
//
// Returns:
//   - New HexValue instance (isValid=false if parse failed)
func NewHexValue(hexStr string) *HexValue {
	hv := &HexValue{
		hexString: hexStr,
		isValid:   true, // dha.java line 5: private boolean d = true
		hexValue:  0,
		offset1:   0,
		offset2:   0,
	}

	// dha.java lines 11-27: null/empty check
	if hexStr == "" {
		// dha.java line 26: set isValid = false
		hv.isValid = false
		return hv
	}

	// dha.java line 12: split by 'x'
	parts := strings.Split(hexStr, "x")

	// dha.java lines 13-24: validate length
	if len(parts) < 2 || len(parts) > 3 {
		// dha.java line 22: set isValid = false
		hv.isValid = false
		return hv
	}

	// dha.java lines 15-19: parse hex value (first component)
	val, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil {
		// dha.java line 17-19: catch NumberFormatException, set isValid = false
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
// Ported from: dha.java a() method (lines 53-55)
//
// Returns:
//   - true if parsing succeeded, false otherwise
func (h *HexValue) IsValid() bool {
	// dha.java line 54: return this.d
	return h.isValid
}

// Value returns the parsed hex value (first component).
// Ported from: dha.java c() method (lines 57-59)
//
// Returns:
//   - Parsed hex value as integer
func (h *HexValue) Value() int {
	// dha.java line 58: return this.a
	return h.hexValue
}

// Offset1 returns the first offset value (second component).
// This is inferred from the format but not explicitly in dha.java
//
// Returns:
//   - First offset value as integer
func (h *HexValue) Offset1() int {
	return h.offset1
}

// Offset2 returns the second offset value (third component).
// This is inferred from the format but not explicitly in dha.java
//
// Returns:
//   - Second offset value as integer (0 if not present)
func (h *HexValue) Offset2() int {
	return h.offset2
}

// String returns the original hex string.
// Ported from: dha.java toString() method (lines 49-51)
//
// Returns:
//   - Original hex-encoded string
func (h *HexValue) String() string {
	// dha.java line 50: return this.c
	return h.hexString
}

// Equals compares two HexValue instances for equality.
// Ported from: dha.java equals() method (lines 31-41)
//
// Algorithm (from dha.java lines 32-40):
// 1. Check if same instance (line 33-34)
// 2. Check if same class (lines 35-39)
// 3. Compare hexString fields (line 37)
//
// Parameters:
//   - other: Other HexValue to compare
//
// Returns:
//   - true if hex strings are equal, false otherwise
func (h *HexValue) Equals(other *HexValue) bool {
	// dha.java line 33-34: if (this == var1) return true
	if h == other {
		return true
	}

	// dha.java line 35-39: check class and cast
	if other == nil {
		return false
	}

	// dha.java line 37: return this.c.equals(var2.c)
	return h.hexString == other.hexString
}

// HashCode returns a hash code for this HexValue.
// Ported from: dha.java hashCode() method (lines 43-47)
//
// Returns:
//   - Hash code based on hex string
func (h *HexValue) HashCode() int {
	// dha.java line 45: return this.c.hashCode()
	// Simple hash implementation
	hash := 0
	for i := 0; i < len(h.hexString); i++ {
		hash = 31*hash + int(h.hexString[i])
	}
	return hash
}
