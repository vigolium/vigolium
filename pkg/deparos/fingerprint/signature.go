package fingerprint

import (
	"fmt"
)

// Signature represents a learned 404 fingerprint signature
// Maps to Burp's b5e.java fingerprint signature (Lines 7-89)
// Contains only stable attributes (consistent across multiple samples)
// Immutable after creation - no synchronization needed.
type Signature struct {
	stable map[Attribute]uint32 // Only stable attributes with their hash values
	debug  string               // Debug description (URL pattern, etc.)
}

// NewSignature creates a signature by analyzing consistency across multiple samples
// Maps to Burp's ds9.java learning algorithm (Lines 5-109)
// Uses 3-baseline sampling: only attributes stable across all 3 samples are included
func NewSignature(samples []*Sample) (*Signature, error) {
	if len(samples) == 0 {
		return nil, fmt.Errorf("no samples provided")
	}

	if len(samples) < 3 {
		return nil, fmt.Errorf("need at least 3 samples for consistency detection, got %d", len(samples))
	}

	sig := &Signature{
		stable: make(map[Attribute]uint32),
		debug:  fmt.Sprintf("learned from %d samples", len(samples)),
	}

	// Get all active attributes
	activeAttrs := AllActiveAttributes()

	// Check each attribute for consistency across all samples
	for _, attr := range activeAttrs {
		if sig.isStableAcrossSamples(attr, samples) {
			// All samples have same hash for this attribute - it's stable
			hash := samples[0].GetHash(attr)
			sig.stable[attr] = hash
		}
	}

	return sig, nil
}

// isStableAcrossSamples checks if an attribute has the same hash across all samples
// Maps to Burp's consistency detection in b5e.java (Lines 35-60)
func (sig *Signature) isStableAcrossSamples(attr Attribute, samples []*Sample) bool {
	if len(samples) == 0 {
		return false
	}

	// Check if first sample has this attribute
	if !samples[0].HasAttribute(attr) {
		return false
	}

	firstHash := samples[0].GetHash(attr)

	// Check all other samples have same hash
	for i := 1; i < len(samples); i++ {
		if !samples[i].HasAttribute(attr) {
			return false // Attribute missing in this sample
		}

		if samples[i].GetHash(attr) != firstHash {
			return false // Hash differs - not stable
		}
	}

	return true // All samples have same hash
}

// Matches checks if a sample matches this signature
// Maps to Burp's b5e.java:matches() (Lines 62-89)
// Returns true if ALL stable attributes in signature match the sample
func (sig *Signature) Matches(sample *Sample) bool {
	// Check each stable attribute
	for attr, expectedHash := range sig.stable {
		// Sample must have this attribute
		if !sample.HasAttribute(attr) {
			return false
		}

		// Hash must match exactly
		if sample.GetHash(attr) != expectedHash {
			return false
		}
	}

	return true // All stable attributes match
}

// StableAttributeCount returns the number of stable attributes
func (sig *Signature) StableAttributeCount() int {
	return len(sig.stable)
}

// GetStableAttributes returns a copy of stable attributes
func (sig *Signature) GetStableAttributes() map[Attribute]uint32 {
	result := make(map[Attribute]uint32, len(sig.stable))
	for k, v := range sig.stable {
		result[k] = v
	}
	return result
}

// HasAttribute returns true if the attribute is stable in this signature
func (sig *Signature) HasAttribute(attr Attribute) bool {
	_, ok := sig.stable[attr]
	return ok
}

// Debug returns debug description
func (sig *Signature) Debug() string {
	return fmt.Sprintf("%s (%d stable attrs)", sig.debug, len(sig.stable))
}

// SetDebug sets debug description.
// NOTE: Must be called immediately after NewSignature(), before sharing.
func (sig *Signature) SetDebug(debug string) {
	sig.debug = debug
}

// IsCriticalMatch checks if critical non-maskable attributes match
// Critical attributes: StatusCode, ContentType
// These must always match for a valid signature match
func (sig *Signature) IsCriticalMatch(sample *Sample) bool {
	// Check StatusCode (attribute 2) - non-maskable
	if expectedStatus, ok := sig.stable[StatusCode]; ok {
		if !sample.HasAttribute(StatusCode) || sample.GetHash(StatusCode) != expectedStatus {
			return false
		}
	}

	// Check ContentType (attribute 5) - non-maskable
	if expectedCT, ok := sig.stable[ContentType]; ok {
		if !sample.HasAttribute(ContentType) || sample.GetHash(ContentType) != expectedCT {
			return false
		}
	}

	return true
}

// PartialMatch returns the percentage of stable attributes that match
// Useful for debugging and tuning
func (sig *Signature) PartialMatch(sample *Sample) float64 {
	if len(sig.stable) == 0 {
		return 0.0
	}

	matches := 0
	for attr, expectedHash := range sig.stable {
		if sample.HasAttribute(attr) && sample.GetHash(attr) == expectedHash {
			matches++
		}
	}

	return float64(matches) / float64(len(sig.stable))
}

// DebugString returns a detailed string representation of the signature for debugging.
func (sig *Signature) DebugString() string {
	result := fmt.Sprintf("Signature[%s]: %d stable attrs\n", sig.debug, len(sig.stable))
	for attr, hash := range sig.stable {
		result += fmt.Sprintf("  %s(#%d): %d\n", attr.String(), attr, hash)
	}
	return result
}
