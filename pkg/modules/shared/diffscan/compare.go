package diffscan

// valuesEqual compares two fingerprint values, using QuantitativeMeasurements.Equals()
// for quantitative types (which uses QuantileOverlap) instead of direct comparison.
func valuesEqual(a, b any) bool {
	// Handle QuantitativeMeasurements comparison
	if qmA, ok := a.(*QuantitativeMeasurements); ok {
		if qmB, ok := b.(*QuantitativeMeasurements); ok {
			return qmA.Equals(qmB)
		}
		return false
	}
	return a == b
}

// Identical performs deep comparison of two attack fingerprints.
// Returns true if fingerprints are exactly equal.
// Returns false if candidate is nil.
func Identical(candidate *Attack, attack2 *Attack) bool {
	if candidate == nil {
		return false
	}
	if len(candidate.Fingerprint) != len(attack2.Fingerprint) {
		return false
	}
	for key, val1 := range candidate.Fingerprint {
		val2, exists := attack2.Fingerprint[key]
		if !exists || !valuesEqual(val1, val2) {
			return false
		}
	}
	return true
}

// SimilarWithTolerance compares consistency between break/baseline groups and individuals.
// Returns true if similar according to complex conditions.
// This logic checks the consistency of fingerprint attributes between groups
// and individual attacks, handling missing keys by referencing the corresponding
// individual attack.
func SimilarWithTolerance(
	baselineGroup *Attack,
	breakGroup *Attack,
	baselineAttack *Attack,
	breakAttack *Attack,
) bool {
	for key, baselineVal := range baselineGroup.Fingerprint {
		if key == "input_reflections" && baselineVal == int(ReflectionCountIncalculable) {
			continue
		}

		if _, ok := breakGroup.Fingerprint[key]; !ok {
			if !valuesEqual(baselineVal, breakAttack.Fingerprint[key]) {
				return false
			}
		} else if !valuesEqual(baselineVal, breakGroup.Fingerprint[key]) {
			return false
		}
	}

	for key, breakVal := range breakGroup.Fingerprint {
		if _, ok := baselineGroup.Fingerprint[key]; !ok {
			if !valuesEqual(breakVal, baselineAttack.Fingerprint[key]) {
				return false
			}
		}
	}

	return true
}

// Similar checks if all key-value pairs in baselineGroup
// exist and match in breakAttack.
// This function checks if the second fingerprint is a superset of
// (or identical to) the first fingerprint.
// Returns true if the second fingerprint contains all entries from the first.
func Similar(baselineGroup *Attack, breakAttack *Attack) bool {
	for key, value := range baselineGroup.Fingerprint {
		fingerprint2Value, ok := breakAttack.Fingerprint[key]
		if !ok {
			return false
		}

		if !valuesEqual(value, fingerprint2Value) {
			return false
		}
	}
	return true
}

// VerySimilar checks if two attack fingerprints are "very similar".
// First, it checks if the number of keys is equal.
// Then, it iterates through the first fingerprint and checks if each key exists
// in the second fingerprint with the same value, except for the key "input_reflections"
// (which allows the value ReflectionCountIncalculable in either).
// Returns true if very similar (same length and matching key-values, except input_reflections).
func VerySimilar(attack1 *Attack, attack2 *Attack) bool {
	if len(attack1.Fingerprint) != len(attack2.Fingerprint) {
		return false
	}

	for key, val1 := range attack1.Fingerprint {
		if key == "input_reflections" &&
			(val1 == int(ReflectionCountIncalculable) ||
				attack2.Fingerprint[key] == int(ReflectionCountIncalculable)) {
			continue
		}

		val2, exists := attack2.Fingerprint[key]
		if !exists || !valuesEqual(val2, val1) {
			return false
		}
	}

	return true
}
