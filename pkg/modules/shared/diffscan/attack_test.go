package diffscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeAttackWithQuant creates Attack with quantitative measurements
func makeAttackWithQuant(fp map[string]any, quantKeys []string) *Attack {
	attack := &Attack{
		Fingerprint:     fp,
		LastFingerprint: fp,
		quantKeys:       make(map[string]struct{}),
		quantMetrics:    make(map[string]*QuantitativeMeasurements),
	}
	for _, k := range quantKeys {
		attack.quantKeys[k] = struct{}{}
	}
	return attack
}

func TestNewAttack(t *testing.T) {
	t.Run("initialization with quantitative keys", func(t *testing.T) {
		attack := NewAttack([]string{"length", "words"}, 5, "")

		require.NotNil(t, attack.quantKeys)
		require.NotNil(t, attack.quantMetrics)
		assert.Contains(t, attack.quantKeys, "length")
		assert.Contains(t, attack.quantKeys, "words")
		assert.Len(t, attack.quantMetrics, 2)
	})

	t.Run("ResponseReflections initialized to UNINITIALISED", func(t *testing.T) {
		attack := NewAttack(nil, 5, "")
		assert.Equal(t, ReflectionCountUninitialized, attack.ResponseReflections)
	})

	t.Run("webfinger components initialized", func(t *testing.T) {
		attack := NewAttack(nil, 5, "")
		assert.NotNil(t, attack.ResponseFingerprint)
		assert.NotNil(t, attack.ResponseKeywordsFingerprint)
	})

	t.Run("empty string in quantDiffKeys is skipped", func(t *testing.T) {
		attack := NewAttack([]string{"length", "", "words"}, 5, "")
		assert.Len(t, attack.quantKeys, 2)
		assert.NotContains(t, attack.quantKeys, "")
	})
}

func TestAttackAddAttack_FirstAttack(t *testing.T) {
	t.Run("when FirstSnapshot is nil copies from input attack", func(t *testing.T) {
		probe := NewProbe("test", 1, "break")
		inputAttack := makeAttackWithQuant(map[string]any{"a": 1}, nil)
		inputAttack.FirstSnapshot = &ResponseSnapshot{}
		inputAttack.Anchor = "canary123"
		inputAttack.Probe = probe
		inputAttack.Payload = "payload123"

		target := NewAttack(nil, 5, "")
		target.AddAttack(inputAttack)

		assert.Equal(t, inputAttack.FirstSnapshot, target.FirstSnapshot)
		assert.Equal(t, "canary123", target.Anchor)
		assert.Equal(t, probe, target.Probe)
		assert.Equal(t, "payload123", target.Payload)
	})
}

func TestAttackAddAttack_MergeFingerprints(t *testing.T) {
	t.Run("static attributes: keeps only matching values", func(t *testing.T) {
		// First attack
		attack1 := &Attack{
			FirstSnapshot:   &ResponseSnapshot{},
			Fingerprint:     map[string]any{"a": 1, "b": 2, "c": 3},
			LastFingerprint: map[string]any{"a": 1, "b": 2, "c": 3},
		}

		// Second attack with some different values
		attack2 := &Attack{
			FirstSnapshot:   &ResponseSnapshot{},
			Fingerprint:     map[string]any{"a": 1, "b": 999, "d": 4}, // b differs, c missing, d new
			LastFingerprint: map[string]any{"a": 1, "b": 999, "d": 4},
		}

		// Create target attack with first attack
		target := NewAttack(nil, 5, "")
		target.FirstSnapshot = attack1.FirstSnapshot
		target.Fingerprint = attack1.Fingerprint

		// Merge second attack
		target.AddAttack(attack2)

		// Only "a" survives (both have a=1)
		// "b" removed (different values)
		// "c" removed (not in attack2)
		// "d" removed (not in attack1's fingerprint which is target.Fingerprint)
		assert.Equal(t, map[string]any{"a": 1}, target.Fingerprint)
	})

	t.Run("quantitative attributes: merges via Merge", func(t *testing.T) {
		qm1 := NewQuantitativeMeasurements("length", 5)
		qm1.UpdateWith(100)

		qm2 := NewQuantitativeMeasurements("length", 5)
		qm2.UpdateWith(200)

		attack1 := &Attack{
			FirstSnapshot:   &ResponseSnapshot{},
			Fingerprint:     map[string]any{"length": qm1},
			LastFingerprint: map[string]any{"length": qm1},
			quantKeys:       map[string]struct{}{"length": {}},
			quantMetrics:    map[string]*QuantitativeMeasurements{"length": qm1},
		}

		attack2 := &Attack{
			FirstSnapshot:   &ResponseSnapshot{},
			Fingerprint:     map[string]any{"length": qm2},
			LastFingerprint: map[string]any{"length": qm2},
		}

		target := NewAttack([]string{"length"}, 5, "")
		target.FirstSnapshot = attack1.FirstSnapshot
		target.Fingerprint = attack1.Fingerprint
		target.quantKeys = attack1.quantKeys
		target.quantMetrics["length"] = qm1

		target.AddAttack(attack2)

		// Merged measurements
		merged := target.Fingerprint["length"].(*QuantitativeMeasurements)
		assert.Len(t, merged.Measurements, 2)
		assert.Contains(t, merged.Measurements, int64(100))
		assert.Contains(t, merged.Measurements, int64(200))
	})

	t.Run("LastFingerprint updated to input's fingerprint", func(t *testing.T) {
		attack1 := &Attack{
			FirstSnapshot:   &ResponseSnapshot{},
			Fingerprint:     map[string]any{"a": 1},
			LastFingerprint: map[string]any{"a": 1},
		}

		attack2 := &Attack{
			FirstSnapshot:   &ResponseSnapshot{},
			Fingerprint:     map[string]any{"a": 1, "b": 2},
			LastFingerprint: map[string]any{"a": 1, "b": 2},
		}

		target := NewAttack(nil, 5, "")
		target.FirstSnapshot = attack1.FirstSnapshot
		target.Fingerprint = attack1.Fingerprint

		target.AddAttack(attack2)

		assert.Equal(t, attack2.Fingerprint, target.LastFingerprint)
	})

	t.Run("LastSnapshot updated to input's LastSnapshot", func(t *testing.T) {
		snap1 := &ResponseSnapshot{}
		snap2 := &ResponseSnapshot{}

		attack1 := &Attack{
			FirstSnapshot:   snap1,
			LastSnapshot:    snap1,
			Fingerprint:     map[string]any{"a": 1},
			LastFingerprint: map[string]any{"a": 1},
		}

		attack2 := &Attack{
			FirstSnapshot:   snap2,
			LastSnapshot:    snap2,
			Fingerprint:     map[string]any{"a": 1},
			LastFingerprint: map[string]any{"a": 1},
		}

		target := NewAttack(nil, 5, "")
		target.FirstSnapshot = attack1.FirstSnapshot
		target.LastSnapshot = attack1.LastSnapshot
		target.Fingerprint = attack1.Fingerprint

		target.AddAttack(attack2)

		assert.Equal(t, snap2, target.LastSnapshot)
	})
}

func TestAttackAllKeysAreQuantitative(t *testing.T) {
	t.Run("returns true if all keys are in quantKeys", func(t *testing.T) {
		attack := NewAttack([]string{"length", "words", "lines"}, 5, "")
		assert.True(t, attack.AllKeysAreQuantitative([]string{"length", "words"}))
	})

	t.Run("returns false if any key not in quantKeys", func(t *testing.T) {
		attack := NewAttack([]string{"length", "words"}, 5, "")
		assert.False(t, attack.AllKeysAreQuantitative([]string{"length", "unknown"}))
	})

	t.Run("empty keys returns true", func(t *testing.T) {
		attack := NewAttack([]string{"length"}, 5, "")
		assert.True(t, attack.AllKeysAreQuantitative([]string{}))
	})
}

func TestAttackSize(t *testing.T) {
	t.Run("returns 0 if no quantMetrics", func(t *testing.T) {
		attack := NewAttack(nil, 5, "")
		assert.Equal(t, 0, attack.Size())
	})

	t.Run("returns measurement count from first quantBox", func(t *testing.T) {
		attack := NewAttack([]string{"length"}, 5, "")
		attack.quantMetrics["length"].UpdateWith(100)
		attack.quantMetrics["length"].UpdateWith(200)
		attack.quantMetrics["length"].UpdateWith(300)

		assert.Equal(t, 3, attack.Size())
	})
}

func TestGetNonMatchingFingerprints(t *testing.T) {
	t.Run("identifies keys with different values", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1, "b": 2})
		attack2 := makeAttack(map[string]any{"a": 1, "b": 999})

		nonMatching := GetNonMatchingFingerprints(attack1, attack2)

		assert.Contains(t, nonMatching, "b")
		assert.NotContains(t, nonMatching, "a")
	})

	t.Run("identifies keys missing in one attack", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1, "b": 2})
		attack2 := makeAttack(map[string]any{"a": 1, "c": 3})

		nonMatching := GetNonMatchingFingerprints(attack1, attack2)

		assert.Contains(t, nonMatching, "b") // only in attack1
		assert.Contains(t, nonMatching, "c") // only in attack2
		assert.NotContains(t, nonMatching, "a")
	})

	t.Run("handles quantitative comparison via Equals", func(t *testing.T) {
		qm1 := NewQuantitativeMeasurements("length", 5)
		qm1.UpdateWith(100)

		qm2 := NewQuantitativeMeasurements("length", 5)
		qm2.UpdateWith(100) // same value, will overlap

		attack1 := makeAttack(map[string]any{"length": qm1})
		attack2 := makeAttack(map[string]any{"length": qm2})

		nonMatching := GetNonMatchingFingerprints(attack1, attack2)

		// Should be empty since qm1.Equals(qm2) is true
		assert.Empty(t, nonMatching)
	})

	t.Run("quantitative no overlap is non-matching", func(t *testing.T) {
		qm1 := NewQuantitativeMeasurements("length", 5)
		qm1.UpdateWith(100)

		qm2 := NewQuantitativeMeasurements("length", 5)
		qm2.UpdateWith(10000) // very different, won't overlap

		attack1 := makeAttack(map[string]any{"length": qm1})
		attack2 := makeAttack(map[string]any{"length": qm2})

		nonMatching := GetNonMatchingFingerprints(attack1, attack2)

		assert.Contains(t, nonMatching, "length")
	})

	t.Run("empty fingerprints return empty", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{})
		attack2 := makeAttack(map[string]any{})

		nonMatching := GetNonMatchingFingerprints(attack1, attack2)

		assert.Empty(t, nonMatching)
	})
}

func TestFingerprintValuesEqual(t *testing.T) {
	t.Run("same primitives", func(t *testing.T) {
		assert.True(t, fingerprintValuesEqual(42, 42))
		assert.True(t, fingerprintValuesEqual("foo", "foo"))
	})

	t.Run("different primitives", func(t *testing.T) {
		assert.False(t, fingerprintValuesEqual(42, 43))
		assert.False(t, fingerprintValuesEqual("foo", "bar"))
	})

	t.Run("QuantitativeMeasurements equal via QuantileOverlap", func(t *testing.T) {
		qm1 := NewQuantitativeMeasurements("test", 5)
		qm1.UpdateWith(100)

		qm2 := NewQuantitativeMeasurements("test", 5)
		qm2.UpdateWith(100)

		assert.True(t, fingerprintValuesEqual(qm1, qm2))
	})

	t.Run("mixed types return false", func(t *testing.T) {
		qm := NewQuantitativeMeasurements("test", 5)
		assert.False(t, fingerprintValuesEqual(qm, "string"))
		assert.False(t, fingerprintValuesEqual("string", qm))
	})
}
