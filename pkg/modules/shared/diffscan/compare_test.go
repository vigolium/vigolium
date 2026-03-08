package diffscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// makeAttack creates an Attack with populated fingerprints for testing
func makeAttack(fp map[string]any) *Attack {
	return &Attack{
		Fingerprint:     fp,
		LastFingerprint: fp,
	}
}

func TestValuesEqual(t *testing.T) {
	t.Run("primitive comparison - int", func(t *testing.T) {
		assert.True(t, valuesEqual(1, 1))
		assert.False(t, valuesEqual(1, 2))
	})

	t.Run("primitive comparison - string", func(t *testing.T) {
		assert.True(t, valuesEqual("foo", "foo"))
		assert.False(t, valuesEqual("foo", "bar"))
	})

	t.Run("primitive comparison - bool", func(t *testing.T) {
		assert.True(t, valuesEqual(true, true))
		assert.False(t, valuesEqual(true, false))
	})

	t.Run("QuantitativeMeasurements comparison via Equals", func(t *testing.T) {
		// QuantileOverlap logic: compare[0] <= qm.GetQuantileTop(qm) && qm.GetQuantileTop(compare) >= qm[0]
		// With Factor=5 and list of 2 elements, GetQuantileTop returns list[0]
		// So for overlap: qm2[0] <= qm1[0] && qm1[0] >= qm2[0]
		qm1 := NewQuantitativeMeasurements("test", 5)
		qm1.UpdateWith(100)
		qm1.UpdateWith(110)

		qm2 := NewQuantitativeMeasurements("test", 5)
		qm2.UpdateWith(95) // qm2[0]=95 <= qm1.GetQuantileTop()=100
		qm2.UpdateWith(105)

		// Should overlap: 95 <= 100 && 95 >= 100 is false...
		// Actually need qm1.GetQuantileTop(compare) >= qm1.Measurements[0]
		// qm1.GetQuantileTop([95,105]) = 95, qm1.Measurements[0] = 100 → 95 >= 100 = false
		// Need values where both conditions are true
		qm3 := NewQuantitativeMeasurements("test", 5)
		qm3.UpdateWith(100) // same value
		qm3.UpdateWith(100)

		qm4 := NewQuantitativeMeasurements("test", 5)
		qm4.UpdateWith(100)
		qm4.UpdateWith(100)

		// Identical values should overlap
		assert.True(t, valuesEqual(qm3, qm4))
	})

	t.Run("QuantitativeMeasurements no overlap", func(t *testing.T) {
		qm1 := NewQuantitativeMeasurements("test", 5)
		qm1.UpdateWith(100)

		qm2 := NewQuantitativeMeasurements("test", 5)
		qm2.UpdateWith(1000)

		// Completely different ranges
		assert.False(t, valuesEqual(qm1, qm2))
	})

	t.Run("type mismatch returns false", func(t *testing.T) {
		qm := NewQuantitativeMeasurements("test", 5)
		assert.False(t, valuesEqual(qm, 100))
		assert.False(t, valuesEqual(100, qm))
	})
}

func TestIdentical(t *testing.T) {
	t.Run("nil candidate returns false", func(t *testing.T) {
		attack := makeAttack(map[string]any{"a": 1})
		assert.False(t, Identical(nil, attack))
	})

	t.Run("identical fingerprints return true", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1, "b": "foo"})
		attack2 := makeAttack(map[string]any{"a": 1, "b": "foo"})
		assert.True(t, Identical(attack1, attack2))
	})

	t.Run("different lengths return false", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1})
		attack2 := makeAttack(map[string]any{"a": 1, "b": 2})
		assert.False(t, Identical(attack1, attack2))
	})

	t.Run("different values return false", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1, "b": 2})
		attack2 := makeAttack(map[string]any{"a": 1, "b": 999})
		assert.False(t, Identical(attack1, attack2))
	})

	t.Run("same keys different order", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1, "b": 2, "c": 3})
		attack2 := makeAttack(map[string]any{"c": 3, "a": 1, "b": 2})
		assert.True(t, Identical(attack1, attack2))
	})

	t.Run("QuantitativeMeasurements comparison", func(t *testing.T) {
		qm1 := NewQuantitativeMeasurements("length", 5)
		qm1.UpdateWith(100)

		qm2 := NewQuantitativeMeasurements("length", 5)
		qm2.UpdateWith(100)

		attack1 := makeAttack(map[string]any{"length": qm1})
		attack2 := makeAttack(map[string]any{"length": qm2})

		assert.True(t, Identical(attack1, attack2))
	})
}

func TestSimilar(t *testing.T) {
	t.Run("doBreak superset of noBreak returns true", func(t *testing.T) {
		noBreak := makeAttack(map[string]any{"a": 1, "b": 2})
		doBreak := makeAttack(map[string]any{"a": 1, "b": 2, "c": 3})
		// doBreak contains all keys from noBreak with same values
		assert.True(t, Similar(noBreak, doBreak))
	})

	t.Run("exact match returns true", func(t *testing.T) {
		noBreak := makeAttack(map[string]any{"a": 1, "b": 2})
		doBreak := makeAttack(map[string]any{"a": 1, "b": 2})
		assert.True(t, Similar(noBreak, doBreak))
	})

	t.Run("missing key in doBreak returns false", func(t *testing.T) {
		noBreak := makeAttack(map[string]any{"a": 1, "b": 2})
		doBreak := makeAttack(map[string]any{"a": 1})
		// doBreak missing "b"
		assert.False(t, Similar(noBreak, doBreak))
	})

	t.Run("different value returns false", func(t *testing.T) {
		noBreak := makeAttack(map[string]any{"a": 1, "b": 2})
		doBreak := makeAttack(map[string]any{"a": 1, "b": 999})
		assert.False(t, Similar(noBreak, doBreak))
	})

	t.Run("empty noBreak returns true (subset of everything)", func(t *testing.T) {
		noBreak := makeAttack(map[string]any{})
		doBreak := makeAttack(map[string]any{"a": 1, "b": 2})
		assert.True(t, Similar(noBreak, doBreak))
	})

	t.Run("QuantitativeMeasurements with overlap", func(t *testing.T) {
		// For QuantileOverlap to return true with Factor=5:
		// compare[0] <= qm.GetQuantileTop(qm) && qm.GetQuantileTop(compare) >= qm[0]
		// Use identical values to ensure overlap
		qm1 := NewQuantitativeMeasurements("length", 5)
		qm1.UpdateWith(100)

		qm2 := NewQuantitativeMeasurements("length", 5)
		qm2.UpdateWith(100) // same value ensures overlap

		noBreak := makeAttack(map[string]any{"length": qm1})
		doBreak := makeAttack(map[string]any{"length": qm2})

		assert.True(t, Similar(noBreak, doBreak))
	})
}

func TestVerySimilar(t *testing.T) {
	t.Run("identical fingerprints return true", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1, "b": 2})
		attack2 := makeAttack(map[string]any{"a": 1, "b": 2})
		assert.True(t, VerySimilar(attack1, attack2))
	})

	t.Run("different lengths return false", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1})
		attack2 := makeAttack(map[string]any{"a": 1, "b": 2})
		assert.False(t, VerySimilar(attack1, attack2))
	})

	t.Run("input_reflections INCALCULABLE is ignored", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{
			"a":                 1,
			"input_reflections": int(ReflectType_INCALCULABLE),
		})
		attack2 := makeAttack(map[string]any{
			"a":                 1,
			"input_reflections": 5, // different value
		})
		// INCALCULABLE in attack1 causes input_reflections to be skipped
		assert.True(t, VerySimilar(attack1, attack2))
	})

	t.Run("input_reflections INCALCULABLE in second attack is ignored", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{
			"a":                 1,
			"input_reflections": 5,
		})
		attack2 := makeAttack(map[string]any{
			"a":                 1,
			"input_reflections": int(ReflectType_INCALCULABLE),
		})
		assert.True(t, VerySimilar(attack1, attack2))
	})

	t.Run("different non-INCALCULABLE input_reflections returns false", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{
			"a":                 1,
			"input_reflections": 3,
		})
		attack2 := makeAttack(map[string]any{
			"a":                 1,
			"input_reflections": 5,
		})
		assert.False(t, VerySimilar(attack1, attack2))
	})

	t.Run("missing key returns false", func(t *testing.T) {
		attack1 := makeAttack(map[string]any{"a": 1, "b": 2})
		attack2 := makeAttack(map[string]any{"a": 1, "c": 2})
		assert.False(t, VerySimilar(attack1, attack2))
	})
}

func TestSimilarIsh(t *testing.T) {
	t.Run("all identical returns true", func(t *testing.T) {
		fp := map[string]any{"a": 1, "b": 2}
		noBreakGroup := makeAttack(fp)
		breakGroup := makeAttack(fp)
		noBreak := makeAttack(fp)
		doBreak := makeAttack(fp)

		assert.True(t, SimilarIsh(noBreakGroup, breakGroup, noBreak, doBreak))
	})

	t.Run("INCALCULABLE input_reflections skipped", func(t *testing.T) {
		noBreakGroup := makeAttack(map[string]any{
			"a":                 1,
			"input_reflections": int(ReflectType_INCALCULABLE),
		})
		breakGroup := makeAttack(map[string]any{
			"a":                 1,
			"input_reflections": 5,
		})
		noBreak := makeAttack(map[string]any{"a": 1})
		doBreak := makeAttack(map[string]any{"a": 1})

		// input_reflections INCALCULABLE is skipped, only "a" compared
		assert.True(t, SimilarIsh(noBreakGroup, breakGroup, noBreak, doBreak))
	})

	t.Run("key in noBreakGroup but not breakGroup falls back to doBreak", func(t *testing.T) {
		noBreakGroup := makeAttack(map[string]any{"a": 1, "b": 2})
		breakGroup := makeAttack(map[string]any{"a": 1}) // missing "b"
		noBreak := makeAttack(map[string]any{"a": 1})
		doBreak := makeAttack(map[string]any{"a": 1, "b": 2}) // has "b" with same value

		// "b" not in breakGroup, falls back to comparing with doBreak
		assert.True(t, SimilarIsh(noBreakGroup, breakGroup, noBreak, doBreak))
	})

	t.Run("key in noBreakGroup but not breakGroup and doBreak differs returns false", func(t *testing.T) {
		noBreakGroup := makeAttack(map[string]any{"a": 1, "b": 2})
		breakGroup := makeAttack(map[string]any{"a": 1}) // missing "b"
		noBreak := makeAttack(map[string]any{"a": 1})
		doBreak := makeAttack(map[string]any{"a": 1, "b": 999}) // "b" has different value

		assert.False(t, SimilarIsh(noBreakGroup, breakGroup, noBreak, doBreak))
	})

	t.Run("key in breakGroup but not noBreakGroup falls back to noBreak", func(t *testing.T) {
		noBreakGroup := makeAttack(map[string]any{"a": 1}) // missing "c"
		breakGroup := makeAttack(map[string]any{"a": 1, "c": 3})
		noBreak := makeAttack(map[string]any{"a": 1, "c": 3}) // has "c" with same value
		doBreak := makeAttack(map[string]any{"a": 1})

		assert.True(t, SimilarIsh(noBreakGroup, breakGroup, noBreak, doBreak))
	})

	t.Run("key in breakGroup but not noBreakGroup and noBreak differs returns false", func(t *testing.T) {
		noBreakGroup := makeAttack(map[string]any{"a": 1}) // missing "c"
		breakGroup := makeAttack(map[string]any{"a": 1, "c": 3})
		noBreak := makeAttack(map[string]any{"a": 1, "c": 999}) // "c" has different value
		doBreak := makeAttack(map[string]any{"a": 1})

		assert.False(t, SimilarIsh(noBreakGroup, breakGroup, noBreak, doBreak))
	})

	t.Run("values differ between noBreakGroup and breakGroup", func(t *testing.T) {
		noBreakGroup := makeAttack(map[string]any{"a": 1})
		breakGroup := makeAttack(map[string]any{"a": 999}) // different value
		noBreak := makeAttack(map[string]any{"a": 1})
		doBreak := makeAttack(map[string]any{"a": 1})

		assert.False(t, SimilarIsh(noBreakGroup, breakGroup, noBreak, doBreak))
	})
}
