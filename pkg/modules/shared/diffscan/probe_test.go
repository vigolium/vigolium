package diffscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProbe(t *testing.T) {
	t.Run("valid creation with break strings", func(t *testing.T) {
		probe := NewProbe("test", 1, "a", "b", "c")
		assert.Equal(t, "test", probe.Name)
		assert.Equal(t, 1, probe.Severity)
		assert.Equal(t, "'", probe.Base)
	})

	t.Run("default values", func(t *testing.T) {
		probe := NewProbe("test", 5, "break")
		assert.True(t, probe.RandomAnchor)
		assert.False(t, probe.UseCacheBuster)
		assert.Equal(t, InjectType_Append, probe.InjectType)
	})

	t.Run("panic on empty breakStrings", func(t *testing.T) {
		assert.Panics(t, func() {
			NewProbe("test", 1)
		})
	})
}

func TestProbePayloadCycling(t *testing.T) {
	t.Run("break payload cycling", func(t *testing.T) {
		probe := NewProbe("test", 1, "a", "b", "c")

		// First 3 calls return payloads in order
		assert.Equal(t, "a", probe.GetNextBreakPayload())
		assert.Equal(t, "b", probe.GetNextBreakPayload())
		assert.Equal(t, "c", probe.GetNextBreakPayload())
		// After 3 calls, wraps around (modulo behavior)
		assert.Equal(t, "a", probe.GetNextBreakPayload())
		assert.Equal(t, "b", probe.GetNextBreakPayload())
	})

	t.Run("escape payload set cycling", func(t *testing.T) {
		probe := NewProbe("test", 1, "break")
		probe.AddEscapePair("x", "y")
		probe.AddEscapePair("z")

		// First 2 calls return escape pairs in order
		assert.Equal(t, []string{"x", "y"}, probe.GetNextEscapePayloadSet())
		assert.Equal(t, []string{"z"}, probe.GetNextEscapePayloadSet())
		// Wraps around
		assert.Equal(t, []string{"x", "y"}, probe.GetNextEscapePayloadSet())
	})
}

func TestProbeEscapeStrings(t *testing.T) {
	t.Run("SetEscapeStrings wraps each arg in single-element slice", func(t *testing.T) {
		probe := NewProbe("test", 1, "break")
		probe.SetEscapeStrings("a", "b", "c")

		escapes := probe.GetEscapeStrings()
		require.Len(t, escapes, 3)
		assert.Equal(t, []string{"a"}, escapes[0])
		assert.Equal(t, []string{"b"}, escapes[1])
		assert.Equal(t, []string{"c"}, escapes[2])
	})

	t.Run("AddEscapePair adds multi-element escape pair", func(t *testing.T) {
		probe := NewProbe("test", 1, "break")
		probe.AddEscapePair("x", "y", "z")

		escapes := probe.GetEscapeStrings()
		require.Len(t, escapes, 1)
		assert.Equal(t, []string{"x", "y", "z"}, escapes[0])
	})

	t.Run("combined SetEscapeStrings and AddEscapePair", func(t *testing.T) {
		probe := NewProbe("test", 1, "break")
		probe.SetEscapeStrings("a", "b")
		probe.AddEscapePair("x", "y")

		escapes := probe.GetEscapeStrings()
		require.Len(t, escapes, 3)
		assert.Equal(t, []string{"a"}, escapes[0])
		assert.Equal(t, []string{"b"}, escapes[1])
		assert.Equal(t, []string{"x", "y"}, escapes[2])
	})
}

func TestProbeSettings(t *testing.T) {
	t.Run("SetRandomAnchor(false) sets UseCacheBuster=true", func(t *testing.T) {
		probe := NewProbe("test", 1, "break")
		probe.SetRandomAnchor(false)

		assert.False(t, probe.RandomAnchor)
		assert.True(t, probe.UseCacheBuster)
	})

	t.Run("SetRandomAnchor(true) sets UseCacheBuster=false", func(t *testing.T) {
		probe := NewProbe("test", 1, "break")
		// Set to false first, then back to true
		probe.SetRandomAnchor(false)
		probe.SetRandomAnchor(true)

		assert.True(t, probe.RandomAnchor)
		assert.False(t, probe.UseCacheBuster)
	})

	t.Run("SetUseCacheBuster independent setting", func(t *testing.T) {
		probe := NewProbe("test", 1, "break")
		probe.SetUseCacheBuster(true)

		assert.True(t, probe.UseCacheBuster)
		// RandomAnchor unchanged
		assert.True(t, probe.RandomAnchor)
	})
}
