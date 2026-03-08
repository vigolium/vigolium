package module

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
)

// mockModule implements Module for testing
type mockModule struct {
	name     string
	desc     string
	priority int
	enabled  bool
	patterns []Pattern
	result   *ModuleResult
}

func newMockModule(name string, priority int, enabled bool) *mockModule {
	return &mockModule{
		name:     name,
		priority: priority,
		enabled:  enabled,
	}
}

func (m *mockModule) Name() string            { return m.name }
func (m *mockModule) Description() string     { return m.desc }
func (m *mockModule) Priority() int           { return m.priority }
func (m *mockModule) Enabled() bool           { return m.enabled }
func (m *mockModule) Patterns() []Pattern     { return m.patterns }
func (m *mockModule) SetEnabled(enabled bool) { m.enabled = enabled }
func (m *mockModule) SetPatterns(p []Pattern) { m.patterns = p }

func (m *mockModule) OnDirectoryMatch(_ context.Context, _ *DirectoryEvent) (*ModuleResult, error) {
	return m.result, nil
}

func (m *mockModule) OnFileMatch(_ context.Context, _ *FileEvent) (*ModuleResult, error) {
	return m.result, nil
}

func (m *mockModule) ShouldAddTask(_ queue.TaskInfo) bool {
	return true
}

var _ Module = (*mockModule)(nil)

func TestRegistry_Register(t *testing.T) {
	t.Run("registers new module", func(t *testing.T) {
		r := NewRegistry()
		m := newMockModule("test", 10, true)

		ok := r.Register(m)

		assert.True(t, ok)
		assert.Equal(t, 1, r.Count())
	})

	t.Run("rejects duplicate name", func(t *testing.T) {
		r := NewRegistry()
		m1 := newMockModule("test", 10, true)
		m2 := newMockModule("test", 20, true)

		r.Register(m1)
		ok := r.Register(m2)

		assert.False(t, ok)
		assert.Equal(t, 1, r.Count())
	})
}

func TestRegistry_Unregister(t *testing.T) {
	t.Run("unregisters existing module", func(t *testing.T) {
		r := NewRegistry()
		r.Register(newMockModule("test", 10, true))

		ok := r.Unregister("test")

		assert.True(t, ok)
		assert.Equal(t, 0, r.Count())
	})

	t.Run("returns false for non-existent", func(t *testing.T) {
		r := NewRegistry()

		ok := r.Unregister("nonexistent")

		assert.False(t, ok)
	})
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	m := newMockModule("test", 10, true)
	r.Register(m)

	t.Run("gets existing module", func(t *testing.T) {
		got, ok := r.Get("test")
		assert.True(t, ok)
		assert.Equal(t, m, got)
	})

	t.Run("returns false for non-existent", func(t *testing.T) {
		_, ok := r.Get("nonexistent")
		assert.False(t, ok)
	})
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()
	r.Register(newMockModule("high", 100, true))
	r.Register(newMockModule("low", 10, true))
	r.Register(newMockModule("mid", 50, false))

	modules := r.All()

	require.Len(t, modules, 3)
	// Should be sorted by priority
	assert.Equal(t, "low", modules[0].Name())
	assert.Equal(t, "mid", modules[1].Name())
	assert.Equal(t, "high", modules[2].Name())
}

func TestRegistry_Enabled(t *testing.T) {
	r := NewRegistry()
	r.Register(newMockModule("enabled1", 100, true))
	r.Register(newMockModule("disabled", 10, false))
	r.Register(newMockModule("enabled2", 50, true))

	modules := r.Enabled()

	require.Len(t, modules, 2)
	// Should be sorted by priority, only enabled
	assert.Equal(t, "enabled2", modules[0].Name())
	assert.Equal(t, "enabled1", modules[1].Name())
}

func TestRegistry_MatchDirectory(t *testing.T) {
	r := NewRegistry()

	// Module matching /css/
	cssModule := newMockModule("css", 10, true)
	cssModule.SetPatterns([]Pattern{NewPattern(PatternPathSuffix, "/css/")})
	r.Register(cssModule)

	// Module matching /api/
	apiModule := newMockModule("api", 20, true)
	apiModule.SetPatterns([]Pattern{NewPattern(PatternPathPrefix, "/api/")})
	r.Register(apiModule)

	// Disabled module
	disabled := newMockModule("disabled", 5, false)
	disabled.SetPatterns([]Pattern{NewPattern(PatternPathContains, "static")})
	r.Register(disabled)

	t.Run("matches css directory", func(t *testing.T) {
		matches := r.MatchDirectory("/static/css/")
		require.Len(t, matches, 1)
		assert.Equal(t, "css", matches[0].Name())
	})

	t.Run("matches api directory", func(t *testing.T) {
		matches := r.MatchDirectory("/api/v1/users")
		require.Len(t, matches, 1)
		assert.Equal(t, "api", matches[0].Name())
	})

	t.Run("no matches", func(t *testing.T) {
		matches := r.MatchDirectory("/users/profile")
		assert.Empty(t, matches)
	})

	t.Run("skips disabled modules", func(t *testing.T) {
		matches := r.MatchDirectory("/static/images/")
		assert.Empty(t, matches)
	})
}

func TestRegistry_MatchFile(t *testing.T) {
	r := NewRegistry()

	jsModule := newMockModule("js", 10, true)
	jsModule.SetPatterns([]Pattern{NewPattern(PatternFileExtension, ".js")})
	r.Register(jsModule)

	matches := r.MatchFile("/scripts/app.js")

	require.Len(t, matches, 1)
	assert.Equal(t, "js", matches[0].Name())
}

func TestRegistry_Names(t *testing.T) {
	r := NewRegistry()
	r.Register(newMockModule("first", 10, true))
	r.Register(newMockModule("second", 20, true))

	names := r.Names()

	assert.Equal(t, []string{"first", "second"}, names)
}

func TestRegistry_EnableDisable(t *testing.T) {
	// Note: Enable/Disable only work with *BaseModule type
	// For mockModule, these will return false
	r := NewRegistry()
	base := NewBaseModule("test", "desc", 10, nil)
	r.Register(base)

	t.Run("enable works with BaseModule", func(t *testing.T) {
		base.SetEnabled(false)
		ok := r.Enable("test")
		assert.True(t, ok)
		assert.True(t, base.Enabled())
	})

	t.Run("disable works with BaseModule", func(t *testing.T) {
		ok := r.Disable("test")
		assert.True(t, ok)
		assert.False(t, base.Enabled())
	})
}

func TestRegistry_EnableOnly(t *testing.T) {
	r := NewRegistry()
	m1 := NewBaseModule("m1", "", 10, nil)
	m2 := NewBaseModule("m2", "", 20, nil)
	m3 := NewBaseModule("m3", "", 30, nil)
	r.Register(m1)
	r.Register(m2)
	r.Register(m3)

	r.EnableOnly([]string{"m1", "m3"})

	assert.True(t, m1.Enabled())
	assert.False(t, m2.Enabled())
	assert.True(t, m3.Enabled())
}

func TestRegistry_DisableAll(t *testing.T) {
	r := NewRegistry()
	m1 := NewBaseModule("m1", "", 10, nil)
	m2 := NewBaseModule("m2", "", 20, nil)
	r.Register(m1)
	r.Register(m2)

	r.DisableAll()

	assert.False(t, m1.Enabled())
	assert.False(t, m2.Enabled())
}

func TestRegistry_EnableAll(t *testing.T) {
	r := NewRegistry()
	m1 := NewBaseModule("m1", "", 10, nil)
	m2 := NewBaseModule("m2", "", 20, nil)
	m1.SetEnabled(false)
	m2.SetEnabled(false)
	r.Register(m1)
	r.Register(m2)

	r.EnableAll()

	assert.True(t, m1.Enabled())
	assert.True(t, m2.Enabled())
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	const numGoroutines = 10
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3)

	// Concurrent registrations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				m := newMockModule("mod-"+string(rune('A'+id))+string(rune('0'+j%10)), id*10+j, true)
				r.Register(m)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = r.All()
				_ = r.Enabled()
				_ = r.Count()
			}
		}()
	}

	// Concurrent matches
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = r.MatchDirectory("/test/path")
				_ = r.MatchFile("/test/file.js")
			}
		}()
	}

	wg.Wait()
	// Just verify no panics or data races
	assert.GreaterOrEqual(t, r.Count(), 1)
}
