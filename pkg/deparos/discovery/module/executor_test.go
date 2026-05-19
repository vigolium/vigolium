package module

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// resultModule returns predefined results
type resultModule struct {
	*mockModule
	dirResult  *ModuleResult
	fileResult *ModuleResult
	dirErr     error
	fileErr    error
}

func (m *resultModule) OnDirectoryMatch(ctx context.Context, event *DirectoryEvent) (*ModuleResult, error) {
	return m.dirResult, m.dirErr
}

func (m *resultModule) OnFileMatch(ctx context.Context, event *FileEvent) (*ModuleResult, error) {
	return m.fileResult, m.fileErr
}

func newResultModule(name string, priority int, enabled bool, patterns []Pattern) *resultModule {
	return &resultModule{
		mockModule: &mockModule{
			name:     name,
			priority: priority,
			enabled:  enabled,
			patterns: patterns,
		},
	}
}

func TestExecutor_ExecuteDirectory(t *testing.T) {
	t.Run("returns nil for nil registry", func(t *testing.T) {
		executor := NewExecutor(nil, nil, nil)

		result, err := executor.ExecuteDirectory(context.Background(), &DirectoryEvent{
			Path: "/test/path",
		})

		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("returns nil when no modules match", func(t *testing.T) {
		r := NewRegistry()
		m := newResultModule("test", 10, true, []Pattern{
			NewPattern(PatternPathSuffix, "/other/"),
		})
		r.Register(m)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteDirectory(context.Background(), &DirectoryEvent{
			Path: "/test/path/",
		})

		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("executes matching module", func(t *testing.T) {
		r := NewRegistry()
		m := newResultModule("test", 10, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m.dirResult = &ModuleResult{
			StopRecursion: true,
		}
		r.Register(m)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteDirectory(context.Background(), &DirectoryEvent{
			Path: "/test/path/",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.StopRecursion)
	})

	t.Run("merges results from multiple modules", func(t *testing.T) {
		r := NewRegistry()

		m1 := newResultModule("mod1", 10, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m1.dirResult = &ModuleResult{
			StopRecursion: true,
		}

		m2 := newResultModule("mod2", 20, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m2.dirResult = &ModuleResult{
			Tasks: []TaskSpec{
				{WordlistSource: config.WordlistObservedNames, Priority: 5},
			},
		}

		r.Register(m1)
		r.Register(m2)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteDirectory(context.Background(), &DirectoryEvent{
			Path: "/test/path/",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.StopRecursion)
		require.Len(t, result.Tasks, 1)
		assert.Equal(t, uint8(5), result.Tasks[0].Priority)
	})

	t.Run("stops processing when requested", func(t *testing.T) {
		r := NewRegistry()

		m1 := newResultModule("stopper", 10, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m1.dirResult = &ModuleResult{
			StopRecursion:  true,
			StopProcessing: true,
		}

		m2 := newResultModule("skipped", 20, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m2.dirResult = &ModuleResult{
			Tasks: []TaskSpec{
				{WordlistSource: config.WordlistObservedNames, Priority: 99},
			},
		}

		r.Register(m1)
		r.Register(m2)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteDirectory(context.Background(), &DirectoryEvent{
			Path: "/test/path/",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.StopRecursion)
		// m2 should not have executed
		assert.Empty(t, result.Tasks)
	})

	t.Run("continues on module error", func(t *testing.T) {
		r := NewRegistry()

		m1 := newResultModule("error", 10, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m1.dirErr = errors.New("module error")

		m2 := newResultModule("success", 20, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m2.dirResult = &ModuleResult{
			SkipDefaultLogic: true,
		}

		r.Register(m1)
		r.Register(m2)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteDirectory(context.Background(), &DirectoryEvent{
			Path: "/test/path/",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.SkipDefaultLogic)
	})

	t.Run("registers block patterns with filter", func(t *testing.T) {
		r := NewRegistry()
		filter := NewTaskFilter(nil, nil)

		m := newResultModule("blocker", 10, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m.dirResult = &ModuleResult{
			BlockTaskPatterns: []string{".*/css/.*", ".*/images/.*"},
		}
		r.Register(m)

		executor := NewExecutor(r, filter, nil)

		_, err := executor.ExecuteDirectory(context.Background(), &DirectoryEvent{
			Path: "/test/path/",
		})

		require.NoError(t, err)
		assert.Equal(t, 2, filter.BlockPatternCount())
		assert.True(t, filter.HasBlockPattern(".*/css/.*"))
		assert.True(t, filter.HasBlockPattern(".*/images/.*"))
	})
}

func TestExecutor_ExecuteFile(t *testing.T) {
	t.Run("returns nil for nil registry", func(t *testing.T) {
		executor := NewExecutor(nil, nil, nil)

		result, err := executor.ExecuteFile(context.Background(), &FileEvent{
			Path: "/test/file.js",
		})

		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("returns nil when no modules match", func(t *testing.T) {
		r := NewRegistry()
		m := newResultModule("test", 10, true, []Pattern{
			NewFilePattern(PatternFileExtension, ".css"),
		})
		r.Register(m)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteFile(context.Background(), &FileEvent{
			Path: "/test/file.js",
		})

		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("executes matching file module", func(t *testing.T) {
		r := NewRegistry()
		m := newResultModule("js", 10, true, []Pattern{
			NewFilePattern(PatternFileExtension, ".js"),
		})
		m.fileResult = &ModuleResult{
			SkipDefaultLogic: true,
		}
		r.Register(m)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteFile(context.Background(), &FileEvent{
			Path: "/scripts/app.js",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.SkipDefaultLogic)
	})

	t.Run("merges multiple file module results", func(t *testing.T) {
		r := NewRegistry()

		m1 := newResultModule("js", 10, true, []Pattern{
			NewFilePattern(PatternFileExtension, ".js"),
		})
		m1.fileResult = &ModuleResult{
			BlockTaskPatterns: []string{".*/vendor/.*"},
		}

		m2 := newResultModule("admin", 20, true, []Pattern{
			NewPattern(PatternPathContains, "admin"),
		})
		m2.fileResult = &ModuleResult{
			SkipDefaultLogic: true,
		}

		r.Register(m1)
		r.Register(m2)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteFile(context.Background(), &FileEvent{
			Path: "/admin/scripts/app.js",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.BlockTaskPatterns, ".*/vendor/.*")
		assert.True(t, result.SkipDefaultLogic)
	})

	t.Run("continues on file module error", func(t *testing.T) {
		r := NewRegistry()

		m1 := newResultModule("error", 10, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m1.fileErr = errors.New("file error")

		m2 := newResultModule("success", 20, true, []Pattern{
			NewPattern(PatternPathContains, "test"),
		})
		m2.fileResult = &ModuleResult{
			StopRecursion: true,
		}

		r.Register(m1)
		r.Register(m2)

		executor := NewExecutor(r, nil, nil)

		result, err := executor.ExecuteFile(context.Background(), &FileEvent{
			Path: "/test/file.txt",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.StopRecursion)
	})
}

func TestExecutor_HasModules(t *testing.T) {
	t.Run("returns false for nil registry", func(t *testing.T) {
		executor := NewExecutor(nil, nil, nil)
		assert.False(t, executor.HasModules())
	})

	t.Run("returns false for empty registry", func(t *testing.T) {
		r := NewRegistry()
		executor := NewExecutor(r, nil, nil)
		assert.False(t, executor.HasModules())
	})

	t.Run("returns true with registered modules", func(t *testing.T) {
		r := NewRegistry()
		r.Register(newMockModule("test", 10, true))
		executor := NewExecutor(r, nil, nil)
		assert.True(t, executor.HasModules())
	})
}

func TestExecutor_HasEnabledModules(t *testing.T) {
	t.Run("returns false for nil registry", func(t *testing.T) {
		executor := NewExecutor(nil, nil, nil)
		assert.False(t, executor.HasEnabledModules())
	})

	t.Run("returns false when all disabled", func(t *testing.T) {
		r := NewRegistry()
		r.Register(newMockModule("test", 10, false))
		executor := NewExecutor(r, nil, nil)
		assert.False(t, executor.HasEnabledModules())
	})

	t.Run("returns true with enabled module", func(t *testing.T) {
		r := NewRegistry()
		r.Register(newMockModule("test", 10, true))
		executor := NewExecutor(r, nil, nil)
		assert.True(t, executor.HasEnabledModules())
	})
}

func TestExecutor_Registry(t *testing.T) {
	r := NewRegistry()
	executor := NewExecutor(r, nil, nil)
	assert.Same(t, r, executor.Registry())
}

func TestExecutor_Filter(t *testing.T) {
	filter := NewTaskFilter(nil, nil)
	executor := NewExecutor(nil, filter, nil)
	assert.Same(t, filter, executor.Filter())
}
