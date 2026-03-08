package module

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
)

// mockTask implements queue.TaskInfo for testing
type mockTask struct {
	hash     uint64
	priority uint8
	baseURL  []byte
	desc     string
}

func newMockTask(baseURL string) *mockTask {
	return &mockTask{
		hash:     uint64(len(baseURL)),
		priority: 10,
		baseURL:  []byte(baseURL),
		desc:     "mock task for " + baseURL,
	}
}

func (m *mockTask) Hash() uint64        { return m.hash }
func (m *mockTask) Priority() uint8     { return m.priority }
func (m *mockTask) Depth() uint16       { return 0 }
func (m *mockTask) FullURL() []byte     { return m.baseURL }
func (m *mockTask) Extension() string   { return "" }
func (m *mockTask) Description() string { return m.desc }
func (m *mockTask) IsFromSpider() bool  { return false }
func (m *mockTask) FoundByName() string { return "mock" }

var _ queue.TaskInfo = (*mockTask)(nil)

// blockingModule blocks tasks based on path
type blockingModule struct {
	*mockModule
	blockPrefix string
}

func (m *blockingModule) ShouldAddTask(task queue.TaskInfo) bool {
	baseURL := string(task.FullURL())
	if m.blockPrefix != "" && len(baseURL) >= len(m.blockPrefix) {
		if baseURL[:len(m.blockPrefix)] == m.blockPrefix {
			return false
		}
	}
	return true
}

func TestTaskFilter_ShouldAdd(t *testing.T) {
	t.Run("allows task with no patterns", func(t *testing.T) {
		filter := NewTaskFilter(nil, nil)
		task := newMockTask("/any/path")

		assert.True(t, filter.ShouldAdd(task))
	})

	t.Run("blocks task matching pattern", func(t *testing.T) {
		filter := NewTaskFilter(nil, nil)
		require.NoError(t, filter.AddBlockPattern(".*/css/.*"))

		task := newMockTask("/static/css/main.css")
		assert.False(t, filter.ShouldAdd(task))
	})

	t.Run("allows task not matching pattern", func(t *testing.T) {
		filter := NewTaskFilter(nil, nil)
		require.NoError(t, filter.AddBlockPattern(".*/css/.*"))

		task := newMockTask("/api/users")
		assert.True(t, filter.ShouldAdd(task))
	})

	t.Run("module blocks task", func(t *testing.T) {
		r := NewRegistry()
		blocker := &blockingModule{
			mockModule:  newMockModule("blocker", 10, true),
			blockPrefix: "/blocked/",
		}
		r.Register(blocker)

		filter := NewTaskFilter(r, nil)
		task := newMockTask("/blocked/path")

		assert.False(t, filter.ShouldAdd(task))
	})
}

func TestTaskFilter_AddBlockPattern(t *testing.T) {
	t.Run("adds valid pattern", func(t *testing.T) {
		filter := NewTaskFilter(nil, nil)

		err := filter.AddBlockPattern(".*/css/.*")

		require.NoError(t, err)
		assert.True(t, filter.HasBlockPattern(".*/css/.*"))
	})

	t.Run("returns error for invalid regex", func(t *testing.T) {
		filter := NewTaskFilter(nil, nil)

		err := filter.AddBlockPattern("[invalid")

		assert.Error(t, err)
	})
}

func TestTaskFilter_RemoveBlockPattern(t *testing.T) {
	filter := NewTaskFilter(nil, nil)
	_ = filter.AddBlockPattern(".*/css/.*")

	filter.RemoveBlockPattern(".*/css/.*")

	assert.False(t, filter.HasBlockPattern(".*/css/.*"))
}

func TestTaskFilter_ClearBlockPatterns(t *testing.T) {
	filter := NewTaskFilter(nil, nil)
	_ = filter.AddBlockPattern(".*/css/.*")
	_ = filter.AddBlockPattern(".*/js/.*")

	filter.ClearBlockPatterns()

	assert.Equal(t, 0, filter.BlockPatternCount())
}

func TestTaskFilter_BlockPatternCount(t *testing.T) {
	filter := NewTaskFilter(nil, nil)

	assert.Equal(t, 0, filter.BlockPatternCount())

	_ = filter.AddBlockPattern(".*/css/.*")
	_ = filter.AddBlockPattern(".*/js/.*")

	assert.Equal(t, 2, filter.BlockPatternCount())
}

func TestTaskFilter_GetBlockPatterns(t *testing.T) {
	filter := NewTaskFilter(nil, nil)
	_ = filter.AddBlockPattern(".*/css/.*")
	_ = filter.AddBlockPattern(".*/js/.*")

	patterns := filter.GetBlockPatterns()

	assert.Len(t, patterns, 2)
	assert.Contains(t, patterns, ".*/css/.*")
	assert.Contains(t, patterns, ".*/js/.*")
}

func TestTaskFilter_IsBlocked(t *testing.T) {
	filter := NewTaskFilter(nil, nil)
	_ = filter.AddBlockPattern(".*/css/.*")

	tests := []struct {
		path     string
		expected bool
	}{
		{"/static/css/main.css", true},
		{"/css/styles.css", true},
		{"/api/users", false},
		{"/styles/main.js", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expected, filter.IsBlocked(tt.path))
		})
	}
}

func TestTaskFilter_MultiplePatterns(t *testing.T) {
	filter := NewTaskFilter(nil, nil)
	_ = filter.AddBlockPattern(".*/css/.*")
	_ = filter.AddBlockPattern(".*/images/.*")
	_ = filter.AddBlockPattern(".*/fonts/.*")

	tests := []struct {
		path     string
		expected bool
	}{
		{"/static/css/main.css", false},    // blocked
		{"/media/images/logo.png", false},  // blocked
		{"/assets/fonts/arial.ttf", false}, // blocked
		{"/api/users", true},               // allowed
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			task := newMockTask(tt.path)
			assert.Equal(t, tt.expected, filter.ShouldAdd(task))
		})
	}
}

func TestTaskFilter_ModuleBeforePatterns(t *testing.T) {
	// Module blocking should be checked before pattern blocking
	r := NewRegistry()
	blocker := &blockingModule{
		mockModule:  newMockModule("blocker", 10, true),
		blockPrefix: "/module/",
	}
	r.Register(blocker)

	filter := NewTaskFilter(r, nil)
	_ = filter.AddBlockPattern(".*/pattern/.*")

	// Module should block this
	task1 := newMockTask("/module/path")
	assert.False(t, filter.ShouldAdd(task1))

	// Pattern should block this
	task2 := newMockTask("/pattern/path")
	assert.False(t, filter.ShouldAdd(task2))
}

func TestTaskFilter_ConcurrentAccess(t *testing.T) {
	filter := NewTaskFilter(nil, nil)
	const numGoroutines = 10
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3)

	// Concurrent pattern adds
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = filter.AddBlockPattern(".*pattern" + string(rune('A'+id)) + ".*")
			}
		}(i)
	}

	// Concurrent ShouldAdd checks
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				task := newMockTask("/test/path")
				filter.ShouldAdd(task)
			}
		}()
	}

	// Concurrent IsBlocked checks
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				filter.IsBlocked("/test/patternA/path")
			}
		}()
	}

	wg.Wait()
	// Verify no panics
	assert.GreaterOrEqual(t, filter.BlockPatternCount(), 1)
}

func TestTaskFilter_DisabledModule(t *testing.T) {
	r := NewRegistry()
	blocker := &blockingModule{
		mockModule:  newMockModule("blocker", 10, false), // disabled
		blockPrefix: "/blocked/",
	}
	r.Register(blocker)

	filter := NewTaskFilter(r, nil)
	task := newMockTask("/blocked/path")

	// Disabled module should not block
	assert.True(t, filter.ShouldAdd(task))
}

func TestTaskFilter_NilRegistry(t *testing.T) {
	filter := NewTaskFilter(nil, nil)
	_ = filter.AddBlockPattern(".*/css/.*")

	// Should still work with patterns
	task1 := newMockTask("/css/main.css")
	assert.False(t, filter.ShouldAdd(task1))

	task2 := newMockTask("/api/users")
	assert.True(t, filter.ShouldAdd(task2))
}
