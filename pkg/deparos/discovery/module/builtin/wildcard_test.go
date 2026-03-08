package builtin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/module"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
)

// mockTask implements queue.TaskInfo for testing
type mockTask struct {
	hash     uint64
	priority uint8
	baseURL  []byte
	desc     string
}

func (m *mockTask) Hash() uint64        { return m.hash }
func (m *mockTask) Priority() uint8     { return m.priority }
func (m *mockTask) Depth() uint16       { return 0 }
func (m *mockTask) FullURL() []byte     { return m.baseURL }
func (m *mockTask) Description() string { return m.desc }
func (m *mockTask) Extension() string   { return "" }
func (m *mockTask) IsFromSpider() bool  { return false }
func (m *mockTask) FoundByName() string { return "mock" }

var _ queue.TaskInfo = (*mockTask)(nil)

func TestWildcardModule_New(t *testing.T) {
	m := NewWildcardModule()

	assert.Equal(t, "wildcard", m.Name())
	assert.Equal(t, 5, m.Priority())
	assert.True(t, m.Enabled())
	assert.NotNil(t, m.Patterns())
}

func TestWildcardModule_OnDirectoryMatch_NoPrefix(t *testing.T) {
	m := NewWildcardModule()

	// First path - no common prefix yet
	result, err := m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
		Path: "/admin",
		URL:  "http://example.com/admin",
	})

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestWildcardModule_OnDirectoryMatch_DetectsWildcard(t *testing.T) {
	m := NewWildcardModule()
	m.SetThreshold(3) // Need 3 paths with same prefix

	// Simulate discovering paths with common prefix
	// Use paths where common prefix is SHORTER than each path
	// e.g., /admin123 vs /admin456 -> common prefix /admin
	paths := []string{"/admin123", "/admin456", "/admin789", "/adminabc"}

	var result *module.ModuleResult
	var err error

	for _, path := range paths {
		result, err = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
			Path: path,
			URL:  "http://example.com" + path,
		})
		require.NoError(t, err)
	}

	// After threshold, should detect wildcard
	require.NotNil(t, result)
	assert.True(t, result.StopRecursion)
	assert.True(t, result.SkipDefaultLogic)
	assert.NotEmpty(t, result.BlockTaskPatterns)
}

func TestWildcardModule_OnDirectoryMatch_WithQueueCleanup(t *testing.T) {
	m := NewWildcardModule()
	m.SetThreshold(3)

	// Use paths where common prefix is shorter than each path
	paths := []string{"/admin123", "/admin456", "/admin789", "/adminabc"}

	var result *module.ModuleResult
	for _, path := range paths {
		result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
			Path: path,
			URL:  "http://example.com" + path,
		})
	}

	// Result should contain QueueCleanup request for engine to handle
	require.NotNil(t, result)
	require.NotNil(t, result.QueueCleanup)
	assert.Equal(t, module.QueueActionRemoveKeepOne, result.QueueCleanup.Action)
	assert.Contains(t, result.QueueCleanup.Pattern, "/admin")
}

func TestWildcardModule_ShouldAddTask(t *testing.T) {
	t.Run("allows task when no wildcards detected", func(t *testing.T) {
		m := NewWildcardModule()

		task := &mockTask{baseURL: []byte("/users/123")}
		assert.True(t, m.ShouldAddTask(task))
	})

	t.Run("blocks task matching wildcard prefix", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Detect wildcard - use paths where common prefix is shorter than each
		paths := []string{"/admin123", "/admin456", "/admin789", "/adminabc"}
		for _, path := range paths {
			_, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: path,
				URL:  "http://example.com" + path,
			})
		}

		// Now try to add a task with matching prefix
		task := &mockTask{baseURL: []byte("/admintest")}
		assert.False(t, m.ShouldAddTask(task))
	})

	t.Run("allows task not matching any wildcard", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Detect wildcard for /admin
		paths := []string{"/admin123", "/admin456", "/admin789", "/adminabc"}
		for _, path := range paths {
			_, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: path,
				URL:  "http://example.com" + path,
			})
		}

		// Task with different prefix should be allowed
		task := &mockTask{baseURL: []byte("/users/test")}
		assert.True(t, m.ShouldAddTask(task))
	})
}

func TestWildcardModule_SetThreshold(t *testing.T) {
	m := NewWildcardModule()
	m.SetThreshold(5)

	// Need 5 paths now
	paths := []string{"/test", "/testx", "/testy"}

	var result *module.ModuleResult
	for _, path := range paths {
		result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
			Path: path,
			URL:  "http://example.com" + path,
		})
	}

	// Should not detect wildcard with only 3 paths
	assert.Nil(t, result)
}

func TestWildcardModule_GetWildcardPrefixes(t *testing.T) {
	m := NewWildcardModule()
	m.SetThreshold(3)

	// Initially empty
	assert.Empty(t, m.GetWildcardPrefixes())

	// Detect wildcard - use paths where common prefix is shorter
	paths := []string{"/admin123", "/admin456", "/admin789", "/adminabc"}
	for _, path := range paths {
		_, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
			Path: path,
			URL:  "http://example.com" + path,
		})
	}

	prefixes := m.GetWildcardPrefixes()
	assert.NotEmpty(t, prefixes)
	assert.Contains(t, prefixes, "/admin")
}

func TestWildcardModule_Stats(t *testing.T) {
	m := NewWildcardModule()
	m.SetThreshold(3)

	prefixCount, wildcardCount := m.Stats()
	assert.Equal(t, 0, prefixCount)
	assert.Equal(t, 0, wildcardCount)

	// Add some paths - use paths where common prefix is shorter
	paths := []string{"/admin123", "/admin456", "/admin789", "/adminabc"}
	for _, path := range paths {
		_, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
			Path: path,
			URL:  "http://example.com" + path,
		})
	}

	prefixCount, wildcardCount = m.Stats()
	assert.GreaterOrEqual(t, prefixCount, 1)
	assert.GreaterOrEqual(t, wildcardCount, 1)
}

func TestWildcardModule_MultipleWildcardPrefixes(t *testing.T) {
	m := NewWildcardModule()
	m.SetThreshold(3)

	// Detect first wildcard: /admin - use paths where common prefix is shorter
	adminPaths := []string{"/admin123", "/admin456", "/admin789", "/adminabc"}
	for _, path := range adminPaths {
		_, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
			Path: path,
			URL:  "http://example.com" + path,
		})
	}

	// Detect second wildcard: /test - use paths where common prefix is shorter
	testPaths := []string{"/test123", "/test456", "/test789", "/testabc"}
	for _, path := range testPaths {
		_, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
			Path: path,
			URL:  "http://example.com" + path,
		})
	}

	prefixes := m.GetWildcardPrefixes()
	assert.GreaterOrEqual(t, len(prefixes), 1)

	// /admin prefix should be blocked
	adminTask := &mockTask{baseURL: []byte("/admintest")}
	assert.False(t, m.ShouldAddTask(adminTask))
}

// Deep path tests - covers edge cases with nested paths like /v1/v2/v3/v4
func TestWildcardModule_DeepPaths(t *testing.T) {
	t.Run("deep nested paths with short final segment - no match", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Paths like /v1/v2/v3/v4a, /v1/v2/v3/v4b have common prefix "v4" which is only 2 chars
		// Since common prefix < 3 chars, no wildcard is detected
		paths := []string{"/v1/v2/v3/v4a", "/v1/v2/v3/v4b", "/v1/v2/v3/v4c", "/v1/v2/v3/v4d"}

		var result *module.ModuleResult
		for _, path := range paths {
			result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: path,
				URL:  "http://example.com" + path,
			})
		}

		// No wildcard detected - "v4" prefix is too short (< 3 chars)
		assert.Nil(t, result)
		prefixes := m.GetWildcardPrefixes()
		assert.Empty(t, prefixes)
	})

	t.Run("deep paths with longer final segment", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Paths like /api/v1/v2/item123 -> prefix /api/v1/v2/item (>= 3 chars)
		paths := []string{"/api/v1/v2/item123", "/api/v1/v2/item456", "/api/v1/v2/item789", "/api/v1/v2/itemabc"}

		var result *module.ModuleResult
		for _, path := range paths {
			result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: path,
				URL:  "http://example.com" + path,
			})
		}

		require.NotNil(t, result)
		prefixes := m.GetWildcardPrefixes()
		assert.Contains(t, prefixes, "/api/v1/v2/item")
	})

	t.Run("very deep paths - 6 levels", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		paths := []string{
			"/a/b/c/d/e/user123",
			"/a/b/c/d/e/user456",
			"/a/b/c/d/e/user789",
			"/a/b/c/d/e/userabc",
		}

		var result *module.ModuleResult
		for _, path := range paths {
			result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: path,
				URL:  "http://example.com" + path,
			})
		}

		require.NotNil(t, result)
		prefixes := m.GetWildcardPrefixes()
		assert.Contains(t, prefixes, "/a/b/c/d/e/user")
	})

	t.Run("regex pattern escaping for deep paths", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Paths with dots and special chars
		paths := []string{
			"/api/v1.0/data/item123",
			"/api/v1.0/data/item456",
			"/api/v1.0/data/item789",
			"/api/v1.0/data/itemabc",
		}

		var result *module.ModuleResult
		for _, path := range paths {
			result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: path,
				URL:  "http://example.com" + path,
			})
		}

		// Result should contain properly escaped regex pattern for queue cleanup
		require.NotNil(t, result)
		require.NotNil(t, result.QueueCleanup)
		// Pattern should have escaped dots
		assert.Contains(t, result.QueueCleanup.Pattern, `v1\.0`)
	})

	t.Run("deduplication returns RemoveKeepOne action", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Multiple similar paths should trigger QueueActionRemoveKeepOne
		// Prefix must be >= 3 chars: "item" (4 chars) will match
		paths := []string{
			"/api/users/itemabc",
			"/api/users/itemdef",
			"/api/users/itemghi",
			"/api/users/itemjkl",
		}

		var result *module.ModuleResult
		for _, path := range paths {
			result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: path,
				URL:  "http://example.com" + path,
			})
		}

		// Result should request RemoveKeepOne action (engine handles actual cleanup)
		require.NotNil(t, result)
		require.NotNil(t, result.QueueCleanup)
		assert.Equal(t, module.QueueActionRemoveKeepOne, result.QueueCleanup.Action)
	})
}

func TestWildcardModule_DeepFolderRecursion(t *testing.T) {
	t.Run("stops recursion into similar deep folders", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Discovered folders: /v1/v2/v3/user001/, /v1/v2/v3/user002/, etc.
		// Should detect pattern and stop recursion into /v1/v2/v3/user*/
		folders := []string{
			"/v1/v2/v3/user001",
			"/v1/v2/v3/user002",
			"/v1/v2/v3/user003",
			"/v1/v2/v3/user004",
		}

		var result *module.ModuleResult
		for _, folder := range folders {
			result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: folder,
				URL:  "http://example.com" + folder,
			})
		}

		require.NotNil(t, result, "should detect wildcard pattern")
		assert.True(t, result.StopRecursion, "should stop recursion into similar folders")
		assert.NotEmpty(t, result.BlockTaskPatterns)
	})

	t.Run("allows recursion into different folder pattern", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Detect wildcard for /api/users/id*
		folders := []string{
			"/api/users/id001",
			"/api/users/id002",
			"/api/users/id003",
			"/api/users/id004",
		}

		for _, folder := range folders {
			_, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: folder,
				URL:  "http://example.com" + folder,
			})
		}

		// Different folder pattern should still be allowed for recursion
		task := &mockTask{baseURL: []byte("/api/users/profile")}
		assert.True(t, m.ShouldAddTask(task), "/api/users/profile should be allowed")

		task2 := &mockTask{baseURL: []byte("/api/groups/id001")}
		assert.True(t, m.ShouldAddTask(task2), "/api/groups/id001 should be allowed")
	})

	t.Run("blocks recursion into matching folder pattern", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// Use varied suffixes so common prefix is /api/data/user (not /api/data/user00)
		folders := []string{
			"/api/data/userabc",
			"/api/data/userdef",
			"/api/data/userghi",
			"/api/data/userjkl",
		}

		for _, folder := range folders {
			_, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: folder,
				URL:  "http://example.com" + folder,
			})
		}

		// Should block recursion into /api/data/userXYZ (same pattern)
		task := &mockTask{baseURL: []byte("/api/data/userxyz")}
		assert.False(t, m.ShouldAddTask(task), "/api/data/userxyz should be blocked")
	})

	t.Run("short segment prefix is ignored", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		// /v1/v2/v3/v4a has potential prefix "v4" which is only 2 chars
		// Since common prefix < 3 chars, no wildcard is detected
		folders := []string{
			"/v1/v2/v3/v4a",
			"/v1/v2/v3/v4b",
			"/v1/v2/v3/v4c",
			"/v1/v2/v3/v4d",
		}

		var result *module.ModuleResult
		for _, folder := range folders {
			result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: folder,
				URL:  "http://example.com" + folder,
			})
		}

		// No wildcard detected because "v4" prefix is < 3 chars
		assert.Nil(t, result)
		prefixes := m.GetWildcardPrefixes()
		assert.Empty(t, prefixes)
	})

	t.Run("queue cleanup returns RemoveKeepOne for deep folders", func(t *testing.T) {
		m := NewWildcardModule()
		m.SetThreshold(3)

		folders := []string{
			"/deep/path/folderabc",
			"/deep/path/folderdef",
			"/deep/path/folderghi",
			"/deep/path/folderjkl",
		}

		var result *module.ModuleResult
		for _, folder := range folders {
			result, _ = m.OnDirectoryMatch(context.Background(), &module.DirectoryEvent{
				Path: folder,
				URL:  "http://example.com" + folder,
			})
		}

		// Result should request RemoveKeepOne action (engine handles actual cleanup)
		require.NotNil(t, result)
		require.NotNil(t, result.QueueCleanup)
		assert.Equal(t, module.QueueActionRemoveKeepOne, result.QueueCleanup.Action)
		assert.Contains(t, result.QueueCleanup.Pattern, "/deep/path/folder")
	})
}
