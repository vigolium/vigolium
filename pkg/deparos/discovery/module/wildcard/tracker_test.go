package wildcard

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefixTracker_AddWithFingerprint(t *testing.T) {
	t.Run("creates new prefix stats", func(t *testing.T) {
		tracker := NewPrefixTracker()

		stats := tracker.AddWithFingerprint("/admin", "/admin123", nil)

		require.NotNil(t, stats)
		assert.Equal(t, "/admin", stats.Prefix)
		assert.Equal(t, 1, stats.Count)
		assert.Equal(t, []string{"/admin123"}, stats.Paths)
	})

	t.Run("increments existing prefix stats", func(t *testing.T) {
		tracker := NewPrefixTracker()

		tracker.AddWithFingerprint("/admin", "/admin123", nil)
		stats := tracker.AddWithFingerprint("/admin", "/adminxyz", nil)

		assert.Equal(t, 2, stats.Count)
		assert.Equal(t, []string{"/admin123", "/adminxyz"}, stats.Paths)
	})

	t.Run("tracks all paths", func(t *testing.T) {
		tracker := NewPrefixTracker()

		tracker.AddWithFingerprint("/admin", "/admin123", nil)
		tracker.AddWithFingerprint("/users", "/users456", nil)

		assert.Equal(t, 2, tracker.PrefixCount())
	})
}

func TestPrefixTracker_Add(t *testing.T) {
	tracker := NewPrefixTracker()

	stats := tracker.Add("/api", "/api/v1")

	assert.Equal(t, 1, stats.Count)
	assert.Nil(t, stats.Fingerprints[0])
}

func TestPrefixTracker_MarkWildcard(t *testing.T) {
	t.Run("marks prefix as wildcard", func(t *testing.T) {
		tracker := NewPrefixTracker()
		tracker.Add("/admin", "/admin123")

		tracker.MarkWildcard("/admin")

		assert.True(t, tracker.IsWildcard("/admin"))
		assert.True(t, tracker.IsWildcard("/admin123"))
		assert.True(t, tracker.IsWildcard("/adminxyz"))
	})

	t.Run("sets IsWildcard flag on stats", func(t *testing.T) {
		tracker := NewPrefixTracker()
		tracker.Add("/admin", "/admin123")

		tracker.MarkWildcard("/admin")

		stats := tracker.GetStats("/admin")
		require.NotNil(t, stats)
		assert.True(t, stats.IsWildcard)
	})

	t.Run("handles marking non-existent prefix", func(t *testing.T) {
		tracker := NewPrefixTracker()

		// Should not panic
		tracker.MarkWildcard("/nonexistent")

		assert.True(t, tracker.IsWildcard("/nonexistent"))
	})
}

func TestPrefixTracker_IsWildcard(t *testing.T) {
	tracker := NewPrefixTracker()
	tracker.MarkWildcard("/admin")
	tracker.MarkWildcard("/test")

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"exact match", "/admin", true},
		{"prefix match", "/admin123", true},
		{"prefix match nested", "/admin/users/list", true},
		{"different prefix", "/test", true},
		{"no match", "/users", false},
		{"partial no match", "/adm", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tracker.IsWildcard(tt.path))
		})
	}
}

func TestPrefixTracker_GetStats(t *testing.T) {
	t.Run("returns stats copy", func(t *testing.T) {
		tracker := NewPrefixTracker()
		tracker.AddWithFingerprint("/admin", "/admin123", nil)
		tracker.AddWithFingerprint("/admin", "/adminxyz", nil)

		stats := tracker.GetStats("/admin")

		require.NotNil(t, stats)
		assert.Equal(t, "/admin", stats.Prefix)
		assert.Equal(t, 2, stats.Count)
		assert.Len(t, stats.Paths, 2)
	})

	t.Run("returns nil for non-existent prefix", func(t *testing.T) {
		tracker := NewPrefixTracker()

		stats := tracker.GetStats("/nonexistent")

		assert.Nil(t, stats)
	})

	t.Run("modification does not affect original", func(t *testing.T) {
		tracker := NewPrefixTracker()
		tracker.Add("/admin", "/admin123")

		stats := tracker.GetStats("/admin")
		stats.Paths = append(stats.Paths, "modified")

		original := tracker.GetStats("/admin")
		assert.Len(t, original.Paths, 1)
	})
}

func TestPrefixTracker_ExtractCommonPrefix(t *testing.T) {
	tests := []struct {
		name           string
		existingPaths  []string // These are added to allPaths via AddWithFingerprint
		newPath        string
		expectedPrefix string
	}{
		{
			name:           "finds admin prefix from similar paths in same parent",
			existingPaths:  []string{"/adminx", "/adminy"},
			newPath:        "/admin123",
			expectedPrefix: "/admin", // Same parent "/", segments share "admin" prefix
		},
		{
			name:           "no common prefix - different segments",
			existingPaths:  []string{"/users"},
			newPath:        "/posts",
			expectedPrefix: "", // "users" and "posts" have no common prefix
		},
		{
			name:           "same path returns empty",
			existingPaths:  []string{"/admin"},
			newPath:        "/admin",
			expectedPrefix: "",
		},
		{
			name:           "too short prefix",
			existingPaths:  []string{"/ab"},
			newPath:        "/ac",
			expectedPrefix: "", // Common prefix "a" is < 3 chars
		},
		{
			name:           "different parent directories - no match",
			existingPaths:  []string{"/api/users"},
			newPath:        "/v1/users",
			expectedPrefix: "", // Different parents: "/api/" vs "/v1/"
		},
		{
			name:           "same parent with common segment prefix",
			existingPaths:  []string{"/api/admin1"},
			newPath:        "/api/admin2",
			expectedPrefix: "/api/admin", // Same parent "/api/", segments share "admin"
		},
		{
			name:           "assets subdirs have no common prefix - NOT wildcard",
			existingPaths:  []string{"/assets/img/", "/assets/css/"},
			newPath:        "/assets/js/",
			expectedPrefix: "", // img, css, js have no common prefix
		},
		{
			name:           "nested wildcard in subdirectory",
			existingPaths:  []string{"/assets/file1"},
			newPath:        "/assets/file2",
			expectedPrefix: "/assets/file", // Same parent, segments share "file"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewPrefixTracker()
			// Add paths to allPaths via AddWithFingerprint (fullPath goes to allPaths)
			for _, path := range tt.existingPaths {
				tracker.AddWithFingerprint("dummy", path, nil)
			}

			result := tracker.ExtractCommonPrefix(tt.newPath)
			assert.Equal(t, tt.expectedPrefix, result)
		})
	}
}

func TestPrefixTracker_GetWildcardPrefixes(t *testing.T) {
	tracker := NewPrefixTracker()
	tracker.MarkWildcard("/admin")
	tracker.MarkWildcard("/test")

	prefixes := tracker.GetWildcardPrefixes()

	assert.Len(t, prefixes, 2)
	assert.Contains(t, prefixes, "/admin")
	assert.Contains(t, prefixes, "/test")
}

func TestPrefixTracker_Counts(t *testing.T) {
	tracker := NewPrefixTracker()

	assert.Equal(t, 0, tracker.PrefixCount())
	assert.Equal(t, 0, tracker.WildcardCount())

	tracker.Add("/admin", "/admin123")
	tracker.Add("/users", "/users456")

	assert.Equal(t, 2, tracker.PrefixCount())
	assert.Equal(t, 0, tracker.WildcardCount())

	tracker.MarkWildcard("/admin")

	assert.Equal(t, 2, tracker.PrefixCount())
	assert.Equal(t, 1, tracker.WildcardCount())
}

func TestPrefixTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewPrefixTracker()
	const numGoroutines = 10
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // 3 types of operations

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				tracker.Add("/prefix", "/prefix"+string(rune('A'+id))+string(rune('0'+j%10)))
			}
		}(i)
	}

	// Concurrent marks
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				if j%10 == 0 {
					tracker.MarkWildcard("/prefix")
				}
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = tracker.IsWildcard("/prefix123")
				_ = tracker.GetStats("/prefix")
				_ = tracker.PrefixCount()
				_ = tracker.WildcardCount()
			}
		}()
	}

	wg.Wait()

	// Verify no data corruption
	assert.GreaterOrEqual(t, tracker.PrefixCount(), 1)
}

func TestLongestCommonPrefix(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected string
	}{
		{"/admin", "/admin123", "/admin"},
		{"/admin123", "/admin", "/admin"},
		{"/api/v1", "/api/v2", "/api/v"},
		{"/users", "/posts", "/"},
		{"", "test", ""},
		{"test", "", ""},
		{"same", "same", "same"},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			assert.Equal(t, tt.expected, longestCommonPrefix(tt.a, tt.b))
		})
	}
}

func TestSplitPathSegment(t *testing.T) {
	tests := []struct {
		path            string
		expectedParent  string
		expectedSegment string
	}{
		{"/assets/img/", "/assets/", "img"},
		{"/admin123", "/", "admin123"},
		{"/api/v1/users", "/api/v1/", "users"},
		{"/", "/", ""},
		{"", "/", ""},
		{"/admin", "/", "admin"},
		{"/api/", "/", "api"},
		{"/a/b/c/", "/a/b/", "c"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			parent, segment := splitPathSegment(tt.path)
			assert.Equal(t, tt.expectedParent, parent, "parent mismatch")
			assert.Equal(t, tt.expectedSegment, segment, "segment mismatch")
		})
	}
}
