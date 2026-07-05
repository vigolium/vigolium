package payload

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLazyMergedPathProvider_Basic(t *testing.T) {
	// Create source with some paths
	source := NewObservedProvider(true)
	source.Add([]byte("/api/users/"))
	source.Add([]byte("/api/config/"))
	source.Add([]byte("/static/js/"))

	// Now uses MergePathWithBase directly (no callback needed)
	provider := NewLazyMergedPathProvider(source, "/test/")

	ctx := context.Background()

	// Should not be initialized until first Next()
	assert.False(t, provider.initialized)

	// First call initializes and returns first item
	val, err := provider.Next(ctx)
	require.NoError(t, err)
	assert.True(t, provider.initialized)
	assert.NotEmpty(t, val)

	// Continue iterating
	count := 1
	for {
		_, err := provider.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		count++
	}

	assert.Equal(t, 3, count)
}

func TestLazyMergedPathProvider_EmptySource(t *testing.T) {
	source := NewObservedProvider(true)
	provider := NewLazyMergedPathProvider(source, "/test/")

	ctx := context.Background()

	val, err := provider.Next(ctx)
	assert.Equal(t, io.EOF, err)
	assert.Nil(t, val)
	assert.True(t, provider.initialized)
	assert.Equal(t, 0, provider.Count())
}

func TestLazyMergedPathProvider_HashContent(t *testing.T) {
	source := NewObservedProvider(true)
	source.Add([]byte("/api/"))

	// Same source, same dirPath = same hash
	p1 := NewLazyMergedPathProvider(source, "/admin/")
	p2 := NewLazyMergedPathProvider(source, "/admin/")
	assert.Equal(t, p1.HashContent(), p2.HashContent())

	// Same source, different dirPath = same hash (dirPath not included in hash)
	// The task itself uses dirPath (directory URL) as part of its deduplication key,
	// so including it here would be redundant.
	p3 := NewLazyMergedPathProvider(source, "/users/")
	assert.Equal(t, p1.HashContent(), p3.HashContent())
}

func TestLazyMergedPathProvider_Count(t *testing.T) {
	source := NewObservedProvider(true)
	source.Add([]byte("/one/"))
	source.Add([]byte("/two/"))

	provider := NewLazyMergedPathProvider(source, "/test/")

	// Before initialization, returns source count
	assert.Equal(t, 2, provider.Count())

	// After initialization, returns actual merged count
	ctx := context.Background()
	_, _ = provider.Next(ctx)
	assert.Equal(t, 2, provider.Count())
}

func TestLazyMergedPathProvider_Close(t *testing.T) {
	source := NewObservedProvider(true)
	source.Add([]byte("/test/"))

	provider := NewLazyMergedPathProvider(source, "/dir/")

	// Initialize by calling Next
	ctx := context.Background()
	_, _ = provider.Next(ctx)
	assert.NotNil(t, provider.items)

	// Close should clear items
	err := provider.Close()
	require.NoError(t, err)
	assert.Nil(t, provider.items)
}

func TestLazyMergedPathProvider_Name(t *testing.T) {
	source := NewObservedProvider(true)
	provider := NewLazyMergedPathProvider(source, "/")
	assert.Equal(t, "lazy-merged-path", provider.Name())
}

func TestLazyMergedPathProvider_ContextCancellation(t *testing.T) {
	source := NewObservedProvider(true)
	source.Add([]byte("/path1/"))
	source.Add([]byte("/path2/"))
	source.Add([]byte("/path3/"))

	provider := NewLazyMergedPathProvider(source, "/dir/")

	// Initialize first with valid context
	ctx := context.Background()
	_, err := provider.Next(ctx)
	require.NoError(t, err)

	// Now try with cancelled context - should return error before EOF
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = provider.Next(cancelledCtx)
	assert.Equal(t, context.Canceled, err)
}

func TestLazyMergedPathProvider_FilteredMerge(t *testing.T) {
	source := NewObservedProvider(true)
	source.Add([]byte("/test/"))   // Same as dirPath, should be filtered by MergePathWithBase
	source.Add([]byte("/api/"))    // Different, should be kept (appended to /test/)
	source.Add([]byte(""))         // Empty, should be filtered
	source.Add([]byte("/config/")) // Different, should be kept (appended to /test/)

	provider := NewLazyMergedPathProvider(source, "/test/")

	ctx := context.Background()
	var results []string
	for {
		val, err := provider.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		results = append(results, string(val))
	}

	// /test/ is exact match → filtered
	// /api/ is unrelated → /test/api/
	// "" is empty → filtered
	// /config/ is unrelated → /test/config/
	assert.Equal(t, 2, len(results))
	assert.Contains(t, results, "/test/api/")
	assert.Contains(t, results, "/test/config/")
}

func TestLazyMergedPathProvider_FullURLDirPath(t *testing.T) {
	source := NewObservedProvider(true)
	source.Add([]byte("/api/v1/"))       // Same as dirPath, should be filtered
	source.Add([]byte("/api/v1/users/")) // Child of dirPath, should be kept

	// Pass full URL as dirPath - should be extracted to path only
	provider := NewLazyMergedPathProvider(source, "http://example.com/api/v1/")

	ctx := context.Background()
	var results []string
	for {
		val, err := provider.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		results = append(results, string(val))
	}

	// /api/v1/ is exact match → filtered
	// /api/v1/users/ is child → kept as full path
	assert.Equal(t, 1, len(results))
	assert.Equal(t, "/api/v1/users/", results[0])
}

func TestExtractPathFromURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"full URL", "http://example.com/api/v1/", "/api/v1/"},
		{"full URL no path", "http://example.com", "/"},
		{"full URL root", "http://example.com/", "/"},
		{"https URL", "https://example.com/admin/config/", "/admin/config/"},
		{"path only", "/api/v1/", "/api/v1/"},
		{"path no leading slash", "api/v1/", "api/v1/"},
		{"empty", "", "/"},
		{"root path", "/", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractPathFromURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergePathWithBase_InProvider(t *testing.T) {
	// Test that MergePathWithBase works correctly within provider
	tests := []struct {
		name       string
		storedPath string
		dirPath    string
		expected   string // empty means should be filtered
	}{
		{"child path", "/api/v1/admin/", "/api/v1/", "/api/v1/admin/"},
		{"exact match", "/api/v1/", "/api/v1/", ""},
		{"parent path", "/api/", "/api/v1/", ""},
		{"common prefix paths", "/api/v2/", "/api/v1/", "/api/v2/"}, // Share "api", return as-is
		{"unrelated path", "/other/", "/api/v1/", "/api/v1/other/"},
		{"overlap merge", "/v1/admin/users/", "/api/v1/admin/", "/api/v1/admin/users/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := NewObservedProvider(true)
			source.Add([]byte(tt.storedPath))

			provider := NewLazyMergedPathProvider(source, tt.dirPath)

			ctx := context.Background()
			val, err := provider.Next(ctx)

			if tt.expected == "" {
				// Should be filtered
				assert.Equal(t, io.EOF, err)
				assert.Nil(t, val)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, string(val))
			}
		})
	}
}
