package reqcache

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHMapCache(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewHMapCache(&Config{Path: tmpDir, Cleanup: true})
	require.NoError(t, err)
	require.NotNil(t, cache)
	defer func() { _ = cache.Close() }()

	assert.Equal(t, int64(0), cache.Size())
	assert.Equal(t, uint64(0), cache.Hits())
}

func TestHMapCache_IsSeen_NewRequest(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewHMapCache(&Config{Path: tmpDir, Cleanup: true})
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	seen := cache.IsSeen("GET", "http://example.com/path", "")
	assert.False(t, seen, "First request should not be seen")
	assert.Equal(t, int64(1), cache.Size())
	assert.Equal(t, uint64(0), cache.Hits())
}

func TestHMapCache_IsSeen_DuplicateRequest(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewHMapCache(&Config{Path: tmpDir, Cleanup: true})
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	url := "http://example.com/path"

	// First request
	seen1 := cache.IsSeen("GET", url, "")
	assert.False(t, seen1)

	// Duplicate request
	seen2 := cache.IsSeen("GET", url, "")
	assert.True(t, seen2, "Duplicate request should be seen")
	assert.Equal(t, int64(1), cache.Size())
	assert.Equal(t, uint64(1), cache.Hits())

	// Third duplicate
	seen3 := cache.IsSeen("GET", url, "")
	assert.True(t, seen3)
	assert.Equal(t, uint64(2), cache.Hits())
}

func TestHMapCache_DifferentMethods(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewHMapCache(&Config{Path: tmpDir, Cleanup: true})
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	url := "http://example.com/path"

	// GET request
	seen1 := cache.IsSeen("GET", url, "")
	assert.False(t, seen1)

	// POST request to same URL - different method = different request
	seen2 := cache.IsSeen("POST", url, "")
	assert.False(t, seen2, "Different method should be treated as new request")
	assert.Equal(t, int64(2), cache.Size())
}

func TestHMapCache_DifferentURLs(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewHMapCache(&Config{Path: tmpDir, Cleanup: true})
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	seen1 := cache.IsSeen("GET", "http://example.com/path1", "")
	assert.False(t, seen1)

	seen2 := cache.IsSeen("GET", "http://example.com/path2", "")
	assert.False(t, seen2)

	assert.Equal(t, int64(2), cache.Size())
}

func TestHMapCache_URLNormalization(t *testing.T) {
	tests := []struct {
		name     string
		url1     string
		url2     string
		sameSeen bool
	}{
		{
			name:     "same URL",
			url1:     "http://example.com/path",
			url2:     "http://example.com/path",
			sameSeen: true,
		},
		{
			name:     "different case in scheme",
			url1:     "HTTP://example.com/path",
			url2:     "http://example.com/path",
			sameSeen: true,
		},
		{
			name:     "different case in host",
			url1:     "http://EXAMPLE.COM/path",
			url2:     "http://example.com/path",
			sameSeen: true,
		},
		{
			name:     "default port 80 for http",
			url1:     "http://example.com:80/path",
			url2:     "http://example.com/path",
			sameSeen: true,
		},
		{
			name:     "default port 443 for https",
			url1:     "https://example.com:443/path",
			url2:     "https://example.com/path",
			sameSeen: true,
		},
		{
			name:     "non-default port preserved",
			url1:     "http://example.com:8080/path",
			url2:     "http://example.com/path",
			sameSeen: false,
		},
		{
			name:     "trailing slash matters",
			url1:     "http://example.com/path",
			url2:     "http://example.com/path/",
			sameSeen: false,
		},
		// Query param values now matter for non-static files
		{
			name:     "query param values matter for non-static",
			url1:     "http://example.com/path?a=1",
			url2:     "http://example.com/path?a=2",
			sameSeen: false, // Different param values = different requests
		},
		{
			name:     "same param values are same",
			url1:     "http://example.com/path?a=1",
			url2:     "http://example.com/path?a=1",
			sameSeen: true,
		},
		{
			name:     "different param order same values are same",
			url1:     "http://example.com/path?b=2&a=1",
			url2:     "http://example.com/path?a=1&b=2",
			sameSeen: true, // Params sorted by key
		},
		{
			name:     "different query param names are different",
			url1:     "http://example.com/path?a=1",
			url2:     "http://example.com/path?b=1",
			sameSeen: false,
		},
		// Static files - query params stripped
		{
			name:     "js files ignore query params",
			url1:     "http://example.com/app.js?v=1",
			url2:     "http://example.com/app.js?v=2",
			sameSeen: true, // Static - params stripped
		},
		{
			name:     "css files ignore query params",
			url1:     "http://example.com/style.css?hash=abc",
			url2:     "http://example.com/style.css?hash=xyz",
			sameSeen: true, // Static - params stripped
		},
		{
			name:     "image files ignore query params",
			url1:     "http://example.com/logo.png?size=100",
			url2:     "http://example.com/logo.png?size=200",
			sameSeen: true, // Static - params stripped
		},
		{
			name:     "font files ignore query params",
			url1:     "http://example.com/font.woff2?v=1",
			url2:     "http://example.com/font.woff2?v=2",
			sameSeen: true, // Static - params stripped
		},
		{
			name:     "map files ignore query params",
			url1:     "http://example.com/bundle.js.map?v=1",
			url2:     "http://example.com/bundle.js.map?v=2",
			sameSeen: true, // Static - params stripped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			c, err := NewHMapCache(&Config{Path: tmpDir, Cleanup: true})
			require.NoError(t, err)
			defer func() { _ = c.Close() }()

			seen1 := c.IsSeen("GET", tt.url1, "")
			assert.False(t, seen1, "First URL should not be seen")

			seen2 := c.IsSeen("GET", tt.url2, "")
			if tt.sameSeen {
				assert.True(t, seen2, "Second URL should be seen as same")
			} else {
				assert.False(t, seen2, "Second URL should be seen as different")
			}
		})
	}
}

func TestHMapCache_Concurrent(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewHMapCache(&Config{Path: tmpDir, Cleanup: true})
	require.NoError(t, err)
	defer func() { _ = cache.Close() }()

	var wg sync.WaitGroup
	numGoroutines := 100
	url := "http://example.com/concurrent"

	// Track how many goroutines see the URL as new
	var newCount int64
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !cache.IsSeen("GET", url, "") {
				mu.Lock()
				newCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Exactly one goroutine should see the URL as new
	assert.Equal(t, int64(1), newCount, "Exactly one goroutine should see URL as new")
	assert.Equal(t, int64(1), cache.Size())
	assert.Equal(t, uint64(numGoroutines-1), cache.Hits())
}
