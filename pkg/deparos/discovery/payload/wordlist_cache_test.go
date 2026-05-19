package payload

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWordlistCache_GetCachesFile(t *testing.T) {
	// Create a temp wordlist file
	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(wordlistPath, []byte("word1\nword2\nword3\n"), 0644)
	require.NoError(t, err)

	cache := NewWordlistCache()

	// First call should load from disk
	cached1, err := cache.Get(ShortFileList, wordlistPath, true)
	require.NoError(t, err)
	require.NotNil(t, cached1)
	assert.Equal(t, 3, len(cached1.Payloads))
	assert.Equal(t, 1, cache.Size())

	// Second call should return same cached instance
	cached2, err := cache.Get(ShortFileList, wordlistPath, true)
	require.NoError(t, err)
	assert.Same(t, cached1, cached2) // Same pointer = cached
}

func TestWordlistCache_DifferentCaseSensitivitySeparateCache(t *testing.T) {
	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(wordlistPath, []byte("Word1\nWORD1\nword1\n"), 0644)
	require.NoError(t, err)

	cache := NewWordlistCache()

	// Case-sensitive: all 3 words are unique
	csSensitive, err := cache.Get(ShortFileList, wordlistPath, true)
	require.NoError(t, err)
	assert.Equal(t, 3, len(csSensitive.Payloads))

	// Case-insensitive: duplicates removed
	csInsensitive, err := cache.Get(ShortFileList, wordlistPath, false)
	require.NoError(t, err)
	assert.Equal(t, 1, len(csInsensitive.Payloads))
	assert.Equal(t, "word1", string(csInsensitive.Payloads[0]))

	// Different cache entries
	assert.Equal(t, 2, cache.Size())
	assert.NotSame(t, csSensitive, csInsensitive)
}

func TestWordlistCache_EmptyPathError(t *testing.T) {
	cache := NewWordlistCache()

	_, err := cache.Get(ShortFileList, "", true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wordlist file path required")
}

func TestWordlistCache_FileNotFoundError(t *testing.T) {
	cache := NewWordlistCache()

	_, err := cache.Get(ShortFileList, "/nonexistent/path/file.txt", true)
	assert.Error(t, err)
}

func TestWordlistCache_Clear(t *testing.T) {
	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(wordlistPath, []byte("word1\n"), 0644)
	require.NoError(t, err)

	cache := NewWordlistCache()

	_, err = cache.Get(ShortFileList, wordlistPath, true)
	require.NoError(t, err)
	assert.Equal(t, 1, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())
}

func TestWordlistCache_Concurrent(t *testing.T) {
	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(wordlistPath, []byte("word1\nword2\nword3\n"), 0644)
	require.NoError(t, err)

	cache := NewWordlistCache()

	// Concurrent access to same wordlist
	var wg sync.WaitGroup
	results := make([]*CachedWordlist, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cached, err := cache.Get(ShortFileList, wordlistPath, true)
			if err == nil {
				results[idx] = cached
			}
		}(i)
	}

	wg.Wait()

	// All goroutines should get the same cached instance
	first := results[0]
	require.NotNil(t, first)
	for i := 1; i < 100; i++ {
		assert.Same(t, first, results[i], "All goroutines should get same cached instance")
	}

	// Only one entry in cache
	assert.Equal(t, 1, cache.Size())
}

func TestWordlistCache_DifferentListTypes(t *testing.T) {
	tmpDir := t.TempDir()
	shortPath := filepath.Join(tmpDir, "short.txt")
	longPath := filepath.Join(tmpDir, "long.txt")

	err := os.WriteFile(shortPath, []byte("s1\ns2\n"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(longPath, []byte("l1\nl2\nl3\n"), 0644)
	require.NoError(t, err)

	cache := NewWordlistCache()

	short, err := cache.Get(ShortFileList, shortPath, true)
	require.NoError(t, err)
	assert.Equal(t, 2, len(short.Payloads))

	long, err := cache.Get(LongFileList, longPath, true)
	require.NoError(t, err)
	assert.Equal(t, 3, len(long.Payloads))

	assert.Equal(t, 2, cache.Size())
	assert.NotSame(t, short, long)
}
