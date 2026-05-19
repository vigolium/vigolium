package payload

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLazyCustomProvider_Basic(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("custom1"), []byte("custom2"), []byte("custom3")},
		FilePath: "/test/custom.txt",
		ListType: CustomListType,
	}

	provider := NewLazyCustomProvider(cached, "test-module")

	ctx := context.Background()

	// First iteration
	val, err := provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("custom1"), val)

	val, err = provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("custom2"), val)

	val, err = provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("custom3"), val)

	// Exhausted - returns io.EOF
	val, err = provider.Next(ctx)
	assert.Equal(t, io.EOF, err)
	assert.Nil(t, val)
}

func TestLazyCustomProvider_Count(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("a"), []byte("b")},
		FilePath: "/test/path.txt",
		ListType: CustomListType,
	}

	provider := NewLazyCustomProvider(cached, "test")
	assert.Equal(t, 2, provider.Count())

	// Count doesn't change after Next()
	_, _ = provider.Next(context.Background())
	assert.Equal(t, 2, provider.Count())
}

func TestLazyCustomProvider_Name(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{},
		FilePath: "/test/path.txt",
		ListType: CustomListType,
	}

	provider := NewLazyCustomProvider(cached, "my-module")
	assert.Equal(t, "lazy-custom:my-module", provider.Name())
}

func TestLazyCustomProvider_Close(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("word")},
		FilePath: "/test/path.txt",
		ListType: CustomListType,
	}

	provider := NewLazyCustomProvider(cached, "test")

	// Close should not error
	err := provider.Close()
	require.NoError(t, err)
}

func TestLazyCustomProvider_HashContent(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("word")},
		FilePath: "/test/path.txt",
		ListType: CustomListType,
	}

	// Same config = same hash
	p1 := NewLazyCustomProvider(cached, "test")
	p2 := NewLazyCustomProvider(cached, "test")
	assert.Equal(t, p1.HashContent(), p2.HashContent())

	// Different name = different hash
	p3 := NewLazyCustomProvider(cached, "other")
	assert.NotEqual(t, p1.HashContent(), p3.HashContent())
}

func TestLazyCustomProvider_ContextCancellation(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("word1"), []byte("word2")},
		FilePath: "/test/path.txt",
		ListType: CustomListType,
	}

	provider := NewLazyCustomProvider(cached, "test")

	// Cancelled context should return error
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := provider.Next(cancelledCtx)
	assert.Equal(t, context.Canceled, err)
}

func TestLazyCustomProviderFromInline_Basic(t *testing.T) {
	words := []string{"inline1", "inline2", "  inline3  ", "", "inline4"}

	provider := NewLazyCustomProviderFromInline("inline-test", words)

	ctx := context.Background()

	// Should get 4 items (empty string filtered)
	var items []string
	for {
		val, err := provider.Next(ctx)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		items = append(items, string(val))
	}

	assert.Equal(t, []string{"inline1", "inline2", "inline3", "inline4"}, items)
}

func TestLazyCustomProviderFromInline_HashContent(t *testing.T) {
	// Same inline words = same hash
	p1 := NewLazyCustomProviderFromInline("test", []string{"a", "b"})
	p2 := NewLazyCustomProviderFromInline("test", []string{"a", "b"})
	assert.Equal(t, p1.HashContent(), p2.HashContent())

	// Different words = different hash
	p3 := NewLazyCustomProviderFromInline("test", []string{"a", "c"})
	assert.NotEqual(t, p1.HashContent(), p3.HashContent())
}

func TestWordlistCache_GetCustom(t *testing.T) {
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "custom.txt")
	err := os.WriteFile(customPath, []byte("custom1\ncustom2\n"), 0644)
	require.NoError(t, err)

	cache := NewWordlistCache()

	// First call should load from disk
	cached1, err := cache.GetCustom(customPath)
	require.NoError(t, err)
	require.NotNil(t, cached1)
	assert.Equal(t, 2, len(cached1.Payloads))
	assert.Equal(t, CustomListType, cached1.ListType)

	// Second call should return same cached instance
	cached2, err := cache.GetCustom(customPath)
	require.NoError(t, err)
	assert.Same(t, cached1, cached2) // Same pointer = cached
}

func TestWordlistCache_GetCustom_EmptyPath(t *testing.T) {
	cache := NewWordlistCache()

	_, err := cache.GetCustom("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "custom wordlist file path required")
}

func TestLazyCustomProvider_Integration(t *testing.T) {
	// Integration test: cache + lazy custom provider
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "module.txt")
	err := os.WriteFile(customPath, []byte("foo\nbar\nbaz\n"), 0644)
	require.NoError(t, err)

	cache := NewWordlistCache()

	// Get cached custom wordlist
	cached, err := cache.GetCustom(customPath)
	require.NoError(t, err)

	// Create provider from cached data
	provider := NewLazyCustomProvider(cached, "my-module")

	ctx := context.Background()

	// Read all items
	var items []string
	for {
		val, err := provider.Next(ctx)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		items = append(items, string(val))
	}

	assert.Equal(t, []string{"foo", "bar", "baz"}, items)
}
