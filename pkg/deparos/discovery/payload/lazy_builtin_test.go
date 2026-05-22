package payload

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLazyBuiltInProvider_Basic(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("word1"), []byte("word2"), []byte("word3")},
		FilePath: "/test/path.txt",
		ListType: ShortFileList,
	}

	provider := NewLazyBuiltInProvider(cached, ShortFileList, true)

	ctx := context.Background()

	// First iteration
	val, err := provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("word1"), val)

	val, err = provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("word2"), val)

	val, err = provider.Next(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("word3"), val)

	// Exhausted - returns io.EOF
	val, err = provider.Next(ctx)
	assert.Equal(t, io.EOF, err)
	assert.Nil(t, val)
}

func TestLazyBuiltInProvider_Count(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("a"), []byte("b"), []byte("c")},
		FilePath: "/test/path.txt",
		ListType: ShortFileList,
	}

	provider := NewLazyBuiltInProvider(cached, ShortFileList, true)
	assert.Equal(t, 3, provider.Count())

	// Count doesn't change after Next()
	_, _ = provider.Next(context.Background())
	assert.Equal(t, 3, provider.Count())
}

func TestLazyBuiltInProvider_Empty(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{},
		FilePath: "/test/path.txt",
		ListType: ShortFileList,
	}

	provider := NewLazyBuiltInProvider(cached, ShortFileList, true)

	ctx := context.Background()
	val, err := provider.Next(ctx)
	assert.Equal(t, io.EOF, err)
	assert.Nil(t, val)

	assert.Equal(t, 0, provider.Count())
}

func TestLazyBuiltInProvider_Name(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{},
		FilePath: "/test/path.txt",
		ListType: ShortFileList,
	}

	provider := NewLazyBuiltInProvider(cached, ShortFileList, true)
	assert.Equal(t, "lazy-builtin:short-files", provider.Name())

	provider2 := NewLazyBuiltInProvider(cached, LongDirList, false)
	assert.Equal(t, "lazy-builtin:long-dirs", provider2.Name())
}

func TestLazyBuiltInProvider_Close(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("word")},
		FilePath: "/test/path.txt",
		ListType: ShortFileList,
	}

	provider := NewLazyBuiltInProvider(cached, ShortFileList, true)

	// Close should not error (data is owned by cache)
	err := provider.Close()
	require.NoError(t, err)
}

func TestLazyBuiltInProvider_HashContent(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("word")},
		FilePath: "/test/path.txt",
		ListType: ShortFileList,
	}

	// Same config = same hash
	p1 := NewLazyBuiltInProvider(cached, ShortFileList, true)
	p2 := NewLazyBuiltInProvider(cached, ShortFileList, true)
	assert.Equal(t, p1.HashContent(), p2.HashContent())

	// Different case sensitivity = different hash
	p3 := NewLazyBuiltInProvider(cached, ShortFileList, false)
	assert.NotEqual(t, p1.HashContent(), p3.HashContent())

	// Different list type = different hash
	p4 := NewLazyBuiltInProvider(cached, LongFileList, true)
	assert.NotEqual(t, p1.HashContent(), p4.HashContent())
}

func TestLazyBuiltInProvider_ContextCancellation(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("word1"), []byte("word2")},
		FilePath: "/test/path.txt",
		ListType: ShortFileList,
	}

	provider := NewLazyBuiltInProvider(cached, ShortFileList, true)

	// Cancelled context should return error
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := provider.Next(cancelledCtx)
	assert.Equal(t, context.Canceled, err)
}

func TestLazyBuiltInProvider_IndependentIterators(t *testing.T) {
	cached := &CachedWordlist{
		Payloads: [][]byte{[]byte("a"), []byte("b"), []byte("c")},
		FilePath: "/test/path.txt",
		ListType: ShortFileList,
	}

	// Two providers sharing same cached data
	p1 := NewLazyBuiltInProvider(cached, ShortFileList, true)
	p2 := NewLazyBuiltInProvider(cached, ShortFileList, true)

	ctx := context.Background()

	// p1 reads first item
	val1, _ := p1.Next(ctx)
	assert.Equal(t, []byte("a"), val1)

	// p2 starts from beginning (independent iterator)
	val2, _ := p2.Next(ctx)
	assert.Equal(t, []byte("a"), val2)

	// p1 continues to second
	val1, _ = p1.Next(ctx)
	assert.Equal(t, []byte("b"), val1)

	// p2 continues to second independently
	val2, _ = p2.Next(ctx)
	assert.Equal(t, []byte("b"), val2)
}

func TestLazyBuiltInProvider_Integration(t *testing.T) {
	// Integration test: cache + lazy provider
	tmpDir := t.TempDir()
	wordlistPath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(wordlistPath, []byte("alpha\nbeta\ngamma\n"), 0644)
	require.NoError(t, err)

	cache := NewWordlistCache()

	// Get cached wordlist
	cached, err := cache.Get(ShortFileList, wordlistPath, true)
	require.NoError(t, err)

	// Create provider from cached data
	provider := NewLazyBuiltInProvider(cached, ShortFileList, true)

	ctx := context.Background()

	// Read all items
	var items []string
	for {
		val, err := provider.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		items = append(items, string(val))
	}

	assert.Equal(t, []string{"alpha", "beta", "gamma"}, items)
}
