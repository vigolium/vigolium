package dedup

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCounter_IncrementAndCheck(t *testing.T) {
	c := NewCounter()

	// First 3 should be allowed
	assert.True(t, c.IncrementAndCheck("key1", 3))
	assert.True(t, c.IncrementAndCheck("key1", 3))
	assert.True(t, c.IncrementAndCheck("key1", 3))

	// 4th should be rejected
	assert.False(t, c.IncrementAndCheck("key1", 3))
	assert.False(t, c.IncrementAndCheck("key1", 3))

	// Different key should be independent
	assert.True(t, c.IncrementAndCheck("key2", 3))
}

func TestCounter_Size(t *testing.T) {
	c := NewCounter()

	assert.Equal(t, int64(0), c.Size())

	c.IncrementAndCheck("a", 3)
	assert.Equal(t, int64(1), c.Size())

	c.IncrementAndCheck("a", 3) // same key
	assert.Equal(t, int64(1), c.Size())

	c.IncrementAndCheck("b", 3)
	assert.Equal(t, int64(2), c.Size())
}

func TestCounter_Concurrent(t *testing.T) {
	c := NewCounter()
	const maxCount int32 = 3
	const goroutines = 100

	var wg sync.WaitGroup
	var allowed, rejected int32
	var mu sync.Mutex

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ok := c.IncrementAndCheck("key", maxCount)
			mu.Lock()
			if ok {
				allowed++
			} else {
				rejected++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(3), allowed)
	assert.Equal(t, int32(goroutines-3), rejected)
}

func TestCounter_Close(t *testing.T) {
	c := NewCounter()
	require.NoError(t, c.Close())
}

func TestHashFormStructure(t *testing.T) {
	// Same sorted inputs produce same hash
	hash1 := HashFormStructure("http://example.com/login", "POST", []string{"password", "username"})
	hash2 := HashFormStructure("http://example.com/login", "POST", []string{"password", "username"})
	assert.Equal(t, hash1, hash2)

	// Different inputs produce different hashes
	hash3 := HashFormStructure("http://example.com/login", "POST", []string{"email", "username"})
	assert.NotEqual(t, hash1, hash3)

	// Different endpoints produce different hashes
	hash4 := HashFormStructure("http://example.com/register", "POST", []string{"password", "username"})
	assert.NotEqual(t, hash1, hash4)

	// Different methods produce different hashes
	hash5 := HashFormStructure("http://example.com/login", "GET", []string{"password", "username"})
	assert.NotEqual(t, hash1, hash5)

	// Empty inputs
	hash6 := HashFormStructure("http://example.com/search", "GET", nil)
	hash7 := HashFormStructure("http://example.com/search", "GET", []string{})
	assert.Equal(t, hash6, hash7)

	// URL normalization applies
	hash8 := HashFormStructure("HTTP://EXAMPLE.COM:80/login", "POST", []string{"username"})
	hash9 := HashFormStructure("http://example.com/login", "POST", []string{"username"})
	assert.Equal(t, hash8, hash9, "URL normalization should make these equal")
}

func TestHashFormStructure_DuplicateNames(t *testing.T) {
	// Forms with duplicate field names (pre-sorted)
	hash1 := HashFormStructure("http://example.com/", "POST", []string{"a", "a", "b"})
	hash2 := HashFormStructure("http://example.com/", "POST", []string{"a", "a", "b"})
	assert.Equal(t, hash1, hash2)

	// Different count of duplicates is different
	hash3 := HashFormStructure("http://example.com/", "POST", []string{"a", "b"})
	assert.NotEqual(t, hash1, hash3, "different number of fields should differ")
}

func BenchmarkCounter_IncrementAndCheck(b *testing.B) {
	c := NewCounter()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.IncrementAndCheck(fmt.Sprintf("key-%d", i%1000), 3)
	}
}
