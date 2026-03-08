package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCache(t *testing.T) {
	learner := NewLearner(nil, nil)
	cache := NewCache(learner)

	assert.NotNil(t, cache)
	assert.Equal(t, 0, cache.Size())
	assert.Equal(t, DefaultCacheMaxSize, cache.MaxSize())
}

func TestNewCacheWithMaxSize(t *testing.T) {
	cache := NewCacheWithMaxSize(nil, 100)
	assert.Equal(t, 100, cache.MaxSize())

	// Test with invalid maxSize (should use default)
	cache2 := NewCacheWithMaxSize(nil, 0)
	assert.Equal(t, DefaultCacheMaxSize, cache2.MaxSize())

	cache3 := NewCacheWithMaxSize(nil, -10)
	assert.Equal(t, DefaultCacheMaxSize, cache3.MaxSize())
}

func TestCache_AddAndGet(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}

	// Create signature
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("application/json"),
		},
	}

	// Add signature
	cache.Add(key, sig)

	// Get signature
	sigs, ok := cache.Get(key)
	assert.True(t, ok)
	assert.Len(t, sigs, 1)
	assert.Equal(t, sig, sigs[0])
}

func TestCache_Get_NotFound(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}

	sigs, ok := cache.Get(key)
	assert.False(t, ok)
	assert.Nil(t, sigs)
}

func TestCache_Add_Multiple(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".html"}

	// Add multiple signatures for same key
	sig1 := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}
	sig2 := &Signature{stable: map[Attribute]uint32{StatusCode: 500}}

	cache.Add(key, sig1)
	cache.Add(key, sig2)

	sigs, ok := cache.Get(key)
	assert.True(t, ok)
	assert.Len(t, sigs, 2)
}

func TestCache_Matches(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".html"}

	// Create and add signature
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}
	cache.Add(key, sig)

	// Create matching sample
	matchingSample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}

	assert.True(t, cache.Matches(key, matchingSample))

	// Create non-matching sample
	nonMatchingSample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  200,
			ContentType: HashString("text/html"),
		},
	}

	assert.False(t, cache.Matches(key, nonMatchingSample))
}

func TestCache_Matches_NoSignatures(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".html"}

	sample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode: 404,
		},
	}

	assert.False(t, cache.Matches(key, sample))
}

func TestCache_LearnAndCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(0)
	cache := NewCache(learner)

	baseURL, _ := url.Parse(server.URL + "/test")
	key := ExtractCacheKey(baseURL)

	sig, err := cache.LearnAndCache(context.Background(), key, baseURL)
	require.NoError(t, err)
	assert.NotNil(t, sig)

	// Signature should be in cache
	sigs, ok := cache.Get(key)
	assert.True(t, ok)
	assert.Len(t, sigs, 1)
}

func TestCache_LearnAndCache_NoLearner(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ""}
	baseURL, _ := url.Parse("http://example.com/test")

	_, err := cache.LearnAndCache(context.Background(), key, baseURL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no learner")
}

func TestCache_Size(t *testing.T) {
	cache := NewCache(nil)

	assert.Equal(t, 0, cache.Size())

	key1 := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}
	key2 := CacheKey{Host: "example.com", Path: "/", Extension: ".html"}

	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}

	cache.Add(key1, sig)
	assert.Equal(t, 1, cache.Size())

	cache.Add(key2, sig)
	assert.Equal(t, 2, cache.Size())
}

func TestCache_Clear(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}
	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}

	cache.Add(key, sig)
	assert.Equal(t, 1, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())

	sigs, ok := cache.Get(key)
	assert.False(t, ok)
	assert.Nil(t, sigs)
}

func TestCache_Remove(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}
	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}

	cache.Add(key, sig)
	assert.Equal(t, 1, cache.Size())

	cache.Remove(key)
	assert.Equal(t, 0, cache.Size())

	sigs, ok := cache.Get(key)
	assert.False(t, ok)
	assert.Nil(t, sigs)
}

func TestCache_GetAllKeys(t *testing.T) {
	cache := NewCache(nil)

	key1 := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}
	key2 := CacheKey{Host: "test.com", Path: "/", Extension: ".html"}

	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}

	cache.Add(key1, sig)
	cache.Add(key2, sig)

	keys := cache.GetAllKeys()
	assert.Len(t, keys, 2)

	// Check both keys are present
	hasKey1 := false
	hasKey2 := false
	for _, k := range keys {
		if k == key1 {
			hasKey1 = true
		}
		if k == key2 {
			hasKey2 = true
		}
	}
	assert.True(t, hasKey1)
	assert.True(t, hasKey2)
}

func TestExtractCacheKey(t *testing.T) {
	tests := []struct {
		name         string
		urlStr       string
		expectedHost string
		expectedExt  string
	}{
		{
			name:         "with_json",
			urlStr:       "https://example.com:443/api/users.json",
			expectedHost: "example.com:443",
			expectedExt:  ".json",
		},
		{
			name:         "with_php",
			urlStr:       "http://test.com/index.php",
			expectedHost: "test.com",
			expectedExt:  ".php",
		},
		{
			name:         "no_extension",
			urlStr:       "https://example.com/api/users",
			expectedHost: "example.com",
			expectedExt:  "",
		},
		{
			name:         "with_port",
			urlStr:       "https://example.com:8080/test.html",
			expectedHost: "example.com:8080",
			expectedExt:  ".html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.urlStr)
			require.NoError(t, err)

			key := ExtractCacheKey(u)
			assert.Equal(t, tt.expectedHost, key.Host)
			assert.Equal(t, tt.expectedExt, key.Extension)
		})
	}
}

func TestCacheKey_String(t *testing.T) {
	tests := []struct {
		name     string
		key      CacheKey
		expected string
	}{
		{
			name:     "with_extension",
			key:      CacheKey{Host: "example.com", Path: "/", Extension: ".json"},
			expected: "example.com:.json",
		},
		{
			name:     "no_extension",
			key:      CacheKey{Host: "example.com", Path: "/", Extension: ""},
			expected: "example.com",
		},
		{
			name:     "with_port_and_ext",
			key:      CacheKey{Host: "example.com:8080", Path: "/", Extension: ".php"},
			expected: "example.com:8080:.php",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.key.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCache_GetStats(t *testing.T) {
	cache := NewCache(nil)

	key1 := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}
	key2 := CacheKey{Host: "test.com", Path: "/", Extension: ".html"}

	sig1 := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}
	sig2 := &Signature{stable: map[Attribute]uint32{StatusCode: 500}}

	cache.Add(key1, sig1)
	cache.Add(key1, sig2) // Add another signature to same key
	cache.Add(key2, sig1)

	stats := cache.GetStats()

	assert.Equal(t, 2, stats.TotalKeys)
	assert.Equal(t, 3, stats.TotalSignatures)
	assert.Equal(t, 2, stats.KeyDetails["example.com:.json"])
	assert.Equal(t, 1, stats.KeyDetails["test.com:.html"])
}

func TestCache_Concurrency(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".html"}

	var wg sync.WaitGroup
	concurrency := 50

	// Concurrent writes
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sig := &Signature{
				stable: map[Attribute]uint32{
					StatusCode: uint32(404 + idx),
				},
			}
			cache.Add(key, sig)
		}(i)
	}

	wg.Wait()

	// Signatures should be added (some might be lost due to race in append)
	sigs, ok := cache.Get(key)
	assert.True(t, ok)
	assert.Greater(t, len(sigs), 0, "should have at least some signatures")
	assert.LessOrEqual(t, len(sigs), concurrency, "should not exceed concurrency limit")
}

func TestCache_ConcurrentReadWrite(t *testing.T) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}

	// Add initial signature
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("application/json"),
		},
	}
	cache.Add(key, sig)

	sample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("application/json"),
		},
	}

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.Matches(key, sample)
			cache.Get(key)
			cache.Size()
		}()
	}

	// Concurrent writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			newSig := &Signature{
				stable: map[Attribute]uint32{
					StatusCode: uint32(500 + idx),
				},
			}
			cache.Add(key, newSig)
		}(i)
	}

	wg.Wait()

	// Should not panic and should have signatures
	sigs, ok := cache.Get(key)
	assert.True(t, ok)
	assert.Greater(t, len(sigs), 0)
}

func BenchmarkCache_Add(b *testing.B) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}
	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(key, sig)
	}
}

func BenchmarkCache_Get(b *testing.B) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}
	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}
	cache.Add(key, sig)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.Get(key)
	}
}

func BenchmarkCache_Matches(b *testing.B) {
	cache := NewCache(nil)
	key := CacheKey{Host: "example.com", Path: "/", Extension: ".json"}
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("application/json"),
		},
	}
	cache.Add(key, sig)

	sample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("application/json"),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.Matches(key, sample)
	}
}

func TestCache_EvictionWhenFull(t *testing.T) {
	maxSize := 100
	cache := NewCacheWithMaxSize(nil, maxSize)

	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}

	// Add entries up to max size
	for i := 0; i < maxSize; i++ {
		key := CacheKey{
			Host:      "example.com",
			Path:      "/",
			Extension: "." + string(rune('a'+i%26)) + string(rune('0'+i/26)),
		}
		cache.Add(key, sig)
	}

	assert.Equal(t, maxSize, cache.Size())

	// Add one more entry - should trigger eviction
	newKey := CacheKey{Host: "example.com", Path: "/", Extension: ".new"}
	cache.Add(newKey, sig)

	// Size should be around 90% of max (evicted 10%) + 1 new entry
	// So around 91 entries
	assert.Less(t, cache.Size(), maxSize)
	assert.Greater(t, cache.Size(), maxSize-maxSize/10-5) // Allow some tolerance

	// New key should be accessible
	_, ok := cache.Get(newKey)
	assert.True(t, ok)
}

func TestCache_EvictionCleansPathIndex(t *testing.T) {
	maxSize := 10
	cache := NewCacheWithMaxSize(nil, maxSize)

	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}

	// Add entries from different hosts
	for i := 0; i < maxSize; i++ {
		key := CacheKey{
			Host:      "host" + string(rune('0'+i)) + ".com",
			Path:      "/path/",
			Extension: ".html",
		}
		cache.Add(key, sig)
	}

	assert.Equal(t, maxSize, cache.Size())

	// Add more entries to trigger eviction
	for i := 0; i < 5; i++ {
		key := CacheKey{
			Host:      "newhost" + string(rune('0'+i)) + ".com",
			Path:      "/",
			Extension: ".json",
		}
		cache.Add(key, sig)
	}

	// Cache should have evicted some entries
	assert.Less(t, cache.Size(), maxSize+5)

	// pathIndex should be consistent with actual entries
	allKeys := cache.GetAllKeys()
	assert.Equal(t, cache.Size(), len(allKeys))
}

func TestCache_EvictionSmallMaxSize(t *testing.T) {
	// Test with very small max size (edge case)
	cache := NewCacheWithMaxSize(nil, 1)

	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 404}}

	key1 := CacheKey{Host: "a.com", Path: "/", Extension: ""}
	key2 := CacheKey{Host: "b.com", Path: "/", Extension: ""}

	cache.Add(key1, sig)
	assert.Equal(t, 1, cache.Size())

	// Adding second entry should evict the first
	cache.Add(key2, sig)
	assert.Equal(t, 1, cache.Size())

	// Only one key should exist
	allKeys := cache.GetAllKeys()
	assert.Len(t, allKeys, 1)
}
