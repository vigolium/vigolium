package llm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type cacheEntry struct {
	resp      *CompletionResponse
	expiresAt time.Time
}

// cachedClient wraps a Client with an LRU cache.
type cachedClient struct {
	inner Client
	cache *lru.Cache[string, *cacheEntry]
	ttl   time.Duration
	mu    sync.Mutex // protects TTL eviction check
}

func newCachedClient(inner Client, size, ttlSeconds int) (*cachedClient, error) {
	c, err := lru.New[string, *cacheEntry](size)
	if err != nil {
		return nil, fmt.Errorf("llm cache: %w", err)
	}
	return &cachedClient{
		inner: inner,
		cache: c,
		ttl:   time.Duration(ttlSeconds) * time.Second,
	}, nil
}

// Complete returns a cached response if available and unexpired, otherwise
// forwards to the inner client and caches the result.
func (c *cachedClient) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	key := cacheKey(req)

	c.mu.Lock()
	if entry, ok := c.cache.Get(key); ok {
		if time.Now().Before(entry.expiresAt) {
			c.mu.Unlock()
			return entry.resp, nil
		}
		c.cache.Remove(key)
	}
	c.mu.Unlock()

	resp, err := c.inner.Complete(ctx, req)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache.Add(key, &cacheEntry{resp: resp, expiresAt: time.Now().Add(c.ttl)})
	c.mu.Unlock()

	return resp, nil
}

func cacheKey(req CompletionRequest) string {
	// Serialize the full request to get a stable cache key.
	data, _ := json.Marshal(req)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
