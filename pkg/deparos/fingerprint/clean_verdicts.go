package fingerprint

import (
	"net/url"
	"sync"
	"time"
)

// Clean-verdict cache bounds (ECON-8).
const (
	cleanVerdictTTL = 10 * time.Minute
	cleanVerdictMax = 4096
)

// cleanVerdicts remembers (host, directory, extension) groups whose last
// sibling validation found no catch-all, so the next unmatched hit there is
// re-checked with one probe instead of four. Entries expire after the TTL so a
// catch-all that appears later is still caught.
type cleanVerdicts struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]time.Time
	now     func() time.Time
}

func newCleanVerdicts(maxEntries int, ttl time.Duration) *cleanVerdicts {
	return &cleanVerdicts{ttl: ttl, max: maxEntries, entries: make(map[string]time.Time), now: time.Now}
}

func cleanVerdictKey(u *url.URL, key CacheKey) string {
	host := key.Host
	if host == "" && u != nil {
		host = u.Host
	}
	return host + "|" + key.Path + "|" + key.Extension
}

func (c *cleanVerdicts) fresh(k string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.entries[k]
	if !ok {
		return false
	}
	if c.now().Sub(at) > c.ttl {
		delete(c.entries, k)
		return false
	}
	return true
}

func (c *cleanVerdicts) mark(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[k]; !ok && len(c.entries) >= c.max {
		now := c.now()
		for ek, at := range c.entries {
			if now.Sub(at) > c.ttl {
				delete(c.entries, ek)
			}
		}
		// Still full: drop the oldest entry.
		if len(c.entries) >= c.max {
			var oldestK string
			var oldest time.Time
			for ek, at := range c.entries {
				if oldestK == "" || at.Before(oldest) {
					oldestK, oldest = ek, at
				}
			}
			delete(c.entries, oldestK)
		}
	}
	c.entries[k] = c.now()
}

func (c *cleanVerdicts) forget(k string) {
	c.mu.Lock()
	delete(c.entries, k)
	c.mu.Unlock()
}
