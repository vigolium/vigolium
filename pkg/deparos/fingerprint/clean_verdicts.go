package fingerprint

import (
	"net/url"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Clean-verdict cache bounds.
const (
	cleanVerdictTTL = 10 * time.Minute
	cleanVerdictMax = 4096
)

// cleanVerdicts remembers (host, directory, extension) groups whose last
// sibling validation found no catch-all, so the next unmatched hit there is
// re-checked with one probe instead of four. Entries expire after the TTL so a
// catch-all that appears later is still caught; past maxEntries the least
// recently marked group is dropped.
//
// A plain LRU with the mark time as value rather than the expirable LRU: that
// one starts a cleanup goroutine per cache that never exits, and a comparator
// is built per discovery run.
type cleanVerdicts struct {
	ttl     time.Duration
	entries *lru.Cache[string, time.Time]
	now     func() time.Time
}

func newCleanVerdicts(maxEntries int, ttl time.Duration) *cleanVerdicts {
	entries, _ := lru.New[string, time.Time](max(maxEntries, 1))
	return &cleanVerdicts{ttl: ttl, entries: entries, now: time.Now}
}

func cleanVerdictKey(u *url.URL, key CacheKey) string {
	host := key.Host
	if host == "" && u != nil {
		host = u.Host
	}
	return host + "|" + key.Path + "|" + key.Extension
}

func (c *cleanVerdicts) fresh(k string) bool {
	at, ok := c.entries.Peek(k)
	if !ok {
		return false
	}
	if c.now().Sub(at) > c.ttl {
		c.entries.Remove(k)
		return false
	}
	return true
}

func (c *cleanVerdicts) mark(k string) { c.entries.Add(k, c.now()) }

func (c *cleanVerdicts) forget(k string) { c.entries.Remove(k) }
