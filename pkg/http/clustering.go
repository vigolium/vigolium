package http

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	// clusterCacheTTL bounds how long a cached response stays fresh. Kept short
	// on purpose: the clusterer keys on the raw request bytes, so it also collapses
	// identical *non-idempotent* probes (e.g. two byte-identical POSTs) within the
	// window — a deliberate safety valve. A cache hit also returns duration=0 so a
	// stale RTT can't poison timing-based modules. Raising it widens both hazards,
	// so it stays a conservative constant rather than a tunable.
	clusterCacheTTL = 500 * time.Millisecond
	// clusterCacheSize is the floor for the LRU entry cap. The effective size
	// scales up with scan concurrency (see ClustererSizeForConcurrency) so wide
	// fan-out doesn't evict still-fresh entries before their TTL elapses.
	clusterCacheSize = 2048
	// clusterCacheSizeMax caps the LRU so a very high --concurrency can't retain an
	// unbounded set of response bodies (each entry holds a ref-counted body).
	clusterCacheSizeMax = 8192
)

// ClustererSizeForConcurrency returns the LRU entry cap for a clusterer given the
// scan's concurrency. The set of TTL-fresh entries at any instant grows with
// in-flight request throughput, so the cache must be at least a few multiples of
// concurrency to avoid evicting fresh entries under wide fan-out — bounded by
// clusterCacheSizeMax to keep retained body memory in check.
func ClustererSizeForConcurrency(concurrency int) int {
	return min(max(concurrency*16, clusterCacheSize), clusterCacheSizeMax)
}

// CachedResponse holds a snapshot of response data that can be used to
// reconstruct independent ResponseChain instances. The body is a plain shared
// slice — its lifetime is managed by the LRU + GC (an entry's body is freed once
// the entry is evicted and every reconstructed chain referencing it is dropped).
type CachedResponse struct {
	StatusCode int
	Proto      string
	Header     http.Header
	body       []byte
	Request    *http.Request
	Duration   int
	CachedAt   time.Time
}

// Body returns the cached response body bytes (shared, do not modify).
func (c *CachedResponse) Body() []byte {
	return c.body
}

// snapshotResponse captures response data from a ResponseChain before Close().
func snapshotResponse(resp *httpUtils.ResponseChain, duration int) *CachedResponse {
	cr := &CachedResponse{
		Duration: duration,
		CachedAt: time.Now(),
	}

	// Copy the body bytes once (they reference pooled buffers reclaimed on Close).
	cr.body = append([]byte(nil), resp.BodyBytes()...)

	// Copy metadata from the underlying http.Response
	if r := resp.Response(); r != nil {
		cr.StatusCode = r.StatusCode
		cr.Proto = r.Proto
		cr.Header = r.Header.Clone()
		// Retain a shallow copy of the request with Body and Response nilled: the
		// response dump only reads Method/URL/Proto, while the original request's
		// .Response pins the entire redirect chain (each prior response + body) for
		// the cache entry's lifetime, and .Body can pin a sent request body.
		if r.Request != nil {
			reqCopy := *r.Request
			reqCopy.Body = nil
			reqCopy.Response = nil
			cr.Request = &reqCopy
		}
	}

	return cr
}

// ToResponseChain reconstructs an independent ResponseChain from cached data.
// The caller must call Close() on the returned chain when done.
// Uses reference-counted shared buffers to avoid copying body/header bytes.
func (c *CachedResponse) ToResponseChain() *httpUtils.ResponseChain {
	// Share the cache entry's body slice (read-only) — avoids a full copy on every
	// cache hit. Lifetime is managed by the LRU + GC.
	bodyBytes := c.body

	// http.Response.Write renders the status line from ProtoMajor/ProtoMinor —
	// parse Proto so the dumped response keeps the original HTTP version instead
	// of falling through to "HTTP/0.0".
	proto, major, minor := normalizeHTTPVersion(c.Proto)

	// Build a synthetic http.Response with body from cache
	resp := &http.Response{
		StatusCode: c.StatusCode,
		Proto:      proto,
		ProtoMajor: major,
		ProtoMinor: minor,
		Header:     c.Header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
		Request:    c.Request,
	}

	chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
	// Fill populates the headers and body pooled buffers from the response
	for chain.Has() {
		if err := chain.Fill(); err != nil {
			break
		}
		if !chain.Previous() {
			break
		}
	}
	return chain
}

// singleflightResult wraps the data returned through singleflight.
type singleflightResult struct {
	cached *CachedResponse
	err    error
}

// RequestClusterer deduplicates concurrent identical HTTP requests using
// singleflight for in-flight dedup and an LRU cache with TTL for near-concurrent dedup.
type RequestClusterer struct {
	group singleflight.Group
	cache *lru.Cache[string, *CachedResponse]
	mu    sync.RWMutex // protects cache access for TTL checks

	// Stats
	clustered atomic.Int64
	cacheHits atomic.Int64
	total     atomic.Int64
}

// ClustererStats holds clusterer metrics.
type ClustererStats struct {
	Total     int64
	Clustered int64
	CacheHits int64
}

// NewRequestClusterer creates a new RequestClusterer with the default LRU size.
func NewRequestClusterer() *RequestClusterer {
	return NewRequestClustererWithSize(clusterCacheSize)
}

// NewRequestClustererWithSize creates a RequestClusterer with an explicit LRU
// entry cap. Sizes below the floor (clusterCacheSize) are raised to it. Callers
// typically derive size from scan concurrency via ClustererSizeForConcurrency.
func NewRequestClustererWithSize(size int) *RequestClusterer {
	if size < clusterCacheSize {
		size = clusterCacheSize
	}
	cache, _ := lru.New[string, *CachedResponse](size)
	return &RequestClusterer{
		cache: cache,
	}
}

// Stats returns current clusterer metrics.
func (rc *RequestClusterer) Stats() ClustererStats {
	return ClustererStats{
		Total:     rc.total.Load(),
		Clustered: rc.clustered.Load(),
		CacheHits: rc.cacheHits.Load(),
	}
}

// Execute checks the cache and singleflight group before delegating to the
// actual HTTP executor. Returns (ResponseChain, duration, error).
// Cache hits receive duration=0.
func (rc *RequestClusterer) Execute(
	input *httpmsg.HttpRequestResponse,
	opts Options,
	doExecute func(*httpmsg.HttpRequestResponse, Options) (*httpUtils.ResponseChain, int, error),
) (*httpUtils.ResponseChain, int, error) {
	rc.total.Add(1)

	key := computeClusterKey(input, opts)

	// Layer 1: LRU cache check (TTL-aware)
	rc.mu.RLock()
	cached, ok := rc.cache.Get(key)
	fresh := ok && time.Since(cached.CachedAt) < clusterCacheTTL
	rc.mu.RUnlock()
	if fresh {
		rc.cacheHits.Add(1)
		return cached.ToResponseChain(), 0, nil
	}
	if ok {
		// Stale hit: drop it now so its body/request are freed immediately instead
		// of lingering in the LRU (TTL is short, 500ms) until capacity eviction.
		rc.mu.Lock()
		if c, stillThere := rc.cache.Peek(key); stillThere && c == cached {
			rc.cache.Remove(key)
		}
		rc.mu.Unlock()
	}

	// Layer 2: singleflight clustering
	resultIface, err, shared := rc.group.Do(key, func() (interface{}, error) {
		resp, duration, execErr := doExecute(input, opts)
		if execErr != nil {
			return &singleflightResult{err: execErr}, nil
		}

		// Snapshot before the primary caller closes the chain
		cached := snapshotResponse(resp, duration)
		resp.Close()

		// Store in cache
		rc.mu.Lock()
		rc.cache.Add(key, cached)
		rc.mu.Unlock()

		return &singleflightResult{cached: cached}, nil
	})

	if err != nil {
		return nil, 0, err
	}

	result := resultIface.(*singleflightResult)
	if result.err != nil {
		return nil, 0, result.err
	}

	if shared {
		rc.clustered.Add(1)
	}

	// Shared callers get duration=0 to avoid false positives in timing-based modules.
	// The singleflight `shared` flag is true for ALL callers (including the one that
	// executed the function) when multiple callers waited. We return real duration
	// from the cached result — which is fine since timing modules need the actual RTT.
	return result.cached.ToResponseChain(), result.cached.Duration, nil
}

// computeClusterKey returns a SHA-256 hash of the raw request bytes and option flags.
func computeClusterKey(input *httpmsg.HttpRequestResponse, opts Options) string {
	h := sha256.New()
	if req := input.Request(); req != nil {
		h.Write(req.Raw())
	}
	// Encode option flags that affect HTTP behavior. RawRequestTarget must be
	// part of the key: two probes can share identical raw bytes and differ only by
	// the literal request-line target (routing-based SSRF), and collapsing them
	// would serve the first probe's response for every target.
	_, _ = fmt.Fprintf(h, "\x00noRedir=%t\x00raw=%t\x00ignTimeout=%t\x00rawTarget=%s",
		opts.NoRedirects, opts.RawRequest, opts.IgnoreTimeoutTracking, opts.RawRequestTarget)
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeHTTPVersion returns the canonical Proto string and matching
// ProtoMajor/ProtoMinor for a cached response. Empty or malformed values fall
// back to HTTP/1.1 so the rebuilt response never renders a bogus "HTTP/0.0"
// status line.
func normalizeHTTPVersion(proto string) (string, int, int) {
	if major, minor, ok := http.ParseHTTPVersion(proto); ok && major > 0 {
		return proto, major, minor
	}
	return "HTTP/1.1", 1, 1
}

// LogStats logs clusterer statistics at info level.
func (rc *RequestClusterer) LogStats() {
	stats := rc.Stats()
	if stats.Total == 0 {
		return
	}
	zap.L().Info("Request clusterer stats",
		zap.Int64("total", stats.Total),
		zap.Int64("clustered", stats.Clustered),
		zap.Int64("cache_hits", stats.CacheHits),
	)
}
