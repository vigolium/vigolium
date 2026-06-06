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
	clusterCacheTTL  = 500 * time.Millisecond
	clusterCacheSize = 2048
)

// sharedBytes is a reference-counted byte slice that avoids copying response
// bodies on every cache hit. When the last reference is released the slice
// becomes eligible for GC.
type sharedBytes struct {
	data []byte
	refs atomic.Int64
}

// newSharedBytes wraps data in a reference-counted container with refcount=1.
func newSharedBytes(data []byte) *sharedBytes {
	sb := &sharedBytes{data: data}
	sb.refs.Store(1)
	return sb
}

// acquire increments the reference count and returns the underlying slice.
// Returns nil if the buffer has already been fully released (should not happen
// in normal usage since the cache holds a reference).
func (sb *sharedBytes) acquire() []byte {
	if sb.refs.Add(1) <= 1 {
		// Was zero — already released; undo the add (best-effort)
		sb.refs.Add(-1)
		return nil
	}
	return sb.data
}

// CachedResponse holds a snapshot of response data that can be used to
// reconstruct independent ResponseChain instances.
type CachedResponse struct {
	StatusCode int
	Proto      string
	Header     http.Header
	body       *sharedBytes // reference-counted shared body
	headerDump *sharedBytes // reference-counted shared headers
	Request    *http.Request
	Duration   int
	CachedAt   time.Time
}

// Body returns the cached response body bytes (shared, do not modify).
func (c *CachedResponse) Body() []byte {
	if c.body == nil {
		return nil
	}
	return c.body.data
}

// snapshotResponse captures response data from a ResponseChain before Close().
func snapshotResponse(resp *httpUtils.ResponseChain, duration int) *CachedResponse {
	cr := &CachedResponse{
		Duration: duration,
		CachedAt: time.Now(),
	}

	// Copy header and body bytes once (they reference pooled buffers).
	// These shared buffers start with refcount=1 (owned by the cache entry).
	cr.headerDump = newSharedBytes(append([]byte(nil), resp.HeadersBytes()...))
	cr.body = newSharedBytes(append([]byte(nil), resp.BodyBytes()...))

	// Copy metadata from the underlying http.Response
	if r := resp.Response(); r != nil {
		cr.StatusCode = r.StatusCode
		cr.Proto = r.Proto
		cr.Header = r.Header.Clone()
		cr.Request = r.Request
	}

	return cr
}

// ToResponseChain reconstructs an independent ResponseChain from cached data.
// The caller must call Close() on the returned chain when done.
// Uses reference-counted shared buffers to avoid copying body/header bytes.
func (c *CachedResponse) ToResponseChain() *httpUtils.ResponseChain {
	// Acquire shared references — these are the same underlying slices as the
	// cache entry, avoiding a full copy on every cache hit.
	var bodyBytes []byte
	if c.body != nil {
		if acquired := c.body.acquire(); acquired != nil {
			bodyBytes = acquired
		}
	}

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

// NewRequestClusterer creates a new RequestClusterer.
func NewRequestClusterer() *RequestClusterer {
	cache, _ := lru.New[string, *CachedResponse](clusterCacheSize)
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
	if cached, ok := rc.cache.Get(key); ok {
		if time.Since(cached.CachedAt) < clusterCacheTTL {
			rc.mu.RUnlock()
			rc.cacheHits.Add(1)
			return cached.ToResponseChain(), 0, nil
		}
	}
	rc.mu.RUnlock()

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
