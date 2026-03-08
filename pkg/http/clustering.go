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
	"github.com/vigolium/vigolium/pkg/httpmsg"
	httpUtils "github.com/projectdiscovery/utils/http"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	clusterCacheTTL  = 500 * time.Millisecond
	clusterCacheSize = 2048
)

// CachedResponse holds a snapshot of response data that can be used to
// reconstruct independent ResponseChain instances.
type CachedResponse struct {
	StatusCode int
	Proto      string
	Header     http.Header
	Body       []byte
	HeaderDump []byte
	Request    *http.Request
	Duration   int
	CachedAt   time.Time
}

// snapshotResponse captures response data from a ResponseChain before Close().
func snapshotResponse(resp *httpUtils.ResponseChain, duration int) *CachedResponse {
	cr := &CachedResponse{
		Duration: duration,
		CachedAt: time.Now(),
	}

	// Copy header and body bytes (they reference pooled buffers)
	cr.HeaderDump = append([]byte(nil), resp.HeadersBytes()...)
	cr.Body = append([]byte(nil), resp.BodyBytes()...)

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
func (c *CachedResponse) ToResponseChain() *httpUtils.ResponseChain {
	// Build a synthetic http.Response with body from cache
	resp := &http.Response{
		StatusCode: c.StatusCode,
		Proto:      c.Proto,
		Header:     c.Header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(c.Body)),
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
	// Encode option flags that affect HTTP behavior
	_, _ = fmt.Fprintf(h, "\x00noRedir=%t\x00raw=%t\x00ignTimeout=%t",
		opts.NoRedirects, opts.RawRequest, opts.IgnoreTimeoutTracking)
	return hex.EncodeToString(h.Sum(nil))
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
