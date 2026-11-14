package http

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
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

	// clusterCacheMaxEntryBytes is the largest response body eligible for the
	// post-request cache. Larger responses still get in-flight singleflight dedup
	// (the high-confidence saving) but are never retained afterward — one huge
	// body must not consume the whole cache budget.
	clusterCacheMaxEntryBytes = 2 << 20 // 2 MiB

	// clusterCacheMaxBytes bounds the total retained response-body bytes across all
	// cache entries. Entry count alone is not a safe memory bound: 8192 entries ×
	// large bodies could retain gigabytes. LRU entries are evicted until the cache
	// is back under this budget.
	clusterCacheMaxBytes = 128 << 20 // 128 MiB

	// clusterEntryOverheadBytes approximates the per-entry header/URL/metadata
	// retained alongside the body, so the byte budget isn't understated for many
	// small entries.
	clusterEntryOverheadBytes = 512
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
	// Close mirrors http.Response.Close: the server signalled it is closing the
	// connection rather than keeping it alive. Go strips the hop-by-hop
	// Connection header from Header before a module ever sees it, so this flag is
	// the only surviving record of keep-alive state - without it every cache hit
	// reports a reusable connection, which silently defeats any module gating on
	// connection reuse (request smuggling, RQP cache poisoning).
	Close    bool
	body     []byte
	Request  *http.Request
	Duration time.Duration
	CachedAt time.Time
}

// Body returns the cached response body bytes (shared, do not modify).
func (c *CachedResponse) Body() []byte {
	return c.body
}

// snapshotResponse captures response data from a ResponseChain before Close().
func snapshotResponse(resp *httpUtils.ResponseChain, duration time.Duration) *CachedResponse {
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
		cr.Close = r.Close
		cr.Header = r.Header.Clone()
		// resp.BodyBytes() above was already decoded by responsechain.Fill (per the
		// response's Content-Encoding), so the captured body no longer matches these
		// content-coding / framing headers. Strip them here — the single point where
		// the decoded body and its headers are paired — so the cached entry is
		// self-consistent and no reconstruction (ToResponseChain) re-decodes the
		// plaintext body. Del is a safe no-op on a nil header.
		cr.Header.Del("Content-Encoding")
		cr.Header.Del("Content-Length")
		cr.Header.Del("Transfer-Encoding")
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

	// snapshotResponse already stripped the content-coding / framing headers from the
	// cached header (the body was decoded before capture), so ResponseChain.Fill
	// won't try to decode this plaintext body a second time. Clone so the
	// reconstructed response owns its header map; set ContentLength to the decoded
	// length so the headers-only dump reports the real size instead of 0.
	header := c.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}

	// Build a synthetic http.Response with body from cache
	resp := &http.Response{
		StatusCode:    c.StatusCode,
		Proto:         proto,
		ProtoMajor:    major,
		ProtoMinor:    minor,
		Header:        header,
		Close:         c.Close,
		Body:          io.NopCloser(bytes.NewReader(bodyBytes)),
		ContentLength: int64(len(bodyBytes)),
		Request:       c.Request,
	}

	chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
	// Fill populates the headers and body pooled buffers from the response.
	// Once, not in a Previous() walk: the reconstructed response above carries
	// no Request.Response, so there is no chain to walk — and the walking form
	// of this idiom is what silently discarded the final response on the live
	// path (see doRequest). Leaving a copy of it here would invite it back.
	_ = chain.Fill()
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
	mu    sync.RWMutex // protects cache access, retainedBytes, and TTL checks

	// retainedBytes tracks the approximate response-body bytes currently held by
	// the cache. Maintained under mu: incremented on admission, decremented by the
	// LRU evict callback. Used to keep the cache under clusterCacheMaxBytes.
	retainedBytes int64

	// Stats
	clustered     atomic.Int64
	cacheHits     atomic.Int64
	total         atomic.Int64
	byteEvictions atomic.Int64 // entries dropped to stay under the byte budget
	sizeRejects   atomic.Int64 // bodies too large to post-cache (singleflight only)
}

// entryWeight approximates the bytes an entry retains: its body plus a fixed
// overhead for headers/URL/metadata.
func entryWeight(cr *CachedResponse) int64 {
	if cr == nil {
		return clusterEntryOverheadBytes
	}
	return int64(len(cr.body)) + clusterEntryOverheadBytes
}

// ClustererStats holds clusterer metrics.
type ClustererStats struct {
	Total         int64
	Clustered     int64
	CacheHits     int64
	RetainedBytes int64 // approximate response-body bytes currently cached
	ByteEvictions int64 // entries evicted to stay under the byte budget
	SizeRejects   int64 // responses too large to post-cache
}

// NewRequestClustererWithSize creates a RequestClusterer with an explicit LRU
// entry cap. Sizes below the floor (clusterCacheSize) are raised to it. Callers
// typically derive size from scan concurrency via ClustererSizeForConcurrency.
func NewRequestClustererWithSize(size int) *RequestClusterer {
	if size < clusterCacheSize {
		size = clusterCacheSize
	}
	rc := &RequestClusterer{}
	// Evict callback keeps retainedBytes in sync however an entry leaves the cache
	// (capacity eviction, byte-budget eviction, TTL removal). It runs synchronously
	// inside the LRU op, which the caller always performs under rc.mu, so the
	// bare-field update needs no extra locking.
	cache, _ := lru.NewWithEvict[string, *CachedResponse](size, func(_ string, cr *CachedResponse) {
		rc.retainedBytes -= entryWeight(cr)
		if rc.retainedBytes < 0 {
			rc.retainedBytes = 0
		}
	})
	rc.cache = cache
	return rc
}

// Stats returns current clusterer metrics.
func (rc *RequestClusterer) Stats() ClustererStats {
	rc.mu.RLock()
	retained := rc.retainedBytes
	rc.mu.RUnlock()
	return ClustererStats{
		Total:         rc.total.Load(),
		Clustered:     rc.clustered.Load(),
		CacheHits:     rc.cacheHits.Load(),
		RetainedBytes: retained,
		ByteEvictions: rc.byteEvictions.Load(),
		SizeRejects:   rc.sizeRejects.Load(),
	}
}

// Execute checks the cache and singleflight group before delegating to the
// actual HTTP executor. Returns (ResponseChain, duration, error).
// Cache hits receive duration=0.
func (rc *RequestClusterer) Execute(
	input *httpmsg.HttpRequestResponse,
	opts Options,
	doExecute func(*httpmsg.HttpRequestResponse, Options) (*httpUtils.ResponseChain, time.Duration, error),
) (*httpUtils.ResponseChain, time.Duration, error) {
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

		// Store in cache under the byte budget (skips bodies too large to retain).
		rc.admitToCache(key, cached)

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

// admitToCache stores cached under key subject to the cache's byte budget. A body
// larger than the per-entry cap is never retained (its in-flight singleflight
// dedup already happened); otherwise it is added, retainedBytes is updated, and
// LRU entries are evicted until the cache is back under the total byte budget.
func (rc *RequestClusterer) admitToCache(key string, cached *CachedResponse) {
	if int64(len(cached.body)) > clusterCacheMaxEntryBytes {
		rc.sizeRejects.Add(1)
		return
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Replace any existing entry explicitly so the evict callback subtracts its
	// old weight before we add the new one (keeps retainedBytes exact).
	if _, ok := rc.cache.Peek(key); ok {
		rc.cache.Remove(key)
	}
	rc.cache.Add(key, cached) // capacity eviction (if any) runs the evict callback
	rc.retainedBytes += entryWeight(cached)

	// Evict least-recently-used entries until back under the byte budget. The
	// just-added entry is the most-recently-used, so RemoveOldest never targets it
	// (and a single entry can't exceed the budget: it's capped at 2 MiB << 128 MiB).
	for rc.retainedBytes > clusterCacheMaxBytes {
		if _, _, ok := rc.cache.RemoveOldest(); !ok {
			break
		}
		rc.byteEvictions.Add(1)
	}
}

// computeClusterKey returns the request's cached content hash combined with the
// option flags that affect HTTP behavior.
func computeClusterKey(input *httpmsg.HttpRequestResponse, opts Options) string {
	var prefix string
	if req := input.Request(); req != nil {
		// Reuse the request's cached SHA-256 (HttpRequest.ID) instead of hashing
		// req.Raw() a second time. ID() is already computed and cached for the
		// host-error tracker and the insertion-point cache, so this avoids a full
		// second SHA-256 pass over the (possibly large) request body on every
		// clustered Execute.
		prefix = req.ID()
	}
	// Append the option flags verbatim — no hashing needed, the 64-char hex
	// prefix already disambiguates the request bytes. RawRequestTarget must be
	// part of the key: two probes can share identical raw bytes and differ only by
	// the literal request-line target (routing-based SSRF), and collapsing them
	// would serve the first probe's response for every target.
	var b strings.Builder
	b.Grow(len(prefix) + len(opts.RawRequestTarget) + len(opts.clusterScope) + 80)
	b.WriteString(prefix)
	b.WriteString("\x00noRedir=")
	b.WriteString(strconv.FormatBool(opts.NoRedirects))
	b.WriteString("\x00raw=")
	b.WriteString(strconv.FormatBool(opts.RawRequest))
	b.WriteString("\x00ignTimeout=")
	b.WriteString(strconv.FormatBool(opts.IgnoreTimeoutTracking))
	// DisableCompression changes the request (drops Accept-Encoding) and the
	// response handling (Go auto-decompression), so two otherwise-identical
	// requests differing only in this flag must not be coalesced — the second
	// caller would receive a body produced under the first's compression behavior.
	b.WriteString("\x00noCompress=")
	b.WriteString(strconv.FormatBool(opts.DisableCompression))
	b.WriteString("\x00rawTarget=")
	b.WriteString(opts.RawRequestTarget)
	// Partitions the cache by credential identity; see Options.clusterScope.
	b.WriteString("\x00scope=")
	b.WriteString(opts.clusterScope)
	return b.String()
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
		zap.Int64("retained_bytes", stats.RetainedBytes),
		zap.Int64("byte_evictions", stats.ByteEvictions),
		zap.Int64("size_rejects", stats.SizeRejects),
	)
}
