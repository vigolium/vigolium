// Package tracker provides per-prefix circuit-breaker state for discovery.
//
// The PrefixBreaker watches probe outcomes grouped by (host, path-prefix) and
// trips when responses under a prefix become overwhelmingly uniform — i.e. the
// server is returning the same shape for everything under that prefix
// (e.g. Juice Shop's /ftp returns 403 + same HTML for any subpath). Once
// tripped, callers can ask IsDead(prefix) to skip queuing further child tasks
// instead of recursing into a black hole.
//
// The breaker is intentionally content-agnostic: it only inspects status code,
// content-type prefix, and a coarse length bucket. This catches both 4xx traps
// and 200-OK soft-404 traps that fool the fingerprint-based detector.
package tracker

import (
	"net/url"
	"strings"
	"sync"
)

// BreakerConfig tunes when the breaker trips.
type BreakerConfig struct {
	// Enabled toggles the whole feature. Zero value disables.
	Enabled bool
	// MinSamples is the number of observations required under a prefix
	// before the breaker may trip. Below this it stays open.
	MinSamples int
	// TripRatio is the share (0..1] of observations that must share the
	// same (status, content-type, length-bucket) tuple to trip.
	TripRatio float64
	// PrefixSegments is how many leading path segments form the prefix key.
	// 1 = "/ftp", 2 = "/ftp/api", etc.
	PrefixSegments int
	// LengthBucket is the byte-size bucket width used to group response sizes.
	// Two responses fall into the same bucket if their lengths div by this
	// value are equal.
	LengthBucket int64
}

// DefaultBreakerConfig returns sensible defaults: enabled, trips after 12
// samples when 90% share the same response shape, prefix = 1 segment.
func DefaultBreakerConfig() BreakerConfig {
	return BreakerConfig{
		Enabled:        true,
		MinSamples:     12,
		TripRatio:      0.9,
		PrefixSegments: 1,
		LengthBucket:   256,
	}
}

// PrefixBreaker tracks per-prefix probe outcomes and trips when uniformity
// thresholds are met. Safe for concurrent use.
type PrefixBreaker struct {
	cfg BreakerConfig

	mu      sync.RWMutex
	buckets map[string]*prefixBucket // key = host + "|" + prefix
	tripped map[string]TrippedReason // key = host + "|" + prefix; presence = tripped
}

// TrippedReason describes why a prefix was marked dead. Returned by IsDeadReason
// for telemetry/logging.
type TrippedReason struct {
	Host             string
	Prefix           string
	Samples          int
	DominantStatus   int
	DominantCT       string
	DominantLenLower int64 // start of bucket (in bytes)
	DominantCount    int
}

type prefixBucket struct {
	host   string
	prefix string
	total  int
	counts map[outcomeKey]int
}

type outcomeKey struct {
	status   int
	ctPrefix string // content-type up to ';', lowercased
	lenBkt   int64  // length / cfg.LengthBucket
}

// NewPrefixBreaker creates a breaker. If cfg.Enabled is false, all methods
// become no-ops and IsDead always returns false.
func NewPrefixBreaker(cfg BreakerConfig) *PrefixBreaker {
	return &PrefixBreaker{
		cfg:     cfg,
		buckets: make(map[string]*prefixBucket),
		tripped: make(map[string]TrippedReason),
	}
}

// Observe records a probe outcome. Callers should pass the request URL plus
// the response status, content-type header value, and body length. Returns
// the TrippedReason and true when this observation caused the prefix to trip
// for the first time; otherwise (false, _).
func (b *PrefixBreaker) Observe(reqURL *url.URL, status int, contentType string, bodyLen int64) (TrippedReason, bool) {
	if b == nil || !b.cfg.Enabled || reqURL == nil {
		return TrippedReason{}, false
	}

	host := reqURL.Host
	prefix := PrefixOf(reqURL.Path, b.cfg.PrefixSegments)
	if prefix == "" {
		return TrippedReason{}, false
	}
	key := host + "|" + prefix

	b.mu.RLock()
	if _, dead := b.tripped[key]; dead {
		b.mu.RUnlock()
		return TrippedReason{}, false
	}
	b.mu.RUnlock()

	ok := outcomeKey{
		status:   status,
		ctPrefix: normalizeContentType(contentType),
		lenBkt:   lengthBucket(bodyLen, b.cfg.LengthBucket),
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Re-check tripped under write lock (could have changed between RUnlock+Lock).
	if _, dead := b.tripped[key]; dead {
		return TrippedReason{}, false
	}

	bk := b.buckets[key]
	if bk == nil {
		bk = &prefixBucket{
			host:   host,
			prefix: prefix,
			counts: make(map[outcomeKey]int),
		}
		b.buckets[key] = bk
	}
	bk.total++
	bk.counts[ok]++

	if bk.total < b.cfg.MinSamples {
		return TrippedReason{}, false
	}

	dominantKey, dominantCount := pickDominant(bk.counts)
	if float64(dominantCount)/float64(bk.total) < b.cfg.TripRatio {
		return TrippedReason{}, false
	}

	reason := TrippedReason{
		Host:             host,
		Prefix:           prefix,
		Samples:          bk.total,
		DominantStatus:   dominantKey.status,
		DominantCT:       dominantKey.ctPrefix,
		DominantLenLower: dominantKey.lenBkt * b.cfg.LengthBucket,
		DominantCount:    dominantCount,
	}
	b.tripped[key] = reason
	delete(b.buckets, key) // free memory; we no longer need samples
	return reason, true
}

// IsDead returns true if the prefix derived from reqURL has tripped.
func (b *PrefixBreaker) IsDead(reqURL *url.URL) bool {
	if b == nil || !b.cfg.Enabled || reqURL == nil {
		return false
	}
	prefix := PrefixOf(reqURL.Path, b.cfg.PrefixSegments)
	if prefix == "" {
		return false
	}
	key := reqURL.Host + "|" + prefix
	b.mu.RLock()
	_, dead := b.tripped[key]
	b.mu.RUnlock()
	return dead
}

// IsDeadReason is like IsDead but also returns the trip reason. The bool is
// false when the prefix is not tripped.
func (b *PrefixBreaker) IsDeadReason(reqURL *url.URL) (TrippedReason, bool) {
	if b == nil || !b.cfg.Enabled || reqURL == nil {
		return TrippedReason{}, false
	}
	prefix := PrefixOf(reqURL.Path, b.cfg.PrefixSegments)
	if prefix == "" {
		return TrippedReason{}, false
	}
	key := reqURL.Host + "|" + prefix
	b.mu.RLock()
	r, dead := b.tripped[key]
	b.mu.RUnlock()
	return r, dead
}

// TrippedCount returns the number of prefixes currently in the dead state.
// Useful for scan summary telemetry.
func (b *PrefixBreaker) TrippedCount() int {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.tripped)
}

// PrefixOf returns the leading n path segments of urlPath, joined with "/"
// and prefixed with "/". Returns "" for empty / root paths or n<=0.
//
// Examples (n=1): "/ftp/api/x" → "/ftp"; "/x" → "/x"; "/" → "".
// Examples (n=2): "/ftp/api/x" → "/ftp/api"; "/ftp" → "/ftp".
func PrefixOf(urlPath string, n int) string {
	if n <= 0 || urlPath == "" || urlPath == "/" {
		return ""
	}
	trimmed := strings.Trim(urlPath, "/")
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) > n {
		parts = parts[:n]
	}
	return "/" + strings.Join(parts, "/")
}

// normalizeContentType returns the media type lowercase, trimmed at ';'.
// Empty in → empty out.
func normalizeContentType(ct string) string {
	if ct == "" {
		return ""
	}
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// lengthBucket buckets a byte length into bucket-sized groups.
// Negative or zero bucket width collapses everything into bucket 0.
func lengthBucket(n, width int64) int64 {
	if width <= 0 {
		return 0
	}
	if n < 0 {
		n = 0
	}
	return n / width
}

// pickDominant returns the key with the highest count and its count.
// Map iteration order is non-deterministic; ties are broken arbitrarily.
func pickDominant(counts map[outcomeKey]int) (outcomeKey, int) {
	var best outcomeKey
	var bestCount int
	for k, c := range counts {
		if c > bestCount {
			best = k
			bestCount = c
		}
	}
	return best, bestCount
}
