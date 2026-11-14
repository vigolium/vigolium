package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"go.uber.org/zap"
)

// MatchResult represents the result of fingerprint comparison
type MatchResult byte

const (
	Unknown       MatchResult = 0 // Unable to determine
	TruePositive  MatchResult = 1 // Real resource (not 404)
	FalsePositive MatchResult = 2 // 404/error page (soft 404)
)

// String returns string representation of match result
func (mr MatchResult) String() string {
	switch mr {
	case Unknown:
		return "Unknown"
	case TruePositive:
		return "TruePositive"
	case FalsePositive:
		return "FalsePositive"
	default:
		return fmt.Sprintf("MatchResult(%d)", mr)
	}
}

// WildcardDetection tracks which strategy detected a wildcard response
type WildcardDetection struct {
	Sample   *Sample
	Strategy PathVariation // Which path generation strategy detected this wildcard
}

// Comparator implements fingerprint comparison and validation logic
type Comparator struct {
	cache   *Cache
	learner *Learner
	clean   *cleanVerdicts
}

// NewComparator creates a new comparator
func NewComparator(cache *Cache, learner *Learner) *Comparator {
	return &Comparator{
		cache:   cache,
		learner: learner,
		clean:   newCleanVerdicts(cleanVerdictMax, cleanVerdictTTL),
	}
}

// Compare compares a response against cached signatures using cascading check.
//
// Algorithm (updated with cascade):
// 1. Extract sample from response
// 2. Cascade check: "" extension → all host signatures → base extension
// 3. If match → FalsePositive (soft 404)
// 4. If no signatures for host → Unknown (need to learn)
// 5. If no match → CheckWildcardWithValidation (3-path test)
func (c *Comparator) Compare(ctx context.Context, req *http.Request, rc *responsechain.ResponseChain) (MatchResult, error) {
	if req == nil || rc == nil || !rc.Has() {
		return Unknown, fmt.Errorf("request or response is nil")
	}

	resp := rc.Response()

	// Extract sample using centralized function
	sample, err := NewSampleFromRC(rc)
	if err != nil {
		return Unknown, fmt.Errorf("failed to extract sample: %w", err)
	}

	// Debug: Log sample details for redirect responses
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		logger.Debug("Compare: redirect response sample",
			zap.String("url", req.URL.String()),
			zap.Int("status", resp.StatusCode),
			zap.String("location", resp.Header.Get("Location")),
			zap.Uint32("sample_status_hash", sample.GetHash(StatusCode)),
			zap.Uint32("sample_location_hash", sample.GetHash(Location)))
	}

	// Steps 1-3: Cascade signature check
	// Check "" extension → all host signatures → base extension
	if c.cache.MatchesWithCascade(req.URL, sample) {
		logger.Debug("Compare: FalsePositive (cascade match)",
			zap.String("url", req.URL.String()),
			zap.Int("status", resp.StatusCode))
		return FalsePositive, nil // Matches known soft-404 signature
	}

	// Step 4: Full wildcard validation (3-path test)
	// Called for both cases:
	// - No signatures exist for host (need to learn)
	// - Has signatures but no match (need to validate)
	// This avoids duplicate sample extraction in caller
	if !c.cache.HasSignaturesForHost(req.URL.Host) {
		logger.Debug("Compare: no signatures for host, proceeding to wildcard validation",
			zap.String("url", req.URL.String()),
			zap.String("host", req.URL.Host))
	} else {
		logger.Debug("Compare: has signatures but no match, proceeding to wildcard validation",
			zap.String("url", req.URL.String()),
			zap.Int("status", resp.StatusCode))
	}
	return c.CheckWildcardWithValidation(ctx, req.URL, rc, sample)
}

// CompareWithLearning compares and learns if no signatures exist
func (c *Comparator) CompareWithLearning(ctx context.Context, req *http.Request, rc *responsechain.ResponseChain) (MatchResult, error) {
	// Try normal comparison first
	result, err := c.Compare(ctx, req, rc)
	if err != nil {
		return Unknown, err
	}

	// If result is unknown, try to learn
	if result == Unknown {
		key := ExtractCacheKey(req.URL)

		// Learn signature for this URL
		_, learnErr := c.cache.LearnAndCache(ctx, key, req.URL)
		if learnErr != nil {
			// Learning failed, but don't return error
			// Just return Unknown result
			return Unknown, learnErr
		}

		// Re-compare with newly learned signature
		return c.Compare(ctx, req, rc)
	}

	return result, nil
}

// ValidateDynamic performs dynamic validation using path variations
//
// Algorithm:
// 1. Generate 3 new random path variations from the current URL
// 2. Request each variation
// 3. Check if responses match existing signatures
// 4. If all match -> likely 404 pattern
// 5. If none match -> likely real resource
func (c *Comparator) ValidateDynamic(ctx context.Context, req *http.Request, sample *Sample) (MatchResult, error) {
	if req == nil || req.URL == nil {
		return Unknown, fmt.Errorf("request or URL is nil")
	}

	// Generate 3 random path variations
	paths, err := GenerateRandomPaths(req.URL)
	if err != nil {
		return Unknown, fmt.Errorf("failed to generate random paths: %w", err)
	}

	key := ExtractCacheKey(req.URL)
	matchCount := 0

	// Request each variation and check if it matches existing signatures
	for _, pathVariation := range paths {
		testURL := *req.URL // Copy
		SetWirePath(&testURL, pathVariation)

		// Request the variation
		varSample, err := c.learner.RequestAndExtract(ctx, &testURL)
		if err != nil {
			// Skip on error
			continue
		}

		// Check if this variation matches cached signatures
		if c.cache.Matches(key, varSample) {
			matchCount++
		}
	}

	// If most/all variations match known signatures, original is likely 404
	if matchCount >= 2 {
		return FalsePositive, nil
	}

	// If few/no variations match, original is likely real resource
	if matchCount == 0 {
		return TruePositive, nil
	}

	// Ambiguous
	return Unknown, nil
}

// IsSoft404 is a convenience method to check if response is a soft 404
func (c *Comparator) IsSoft404(ctx context.Context, req *http.Request, rc *responsechain.ResponseChain) (bool, error) {
	result, err := c.Compare(ctx, req, rc)
	if err != nil {
		return false, err
	}

	return result == FalsePositive, nil
}

// LearnIfNeeded learns signature if no signatures exist for the URL
func (c *Comparator) LearnIfNeeded(ctx context.Context, url *url.URL) error {
	key := ExtractCacheKey(url)

	// Check if we already have signatures
	sigs, ok := c.cache.Get(key)
	if ok && len(sigs) > 0 {
		return nil // Already have signatures
	}

	// Learn new signature
	_, err := c.cache.LearnAndCache(ctx, key, url)
	return err
}

// CheckWildcardWithValidation performs complete wildcard detection with 3-path validation
//
// This is the FINAL step in the detection flow, called after cascade check passes.
// Algorithm:
// 1. Quick exit if HTTP 404
// 2. Cascade check (already done by caller, but double-check for safety)
// 3. If no match, perform 3-path wildcard validation
// 4. Learn new wildcard patterns if detected
// 5. Return whether content is valid or wildcard
func (c *Comparator) CheckWildcardWithValidation(ctx context.Context, targetURL *url.URL, rc *responsechain.ResponseChain, sample *Sample) (MatchResult, error) {
	// Quick exit: a hard miss (404, 400, 414, 421, 431) never means content.
	if IsHardMissStatus(rc.Response().StatusCode) {
		return FalsePositive, nil
	}

	// Cascade check - catches cross-extension soft-404s
	// This is needed when CheckWildcardWithValidation is called directly
	if c.cache.MatchesWithCascade(targetURL, sample) {
		return FalsePositive, nil
	}

	// No match in cache - need to validate with wildcard test
	key := ExtractCacheKey(targetURL)
	verdict, err := c.validateWithWildcardTest(ctx, targetURL, key, sample)
	if err != nil {
		// Failed to validate - return unknown
		return Unknown, err
	}
	return verdict, nil
}

// validateWithWildcardTest performs 4-path wildcard validation.
// Uses 4 strategies that only modify the last segment, preserving directory structure.
// This ensures test paths stay within path-based catch-all patterns like /api/v1/*
//
// The 4 strategies split into two classes by whether they break the segment's
// leading characters:
//   - prefix-BREAKING: Prefix (prepend random) and Middle (insert random) — the
//     probed path no longer starts with the target segment.
//   - prefix-PRESERVING: Suffix (append) and Extension (add fake ext) — the probed
//     path still starts with the target segment.
//
// A GENUINE host-wide catch-all answers content even for prefix-breaking probes.
// A server that merely routes on the segment prefix (e.g. a gateway mapping
// "/metrics*" to a real /metrics endpoint that returns an empty 200 on the
// backends without the exporter) answers content ONLY for the prefix-preserving
// probes while prefix-breaking probes 404. Treating that as a wildcard drops a
// real resource, so we suppress ONLY when a prefix-breaking probe returns content.
//
// Algorithm:
//  1. Generate 4 random path variations (Prefix, Suffix, Extension, Middle)
//  2. Fetch each path with delays
//  3. If NO prefix-breaking probe returns content -> content is VALID (covers both
//     "all probes 404" unique files and "only prefix-preserving 200" real routes)
//  4. If a prefix-breaking probe returns content that RESEMBLES the hit (same
//     status and content type, same tag structure or length bucket) -> learn as
//     wildcard and return FalsePositive. A breaking sibling that answers with a
//     different page (a 403 next to a 200 hit) is not evidence against the hit.
//
// Siblings that answer with a hard-miss status (404/400/414/421/431) are misses
// whatever the cache knows about their shape. A sibling that was throttled
// (429/503/edge block) says nothing about the directory; when no resembling
// breaking sibling was seen the verdict is Unknown, which keeps the hit.
func (c *Comparator) validateWithWildcardTest(ctx context.Context, targetURL *url.URL, key CacheKey, hit *Sample) (MatchResult, error) {
	// Escaped (wire) path so a bypass prefix survives into the sibling probes.
	basePath := targetURL.EscapedPath()
	if basePath == "" {
		basePath = "/"
	}
	gen := func(v PathVariation) (string, error) {
		switch v {
		case VariationPrefix:
			r, err := generateRandomHex(6)
			return prependToLastSegment(basePath, r), err
		case VariationSuffix:
			r, err := generateRandomHex(6)
			return appendToLastSegment(basePath, r), err
		case VariationExtension:
			r, err := generateRandomHex(4)
			return addFakeExtension(basePath, r), err
		default:
			r, err := generateRandomHex(9)
			return insertIntoLastSegment(basePath, r), err
		}
	}

	// Only the prefix-BREAKING probes (Prefix, Middle) decide the verdict, so
	// they go first; the prefix-preserving ones (Suffix, Extension) are fetched
	// only when a wildcard is being learned. A directory/extension that came
	// back clean recently is re-checked with the Middle probe alone.
	decisive := []PathVariation{VariationPrefix, VariationMiddle}
	cleanKey := cleanVerdictKey(targetURL, key)
	if c.clean != nil && c.clean.fresh(cleanKey) {
		decisive = []PathVariation{VariationMiddle}
	}

	var wildcardDetections []WildcardDetection
	breakingContent, throttled := false, false
	probe := func(i int, v PathVariation) error {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		wire, err := gen(v)
		if err != nil {
			return err
		}
		testURL := *targetURL
		SetWirePath(&testURL, wire)
		sample, hasContent, err := c.fetchAndCheckContent(ctx, &testURL)
		if err != nil {
			return nil // ignore errors - treat as no content
		}
		if sample.Throttled() {
			throttled = true
			return nil
		}
		if !hasContent {
			return nil
		}
		wildcardDetections = append(wildcardDetections, WildcardDetection{Sample: sample, Strategy: v})
		// A prefix-breaking probe returning the SAME page as the hit means the
		// catch-all does not require the segment's real leading characters ->
		// genuine wildcard. A different page does not make the hit a false positive.
		if (v == VariationPrefix || v == VariationMiddle) && (hit == nil || hit.Resembles(sample)) {
			breakingContent = true
		}
		return nil
	}

	n := 0
	for _, v := range decisive {
		if err := probe(n, v); err != nil {
			return Unknown, err
		}
		n++
		if breakingContent {
			break
		}
	}

	if !breakingContent {
		// A throttled sibling leaves the directory's shape unknown: keep the hit
		// without claiming it was validated (and remember nothing).
		if throttled {
			return Unknown, nil
		}
		if c.clean != nil {
			c.clean.mark(cleanKey)
		}
		return TruePositive, nil
	}

	// Genuine wildcard: fetch the prefix-preserving probes too, so every
	// catch-all shape this directory answers with is learned and cached.
	if c.clean != nil {
		c.clean.forget(cleanKey)
	}
	for _, v := range []PathVariation{VariationSuffix, VariationExtension} {
		if err := probe(n, v); err != nil {
			break
		}
		n++
	}
	_ = c.learnWildcardPatterns(ctx, key, targetURL, wildcardDetections)
	return FalsePositive, nil
}

// fetchAndCheckContent fetches a URL and checks if it returns content
//
// CRITICAL: Uses cascade check to catch cross-extension soft-404s!
func (c *Comparator) fetchAndCheckContent(ctx context.Context, targetURL *url.URL) (*Sample, bool, error) {
	// Fetch the URL
	sample, err := c.learner.RequestAndExtract(ctx, targetURL)
	if err != nil {
		return nil, false, err
	}

	// A hard-miss status is no content whatever shape the cache has seen: an
	// uncached 404 shape must not count as a sibling "with content".
	if IsHardMissStatus(sample.Status()) {
		return sample, false, nil
	}

	// Use CASCADE check instead of single extension match!
	// This is critical for detecting cross-extension soft-404s like:
	// - sample.php.backup matching .php signature
	// - any path matching "" (root wildcard) signature
	is404Like := c.cache.MatchesWithCascade(targetURL, sample)

	// hasContent = NOT 404-like
	hasContent := !is404Like

	return sample, hasContent, nil
}

// learnWildcardPatterns learns new wildcard fingerprints from detected wildcards.
// Each strategy is learned INDEPENDENTLY with 3 samples to get stable attributes.
func (c *Comparator) learnWildcardPatterns(ctx context.Context, key CacheKey, baseURL *url.URL, detections []WildcardDetection) error {
	// For each wildcard detection, re-learn using the SAME strategy that detected it
	for _, detection := range detections {
		// Check if already learned to avoid duplicates
		if c.cache.Matches(key, detection.Sample) {
			continue // Already learned, skip
		}

		// Determine re-learning lengths based on strategy
		var length1, length2 int
		switch detection.Strategy {
		case VariationPrefix, VariationSuffix, VariationMiddle:
			// Segment-based strategies use lengths (6, 12)
			length1, length2 = 6, 12
		case VariationExtension:
			// Extension strategy uses lengths (3, 5)
			length1, length2 = 3, 5
		default:
			length1, length2 = 6, 12
		}

		// Generate 2 random paths using SAME strategy with different lengths
		path1, err := GenerateRandomPathWithVariation(baseURL.EscapedPath(), detection.Strategy, length1)
		if err != nil {
			continue
		}

		path2, err := GenerateRandomPathWithVariation(baseURL.EscapedPath(), detection.Strategy, length2)
		if err != nil {
			continue
		}

		// Fetch the additional paths
		samples := []*Sample{detection.Sample}

		for i, path := range []string{path1, path2} {
			// Delay between requests
			if i > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(20 * time.Millisecond):
				}
			}

			testURL := *baseURL
			SetWirePath(&testURL, path)

			sample, err := c.learner.RequestAndExtract(ctx, &testURL)
			if err != nil {
				continue
			}

			samples = append(samples, sample)
		}

		// Create fingerprint from all 3 samples (original + 2 random)
		// Only stable attributes across all 3 are included
		if len(samples) >= 3 {
			sig, err := NewSignature(samples)
			if err != nil {
				continue
			}

			sig.SetDebug(fmt.Sprintf("wildcard learned from %s (strategy %d)", baseURL.Host, detection.Strategy))

			// Add to cache (cumulative - multiple signatures per key)
			c.cache.Add(key, sig)
		}
	}

	return nil
}
