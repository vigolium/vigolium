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
}

// NewComparator creates a new comparator
func NewComparator(cache *Cache, learner *Learner) *Comparator {
	return &Comparator{
		cache:   cache,
		learner: learner,
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
		testURL.Path = pathVariation

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
	// Quick exit: HTTP 404 is always a false positive (wildcard)
	if rc.Response().StatusCode == 404 {
		return FalsePositive, nil
	}

	// Cascade check - catches cross-extension soft-404s
	// This is needed when CheckWildcardWithValidation is called directly
	if c.cache.MatchesWithCascade(targetURL, sample) {
		return FalsePositive, nil
	}

	// No match in cache - need to validate with wildcard test
	key := ExtractCacheKey(targetURL)
	isValid, err := c.validateWithWildcardTest(ctx, targetURL, key)
	if err != nil {
		// Failed to validate - return unknown
		return Unknown, err
	}

	if isValid {
		return TruePositive, nil
	}

	return FalsePositive, nil
}

// validateWithWildcardTest performs 4-path wildcard validation.
// Uses 4 strategies that only modify the last segment, preserving directory structure.
// This ensures test paths stay within path-based catch-all patterns like /api/v1/*
//
// Algorithm:
// 1. Generate 4 random path variations (Prefix, Suffix, Extension, Middle)
// 2. Fetch each path with delays
// 3. If ALL return non-content (404, errors) -> content is VALID
// 4. If ANY return content -> learn as wildcard and return FALSE
func (c *Comparator) validateWithWildcardTest(ctx context.Context, targetURL *url.URL, key CacheKey) (bool, error) {
	basePath := targetURL.Path
	if basePath == "" {
		basePath = "/"
	}

	// Test path 1: Prepend random to last segment (6 chars)
	// Detects suffix wildcards like *admin
	prefix, err := generateRandomHex(6)
	if err != nil {
		return false, err
	}
	testPath1 := prependToLastSegment(basePath, prefix)

	// Test path 2: Append random to last segment (6 chars)
	// Detects prefix wildcards like user*
	suffix, err := generateRandomHex(6)
	if err != nil {
		return false, err
	}
	testPath2 := appendToLastSegment(basePath, suffix)

	// Test path 3: Add fake extension (4 chars)
	// Detects extension-based routing
	fakeExt, err := generateRandomHex(4)
	if err != nil {
		return false, err
	}
	testPath3 := addFakeExtension(basePath, fakeExt)

	// Test path 4: Insert random into middle (9 chars)
	// Most effective - breaks both prefix AND suffix wildcards
	middle, err := generateRandomHex(9)
	if err != nil {
		return false, err
	}
	testPath4 := insertIntoLastSegment(basePath, middle)

	// Map paths to strategies for tracking
	testConfigs := []struct {
		path     string
		strategy PathVariation
	}{
		{testPath1, VariationPrefix},
		{testPath2, VariationSuffix},
		{testPath3, VariationExtension},
		{testPath4, VariationMiddle},
	}

	// Fetch all 4 random paths and track which strategy detected wildcard
	wildcardDetections := make([]WildcardDetection, 0, 4)
	foundContent := false

	for i, config := range testConfigs {
		// Add delay between requests (except first)
		if i > 0 {
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}

		// Build test URL
		testURL := *targetURL
		testURL.Path = config.path

		// Fetch the random path
		sample, hasContent, err := c.fetchAndCheckContent(ctx, &testURL)
		if err != nil {
			// Ignore errors - treat as no content
			continue
		}

		// Track which strategy detected this wildcard
		if hasContent {
			foundContent = true
			wildcardDetections = append(wildcardDetections, WildcardDetection{
				Sample:   sample,
				Strategy: config.strategy,
			})
		}
	}

	// If ALL random paths returned no content -> target is VALID
	if !foundContent {
		return true, nil
	}

	// At least one random path returned content -> wildcard detected
	// Learn these wildcard responses and cache them
	if len(wildcardDetections) > 0 {
		_ = c.learnWildcardPatterns(ctx, key, targetURL, wildcardDetections)
	}

	return false, nil
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
		path1, err := GenerateRandomPathWithVariation(baseURL.Path, detection.Strategy, length1)
		if err != nil {
			continue
		}

		path2, err := GenerateRandomPathWithVariation(baseURL.Path, detection.Strategy, length2)
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
			testURL.Path = path

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
