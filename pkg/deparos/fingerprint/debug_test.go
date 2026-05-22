package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

const debugFingerprintTargetURL = "http://testphp.vulnweb.com/"

func requireReachableDebugHost(t *testing.T, targetURL string) *url.URL {
	t.Helper()

	baseURL, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, baseURL.String(), nil)
	if err != nil {
		t.Fatalf("Failed to create reachability probe: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("Skipping external debug test: %s is unreachable: %v", baseURL.Host, err)
	}
	_ = resp.Body.Close()

	return baseURL
}

// TestFingerprintLearningAndComparison runs against testphp.vulnweb.com
// to debug why 404s are not filtered.
//
// Run with: go test -v -timeout 120s -run TestFingerprintLearningAndComparison ./god/internal/infrastructure/fingerprint/
func TestFingerprintLearningAndComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("network integration test against an external host; skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	baseURL := requireReachableDebugHost(t, debugFingerprintTargetURL)

	client := &http.Client{Timeout: 10 * time.Second}
	learner := NewLearner(client, nil)
	learner.SetDelay(500 * time.Millisecond) // Faster for testing
	cache := NewCache(learner)
	comparator := NewComparator(cache, learner)

	fmt.Println("=== STEP 1: Learning baseline fingerprints ===")

	// Test extensions to learn
	extensions := []string{"", ".php", ".html"}

	for _, ext := range extensions {
		key := CacheKey{
			Host:      baseURL.Host,
			Extension: ext,
		}

		fmt.Printf("\n--- Learning for extension: %q (key: %s) ---\n", ext, key.String())

		sig, err := cache.LearnAndCache(ctx, key, baseURL)
		if err != nil {
			fmt.Printf("  ERROR: Failed to learn: %v\n", err)
			continue
		}

		fmt.Printf("  SUCCESS: Learned signature with %d stable attributes\n", sig.StableAttributeCount())
		fmt.Printf("  Debug: %s\n", sig.Debug())
	}

	// Print cache stats
	stats := cache.GetStats()
	fmt.Printf("\n=== Cache Stats ===\n")
	fmt.Printf("  Total keys: %d\n", stats.TotalKeys)
	fmt.Printf("  Total signatures: %d\n", stats.TotalSignatures)
	for k, v := range stats.KeyDetails {
		fmt.Printf("  Key '%s': %d signatures\n", k, v)
	}

	fmt.Println("\n=== STEP 2: Testing Compare() with different paths ===")

	testPaths := []string{
		"/nonexistent",          // no extension
		"/nonexistent/",         // directory-style
		"/api/",                 // directory
		"/admin",                // no extension
		"/test.php",             // .php extension
		"/test.html",            // .html extension
		"/testXYZ123random.php", // random php file
		"/some/nested/path/",    // nested directory
		"/CVS/",                 // common dir
	}

	for _, path := range testPaths {
		testURL := *baseURL
		testURL.Path = path

		// Make request
		req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
		if err != nil {
			fmt.Printf("  %s: ERROR creating request: %v\n", path, err)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("  %s: ERROR making request: %v\n", path, err)
			continue
		}

		// Get cache key for this URL
		key := ExtractCacheKey(&testURL)

		// Check if we have signatures for this key
		sigs, hasSigs := cache.Get(key)

		// Create ResponseChain for comparison
		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()

		// Compare
		result, err := comparator.Compare(ctx, req, rc)
		resultStr := "Unknown"
		if err == nil {
			switch result {
			case Unknown:
				resultStr = "Unknown"
			case TruePositive:
				resultStr = "TruePositive (REAL RESOURCE)"
			case FalsePositive:
				resultStr = "FalsePositive (SOFT 404)"
			}
		}

		body := rc.BodyBytes()
		rc.Close()

		fmt.Printf("\n--- Path: %s ---\n", path)
		fmt.Printf("  HTTP Status: %d\n", resp.StatusCode)
		fmt.Printf("  Body length: %d bytes\n", len(body))
		fmt.Printf("  Cache key: %s\n", key.String())
		fmt.Printf("  Has cached signatures: %v (count: %d)\n", hasSigs, len(sigs))
		fmt.Printf("  Compare result: %s\n", resultStr)
		if err != nil {
			fmt.Printf("  Compare error: %v\n", err)
		}

		// If Unknown, explain why
		if result == Unknown && err == nil {
			fmt.Printf("  REASON: No signatures in cache for key '%s'\n", key.String())
			fmt.Printf("  IMPACT: This path will be marked as StatusFound (real resource)\n")
		}

		// Show body snippet if 200
		if resp.StatusCode == 200 && len(body) > 0 {
			snippet := string(body)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			// Clean up whitespace
			snippet = strings.ReplaceAll(snippet, "\n", " ")
			snippet = strings.ReplaceAll(snippet, "\r", "")
			snippet = strings.TrimSpace(snippet)
			fmt.Printf("  Body snippet: %s\n", snippet)
		}
	}

	fmt.Println("\n=== STEP 3: Testing CheckWildcardWithValidation ===")

	// Test the wildcard validation flow
	wildcardTestPath := "/totally_random_xyz_123/"
	testURL := *baseURL
	testURL.Path = wildcardTestPath

	req, _ := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()

		sample, _ := NewSampleFromRC(rc)

		fmt.Printf("\nTesting CheckWildcardWithValidation for: %s\n", wildcardTestPath)
		fmt.Printf("  HTTP Status: %d\n", resp.StatusCode)

		result, err := comparator.CheckWildcardWithValidation(ctx, &testURL, rc, sample)
		if err != nil {
			fmt.Printf("  Validation ERROR: %v\n", err)
		} else {
			switch result {
			case Unknown:
				fmt.Printf("  Result: Unknown\n")
			case TruePositive:
				fmt.Printf("  Result: TruePositive (REAL RESOURCE) - This is likely WRONG for a random path!\n")
			case FalsePositive:
				fmt.Printf("  Result: FalsePositive (WILDCARD DETECTED) - CORRECT!\n")
			}
		}

		rc.Close()

		// Check cache again after validation
		stats = cache.GetStats()
		fmt.Printf("\n  Cache stats after validation:\n")
		fmt.Printf("    Total keys: %d\n", stats.TotalKeys)
		fmt.Printf("    Total signatures: %d\n", stats.TotalSignatures)
	}

	fmt.Println("\n=== SUMMARY ===")
	fmt.Println("If you see 'Unknown' results for paths without cached signatures,")
	fmt.Println("that's the bug - those will be marked as StatusFound (real resources)")
	fmt.Println("and stored in the database even though they're 404s.")
}

// TestSignatureMatchDebug shows why signatures don't match 404s
func TestSignatureMatchDebug(t *testing.T) {
	if testing.Short() {
		t.Skip("network integration test against an external host; skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	baseURL := requireReachableDebugHost(t, debugFingerprintTargetURL)

	client := &http.Client{Timeout: 10 * time.Second}
	learner := NewLearner(client, nil)
	learner.SetDelay(500 * time.Millisecond)
	cache := NewCache(learner)

	fmt.Println("=== Learning Signature ===")
	key := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(ctx, key, baseURL)
	if err != nil {
		t.Fatalf("Failed to learn: %v", err)
	}

	// Print signature stable attributes
	stableAttrs := sig.GetStableAttributes()
	fmt.Printf("\nSignature has %d stable attributes:\n", len(stableAttrs))
	for attr, hash := range stableAttrs {
		fmt.Printf("  %s = %d\n", attr.String(), hash)
	}

	// Now test a 404 response
	fmt.Println("\n=== Testing 404 Response ===")
	testURL := *baseURL
	testURL.Path = "/random_nonexistent_path"

	req, _ := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()
	defer rc.Close()

	body := rc.BodyBytes()
	sample, _ := NewSampleFromRC(rc)

	fmt.Printf("Response Status: %d\n", resp.StatusCode)
	fmt.Printf("Response Body Length: %d\n", len(body))
	fmt.Printf("Response Body: %s\n", strings.TrimSpace(string(body)))

	// Compare sample attributes vs signature
	fmt.Println("\n=== Attribute Comparison ===")
	fmt.Println("Attribute           | Signature Hash | Sample Hash | Match?")
	fmt.Println("--------------------|----------------|-------------|-------")

	for attr, sigHash := range stableAttrs {
		sampleHash := sample.GetHash(attr)
		hasAttr := sample.HasAttribute(attr)
		match := hasAttr && sampleHash == sigHash
		matchStr := "YES"
		if !match {
			matchStr = "NO"
		}
		fmt.Printf("%-19s | %-14d | %-11d | %s\n", attr.String(), sigHash, sampleHash, matchStr)
	}

	// Test match
	matches := sig.Matches(sample)
	partialMatch := sig.PartialMatch(sample)
	criticalMatch := sig.IsCriticalMatch(sample)

	fmt.Printf("\n=== Match Results ===\n")
	fmt.Printf("Full Match: %v\n", matches)
	fmt.Printf("Partial Match: %.2f%%\n", partialMatch*100)
	fmt.Printf("Critical Match: %v\n", criticalMatch)

	if !matches && criticalMatch {
		fmt.Println("\nBUG IDENTIFIED:")
		fmt.Println("Critical attributes (StatusCode, ContentType) match,")
		fmt.Println("but non-critical attributes differ (probably BodyLength or ETag).")
		fmt.Println("Signature.Matches() requires ALL attributes to match,")
		fmt.Println("which is too strict for 404 detection!")
	}
}

// TestCacheKeyMismatch demonstrates the cache key mismatch bug
func TestCacheKeyMismatch(t *testing.T) {
	fmt.Println("=== Cache Key Mismatch Test ===")

	testURLs := []string{
		"http://testphp.vulnweb.com/",
		"http://testphp.vulnweb.com/test",
		"http://testphp.vulnweb.com/test.php",
		"http://testphp.vulnweb.com/test.html",
		"http://testphp.vulnweb.com/api/",
		"http://testphp.vulnweb.com/admin/test",
		"http://testphp.vulnweb.com/admin/test.php",
	}

	for _, urlStr := range testURLs {
		u, _ := url.Parse(urlStr)
		key := ExtractCacheKey(u)

		fmt.Printf("URL: %-50s -> Key: %s\n", urlStr, key.String())
	}

	fmt.Println("\nNOTE: If you learn fingerprints for '.php' extension,")
	fmt.Println("they won't help filter paths without extensions (empty extension key).")
	fmt.Println("Each (host, extension) combination needs its own learned fingerprint.")
}
