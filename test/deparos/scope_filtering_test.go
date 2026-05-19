//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// AssertAllURLsMatchHost verifies ALL result URLs belong to the expected host.
// This is critical for scope filtering tests - we must ensure NO external URLs leaked through.
func AssertAllURLsMatchHost(t *testing.T, results []JSONResult, expectedHost string) {
	t.Helper()

	for _, r := range results {
		parsedURL, err := url.Parse(r.URL)
		if err != nil {
			t.Errorf("Failed to parse URL %s: %v", r.URL, err)
			continue
		}

		if parsedURL.Host != expectedHost {
			t.Errorf("SCOPE VIOLATION: URL %s has host %q, expected %q (found_by=%s)",
				r.URL, parsedURL.Host, expectedHost, r.FoundBy)
		}
	}
}

// AssertNoExternalURLs verifies NO result URLs contain external domains.
// Pass a list of external domain substrings to check against.
func AssertNoExternalURLs(t *testing.T, results []JSONResult, externalDomains []string) {
	t.Helper()

	for _, r := range results {
		for _, extDomain := range externalDomains {
			if strings.Contains(r.URL, extDomain) {
				t.Errorf("SCOPE VIOLATION: External domain %q found in results: %s (found_by=%s)",
					extDomain, r.URL, r.FoundBy)
			}
		}
	}
}

// TestScopeFiltering_Subdomain_ExternalLinksNotDiscovered verifies that when
// ScopeMode="subdomain", spider-extracted links to external domains are NOT
// added to results (no tasks created for them).
func TestScopeFiltering_Subdomain_ExternalLinksNotDiscovered(t *testing.T) {
	scenarios := []ResponseScenario{
		{
			Path:       "/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			Body: `<!DOCTYPE html>
<html>
<head><title>Home</title></head>
<body>
<a href="/internal-page">Internal Link</a>
<a href="https://external.com/admin/">External Link</a>
<a href="https://cdn.example.com/tracking">CDN Link</a>
<script src="https://analytics.external.com/script.js"></script>
</body>
</html>`,
		},
		{
			Path:       "/internal-page",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body: `<!DOCTYPE html>
<html>
<head><title>Internal Page</title></head>
<body>
<h1>Internal Page - unique content for fingerprint detection</h1>
<p>This is internal content that should be discovered.</p>
<p>Hash: 12345678</p>
</body>
</html>`,
		},
	}

	server := NewTestServer(scenarios)
	defer server.Close()

	// Extract host from server URL for strict verification
	serverURL, _ := url.Parse(server.URL())
	expectedHost := serverURL.Host

	opts := NewTestOptions(server.URL())
	opts.ScopeMode = "subdomain" // Only same domain (eTLD+1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := RunDeparos(t, ctx, opts)
	t.Log(ResultsToString(result.Results))

	// CRITICAL: Verify ALL URLs in results belong to target host
	// This catches any scope filtering failures
	AssertAllURLsMatchHost(t, result.Results, expectedHost)

	// Also verify no external domains leaked through
	AssertNoExternalURLs(t, result.Results, []string{
		"external.com",
		"cdn.example.com",
		"analytics.external.com",
	})

	// Verify internal page WAS discovered (same localhost domain)
	AssertURLPresent(t, result.Results, server.URL()+"/internal-page")

	// Verify external URLs were NOT in results (scope filtering blocks task creation)
	AssertNotPresent(t, result.Results, []string{
		"https://external.com/admin/",
		"https://cdn.example.com/tracking",
		"https://analytics.external.com/script.js",
	})
}

// TestScopeFiltering_Subdomain_ObservedPathsStillExtracted verifies that while
// external URLs are not crawled, their paths/names ARE still extracted
// for observed wordlists (this is expected and desired behavior).
func TestScopeFiltering_Subdomain_ObservedPathsStillExtracted(t *testing.T) {
	// This test verifies that:
	// 1. External URLs do NOT appear in results (no tasks created)
	// 2. BUT the paths/names from external URLs ARE extracted for wordlists
	//
	// Note: This is the desired behavior - we WANT to collect paths from
	// external sources for wordlist enrichment, just not crawl them.

	scenarios := []ResponseScenario{
		{
			Path:       "/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			Body: `<!DOCTYPE html>
<html>
<head><title>Home</title></head>
<body>
<a href="/internal">Internal</a>
<a href="https://external.com/admin/config.json">External Admin</a>
</body>
</html>`,
		},
		{
			Path:       "/internal",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       fmt.Sprintf(`<html><body>Internal unique content %d</body></html>`, time.Now().UnixNano()),
		},
		// If observed-paths is working, /admin/ might be probed on target domain
		{
			Path:       "/admin/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       fmt.Sprintf(`<html><body>Admin page unique %d</body></html>`, time.Now().UnixNano()),
		},
	}

	server := NewTestServer(scenarios)
	defer server.Close()

	// Extract host from server URL for strict verification
	serverURL, _ := url.Parse(server.URL())
	expectedHost := serverURL.Host

	opts := NewTestOptions(server.URL())
	opts.ScopeMode = "subdomain"
	// Enable observed paths to test path extraction from external links
	opts.ObservedPaths = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := RunDeparos(t, ctx, opts)
	t.Log(ResultsToString(result.Results))

	// CRITICAL: Verify ALL URLs in results belong to target host
	AssertAllURLsMatchHost(t, result.Results, expectedHost)

	// Also verify no external domains leaked through
	AssertNoExternalURLs(t, result.Results, []string{
		"external.com",
	})

	// External URL should NOT be in results
	AssertNotPresent(t, result.Results, []string{
		"https://external.com/admin/config.json",
	})

	// Internal pages should be discovered
	AssertURLPresent(t, result.Results, server.URL()+"/internal")
}

// TestScopeFiltering_Any_AllDomainsAllowed verifies that when ScopeMode="any",
// all spider-extracted links are discovered regardless of domain.
func TestScopeFiltering_Any_AllDomainsAllowed(t *testing.T) {
	scenarios := []ResponseScenario{
		{
			Path:       "/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			Body: `<!DOCTYPE html>
<html>
<head><title>Home</title></head>
<body>
<a href="/internal-page">Internal Link</a>
</body>
</html>`,
		},
		{
			Path:       "/internal-page",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       fmt.Sprintf(`<html><body>Internal Page unique content %d</body></html>`, time.Now().UnixNano()),
		},
	}

	server := NewTestServer(scenarios)
	defer server.Close()

	opts := NewTestOptions(server.URL())
	opts.ScopeMode = "any" // Allow all domains

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := RunDeparos(t, ctx, opts)
	t.Log(ResultsToString(result.Results))

	// With ScopeMode="any", internal URLs should be found
	AssertURLPresent(t, result.Results, server.URL()+"/internal-page")

	// Log all URLs for inspection
	t.Logf("Total results with ScopeMode=any: %d", len(result.Results))
	for i, r := range result.Results {
		t.Logf("  [%d] %s (found_by=%s)", i, r.URL, r.FoundBy)
	}
}

// TestScopeFiltering_Exact_OnlySameHost verifies that when
// ScopeMode="exact", only exact host matches are allowed.
func TestScopeFiltering_Exact_OnlySameHost(t *testing.T) {
	scenarios := []ResponseScenario{
		{
			Path:       "/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body: `<html><body>
<a href="/same-host">Same Host</a>
<a href="https://other-subdomain.example.com/page">Different Subdomain</a>
</body></html>`,
		},
		{
			Path:       "/same-host",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       fmt.Sprintf(`<html><body>Same Host Page unique %d</body></html>`, time.Now().UnixNano()),
		},
	}

	server := NewTestServer(scenarios)
	defer server.Close()

	// Extract host from server URL for strict verification
	serverURL, _ := url.Parse(server.URL())
	expectedHost := serverURL.Host

	opts := NewTestOptions(server.URL())
	opts.ScopeMode = "exact" // Exact host match only

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := RunDeparos(t, ctx, opts)
	t.Log(ResultsToString(result.Results))

	// CRITICAL: Verify ALL URLs in results belong to target host
	AssertAllURLsMatchHost(t, result.Results, expectedHost)

	// Also verify no external subdomains leaked through
	AssertNoExternalURLs(t, result.Results, []string{
		"other-subdomain.example.com",
	})

	// Same host should be found
	AssertURLPresent(t, result.Results, server.URL()+"/same-host")

	// Different subdomain should NOT be found
	AssertNotPresent(t, result.Results, []string{
		"https://other-subdomain.example.com/page",
	})
}
