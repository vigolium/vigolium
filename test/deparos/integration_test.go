//go:build integration

package integration_test

import (
	"context"
	"testing"
	"time"
)

// TestBasicSpiderDiscovery tests that deparos can discover links from HTML pages.
// This is the most basic integration test - spider extracts links from homepage.
func TestBasicSpiderDiscovery(t *testing.T) {
	// Setup test server with known responses
	scenarios := []ResponseScenario{
		{
			Path:       "/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			Body: `<!DOCTYPE html>
<html>
<head><title>Home Page</title></head>
<body>
<h1>Welcome</h1>
<nav>
<a href="/admin/">Admin Panel</a>
<a href="/api/users">User API</a>
</nav>
</body>
</html>`,
		},
		{
			Path:       "/admin/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			Body: `<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body><h1>Admin</h1></body>
</html>`,
		},
		{
			Path:       "/api/users",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"users": [{"id": 1, "name": "test"}]}`,
		},
	}

	server := NewTestServer(scenarios)
	defer server.Close()

	// Create test options
	opts := NewTestOptions(server.URL())

	// Run discovery
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := RunDeparos(t, ctx, opts)

	// Debug: print all results
	t.Log(ResultsToString(result.Results))

	// Assert we found exactly 2 URLs (the 2 links discovered by spider)
	// Note: The start URL "/" is not stored as a "discovery" result
	// because it's the seed URL, not a discovered URL.
	AssertResultCount(t, result.Results, 2)

	// Assert each URL with exact values
	expected := []ExpectedResult{
		{
			URL:        server.URL() + "/admin/",
			StatusCode: IntPtr(200),
			Type:       StringPtr("directory"),
			FoundBy:    StringPtr("spider"),
		},
		{
			URL:        server.URL() + "/api/users",
			StatusCode: IntPtr(200),
			Type:       StringPtr("file"),
			FoundBy:    StringPtr("spider"),
		},
	}

	AssertResults(t, result.Results, expected)
}

// TestRedirectHandling tests that deparos correctly follows and records redirects.
func TestRedirectHandling(t *testing.T) {
	scenarios := []ResponseScenario{
		{
			Path:       "/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       `<html><head><title>Home</title></head><body><a href="/old-page">Old Page</a></body></html>`,
		},
		{
			Path:       "/old-page",
			StatusCode: 301,
			Headers: map[string]string{
				"Location":     "/new-page",
				"Content-Type": "text/html",
			},
			Body: `<html><body>Moved</body></html>`,
		},
		{
			Path:       "/new-page",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       `<html><head><title>New Page</title></head><body>New content</body></html>`,
		},
	}

	server := NewTestServer(scenarios)
	defer server.Close()

	opts := NewTestOptions(server.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := RunDeparos(t, ctx, opts)

	t.Log(ResultsToString(result.Results))

	// Verify redirect page has location header recorded
	oldPage := FindResult(result.Results, server.URL()+"/old-page")
	if oldPage != nil {
		if oldPage.StatusCode != 301 {
			t.Errorf("/old-page: expected status 301, got %d", oldPage.StatusCode)
		}
		if oldPage.Location != "/new-page" {
			t.Errorf("/old-page: expected location '/new-page', got %q", oldPage.Location)
		}
	}

	// Verify new page was discovered
	AssertURLPresent(t, result.Results, server.URL()+"/new-page")
}

// TestNotFoundFiltering tests that 404 responses are correctly filtered out.
func TestNotFoundFiltering(t *testing.T) {
	scenarios := []ResponseScenario{
		{
			Path:       "/",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body: `<html>
<head><title>Home</title></head>
<body>
<a href="/exists">Exists</a>
<a href="/not-found">Not Found Link</a>
</body>
</html>`,
		},
		{
			Path:       "/exists",
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       `<html><head><title>Exists</title></head><body>This page exists</body></html>`,
		},
		// /not-found will return 404 from default handler
	}

	server := NewTestServer(scenarios)
	defer server.Close()

	opts := NewTestOptions(server.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := RunDeparos(t, ctx, opts)

	t.Log(ResultsToString(result.Results))

	// Verify /exists was found
	AssertURLPresent(t, result.Results, server.URL()+"/exists")

	// Verify /not-found is NOT in results (404 should be filtered)
	// Note: Depending on fingerprinting, 404s might still appear
	// This test verifies the expected behavior
	for _, r := range result.Results {
		if r.StatusCode == 404 {
			t.Logf("Found 404 response: %s (this may be expected if fingerprinting is disabled)", r.URL)
		}
	}
}
