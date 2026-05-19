//go:build integration

package integration_test

import (
	"context"
	"embed"
	"fmt"
	"strings"
	"testing"
	"time"
)

//go:embed testdata/spider-app/*.html testdata/spider-app/*.txt
//go:embed testdata/spider-app/forms/*.html
var spiderTestData embed.FS

// loadTestHTML loads HTML from embedded test data.
func loadTestHTML(name string) string {
	data, err := spiderTestData.ReadFile("testdata/spider-app/" + name)
	if err != nil {
		panic("failed to load test data: " + name + ": " + err.Error())
	}
	return string(data)
}

// loadTestHTMLWithBaseURL loads HTML and replaces {{BASEURL}} placeholder with actual server URL.
func loadTestHTMLWithBaseURL(name, baseURL string) string {
	content := loadTestHTML(name)
	return strings.ReplaceAll(content, "{{BASEURL}}", baseURL)
}

// TestSpiderComprehensiveExtraction tests all 11 link extractors with a comprehensive web app.
func TestSpiderComprehensiveExtraction(t *testing.T) {
	server := NewTestServer(nil)
	defer server.Close()

	baseURL := server.URL()

	// Add all page scenarios
	addSpiderScenarios(server, baseURL)

	opts := NewTestOptions(baseURL)
	// Increase threads for faster crawling
	opts.Threads = 10
	opts.HTTPTimeout = 5

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	result := RunDeparos(t, ctx, opts)
	t.Log(ResultsToString(result.Results))

	// === Verify HTML Attribute Extraction ===
	t.Run("HTMLAttributes", func(t *testing.T) {
		// Standard links - should be stored in results
		AssertURLPresent(t, result.Results, baseURL+"/html-attr/anchor-link.html")
		AssertURLPresent(t, result.Results, baseURL+"/html-attr/another-page.html")

		// Iframes - should be stored
		AssertURLPresent(t, result.Results, baseURL+"/html-attr/iframe-page.html")

		// Object and embed (swf files) - should be stored
		AssertURLPresent(t, result.Results, baseURL+"/html-attr/flash.swf")
		AssertURLPresent(t, result.Results, baseURL+"/html-attr/object.swf")

		// Form action
		AssertURLPresent(t, result.Results, baseURL+"/html-attr/form-action")

		// Note: Media files (.png, .jpg, .mp4, .js, .css) are extracted and requested
		// but may be filtered by fingerprint analyzer as soft-404 wildcards.
		// This is expected behavior - Deparos focuses on HTML/dynamic content discovery.
		// Verify they were at least discovered (requests made):
		// Note: <audio> tag is NOT in Burp's 32 supported HTML tags, so audio.mp3 won't be extracted.
		mediaUrls := []string{
			"/html-attr/image.png",
			"/html-attr/photo.jpg",
			"/html-attr/external.js",
			"/html-attr/video.mp4",
			"/html-attr/input-image.png",
		}
		for _, path := range mediaUrls {
			if reqs := server.GetRequestsForPath(path); len(reqs) == 0 {
				t.Errorf("URL was not discovered (no request made): %s", path)
			}
		}
	})

	// === Verify JavaScript/Script Content Extraction ===
	t.Run("JavaScript", func(t *testing.T) {
		// String literals
		AssertURLPresent(t, result.Results, baseURL+"/js-content/api/users")
		AssertURLPresent(t, result.Results, baseURL+"/js-content/api/v2/config")
		AssertURLPresent(t, result.Results, baseURL+"/js-content/data/items.json")

		// fetch calls
		AssertURLPresent(t, result.Results, baseURL+"/js-content/fetch-endpoint")

		// Object properties
		AssertURLPresent(t, result.Results, baseURL+"/js-content/api-base")
		AssertURLPresent(t, result.Results, baseURL+"/js-content/settings.json")

		// HTML in JS strings
		AssertURLPresent(t, result.Results, baseURL+"/js-content/from-js-html.html")
	})

	// === Verify Comment Extraction ===
	t.Run("Comments", func(t *testing.T) {
		AssertURLPresent(t, result.Results, baseURL+"/comment/admin-panel.html")
		AssertURLPresent(t, result.Results, baseURL+"/comment/old-api/v1")
		AssertURLPresent(t, result.Results, baseURL+"/comment/debug-server.html")
	})

	// === Verify Meta Refresh Extraction ===
	t.Run("MetaRefresh", func(t *testing.T) {
		AssertURLPresent(t, result.Results, baseURL+"/meta/redirect-target.html")
	})

	// === Verify Event Handler Extraction ===
	t.Run("EventHandlers", func(t *testing.T) {
		AssertURLPresent(t, result.Results, baseURL+"/event/onclick-target.html")
		AssertURLPresent(t, result.Results, baseURL+"/event/onclick-window.html")
		AssertURLPresent(t, result.Results, baseURL+"/event/api/mouseover")
		AssertURLPresent(t, result.Results, baseURL+"/event/js-proto.html")
	})

	// === Verify robots.txt Extraction ===
	t.Run("RobotsTxt", func(t *testing.T) {
		AssertURLPresent(t, result.Results, baseURL+"/robots/allowed-path/")
		AssertURLPresent(t, result.Results, baseURL+"/robots/disallowed-path/")
		AssertURLPresent(t, result.Results, baseURL+"/robots/admin/")
		AssertURLPresent(t, result.Results, baseURL+"/robots/sitemap.xml")
	})

	// === Verify HTTP Header Extraction ===
	t.Run("HTTPHeaders", func(t *testing.T) {
		AssertURLPresent(t, result.Results, baseURL+"/header/location-target")
		AssertURLPresent(t, result.Results, baseURL+"/header/refresh-target")
	})

	// === Verify pages are discovered from index ===
	t.Run("IndexNavigation", func(t *testing.T) {
		AssertURLPresent(t, result.Results, baseURL+"/html_attributes.html")
		AssertURLPresent(t, result.Results, baseURL+"/javascript.html")
		AssertURLPresent(t, result.Results, baseURL+"/comments.html")
		AssertURLPresent(t, result.Results, baseURL+"/event_handlers.html")
		AssertURLPresent(t, result.Results, baseURL+"/meta_refresh.html")
	})
}

// TestFormSubmissions tests form extraction and submission variants.
func TestFormSubmissions(t *testing.T) {
	server := NewTestServer(nil)
	defer server.Close()

	baseURL := server.URL()
	addFormScenarios(server, baseURL)

	opts := NewTestOptions(baseURL)
	// Increase threads for faster crawling
	opts.Threads = 10
	opts.HTTPTimeout = 5

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	_ = RunDeparos(t, ctx, opts)

	t.Log("Request log:")
	t.Log(RequestLogToString(server.GetRequests()))

	// === Verify Simple GET Form ===
	t.Run("SimpleGETForm", func(t *testing.T) {
		requests := server.GetRequestsForPath("/form-result/search")
		if len(requests) == 0 {
			t.Error("No requests to /form-result/search")
			return
		}
		// GET form should have params in query string
		// Look for the form submission (has query params)
		foundFormSubmission := false
		for _, req := range requests {
			if req.Method == "GET" && req.Query.Get("q") == "test-query" && req.Query.Get("source") == "web" {
				foundFormSubmission = true
				break
			}
		}
		if !foundFormSubmission {
			t.Error("No GET form submission with q=test-query&source=web found")
		}
	})

	// === Verify Simple POST Form ===
	t.Run("SimplePOSTForm", func(t *testing.T) {
		requests := server.GetRequestsForPath("/form-result/login")
		if len(requests) == 0 {
			t.Error("No requests to /form-result/login")
			return
		}
		AssertMethodUsed(t, requests, "/form-result/login", "POST")
		// Verify body contains expected params
		for _, req := range requests {
			if req.Method == "POST" {
				if !strings.Contains(req.Body, "username=testuser") {
					t.Errorf("Expected username=testuser in body, got %s", req.Body)
				}
				if !strings.Contains(req.Body, "csrf=token123") {
					t.Errorf("Expected csrf=token123 in body, got %s", req.Body)
				}
				return
			}
		}
	})

	// === Verify Radio Button Variants (3 options = 3 variants) ===
	t.Run("RadioButtonVariants", func(t *testing.T) {
		requests := server.GetRequestsForPath("/form-result/survey")
		// Deparos generates one variant per radio option (cartesian product)
		if len(requests) < 3 {
			t.Errorf("Expected at least 3 requests for radio variants, got %d", len(requests))
		}

		// Verify each radio value was submitted
		foundValues := make(map[string]bool)
		for _, req := range requests {
			if strings.Contains(req.Body, "gender=male") {
				foundValues["male"] = true
			}
			if strings.Contains(req.Body, "gender=female") {
				foundValues["female"] = true
			}
			if strings.Contains(req.Body, "gender=other") {
				foundValues["other"] = true
			}
		}

		if !foundValues["male"] {
			t.Error("Missing radio variant: gender=male")
		}
		if !foundValues["female"] {
			t.Error("Missing radio variant: gender=female")
		}
		if !foundValues["other"] {
			t.Error("Missing radio variant: gender=other")
		}
	})

	// === Verify Checkbox Form (all checkboxes checked, no variants) ===
	t.Run("CheckboxAllChecked", func(t *testing.T) {
		requests := server.GetRequestsForPath("/form-result/preferences")
		// Deparos checks ALL checkboxes (no variants - single submission with all checked)
		if len(requests) == 0 {
			t.Error("Expected at least 1 request for checkbox form")
			return
		}

		// Verify both checkboxes are checked in at least one request
		foundBothChecked := false
		for _, req := range requests {
			if req.Method == "POST" {
				hasNewsletter := strings.Contains(req.Body, "newsletter=1")
				hasMarketing := strings.Contains(req.Body, "marketing=1")
				if hasNewsletter && hasMarketing {
					foundBothChecked = true
					break
				}
			}
		}
		if !foundBothChecked {
			t.Error("Expected both checkboxes (newsletter=1 and marketing=1) to be checked")
		}
	})

	// === Verify Multiple Submit Buttons (3 buttons = 3 variants) ===
	t.Run("MultipleSubmitButtons", func(t *testing.T) {
		requests := server.GetRequestsForPath("/form-result/action")
		// Deparos generates one variant per submit button
		if len(requests) < 3 {
			t.Errorf("Expected at least 3 requests for submit variants, got %d", len(requests))
		}

		foundActions := make(map[string]bool)
		for _, req := range requests {
			if strings.Contains(req.Body, "action=add_to_cart") {
				foundActions["add_to_cart"] = true
			}
			if strings.Contains(req.Body, "action=buy_now") {
				foundActions["buy_now"] = true
			}
			if strings.Contains(req.Body, "action=save_for_later") {
				foundActions["save_for_later"] = true
			}
		}

		if !foundActions["add_to_cart"] {
			t.Error("Missing submit variant: action=add_to_cart")
		}
		if !foundActions["buy_now"] {
			t.Error("Missing submit variant: action=buy_now")
		}
		if !foundActions["save_for_later"] {
			t.Error("Missing submit variant: action=save_for_later")
		}
	})

	// === Verify File Upload (multipart/form-data) ===
	t.Run("FileUploadMultipart", func(t *testing.T) {
		requests := server.GetRequestsForPath("/form-result/upload")
		if len(requests) == 0 {
			t.Error("No requests to /form-result/upload")
			return
		}

		// Check that POST requests have multipart/form-data content-type
		foundMultipart := false
		for _, req := range requests {
			if req.Method == "POST" {
				if strings.Contains(req.ContentType, "multipart/form-data") {
					foundMultipart = true
				} else {
					t.Errorf("Expected multipart/form-data content-type for POST, got %s", req.ContentType)
				}
			}
		}
		if !foundMultipart {
			t.Error("No POST request with multipart/form-data found")
		}
	})

	// === Verify Mixed Form (3 radio x 1 checkbox combo x 2 submit = 6 variants) ===
	t.Run("MixedFormAllVariants", func(t *testing.T) {
		requests := server.GetRequestsForPath("/form-result/order")

		// Expected: 3 shipping options × 1 (all checkboxes checked) × 2 submit buttons = 6
		expectedCount := 6
		if len(requests) < expectedCount {
			t.Errorf("Expected at least %d requests for mixed form variants, got %d", expectedCount, len(requests))
		}

		// Verify all shipping options were used
		shippingOptions := make(map[string]bool)
		submitOptions := make(map[string]bool)

		for _, req := range requests {
			if strings.Contains(req.Body, "shipping=standard") {
				shippingOptions["standard"] = true
			}
			if strings.Contains(req.Body, "shipping=express") {
				shippingOptions["express"] = true
			}
			if strings.Contains(req.Body, "shipping=overnight") {
				shippingOptions["overnight"] = true
			}
			if strings.Contains(req.Body, "submit=place_order") {
				submitOptions["place_order"] = true
			}
			if strings.Contains(req.Body, "submit=save_draft") {
				submitOptions["save_draft"] = true
			}
		}

		if !shippingOptions["standard"] {
			t.Error("Missing shipping variant: standard")
		}
		if !shippingOptions["express"] {
			t.Error("Missing shipping variant: express")
		}
		if !shippingOptions["overnight"] {
			t.Error("Missing shipping variant: overnight")
		}
		if !submitOptions["place_order"] {
			t.Error("Missing submit variant: place_order")
		}
		if !submitOptions["save_draft"] {
			t.Error("Missing submit variant: save_draft")
		}

		// Verify all checkboxes are checked in every submission
		for _, req := range requests {
			if req.Method == "POST" && strings.Contains(req.Body, "shipping=") {
				if !strings.Contains(req.Body, "gift_wrap=1") {
					t.Error("Expected gift_wrap=1 in all form submissions")
				}
				if !strings.Contains(req.Body, "insurance=1") {
					t.Error("Expected insurance=1 in all form submissions")
				}
			}
		}
	})
}

// addSpiderScenarios adds all spider test scenarios to the server.
func addSpiderScenarios(server *TestServer, baseURL string) {
	// Main pages
	server.AddScenario(ResponseScenario{
		Path:       "/",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("index.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/html_attributes.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("html_attributes.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/javascript.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("javascript.html"),
	})

	// Comments need {{BASEURL}} replaced for inline URL scanner
	server.AddScenario(ResponseScenario{
		Path:       "/comments.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTMLWithBaseURL("comments.html", baseURL),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/event_handlers.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("event_handlers.html"),
	})

	// Meta refresh needs {{BASEURL}} replaced for InlineURLScanner
	server.AddScenario(ResponseScenario{
		Path:       "/meta_refresh.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTMLWithBaseURL("meta_refresh.html", baseURL),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/regex_paths.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("regex_paths.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/robots.txt",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/plain"},
		Body:       loadTestHTML("robots.txt"),
	})

	// Page with HTTP headers for header extraction test
	server.AddScenario(ResponseScenario{
		Path:       "/with-headers",
		StatusCode: 302,
		Headers: map[string]string{
			"Content-Type": "text/html",
			"Location":     "/header/location-target",
			"Refresh":      "0; url=/header/refresh-target",
		},
		Body: "<html><body>Redirecting...</body></html>",
	})

	// Add target pages for discovered URLs (return 200 OK)
	addTargetScenarios(server)
}

// addTargetScenarios adds scenarios for all target URLs that should be discovered.
func addTargetScenarios(server *TestServer) {
	// HTML attribute targets
	htmlAttrTargets := []string{
		"/html-attr/app.manifest",
		"/html-attr/canonical.html",
		"/html-attr/preload.js",
		"/html-attr/module.mjs",
		"/html-attr/style.css",
		"/html-attr/external.js",
		"/html-attr/bg.jpg",
		"/html-attr/anchor-link.html",
		"/html-attr/another-page.html",
		"/html-attr/image.png",
		"/html-attr/photo.jpg",
		"/html-attr/photo-2x.jpg",
		"/html-attr/photo-3x.jpg",
		"/html-attr/iframe-page.html",
		"/html-attr/video.mp4",
		"/html-attr/video-alt.webm",
		"/html-attr/audio.mp3",
		"/html-attr/flash.swf",
		"/html-attr/object.swf",
		"/html-attr/param-movie.swf",
		"/html-attr/form-action",
		"/html-attr/input-image.png",
		"/html-attr/blockquote-cite.html",
		"/html-attr/ins-cite.html",
		"/html-attr/del-cite.html",
		"/html-attr/area-link.html",
		"/html-attr/svg-image.svg",
		"/html-attr/table-bg.png",
		"/html-attr/td-bg.png",
	}

	for _, path := range htmlAttrTargets {
		// Each response must have unique AND LARGE content to avoid soft-404 wildcard detection.
		// The fingerprint analyzer compares responses based on multiple attributes including content length.
		// A response that's much larger than 404 (19 bytes) will be clearly distinguishable.
		uniqueBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Resource: %s</title></head>
<body>
<h1>Target Resource Found</h1>
<p>This is the unique content for path: %s</p>
<p>Hash value: %d</p>
<div>Additional padding content to ensure this response is significantly different from 404 responses.
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore.
This text ensures the response body is large enough to be clearly distinguishable from error pages.</div>
</body>
</html>`, path, path, len(path)*17)
		server.AddScenario(ResponseScenario{
			Path:       path,
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       uniqueBody,
		})
	}

	// JavaScript content targets
	jsTargets := []string{
		"/js-content/api/users",
		"/js-content/api/v2/config",
		"/js-content/data/items.json",
		"/js-content/fetch-endpoint",
		"/js-content/api/fetch-double-quotes",
		"/js-content/api-base",
		"/js-content/settings.json",
		"/js-content/endpoint",
		"/js-content/template-url",
		"/js-content/from-js-html.html",
		"/js-content/from-js-img.png",
		"/js-content/dynamic-import.js",
		"/js-content/xhr-endpoint",
		"/js-content/jquery-ajax",
		"/js-content/jquery-get",
		"/js-content/jquery-post",
	}

	for _, path := range jsTargets {
		// Unique JSON response to avoid soft-404 detection
		uniqueBody := fmt.Sprintf(`{"status": "ok", "path": "%s", "hash": %d}`, path, len(path)*31)
		server.AddScenario(ResponseScenario{
			Path:       path,
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       uniqueBody,
		})
	}

	// Comment targets
	commentTargets := []string{
		"/comment/admin-panel.html",
		"/comment/old-api/v1",
		"/comment/debug-server.html",
		"/comment/internal-tool",
		"/comment/dev/endpoint",
		"/comment/staging-server",
		"/comment/todo-endpoint",
	}

	for _, path := range commentTargets {
		uniqueBody := fmt.Sprintf("<html><body>Hidden: %s (id=%d)</body></html>", path, len(path)*37)
		server.AddScenario(ResponseScenario{
			Path:       path,
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       uniqueBody,
		})
	}

	// Event handler targets
	eventTargets := []string{
		"/event/onclick-target.html",
		"/event/onclick-window.html",
		"/event/onclick-document.html",
		"/event/api/mouseover",
		"/event/onload-callback",
		"/event/onerror-fallback",
		"/event/onfocus-suggest",
		"/event/onblur-validate",
		"/event/form-validate",
		"/event/onchange-options",
		"/event/js-proto.html",
		"/event/js-navigate",
		"/event/dblclick-detail",
		"/event/keydown-search",
	}

	for _, path := range eventTargets {
		uniqueBody := fmt.Sprintf("<html><body>Event: %s (id=%d)</body></html>", path, len(path)*41)
		server.AddScenario(ResponseScenario{
			Path:       path,
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       uniqueBody,
		})
	}

	// Meta refresh target - needs unique content and {{BASEURL}} in meta_refresh.html
	server.AddScenario(ResponseScenario{
		Path:       "/meta/redirect-target.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html"},
		Body:       "<html><body>Meta Redirect Target - unique content for fingerprint</body></html>",
	})

	// robots.txt targets
	robotsTargets := []string{
		"/robots/allowed-path/",
		"/robots/disallowed-path/",
		"/robots/admin/",
		"/robots/private/",
		"/robots/googlebot-allowed/",
		"/robots/googlebot-disallowed/",
		"/robots/sitemap.xml",
		"/robots/sitemap-images.xml",
	}

	for _, path := range robotsTargets {
		uniqueBody := fmt.Sprintf("<html><body>Robots: %s (id=%d)</body></html>", path, len(path)*43)
		server.AddScenario(ResponseScenario{
			Path:       path,
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       uniqueBody,
		})
	}

	// HTTP header targets
	headerTargets := []string{
		"/header/location-target",
		"/header/refresh-target",
	}

	for _, path := range headerTargets {
		uniqueBody := fmt.Sprintf("<html><body>Header: %s (id=%d)</body></html>", path, len(path)*47)
		server.AddScenario(ResponseScenario{
			Path:       path,
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       uniqueBody,
		})
	}

	// Index navigation targets
	server.AddScenario(ResponseScenario{
		Path:       "/css/style.css",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/css"},
		Body:       "body { color: black; }",
	})

	server.AddScenario(ResponseScenario{
		Path:       "/js/app.js",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/javascript"},
		Body:       "console.log('app');",
	})

	// Placeholder image for event handlers test
	server.AddScenario(ResponseScenario{
		Path:       "/placeholder.png",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "image/png"},
		Body:       "",
	})
}

// addFormScenarios adds form-related scenarios to the server.
func addFormScenarios(server *TestServer, _ string) {
	// Index page linking to forms
	server.AddScenario(ResponseScenario{
		Path:       "/",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("index.html"),
	})

	// Form pages
	server.AddScenario(ResponseScenario{
		Path:       "/forms/simple_get.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("forms/simple_get.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/forms/simple_post.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("forms/simple_post.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/forms/radio_buttons.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("forms/radio_buttons.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/forms/checkboxes.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("forms/checkboxes.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/forms/multi_submit.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("forms/multi_submit.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/forms/file_upload.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("forms/file_upload.html"),
	})

	server.AddScenario(ResponseScenario{
		Path:       "/forms/mixed_form.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       loadTestHTML("forms/mixed_form.html"),
	})

	// Form action endpoints (accept any method, return 200)
	formEndpoints := []string{
		"/form-result/search",
		"/form-result/login",
		"/form-result/survey",
		"/form-result/preferences",
		"/form-result/action",
		"/form-result/upload",
		"/form-result/order",
	}

	for _, path := range formEndpoints {
		server.AddScenario(ResponseScenario{
			Path:       path,
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"status": "received"}`,
		})
	}

	// Add CSS/JS targets from index
	server.AddScenario(ResponseScenario{
		Path:       "/css/style.css",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/css"},
		Body:       "body { color: black; }",
	})

	server.AddScenario(ResponseScenario{
		Path:       "/js/app.js",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/javascript"},
		Body:       "console.log('app');",
	})

	// Other pages from index
	otherPages := []string{
		"/html_attributes.html",
		"/javascript.html",
		"/comments.html",
		"/event_handlers.html",
		"/meta_refresh.html",
		"/regex_paths.html",
	}

	for _, path := range otherPages {
		server.AddScenario(ResponseScenario{
			Path:       path,
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "text/html"},
			Body:       "<html><body>Placeholder</body></html>",
		})
	}
}
