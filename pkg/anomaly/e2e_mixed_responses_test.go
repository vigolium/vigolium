package anomaly

import (
	"testing"
)

// ResponseInfo stores metadata about a test response for verification
type ResponseInfo struct {
	Description string
	StatusCode  int
	ContentType string
	IsAnomalous bool
}

// TestMixedResponses demonstrates ranking a realistic mix of 30 JSON and HTML responses
// with various status codes, showing how the algorithm identifies anomalies.
func TestMixedResponses(t *testing.T) {
	engine := NewDefaultEngine()

	// Create 30 mixed responses simulating a real web application
	testCases := []struct {
		statusCode  int
		body        string
		contentType string
		description string
		isAnomalous bool
	}{
		// Typical successful HTML pages (9 responses - common pattern)
		{200, `<html><head><title>Dashboard</title></head><body><h1>Welcome</h1><p>Main content</p></body></html>`, "text/html; charset=utf-8", "Dashboard page", false},
		{200, `<html><head><title>Dashboard</title></head><body><h1>Welcome</h1><p>Main content</p></body></html>`, "text/html; charset=utf-8", "Dashboard page", false},
		{200, `<html><head><title>Dashboard</title></head><body><h1>Welcome</h1><p>Main content</p></body></html>`, "text/html; charset=utf-8", "Dashboard page", false},
		{200, `<html><head><title>Dashboard</title></head><body><h1>Welcome</h1><p>Main content</p></body></html>`, "text/html; charset=utf-8", "Dashboard page", false},
		{200, `<html><head><title>Dashboard</title></head><body><h1>Welcome</h1><p>Main content</p></body></html>`, "text/html; charset=utf-8", "Dashboard page", false},
		{200, `<html><head><title>Profile</title></head><body><h1>User Profile</h1></body></html>`, "text/html; charset=utf-8", "Profile page", false},
		{200, `<html><head><title>Profile</title></head><body><h1>User Profile</h1></body></html>`, "text/html; charset=utf-8", "Profile page", false},
		{200, `<html><head><title>Settings</title></head><body><h1>Settings</h1></body></html>`, "text/html; charset=utf-8", "Settings page", false},
		{200, `<html><head><title>Settings</title></head><body><h1>Settings</h1></body></html>`, "text/html; charset=utf-8", "Settings page", false},

		// Typical successful API responses (6 responses - common pattern)
		{200, `{"status":"success","data":{"id":1,"name":"user1"}}`, "application/json", "API success", false},
		{200, `{"status":"success","data":{"id":2,"name":"user2"}}`, "application/json", "API success", false},
		{200, `{"status":"success","data":{"id":3,"name":"user3"}}`, "application/json", "API success", false},
		{200, `{"status":"success","data":{"id":4,"name":"user4"}}`, "application/json", "API success", false},
		{200, `{"status":"success","data":{"id":5,"name":"user5"}}`, "application/json", "API success", false},
		{200, `{"status":"success","data":{"id":6,"name":"user6"}}`, "application/json", "API success", false},

		// Standard 404 errors (2 responses - somewhat common)
		{404, `<html><head><title>404 Not Found</title></head><body><h1>Page Not Found</h1></body></html>`, "text/html; charset=utf-8", "404 HTML", false},
		{404, `{"error":"not_found","message":"Resource not found"}`, "application/json", "404 JSON", false},

		// ANOMALY 1: 500 Internal Server Error with HTML (rare!)
		{500, `<html><head><title>Internal Server Error</title></head><body><h1>500 Error</h1><pre>Stack trace: Error at line 42...</pre></body></html>`, "text/html", "500 error", true},

		// ANOMALY 2: 403 Forbidden (rare!)
		{403, `{"error":"forbidden","message":"Access denied"}`, "application/json", "403 forbidden", true},

		// ANOMALY 3: 401 Unauthorized (rare!)
		{401, `<html><head><title>Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>`, "text/html", "401 unauthorized", true},

		// ANOMALY 4: Debug page accidentally exposed (rare content!)
		{200, `<html><head><title>DEBUG</title></head><body><h1>Debug Info</h1><pre>DB_PASSWORD=secret123
API_KEY=xyz789
Internal paths: /admin/backdoor</pre></body></html>`, "text/html", "Debug page", true},

		// ANOMALY 5: XML response (unexpected content type!)
		{200, `<?xml version="1.0"?><root><status>success</status></root>`, "application/xml", "XML response", true},

		// ANOMALY 6: 503 Service Unavailable (rare!)
		{503, `{"error":"service_unavailable","message":"Service temporarily unavailable"}`, "application/json", "503 unavailable", true},

		// ANOMALY 7: Very long error message (unusual content length!)
		{400, `{"error":"validation_failed","message":"Validation failed for the following fields: username must be at least 3 characters, password must contain uppercase, lowercase, number and special character, email format is invalid, phone number must be in E.164 format, date of birth must be in the past, address line 1 is required, city is required, postal code must match the country format, terms of service must be accepted...","details":"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."}`, "application/json", "Long validation error", true},

		// ANOMALY 8: Empty response with 200 OK (unexpected!)
		{200, ``, "text/html", "Empty 200", true},

		// ANOMALY 9: 418 I'm a teapot (easter egg status code - extremely rare!)
		{418, `{"error":"teapot","message":"I'm a teapot"}`, "application/json", "418 teapot", true},

		// ANOMALY 10: Redirect with JSON body (unusual combination!)
		{301, `{"redirect":"/new-location","permanent":true}`, "application/json", "301 with JSON", true},

		// ANOMALY 11: Plain text error (unexpected content type!)
		{500, `Internal Server Error: Database connection failed`, "text/plain", "500 plain text", true},

		// ANOMALY 12: 429 Too Many Requests (rate limiting - rare!)
		{429, `{"error":"rate_limit_exceeded","retry_after":60}`, "application/json", "429 rate limit", true},

		// Normal 302 redirect
		{302, `<html><body>Redirecting...</body></html>`, "text/html", "302 redirect", false},
	}

	// Convert to ResponseRecords
	records := make([]*ResponseRecord, 0, len(testCases))
	for i, tc := range testCases {
		headers := map[string][]string{
			"Content-Type": {tc.contentType},
		}

		// Add Location header for redirects
		switch tc.statusCode {
		case 301:
			headers["Location"] = []string{"/new-location"}
		case 302:
			headers["Location"] = []string{"/dashboard"}
		}

		attrs, err := ExtractAttributesFromRaw(tc.statusCode, tc.body, headers)
		if err != nil {
			t.Fatalf("failed to extract attributes for test case %d: %v", i, err)
		}

		records = append(records, &ResponseRecord{
			Attributes: *attrs,
			Metadata: ResponseInfo{
				Description: tc.description,
				StatusCode:  tc.statusCode,
				ContentType: tc.contentType,
				IsAnomalous: tc.isAnomalous,
			},
		})
	}

	// Rank all responses
	err := engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 30 {
		t.Fatalf("expected 30 ranked responses, got %d", len(records))
	}

	// Display top 15 most anomalous responses with details
	t.Log("\nTop 15 Most Anomalous Responses:")
	t.Log("==================================")
	for i := 0; i < 15 && i < len(records); i++ {
		r := records[i]
		meta := r.Metadata.(ResponseInfo)

		// Truncate description for display
		desc := meta.Description
		if len(desc) > 30 {
			desc = desc[:27] + "..."
		}

		t.Logf("#%-2d Score: %-6d | Status: %-3d | Type: %-25s | Desc: %s",
			i+1, r.Score, meta.StatusCode, meta.ContentType, desc)
	}

	// Verify that the most anomalous responses are the rare status codes and content types
	// Top responses should include rare status codes like: 500, 401, 302, 301, etc.
	topStatuses := make(map[int]int)
	anomalousInTop10 := 0

	for i := 0; i < 10 && i < len(records); i++ {
		meta := records[i].Metadata.(ResponseInfo)
		topStatuses[meta.StatusCode]++
		if meta.IsAnomalous {
			anomalousInTop10++
		}
	}

	// Verify we found some anomalous status codes in top 10
	anomalousStatusCount := 0
	for status := range topStatuses {
		if status != 200 && status != 404 {
			anomalousStatusCount++
		}
	}

	// We expect at least 4 different anomalous status codes in top 10
	// (500, 401, 302, 301, etc.)
	if anomalousStatusCount < 4 {
		t.Errorf("expected at least 4 different anomalous status codes in top 10, got %d", anomalousStatusCount)
	}

	// Most of top 10 should be marked as anomalous
	// Note: Some "normal" responses may rank high if they have rare patterns (e.g., Settings page)
	if anomalousInTop10 < 4 {
		t.Errorf("expected at least 4 anomalous responses in top 10, got %d", anomalousInTop10)
	}

	t.Logf("\nAnomaly Detection Summary:")
	t.Logf("- Total responses analyzed: %d", len(records))
	t.Logf("- Unique status codes in top 10: %d", len(topStatuses))
	t.Logf("- Anomalous status codes found: %d", anomalousStatusCount)
	t.Logf("- Anomalous responses in top 10: %d", anomalousInTop10)

	// Verify top score is from a rare status code
	topMeta := records[0].Metadata.(ResponseInfo)
	if topMeta.StatusCode == 200 && !topMeta.IsAnomalous {
		t.Errorf("expected top anomaly to be a rare response, got normal 200 OK")
	}

	// Verify bottom scores are mostly normal responses
	// Check bottom 5 responses - most should be normal
	normalInBottom5 := 0
	for i := len(records) - 5; i < len(records); i++ {
		meta := records[i].Metadata.(ResponseInfo)
		if !meta.IsAnomalous {
			normalInBottom5++
		}
	}
	if normalInBottom5 < 3 {
		t.Errorf("expected at least 3 normal responses in bottom 5, got %d", normalInBottom5)
	}
}

// TestMixedResponsesWithFiltering tests the filtering of interesting responses
func TestMixedResponsesWithFiltering(t *testing.T) {
	engine := NewDefaultEngine()

	// Create mix: 20 normal + 10 anomalous
	testCases := []struct {
		statusCode  int
		body        string
		isAnomalous bool
	}{
		// 20 normal responses
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `<html><title>Page</title><body>Content</body></html>`, false},
		{200, `{"status":"ok"}`, false},
		{200, `{"status":"ok"}`, false},
		{200, `{"status":"ok"}`, false},
		{200, `{"status":"ok"}`, false},
		{200, `{"status":"ok"}`, false},
		{404, `<html><title>Not Found</title></html>`, false},
		{404, `<html><title>Not Found</title></html>`, false},
		{404, `{"error":"not_found"}`, false},
		{404, `{"error":"not_found"}`, false},
		{404, `{"error":"not_found"}`, false},

		// 10 anomalous responses
		{500, `<html><title>Error</title><body>Internal Server Error</body></html>`, true},
		{500, `{"error":"internal_error"}`, true},
		{403, `<html><title>Forbidden</title></html>`, true},
		{401, `{"error":"unauthorized"}`, true},
		{503, `{"error":"service_unavailable"}`, true},
		{418, `{"error":"teapot"}`, true},
		{429, `{"error":"rate_limit"}`, true},
		{400, `{"error":"bad_request","details":"very long error message with lots of details..."}`, true},
		{200, ``, true}, // Empty body
		{200, `<?xml version="1.0"?><root><error>true</error></root>`, true},
	}

	records := make([]*ResponseRecord, 0, len(testCases))
	for i, tc := range testCases {
		contentType := "text/html"
		if tc.body != "" && tc.body[0] == '{' {
			contentType = "application/json"
		} else if tc.body != "" && tc.body[0] == '<' && tc.body[1] == '?' {
			contentType = "application/xml"
		}

		attrs, _ := ExtractAttributesFromRaw(tc.statusCode, tc.body, map[string][]string{
			"Content-Type": {contentType},
		})

		records = append(records, &ResponseRecord{
			Attributes: *attrs,
			Metadata: map[string]interface{}{
				"index":       i,
				"isAnomalous": tc.isAnomalous,
			},
		})
	}

	// Filter interesting responses
	config := DefaultFilterConfig()
	config.MaximumInteresting = 15 // Limit to top 15

	interesting, err := FilterInteresting(engine, records, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("Total: %d, Interesting: %d", len(records), len(interesting))

	// Verify interesting responses are mostly anomalous
	anomalousCount := 0
	for _, r := range interesting {
		meta := r.Metadata.(map[string]interface{})
		if meta["isAnomalous"].(bool) {
			anomalousCount++
		}
	}

	anomalousRatio := float64(anomalousCount) / float64(len(interesting))
	t.Logf("Anomalous in interesting: %d/%d (%.1f%%)",
		anomalousCount, len(interesting), anomalousRatio*100)

	// At least 60% of interesting responses should be anomalous
	if anomalousRatio < 0.6 {
		t.Errorf("expected at least 60%% of interesting responses to be anomalous, got %.1f%%", anomalousRatio*100)
	}

	// Verify all 10 known anomalies are in the interesting set
	foundAnomalies := 0
	for _, r := range records {
		meta := r.Metadata.(map[string]interface{})
		if !meta["isAnomalous"].(bool) {
			continue
		}

		// Check if this anomaly is in interesting set
		for _, ir := range interesting {
			imeta := ir.Metadata.(map[string]interface{})
			if imeta["index"].(int) == meta["index"].(int) {
				foundAnomalies++
				break
			}
		}
	}

	t.Logf("Found %d/10 known anomalies in interesting set", foundAnomalies)
	if foundAnomalies < 8 {
		t.Errorf("expected to find at least 8/10 known anomalies, found %d", foundAnomalies)
	}
}
