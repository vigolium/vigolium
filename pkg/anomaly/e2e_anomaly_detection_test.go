package anomaly

import (
	"testing"
)

// AnomalyMetadata stores test metadata for verification
type AnomalyMetadata struct {
	Type        string // "normal", "500_error", "debug_leak", etc.
	StatusCode  int
	ContentType string
	Frequency   int // How many times this appears in dataset
}

// TestControlledAnomalies tests that rare responses (1-3 occurrences) always rank higher
// than common responses (25 occurrences), demonstrating frequency-based anomaly detection.
func TestControlledAnomalies(t *testing.T) {
	engine := NewDefaultEngine()

	records := make([]*ResponseRecord, 0, 32)

	// ========================================
	// NORMAL PATTERN (25 identical responses)
	// ========================================
	normalBody := `<html><head><title>Dashboard</title></head><body>
		<h1>Welcome to Dashboard</h1>
		<p>Standard content here</p>
		<div id="main">Main section</div>
	</body></html>`
	normalHeaders := map[string][]string{
		"Content-Type":   {"text/html; charset=utf-8"},
		"Server":         {"nginx/1.18.0"},
		"Cache-Control":  {"max-age=3600"},
		"Content-Length": {"200"},
	}

	for i := 0; i < 25; i++ {
		attrs, err := ExtractAttributesFromRaw(200, normalBody, normalHeaders)
		if err != nil {
			t.Fatalf("failed to extract normal attributes: %v", err)
		}

		records = append(records, &ResponseRecord{
			Attributes: *attrs,
			Metadata: AnomalyMetadata{
				Type:        "normal",
				StatusCode:  200,
				ContentType: "text/html; charset=utf-8",
				Frequency:   25,
			},
		})
	}

	// ========================================
	// ANOMALY 1: Unique 500 error (1 occurrence)
	// ========================================
	anomaly1Body := `<html><head><title>500 Internal Server Error</title></head><body>
		<h1>Fatal Error</h1>
		<pre>Stack trace:
at handleRequest (server.js:42)
at processRequest (middleware.js:15)
Database connection failed: ECONNREFUSED</pre>
		<div id="error-details">Critical system failure</div>
	</body></html>`
	anomaly1Headers := map[string][]string{
		"Content-Type": {"text/html"},
		"Server":       {"Apache/2.4.41"},
		"X-Error-ID":   {"ERR-500-DBFAIL"},
	}

	attrs1, _ := ExtractAttributesFromRaw(500, anomaly1Body, anomaly1Headers)
	records = append(records, &ResponseRecord{
		Attributes: *attrs1,
		Metadata: AnomalyMetadata{
			Type:        "500_error",
			StatusCode:  500,
			ContentType: "text/html",
			Frequency:   1,
		},
	})

	// ========================================
	// ANOMALY 2: Unique admin debug page (1 occurrence)
	// ========================================
	anomaly2Body := `<html><head><title>Admin Debug Console</title></head><body>
		<h1>Debug Information - CONFIDENTIAL</h1>
		<pre>DB_PASSWORD=prod_secret_2024
API_KEY=sk_live_abc123xyz789
JWT_SECRET=ultra_secure_key_do_not_share
AWS_ACCESS_KEY=AKIA1234567890EXAMPLE</pre>
		<div id="admin-panel">
			<a href="/admin/users">User Management</a>
			<a href="/admin/logs">System Logs</a>
			<a href="/admin/backdoor">Emergency Access</a>
		</div>
	</body></html>`
	anomaly2Headers := map[string][]string{
		"Content-Type":  {"text/html"},
		"Server":        {"Express/4.17.1"},
		"X-Debug-Mode":  {"enabled"},
		"X-Admin-Token": {"admin_debug_session"},
	}

	attrs2, _ := ExtractAttributesFromRaw(200, anomaly2Body, anomaly2Headers)
	records = append(records, &ResponseRecord{
		Attributes: *attrs2,
		Metadata: AnomalyMetadata{
			Type:        "debug_leak",
			StatusCode:  200,
			ContentType: "text/html",
			Frequency:   1,
		},
	})

	// ========================================
	// ANOMALY 3: Unique GraphQL error (1 occurrence)
	// ========================================
	anomaly3Body := `{"errors":[{"message":"Cannot query field 'secretData' on type 'User'","locations":[{"line":3,"column":5}],"path":["user","secretData"],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED","exception":{"stacktrace":["at validateQuery (validator.js:89)","at executeQuery (executor.js:234)"]}}}],"data":null}`
	anomaly3Headers := map[string][]string{
		"Content-Type":           {"application/json"},
		"X-GraphQL-Error":        {"VALIDATION_FAILED"},
		"X-Request-ID":           {"gql-error-abc123"},
		"Access-Control-Max-Age": {"86400"},
	}

	attrs3, _ := ExtractAttributesFromRaw(400, anomaly3Body, anomaly3Headers)
	records = append(records, &ResponseRecord{
		Attributes: *attrs3,
		Metadata: AnomalyMetadata{
			Type:        "graphql_error",
			StatusCode:  400,
			ContentType: "application/json",
			Frequency:   1,
		},
	})

	// ========================================
	// ANOMALY 4: 401 Unauthorized (1 occurrence)
	// ========================================
	anomaly4Body := `<html><head><title>401 Unauthorized</title></head><body>
		<h1>Authentication Required</h1>
		<p>You must be authenticated to access this resource.</p>
		<div id="auth-error">
			<p>Error code: AUTH_REQUIRED</p>
			<p>Please provide valid credentials</p>
		</div>
		<form action="/login" method="post">
			<input type="text" name="username" placeholder="Username">
			<input type="password" name="password" placeholder="Password">
			<button type="submit">Login</button>
		</form>
	</body></html>`
	anomaly4Headers := map[string][]string{
		"Content-Type":     {"text/html"},
		"WWW-Authenticate": {"Basic realm=\"Restricted Area\""},
		"X-Auth-Error":     {"NO_TOKEN_PROVIDED"},
	}

	attrs4, _ := ExtractAttributesFromRaw(401, anomaly4Body, anomaly4Headers)
	records = append(records, &ResponseRecord{
		Attributes: *attrs4,
		Metadata: AnomalyMetadata{
			Type:        "auth_error",
			StatusCode:  401,
			ContentType: "text/html",
			Frequency:   1,
		},
	})

	// ========================================
	// ANOMALY 5: Rate limit response (3 occurrences)
	// ========================================
	anomaly5Body := `{"error":{"code":"RATE_LIMIT_EXCEEDED","message":"Too many requests from this IP address","details":"You have exceeded the rate limit of 100 requests per minute. Please try again later.","retry_after":60,"current_usage":156,"limit":100},"request_id":"rate-limit-xyz789","timestamp":"2024-01-15T10:30:45Z"}`
	anomaly5Headers := map[string][]string{
		"Content-Type":          {"application/json"},
		"Retry-After":           {"60"},
		"X-RateLimit-Limit":     {"100"},
		"X-RateLimit-Remaining": {"0"},
		"X-RateLimit-Reset":     {"1705318245"},
	}

	attrs5, _ := ExtractAttributesFromRaw(429, anomaly5Body, anomaly5Headers)
	for i := 0; i < 3; i++ {
		records = append(records, &ResponseRecord{
			Attributes: *attrs5,
			Metadata: AnomalyMetadata{
				Type:        "rate_limit",
				StatusCode:  429,
				ContentType: "application/json",
				Frequency:   3,
			},
		})
	}

	// Total: 25 normal + 1 + 1 + 1 + 1 + 3 = 32 responses

	// ========================================
	// RANK AND ANALYZE
	// ========================================
	err := engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 32 {
		t.Fatalf("expected 32 ranked responses, got %d", len(records))
	}

	// ========================================
	// DISPLAY TOP RESULTS
	// ========================================
	t.Log("\n=== TOP 10 ANOMALOUS RESPONSES ===")
	for i := 0; i < 10 && i < len(records); i++ {
		r := records[i]
		meta := r.Metadata.(AnomalyMetadata)

		t.Logf("#%-2d Score: %-8d | Status: %-3d | Type: %-30s | AnomalyType: %s",
			i+1, r.Score, meta.StatusCode, meta.ContentType, meta.Type)
	}

	// ========================================
	// VERIFY TOP 5 ARE ALL ANOMALIES
	// ========================================
	t.Log("\n=== VERIFYING TOP 5 ARE ANOMALIES ===")

	// Track which anomaly types we found
	foundAnomalies := make(map[string]bool)

	for i := 0; i < 5; i++ {
		r := records[i]
		meta := r.Metadata.(AnomalyMetadata)

		foundAnomalies[meta.Type] = true
		t.Logf("#%d: %s (status=%d, score=%d)", i+1, meta.Type, meta.StatusCode, r.Score)

		// Verify it's NOT a normal response
		if meta.Type == "normal" {
			t.Errorf("Position #%d: Found normal response in top 5 (score=%d). Expected only anomalies!", i+1, r.Score)
		}
	}

	// ========================================
	// VERIFY ALL 5 ANOMALY TYPES ARE IN TOP 5
	// ========================================
	expectedAnomalies := []string{"500_error", "debug_leak", "graphql_error", "auth_error", "rate_limit"}
	for _, expected := range expectedAnomalies {
		if !foundAnomalies[expected] {
			t.Errorf("Missing expected anomaly type in top 5: %s", expected)
		}
	}

	t.Logf("\n✓ All 5 anomaly types found in top 5 positions")

	// ========================================
	// VERIFY SCORE RANGES
	// ========================================
	// Anomalies (frequency 1-3) should have MUCH higher scores than normal (frequency 25)
	top5MinScore := records[4].Score // Minimum score in top 5
	firstNormalIdx := -1

	// Find first normal response
	for i, r := range records {
		meta := r.Metadata.(AnomalyMetadata)
		if meta.Type == "normal" {
			firstNormalIdx = i
			break
		}
	}

	if firstNormalIdx == -1 {
		t.Fatal("Could not find normal responses in results")
	}

	firstNormalScore := records[firstNormalIdx].Score

	t.Logf("\n=== SCORE ANALYSIS ===")
	t.Logf("Top 5 minimum score:  %d", top5MinScore)
	t.Logf("First normal score:   %d", firstNormalScore)
	t.Logf("Score ratio:          %.2fx", float64(top5MinScore)/float64(firstNormalScore))

	// Top 5 anomalies should score AT LEAST 2x higher than normal responses
	if top5MinScore <= firstNormalScore*2 {
		t.Errorf("Top 5 anomalies should score much higher than normal responses. Got top5=%d, normal=%d (ratio=%.2fx)",
			top5MinScore, firstNormalScore, float64(top5MinScore)/float64(firstNormalScore))
	}

	// ========================================
	// FREQUENCY VERIFICATION
	// ========================================
	t.Log("\n=== FREQUENCY DISTRIBUTION ===")

	// Count occurrences of each response type in results
	typeCounts := make(map[string]int)

	for _, r := range records {
		meta := r.Metadata.(AnomalyMetadata)
		typeCounts[meta.Type]++
	}

	t.Logf("Normal responses:     %d (frequency=25)", typeCounts["normal"])
	t.Logf("500 error:            %d (frequency=1)", typeCounts["500_error"])
	t.Logf("Debug leak:           %d (frequency=1)", typeCounts["debug_leak"])
	t.Logf("GraphQL error:        %d (frequency=1)", typeCounts["graphql_error"])
	t.Logf("401 Auth error:       %d (frequency=1)", typeCounts["auth_error"])
	t.Logf("Rate limit:           %d (frequency=3)", typeCounts["rate_limit"])

	// Verify counts match what we inserted
	if typeCounts["normal"] != 25 {
		t.Errorf("Expected 25 normal responses, got %d", typeCounts["normal"])
	}
	if typeCounts["500_error"] != 1 {
		t.Errorf("Expected 1 500_error, got %d", typeCounts["500_error"])
	}
	if typeCounts["debug_leak"] != 1 {
		t.Errorf("Expected 1 debug_leak, got %d", typeCounts["debug_leak"])
	}
	if typeCounts["graphql_error"] != 1 {
		t.Errorf("Expected 1 graphql_error, got %d", typeCounts["graphql_error"])
	}
	if typeCounts["auth_error"] != 1 {
		t.Errorf("Expected 1 auth_error, got %d", typeCounts["auth_error"])
	}
	if typeCounts["rate_limit"] != 3 {
		t.Errorf("Expected 3 rate_limit, got %d", typeCounts["rate_limit"])
	}

	t.Log("\n✓ Test passed: Rare responses (1-3 occurrences) ranked higher than common responses (25 occurrences)")
}
