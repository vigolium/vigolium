package integration_test

import (
	"fmt"
	"strings"
	"testing"
)

// AssertResultCount validates that the actual result count matches expected exactly.
func AssertResultCount(t *testing.T, actual []JSONResult, expected int) {
	t.Helper()

	if len(actual) != expected {
		t.Errorf("result count mismatch: got %d, want %d", len(actual), expected)
		if len(actual) < 10 {
			for i, r := range actual {
				t.Logf("  result[%d]: %s (status=%d, type=%s)", i, r.URL, r.StatusCode, r.Type)
			}
		}
	}
}

// AssertResults validates that all expected results are present with exact field matches.
// Only non-nil fields in ExpectedResult are checked.
func AssertResults(t *testing.T, actual []JSONResult, expected []ExpectedResult) {
	t.Helper()

	// Build lookup map from actual results
	actualMap := make(map[string]JSONResult)
	for _, r := range actual {
		actualMap[r.URL] = r
	}

	for _, exp := range expected {
		act, found := actualMap[exp.URL]
		if !found {
			t.Errorf("expected URL not found: %s", exp.URL)
			continue
		}

		// Check each non-nil expected field
		if exp.StatusCode != nil && *exp.StatusCode != act.StatusCode {
			t.Errorf("%s: status_code mismatch: got %d, want %d", exp.URL, act.StatusCode, *exp.StatusCode)
		}

		if exp.ContentLength != nil && *exp.ContentLength != act.ContentLength {
			t.Errorf("%s: content_length mismatch: got %d, want %d", exp.URL, act.ContentLength, *exp.ContentLength)
		}

		if exp.ContentType != nil && *exp.ContentType != act.ContentType {
			t.Errorf("%s: content_type mismatch: got %q, want %q", exp.URL, act.ContentType, *exp.ContentType)
		}

		if exp.Location != nil && *exp.Location != act.Location {
			t.Errorf("%s: location mismatch: got %q, want %q", exp.URL, act.Location, *exp.Location)
		}

		if exp.Title != nil && *exp.Title != act.Title {
			t.Errorf("%s: title mismatch: got %q, want %q", exp.URL, act.Title, *exp.Title)
		}

		if exp.FoundBy != nil && *exp.FoundBy != act.FoundBy {
			t.Errorf("%s: found_by mismatch: got %q, want %q", exp.URL, act.FoundBy, *exp.FoundBy)
		}

		if exp.Type != nil && *exp.Type != act.Type {
			t.Errorf("%s: type mismatch: got %q, want %q", exp.URL, act.Type, *exp.Type)
		}

		if exp.Depth != nil && *exp.Depth != act.Depth {
			t.Errorf("%s: depth mismatch: got %d, want %d", exp.URL, act.Depth, *exp.Depth)
		}
	}
}

// AssertNotPresent validates that certain URLs are NOT in results.
// Use this to verify 404 detection or filtering.
func AssertNotPresent(t *testing.T, actual []JSONResult, notExpected []string) {
	t.Helper()

	actualMap := make(map[string]bool)
	for _, r := range actual {
		actualMap[r.URL] = true
	}

	for _, url := range notExpected {
		if actualMap[url] {
			t.Errorf("URL should not be present: %s", url)
		}
	}
}

// AssertURLPresent validates that a specific URL exists in results.
func AssertURLPresent(t *testing.T, actual []JSONResult, url string) {
	t.Helper()

	for _, r := range actual {
		if r.URL == url {
			return
		}
	}
	t.Errorf("expected URL not found: %s", url)
}

// AssertExactURL validates a URL exists with exact status code and type.
// Shorthand for common assertion pattern.
func AssertExactURL(t *testing.T, results []JSONResult, url string, statusCode int, typ string) {
	t.Helper()

	for _, r := range results {
		if r.URL == url {
			if r.StatusCode != statusCode {
				t.Errorf("%s: status_code mismatch: got %d, want %d", url, r.StatusCode, statusCode)
			}
			if r.Type != typ {
				t.Errorf("%s: type mismatch: got %q, want %q", url, r.Type, typ)
			}
			return
		}
	}
	t.Errorf("expected URL not found: %s", url)
}

// ResultsToString converts results to a readable string for debugging.
func ResultsToString(results []JSONResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Results (%d):\n", len(results))
	for i, r := range results {
		fmt.Fprintf(&sb, "  [%d] %s (status=%d, type=%s, found_by=%s)\n",
			i, r.URL, r.StatusCode, r.Type, r.FoundBy)
	}
	return sb.String()
}

// FindResult returns the JSONResult for a given URL, or nil if not found.
func FindResult(results []JSONResult, url string) *JSONResult {
	for i := range results {
		if results[i].URL == url {
			return &results[i]
		}
	}
	return nil
}

// AssertRequestCountForPath validates the number of requests made to a path.
func AssertRequestCountForPath(t *testing.T, requests []RequestLog, path string, expectedCount int) {
	t.Helper()

	count := 0
	for _, req := range requests {
		if req.Path == path {
			count++
		}
	}

	if count != expectedCount {
		t.Errorf("request count for %s: got %d, want %d", path, count, expectedCount)
	}
}

// AssertMethodUsed validates that a specific HTTP method was used for a path.
func AssertMethodUsed(t *testing.T, requests []RequestLog, path, method string) {
	t.Helper()

	for _, req := range requests {
		if req.Path == path && req.Method == method {
			return
		}
	}
	t.Errorf("no %s request found for path %s", method, path)
}

// AssertFormSubmitted verifies a form was submitted with expected parameters.
func AssertFormSubmitted(t *testing.T, requests []RequestLog, method, path string, expectedParams map[string]string) {
	t.Helper()

	for _, req := range requests {
		if req.Path == path && req.Method == method {
			if matchesBodyParams(req.Body, expectedParams) {
				return
			}
		}
	}
	t.Errorf("expected form submission not found: %s %s with params %v", method, path, expectedParams)
}

// matchesBodyParams checks if URL-encoded body contains expected parameters.
func matchesBodyParams(body string, expected map[string]string) bool {
	for key, value := range expected {
		param := key + "=" + value
		if !strings.Contains(body, param) {
			return false
		}
	}
	return true
}

// RequestLogToString converts request logs to a readable string for debugging.
func RequestLogToString(requests []RequestLog) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Requests (%d):\n", len(requests))
	for i, r := range requests {
		fmt.Fprintf(&sb, "  [%d] %s %s (content-type=%s, body=%d bytes)\n",
			i, r.Method, r.Path, r.ContentType, len(r.Body))
	}
	return sb.String()
}
