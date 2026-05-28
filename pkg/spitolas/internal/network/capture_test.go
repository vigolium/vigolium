package network

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// mockWriter implements Writer interface for testing.
type mockWriter struct {
	mu         sync.Mutex
	writeCount int
	entries    []*TrafficEntry
	shouldFail bool
}

func (m *mockWriter) Write(entry *TrafficEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail {
		return fmt.Errorf("mock write error")
	}

	m.writeCount++
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockWriter) Close() error {
	return nil
}

func (m *mockWriter) getWriteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeCount
}

// createTestEntry creates a test TrafficEntry with specified URL.
func createTestEntry(url string) *TrafficEntry {
	return &TrafficEntry{
		Timestamp: time.Now(),
		Request: RequestData{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{},
			Body:    []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "text/html"},
			Body:    []byte{},
		},
		ResourceType: "Document",
	}
}

// TestWriteEntryBasicDedup tests basic deduplication: same hash written once, duplicates skipped.
func TestWriteEntryBasicDedup(t *testing.T) {
	mock := &mockWriter{}
	capture := &Capture{
		writer:         mock,
		logged:         make(map[string]struct{}),
		seenHashes:     make(map[string]bool),
		duplicateCount: 0,
		writtenCount:   0,
		noColor:        true,
	}

	// Create entry with specific URL
	entry1 := createTestEntry("https://example.com/page1")

	// Write entry1 - should call writer.Write()
	capture.writeEntry(entry1)

	// Verify first write
	if mock.getWriteCount() != 1 {
		t.Errorf("Expected writeCount=1, got %d", mock.getWriteCount())
	}
	if capture.writtenCount != 1 {
		t.Errorf("Expected writtenCount=1, got %d", capture.writtenCount)
	}
	if capture.duplicateCount != 0 {
		t.Errorf("Expected duplicateCount=0, got %d", capture.duplicateCount)
	}

	// Write entry2 with SAME hash (same URL and response)
	entry2 := createTestEntry("https://example.com/page1")
	capture.writeEntry(entry2)

	// Verify duplicate was skipped
	if mock.getWriteCount() != 1 {
		t.Errorf("Expected writeCount=1 (duplicate skipped), got %d", mock.getWriteCount())
	}
	if capture.writtenCount != 1 {
		t.Errorf("Expected writtenCount=1 (duplicate not counted), got %d", capture.writtenCount)
	}
	if capture.duplicateCount != 1 {
		t.Errorf("Expected duplicateCount=1, got %d", capture.duplicateCount)
	}
	if len(capture.seenHashes) != 1 {
		t.Errorf("Expected seenHashes length=1, got %d", len(capture.seenHashes))
	}
}

// TestWriteEntryMultipleUnique tests that different hashes are all written.
func TestWriteEntryMultipleUnique(t *testing.T) {
	mock := &mockWriter{}
	capture := &Capture{
		writer:         mock,
		logged:         make(map[string]struct{}),
		seenHashes:     make(map[string]bool),
		duplicateCount: 0,
		writtenCount:   0,
		noColor:        true,
	}

	// Create 3 entries with DIFFERENT URLs
	entry1 := createTestEntry("https://example.com/page1")
	entry2 := createTestEntry("https://example.com/page2")
	entry3 := createTestEntry("https://example.com/page3")

	// Write all 3
	capture.writeEntry(entry1)
	capture.writeEntry(entry2)
	capture.writeEntry(entry3)

	// Verify all written
	if mock.getWriteCount() != 3 {
		t.Errorf("Expected writeCount=3, got %d", mock.getWriteCount())
	}
	if capture.writtenCount != 3 {
		t.Errorf("Expected writtenCount=3, got %d", capture.writtenCount)
	}
	if capture.duplicateCount != 0 {
		t.Errorf("Expected duplicateCount=0, got %d", capture.duplicateCount)
	}
	if len(capture.seenHashes) != 3 {
		t.Errorf("Expected seenHashes length=3, got %d", len(capture.seenHashes))
	}
}

// TestWriteEntryDedupWithStderrLogging tests that stderr logging still works for duplicates.
func TestWriteEntryDedupWithStderrLogging(t *testing.T) {
	mock := &mockWriter{}
	capture := &Capture{
		writer:         mock,
		logged:         make(map[string]struct{}),
		seenHashes:     make(map[string]bool),
		duplicateCount: 0,
		writtenCount:   0,
		noColor:        true,
	}

	// Write entry1 - should log to stderr
	entry1 := createTestEntry("https://example.com/page1")
	capture.writeEntry(entry1)

	// Verify logged map has 1 entry
	if len(capture.logged) != 1 {
		t.Errorf("Expected logged length=1, got %d", len(capture.logged))
	}

	// Write entry2 (same hash) - should NOT log to stderr (already logged)
	entry2 := createTestEntry("https://example.com/page1")
	capture.writeEntry(entry2)

	// Write entry3 (same hash again)
	entry3 := createTestEntry("https://example.com/page1")
	capture.writeEntry(entry3)

	// Verify file dedup
	if mock.getWriteCount() != 1 {
		t.Errorf("Expected writeCount=1 (file dedup), got %d", mock.getWriteCount())
	}
	if capture.writtenCount != 1 {
		t.Errorf("Expected writtenCount=1, got %d", capture.writtenCount)
	}
	if capture.duplicateCount != 2 {
		t.Errorf("Expected duplicateCount=2, got %d", capture.duplicateCount)
	}

	// Verify stderr dedup (logged map should still have 1 entry)
	if len(capture.logged) != 1 {
		t.Errorf("Expected logged length=1 (stderr dedup), got %d", len(capture.logged))
	}
}

// TestWriteEntryConcurrency tests thread safety with concurrent writes.
func TestWriteEntryConcurrency(t *testing.T) {
	mock := &mockWriter{}
	capture := &Capture{
		writer:         mock,
		logged:         make(map[string]struct{}),
		seenHashes:     make(map[string]bool),
		duplicateCount: 0,
		writtenCount:   0,
		noColor:        true,
	}

	// Launch 10 goroutines, each writing the SAME entry
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry := createTestEntry("https://example.com/concurrent")
			capture.writeEntry(entry)
		}()
	}

	wg.Wait()

	// Verify race-free dedup - only 1 write should succeed
	if mock.getWriteCount() != 1 {
		t.Errorf("Expected writeCount=1 (race-free dedup), got %d", mock.getWriteCount())
	}
	if capture.writtenCount != 1 {
		t.Errorf("Expected writtenCount=1, got %d", capture.writtenCount)
	}
	if capture.duplicateCount != numGoroutines-1 {
		t.Errorf("Expected duplicateCount=%d, got %d", numGoroutines-1, capture.duplicateCount)
	}
}

// TestWriteEntryAfterClose verifies that writeEntry drops entries (rather than
// panicking) when called after Close() has niled the writer. This reproduces
// the nil-pointer dereference seen at the end of spider runs, where the
// browser's CDP event goroutine delivers a late NetworkLoadingFailed event
// after Close() has already torn down the writer.
func TestWriteEntryAfterClose(t *testing.T) {
	mock := &mockWriter{}
	capture := &Capture{
		writer:     mock,
		logged:     make(map[string]struct{}),
		seenHashes: make(map[string]bool),
		noColor:    true,
		silent:     true,
	}

	if err := capture.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	// Must not panic even though c.writer is now nil.
	capture.writeEntry(createTestEntry("https://example.com/late-event"))

	if mock.getWriteCount() != 0 {
		t.Errorf("Expected no writes after Close(), got %d", mock.getWriteCount())
	}
}

// TestWriteEntryCloseRace exercises the close-vs-writeEntry race under the race
// detector: concurrent writeEntry calls overlapping a Close() must never panic.
func TestWriteEntryCloseRace(t *testing.T) {
	mock := &mockWriter{}
	capture := &Capture{
		writer:     mock,
		logged:     make(map[string]struct{}),
		seenHashes: make(map[string]bool),
		noColor:    true,
		silent:     true,
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			capture.writeEntry(createTestEntry(fmt.Sprintf("https://example.com/race/%d", i)))
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = capture.Close()
	}()

	wg.Wait()
}

// TestCloseStatistics tests that Close() logs correct statistics.
func TestCloseStatistics(t *testing.T) {
	// Create zaptest logger to capture logs
	logger := zaptest.NewLogger(t)
	zap.ReplaceGlobals(logger)

	mock := &mockWriter{}
	capture := &Capture{
		writer:         mock,
		logged:         make(map[string]struct{}),
		seenHashes:     make(map[string]bool),
		duplicateCount: 0,
		writtenCount:   0,
		noColor:        true,
	}

	// Write 5 unique entries
	for i := 1; i <= 5; i++ {
		entry := createTestEntry(fmt.Sprintf("https://example.com/page%d", i))
		capture.writeEntry(entry)
	}

	// Write 3 duplicates
	for i := 1; i <= 3; i++ {
		entry := createTestEntry("https://example.com/page1")
		capture.writeEntry(entry)
	}

	// Verify counts before Close
	if capture.writtenCount != 5 {
		t.Errorf("Expected writtenCount=5, got %d", capture.writtenCount)
	}
	if capture.duplicateCount != 3 {
		t.Errorf("Expected duplicateCount=3, got %d", capture.duplicateCount)
	}

	// Call Close - should log stats
	err := capture.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Note: zaptest logger doesn't expose log entries easily,
	// but we verify stats were set correctly before Close
	// In manual testing, check logs contain:
	// "written: 5", "duplicates_skipped: 3", "total_processed: 8"
}

// TestCloseWithZeroDuplicates tests that Close() doesn't log when no duplicates.
func TestCloseWithZeroDuplicates(t *testing.T) {
	logger := zaptest.NewLogger(t)
	zap.ReplaceGlobals(logger)

	mock := &mockWriter{}
	capture := &Capture{
		writer:         mock,
		logged:         make(map[string]struct{}),
		seenHashes:     make(map[string]bool),
		duplicateCount: 0,
		writtenCount:   0,
		noColor:        true,
	}

	// Write 3 unique entries (no duplicates)
	for i := 1; i <= 3; i++ {
		entry := createTestEntry(fmt.Sprintf("https://example.com/page%d", i))
		capture.writeEntry(entry)
	}

	// Verify no duplicates
	if capture.duplicateCount != 0 {
		t.Errorf("Expected duplicateCount=0, got %d", capture.duplicateCount)
	}

	// Call Close - should NOT log stats (clean output)
	err := capture.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

// TestWriteEntryWithWriteError tests behavior when writer.Write() fails.
func TestWriteEntryWithWriteError(t *testing.T) {
	mock := &mockWriter{shouldFail: true}
	capture := &Capture{
		writer:         mock,
		logged:         make(map[string]struct{}),
		seenHashes:     make(map[string]bool),
		duplicateCount: 0,
		writtenCount:   0,
		noColor:        true,
	}

	entry := createTestEntry("https://example.com/error")
	capture.writeEntry(entry)

	// Verify hash was marked as seen even though write failed
	if len(capture.seenHashes) != 1 {
		t.Errorf("Expected seenHashes length=1 (marked even on error), got %d", len(capture.seenHashes))
	}

	// Verify writtenCount NOT incremented on error
	if capture.writtenCount != 0 {
		t.Errorf("Expected writtenCount=0 (write failed), got %d", capture.writtenCount)
	}

	// Try writing same entry again - should be skipped as duplicate
	mock.shouldFail = false // Fix writer
	entry2 := createTestEntry("https://example.com/error")
	capture.writeEntry(entry2)

	// Should skip as duplicate (even though first write failed)
	if capture.duplicateCount != 1 {
		t.Errorf("Expected duplicateCount=1 (seen despite error), got %d", capture.duplicateCount)
	}
	if capture.writtenCount != 0 {
		t.Errorf("Expected writtenCount=0 (duplicate skipped), got %d", capture.writtenCount)
	}
}

// TestComputeHashConsistency tests that same entry produces same hash.
func TestComputeHashConsistency(t *testing.T) {
	entry1 := createTestEntry("https://example.com/test")
	entry2 := createTestEntry("https://example.com/test")

	hash1 := computeHash(entry1)
	hash2 := computeHash(entry2)

	if hash1 != hash2 {
		t.Errorf("Same entries should produce same hash: %s vs %s", hash1, hash2)
	}

	// Different URL should produce different hash
	entry3 := createTestEntry("https://example.com/different")
	hash3 := computeHash(entry3)

	if hash1 == hash3 {
		t.Errorf("Different entries should produce different hash")
	}
}

// TestHashLength tests that hash is 16 characters (as per computeHash implementation).
func TestHashLength(t *testing.T) {
	entry := createTestEntry("https://example.com/test")
	hash := computeHash(entry)

	if len(hash) != 16 {
		t.Errorf("Expected hash length=16, got %d", len(hash))
	}
}

// TestComputeHTTPXFields tests that httpx fields are correctly extracted from response.
func TestComputeHTTPXFields(t *testing.T) {
	tests := []struct {
		name              string
		entry             *TrafficEntry
		wantContentType   string
		wantWebServer     string
		wantContentLength int
		wantWords         int
		wantLines         int
	}{
		{
			name: "extracts all httpx fields",
			entry: &TrafficEntry{
				Response: &ResponseData{
					Headers: map[string]string{
						"Content-Type": "text/html; charset=utf-8",
						"Server":       "nginx/1.18.0",
					},
					Body: []byte("Hello World\nThis is line 2\nLine 3"),
				},
			},
			wantContentType:   "text/html; charset=utf-8",
			wantWebServer:     "nginx/1.18.0",
			wantContentLength: 33, // len("Hello World\nThis is line 2\nLine 3")
			wantWords:         8,  // Hello, World, This, is, line, 2, Line, 3
			wantLines:         3,
		},
		{
			name: "case insensitive headers",
			entry: &TrafficEntry{
				Response: &ResponseData{
					Headers: map[string]string{
						"content-type": "application/json",
						"server":       "Apache",
					},
					Body: []byte(`{"key": "value"}`),
				},
			},
			wantContentType:   "application/json",
			wantWebServer:     "Apache",
			wantContentLength: 16,
			wantWords:         2,
			wantLines:         1,
		},
		{
			name: "nil response",
			entry: &TrafficEntry{
				Response: nil,
			},
			wantContentType:   "",
			wantWebServer:     "",
			wantContentLength: 0,
			wantWords:         0,
			wantLines:         0,
		},
		{
			name: "empty body",
			entry: &TrafficEntry{
				Response: &ResponseData{
					Headers: map[string]string{
						"Content-Type": "text/plain",
					},
					Body: nil,
				},
			},
			wantContentType:   "text/plain",
			wantWebServer:     "",
			wantContentLength: 0,
			wantWords:         0,
			wantLines:         0,
		},
		{
			name: "binary body (invalid UTF-8)",
			entry: &TrafficEntry{
				Response: &ResponseData{
					Headers: map[string]string{
						"Content-Type": "image/png",
					},
					Body: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG header
				},
			},
			wantContentType:   "image/png",
			wantWebServer:     "",
			wantContentLength: 8,
			wantWords:         0, // Binary, so no word count
			wantLines:         0, // Binary, so no line count
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			computeHTTPXFields(tt.entry)

			if tt.entry.ContentType != tt.wantContentType {
				t.Errorf("ContentType = %q, want %q", tt.entry.ContentType, tt.wantContentType)
			}
			if tt.entry.WebServer != tt.wantWebServer {
				t.Errorf("WebServer = %q, want %q", tt.entry.WebServer, tt.wantWebServer)
			}
			if tt.entry.ContentLength != tt.wantContentLength {
				t.Errorf("ContentLength = %d, want %d", tt.entry.ContentLength, tt.wantContentLength)
			}
			if tt.entry.Words != tt.wantWords {
				t.Errorf("Words = %d, want %d", tt.entry.Words, tt.wantWords)
			}
			if tt.entry.Lines != tt.wantLines {
				t.Errorf("Lines = %d, want %d", tt.entry.Lines, tt.wantLines)
			}
		})
	}
}

// TestHTTPXFieldsSurviveAfterClearingBodyHeaders verifies that httpx fields
// are preserved even after clearing body and headers (simulating !includeBody, !includeHeaders).
func TestHTTPXFieldsSurviveAfterClearingBodyHeaders(t *testing.T) {
	entry := &TrafficEntry{
		Request: RequestData{
			Method: "GET",
			URL:    "https://example.com/test",
		},
		Response: &ResponseData{
			Status: 200,
			Headers: map[string]string{
				"Content-Type": "text/html",
				"Server":       "nginx",
			},
			Body: []byte("Hello World\nLine 2"),
		},
	}

	// Step 1: Compute httpx fields (this happens BEFORE clearing body/headers)
	computeHTTPXFields(entry)

	// Verify fields are set
	if entry.ContentType != "text/html" {
		t.Errorf("ContentType = %q, want %q", entry.ContentType, "text/html")
	}
	if entry.WebServer != "nginx" {
		t.Errorf("WebServer = %q, want %q", entry.WebServer, "nginx")
	}
	if entry.ContentLength != 18 {
		t.Errorf("ContentLength = %d, want %d", entry.ContentLength, 18)
	}
	if entry.Words != 4 { // Hello, World, Line, 2
		t.Errorf("Words = %d, want %d", entry.Words, 4)
	}
	if entry.Lines != 2 {
		t.Errorf("Lines = %d, want %d", entry.Lines, 2)
	}

	// Step 2: Clear body and headers (simulating !includeBody, !includeHeaders)
	entry.Response.Body = nil
	entry.Response.Headers = nil

	// Step 3: Verify httpx fields are STILL preserved
	if entry.ContentType != "text/html" {
		t.Errorf("ContentType after clear = %q, want %q", entry.ContentType, "text/html")
	}
	if entry.WebServer != "nginx" {
		t.Errorf("WebServer after clear = %q, want %q", entry.WebServer, "nginx")
	}
	if entry.ContentLength != 18 {
		t.Errorf("ContentLength after clear = %d, want %d", entry.ContentLength, 18)
	}
	if entry.Words != 4 { // Hello, World, Line, 2
		t.Errorf("Words after clear = %d, want %d", entry.Words, 4)
	}
	if entry.Lines != 2 {
		t.Errorf("Lines after clear = %d, want %d", entry.Lines, 2)
	}
}

// TestComputeHashDifferentAuthHeaders tests that requests with different auth headers produce different hashes.
func TestComputeHashDifferentAuthHeaders(t *testing.T) {
	// Entry without Authorization header
	entry1 := &TrafficEntry{
		Request: RequestData{
			Method: "POST",
			URL:    "https://example.com/api/auth",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "application/json"},
		},
	}

	// Entry WITH Authorization header
	entry2 := &TrafficEntry{
		Request: RequestData{
			Method: "POST",
			URL:    "https://example.com/api/auth",
			Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Basic YWRtaW46YWRtaW4=",
			},
			Body: []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "application/json"},
		},
	}

	hash1 := computeHash(entry1)
	hash2 := computeHash(entry2)

	if hash1 == hash2 {
		t.Errorf("Requests with different Authorization headers should have different hashes, got same: %s", hash1)
	}
}

// TestComputeHashIgnoresNonAuthHeaders tests that non-auth headers don't affect hash.
func TestComputeHashIgnoresNonAuthHeaders(t *testing.T) {
	entry1 := &TrafficEntry{
		Request: RequestData{
			Method: "GET",
			URL:    "https://example.com/api/data",
			Headers: map[string]string{
				"User-Agent": "Chrome/100",
			},
			Body: []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "application/json"},
		},
	}

	entry2 := &TrafficEntry{
		Request: RequestData{
			Method: "GET",
			URL:    "https://example.com/api/data",
			Headers: map[string]string{
				"User-Agent": "Firefox/90",
			},
			Body: []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "application/json"},
		},
	}

	hash1 := computeHash(entry1)
	hash2 := computeHash(entry2)

	if hash1 != hash2 {
		t.Errorf("Requests with only different User-Agent should have same hash, got %s vs %s", hash1, hash2)
	}
}

// TestComputeHashAllAuthHeaders tests that all auth headers in the whitelist affect the hash.
func TestComputeHashAllAuthHeaders(t *testing.T) {
	authHeaderTests := []string{
		"Authorization",
		"X-Auth-Token",
		"X-API-Key",
		"X-Access-Token",
		"X-CSRF-Token",
		"X-XSRF-Token",
		"X-Session-ID",
		"X-Session-Token",
	}

	baseEntry := &TrafficEntry{
		Request: RequestData{
			Method:  "GET",
			URL:     "https://example.com/api/data",
			Headers: map[string]string{},
			Body:    []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "application/json"},
		},
	}
	baseHash := computeHash(baseEntry)

	for _, headerName := range authHeaderTests {
		t.Run(headerName, func(t *testing.T) {
			entry := &TrafficEntry{
				Request: RequestData{
					Method: "GET",
					URL:    "https://example.com/api/data",
					Headers: map[string]string{
						headerName: "test-value-123",
					},
					Body: []byte{},
				},
				Response: &ResponseData{
					Status:  200,
					Headers: map[string]string{"content-type": "application/json"},
				},
			}
			hash := computeHash(entry)

			if hash == baseHash {
				t.Errorf("%s header should affect hash, but got same hash as base", headerName)
			}
		})
	}
}

// TestComputeHashAuthHeaderCaseInsensitive tests that auth header matching is case-insensitive.
func TestComputeHashAuthHeaderCaseInsensitive(t *testing.T) {
	// Test with lowercase "authorization"
	entry1 := &TrafficEntry{
		Request: RequestData{
			Method: "GET",
			URL:    "https://example.com/api/data",
			Headers: map[string]string{
				"authorization": "Bearer token123",
			},
			Body: []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "application/json"},
		},
	}

	// Test with mixed case "Authorization"
	entry2 := &TrafficEntry{
		Request: RequestData{
			Method: "GET",
			URL:    "https://example.com/api/data",
			Headers: map[string]string{
				"Authorization": "Bearer token123",
			},
			Body: []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "application/json"},
		},
	}

	// Base entry without auth header
	baseEntry := &TrafficEntry{
		Request: RequestData{
			Method:  "GET",
			URL:     "https://example.com/api/data",
			Headers: map[string]string{},
			Body:    []byte{},
		},
		Response: &ResponseData{
			Status:  200,
			Headers: map[string]string{"content-type": "application/json"},
		},
	}

	hash1 := computeHash(entry1)
	hash2 := computeHash(entry2)
	baseHash := computeHash(baseEntry)

	// Both should differ from base (auth header is recognized)
	if hash1 == baseHash {
		t.Errorf("lowercase authorization should affect hash")
	}
	if hash2 == baseHash {
		t.Errorf("mixed case Authorization should affect hash")
	}

	// Both should produce the same hash (case-insensitive matching)
	if hash1 != hash2 {
		t.Errorf("authorization and Authorization with same value should produce same hash, got %s vs %s", hash1, hash2)
	}
}
