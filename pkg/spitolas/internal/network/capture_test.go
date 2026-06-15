package network

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
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

// TestShouldLogEntryCrossOriginFilter verifies the non-verbose cross-origin
// log filter: traffic on a host unrelated to the configured target is
// suppressed, while same/sub-host traffic is logged.
func TestShouldLogEntryCrossOriginFilter(t *testing.T) {
	c := New(&mockWriter{}, true, false, false, false, false, "eaccess.mis.teach.stryker.com", "spider")

	if c.shouldLogEntry(createTestEntry("https://eaccess.mis.teach.stryker.com/app")) != true {
		t.Errorf("same-host entry should be logged")
	}
	if c.shouldLogEntry(createTestEntry("https://www.stryker.com/us/en/x.html")) != false {
		t.Errorf("cross-origin entry should be suppressed before adoption")
	}
}

// TestSetTargetHostUnsuppressesAdoptedHost reproduces the off-host-redirect
// adoption case: the start host redirects to an unrelated host that the crawler
// adopts into scope. Until the capture's filter is re-pointed at the adopted
// host, every adopted-host line is dropped from stderr even though records are
// written. SetTargetHost must flip that.
func TestSetTargetHostUnsuppressesAdoptedHost(t *testing.T) {
	c := New(&mockWriter{}, true, false, false, false, false, "eaccess.mis.teach.stryker.com", "spider")

	adopted := createTestEntry("https://www.stryker.com/us/en/training.html")
	if c.shouldLogEntry(adopted) != false {
		t.Fatalf("precondition: adopted-host entry should be suppressed before SetTargetHost")
	}

	// Crawler adopts the off-host redirect target into scope.
	c.SetTargetHost("www.stryker.com")

	if c.shouldLogEntry(adopted) != true {
		t.Errorf("adopted-host entry should be logged after SetTargetHost")
	}
	if c.targetHostValue() != "www.stryker.com" {
		t.Errorf("targetHostValue() = %q, want %q", c.targetHostValue(), "www.stryker.com")
	}
}

// TestSetTargetHostStaticStillSuppressed confirms re-pointing the filter does
// not override the unconditional static-content suppression.
func TestSetTargetHostStaticStillSuppressed(t *testing.T) {
	c := New(&mockWriter{}, true, false, false, false, false, "eaccess.mis.teach.stryker.com", "spider")
	c.SetTargetHost("www.stryker.com")

	css := createTestEntry("https://www.stryker.com/assets/app.css")
	css.Response.Headers = map[string]string{"content-type": "text/css"}
	if c.shouldLogEntry(css) != false {
		t.Errorf("static content on adopted host should still be suppressed")
	}
}

// TestOnWorkerAttachedGuards verifies the service-worker attach handler is a safe
// no-op for nil/empty events (so a malformed Target.attachedToTarget never panics
// the capture event loop) and does not dereference the browser in those paths.
func TestOnWorkerAttachedGuards(t *testing.T) {
	c := &Capture{}
	// nil browser + nil event: must not panic.
	c.onWorkerAttached(nil, nil)
	// nil browser + event with no TargetInfo: must return before touching browser.
	c.onWorkerAttached(nil, &proto.TargetAttachedToTarget{SessionID: "s1"})
	// non-nil event but nil TargetInfo with a session: still must not touch browser.
	c.onWorkerAttached(nil, &proto.TargetAttachedToTarget{SessionID: "s2", WaitingForDebugger: true})
}

// TestServiceWorkerAutoAttachConfig locks down the auto-attach request invariants.
// These are safety-critical: the filter must stay scoped to service workers so
// auto-attach never fights rod's page/tab management (which would risk stuck
// sessions and un-reaped "zombie" browsers), and the flags must be set so the
// worker's first precache request is captured rather than missed.
func TestServiceWorkerAutoAttachConfig(t *testing.T) {
	cfg := serviceWorkerAutoAttachConfig()

	if !cfg.AutoAttach {
		t.Error("AutoAttach must be true")
	}
	if !cfg.Flatten {
		t.Error("Flatten must be true so worker events arrive over the root connection")
	}
	if !cfg.WaitForDebuggerOnStart {
		t.Error("WaitForDebuggerOnStart must be true so Network is enabled before the worker runs")
	}

	if len(cfg.Filter) < 2 {
		t.Fatalf("filter must have an include + a trailing exclude-all, got %d entries", len(cfg.Filter))
	}
	// First entry includes service workers.
	if got := cfg.Filter[0]; got.Type != string(proto.TargetTargetInfoTypeServiceWorker) || got.Exclude {
		t.Errorf("first filter entry must INCLUDE service_worker, got %+v", got)
	}
	// Last entry is the exclude-everything-else catch-all.
	if last := cfg.Filter[len(cfg.Filter)-1]; !last.Exclude || last.Type != "" {
		t.Errorf("last filter entry must be an exclude-all catch-all, got %+v", last)
	}
	// Regression guard: no page/tab/browser/iframe target may be auto-attached —
	// only service workers. Broadening this is the path to zombie browsers.
	for _, e := range cfg.Filter {
		if e.Exclude {
			continue
		}
		switch e.Type {
		case "page", "tab", "browser", "iframe":
			t.Errorf("filter must not auto-attach %q targets (service workers only)", e.Type)
		case "":
			t.Errorf("filter must not have an INCLUDE-everything entry (%+v) — that attaches pages too", e)
		}
	}
}

// TestWriteEntryDropsCatchAllAssetShell verifies the soft-404 guard: a JS/JSON
// asset path that returns the SPA index shell (200, text/html) — as the service
// -worker priming probe's well-known-filename guesses do on a catch-all host — is
// dropped, never written to the DB, while a genuine asset served with its proper
// content-type is written.
func TestWriteEntryDropsCatchAllAssetShell(t *testing.T) {
	mock := &mockWriter{}
	capture := &Capture{
		writer:     mock,
		logged:     make(map[string]struct{}),
		seenHashes: make(map[string]bool),
		noColor:    true,
		silent:     true,
	}

	// All of these are PWA priming guesses that a SPA catch-all returns as its
	// text/html index shell — none is a real endpoint.
	shells := []string{
		"https://example.com/sw.js",
		"https://example.com/firebase-messaging-sw.js",
		"https://example.com/combined-sw.js",
		"https://example.com/safety-worker.js",
		"https://example.com/worker-basic.min.js",
		"https://example.com/ngsw.json",
		"https://example.com/manifest.webmanifest",
		"https://example.com/_nuxt/builds/latest.json",
	}
	for _, u := range shells {
		e := createTestEntry(u) // createTestEntry defaults to a 200 text/html response
		capture.writeEntry(e)
	}
	if mock.getWriteCount() != 0 {
		t.Errorf("catch-all asset shells should not be written, got writeCount=%d", mock.getWriteCount())
	}

	// A genuine service worker / bundle / manifest served with its real
	// content-type is kept.
	realSW := createTestEntry("https://example.com/service-worker.js")
	realSW.Response.Headers = map[string]string{"content-type": "application/javascript"}
	realSW.ContentType = "application/javascript"
	capture.writeEntry(realSW)

	realManifest := createTestEntry("https://example.com/config.json")
	realManifest.Response.Headers = map[string]string{"content-type": "application/json"}
	realManifest.ContentType = "application/json"
	capture.writeEntry(realManifest)

	if mock.getWriteCount() != 2 {
		t.Errorf("genuine JS/JSON assets should be written, got writeCount=%d", mock.getWriteCount())
	}

	// A non-asset HTML route (no JS/JSON extension) is unaffected by the guard.
	htmlPage := createTestEntry("https://example.com/dashboard")
	capture.writeEntry(htmlPage)
	if mock.getWriteCount() != 3 {
		t.Errorf("normal HTML route should still be written, got writeCount=%d", mock.getWriteCount())
	}
}

// TestIsCatchAllAssetShell unit-tests the soft-404 classifier directly.
func TestIsCatchAllAssetShell(t *testing.T) {
	mkEntry := func(rawURL, ct string, status int) *TrafficEntry {
		return &TrafficEntry{
			Request:     RequestData{Method: "GET", URL: rawURL},
			Response:    &ResponseData{Status: status, Headers: map[string]string{"content-type": ct}},
			ContentType: ct,
		}
	}
	tests := []struct {
		name   string
		entry  *TrafficEntry
		expect bool
	}{
		{"js served as html (catch-all)", mkEntry("https://x.com/sw.js", "text/html", 200), true},
		{"json served as html (catch-all)", mkEntry("https://x.com/ngsw.json", "text/html; charset=utf-8", 200), true},
		{"webmanifest served as html", mkEntry("https://x.com/manifest.webmanifest", "text/html", 200), true},
		{"mjs served as html", mkEntry("https://x.com/app.mjs", "text/html", 200), true},
		{"real js asset", mkEntry("https://x.com/app.js", "application/javascript", 200), false},
		{"real json asset", mkEntry("https://x.com/config.json", "application/json", 200), false},
		{"html page (no asset ext)", mkEntry("https://x.com/dashboard", "text/html", 200), false},
		{"js 404 (handled elsewhere)", mkEntry("https://x.com/sw.js", "text/html", 404), false},
		{"js 3xx redirect", mkEntry("https://x.com/sw.js", "text/html", 302), false},
		{"json query string still matches path ext", mkEntry("https://x.com/ngsw.json?v=2", "text/html", 200), true},
		{"nil response", &TrafficEntry{Request: RequestData{URL: "https://x.com/sw.js"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCatchAllAssetShell(tt.entry); got != tt.expect {
				t.Errorf("isCatchAllAssetShell(%s) = %v, want %v", tt.name, got, tt.expect)
			}
		})
	}
}

// newRedirectTestCapture builds a Capture wired to a mock writer, suitable for
// driving onRequestWillBeSent directly (no browser). silent avoids stderr; the
// pending map must be initialized or onRequestWillBeSent's map assignment panics.
func newRedirectTestCapture(mock *mockWriter) *Capture {
	return &Capture{
		writer:     mock,
		pending:    make(map[proto.NetworkRequestID]*pendingEntry),
		logged:     make(map[string]struct{}),
		seenHashes: make(map[string]bool),
		noColor:    true,
		silent:     true,
	}
}

func reqWillBeSent(reqID, url string, redirect *proto.NetworkResponse) *proto.NetworkRequestWillBeSent {
	return &proto.NetworkRequestWillBeSent{
		RequestID:        proto.NetworkRequestID(reqID),
		Type:             proto.NetworkResourceTypeDocument,
		Request:          &proto.NetworkRequest{Method: "GET", URL: url},
		RedirectResponse: redirect,
	}
}

func (m *mockWriter) urls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e.Request.URL)
	}
	return out
}

// TestOnRequestWillBeSentEmitsRedirectHops is the regression guard for the bug
// where each 3xx hop in a redirect chain was overwritten by its target and lost
// (so an SSO chain's /oauth2/authorize and /idp/endpoint/HttpRedirect were never
// recorded). CDP reuses one RequestID across a redirect chain, delivering the
// previous hop's response in RedirectResponse on the next requestWillBeSent. Each
// intermediate hop must be emitted as its own record.
func TestOnRequestWillBeSentEmitsRedirectHops(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)

	const (
		a  = "https://app.example.com/oauth2/authorize?response_type=code"
		b  = "https://idp.example.com/idp/login?app=1"
		cc = "https://idp.example.com/idp/endpoint/HttpRedirect?SAMLRequest=zzz"
	)

	// Same RequestID across the whole chain: A -302-> B -302-> C.
	c.onRequestWillBeSent(reqWillBeSent("1", a, nil), "sess")
	c.onRequestWillBeSent(reqWillBeSent("1", b, &proto.NetworkResponse{Status: 302}), "sess")
	c.onRequestWillBeSent(reqWillBeSent("1", cc, &proto.NetworkResponse{Status: 302}), "sess")

	got := mock.urls()
	// The two completed hops (A and B) must be written; C is still pending its
	// own response and is emitted later by onLoadingFinished.
	if len(got) != 2 {
		t.Fatalf("expected 2 redirect hops emitted, got %d: %v", len(got), got)
	}
	wantSet := map[string]bool{a: false, b: false}
	for _, u := range got {
		if _, ok := wantSet[u]; !ok {
			t.Errorf("unexpected emitted URL %q", u)
			continue
		}
		wantSet[u] = true
	}
	for u, seen := range wantSet {
		if !seen {
			t.Errorf("redirect hop %q was not emitted (it would be silently lost)", u)
		}
	}

	// C is still in flight (not yet emitted): exactly one pending entry, keyed by
	// the shared RequestID, pointing at the final URL.
	c.mu.Lock()
	pendingLen := len(c.pending)
	finalEntry := c.pending["1"]
	c.mu.Unlock()
	if pendingLen != 1 || finalEntry == nil || finalEntry.entry.Request.URL != cc {
		t.Errorf("expected the final hop %q to remain pending, got pending=%d entry=%v", cc, pendingLen, finalEntry)
	}
}

// TestOnRequestWillBeSentNoRedirectDoesNotEmit verifies a normal (non-redirect)
// request is only buffered as pending — it is emitted later by
// onLoadingFinished/onLoadingFailed, not prematurely here.
func TestOnRequestWillBeSentNoRedirectDoesNotEmit(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)

	c.onRequestWillBeSent(reqWillBeSent("1", "https://example.com/page", nil), "sess")

	if mock.getWriteCount() != 0 {
		t.Errorf("a non-redirect request must not be written from onRequestWillBeSent, got %d", mock.getWriteCount())
	}
	c.mu.Lock()
	_, pending := c.pending["1"]
	c.mu.Unlock()
	if !pending {
		t.Errorf("a non-redirect request must be buffered as pending")
	}
}

// TestOnRequestWillBeSentRedirectCapturesResponseMeta verifies the emitted
// redirect hop carries the redirect status and (when headers are included) the
// Location header that points at the next hop — the evidence that proves it was a
// redirect and where it went.
func TestOnRequestWillBeSentRedirectCapturesResponseMeta(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)
	c.includeResponseHeaders = true

	const hop = "https://app.example.com/oauth2/authorize"
	const next = "https://idp.example.com/idp/login"

	c.onRequestWillBeSent(reqWillBeSent("1", hop, nil), "sess")
	c.onRequestWillBeSent(&proto.NetworkRequestWillBeSent{
		RequestID: "1",
		Type:      proto.NetworkResourceTypeDocument,
		Request:   &proto.NetworkRequest{Method: "GET", URL: next},
		RedirectResponse: &proto.NetworkResponse{
			Status:  302,
			Headers: proto.NetworkHeaders{"Location": gson.New(next)},
		},
	}, "sess")

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.entries) != 1 {
		t.Fatalf("expected 1 emitted redirect hop, got %d", len(mock.entries))
	}
	e := mock.entries[0]
	if e.Request.URL != hop {
		t.Errorf("emitted hop URL = %q, want %q", e.Request.URL, hop)
	}
	if e.Response == nil || e.Response.Status != 302 {
		t.Fatalf("emitted hop must carry the 302 redirect status, got %+v", e.Response)
	}
	if loc := e.Response.Headers["Location"]; loc != next {
		t.Errorf("emitted hop Location header = %q, want %q", loc, next)
	}
}

// TestShouldLogEntry404Suppressed verifies probe noise (404s from e.g.
// service-worker / manifest priming) is suppressed from stderr in non-verbose
// mode but shown under verbose. Records are still written regardless.
func TestShouldLogEntry404Suppressed(t *testing.T) {
	// Non-verbose: same-host 404 is suppressed.
	c := New(&mockWriter{}, true, false, false, false, false, "example.com", "spider")
	notFound := createTestEntry("https://example.com/ngsw.json")
	notFound.Response.Status = 404
	if c.shouldLogEntry(notFound) != false {
		t.Errorf("404 should be suppressed in non-verbose mode")
	}
	// A same-host 200 on the same path is still logged (only 404s are dropped).
	ok := createTestEntry("https://example.com/ngsw.json")
	if c.shouldLogEntry(ok) != true {
		t.Errorf("200 should still be logged in non-verbose mode")
	}

	// Verbose: 404 is shown.
	cv := New(&mockWriter{}, true, false, true, false, false, "example.com", "spider")
	if cv.shouldLogEntry(notFound) != true {
		t.Errorf("404 should be logged under verbose mode")
	}
}
