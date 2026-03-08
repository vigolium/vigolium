package discovery

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_WaitForStateTimeout(t *testing.T) {
	server := testServer()
	defer server.Close()

	engine, err := testEngine(server.URL)
	require.NoError(t, err)
	defer engine.Stop()

	// Wait for state that never happens
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = engine.WaitForState(ctx, StateRunning)
	assert.Error(t, err)
	assert.Equal(t, context.DeadlineExceeded, err)
}

// Note: Legacy tests removed - deduplication and directory tracking now handled by sitemap storage
// See spider_integration_test.go for sitemap-based tests:
// - TestEngine_SitemapDeduplication (replaces TestEngine_DuplicateDetection)
// - TestEngine_DirectoriesFromSitemap (replaces TestEngine_DirectoryTracking)

func TestEngine_ObservedFileTracking(t *testing.T) {
	server := testServer()
	defer server.Close()

	engine, err := testEngine(server.URL)
	require.NoError(t, err)
	defer engine.Stop()

	engine.AddObservedName("index")
	engine.AddObservedName("config")
	engine.AddObservedName("index") // Duplicate

	engine.AddObservedExtension("php")
	engine.AddObservedExtension("inc")

	names := engine.GetObservedNames()
	assert.Equal(t, 2, names.Count())
	assert.True(t, names.Contains([]byte("index")))
	assert.True(t, names.Contains([]byte("config")))

	extensions := engine.GetObservedExtensions()
	assert.Equal(t, 2, extensions.Count())
	assert.True(t, extensions.Contains([]byte("php")))
	assert.True(t, extensions.Contains([]byte("inc")))
}

// Note: TestEngine_ConcurrentDuplicateDetection removed - deduplication is now handled by sitemap
// Concurrent tests for sitemap-based deduplication should be in spider_integration_test.go

// TestEngine_ConcurrentExtensionAddition_NoDeadlock tests that concurrent
// extension additions don't cause deadlock from nested locking
func TestEngine_ConcurrentExtensionAddition_NoDeadlock(t *testing.T) {
	server := testServer()
	defer server.Close()

	engine, err := testEngine(server.URL)
	require.NoError(t, err)
	defer engine.Stop()

	// Use whitelisted extensions for the test
	whitelistedExts := []string{"php", "asp", "aspx", "jsp", "html", "htm", "js", "txt", "xml", "bak"}
	numUniqueExtensions := len(whitelistedExts)

	// Launch 100 goroutines adding extensions concurrently
	// This tests the fix for nested lock deadlock (observedExtensionsMu -> observedExtensions.mu)
	const numGoroutines = 100

	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Each goroutine tries to add same extensions
			// This creates high contention on the locks
			for _, ext := range whitelistedExts {
				wasNew := engine.addObservedExtensionIfNew(ext)
				_ = wasNew // First goroutine for each ext will get true
			}
		}(i)
	}

	// Wait for all goroutines with timeout
	timeout := time.After(5 * time.Second)
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("Test timed out - likely deadlock detected")
		}
	}

	// Verify exactly numUniqueExtensions were added (deduplication worked)
	assert.Equal(t, int64(numUniqueExtensions), engine.seenExtensions.Size())

	// Verify all extensions are in observedExtensions provider
	assert.Equal(t, numUniqueExtensions, engine.observedExtensions.Count())
}

// TestEngine_ObservedExtensionWhitelist tests that only extensions in the
// AllowedObservedExtensions whitelist are added to observed extensions.
func TestEngine_ObservedExtensionWhitelist(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()

	tests := []struct {
		extension string
		shouldAdd bool
	}{
		// Extensions in whitelist (should be added)
		{"php", true},
		{"PHP", false}, // Case-insensitive dedup - "php" already added
		{"asp", true},
		{"html", true},
		{"js", true},
		{"txt", true},
		{"bak", true},
		{"log", true},

		// Extensions NOT in whitelist (should be filtered)
		{"mp4", false},
		{"mp3", false},
		{"css", false},
		{"woff", false},
		{"png", false},
		{"svg", false},
		{"randomext", false},
	}

	for _, tt := range tests {
		wasNew := engine.addObservedExtensionIfNew(tt.extension)
		if tt.shouldAdd {
			assert.True(t, wasNew, "extension %q should be added (in whitelist)", tt.extension)
		} else {
			assert.False(t, wasNew, "extension %q should be filtered", tt.extension)
		}
	}

	// Verify only whitelisted extensions were added (case-insensitive dedup)
	// php, asp, html, js, txt, bak, log = 7
	assert.Equal(t, 7, engine.observedExtensions.Count(),
		"should have exactly 7 whitelisted extensions")
}

// TestEngine_ConcurrentDirectoryCallback_NoDuplicateTasks tests that concurrent
// OnDirectoryDiscovered calls don't create duplicate tasks
func TestEngine_ConcurrentDirectoryCallback_NoDuplicateTasks(t *testing.T) {
	server := testServer()
	defer server.Close()

	// Create config with UseObservedNames enabled
	cfg := testConfig(server.URL)
	cfg.Filenames.UseObservedNames = true

	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()

	// Add some observed names so tasks will be created
	engine.AddObservedName("admin")
	engine.AddObservedName("config")
	engine.AddObservedName("index")

	testDir := server.URL + "/testdir/"

	// Launch 50 goroutines all discovering the same directory
	// This tests the fix for directory task creation race
	const numGoroutines = 50

	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- true }()

			// All goroutines discover same directory
			err := engine.OnDirectoryDiscovered(testDir, 1)
			if err != nil {
				t.Errorf("OnDirectoryDiscovered failed: %v", err)
			}
		}()
	}

	// Wait for all goroutines
	timeout := time.After(5 * time.Second)
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
			// Success
		case <-timeout:
			t.Fatal("Test timed out waiting for directory callbacks")
		}
	}

	// Verify tasks were created (hash-based deduplication should prevent duplicates)
	// The presence of tasks in taskHashes indicates tasks were created

	// Verify exactly one set of tasks was created (not 50 sets)
	// Since we have 3 observed names and default config, we expect:
	// - Priority 0: 1 task (observed names, no ext)
	// - Priority 1: 1 task (observed names, custom ext) - if TestCustom enabled
	// Total: 1-2 tasks (depending on config)
	metrics := engine.GetMetrics()
	// Should have created tasks only once, not 50 times
	assert.Less(t, metrics.TasksGenerated, uint64(10),
		"Should not have created 50x duplicate tasks")
}

// TestEngine_NetworkErrorTracker_Disabled tests that error tracker is nil when threshold is 0
func TestEngine_NetworkErrorTracker_Disabled(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Engine.MaxConsecutiveErrors = 0 // Disabled

	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()

	// Verify error tracker is NOT initialized
	assert.Nil(t, engine.errorTracker, "error tracker should be nil when disabled")

	// Verify callbacks don't have error tracker
	callbacks := engine.newCallbacks()
	assert.Nil(t, callbacks.ErrorTracker)
}

// TestEngine_NetworkErrorTracker_Callbacks tests that error tracker is passed to callbacks
func TestEngine_NetworkErrorTracker_Callbacks(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Engine.MaxConsecutiveErrors = 100

	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()

	// Verify error tracker is initialized and passed to callbacks
	assert.NotNil(t, engine.errorTracker)

	callbacks := engine.newCallbacks()
	assert.NotNil(t, callbacks.ErrorTracker)
	assert.Equal(t, engine.errorTracker, callbacks.ErrorTracker)
}

func TestEngine_IsRootURL(t *testing.T) {
	server := testServer()
	defer server.Close()

	tests := []struct {
		name     string
		startURL string
		testURL  string
		expected bool
	}{
		{
			name:     "exact match without trailing slash",
			startURL: "https://example.com",
			testURL:  "https://example.com",
			expected: true,
		},
		{
			name:     "exact match with trailing slash",
			startURL: "https://example.com/",
			testURL:  "https://example.com/",
			expected: true,
		},
		{
			name:     "start without slash, test with slash",
			startURL: "https://example.com",
			testURL:  "https://example.com/",
			expected: true,
		},
		{
			name:     "start with slash, test without slash",
			startURL: "https://example.com/",
			testURL:  "https://example.com",
			expected: true,
		},
		{
			name:     "non-root path should not match",
			startURL: "https://example.com",
			testURL:  "https://example.com/admin",
			expected: false,
		},
		{
			name:     "non-root path with trailing slash should not match",
			startURL: "https://example.com",
			testURL:  "https://example.com/admin/",
			expected: false,
		},
		{
			name:     "different host should not match",
			startURL: "https://example.com",
			testURL:  "https://other.com/",
			expected: false,
		},
		{
			name:     "different scheme should not match",
			startURL: "https://example.com",
			testURL:  "http://example.com/",
			expected: false,
		},
		{
			name:     "start with path, test with root",
			startURL: "https://example.com/app",
			testURL:  "https://example.com/",
			expected: false,
		},
		{
			name:     "start with path, test matching path",
			startURL: "https://example.com/app",
			testURL:  "https://example.com/app",
			expected: true,
		},
		{
			name:     "start with path, test matching path with slash",
			startURL: "https://example.com/app",
			testURL:  "https://example.com/app/",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(server.URL)
			cfg.Target.StartURL = tt.startURL

			engine, err := testEngineWithConfig(cfg)
			require.NoError(t, err)
			defer engine.Stop()

			testURL, err := http.NewRequest("GET", tt.testURL, nil)
			require.NoError(t, err)

			result := engine.isRootURL(testURL.URL)
			assert.Equal(t, tt.expected, result, "isRootURL(%s) with startURL=%s", tt.testURL, tt.startURL)
		})
	}
}

// TestEngine_WAFBlockTracker_Disabled tests that WAF block tracker is nil when threshold is 0
func TestEngine_WAFBlockTracker_Disabled(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Engine.MaxConsecutiveWAFBlocks = 0 // Disabled

	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()

	// Verify WAF block tracker is NOT initialized
	assert.Nil(t, engine.wafBlockTracker, "WAF block tracker should be nil when disabled")
	assert.Nil(t, engine.wafDetector, "WAF detector should be nil when disabled")

	// Verify callbacks don't have WAF tracker
	callbacks := engine.newCallbacks()
	assert.Nil(t, callbacks.WAFBlockTracker)
	assert.Nil(t, callbacks.WAFDetector)
}

// TestEngine_WAFBlockTracker_Callbacks tests that WAF block tracker is passed to callbacks
func TestEngine_WAFBlockTracker_Callbacks(t *testing.T) {
	server := testServer()
	defer server.Close()

	cfg := testConfig(server.URL)
	cfg.Engine.MaxConsecutiveWAFBlocks = 100

	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()

	// Verify WAF block tracker is initialized and passed to callbacks
	assert.NotNil(t, engine.wafBlockTracker)
	assert.NotNil(t, engine.wafDetector)

	callbacks := engine.newCallbacks()
	assert.NotNil(t, callbacks.WAFBlockTracker)
	assert.NotNil(t, callbacks.WAFDetector)
	assert.Equal(t, engine.wafBlockTracker, callbacks.WAFBlockTracker)
	assert.Equal(t, engine.wafDetector, callbacks.WAFDetector)
}
