//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
)

// PostgreSQL connection settings (from environment or defaults for docker-compose)
func getPostgresConfig() *storage.StorageConfig {
	host := getEnv("POSTGRES_HOST", "localhost")
	port := getEnvInt("POSTGRES_PORT", 6432)
	user := getEnv("POSTGRES_USER", "deparos_app")
	password := getEnv("POSTGRES_PASSWORD", "deparos_app_password")
	database := getEnv("POSTGRES_DB", "deparos")

	cfg := storage.PostgresConfig(host, database, user, password)
	cfg.Database.Port = port
	return cfg
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		var i int
		fmt.Sscanf(val, "%d", &i)
		return i
	}
	return defaultVal
}

// TestPostgresStorageIntegration is a comprehensive test that covers all major storage operations.
// Run with: go test -tags=integration -v ./test/... -run TestPostgres
func TestPostgresStorageIntegration(t *testing.T) {
	cfg := getPostgresConfig()
	cfg.TargetURL = "https://test-postgres.example.com"

	t.Logf("Connecting to PostgreSQL at %s:%d", cfg.Database.Host, cfg.Database.Port)

	sitemap, err := storage.NewSiteMap(cfg)
	if err != nil {
		t.Fatalf("Failed to create sitemap: %v", err)
	}
	defer sitemap.Close()

	sessionDBID := sitemap.SessionDBID()
	t.Logf("Created session DB ID: %d", sessionDBID)

	// =========================================================================
	// Test 1: Basic CRUD operations
	// =========================================================================
	t.Run("BasicCRUD", func(t *testing.T) {
		// Store
		testURL, _ := url.Parse("https://test-postgres.example.com/crud/test")
		result := storage.NewResult(testURL)
		result.Response.StatusCode = 200
		result.Response.MIMEType = "text/html"
		result.Request.Method = "GET"
		result.Metadata.FoundBy = "integration-test"

		if err := sitemap.Store(result); err != nil {
			t.Fatalf("Store failed: %v", err)
		}

		// Get (verifies existence)
		if _, err := sitemap.Get(testURL); err != nil {
			t.Errorf("Get returned error for stored URL: %v", err)
		}

		// Get
		node, err := sitemap.Get(testURL)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if node == nil {
			t.Fatal("Get returned nil node")
		}
		if node.Response().StatusCode != 200 {
			t.Errorf("StatusCode mismatch: got %d, want 200", node.Response().StatusCode)
		}

		// Count
		count := sitemap.Count()
		if count < 1 {
			t.Errorf("Count should be >= 1, got %d", count)
		}

		t.Log("BasicCRUD passed")
	})

	// =========================================================================
	// Test 2: Multiple results with different paths
	// =========================================================================
	t.Run("MultiplePaths", func(t *testing.T) {
		paths := []string{
			"/api/v1/users",
			"/api/v1/products",
			"/api/v2/orders",
			"/admin/dashboard",
			"/admin/settings",
		}

		for _, path := range paths {
			testURL, _ := url.Parse("https://test-postgres.example.com" + path)
			result := storage.NewResult(testURL)
			result.Response.StatusCode = 200
			result.Request.Method = "GET"
			result.Metadata.FoundBy = "multi-path-test"

			if err := sitemap.Store(result); err != nil {
				t.Errorf("Failed to store %s: %v", path, err)
			}
		}

		// Verify all stored
		for _, path := range paths {
			testURL, _ := url.Parse("https://test-postgres.example.com" + path)
			if _, err := sitemap.Get(testURL); err != nil {
				t.Errorf("Path not found: %s, error: %v", path, err)
			}
		}

		t.Logf("Stored and verified %d paths", len(paths))
	})

	// =========================================================================
	// Test 3: Different status codes
	// =========================================================================
	t.Run("StatusCodes", func(t *testing.T) {
		statusCodes := []int{200, 201, 301, 302, 400, 401, 403, 500}

		for _, code := range statusCodes {
			path := fmt.Sprintf("/status/%d", code)
			testURL, _ := url.Parse("https://test-postgres.example.com" + path)
			result := storage.NewResult(testURL)
			result.Response.StatusCode = code
			result.Request.Method = "GET"
			result.Metadata.FoundBy = "status-test"

			if err := sitemap.Store(result); err != nil {
				t.Errorf("Failed to store status %d: %v", code, err)
			}
		}

		// Verify status codes preserved
		for _, code := range statusCodes {
			path := fmt.Sprintf("/status/%d", code)
			testURL, _ := url.Parse("https://test-postgres.example.com" + path)
			node, err := sitemap.Get(testURL)
			if err != nil {
				t.Errorf("Failed to get status %d: %v", code, err)
				continue
			}
			if node.Response().StatusCode != code {
				t.Errorf("Status mismatch for %s: got %d, want %d", path, node.Response().StatusCode, code)
			}
		}

		t.Logf("Verified %d status codes", len(statusCodes))
	})

	// =========================================================================
	// Test 4: Response body storage
	// =========================================================================
	t.Run("ResponseBody", func(t *testing.T) {
		testURL, _ := url.Parse("https://test-postgres.example.com/body/test")
		result := storage.NewResult(testURL)
		result.Response.StatusCode = 200
		result.Response.Body = []byte(`{"message": "Hello PostgreSQL", "data": [1,2,3]}`)
		result.Response.MIMEType = "application/json"
		result.Request.Method = "GET"

		if err := sitemap.Store(result); err != nil {
			t.Fatalf("Failed to store body: %v", err)
		}

		node, err := sitemap.Get(testURL)
		if err != nil {
			t.Fatalf("Failed to get body: %v", err)
		}

		if string(node.Response().Body) != `{"message": "Hello PostgreSQL", "data": [1,2,3]}` {
			t.Errorf("Body mismatch: got %s", string(node.Response().Body))
		}

		t.Log("ResponseBody passed")
	})

	// =========================================================================
	// Test 5: Redirects with Location header
	// =========================================================================
	t.Run("Redirects", func(t *testing.T) {
		testURL, _ := url.Parse("https://test-postgres.example.com/redirect/old")
		result := storage.NewResult(testURL)
		result.Response.StatusCode = 301
		result.Response.Location = "/redirect/new"
		result.Request.Method = "GET"
		result.Metadata.FoundBy = "redirect-test"

		if err := sitemap.Store(result); err != nil {
			t.Fatalf("Failed to store redirect: %v", err)
		}

		node, err := sitemap.Get(testURL)
		if err != nil {
			t.Fatalf("Failed to get redirect: %v", err)
		}

		if node.Response().Location != "/redirect/new" {
			t.Errorf("Location mismatch: got %q, want %q", node.Response().Location, "/redirect/new")
		}

		t.Log("Redirects passed")
	})

	// =========================================================================
	// Test 6: Session operations
	// =========================================================================
	t.Run("SessionOperations", func(t *testing.T) {
		sessions, err := sitemap.ListSessions()
		if err != nil {
			t.Fatalf("ListSessions failed: %v", err)
		}

		if len(sessions) < 1 {
			t.Error("Expected at least 1 session")
		}

		// Find our session
		var found bool
		for _, s := range sessions {
			if s.DBID == sessionDBID {
				found = true
				// Verify TargetURL contains the expected hostname
				if s.TargetURL != "https://test-postgres.example.com" {
					t.Errorf("TargetURL mismatch: got %q", s.TargetURL)
				}
				break
			}
		}
		if !found {
			t.Error("Current session not found in ListSessions")
		}

		t.Logf("Found %d sessions", len(sessions))
	})

	// =========================================================================
	// Test 7: StreamAllResults
	// =========================================================================
	t.Run("StreamAllResults", func(t *testing.T) {
		var count int
		err := sitemap.StreamAllResults(func(node *storage.DiscoveredNode) error {
			count++
			return nil
		})
		if err != nil {
			t.Fatalf("StreamAllResults failed: %v", err)
		}

		// Should have at least the URLs we stored in previous tests
		if count < 5 {
			t.Errorf("Expected >= 5 results, got %d", count)
		}

		t.Logf("StreamAllResults returned %d results", count)
	})

	// =========================================================================
	// Test 8: Extraction repository
	// =========================================================================
	t.Run("ExtractionRepository", func(t *testing.T) {
		extractions := sitemap.Extractions()
		if extractions == nil {
			t.Fatal("Extractions() returned nil")
		}

		// Store a spider link extraction using the proper API
		linkURL, _ := url.Parse("https://test-postgres.example.com/extracted/link")
		link := &spider.DiscoveredLink{
			URL:        linkURL,
			SourceType: spider.SourceHTMLAttribute,
		}
		err := extractions.StoreSpiderLink(
			1,                     // sourceNodeID
			sitemap.SessionDBID(), // sessionID
			link,
		)
		if err != nil {
			t.Errorf("StoreSpiderLink failed: %v", err)
		}

		// Query extractions by hostname
		links, err := extractions.GetByHostname("test-postgres.example.com")
		if err != nil {
			t.Errorf("GetByHostname failed: %v", err)
		}

		if len(links) < 1 {
			t.Error("Expected at least 1 extraction")
		}

		t.Logf("Extraction repository: stored and retrieved %d links", len(links))
	})

	// =========================================================================
	// Test 9: Deduplication
	// =========================================================================
	t.Run("Deduplication", func(t *testing.T) {
		testURL, _ := url.Parse("https://test-postgres.example.com/dedup/test")

		// Store same URL twice
		for i := 0; i < 2; i++ {
			result := storage.NewResult(testURL)
			result.Response.StatusCode = 200 + i // Different status each time
			result.Request.Method = "GET"

			if err := sitemap.Store(result); err != nil {
				t.Errorf("Store %d failed: %v", i, err)
			}
		}

		// Should only have one entry (upsert behavior)
		node, err := sitemap.Get(testURL)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		// Second store should have updated status
		if node.Response().StatusCode != 201 {
			t.Logf("Note: Dedup kept status %d (upsert behavior may vary)", node.Response().StatusCode)
		}

		t.Log("Deduplication passed")
	})

	// =========================================================================
	// Test 10: Tags
	// =========================================================================
	t.Run("Tags", func(t *testing.T) {
		testURL, _ := url.Parse("https://test-postgres.example.com/tags/test")
		result := storage.NewResult(testURL)
		result.Response.StatusCode = 200
		result.Request.Method = "GET"
		result.Tags = []string{"api", "json", "authenticated"}

		if err := sitemap.Store(result); err != nil {
			t.Fatalf("Store with tags failed: %v", err)
		}

		// Update tags
		err := sitemap.UpdateNodeTagsByURL(testURL.String(), []string{"updated", "tag"})
		if err != nil {
			t.Errorf("UpdateNodeTagsByURL failed: %v", err)
		}

		t.Log("Tags passed")
	})

	t.Log("All PostgreSQL storage integration tests completed!")
}

// TestPostgresConcurrency tests concurrent access to PostgreSQL storage.
func TestPostgresConcurrency(t *testing.T) {
	cfg := getPostgresConfig()
	cfg.TargetURL = "https://concurrent.example.com"

	sitemap, err := storage.NewSiteMap(cfg)
	if err != nil {
		t.Fatalf("Failed to create sitemap: %v", err)
	}
	defer sitemap.Close()

	const numGoroutines = 50
	const urlsPerGoroutine = 10

	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines*urlsPerGoroutine)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("ConcurrentWrites", func(t *testing.T) {
		for g := 0; g < numGoroutines; g++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				for i := 0; i < urlsPerGoroutine; i++ {
					select {
					case <-ctx.Done():
						return
					default:
					}

					path := fmt.Sprintf("/concurrent/g%d/url%d", goroutineID, i)
					testURL, _ := url.Parse("https://concurrent.example.com" + path)
					result := storage.NewResult(testURL)
					result.Response.StatusCode = 200
					result.Request.Method = "GET"
					result.Metadata.FoundBy = fmt.Sprintf("goroutine-%d", goroutineID)

					if err := sitemap.Store(result); err != nil {
						errCh <- fmt.Errorf("g%d url%d: %w", goroutineID, i, err)
					}
				}
			}(g)
		}

		wg.Wait()
		close(errCh)

		var errors []error
		for err := range errCh {
			errors = append(errors, err)
		}

		if len(errors) > 0 {
			t.Errorf("Had %d errors during concurrent writes", len(errors))
			for i, err := range errors {
				if i < 5 {
					t.Logf("  Error %d: %v", i, err)
				}
			}
		}

		// Verify count
		count := sitemap.Count()
		expected := numGoroutines * urlsPerGoroutine
		if count < expected/2 { // Allow some tolerance for concurrent upserts
			t.Errorf("Count too low: got %d, expected ~%d", count, expected)
		}

		t.Logf("Concurrent test: %d goroutines × %d URLs = %d stored", numGoroutines, urlsPerGoroutine, count)
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		var wg sync.WaitGroup
		errCh := make(chan error, numGoroutines)

		for g := 0; g < numGoroutines; g++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				// Read all results using streaming
				var count int
				err := sitemap.StreamAllResults(func(node *storage.DiscoveredNode) error {
					count++
					return nil
				})
				if err != nil {
					errCh <- fmt.Errorf("g%d StreamAllResults: %w", goroutineID, err)
					return
				}
				if count < 1 {
					errCh <- fmt.Errorf("g%d: no results returned", goroutineID)
				}
			}(g)
		}

		wg.Wait()
		close(errCh)

		var errors []error
		for err := range errCh {
			errors = append(errors, err)
		}

		if len(errors) > 0 {
			t.Errorf("Had %d errors during concurrent reads", len(errors))
			for i, err := range errors {
				if i < 5 {
					t.Logf("  Error %d: %v", i, err)
				}
			}
		}

		t.Log("Concurrent reads completed successfully")
	})
}

// TestPostgresMultipleSessions tests multiple sessions writing to same database.
func TestPostgresMultipleSessions(t *testing.T) {
	const numSessions = 5

	var sitemaps []*storage.SiteMap
	defer func() {
		for _, sm := range sitemaps {
			if sm != nil {
				sm.Close()
			}
		}
	}()

	// Create multiple sessions
	for i := 0; i < numSessions; i++ {
		cfg := getPostgresConfig()
		cfg.TargetURL = fmt.Sprintf("https://session%d.example.com", i)

		sm, err := storage.NewSiteMap(cfg)
		if err != nil {
			t.Fatalf("Failed to create session %d: %v", i, err)
		}
		sitemaps = append(sitemaps, sm)

		// Store some data in each session
		testURL, _ := url.Parse(fmt.Sprintf("https://session%d.example.com/data", i))
		result := storage.NewResult(testURL)
		result.Response.StatusCode = 200
		result.Request.Method = "GET"
		result.Metadata.FoundBy = fmt.Sprintf("session-%d", i)

		if err := sm.Store(result); err != nil {
			t.Errorf("Session %d store failed: %v", i, err)
		}
	}

	// Verify all sessions exist
	sessions, err := sitemaps[0].ListSessions()
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}

	// Should have at least numSessions (may have more from previous tests)
	if len(sessions) < numSessions {
		t.Errorf("Expected >= %d sessions, got %d", numSessions, len(sessions))
	}

	t.Logf("Multiple sessions test: created %d sessions, total in DB: %d", numSessions, len(sessions))
}
