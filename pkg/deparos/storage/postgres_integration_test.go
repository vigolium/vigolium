//go:build integration

package storage

import (
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestPostgresIntegration tests the PostgreSQL driver with a real database.
// Run with: go test -tags=integration -v ./pkg/storage/...
//
// Environment variables:
//
//	POSTGRES_HOST (default: localhost)
//	POSTGRES_PORT (default: 6432)
//	POSTGRES_USER (default: deparos_app)
//	POSTGRES_PASSWORD (default: deparos_app_password)
//	POSTGRES_DB (default: deparos)
func TestPostgresIntegration(t *testing.T) {
	host := getEnv("POSTGRES_HOST", "localhost")
	port := getEnvInt("POSTGRES_PORT", 6432)
	user := getEnv("POSTGRES_USER", "deparos_app")
	password := getEnv("POSTGRES_PASSWORD", "deparos_app_password")
	database := getEnv("POSTGRES_DB", "deparos")

	t.Logf("Connecting to PostgreSQL at %s:%d as %s", host, port, user)

	cfg := PostgresConfig(host, database, user, password)
	cfg.Database.Port = port
	cfg.TargetURL = "https://example.com"

	// Create sitemap
	sitemap, err := NewSiteMap(cfg)
	if err != nil {
		t.Fatalf("Failed to create sitemap: %v", err)
	}
	defer sitemap.Close()

	t.Logf("Created session DB ID: %d", sitemap.SessionDBID())

	// Test 1: Store a result
	t.Run("Store", func(t *testing.T) {
		testURL, _ := url.Parse("https://example.com/test/path")
		result := NewResult(testURL)
		result.Response.StatusCode = 200
		result.Request.Method = "GET"
		result.Metadata.FoundBy = "test"

		if err := sitemap.Store(result); err != nil {
			t.Fatalf("Failed to store result: %v", err)
		}
		t.Log("Stored result successfully")
	})

	// Test 2: Check node retrieval via Get
	t.Run("Get_Exists", func(t *testing.T) {
		testURL, _ := url.Parse("https://example.com/test/path")
		node, err := sitemap.Get(testURL)
		if err != nil || node == nil {
			t.Error("Expected URL to exist")
		}
		t.Log("Get_Exists check passed")
	})

	// Test 3: Get result
	t.Run("Get", func(t *testing.T) {
		testURL, _ := url.Parse("https://example.com/test/path")
		node, err := sitemap.Get(testURL)
		if err != nil {
			t.Fatalf("Failed to get node: %v", err)
		}
		if node == nil {
			t.Error("Expected node to not be nil")
		}
		t.Logf("Got node: %s", node.URL())
	})

	// Test 4: Count
	t.Run("Count", func(t *testing.T) {
		count := sitemap.Count()
		if count < 1 {
			t.Errorf("Expected count >= 1, got %d", count)
		}
		t.Logf("Count: %d", count)
	})

	// Test 5: Store multiple results (connection pool test)
	t.Run("StoreMultiple", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			testURL, _ := url.Parse(fmt.Sprintf("https://example.com/path%d", i))
			result := NewResult(testURL)
			result.Response.StatusCode = 200
			result.Request.Method = "GET"
			result.Metadata.FoundBy = "test"
			if err := sitemap.Store(result); err != nil {
				t.Fatalf("Failed to store result %d: %v", i, err)
			}
		}
		t.Log("Stored 10 results successfully")
	})

	// Test 6: StreamAllResults
	t.Run("StreamAllResults", func(t *testing.T) {
		var count int
		err := sitemap.StreamAllResults(func(node *TreeNode) error {
			count++
			return nil
		})
		if err != nil {
			t.Fatalf("Failed to stream all results: %v", err)
		}
		t.Logf("Total results: %d", count)
	})

	// Test 7: List sessions
	t.Run("ListSessions", func(t *testing.T) {
		sessions, err := sitemap.ListSessions()
		if err != nil {
			t.Fatalf("Failed to list sessions: %v", err)
		}
		if len(sessions) < 1 {
			t.Error("Expected at least 1 session")
		}
		t.Logf("Sessions: %d", len(sessions))
	})

	t.Log("All PostgreSQL integration tests passed!")
}

// TestPostgresConnectionPool tests connection pool behavior with concurrent operations.
func TestPostgresConnectionPool(t *testing.T) {
	host := getEnv("POSTGRES_HOST", "localhost")
	port := getEnvInt("POSTGRES_PORT", 6432)
	user := getEnv("POSTGRES_USER", "deparos_app")
	password := getEnv("POSTGRES_PASSWORD", "deparos_app_password")
	database := getEnv("POSTGRES_DB", "deparos")

	cfg := PostgresConfig(host, database, user, password)
	cfg.Database.Port = port
	cfg.TargetURL = "https://pooltest.com"

	sitemap, err := NewSiteMap(cfg)
	if err != nil {
		t.Fatalf("Failed to create sitemap: %v", err)
	}
	defer sitemap.Close()

	// Concurrent writes
	t.Run("ConcurrentWrites", func(t *testing.T) {
		done := make(chan bool, 20)
		errCh := make(chan error, 20)

		for i := 0; i < 20; i++ {
			go func(idx int) {
				testURL, _ := url.Parse(fmt.Sprintf("https://pooltest.com/concurrent/%d", idx))
				result := NewResult(testURL)
				result.Response.StatusCode = 200
				result.Request.Method = "GET"
				result.Metadata.FoundBy = "concurrent-test"
				if err := sitemap.Store(result); err != nil {
					errCh <- err
				}
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 20; i++ {
			select {
			case <-done:
			case err := <-errCh:
				t.Errorf("Concurrent write error: %v", err)
			case <-time.After(30 * time.Second):
				t.Fatal("Timeout waiting for concurrent writes")
			}
		}

		t.Log("20 concurrent writes completed successfully")
	})
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
