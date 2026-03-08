//go:build e2e

package e2e

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
)

// TestCurlParser_ShellScript parses crapi-curl-examples.sh and verifies
// correct extraction, parsing, and database storage of all 44 endpoints.
func TestCurlParser_ShellScript(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "crapi-curl-examples.sh")

	parser := curl.New()
	parser.SetCurlOptions(curl.Options{
		Variables: map[string]string{
			"BASE_URL": "http://localhost:8888",
			"TOKEN":    "test-jwt-token",
		},
	})
	uuids := parseAndStore(t, parser, filePath, repo, "test-curl-shell")

	// The shell script contains 44 curl commands
	require.Len(t, uuids, 44, "shell script should produce 44 requests")

	// Query all records from DB
	qb := database.NewQueryBuilder(db, database.QueryFilters{
		ScanUUID: "test-curl-shell",
	})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 44)

	// Count methods
	methodCounts := make(map[string]int)
	for _, rec := range records {
		methodCounts[rec.Method]++

		// Every record must have basic fields populated
		assert.NotEmpty(t, rec.Method, "method should not be empty")
		assert.NotEmpty(t, rec.Path, "path should not be empty")
		assert.NotEmpty(t, rec.RawRequest, "raw request should not be empty")
		assert.NotEmpty(t, rec.RequestHash, "request hash should not be empty")
	}

	// Verify method distribution
	assert.True(t, methodCounts["POST"] > 0, "expected POST requests")
	assert.True(t, methodCounts["GET"] > 0, "expected GET requests")
	assert.True(t, methodCounts["PUT"] > 0, "expected PUT requests")
	assert.True(t, methodCounts["DELETE"] > 0, "expected DELETE requests")

	// Verify specific endpoints exist
	pathMethodPairs := make(map[string]string) // path -> method
	for _, rec := range records {
		pathMethodPairs[rec.Path] = rec.Method
	}

	// Verify some key paths and methods
	signupPath := findRecordByPathContains(records, "/identity/api/auth/signup")
	require.NotNil(t, signupPath, "expected signup endpoint")
	assert.Equal(t, "POST", signupPath.Method)

	dashboardPath := findRecordByPathContains(records, "/identity/api/v2/user/dashboard")
	require.NotNil(t, dashboardPath, "expected dashboard endpoint")
	assert.Equal(t, "GET", dashboardPath.Method)

	// Verify POST requests have body content
	postWithBody := 0
	for _, rec := range records {
		if rec.Method == "POST" && len(rec.RequestBody) > 0 {
			postWithBody++
		}
	}
	assert.True(t, postWithBody > 0, "some POST requests should have body content")

	// Verify records can be queried by hostname
	hostRecords, err := repo.GetRecordsByHostname(ctx, database.DefaultProjectUUID, "localhost", 100)
	require.NoError(t, err)
	assert.True(t, len(hostRecords) > 0, "expected records with hostname=localhost")
}

// TestCurlParser_Markdown parses crapi-curl-examples.md and verifies
// correct extraction from fenced code blocks and database storage.
func TestCurlParser_Markdown(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "crapi-curl-examples.md")

	parser := curl.New()
	uuids := parseAndStore(t, parser, filePath, repo, "test-curl-markdown")

	// The markdown file contains 44 curl commands in code blocks
	require.Len(t, uuids, 44, "markdown should produce 44 requests")

	// Query all records
	qb := database.NewQueryBuilder(db, database.QueryFilters{
		ScanUUID: "test-curl-markdown",
	})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 44)

	// Verify {{TOKEN}} placeholders are preserved in raw request
	authCount := 0
	for _, rec := range records {
		rawStr := string(rec.RawRequest)
		if containsStr(rawStr, "{{TOKEN}}") {
			authCount++
		}
	}
	assert.True(t, authCount > 0, "expected some requests to preserve {{TOKEN}} placeholder")

	// Verify query parameters in URLs
	recentPosts := findRecordByPathContains(records, "/community/api/v2/community/posts/recent")
	require.NotNil(t, recentPosts, "expected recent posts endpoint")
	assert.Contains(t, recentPosts.Path, "limit=30")
	assert.Contains(t, recentPosts.Path, "offset=0")

	// Verify hostname and port
	for _, rec := range records {
		assert.Equal(t, "localhost", rec.Hostname)
		assert.Equal(t, 8888, rec.Port)
		assert.Equal(t, "http", rec.Scheme)
	}
}

// TestCurlParser_RawCommands tests parsing individual curl command strings
// and verifying their database representation.
func TestCurlParser_RawCommands(t *testing.T) {
	tests := []struct {
		name           string
		cmd            string
		expectMethod   string
		expectPath     string
		expectHostname string
		expectPort     int
		expectBody     string
		expectHeaders  map[string]string
	}{
		{
			name:           "POST with JSON body",
			cmd:            `curl -X POST http://localhost:8888/workshop/api/mechanic/signup -H 'Content-Type: application/json' -d '{"name":"John","email":"john@workshop.com"}'`,
			expectMethod:   "POST",
			expectPath:     "/workshop/api/mechanic/signup",
			expectHostname: "localhost",
			expectPort:     8888,
			expectBody:     `{"name":"John","email":"john@workshop.com"}`,
		},
		{
			name:           "GET with query params",
			cmd:            `curl -X GET 'http://localhost:8888/workshop/api/mechanic/service_requests?limit=30&offset=0' -H 'Authorization: Bearer testtoken'`,
			expectMethod:   "GET",
			expectPath:     "/workshop/api/mechanic/service_requests",
			expectHostname: "localhost",
			expectPort:     8888,
			expectHeaders:  map[string]string{"Authorization": "Bearer testtoken"},
		},
		{
			name:           "Simple GET",
			cmd:            `curl http://localhost:8888/workshop/api/shop/products`,
			expectMethod:   "GET",
			expectPath:     "/workshop/api/shop/products",
			expectHostname: "localhost",
			expectPort:     8888,
		},
		{
			name:           "PUT with body",
			cmd:            `curl -X PUT http://localhost:8888/workshop/api/shop/orders/1 -H 'Content-Type: application/json' -d '{"quantity":2}'`,
			expectMethod:   "PUT",
			expectPath:     "/workshop/api/shop/orders/1",
			expectHostname: "localhost",
			expectPort:     8888,
			expectBody:     `{"quantity":2}`,
		},
		{
			name:           "DELETE",
			cmd:            `curl -X DELETE http://localhost:8888/identity/api/v2/user/videos/1 -H 'Authorization: Bearer token123'`,
			expectMethod:   "DELETE",
			expectPath:     "/identity/api/v2/user/videos/1",
			expectHostname: "localhost",
			expectPort:     8888,
		},
	}

	_, repo := setupTestDB(t)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := curl.ParseSingleCommand(tt.cmd)
			require.NoError(t, err)
			require.NotNil(t, rr)

			// Verify parsed request
			req := rr.Request()
			assert.Equal(t, tt.expectMethod, req.Method())
			assert.Equal(t, tt.expectHostname, req.Service().Host())
			assert.Equal(t, tt.expectPort, req.Service().Port())

			// Save to DB and verify
			uuid, err := repo.SaveRecord(ctx, rr, "test", database.DefaultProjectUUID)
			require.NoError(t, err)

			rec, err := repo.GetRecordByUUID(ctx, uuid)
			require.NoError(t, err)

			assert.Equal(t, tt.expectMethod, rec.Method)
			assert.Equal(t, tt.expectHostname, rec.Hostname)
			assert.Equal(t, tt.expectPort, rec.Port)
			assert.Contains(t, rec.Path, tt.expectPath)

			if tt.expectBody != "" {
				assert.Equal(t, tt.expectBody, string(rec.RequestBody))
			}

			if tt.expectHeaders != nil {
				for key, val := range tt.expectHeaders {
					headerVals, ok := rec.RequestHeaders[key]
					assert.True(t, ok, "expected header %s", key)
					if ok {
						assert.Contains(t, headerVals, val)
					}
				}
			}
		})
	}
}

// TestCurlParser_DatabaseParameterExtraction verifies that parsed curl requests
// have their parameters correctly extracted when stored in the database.
func TestCurlParser_DatabaseParameterExtraction(t *testing.T) {
	_, repo := setupTestDB(t)
	ctx := context.Background()

	t.Run("POST with JSON body parameters", func(t *testing.T) {
		cmd := `curl -X POST http://localhost:8888/api/signup -H 'Content-Type: application/json' -d '{"email":"test@example.com","name":"Test User","password":"secret123"}'`
		rr, err := curl.ParseSingleCommand(cmd)
		require.NoError(t, err)

		uuid, err := repo.SaveRecord(ctx, rr, "test", database.DefaultProjectUUID)
		require.NoError(t, err)

		rec, err := repo.GetRecordByUUID(ctx, uuid)
		require.NoError(t, err)

		// JSON body should produce parameters
		assert.True(t, len(rec.Parameters) > 0, "POST with JSON body should have parameters extracted")

		// Check that parameter names are present
		paramNames := make(map[string]bool)
		for _, p := range rec.Parameters {
			paramNames[p.Name] = true
		}
		assert.True(t, paramNames["email"], "expected 'email' parameter")
		assert.True(t, paramNames["name"], "expected 'name' parameter")
		assert.True(t, paramNames["password"], "expected 'password' parameter")
	})

	t.Run("GET with URL query parameters", func(t *testing.T) {
		cmd := `curl -X GET 'http://localhost:8888/api/search?limit=30&offset=0&query=test'`
		rr, err := curl.ParseSingleCommand(cmd)
		require.NoError(t, err)

		uuid, err := repo.SaveRecord(ctx, rr, "test", database.DefaultProjectUUID)
		require.NoError(t, err)

		rec, err := repo.GetRecordByUUID(ctx, uuid)
		require.NoError(t, err)

		// URL query params should produce parameters
		assert.True(t, len(rec.Parameters) > 0, "GET with query params should have parameters extracted")

		paramNames := make(map[string]bool)
		for _, p := range rec.Parameters {
			paramNames[p.Name] = true
		}
		assert.True(t, paramNames["limit"], "expected 'limit' parameter")
		assert.True(t, paramNames["offset"], "expected 'offset' parameter")
		assert.True(t, paramNames["query"], "expected 'query' parameter")
	})
}

// Helper functions

// findRecordByPathContains finds the first record whose path contains the given substring.
func findRecordByPathContains(records []*database.HTTPRecord, pathSubstr string) *database.HTTPRecord {
	for _, rec := range records {
		if containsStr(rec.Path, pathSubstr) {
			return rec
		}
	}
	return nil
}

// containsStr checks if s contains substr (simple wrapper for readability).
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstr(s, substr))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
