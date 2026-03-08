//go:build e2e

package e2e

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"github.com/vigolium/vigolium/pkg/input/formats/burpraw"
	"github.com/vigolium/vigolium/pkg/input/formats/burpxml"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
)

// testdataDir returns the absolute path to test/testdata/sample-inputs/
func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "testdata", "sample-inputs")
}

// setupTestDB creates an in-memory SQLite database for testing.
func setupTestDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        ":memory:",
			BusyTimeout: 5000,
			JournalMode: "MEMORY",
			Synchronous: "OFF",
			CacheSize:   10000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { db.Close() })
	return db, database.NewRepository(db)
}

// parseAndStore parses a file with the given format and stores all results in the DB.
// Returns the list of saved record UUIDs.
func parseAndStore(t *testing.T, format formats.Format, filePath string, repo *database.Repository, _ string) []string {
	t.Helper()
	ctx := context.Background()

	var uuids []string
	err := format.Parse(filePath, func(rr *httpmsg.HttpRequestResponse) bool {
		uuid, saveErr := repo.SaveRecord(ctx, rr, "test", database.DefaultProjectUUID)
		require.NoError(t, saveErr, "failed to save record")
		uuids = append(uuids, uuid)
		return true
	})
	require.NoError(t, err, "failed to parse file")

	return uuids
}

// TestParseSwagger_JuiceShop verifies parsing a Swagger/OpenAPI 3.0 YAML spec.
func TestParseSwagger_JuiceShop(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "juice-shop-swagger.yaml")

	// Configure OpenAPI parser
	// The spec has a relative server URL (/b2b/v2), so we must supply a BaseURL
	parser := openapi.New()
	parser.SetOptions(formats.InputFormatOptions{})
	parser.SetOpenAPIOptions(openapi.Options{
		BaseURL:              "http://localhost:3000",
		DefaultFallbackValue: "1",
	})

	uuids := parseAndStore(t, parser, filePath, repo, "test-swagger-juiceshop")

	// The spec has 1 endpoint: POST /orders
	require.NotEmpty(t, uuids, "expected at least one parsed request")

	// Verify records in DB
	qb := database.NewQueryBuilder(db, database.QueryFilters{
		ScanUUID: "test-swagger-juiceshop",
	})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, len(uuids))

	// Verify the POST /orders endpoint
	found := false
	for _, rec := range records {
		assert.NotEmpty(t, rec.Method)
		assert.NotEmpty(t, rec.Path)
		assert.NotEmpty(t, rec.RawRequest)
		assert.NotEmpty(t, rec.RequestHash)

		if rec.Method == "POST" {
			found = true
			assert.Contains(t, rec.Path, "/orders")
			assert.True(t, len(rec.Parameters) > 0, "POST /orders should have parameters")
		}
	}
	assert.True(t, found, "expected POST /orders endpoint")
}

// TestParsePostman_VAmPI verifies parsing a Postman v2.1 collection (unwrapped format).
func TestParsePostman_VAmPI(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "vampi-postman_collection.json")

	// Configure Postman parser
	parser := postman.New()
	parser.SetPostmanOptions(postman.Options{
		BaseURL: "http://localhost:5000",
	})

	uuids := parseAndStore(t, parser, filePath, repo, "test-postman-vampi")

	// VAmPI collection has 14 requests
	require.Len(t, uuids, 14, "VAmPI collection should produce 14 requests")

	// Query all records
	qb := database.NewQueryBuilder(db, database.QueryFilters{
		ScanUUID: "test-postman-vampi",
	})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 14)

	// Count methods
	methodCounts := make(map[string]int)
	for _, rec := range records {
		methodCounts[rec.Method]++

		// Every record must have basic fields populated
		assert.NotEmpty(t, rec.Method, "method should not be empty")
		assert.NotEmpty(t, rec.Path, "path should not be empty")
		assert.NotEmpty(t, rec.Hostname, "hostname should not be empty")
		assert.NotEmpty(t, rec.RawRequest, "raw request should not be empty")
		assert.NotEmpty(t, rec.RequestHash, "request hash should not be empty")
		assert.Equal(t, "localhost", rec.Hostname)
	}

	// Verify method distribution
	assert.Equal(t, 8, methodCounts["GET"], "expected 8 GET requests")
	assert.Equal(t, 3, methodCounts["POST"], "expected 3 POST requests")
	assert.Equal(t, 2, methodCounts["PUT"], "expected 2 PUT requests")
	assert.Equal(t, 1, methodCounts["DELETE"], "expected 1 DELETE request")

	// Verify some specific paths exist
	paths := make(map[string]bool)
	for _, rec := range records {
		paths[rec.Path] = true
	}
	assert.True(t, paths["/createdb"], "expected /createdb path")
	assert.True(t, paths["/users/v1"], "expected /users/v1 path")
	assert.True(t, paths["/books/v1"], "expected /books/v1 path")

	// Verify POST requests have parameters (JSON body)
	for _, rec := range records {
		if rec.Method == "POST" || rec.Method == "PUT" {
			assert.NotEmpty(t, rec.RequestBody, "POST/PUT request %s should have a body", rec.Path)
		}
	}

	// Verify request headers are preserved
	for _, rec := range records {
		if rec.RequestHeaders != nil {
			// Check that Accept header is present in most requests
			if vals, ok := rec.RequestHeaders["Accept"]; ok {
				assert.Contains(t, vals, "application/json")
			}
		}
	}
}

// TestParsePostman_crAPI verifies parsing a Postman v2.1 collection (wrapped format).
func TestParsePostman_crAPI(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "crAPI.postman_collection.json")

	// Configure Postman parser
	// The collection uses {{url}} for most requests and {{url_mail}} for 4 mail-search requests
	parser := postman.New()
	parser.SetPostmanOptions(postman.Options{
		BaseURL: "http://localhost:8888",
		Variables: map[string]string{
			"url_mail": "http://localhost:8888",
		},
	})

	uuids := parseAndStore(t, parser, filePath, repo, "test-postman-crapi")

	// crAPI collection has 49 requests
	require.Len(t, uuids, 49, "crAPI collection should produce 49 requests")

	// Query all records
	qb := database.NewQueryBuilder(db, database.QueryFilters{
		ScanUUID: "test-postman-crapi",
	})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 49)

	// Count methods
	methodCounts := make(map[string]int)
	for _, rec := range records {
		methodCounts[rec.Method]++

		// Every record must have basic fields
		assert.NotEmpty(t, rec.Method)
		assert.NotEmpty(t, rec.Path)
		assert.NotEmpty(t, rec.Hostname)
		assert.NotEmpty(t, rec.RawRequest)
		assert.NotEmpty(t, rec.RequestHash)
		assert.Equal(t, "localhost", rec.Hostname)
	}

	// Verify method distribution
	assert.Equal(t, 26, methodCounts["POST"], "expected 26 POST requests")
	assert.Equal(t, 20, methodCounts["GET"], "expected 20 GET requests")
	assert.Equal(t, 1, methodCounts["PUT"], "expected 1 PUT request")
	assert.Equal(t, 2, methodCounts["DELETE"], "expected 2 DELETE requests")

	// Verify some key paths exist
	pathFound := make(map[string]bool)
	for _, rec := range records {
		pathFound[rec.Path] = true
	}
	assert.True(t, pathFound["/identity/api/auth/signup"], "expected /identity/api/auth/signup path")
	assert.True(t, pathFound["/identity/api/auth/login"], "expected /identity/api/auth/login path")

	// Verify POST requests have body content
	postWithBody := 0
	for _, rec := range records {
		if rec.Method == "POST" && len(rec.RequestBody) > 0 {
			postWithBody++
		}
	}
	assert.True(t, postWithBody > 0, "some POST requests should have body content")

	// Verify headers are preserved (User-Agent, Content-Type, Accept)
	headersFound := 0
	for _, rec := range records {
		if rec.RequestHeaders != nil {
			if _, ok := rec.RequestHeaders["Content-Type"]; ok {
				headersFound++
			}
		}
	}
	assert.True(t, headersFound > 0, "some records should have Content-Type headers")
}

// TestParseBurpRaw_Request1 verifies parsing a raw Burp request file (crunchbase POST).
func TestParseBurpRaw_Request1(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "burp-request-1.txt")

	parser := burpraw.New()
	uuids := parseAndStore(t, parser, filePath, repo, "test-burpraw-1")

	require.Len(t, uuids, 1, "burp raw file should produce exactly 1 request")

	qb := database.NewQueryBuilder(db, database.QueryFilters{ScanUUID: "test-burpraw-1"})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 1)

	rec := records[0]
	assert.Equal(t, "POST", rec.Method)
	assert.Equal(t, "www.crunchbase.com", rec.Hostname)
	assert.Equal(t, "/v4/cb/events/clientapp", rec.Path)
	assert.Equal(t, "https", rec.Scheme)
	assert.NotEmpty(t, rec.RawRequest)
	assert.Contains(t, string(rec.RequestBody), "events")
	assert.NotNil(t, rec.RequestHeaders)
	if vals, ok := rec.RequestHeaders["Content-Type"]; ok {
		assert.Contains(t, vals, "application/json")
	}
}

// TestParseBurpRaw_Request2 verifies parsing a raw Burp request file (infura POST).
func TestParseBurpRaw_Request2(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "burp-request-2.txt")

	parser := burpraw.New()
	uuids := parseAndStore(t, parser, filePath, repo, "test-burpraw-2")

	require.Len(t, uuids, 1, "burp raw file should produce exactly 1 request")

	qb := database.NewQueryBuilder(db, database.QueryFilters{ScanUUID: "test-burpraw-2"})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 1)

	rec := records[0]
	assert.Equal(t, "POST", rec.Method)
	assert.Equal(t, "mainnet.infura.io", rec.Hostname)
	assert.True(t, strings.HasPrefix(rec.Path, "/v3/"), "path should start with /v3/")
	assert.Equal(t, "https", rec.Scheme)
	assert.Contains(t, string(rec.RequestBody), "jsonrpc")
	assert.NotNil(t, rec.RequestHeaders)
	if vals, ok := rec.RequestHeaders["Content-Type"]; ok {
		assert.Contains(t, vals, "application/json")
	}
}

// TestParseBurpXML_RawFile verifies parsing a Burp XML file with raw (non-base64) requests.
func TestParseBurpXML_RawFile(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "burp-file-raw.burp")

	parser := burpxml.New()
	uuids := parseAndStore(t, parser, filePath, repo, "test-burpxml-raw")

	require.Len(t, uuids, 54, "burp XML raw file should produce 54 requests")

	qb := database.NewQueryBuilder(db, database.QueryFilters{ScanUUID: "test-burpxml-raw"})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 54)

	methodCounts := make(map[string]int)
	for _, rec := range records {
		methodCounts[rec.Method]++

		assert.Equal(t, "grep.app", rec.Hostname)
		assert.Equal(t, "https", rec.Scheme)
		assert.Equal(t, 443, rec.Port)
		assert.NotEmpty(t, rec.RawRequest)
		assert.NotEmpty(t, rec.RequestHash)

		if rec.Method == "POST" {
			assert.NotEmpty(t, rec.RequestBody, "POST request should have body: %s", rec.Path)
		}
	}

	assert.Equal(t, 45, methodCounts["GET"], "expected 45 GET requests")
	assert.Equal(t, 9, methodCounts["POST"], "expected 9 POST requests")
}

// TestParseBurpXML_Base64File verifies parsing a Burp XML file with base64-encoded requests.
func TestParseBurpXML_Base64File(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()
	filePath := filepath.Join(testdataDir(), "burp-file-base64.burp")

	parser := burpxml.New()
	uuids := parseAndStore(t, parser, filePath, repo, "test-burpxml-b64")

	require.Len(t, uuids, 54, "burp XML base64 file should produce 54 requests")

	qb := database.NewQueryBuilder(db, database.QueryFilters{ScanUUID: "test-burpxml-b64"})
	records, err := qb.Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 54)

	methodCounts := make(map[string]int)
	for _, rec := range records {
		methodCounts[rec.Method]++

		assert.Equal(t, "grep.app", rec.Hostname)
		assert.Equal(t, "https", rec.Scheme)
		assert.Equal(t, 443, rec.Port)
		assert.NotEmpty(t, rec.RawRequest)
		assert.NotEmpty(t, rec.RequestHash)

		if rec.Method == "POST" {
			assert.NotEmpty(t, rec.RequestBody, "POST request should have body: %s", rec.Path)
		}
	}

	assert.Equal(t, 45, methodCounts["GET"], "expected 45 GET requests")
	assert.Equal(t, 9, methodCounts["POST"], "expected 9 POST requests")
}

// TestParseAndStore_AllFormats parses all valid sample files into a single DB
// and verifies aggregate counts.
func TestParseAndStore_AllFormats(t *testing.T) {
	db, repo := setupTestDB(t)
	ctx := context.Background()

	// 1. Parse Juice Shop Swagger (OpenAPI) — spec has relative server, needs BaseURL
	swaggerParser := openapi.New()
	swaggerParser.SetOpenAPIOptions(openapi.Options{
		BaseURL:              "http://localhost:3000",
		DefaultFallbackValue: "1",
	})
	swaggerUUIDs := parseAndStore(t, swaggerParser, filepath.Join(testdataDir(), "juice-shop-swagger.yaml"), repo, "scan-swagger")

	// 2. Parse VAmPI Postman collection
	vampiParser := postman.New()
	vampiParser.SetPostmanOptions(postman.Options{
		BaseURL: "http://localhost:5000",
	})
	vampiUUIDs := parseAndStore(t, vampiParser, filepath.Join(testdataDir(), "vampi-postman_collection.json"), repo, "scan-vampi")

	// 3. Parse crAPI Postman collection — needs url_mail variable
	crapiParser := postman.New()
	crapiParser.SetPostmanOptions(postman.Options{
		BaseURL: "http://localhost:8888",
		Variables: map[string]string{
			"url_mail": "http://localhost:8888",
		},
	})
	crapiUUIDs := parseAndStore(t, crapiParser, filepath.Join(testdataDir(), "crAPI.postman_collection.json"), repo, "scan-crapi")

	// 4. Parse Burp raw request files
	burpRawParser := burpraw.New()
	burpRaw1UUIDs := parseAndStore(t, burpRawParser, filepath.Join(testdataDir(), "burp-request-1.txt"), repo, "scan-burpraw1")
	burpRaw2UUIDs := parseAndStore(t, burpRawParser, filepath.Join(testdataDir(), "burp-request-2.txt"), repo, "scan-burpraw2")

	// 5. Parse Burp XML session file (raw)
	burpXMLParser := burpxml.New()
	burpXMLUUIDs := parseAndStore(t, burpXMLParser, filepath.Join(testdataDir(), "burp-file-raw.burp"), repo, "scan-burpxml")

	t.Logf("Parsed: swagger=%d, vampi=%d, crapi=%d, burpraw1=%d, burpraw2=%d, burpxml=%d",
		len(swaggerUUIDs), len(vampiUUIDs), len(crapiUUIDs),
		len(burpRaw1UUIDs), len(burpRaw2UUIDs), len(burpXMLUUIDs))

	// Verify aggregate count
	totalQB := database.NewQueryBuilder(db, database.QueryFilters{})
	totalCount, err := totalQB.Count(ctx)
	require.NoError(t, err)

	expectedTotal := int64(len(swaggerUUIDs) + len(vampiUUIDs) + len(crapiUUIDs) +
		len(burpRaw1UUIDs) + len(burpRaw2UUIDs) + len(burpXMLUUIDs))
	assert.Equal(t, expectedTotal, totalCount, "total records should match sum of all parsed files")

	// Verify records can be queried by scan_id
	for _, scanID := range []string{"scan-swagger", "scan-vampi", "scan-crapi", "scan-burpraw1", "scan-burpraw2", "scan-burpxml"} {
		qb := database.NewQueryBuilder(db, database.QueryFilters{ScanUUID: scanID})
		count, err := qb.Count(ctx)
		require.NoError(t, err)
		assert.True(t, count > 0, "expected records for scan_id=%s", scanID)
	}

	// Verify records can be queried by hostname
	vampiRecords, err := repo.GetRecordsByHostname(ctx, database.DefaultProjectUUID, "localhost", 100)
	require.NoError(t, err)
	assert.True(t, len(vampiRecords) > 0, "expected records with hostname=localhost")

	// Verify records can be queried by method
	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		qb := database.NewQueryBuilder(db, database.QueryFilters{Methods: []string{method}})
		count, err := qb.Count(ctx)
		require.NoError(t, err)
		assert.True(t, count > 0, "expected records with method=%s", method)
	}
}
