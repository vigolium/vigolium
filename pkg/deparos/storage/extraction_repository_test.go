package storage

import (
	"context"
	"database/sql"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
)

// setupTestDB creates an in-memory SQLite database for testing.
func setupTestDB(t *testing.T) *bun.DB {
	t.Helper()

	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	db := bun.NewDB(sqldb, sqlitedialect.New())

	// Create table via DDL
	ctx := context.Background()
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS extractions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_node_id INTEGER NOT NULL,
		session_id INTEGER NOT NULL,
		hash TEXT NOT NULL,
		source INTEGER NOT NULL DEFAULT 0,
		source_sub INTEGER NOT NULL DEFAULT 0,
		hostname TEXT NOT NULL DEFAULT '',
		url TEXT NOT NULL,
		method TEXT NOT NULL DEFAULT 'GET',
		body TEXT,
		content_type TEXT,
		headers TEXT,
		cookies TEXT,
		created_at INTEGER NOT NULL
	)`)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	_, err = db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_ext_hash ON extractions(hash)`)
	if err != nil {
		t.Fatalf("failed to create index: %v", err)
	}

	return db
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", rawURL, err)
	}
	return u
}

// helper to query last inserted extraction
func queryLastExtraction(t *testing.T, db *bun.DB) ExtractionModel {
	t.Helper()
	ctx := context.Background()
	var result ExtractionModel
	err := db.NewSelect().Model(&result).OrderExpr("id DESC").Limit(1).Scan(ctx)
	if err != nil {
		t.Fatalf("failed to query result: %v", err)
	}
	return result
}

// helper to query all extractions ordered by id
func queryAllExtractions(t *testing.T, db *bun.DB) []ExtractionModel {
	t.Helper()
	ctx := context.Background()
	var results []ExtractionModel
	err := db.NewSelect().Model(&results).Order("id").Scan(ctx)
	if err != nil {
		t.Fatalf("failed to query results: %v", err)
	}
	return results
}

// helper to count extractions
func countExtractions(t *testing.T, db *bun.DB) int {
	t.Helper()
	ctx := context.Background()
	count, err := db.NewSelect().Model((*ExtractionModel)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("failed to count: %v", err)
	}
	return count
}

// ============ Spider Link Tests ============

func TestStoreSpiderLink(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	tests := []struct {
		name         string
		sourceNodeID int64
		sessionID    int64
		link         *spider.DiscoveredLink
		wantURL      string
		wantSource   uint8
		wantSub      uint8
		wantMethod   string
	}{
		{
			name:         "HTML attribute link",
			sourceNodeID: 1,
			sessionID:    100,
			link: &spider.DiscoveredLink{
				URL:        mustParseURL(t, "https://example.com/page"),
				SourceType: spider.SourceHTMLAttribute,
			},
			wantURL:    "https://example.com/page",
			wantSource: uint8(SourceSpider),
			wantSub:    uint8(spider.SourceHTMLAttribute),
			wantMethod: "GET",
		},
		{
			name:         "JavaScript extracted link",
			sourceNodeID: 2,
			sessionID:    100,
			link: &spider.DiscoveredLink{
				URL:        mustParseURL(t, "https://api.example.com/v1/users"),
				SourceType: spider.SourceJavaScript,
			},
			wantURL:    "https://api.example.com/v1/users",
			wantSource: uint8(SourceSpider),
			wantSub:    uint8(spider.SourceJavaScript),
			wantMethod: "GET",
		},
		{
			name:         "Comment extracted link",
			sourceNodeID: 3,
			sessionID:    101,
			link: &spider.DiscoveredLink{
				URL:        mustParseURL(t, "https://example.com/admin/config"),
				SourceType: spider.SourceComment,
			},
			wantURL:    "https://example.com/admin/config",
			wantSource: uint8(SourceSpider),
			wantSub:    uint8(spider.SourceComment),
			wantMethod: "GET",
		},
		{
			name:         "Robots.txt link",
			sourceNodeID: 4,
			sessionID:    101,
			link: &spider.DiscoveredLink{
				URL:        mustParseURL(t, "https://example.com/secret/path"),
				SourceType: spider.SourceRobotsTxt,
			},
			wantURL:    "https://example.com/secret/path",
			wantSource: uint8(SourceSpider),
			wantSub:    uint8(spider.SourceRobotsTxt),
			wantMethod: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.StoreSpiderLink(tt.sourceNodeID, tt.sessionID, tt.link)
			if err != nil {
				t.Fatalf("StoreSpiderLink() error = %v", err)
			}

			result := queryLastExtraction(t, db)

			if result.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", result.URL, tt.wantURL)
			}
			if result.Source != tt.wantSource {
				t.Errorf("Source = %d, want %d", result.Source, tt.wantSource)
			}
			if result.SourceSub != tt.wantSub {
				t.Errorf("SourceSub = %d, want %d", result.SourceSub, tt.wantSub)
			}
			if result.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", result.Method, tt.wantMethod)
			}
			if result.SourceNodeID != tt.sourceNodeID {
				t.Errorf("SourceNodeID = %d, want %d", result.SourceNodeID, tt.sourceNodeID)
			}
			if result.SessionID != tt.sessionID {
				t.Errorf("SessionID = %d, want %d", result.SessionID, tt.sessionID)
			}
		})
	}
}

func TestStoreSpiderLink_NilInputs(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Test nil link
	err := repo.StoreSpiderLink(1, 1, nil)
	if err != nil {
		t.Errorf("StoreSpiderLink(nil) should not return error, got %v", err)
	}

	// Test link with nil URL
	err = repo.StoreSpiderLink(1, 1, &spider.DiscoveredLink{URL: nil})
	if err != nil {
		t.Errorf("StoreSpiderLink(nil URL) should not return error, got %v", err)
	}

	// Verify nothing was stored
	count := countExtractions(t, db)
	if count != 0 {
		t.Errorf("expected 0 records, got %d", count)
	}
}

func TestBatchStoreSpiderLinks(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	links := []*spider.DiscoveredLink{
		{URL: mustParseURL(t, "https://example.com/a"), SourceType: spider.SourceHTMLAttribute},
		{URL: mustParseURL(t, "https://example.com/b"), SourceType: spider.SourceJavaScript},
		nil, // Should be skipped
		{URL: nil, SourceType: spider.SourceComment}, // Should be skipped
		{URL: mustParseURL(t, "https://example.com/c"), SourceType: spider.SourceHTTPHeader},
	}

	err := repo.BatchStoreSpiderLinks(10, 200, links)
	if err != nil {
		t.Fatalf("BatchStoreSpiderLinks() error = %v", err)
	}

	results := queryAllExtractions(t, db)

	if len(results) != 3 {
		t.Fatalf("expected 3 records, got %d", len(results))
	}

	expectedURLs := []string{
		"https://example.com/a",
		"https://example.com/b",
		"https://example.com/c",
	}
	expectedSubs := []uint8{
		uint8(spider.SourceHTMLAttribute),
		uint8(spider.SourceJavaScript),
		uint8(spider.SourceHTTPHeader),
	}

	for i, result := range results {
		if result.URL != expectedURLs[i] {
			t.Errorf("results[%d].URL = %q, want %q", i, result.URL, expectedURLs[i])
		}
		if result.SourceSub != expectedSubs[i] {
			t.Errorf("results[%d].SourceSub = %d, want %d", i, result.SourceSub, expectedSubs[i])
		}
		if result.SourceNodeID != 10 {
			t.Errorf("results[%d].SourceNodeID = %d, want 10", i, result.SourceNodeID)
		}
		if result.SessionID != 200 {
			t.Errorf("results[%d].SessionID = %d, want 200", i, result.SessionID)
		}
		if result.Source != uint8(SourceSpider) {
			t.Errorf("results[%d].Source = %d, want %d", i, result.Source, uint8(SourceSpider))
		}
	}
}

func TestBatchStoreSpiderLinks_EmptySlice(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	err := repo.BatchStoreSpiderLinks(1, 1, []*spider.DiscoveredLink{})
	if err != nil {
		t.Errorf("BatchStoreSpiderLinks([]) should not return error, got %v", err)
	}

	err = repo.BatchStoreSpiderLinks(1, 1, nil)
	if err != nil {
		t.Errorf("BatchStoreSpiderLinks(nil) should not return error, got %v", err)
	}
}

// ============ JSScan Tests ============

func TestStoreJSScanRequest(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	tests := []struct {
		name         string
		sourceNodeID int64
		sessionID    int64
		req          *jsscan.ExtractedRequest
		wantURL      string
		wantMethod   string
		wantBody     string
		wantHeaders  string
		wantCookies  string
	}{
		{
			name:         "Simple GET request",
			sourceNodeID: 1,
			sessionID:    100,
			req: &jsscan.ExtractedRequest{
				URL:    "https://api.example.com/users",
				Method: "GET",
			},
			wantURL:    "https://api.example.com/users",
			wantMethod: "GET",
			wantBody:   "",
		},
		{
			name:         "GET with params merged into URL",
			sourceNodeID: 2,
			sessionID:    100,
			req: &jsscan.ExtractedRequest{
				URL:    "https://api.example.com/search",
				Method: "GET",
				Params: "q=test&page=1",
			},
			wantURL:    "https://api.example.com/search?q=test&page=1",
			wantMethod: "GET",
			wantBody:   "",
		},
		{
			name:         "GET with existing query + params",
			sourceNodeID: 3,
			sessionID:    100,
			req: &jsscan.ExtractedRequest{
				URL:    "https://api.example.com/search?sort=asc",
				Method: "GET",
				Params: "q=test",
			},
			wantURL:    "https://api.example.com/search?sort=asc&q=test",
			wantMethod: "GET",
			wantBody:   "",
		},
		{
			name:         "POST with body",
			sourceNodeID: 4,
			sessionID:    101,
			req: &jsscan.ExtractedRequest{
				URL:    "https://api.example.com/login",
				Method: "POST",
				Body:   `{"username":"admin","password":"secret"}`,
			},
			wantURL:    "https://api.example.com/login",
			wantMethod: "POST",
			wantBody:   `{"username":"admin","password":"secret"}`,
		},
		{
			name:         "Request with headers",
			sourceNodeID: 5,
			sessionID:    101,
			req: &jsscan.ExtractedRequest{
				URL:     "https://api.example.com/data",
				Method:  "GET",
				Headers: []string{"Authorization: Bearer token123", "X-Custom: value"},
			},
			wantURL:     "https://api.example.com/data",
			wantMethod:  "GET",
			wantHeaders: `["Authorization: Bearer token123","X-Custom: value"]`,
		},
		{
			name:         "Request with cookies",
			sourceNodeID: 6,
			sessionID:    101,
			req: &jsscan.ExtractedRequest{
				URL:     "https://api.example.com/profile",
				Method:  "GET",
				Cookies: []string{"session=abc123", "user=john"},
			},
			wantURL:     "https://api.example.com/profile",
			wantMethod:  "GET",
			wantCookies: `["session=abc123","user=john"]`,
		},
		{
			name:         "Full request with all fields",
			sourceNodeID: 7,
			sessionID:    102,
			req: &jsscan.ExtractedRequest{
				URL:     "https://api.example.com/api/v2/create",
				Method:  "POST",
				Params:  "version=2",
				Body:    `{"name":"test"}`,
				Headers: []string{"Content-Type: application/json"},
				Cookies: []string{"auth=xyz"},
			},
			wantURL:     "https://api.example.com/api/v2/create?version=2",
			wantMethod:  "POST",
			wantBody:    `{"name":"test"}`,
			wantHeaders: `["Content-Type: application/json"]`,
			wantCookies: `["auth=xyz"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.StoreJSScanRequest(tt.sourceNodeID, tt.sessionID, tt.req)
			if err != nil {
				t.Fatalf("StoreJSScanRequest() error = %v", err)
			}

			result := queryLastExtraction(t, db)

			if result.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", result.URL, tt.wantURL)
			}
			if result.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", result.Method, tt.wantMethod)
			}
			if result.Body.String != tt.wantBody {
				t.Errorf("Body = %q, want %q", result.Body.String, tt.wantBody)
			}
			if result.Source != uint8(SourceJSScan) {
				t.Errorf("Source = %d, want %d", result.Source, uint8(SourceJSScan))
			}
			if tt.wantHeaders != "" && result.Headers.String != tt.wantHeaders {
				t.Errorf("Headers = %q, want %q", result.Headers.String, tt.wantHeaders)
			}
			if tt.wantCookies != "" && result.Cookies.String != tt.wantCookies {
				t.Errorf("Cookies = %q, want %q", result.Cookies.String, tt.wantCookies)
			}
		})
	}
}

func TestStoreJSScanRequest_NilInput(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	err := repo.StoreJSScanRequest(1, 1, nil)
	if err != nil {
		t.Errorf("StoreJSScanRequest(nil) should not return error, got %v", err)
	}

	count := countExtractions(t, db)
	if count != 0 {
		t.Errorf("expected 0 records, got %d", count)
	}
}

func TestBatchStoreJSScanRequests(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	reqs := []jsscan.ExtractedRequest{
		{URL: "https://api.example.com/a", Method: "GET"},
		{URL: "https://api.example.com/b", Method: "POST", Body: "data=test"},
		{URL: "https://api.example.com/c", Method: "PUT", Params: "id=1"},
	}

	err := repo.BatchStoreJSScanRequests(20, 300, reqs)
	if err != nil {
		t.Fatalf("BatchStoreJSScanRequests() error = %v", err)
	}

	results := queryAllExtractions(t, db)

	if len(results) != 3 {
		t.Fatalf("expected 3 records, got %d", len(results))
	}

	expected := []struct {
		url    string
		method string
		body   string
	}{
		{"https://api.example.com/a", "GET", ""},
		{"https://api.example.com/b", "POST", "data=test"},
		{"https://api.example.com/c?id=1", "PUT", ""},
	}

	for i, result := range results {
		if result.URL != expected[i].url {
			t.Errorf("results[%d].URL = %q, want %q", i, result.URL, expected[i].url)
		}
		if result.Method != expected[i].method {
			t.Errorf("results[%d].Method = %q, want %q", i, result.Method, expected[i].method)
		}
		if result.Body.String != expected[i].body {
			t.Errorf("results[%d].Body = %q, want %q", i, result.Body.String, expected[i].body)
		}
		if result.Source != uint8(SourceJSScan) {
			t.Errorf("results[%d].Source = %d, want %d", i, result.Source, uint8(SourceJSScan))
		}
	}
}

// ============ Form Tests ============

func TestStoreFormRequest(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	tests := []struct {
		name            string
		sourceNodeID    int64
		sessionID       int64
		form            *spider.FormRequest
		wantURL         string
		wantMethod      string
		wantBody        string
		wantContentType string
	}{
		{
			name:         "GET form with query params in URL",
			sourceNodeID: 1,
			sessionID:    100,
			form: &spider.FormRequest{
				URL:    mustParseURL(t, "https://example.com/search?q=test&page=1"),
				Method: "GET",
			},
			wantURL:    "https://example.com/search?q=test&page=1",
			wantMethod: "GET",
			wantBody:   "",
		},
		{
			name:         "POST form with urlencoded body",
			sourceNodeID: 2,
			sessionID:    100,
			form: &spider.FormRequest{
				URL:         mustParseURL(t, "https://example.com/login"),
				Method:      "POST",
				Body:        "username=admin&password=secret",
				ContentType: "application/x-www-form-urlencoded",
			},
			wantURL:         "https://example.com/login",
			wantMethod:      "POST",
			wantBody:        "username=admin&password=secret",
			wantContentType: "application/x-www-form-urlencoded",
		},
		{
			name:         "POST form with multipart",
			sourceNodeID: 3,
			sessionID:    101,
			form: &spider.FormRequest{
				URL:         mustParseURL(t, "https://example.com/upload"),
				Method:      "POST",
				Body:        "--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata\r\n--boundary--",
				ContentType: "multipart/form-data; boundary=boundary",
			},
			wantURL:         "https://example.com/upload",
			wantMethod:      "POST",
			wantBody:        "--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata\r\n--boundary--",
			wantContentType: "multipart/form-data; boundary=boundary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.StoreFormRequest(tt.sourceNodeID, tt.sessionID, tt.form)
			if err != nil {
				t.Fatalf("StoreFormRequest() error = %v", err)
			}

			result := queryLastExtraction(t, db)

			if result.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", result.URL, tt.wantURL)
			}
			if result.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", result.Method, tt.wantMethod)
			}
			if result.Body.String != tt.wantBody {
				t.Errorf("Body = %q, want %q", result.Body.String, tt.wantBody)
			}
			if result.ContentType.String != tt.wantContentType {
				t.Errorf("ContentType = %q, want %q", result.ContentType.String, tt.wantContentType)
			}
			if result.Source != uint8(SourceForm) {
				t.Errorf("Source = %d, want %d", result.Source, uint8(SourceForm))
			}
		})
	}
}

func TestStoreFormRequest_NilInputs(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Test nil form
	err := repo.StoreFormRequest(1, 1, nil)
	if err != nil {
		t.Errorf("StoreFormRequest(nil) should not return error, got %v", err)
	}

	// Test form with nil URL
	err = repo.StoreFormRequest(1, 1, &spider.FormRequest{URL: nil})
	if err != nil {
		t.Errorf("StoreFormRequest(nil URL) should not return error, got %v", err)
	}

	count := countExtractions(t, db)
	if count != 0 {
		t.Errorf("expected 0 records, got %d", count)
	}
}

func TestBatchStoreFormRequests(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	forms := []*spider.FormRequest{
		{URL: mustParseURL(t, "https://example.com/form1?a=1"), Method: "GET"},
		nil, // Should be skipped
		{URL: mustParseURL(t, "https://example.com/form2"), Method: "POST", Body: "b=2", ContentType: "application/x-www-form-urlencoded"},
		{URL: nil}, // Should be skipped
		{URL: mustParseURL(t, "https://example.com/form3"), Method: "POST", Body: "c=3"},
	}

	err := repo.BatchStoreFormRequests(30, 400, forms)
	if err != nil {
		t.Fatalf("BatchStoreFormRequests() error = %v", err)
	}

	results := queryAllExtractions(t, db)

	if len(results) != 3 {
		t.Fatalf("expected 3 records, got %d", len(results))
	}

	expected := []struct {
		url         string
		method      string
		body        string
		contentType string
	}{
		{"https://example.com/form1?a=1", "GET", "", ""},
		{"https://example.com/form2", "POST", "b=2", "application/x-www-form-urlencoded"},
		{"https://example.com/form3", "POST", "c=3", ""},
	}

	for i, result := range results {
		if result.URL != expected[i].url {
			t.Errorf("results[%d].URL = %q, want %q", i, result.URL, expected[i].url)
		}
		if result.Method != expected[i].method {
			t.Errorf("results[%d].Method = %q, want %q", i, result.Method, expected[i].method)
		}
		if result.Body.String != expected[i].body {
			t.Errorf("results[%d].Body = %q, want %q", i, result.Body.String, expected[i].body)
		}
		if result.ContentType.String != expected[i].contentType {
			t.Errorf("results[%d].ContentType = %q, want %q", i, result.ContentType.String, expected[i].contentType)
		}
	}
}

// ============ Query Tests ============

func TestGetBySession(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Insert test data for session 100
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/a"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/b", Method: "GET"}))
	require.NoError(t, repo.StoreFormRequest(1, 100, &spider.FormRequest{URL: mustParseURL(t, "https://example.com/c"), Method: "POST"}))

	// Insert test data for session 200
	require.NoError(t, repo.StoreSpiderLink(2, 200, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/x"), SourceType: spider.SourceJavaScript}))

	// Query session 100
	results, err := repo.GetBySession(100)
	if err != nil {
		t.Fatalf("GetBySession() error = %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results for session 100, got %d", len(results))
	}

	// Query session 200
	results, err = repo.GetBySession(200)
	if err != nil {
		t.Fatalf("GetBySession() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result for session 200, got %d", len(results))
	}
	if results[0].URL != "https://example.com/x" {
		t.Errorf("URL = %q, want %q", results[0].URL, "https://example.com/x")
	}

	// Query non-existent session
	results, err = repo.GetBySession(999)
	if err != nil {
		t.Fatalf("GetBySession() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for session 999, got %d", len(results))
	}
}

func TestGetBySource(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Insert mixed data
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/spider1"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/spider2"), SourceType: spider.SourceJavaScript}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/jsscan1", Method: "GET"}))
	require.NoError(t, repo.StoreFormRequest(1, 100, &spider.FormRequest{URL: mustParseURL(t, "https://example.com/form1"), Method: "POST"}))

	// Get spider links
	spiderLinks, err := repo.GetBySource(100, SourceSpider)
	if err != nil {
		t.Fatalf("GetBySource(SourceSpider) error = %v", err)
	}
	if len(spiderLinks) != 2 {
		t.Errorf("expected 2 spider links, got %d", len(spiderLinks))
	}

	// Get jsscan requests
	jsscanReqs, err := repo.GetBySource(100, SourceJSScan)
	if err != nil {
		t.Fatalf("GetBySource(SourceJSScan) error = %v", err)
	}
	if len(jsscanReqs) != 1 {
		t.Errorf("expected 1 jsscan request, got %d", len(jsscanReqs))
	}
	if jsscanReqs[0].URL != "https://example.com/jsscan1" {
		t.Errorf("URL = %q, want %q", jsscanReqs[0].URL, "https://example.com/jsscan1")
	}

	// Get forms
	forms, err := repo.GetBySource(100, SourceForm)
	if err != nil {
		t.Fatalf("GetBySource(SourceForm) error = %v", err)
	}
	if len(forms) != 1 {
		t.Errorf("expected 1 form, got %d", len(forms))
	}
}

func TestGetByNode(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Insert data from different nodes
	require.NoError(t, repo.StoreSpiderLink(10, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/from10a"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreSpiderLink(10, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/from10b"), SourceType: spider.SourceJavaScript}))
	require.NoError(t, repo.StoreSpiderLink(20, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/from20"), SourceType: spider.SourceComment}))

	// Get extractions from node 10
	results, err := repo.GetByNode(10)
	if err != nil {
		t.Fatalf("GetByNode() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results from node 10, got %d", len(results))
	}

	// Get extractions from node 20
	results, err = repo.GetByNode(20)
	if err != nil {
		t.Fatalf("GetByNode() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result from node 20, got %d", len(results))
	}
	if results[0].URL != "https://example.com/from20" {
		t.Errorf("URL = %q, want %q", results[0].URL, "https://example.com/from20")
	}
}

func TestCountBySource(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Insert test data
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/s1"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/s2"), SourceType: spider.SourceJavaScript}))
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/s3"), SourceType: spider.SourceComment}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/j1", Method: "GET"}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/j2", Method: "POST"}))
	require.NoError(t, repo.StoreFormRequest(1, 100, &spider.FormRequest{URL: mustParseURL(t, "https://example.com/f1"), Method: "POST"}))

	counts, err := repo.CountBySource(100)
	if err != nil {
		t.Fatalf("CountBySource() error = %v", err)
	}

	if counts[SourceSpider] != 3 {
		t.Errorf("SourceSpider count = %d, want 3", counts[SourceSpider])
	}
	if counts[SourceJSScan] != 2 {
		t.Errorf("SourceJSScan count = %d, want 2", counts[SourceJSScan])
	}
	if counts[SourceForm] != 1 {
		t.Errorf("SourceForm count = %d, want 1", counts[SourceForm])
	}
}

func TestGetByURLPattern(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Insert test data
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/api/users"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/api/posts"), SourceType: spider.SourceJavaScript}))
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/admin/config"), SourceType: spider.SourceComment}))

	// Search for "api"
	results, err := repo.GetByURLPattern(100, "api")
	if err != nil {
		t.Fatalf("GetByURLPattern() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results matching 'api', got %d", len(results))
	}

	// Search for "admin"
	results, err = repo.GetByURLPattern(100, "admin")
	if err != nil {
		t.Fatalf("GetByURLPattern() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result matching 'admin', got %d", len(results))
	}
	if results[0].URL != "https://example.com/admin/config" {
		t.Errorf("URL = %q, want %q", results[0].URL, "https://example.com/admin/config")
	}

	// Search for non-existent pattern
	results, err = repo.GetByURLPattern(100, "nonexistent")
	if err != nil {
		t.Fatalf("GetByURLPattern() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results matching 'nonexistent', got %d", len(results))
	}
}

func TestGetByMethod(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Insert mixed methods
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/get1"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/post1", Method: "POST"}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/put1", Method: "PUT"}))
	require.NoError(t, repo.StoreFormRequest(1, 100, &spider.FormRequest{URL: mustParseURL(t, "https://example.com/post2"), Method: "POST"}))

	// Get GET requests
	getResults, err := repo.GetByMethod(100, "GET")
	if err != nil {
		t.Fatalf("GetByMethod(GET) error = %v", err)
	}
	if len(getResults) != 1 {
		t.Errorf("expected 1 GET request, got %d", len(getResults))
	}

	// Get POST requests
	postResults, err := repo.GetByMethod(100, "POST")
	if err != nil {
		t.Fatalf("GetByMethod(POST) error = %v", err)
	}
	if len(postResults) != 2 {
		t.Errorf("expected 2 POST requests, got %d", len(postResults))
	}

	// Get PUT requests
	putResults, err := repo.GetByMethod(100, "PUT")
	if err != nil {
		t.Fatalf("GetByMethod(PUT) error = %v", err)
	}
	if len(putResults) != 1 {
		t.Errorf("expected 1 PUT request, got %d", len(putResults))
	}
}

func TestGetSpiderLinks(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/link1"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/link2"), SourceType: spider.SourceJavaScript}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/jsscan", Method: "GET"}))

	links, err := repo.GetSpiderLinks(100)
	if err != nil {
		t.Fatalf("GetSpiderLinks() error = %v", err)
	}
	if len(links) != 2 {
		t.Errorf("expected 2 spider links, got %d", len(links))
	}
}

func TestGetJSScanRequests(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/spider"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/js1", Method: "GET"}))
	require.NoError(t, repo.StoreJSScanRequest(1, 100, &jsscan.ExtractedRequest{URL: "https://example.com/js2", Method: "POST"}))

	reqs, err := repo.GetJSScanRequests(100)
	if err != nil {
		t.Fatalf("GetJSScanRequests() error = %v", err)
	}
	if len(reqs) != 2 {
		t.Errorf("expected 2 jsscan requests, got %d", len(reqs))
	}
}

func TestGetForms(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/spider"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreFormRequest(1, 100, &spider.FormRequest{URL: mustParseURL(t, "https://example.com/form1"), Method: "GET"}))
	require.NoError(t, repo.StoreFormRequest(1, 100, &spider.FormRequest{URL: mustParseURL(t, "https://example.com/form2"), Method: "POST"}))

	forms, err := repo.GetForms(100)
	if err != nil {
		t.Fatalf("GetForms() error = %v", err)
	}
	if len(forms) != 2 {
		t.Errorf("expected 2 forms, got %d", len(forms))
	}
}

// ============ Delete Tests ============

func TestDeleteBySession(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Insert data for two sessions
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/s100a"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreSpiderLink(1, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/s100b"), SourceType: spider.SourceJavaScript}))
	require.NoError(t, repo.StoreSpiderLink(1, 200, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/s200"), SourceType: spider.SourceComment}))

	// Delete session 100
	err := repo.DeleteBySession(100)
	if err != nil {
		t.Fatalf("DeleteBySession() error = %v", err)
	}

	// Verify session 100 is deleted
	results, _ := repo.GetBySession(100)
	if len(results) != 0 {
		t.Errorf("expected 0 results for session 100 after delete, got %d", len(results))
	}

	// Verify session 200 still exists
	results, _ = repo.GetBySession(200)
	if len(results) != 1 {
		t.Errorf("expected 1 result for session 200, got %d", len(results))
	}
}

func TestDeleteByNode(t *testing.T) {
	db := setupTestDB(t)
	repo := NewExtractionRepository(db)

	// Insert data from two nodes
	require.NoError(t, repo.StoreSpiderLink(10, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/n10a"), SourceType: spider.SourceHTMLAttribute}))
	require.NoError(t, repo.StoreSpiderLink(10, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/n10b"), SourceType: spider.SourceJavaScript}))
	require.NoError(t, repo.StoreSpiderLink(20, 100, &spider.DiscoveredLink{URL: mustParseURL(t, "https://example.com/n20"), SourceType: spider.SourceComment}))

	// Delete node 10
	err := repo.DeleteByNode(10)
	if err != nil {
		t.Fatalf("DeleteByNode() error = %v", err)
	}

	// Verify node 10 is deleted
	results, _ := repo.GetByNode(10)
	if len(results) != 0 {
		t.Errorf("expected 0 results for node 10 after delete, got %d", len(results))
	}

	// Verify node 20 still exists
	results, _ = repo.GetByNode(20)
	if len(results) != 1 {
		t.Errorf("expected 1 result for node 20, got %d", len(results))
	}
}

// ============ Edge Cases ============

func TestExtractionSource_String(t *testing.T) {
	tests := []struct {
		source ExtractionSource
		want   string
	}{
		{SourceSpider, "spider"},
		{SourceJSScan, "jsscan"},
		{SourceForm, "form"},
		{ExtractionSource(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.source.String()
		if got != tt.want {
			t.Errorf("ExtractionSource(%d).String() = %q, want %q", tt.source, got, tt.want)
		}
	}
}

func TestNullString(t *testing.T) {
	tests := []struct {
		input     string
		wantValid bool
	}{
		{"", false},
		{"value", true},
		{"   ", true}, // Whitespace is still valid
	}

	for _, tt := range tests {
		result := nullString(tt.input)
		if result.Valid != tt.wantValid {
			t.Errorf("nullString(%q).Valid = %v, want %v", tt.input, result.Valid, tt.wantValid)
		}
		if result.String != tt.input {
			t.Errorf("nullString(%q).String = %q, want %q", tt.input, result.String, tt.input)
		}
	}
}
