package storage

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create ephemeral storage for tests
func newTestSiteMap(t *testing.T) *SiteMap {
	cfg := DefaultConfig()
	cfg.TargetURL = "https://example.com"
	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	return sm
}

func TestNewSiteMap(t *testing.T) {
	sm := newTestSiteMap(t)
	assert.NotNil(t, sm)
	assert.Equal(t, 0, sm.Count())
	assert.NotZero(t, sm.SessionDBID())
}

func TestNewSiteMap_Persistent(t *testing.T) {
	// Create temp file for persistent storage
	tmpFile := t.TempDir() + "/test.db"

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"
	cfg.SessionName = "test-session"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	assert.NotNil(t, sm)

	sessionDBID := sm.SessionDBID()
	assert.NotZero(t, sessionDBID)

	// Store a result
	u, _ := url.Parse("https://example.com/test")
	result := NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
		Build()

	err = sm.Store(result)
	require.NoError(t, err)

	// Close and reopen - will create NEW session ID (new behavior)
	_ = sm.Close()

	sm2, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	// Data persists - check via Get
	node, err := sm2.Get(u)
	assert.NoError(t, err)
	assert.NotNil(t, node, "URL should exist in database")

	// StreamResultsBySessionName returns nodes from all sessions with same name
	var nodes []*DiscoveredNode
	err = sm2.StreamResultsBySessionName("test-session", func(node *DiscoveredNode) error {
		nodes = append(nodes, node)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, nodes, 1, "Should have 1 node in session 'test-session'")
}

func TestSiteMap_Store(t *testing.T) {
	sm := newTestSiteMap(t)

	u, _ := url.Parse("https://example.com/api/v1/users")
	result := NewResultBuilder().
		WithURL(u).
		WithRequest("GET", map[string]string{"User-Agent": "test"}, nil).
		WithResponse(200, nil, []byte("[]"), 2, "application/json", "", "", 0, 0).
		WithMetadata("custom-files", 2, time.Now()).
		Build()

	err := sm.Store(result)
	assert.NoError(t, err)

	// Verify storage
	assert.Equal(t, 1, sm.Count())

	// Retrieve and verify
	node, err := sm.Get(u)
	assert.NoError(t, err)
	assert.NotNil(t, node)
	assert.Equal(t, u.String(), node.URL().String())
	assert.Equal(t, "GET", node.Request().Method)
	assert.Equal(t, 200, node.Response().StatusCode)
	// Depth is now path depth (3 segments: api, v1, users)
	assert.Equal(t, uint16(3), node.Metadata().Depth)
}

func TestSiteMap_TreeStructure(t *testing.T) {
	sm := newTestSiteMap(t)

	// Store multiple URLs with hierarchical paths
	urls := []string{
		"https://example.com/",
		"https://example.com/api",
		"https://example.com/api/v1",
		"https://example.com/api/v1/users",
		"https://example.com/admin/login",
	}

	for _, urlStr := range urls {
		u, _ := url.Parse(urlStr)
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
			Build()

		err := sm.Store(result)
		require.NoError(t, err)
	}

	// Flat storage: each URL is stored as a single node
	// All 5 URLs are stored: /, /api, /api/v1, /api/v1/users, /admin/login
	assert.Equal(t, 5, sm.Count())

	// Check api node exists via Get
	apiURL, _ := url.Parse("https://example.com/api")
	apiNode, err := sm.Get(apiURL)
	assert.NoError(t, err)
	assert.NotNil(t, apiNode)
}

func TestSiteMap_Deduplication(t *testing.T) {
	sm := newTestSiteMap(t)

	u, _ := url.Parse("https://example.com/test")

	// Store first result
	result1 := NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("test1"), 5, "text/html", "", "", 0, 0).
		WithMetadata("task1", 1, time.Now()).
		Build()

	err := sm.Store(result1)
	assert.NoError(t, err)
	assert.Equal(t, 1, sm.Count())

	// Store duplicate with same semantic structure (same hash)
	// Hash = scheme|host|method|status|server|path|queryNames|bodyKeys
	// Both have GET|200||/test|| → same hash
	result2 := NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("test2"), 5, "text/html", "", "", 0, 0).
		WithMetadata("task2", 2, time.Now()).
		Build()

	err = sm.Store(result2)
	assert.NoError(t, err)
	assert.Equal(t, 1, sm.Count()) // Still 1 URL

	// With hash-based dedup, within-session duplicates are skipped entirely
	// (no session_nodes entry created for duplicates within same session)
	node, err := sm.Get(u)
	assert.NoError(t, err)
	assert.Equal(t, "task1", node.Metadata().FoundBy) // Original FoundBy preserved
}

// TestSameHashFirstSession_AllDiscovered verifies that within a single session,
// URLs with the same semantic hash produce only "discovered" actions (not "updated").
// This tests the fix for the bug where within-session duplicates were marked as "updated".
func TestSameHashFirstSession_AllDiscovered(t *testing.T) {
	sm := newTestSiteMap(t)

	// Store /api/users?id=1 (hash based on queryNames="id")
	u1, _ := url.Parse("https://example.com/api/users?id=1")
	result1 := NewResultBuilder().
		WithURL(u1).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("user 1"), 6, "application/json", "", "", 0, 0).
		WithMetadata("wordlist", 2, time.Now()).
		Build()

	err := sm.Store(result1)
	require.NoError(t, err)

	// Store /api/users?id=2 (same semantic hash - same queryNames="id")
	u2, _ := url.Parse("https://example.com/api/users?id=2")
	result2 := NewResultBuilder().
		WithURL(u2).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("user 2"), 6, "application/json", "", "", 0, 0).
		WithMetadata("wordlist", 2, time.Now()).
		Build()

	err = sm.Store(result2)
	require.NoError(t, err)

	// Should have 1 node (deduplicated by semantic hash)
	assert.Equal(t, 1, sm.Count())

	// Verify no "updated" actions in first session - all should be "discovered"
	ctx := context.Background()
	var sessionNodes []SessionNodeModel
	err = sm.bunDB.NewSelect().Model(&sessionNodes).
		Where("session_id = ?", sm.sessionDBID).
		Scan(ctx)
	require.NoError(t, err)

	assert.Len(t, sessionNodes, 1, "Should have exactly 1 session-node entry")
	assert.Equal(t, "discovered", sessionNodes[0].Action,
		"First session should only have 'discovered' actions, not 'updated'")
}

func TestSiteMap_ConcurrentInserts(t *testing.T) {
	sm := newTestSiteMap(t)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			u, _ := url.Parse(fmt.Sprintf("https://example.com/test%d", id))
			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
				Build()

			err := sm.Store(result)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Verify all URLs stored
	assert.Equal(t, numGoroutines, sm.Count())

	for i := 0; i < numGoroutines; i++ {
		u, _ := url.Parse(fmt.Sprintf("https://example.com/test%d", i))
		node, _ := sm.Get(u)
		assert.NotNil(t, node, "URL %s should exist", u.String())
	}
}

func TestSiteMap_ConcurrentDuplicates(t *testing.T) {
	sm := newTestSiteMap(t)

	// Same URL stored concurrently
	u, _ := url.Parse("https://example.com/test")

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
				WithMetadata(fmt.Sprintf("task%d", id), uint16(id), time.Now()).
				Build()

			_ = sm.Store(result)
		}(i)
	}

	wg.Wait()

	// Should only have 1 URL
	assert.Equal(t, 1, sm.Count())
}

func TestSiteMap_Get_NotFound(t *testing.T) {
	sm := newTestSiteMap(t)

	u, _ := url.Parse("https://example.com/notfound")
	node, err := sm.Get(u)

	assert.Error(t, err)
	assert.Nil(t, node)
}

func TestSiteMap_WalkFiles(t *testing.T) {
	sm := newTestSiteMap(t)

	// Store multiple URLs
	urls := []string{
		"https://example.com/api/v1/users",
		"https://example.com/api/v1/products",
		"https://example.com/admin/login",
	}

	for _, urlStr := range urls {
		u, _ := url.Parse(urlStr)
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
			Build()

		err := sm.Store(result)
		require.NoError(t, err)
	}

	// WalkFiles and count (flat storage - all are file nodes)
	fileCount := 0
	err := sm.WalkFiles(func(node *DiscoveredNode) error {
		fileCount++
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 3, fileCount)
}

func TestSiteMap_InvalidInput(t *testing.T) {
	sm := newTestSiteMap(t)

	// Nil result
	err := sm.Store(nil)
	assert.Error(t, err)

	// Result with nil URL
	result := &Result{}
	err = sm.Store(result)
	assert.Error(t, err)

	// Get with nil URL
	node, err := sm.Get(nil)
	assert.Error(t, err)
	assert.Nil(t, node)

}

func TestSiteMap_SessionTracking(t *testing.T) {
	// Create persistent storage
	tmpFile := t.TempDir() + "/session_test.db"

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	// First session (anonymous - no session name)
	sm1, err := NewSiteMap(cfg)
	require.NoError(t, err)

	session1DBID := sm1.SessionDBID()
	assert.NotZero(t, session1DBID)

	// Store some URLs
	for i := range 3 {
		u, _ := url.Parse(fmt.Sprintf("https://example.com/session1/path%d", i))
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
			Build()

		err := sm1.Store(result)
		require.NoError(t, err)
	}

	_ = sm1.Close()

	// Second session (anonymous - no session name)
	sm2, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	session2DBID := sm2.SessionDBID()
	assert.NotZero(t, session2DBID)
	assert.NotEqual(t, session1DBID, session2DBID, "Anonymous sessions should have different DB IDs")

	// Store more URLs (some new, some existing)
	for i := range 5 {
		u, _ := url.Parse(fmt.Sprintf("https://example.com/session1/path%d", i)) // 0,1,2 already exist
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
			Build()

		err := sm2.Store(result)
		require.NoError(t, err)
	}

	// List sessions
	sessions, err := sm2.ListSessions()
	require.NoError(t, err)
	assert.Len(t, sessions, 2)

	// Get new discoveries (should be URLs 3 and 4 only)
	newDiscoveries, err := sm2.GetNewDiscoveries()
	require.NoError(t, err)
	assert.Len(t, newDiscoveries, 2)
}

// TestSiteMap_NodeTypes verifies Burp-style node type classification:
// - Root (to): scheme://host
// - Directory (gul): path segment without response
// - DirectoryCrawled (aak): "/" node with response (trailing slash URLs)
// - File (d3z): leaf node with response, no trailing slash
//
// Tree structure for /admin/ and /api/users:
//
//	https://example.com/
//	├── admin           (Directory - no response for /admin itself)
//	│   └── /           (DirectoryCrawled - response for /admin/)
//	└── api             (Directory - no response)
//	    └── users       (File - response for /api/users)
func TestSiteMap_NodeTypes(t *testing.T) {
	sm := newTestSiteMap(t)

	// Store a file (no trailing slash, with response) → File (d3z)
	fileURL, _ := url.Parse("https://example.com/api/users")
	fileResult := NewResultBuilder().
		WithURL(fileURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("[]"), 2, "application/json", "", "", 0, 0).
		WithMetadata("wordlist", 2, time.Now()).
		Build()
	err := sm.Store(fileResult)
	require.NoError(t, err)

	// Store a directory (trailing slash, with response)
	dirURL, _ := url.Parse("https://example.com/admin/")
	dirResult := NewResultBuilder().
		WithURL(dirURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("admin listing"), 13, "text/html", "", "", 0, 0).
		WithMetadata("spider", 1, time.Now()).
		Build()
	err = sm.Store(dirResult)
	require.NoError(t, err)

	// Verify file node type (flat storage - single record per URL)
	fileNode, err := sm.Get(fileURL)
	require.NoError(t, err)
	assert.Equal(t, NodeTypeFile, fileNode.NodeType(), "URL without trailing slash should be File")

	// Verify trailing slash URL stored as separate node
	dirNode, err := sm.Get(dirURL)
	require.NoError(t, err)
	assert.NotNil(t, dirNode)
	assert.Equal(t, 200, dirNode.Response().StatusCode)
	assert.Equal(t, NodeTypeDirectory, dirNode.NodeType(), "URL with trailing slash should be Directory")
}

// TestSiteMap_NodeTypeCanHaveChildren verifies file nodes cannot have children
func TestSiteMap_NodeTypeCanHaveChildren(t *testing.T) {
	sm := newTestSiteMap(t)

	// Store a file first
	fileURL, _ := url.Parse("https://example.com/api/users")
	fileResult := NewResultBuilder().
		WithURL(fileURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("[]"), 2, "application/json", "", "", 0, 0).
		Build()
	err := sm.Store(fileResult)
	require.NoError(t, err)

	// Now store a "child" of the file - this should create a new path, not a child
	childURL, _ := url.Parse("https://example.com/api/users/123")
	childResult := NewResultBuilder().
		WithURL(childURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("user 123"), 8, "application/json", "", "", 0, 0).
		Build()
	err = sm.Store(childResult)
	require.NoError(t, err)

	// Both should exist as separate nodes
	fileNode, _ := sm.Get(fileURL)
	assert.NotNil(t, fileNode, "fileURL should exist")
	childNode, _ := sm.Get(childURL)
	assert.NotNil(t, childNode, "childURL should exist")
}

// TestSiteMap_DirectoryCrawledCanHaveChildren verifies DirectoryCrawled nodes can have children
//
// Burp-style tree for /api/ and /api/users:
//
//	api (Directory)
//	├── /      (DirectoryCrawled - response for /api/)
//	└── users  (File - response for /api/users)
//
// Note: "users" is a sibling of "/", not a child. Both are children of "api".
func TestSiteMap_DirectoryCrawledCanHaveChildren(t *testing.T) {
	sm := newTestSiteMap(t)

	// Store a directory with trailing slash
	dirURL, _ := url.Parse("https://example.com/api/")
	dirResult := NewResultBuilder().
		WithURL(dirURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("directory listing"), 17, "text/html", "", "", 0, 0).
		Build()
	err := sm.Store(dirResult)
	require.NoError(t, err)

	// Store a file under the same parent (/api/users is sibling of /)
	fileURL, _ := url.Parse("https://example.com/api/users")
	fileResult := NewResultBuilder().
		WithURL(fileURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("[]"), 2, "application/json", "", "", 0, 0).
		Build()
	err = sm.Store(fileResult)
	require.NoError(t, err)

	// Verify /api/ exists
	dirNode, err := sm.Get(dirURL)
	require.NoError(t, err)
	assert.NotNil(t, dirNode)

	// Verify /api/users exists
	usersURL, _ := url.Parse("https://example.com/api/users")
	usersNode, err := sm.Get(usersURL)
	require.NoError(t, err)
	assert.NotNil(t, usersNode)
}

// TestSiteMap_SeparateNodesForTrailingSlash verifies /admin and /admin/ are separate nodes
// This is critical for Burp-style behavior where these URLs may have different responses
func TestSiteMap_SeparateNodesForTrailingSlash(t *testing.T) {
	sm := newTestSiteMap(t)

	// Store /admin (no trailing slash) with one response
	adminURL, _ := url.Parse("https://example.com/admin")
	adminResult := NewResultBuilder().
		WithURL(adminURL).
		WithRequest("GET", nil, nil).
		WithResponse(301, nil, []byte("redirect to /admin/"), 19, "text/html", "", "", 0, 0).
		Build()
	err := sm.Store(adminResult)
	require.NoError(t, err)

	// Store /admin/ (with trailing slash) with different response
	adminSlashURL, _ := url.Parse("https://example.com/admin/")
	adminSlashResult := NewResultBuilder().
		WithURL(adminSlashURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("admin dashboard"), 15, "text/html", "", "", 0, 0).
		Build()
	err = sm.Store(adminSlashResult)
	require.NoError(t, err)

	// Verify they have different node types
	adminNode, err := sm.Get(adminURL)
	require.NoError(t, err)
	assert.Equal(t, NodeTypeFile, adminNode.NodeType(), "/admin should be File")
	assert.Equal(t, 301, adminNode.Response().StatusCode)

	adminSlashNode, err := sm.Get(adminSlashURL)
	require.NoError(t, err)
	assert.NotNil(t, adminSlashNode)
	assert.Equal(t, 200, adminSlashNode.Response().StatusCode)
}

// TestSiteMap_SecretFindingsPersistence verifies secret findings are stored and retrieved correctly
func TestSiteMap_SecretFindingsPersistence(t *testing.T) {
	// Use persistent storage to test full save/load cycle
	tmpFile := t.TempDir() + "/secret_test.db"

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)

	// Create result with secret findings
	u, _ := url.Parse("https://example.com/api/config.js")
	result := NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte(`{"aws_key": "AKIAIOSFODNN7EXAMPLE"}`), 37, "application/javascript", "", "", 0, 0).
		WithMetadata("spider", 2, time.Now()).
		Build()

	// Add secret findings
	result.SecretFindings = []SecretFinding{
		{
			RuleID:     "aws-access-key",
			RuleName:   "AWS Access Key ID",
			Snippet:    "AKIAIOSFODNN7EXAMPLE",
			Confidence: "high",
			Validated:  true,
		},
		{
			RuleID:     "mongodb-uri",
			RuleName:   "MongoDB Connection URI",
			Snippet:    "mongodb://admin:secret@localhost:27017",
			Confidence: "medium",
			Validated:  false,
		},
	}

	err = sm.Store(result)
	require.NoError(t, err)

	// Close and reopen to force reload from database
	_ = sm.Close()

	sm2, err := OpenSiteMapDSN(tmpFile)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	// Get node and verify findings
	node, err := sm2.Get(u)
	require.NoError(t, err)
	require.NotNil(t, node)

	findings := node.SecretFindings()
	require.Len(t, findings, 2, "Should have 2 secret findings")

	// Verify first finding
	assert.Equal(t, "aws-access-key", findings[0].RuleID)
	assert.Equal(t, "AWS Access Key ID", findings[0].RuleName)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", findings[0].Snippet)
	assert.Equal(t, "high", findings[0].Confidence)
	assert.True(t, findings[0].Validated)

	// Verify second finding
	assert.Equal(t, "mongodb-uri", findings[1].RuleID)
	assert.Equal(t, "MongoDB Connection URI", findings[1].RuleName)
	assert.Equal(t, "mongodb://admin:secret@localhost:27017", findings[1].Snippet)
	assert.Equal(t, "medium", findings[1].Confidence)
	assert.False(t, findings[1].Validated)
}

// TestSiteMap_SecretFindingsStreamQuery verifies secret findings are included in streaming queries
func TestSiteMap_SecretFindingsStreamQuery(t *testing.T) {
	sm := newTestSiteMap(t)

	// Create result with secret findings
	u, _ := url.Parse("https://example.com/secrets.json")
	result := NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte(`{"secret": "leaked"}`), 20, "application/json", "", "", 0, 0).
		WithMetadata("wordlist", 1, time.Now()).
		Build()

	result.SecretFindings = []SecretFinding{
		{
			RuleID:     "generic-secret",
			RuleName:   "Generic Secret",
			Snippet:    "leaked",
			Confidence: "low",
			Validated:  false,
		},
	}

	err := sm.Store(result)
	require.NoError(t, err)

	// Test StreamAllResults (used by export)
	var nodes []*DiscoveredNode
	err = sm.StreamAllResults(func(node *DiscoveredNode) error {
		nodes = append(nodes, node)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, nodes, 1)

	findings := nodes[0].SecretFindings()
	require.Len(t, findings, 1, "Streaming query should include secret findings")
	assert.Equal(t, "generic-secret", findings[0].RuleID)
}

// TestSiteMap_QueryStringPreservation verifies query strings are stored and retrieved correctly
func TestSiteMap_QueryStringPreservation(t *testing.T) {
	testCases := []struct {
		name      string
		urlStr    string
		wantQuery string
		wantPath  string
	}{
		{
			name:      "simple query params",
			urlStr:    "https://example.com/api/users?id=123&sort=asc",
			wantQuery: "id=123&sort=asc",
			wantPath:  "/api/users",
		},
		{
			name:      "complex query with array params",
			urlStr:    "https://example.com/search?q=test&filter[status]=active&filter[type]=user",
			wantQuery: "q=test&filter[status]=active&filter[type]=user",
			wantPath:  "/search",
		},
		{
			name:      "url encoded query",
			urlStr:    "https://example.com/api?name=John+Doe&email=john%40example.com",
			wantQuery: "name=John+Doe&email=john%40example.com",
			wantPath:  "/api",
		},
		{
			name:      "no query string",
			urlStr:    "https://example.com/api/simple",
			wantQuery: "",
			wantPath:  "/api/simple",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use separate storage for each test case to avoid conflicts
			sm := newTestSiteMap(t)

			u, err := url.Parse(tc.urlStr)
			require.NoError(t, err)

			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("ok"), 2, "text/plain", "", "", 0, 0).
				WithMetadata("spider", 1, time.Now()).
				Build()

			err = sm.Store(result)
			require.NoError(t, err)

			// Use StreamAllResults which is what export uses
			var nodes []*DiscoveredNode
			err = sm.StreamAllResults(func(node *DiscoveredNode) error {
				nodes = append(nodes, node)
				return nil
			})
			require.NoError(t, err)
			require.Len(t, nodes, 1)

			gotURL := nodes[0].URL()
			assert.Equal(t, tc.wantPath, gotURL.Path, "path should match")
			assert.Equal(t, tc.wantQuery, gotURL.RawQuery, "query string should be preserved")
			assert.Equal(t, tc.urlStr, gotURL.String(), "full URL should match original")
		})
	}
}

// TestSiteMap_QueryStringInStreamQuery verifies query strings are included in streaming queries (used by export)
func TestSiteMap_QueryStringInStreamQuery(t *testing.T) {
	sm := newTestSiteMap(t)

	// Store multiple URLs with different query strings
	urls := []string{
		"https://example.com/api/search?q=test&page=1",
		"https://example.com/api/data?format=json&limit=100",
		"https://example.com/api/simple", // no query
	}

	for _, urlStr := range urls {
		u, _ := url.Parse(urlStr)
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("ok"), 2, "text/plain", "", "", 0, 0).
			WithMetadata("spider", 1, time.Now()).
			Build()
		require.NoError(t, sm.Store(result))
	}

	// Get all results using streaming (used by export)
	var nodes []*DiscoveredNode
	err := sm.StreamAllResults(func(node *DiscoveredNode) error {
		nodes = append(nodes, node)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, nodes, 3)

	// Build map of path -> query for verification
	gotURLs := make(map[string]string)
	for _, node := range nodes {
		u := node.URL()
		gotURLs[u.Path] = u.RawQuery
	}

	assert.Equal(t, "q=test&page=1", gotURLs["/api/search"], "search query should be preserved")
	assert.Equal(t, "format=json&limit=100", gotURLs["/api/data"], "data query should be preserved")
	assert.Equal(t, "", gotURLs["/api/simple"], "simple should have no query")
}

// TestSiteMap_QueryStringPersistence verifies query strings persist across db close/reopen
func TestSiteMap_QueryStringPersistence(t *testing.T) {
	tmpFile := t.TempDir() + "/query_test.db"

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	// Store URL with query string
	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)

	originalURL := "https://example.com/api/v1/users?id=123&include=profile,settings"
	u, _ := url.Parse(originalURL)
	result := NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte(`{"id":123}`), 10, "application/json", "", "", 0, 0).
		WithMetadata("spider", 3, time.Now()).
		Build()

	err = sm.Store(result)
	require.NoError(t, err)

	// Close db
	_ = sm.Close()

	// Reopen and verify using StreamAllResults (what export uses)
	sm2, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	var nodes []*DiscoveredNode
	err = sm2.StreamAllResults(func(node *DiscoveredNode) error {
		nodes = append(nodes, node)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, nodes, 1)

	assert.Equal(t, originalURL, nodes[0].URL().String(), "full URL with query should persist")
	assert.Equal(t, "id=123&include=profile,settings", nodes[0].URL().RawQuery, "query string should persist")
}

// TestNewSiteMap_MultiTarget_SameSessionName verifies that multiple targets
// with the same session name create DIFFERENT session IDs (new behavior).
// Session name is for export grouping only.
func TestNewSiteMap_MultiTarget_SameSessionName(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/multi-target.db"

	// Target 1 with session name "daily"
	cfg1 := SQLiteConfig(dbPath)
	cfg1.TargetURL = "https://a.com"
	cfg1.SessionName = "daily"

	sm1, err := NewSiteMap(cfg1)
	require.NoError(t, err, "First session should be created successfully")

	session1DBID := sm1.SessionDBID()
	session1Name := sm1.SessionName()
	assert.NotZero(t, session1DBID)
	assert.Equal(t, "daily", session1Name)

	// Store a URL in first session
	u1, _ := url.Parse("https://a.com/path1")
	result1 := NewResultBuilder().
		WithURL(u1).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
		Build()
	err = sm1.Store(result1)
	require.NoError(t, err)

	_ = sm1.Close()

	// Target 2 with SAME session name "daily" - creates NEW session ID
	cfg2 := SQLiteConfig(dbPath)
	cfg2.TargetURL = "https://b.com"
	cfg2.SessionName = "daily" // Same name!

	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err, "Second process with same session name should be created successfully")

	session2DBID := sm2.SessionDBID()
	session2Name := sm2.SessionName()

	// KEY: Each start creates NEW session ID (different from before)
	assert.NotEqual(t, session1DBID, session2DBID, "Same session name must create DIFFERENT sessionDBID")
	// Session names should be the same
	assert.Equal(t, "daily", session2Name)
	assert.Equal(t, session1Name, session2Name)

	// Store a URL in second session
	u2, _ := url.Parse("https://b.com/path2")
	result2 := NewResultBuilder().
		WithURL(u2).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
		Build()
	err = sm2.Store(result2)
	require.NoError(t, err)

	// StreamResultsBySessionName should return nodes from ALL sessions with that name
	var nodes []*DiscoveredNode
	err = sm2.StreamResultsBySessionName("daily", func(node *DiscoveredNode) error {
		nodes = append(nodes, node)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, nodes, 2, "Should have nodes from both sessions with name 'daily'")

	_ = sm2.Close()
}

// TestNewSiteMap_SessionName_Empty verifies behavior when no session name is provided.
// Empty session name creates an anonymous session (NULL in DB).
func TestNewSiteMap_SessionName_Empty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TargetURL = "https://example.com"
	// SessionName not set - should be empty (anonymous session)

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	// SessionDBID should be assigned
	assert.NotZero(t, sm.SessionDBID())
	// SessionName should be empty
	assert.Empty(t, sm.SessionName())
}

// TestGetAllResultsBySessionName verifies that StreamResultsBySessionName returns
// all nodes from all sessions with the same name.
// Each start creates a new session ID, but session name groups them for export.
func TestGetAllResultsBySessionName(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/multi-session-export.db"

	// Simulate 3 processes writing to the same DB with same session name
	// Each process creates a NEW session ID (behavior changed)
	// Process 1: scans target1.com
	cfg1 := SQLiteConfig(dbPath)
	cfg1.TargetURL = "https://target1.com"
	cfg1.SessionName = "batch-scan"

	sm1, err := NewSiteMap(cfg1)
	require.NoError(t, err)
	session1DBID := sm1.SessionDBID()

	// Store URLs from target1
	urls1 := []string{
		"https://target1.com/api/users",
		"https://target1.com/api/admin",
		"https://target1.com/login",
	}
	for _, urlStr := range urls1 {
		u, _ := url.Parse(urlStr)
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("content"), 7, "text/html", "", "", 0, 0).
			Build()
		err = sm1.Store(result)
		require.NoError(t, err)
	}
	_ = sm1.Close()

	// Process 2: scans target2.com - creates NEW session ID
	cfg2 := SQLiteConfig(dbPath)
	cfg2.TargetURL = "https://target2.com"
	cfg2.SessionName = "batch-scan" // Same session name!

	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)
	session2DBID := sm2.SessionDBID()
	assert.NotEqual(t, session1DBID, session2DBID, "Each start creates NEW sessionDBID")

	// Store URLs from target2
	urls2 := []string{
		"https://target2.com/dashboard",
		"https://target2.com/settings",
	}
	for _, urlStr := range urls2 {
		u, _ := url.Parse(urlStr)
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("content"), 7, "text/html", "", "", 0, 0).
			Build()
		err = sm2.Store(result)
		require.NoError(t, err)
	}
	_ = sm2.Close()

	// Process 3: scans target3.com - creates NEW session ID
	cfg3 := SQLiteConfig(dbPath)
	cfg3.TargetURL = "https://target3.com"
	cfg3.SessionName = "batch-scan" // Same session name!

	sm3, err := NewSiteMap(cfg3)
	require.NoError(t, err)
	session3DBID := sm3.SessionDBID()
	assert.NotEqual(t, session1DBID, session3DBID, "Each start creates NEW sessionDBID")
	assert.NotEqual(t, session2DBID, session3DBID, "Each start creates NEW sessionDBID")

	// Store URLs from target3
	urls3 := []string{
		"https://target3.com/profile",
		"https://target3.com/logout",
		"https://target3.com/api/data",
	}
	for _, urlStr := range urls3 {
		u, _ := url.Parse(urlStr)
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("content"), 7, "text/html", "", "", 0, 0).
			Build()
		err = sm3.Store(result)
		require.NoError(t, err)
	}

	// Verify: Multiple sessions with same name exist
	sessions, err := sm3.repo.GetSessionsByName(context.Background(), "batch-scan")
	require.NoError(t, err)
	assert.Len(t, sessions, 3, "Should have 3 sessions with name 'batch-scan'")

	// KEY TEST: StreamResultsBySessionName should return ALL nodes from unified session
	var nodes []*DiscoveredNode
	err = sm3.StreamResultsBySessionName("batch-scan", func(node *DiscoveredNode) error {
		nodes = append(nodes, node)
		return nil
	})
	require.NoError(t, err)

	// Should have all 8 URLs (3 + 2 + 3)
	expectedTotal := len(urls1) + len(urls2) + len(urls3)
	assert.Len(t, nodes, expectedTotal,
		"StreamResultsBySessionName should return all %d nodes from unified session, got %d",
		expectedTotal, len(nodes))

	// Verify all URLs are present
	nodeURLs := make(map[string]bool)
	for _, node := range nodes {
		nodeURLs[node.URL().String()] = true
	}

	allExpectedURLs := append(append(urls1, urls2...), urls3...)
	for _, expectedURL := range allExpectedURLs {
		assert.True(t, nodeURLs[expectedURL],
			"Expected URL %s not found in results", expectedURL)
	}

	_ = sm3.Close()

	// Test with a non-existent session name
	smRead, err := OpenSiteMapDSN(dbPath)
	require.NoError(t, err)
	defer func() { _ = smRead.Close() }()

	var nodesEmpty []*DiscoveredNode
	err = smRead.StreamResultsBySessionName("non-existent", func(node *DiscoveredNode) error {
		nodesEmpty = append(nodesEmpty, node)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, nodesEmpty, 0, "Non-existent session name should return empty slice")
}

// TestStreamResultsBySessionName_DifferentSessionNames verifies that
// StreamResultsBySessionName only returns nodes from sessions with matching name,
// not from sessions with different names.
func TestStreamResultsBySessionName_DifferentSessionNames(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/diff-session-names.db"

	// Session 1: name = "batch-1"
	cfg1 := SQLiteConfig(dbPath)
	cfg1.TargetURL = "https://a.com"
	cfg1.SessionName = "batch-1"

	sm1, err := NewSiteMap(cfg1)
	require.NoError(t, err)

	u1, _ := url.Parse("https://a.com/page1")
	result1 := NewResultBuilder().
		WithURL(u1).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("a"), 1, "text/html", "", "", 0, 0).
		Build()
	require.NoError(t, sm1.Store(result1))
	_ = sm1.Close()

	// Session 2: name = "batch-2" (different name)
	cfg2 := SQLiteConfig(dbPath)
	cfg2.TargetURL = "https://b.com"
	cfg2.SessionName = "batch-2"

	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)

	u2, _ := url.Parse("https://b.com/page2")
	result2 := NewResultBuilder().
		WithURL(u2).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("b"), 1, "text/html", "", "", 0, 0).
		Build()
	require.NoError(t, sm2.Store(result2))

	// Query for batch-1 should only return 1 node
	var nodesBatch1 []*DiscoveredNode
	err = sm2.StreamResultsBySessionName("batch-1", func(node *DiscoveredNode) error {
		nodesBatch1 = append(nodesBatch1, node)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, nodesBatch1, 1, "batch-1 should have only 1 node")
	assert.Equal(t, "https://a.com/page1", nodesBatch1[0].URL().String())

	// Query for batch-2 should only return 1 node
	var nodesBatch2 []*DiscoveredNode
	err = sm2.StreamResultsBySessionName("batch-2", func(node *DiscoveredNode) error {
		nodesBatch2 = append(nodesBatch2, node)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, nodesBatch2, 1, "batch-2 should have only 1 node")
	assert.Equal(t, "https://b.com/page2", nodesBatch2[0].URL().String())

	_ = sm2.Close()
}

// TestCreateSession_AlwaysNewID verifies that each start creates a new session ID,
// even with the same session name. Session name is for export grouping only.
func TestCreateSession_AlwaysNewID(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/multi-session.db"

	const numSessions = 5
	var sessionDBIDs []int64

	// Create multiple sessions with the SAME name
	for i := range numSessions {
		cfg := SQLiteConfig(dbPath)
		cfg.SessionName = "grouped-sessions"
		cfg.TargetURL = fmt.Sprintf("https://target%d.com", i)

		sm, err := NewSiteMap(cfg)
		require.NoError(t, err, "Session %d failed to create sitemap", i)

		sessionDBIDs = append(sessionDBIDs, sm.SessionDBID())
		_ = sm.Close()
	}

	// Verify each session got DIFFERENT sessionDBID
	seen := make(map[int64]bool)
	for i, id := range sessionDBIDs {
		assert.False(t, seen[id], "Session %d must get UNIQUE sessionDBID, but %d was already used", i, id)
		seen[id] = true
	}

	// Verify multiple sessions in DB with same name
	smFinal, err := OpenSiteMapDSN(dbPath)
	require.NoError(t, err)
	defer func() { _ = smFinal.Close() }()

	sessions, err := smFinal.ListSessions()
	require.NoError(t, err)

	namedSessions := 0
	for _, s := range sessions {
		if s.Name == "grouped-sessions" {
			namedSessions++
		}
	}
	assert.Equal(t, numSessions, namedSessions, "All sessions with same name should be stored")
}

// TestAnonymousSession_MultipleInstances verifies that anonymous sessions
// (empty session_name) have different IDs and are properly isolated.
// NULL session_name doesn't violate UNIQUE constraint in SQLite.
func TestAnonymousSession_MultipleInstances(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/anon-multi.db"

	var sessionDBIDs [3]int64

	// Create 3 anonymous sessions
	for i := 0; i < 3; i++ {
		cfg := SQLiteConfig(dbPath)
		cfg.TargetURL = fmt.Sprintf("https://target%d.com", i)
		// SessionName NOT set → anonymous (NULL in DB)

		sm, err := NewSiteMap(cfg)
		require.NoError(t, err)
		sessionDBIDs[i] = sm.SessionDBID()

		// Store unique URLs
		for j := 0; j < 3; j++ {
			u, _ := url.Parse(fmt.Sprintf("https://target%d.com/path%d", i, j))
			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
				Build()
			err = sm.Store(result)
			require.NoError(t, err)
		}
		_ = sm.Close()
	}

	// Verify all have DIFFERENT session IDs
	assert.NotEqual(t, sessionDBIDs[0], sessionDBIDs[1], "Anonymous sessions must have different IDs")
	assert.NotEqual(t, sessionDBIDs[1], sessionDBIDs[2], "Anonymous sessions must have different IDs")
	assert.NotEqual(t, sessionDBIDs[0], sessionDBIDs[2], "Anonymous sessions must have different IDs")

	// Verify ListSessions() returns all 3
	sm, err := OpenSiteMapDSN(dbPath)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	sessions, err := sm.ListSessions()
	require.NoError(t, err)

	anonymousSessions := 0
	for _, s := range sessions {
		if s.Name == "" {
			anonymousSessions++
		}
	}
	assert.Equal(t, 3, anonymousSessions, "Should have 3 anonymous sessions")
}

// TestSessionIsolation_NamedVsAnonymous verifies that named sessions
// and anonymous sessions are properly isolated from each other.
func TestSessionIsolation_NamedVsAnonymous(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/isolation-test.db"

	// 1. Create anonymous session, store 3 URLs
	cfg1 := SQLiteConfig(dbPath)
	cfg1.TargetURL = "https://anon.com"
	// SessionName empty → anonymous

	sm1, err := NewSiteMap(cfg1)
	require.NoError(t, err)
	anonDBID := sm1.SessionDBID()

	for i := range 3 {
		u, _ := url.Parse(fmt.Sprintf("https://anon.com/anon-path%d", i))
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("anon"), 4, "text/html", "", "", 0, 0).
			Build()
		require.NoError(t, sm1.Store(result))
	}
	_ = sm1.Close()

	// 2. Create named session, store 5 URLs
	cfg2 := SQLiteConfig(dbPath)
	cfg2.TargetURL = "https://named.com"
	cfg2.SessionName = "my-named-session"

	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)
	namedDBID := sm2.SessionDBID()

	for i := range 5 {
		u, _ := url.Parse(fmt.Sprintf("https://named.com/named-path%d", i))
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("named"), 5, "text/html", "", "", 0, 0).
			Build()
		require.NoError(t, sm2.Store(result))
	}

	// Verify different session IDs
	assert.NotEqual(t, anonDBID, namedDBID, "Anonymous and named sessions must have different IDs")

	// StreamResultsBySessionName for named session
	var namedNodes []*DiscoveredNode
	err = sm2.StreamResultsBySessionName("my-named-session", func(node *DiscoveredNode) error {
		namedNodes = append(namedNodes, node)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, namedNodes, 5, "Named session should have exactly 5 nodes")

	// Verify named session nodes don't contain anonymous URLs
	for _, node := range namedNodes {
		assert.NotContains(t, node.URL().String(), "anon-path",
			"Named session should not contain anonymous URLs")
	}

	// StreamResultsBySessionName for non-existent returns empty
	var emptyNodes []*DiscoveredNode
	err = sm2.StreamResultsBySessionName("non-existent", func(node *DiscoveredNode) error {
		emptyNodes = append(emptyNodes, node)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, emptyNodes, 0, "Non-existent session should return empty")

	// StreamAllResults returns ALL (8 total)
	var allNodes []*DiscoveredNode
	err = sm2.StreamAllResults(func(node *DiscoveredNode) error {
		allNodes = append(allNodes, node)
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, allNodes, 8, "StreamAllResults should return all 8 nodes (3+5)")

	_ = sm2.Close()
}

// TestSessionConcurrentWrites verifies that sequential writes from multiple
// processes to the same session work correctly.
// Note: SQLite has limited concurrent write support, so we test sequentially.
// For true concurrent testing, use PostgreSQL integration tests.
func TestSessionConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/concurrent-writes.db"

	const numProcesses = 5
	const urlsPerProcess = 10

	// Write sequentially from different "processes"
	for i := range numProcesses {
		cfg := SQLiteConfig(dbPath)
		cfg.SessionName = "concurrent-writes"
		cfg.TargetURL = fmt.Sprintf("https://target%d.com", i)

		sm, err := NewSiteMap(cfg)
		require.NoError(t, err, "Process %d failed to create sitemap", i)

		for j := range urlsPerProcess {
			u, _ := url.Parse(fmt.Sprintf("https://target%d.com/path%d", i, j))
			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("content"), 7, "text/html", "", "", 0, 0).
				Build()
			err := sm.Store(result)
			require.NoError(t, err, "Process %d failed to store URL %d", i, j)
		}
		_ = sm.Close()
	}

	// Verify all data
	sm, err := OpenSiteMapDSN(dbPath)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	var nodes []*DiscoveredNode
	err = sm.StreamResultsBySessionName("concurrent-writes", func(node *DiscoveredNode) error {
		nodes = append(nodes, node)
		return nil
	})
	require.NoError(t, err)

	expectedTotal := numProcesses * urlsPerProcess
	assert.Len(t, nodes, expectedTotal,
		"Should have %d nodes (%d processes × %d URLs)", expectedTotal, numProcesses, urlsPerProcess)
}

// TestGetSessionByName_EdgeCases tests edge cases for GetSessionByName.
func TestGetSessionByName_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/edge-cases.db"

	// Create a named session
	cfg := SQLiteConfig(dbPath)
	cfg.TargetURL = "https://example.com"
	cfg.SessionName = "test-session"
	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)

	// Test 1: Get existing session
	session, err := sm.GetSessionByName("test-session")
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "test-session", session.Name)
	assert.NotZero(t, session.DBID)

	// Test 2: Get non-existent session
	_, err = sm.GetSessionByName("non-existent")
	assert.Error(t, err, "Non-existent session should return error")

	// Test 3: Get with empty name (should error - looking for anonymous)
	_, err = sm.GetSessionByName("")
	assert.Error(t, err, "Empty name should not match anonymous sessions")

	// Test 4: Session name with special characters
	_ = sm.Close()

	cfg2 := SQLiteConfig(dbPath)
	cfg2.TargetURL = "https://special.com"
	cfg2.SessionName = "test-session-with-dashes_and_underscores.and.dots"
	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	session2, err := sm2.GetSessionByName("test-session-with-dashes_and_underscores.and.dots")
	require.NoError(t, err)
	assert.Equal(t, "test-session-with-dashes_and_underscores.and.dots", session2.Name)
}

// TestListSessions_SessionStats verifies ListSessions returns correct metadata.
func TestListSessions_SessionStats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/stats-test.db"

	// Create session 1 with 5 URLs
	cfg1 := SQLiteConfig(dbPath)
	cfg1.TargetURL = "https://target1.com"
	cfg1.SessionName = "session-1"
	sm1, err := NewSiteMap(cfg1)
	require.NoError(t, err)

	for i := range 5 {
		u, _ := url.Parse(fmt.Sprintf("https://target1.com/path%d", i))
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("ok"), 2, "text/html", "", "", 0, 0).
			Build()
		require.NoError(t, sm1.Store(result))
	}
	_ = sm1.Close()

	// Create session 2 with 3 URLs
	cfg2 := SQLiteConfig(dbPath)
	cfg2.TargetURL = "https://target2.com"
	cfg2.SessionName = "session-2"
	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)

	for i := range 3 {
		u, _ := url.Parse(fmt.Sprintf("https://target2.com/path%d", i))
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("ok"), 2, "text/html", "", "", 0, 0).
			Build()
		require.NoError(t, sm2.Store(result))
	}

	// List all sessions
	sessions, err := sm2.ListSessions()
	require.NoError(t, err)
	assert.Len(t, sessions, 2)

	// Verify session metadata
	sessionMap := make(map[string]*Session)
	for _, s := range sessions {
		sessionMap[s.Name] = s
	}

	assert.NotNil(t, sessionMap["session-1"])
	assert.Equal(t, "https://target1.com", sessionMap["session-1"].TargetURL)
	assert.False(t, sessionMap["session-1"].StartedAt.IsZero())

	assert.NotNil(t, sessionMap["session-2"])
	assert.Equal(t, "https://target2.com", sessionMap["session-2"].TargetURL)

	_ = sm2.Close()
}

// TestParallelInstances_SessionIsolation verifies that multiple SiteMap instances
// running concurrently with the same database do not affect each other's operations.
// This simulates multiple processes (e.g., different deparos instances) scanning
// different targets but sharing the same database file.
func TestParallelInstances_SessionIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/parallel-test.db"

	// Create two SiteMap instances concurrently (simulating different processes)
	cfg1 := SQLiteConfig(dbPath)
	cfg1.TargetURL = "https://target1.com"
	cfg1.SessionName = "parallel-test"
	sm1, err := NewSiteMap(cfg1)
	require.NoError(t, err)
	defer func() { _ = sm1.Close() }()

	cfg2 := SQLiteConfig(dbPath)
	cfg2.TargetURL = "https://target2.com"
	cfg2.SessionName = "parallel-test" // Same session name, but should get different session ID
	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	// Verify they got different session IDs
	assert.NotEqual(t, sm1.sessionDBID, sm2.sessionDBID, "Each instance should have unique session ID")

	// Store nodes concurrently using goroutines to simulate parallel execution
	var wg sync.WaitGroup
	wg.Add(2)

	// Instance 1: Store 10 nodes
	go func() {
		defer wg.Done()
		for i := range 10 {
			u, _ := url.Parse(fmt.Sprintf("https://target1.com/path%d", i))
			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("content"), 7, "text/html", "", "", 0, 0).
				Build()
			_ = sm1.Store(result)
		}
	}()

	// Instance 2: Store 5 nodes
	go func() {
		defer wg.Done()
		for i := range 5 {
			u, _ := url.Parse(fmt.Sprintf("https://target2.com/resource%d", i))
			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("data"), 4, "text/html", "", "", 0, 0).
				Build()
			_ = sm2.Store(result)
		}
	}()

	wg.Wait()

	// Verify Count() returns only session-specific nodes
	count1 := sm1.Count()
	assert.Equal(t, 10, count1, "Instance 1 should see only its 10 nodes")

	count2 := sm2.Count()
	assert.Equal(t, 5, count2, "Instance 2 should see only its 5 nodes")

	// Verify GetFileNodesWithIDs() returns only session-specific nodes
	nodes1, err := sm1.GetFileNodesWithIDs()
	require.NoError(t, err)
	assert.Len(t, nodes1, 10, "Instance 1 GetFileNodesWithIDs should return only its 10 nodes")
	for _, n := range nodes1 {
		assert.Contains(t, n.Node.URL().String(), "target1.com", "All nodes should belong to target1")
	}

	nodes2, err := sm2.GetFileNodesWithIDs()
	require.NoError(t, err)
	assert.Len(t, nodes2, 5, "Instance 2 GetFileNodesWithIDs should return only its 5 nodes")
	for _, n := range nodes2 {
		assert.Contains(t, n.Node.URL().String(), "target2.com", "All nodes should belong to target2")
	}

	// Verify deletion only affects current session's nodes
	// Delete 3 nodes from instance 1
	idsToDelete := make([]int64, 3)
	for i := 0; i < 3; i++ {
		idsToDelete[i] = nodes1[i].ID
	}
	err = sm1.DeleteNodesByIDs(idsToDelete)
	require.NoError(t, err)

	// Instance 1 should now have 7 nodes
	count1After := sm1.Count()
	assert.Equal(t, 7, count1After, "Instance 1 should have 7 nodes after deletion")

	// Instance 2 should still have all 5 nodes (unaffected)
	count2After := sm2.Count()
	assert.Equal(t, 5, count2After, "Instance 2 should still have 5 nodes (unaffected by instance 1's deletion)")

	// Verify nodes in instance 2 are still intact
	nodes2After, err := sm2.GetFileNodesWithIDs()
	require.NoError(t, err)
	assert.Len(t, nodes2After, 5, "Instance 2 should still have all 5 nodes")
}

// TestParallelInstances_ConcurrentStoreAndCount verifies thread-safety
// when multiple instances perform Store and Count operations simultaneously.
func TestParallelInstances_ConcurrentStoreAndCount(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/concurrent-test.db"

	const numInstances = 3
	const nodesPerInstance = 20
	const iterations = 5

	// Create multiple SiteMap instances
	instances := make([]*SiteMap, numInstances)
	for i := range numInstances {
		cfg := SQLiteConfig(dbPath)
		cfg.TargetURL = fmt.Sprintf("https://target%d.com", i)
		cfg.SessionName = fmt.Sprintf("concurrent-session-%d", i)
		sm, err := NewSiteMap(cfg)
		require.NoError(t, err)
		instances[i] = sm
		defer func() { _ = sm.Close() }()
	}

	// Verify all instances have unique session IDs
	sessionIDs := make(map[int64]bool)
	for _, sm := range instances {
		assert.False(t, sessionIDs[sm.sessionDBID], "Session ID should be unique")
		sessionIDs[sm.sessionDBID] = true
	}

	// Concurrent Store and Count operations
	var wg sync.WaitGroup
	errors := make(chan error, numInstances*iterations*2)

	for idx, sm := range instances {
		wg.Add(1)
		go func(instanceIdx int, sitemap *SiteMap) {
			defer wg.Done()
			for iter := range iterations {
				// Store nodes
				for j := range nodesPerInstance / iterations {
					u, _ := url.Parse(fmt.Sprintf("https://target%d.com/iter%d/path%d", instanceIdx, iter, j))
					result := NewResultBuilder().
						WithURL(u).
						WithRequest("GET", nil, nil).
						WithResponse(200, nil, []byte("ok"), 2, "text/html", "", "", 0, 0).
						Build()
					_ = sitemap.Store(result)
				}

				// Verify Count (should only see this instance's nodes)
				count := sitemap.Count()
				// Count should be increasing but never exceed nodesPerInstance
				if count > nodesPerInstance {
					errors <- fmt.Errorf("instance %d has too many nodes: %d > %d", instanceIdx, count, nodesPerInstance)
				}
			}
		}(idx, sm)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}

	// Final verification: each instance should have exactly nodesPerInstance nodes
	for i, sm := range instances {
		count := sm.Count()
		assert.Equal(t, nodesPerInstance, count, "Instance %d should have exactly %d nodes", i, nodesPerInstance)

		// GetFileNodesWithIDs should also return correct count
		nodes, err := sm.GetFileNodesWithIDs()
		require.NoError(t, err)
		assert.Len(t, nodes, nodesPerInstance, "Instance %d GetFileNodesWithIDs should return %d nodes", i, nodesPerInstance)

		// All URLs should belong to this instance's target
		expectedHost := fmt.Sprintf("target%d.com", i)
		for _, n := range nodes {
			assert.Contains(t, n.Node.URL().String(), expectedHost, "Node URL should contain %s", expectedHost)
		}
	}
}
