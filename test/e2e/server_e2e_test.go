//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// apiTestEnv holds components for API-focused e2e tests.
// Unlike the old env, this does NOT spin up a runner — it only
// tests the API server + DB layer.
type apiTestEnv struct {
	server *server.Server
	url    string
	db     *database.DB
	repo   *database.Repository
	queue  queue.Queue
	apiKey string
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// newAPITestEnv starts a fiber API server on a random port with an in-memory
// SQLite database. Use apiKey="" for no-auth mode.
func newAPITestEnv(t *testing.T, apiKey string) *apiTestEnv {
	t.Helper()

	db, repo := setupTestDB(t)

	tmpDir := t.TempDir()
	taskQueue, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = taskQueue.Close() })

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var keys []string
	noAuth := true
	if apiKey != "" {
		keys = []string{apiKey}
		noAuth = false
	}

	srv := server.NewServer(server.ServerConfig{
		ServiceAddr:          addr,
		APIKeys:              keys,
		NoAuth:               noAuth,
		CORSAllowedOrigins:   "reflect-origin",
		Version:              "test-v0.0.1",
		DisableFetchResponse: true,
	}, taskQueue, db, repo, nil, nil)

	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	apiURL := "http://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(apiURL + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return &apiTestEnv{
		server: srv,
		url:    apiURL,
		db:     db,
		repo:   repo,
		queue:  taskQueue,
		apiKey: apiKey,
	}
}

// post sends a POST request with JSON body and optional Bearer auth.
func (env *apiTestEnv) post(t *testing.T, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.url+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// get sends a GET request with optional Bearer auth.
func (env *apiTestEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.url+path, nil)
	require.NoError(t, err)
	if env.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+env.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// readJSON decodes resp body into dest and closes the body.
func readJSON(t *testing.T, resp *http.Response, dest interface{}) {
	t.Helper()
	defer resp.Body.Close()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(dest))
}

// countRecords returns the total number of HTTPRecords in the DB.
func (env *apiTestEnv) countRecords(t *testing.T) int {
	t.Helper()
	count, err := env.db.NewSelect().Model((*database.HTTPRecord)(nil)).Count(context.Background())
	require.NoError(t, err)
	return count
}

// ============================================================
// GET /health
// ============================================================

func TestAPI_Health(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/health")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.HealthResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "healthy", body.Status)
	assert.NotEmpty(t, body.Timestamp)
}

func TestAPI_Health_NoAuthRequired(t *testing.T) {
	env := newAPITestEnv(t, "secret-key")

	// Hit /health without any auth header
	req, err := http.NewRequest(http.MethodGet, env.url+"/health", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ============================================================
// GET /server-info
// ============================================================

func TestAPI_ServerInfo(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/server-info")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.ServerInfoResponse
	readJSON(t, resp, &body)
	assert.Equal(t, "test-v0.0.1", body.Version)
	assert.NotEmpty(t, body.Uptime)
	assert.Contains(t, body.DBDriver, "sqlite")
	assert.Equal(t, int64(0), body.TotalRecords)
	assert.Equal(t, int64(0), body.TotalFindings)
}

func TestAPI_ServerInfo_CountsAfterIngest(t *testing.T) {
	env := newAPITestEnv(t, "")

	// Ingest a URL so there is at least one record
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/page?id=1"
	}`)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp = env.get(t, "/server-info")
	var info server.ServerInfoResponse
	readJSON(t, resp, &info)
	assert.Equal(t, int64(1), info.TotalRecords)
}

// ============================================================
// GET /api/modules
// ============================================================

func TestAPI_Modules_ListAll(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/api/modules")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Modules []server.ModuleInfo `json:"modules"`
		Total   int              `json:"total"`
	}
	readJSON(t, resp, &body)
	assert.Greater(t, body.Total, 0, "expected at least 1 module")
	assert.Len(t, body.Modules, body.Total)

	// Verify each module has required fields
	for _, m := range body.Modules {
		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Name)
		assert.NotEmpty(t, m.Severity)
		assert.Contains(t, []string{"active", "passive"}, m.Type)
	}
}

func TestAPI_Modules_Search(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/api/modules?search=xss")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Modules []server.ModuleInfo `json:"modules"`
		Total   int              `json:"total"`
	}
	readJSON(t, resp, &body)
	assert.Greater(t, body.Total, 0)

	for _, m := range body.Modules {
		combined := strings.ToLower(m.ID + m.Name + m.ShortDescription)
		tagMatch := false
		for _, tag := range m.Tags {
			if strings.Contains(strings.ToLower(tag), "xss") {
				tagMatch = true
				break
			}
		}
		assert.True(t, strings.Contains(combined, "xss") || tagMatch,
			"search result %s should match 'xss' in name/description or tags", m.ID)
	}
}

func TestAPI_Modules_SearchNoMatch(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/api/modules?search=nonexistent_module_xyz")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Total int `json:"total"`
	}
	readJSON(t, resp, &body)
	assert.Equal(t, 0, body.Total)
}

// ============================================================
// GET /api/http-records
// ============================================================

func TestAPI_Records_EmptyDB(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/api/http-records")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(0), body.Total)
	assert.Equal(t, 50, body.Limit)
	assert.Equal(t, 0, body.Offset)
	assert.False(t, body.HasMore)
}

func TestAPI_Records_AfterIngest(t *testing.T) {
	env := newAPITestEnv(t, "")

	// Ingest two URLs
	for _, u := range []string{"http://example.com/a?x=1", "http://example.com/b?y=2"} {
		resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{"input_mode":"url","content":"%s"}`, u))
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	resp := env.get(t, "/api/http-records?limit=10")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(2), body.Total)
}

func TestAPI_Records_FilterByDomain(t *testing.T) {
	env := newAPITestEnv(t, "")

	// Ingest records for two different domains
	env.post(t, "/api/ingest-http", `{"input_mode":"url","content":"http://alpha.example.com/page"}`).Body.Close()
	env.post(t, "/api/ingest-http", `{"input_mode":"url","content":"http://beta.example.com/page"}`).Body.Close()

	resp := env.get(t, "/api/http-records?domain=alpha.example.com")
	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(1), body.Total)
}

func TestAPI_Records_FilterByMethod(t *testing.T) {
	env := newAPITestEnv(t, "")

	// Ingest a GET via url mode
	env.post(t, "/api/ingest-http", `{"input_mode":"url","content":"http://example.com/get-page"}`).Body.Close()

	// Ingest a POST via curl mode
	env.post(t, "/api/ingest-http", `{"input_mode":"curl","content":"curl -X POST http://example.com/post-page -d 'key=value'"}`).Body.Close()

	// Filter GET only
	resp := env.get(t, "/api/http-records?method=GET")
	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(1), body.Total)

	// Filter POST only
	resp = env.get(t, "/api/http-records?method=POST")
	readJSON(t, resp, &body)
	assert.Equal(t, int64(1), body.Total)
}

func TestAPI_Records_Pagination(t *testing.T) {
	env := newAPITestEnv(t, "")

	// Ingest 5 URLs
	for i := 0; i < 5; i++ {
		env.post(t, "/api/ingest-http", fmt.Sprintf(`{"input_mode":"url","content":"http://example.com/page%d"}`, i)).Body.Close()
	}

	// Page 1: limit=2, offset=0
	resp := env.get(t, "/api/http-records?limit=2&offset=0")
	var page1 server.PaginatedResponse
	readJSON(t, resp, &page1)
	assert.Equal(t, int64(5), page1.Total)
	assert.Equal(t, 2, page1.Limit)
	assert.True(t, page1.HasMore)

	// Page 3: limit=2, offset=4  → has_more=false
	resp = env.get(t, "/api/http-records?limit=2&offset=4")
	var page3 server.PaginatedResponse
	readJSON(t, resp, &page3)
	assert.False(t, page3.HasMore)
}

// ============================================================
// GET /api/findings
// ============================================================

func TestAPI_Findings_EmptyDB(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/api/findings")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(0), body.Total)
}

// ============================================================
// Bearer auth
// ============================================================

func TestAPI_Auth_MissingToken_Returns401(t *testing.T) {
	env := newAPITestEnv(t, "secret-key")

	// Make a request without setting the key helper
	req, err := http.NewRequest(http.MethodGet, env.url+"/api/modules", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	var body server.ErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, body.Error, "missing")
}

func TestAPI_Auth_InvalidToken_Returns401(t *testing.T) {
	env := newAPITestEnv(t, "secret-key")

	req, err := http.NewRequest(http.MethodGet, env.url+"/api/modules", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer wrong-key")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPI_Auth_ValidToken_Succeeds(t *testing.T) {
	env := newAPITestEnv(t, "secret-key")

	resp := env.get(t, "/api/modules")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

// ============================================================
// Security headers
// ============================================================

func TestAPI_SecurityHeaders(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.get(t, "/health")
	defer resp.Body.Close()

	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
}

// ============================================================
// POST /api/ingest-http — curl mode
// ============================================================

func TestAPI_Ingest_Curl_SimpleGET(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "curl",
		"content": "curl http://example.com/api/users?page=1"
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)

	assert.Equal(t, 1, env.countRecords(t))
}

func TestAPI_Ingest_Curl_POSTWithHeaders(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "curl",
		"content": "curl -X POST http://example.com/api/login -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"pass\":\"secret\"}'"
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)
}

func TestAPI_Ingest_Curl_ContentBase64(t *testing.T) {
	env := newAPITestEnv(t, "")

	curlCmd := "curl http://example.com/from-base64"
	encoded := base64.StdEncoding.EncodeToString([]byte(curlCmd))

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "curl",
		"content_base64": "%s"
	}`, encoded))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)
}

// ============================================================
// POST /api/ingest-http — burp_base64 mode
// ============================================================

func TestAPI_Ingest_BurpBase64_RequestOnly(t *testing.T) {
	env := newAPITestEnv(t, "")

	rawReq := "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
	b64Req := base64.StdEncoding.EncodeToString([]byte(rawReq))

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "burp_base64",
		"http_request_base64": "%s"
	}`, b64Req))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)
	assert.Equal(t, 1, env.countRecords(t))
}

func TestAPI_Ingest_BurpBase64_RequestAndResponse(t *testing.T) {
	env := newAPITestEnv(t, "")

	rawReq := "GET /status HTTP/1.1\r\nHost: example.com\r\n\r\n"
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>OK</h1>"
	b64Req := base64.StdEncoding.EncodeToString([]byte(rawReq))
	b64Resp := base64.StdEncoding.EncodeToString([]byte(rawResp))

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "burp_base64",
		"http_request_base64": "%s",
		"http_response_base64": "%s"
	}`, b64Req, b64Resp))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)
}

func TestAPI_Ingest_BurpBase64_POSTRequest(t *testing.T) {
	env := newAPITestEnv(t, "")

	rawReq := "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n{\"username\":\"admin\",\"password\":\"pass\"}"
	b64Req := base64.StdEncoding.EncodeToString([]byte(rawReq))

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "burp_base64",
		"http_request_base64": "%s"
	}`, b64Req))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)
}

func TestAPI_Ingest_BurpBase64_MissingField(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "burp_base64"
	}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestAPI_Ingest_BurpBase64_InvalidBase64(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "burp_base64",
		"http_request_base64": "not-valid-base64!!!"
	}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// ============================================================
// POST /api/ingest-http — url mode
// ============================================================

func TestAPI_Ingest_URL_Simple(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/page?id=42"
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)
	assert.Equal(t, 1, env.countRecords(t))
}

func TestAPI_Ingest_URL_WithPath(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "https://api.example.com/v2/users/123/profile?fields=name,email"
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)
}

// ============================================================
// POST /api/ingest-http — url_file mode
// ============================================================

func TestAPI_Ingest_URLFile_MultipleLines(t *testing.T) {
	env := newAPITestEnv(t, "")

	urls := "http://example.com/page1\nhttp://example.com/page2\nhttp://example.com/page3"
	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "url_file",
		"content": "%s"
	}`, strings.ReplaceAll(urls, "\n", "\\n")))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 3, body.Imported)
	assert.Equal(t, 3, env.countRecords(t))
}

func TestAPI_Ingest_URLFile_SkipsBlanksAndComments(t *testing.T) {
	env := newAPITestEnv(t, "")

	content := "http://example.com/a\n\n# this is a comment\nhttp://example.com/b\n"
	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "url_file",
		"content": "%s"
	}`, strings.ReplaceAll(content, "\n", "\\n")))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 2, body.Imported)
}

func TestAPI_Ingest_URLFile_Base64Encoded(t *testing.T) {
	env := newAPITestEnv(t, "")

	urls := "http://example.com/base64-1\nhttp://example.com/base64-2"
	encoded := base64.StdEncoding.EncodeToString([]byte(urls))

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "url_file",
		"content_base64": "%s"
	}`, encoded))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 2, body.Imported)
}

// ============================================================
// POST /api/ingest-http — openapi mode
// ============================================================

func TestAPI_Ingest_OpenAPI_MinimalSpec(t *testing.T) {
	env := newAPITestEnv(t, "")

	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0"},
		"servers": [{"url": "http://api.example.com"}],
		"paths": {
			"/users": {
				"get": {
					"summary": "List users",
					"responses": {"200": {"description": "OK"}}
				}
			},
			"/users/{id}": {
				"get": {
					"summary": "Get user",
					"parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`

	// Escape JSON for embedding in outer JSON
	specEscaped := strings.ReplaceAll(spec, `"`, `\"`)
	specEscaped = strings.ReplaceAll(specEscaped, "\n", "\\n")
	specEscaped = strings.ReplaceAll(specEscaped, "\t", "\\t")

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "openapi",
		"content": "%s"
	}`, specEscaped))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.GreaterOrEqual(t, body.Imported, 1, "expected at least 1 request from OpenAPI spec")
	t.Logf("OpenAPI ingest: imported=%d, errors=%v", body.Imported, body.Errors)
}

func TestAPI_Ingest_OpenAPI_Base64(t *testing.T) {
	env := newAPITestEnv(t, "")

	spec := `{"openapi":"3.0.0","info":{"title":"T","version":"1"},"servers":[{"url":"http://api.example.com"}],"paths":{"/ping":{"get":{"responses":{"200":{"description":"OK"}}}}}}`
	encoded := base64.StdEncoding.EncodeToString([]byte(spec))

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "openapi",
		"content_base64": "%s"
	}`, encoded))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.GreaterOrEqual(t, body.Imported, 1)
}

func TestAPI_Ingest_Swagger_Mode(t *testing.T) {
	env := newAPITestEnv(t, "")

	// swagger alias should work identically to openapi
	spec := `{"openapi":"3.0.0","info":{"title":"T","version":"1"},"servers":[{"url":"http://api.example.com"}],"paths":{"/health":{"get":{"responses":{"200":{"description":"OK"}}}}}}`
	encoded := base64.StdEncoding.EncodeToString([]byte(spec))

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "swagger",
		"content_base64": "%s"
	}`, encoded))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.GreaterOrEqual(t, body.Imported, 1)
}

// ============================================================
// POST /api/ingest-http — postman_collection mode
// ============================================================

func TestAPI_Ingest_Postman_MinimalCollection(t *testing.T) {
	env := newAPITestEnv(t, "")

	collection := `{
		"info": {"name": "Test", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
		"item": [
			{
				"name": "Get Users",
				"request": {
					"method": "GET",
					"url": {"raw": "http://api.example.com/users?page=1", "host": ["api.example.com"], "path": ["users"], "query": [{"key": "page", "value": "1"}]}
				}
			},
			{
				"name": "Create User",
				"request": {
					"method": "POST",
					"url": {"raw": "http://api.example.com/users", "host": ["api.example.com"], "path": ["users"]},
					"header": [{"key": "Content-Type", "value": "application/json"}],
					"body": {"mode": "raw", "raw": "{\"name\":\"Alice\"}"}
				}
			}
		]
	}`

	reqBody, _ := json.Marshal(map[string]string{
		"input_mode": "postman_collection",
		"content":    collection,
	})

	resp := env.post(t, "/api/ingest-http", string(reqBody))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 2, body.Imported)
	assert.Equal(t, 2, env.countRecords(t))
	t.Logf("Postman ingest: imported=%d", body.Imported)
}

func TestAPI_Ingest_Postman_Base64(t *testing.T) {
	env := newAPITestEnv(t, "")

	collection := `{"info":{"name":"T","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},"item":[{"name":"Ping","request":{"method":"GET","url":{"raw":"http://api.example.com/ping"}}}]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(collection))

	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "postman_collection",
		"content_base64": "%s"
	}`, encoded))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported)
}

// ============================================================
// POST /api/ingest-http — error cases
// ============================================================

func TestAPI_Ingest_MissingInputMode(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{"content": "http://example.com"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "input_mode")
}

func TestAPI_Ingest_UnsupportedMode(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{"input_mode": "har", "content": "data"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "unsupported")
}

func TestAPI_Ingest_MissingContent(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{"input_mode": "curl"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestAPI_Ingest_InvalidJSON(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `not json at all`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// ============================================================
// POST /api/ingest-http — records are saved with scanned=false
// ============================================================

func TestAPI_Ingest_RecordsSavedUnscanned(t *testing.T) {
	env := newAPITestEnv(t, "")

	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/unscanned-check"
	}`)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify record is in DB with correct source
	var records []*database.HTTPRecord
	err := env.db.NewSelect().Model(&records).Where("hostname = ?", "example.com").Scan(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, records)
	assert.Equal(t, "ingest-server", records[0].Source, "ingested records should have source=ingest-server")
}

// ============================================================
// POST /api/ingest-http — records show up in GET /api/http-records
// ============================================================

func TestAPI_Ingest_ThenList(t *testing.T) {
	env := newAPITestEnv(t, "")

	// Ingest via different modes
	env.post(t, "/api/ingest-http", `{"input_mode":"url","content":"http://alpha.test/a"}`).Body.Close()
	env.post(t, "/api/ingest-http", `{"input_mode":"curl","content":"curl http://beta.test/b"}`).Body.Close()

	rawReq := "GET /c HTTP/1.1\r\nHost: gamma.test\r\n\r\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(rawReq))
	env.post(t, "/api/ingest-http", fmt.Sprintf(`{"input_mode":"burp_base64","http_request_base64":"%s"}`, b64)).Body.Close()

	// List all records
	resp := env.get(t, "/api/http-records?limit=100")
	var body server.PaginatedResponse
	readJSON(t, resp, &body)
	assert.Equal(t, int64(3), body.Total)

	// Filter by one domain
	resp = env.get(t, "/api/http-records?domain=beta.test")
	readJSON(t, resp, &body)
	assert.Equal(t, int64(1), body.Total)
}

// ============================================================
// POST /api/ingest-http — auth enforced
// ============================================================

func TestAPI_Ingest_AuthRequired(t *testing.T) {
	env := newAPITestEnv(t, "my-secret")

	// Without token
	req, err := http.NewRequest(http.MethodPost, env.url+"/api/ingest-http",
		strings.NewReader(`{"input_mode":"url","content":"http://example.com"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// With valid token — should succeed
	resp2 := env.post(t, "/api/ingest-http", `{"input_mode":"url","content":"http://example.com/authed"}`)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	resp2.Body.Close()
}

// ============================================================
// POST /api/scans/run — requires targets
// ============================================================

func TestAPI_ScanRoute_RequiresTargets(t *testing.T) {
	env := newAPITestEnv(t, "")

	// POST /api/scans/run with no targets returns 400
	resp := env.post(t, "/api/scans/run", `{}`)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
