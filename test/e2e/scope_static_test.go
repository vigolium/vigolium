//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/server"
)

// scopeTestEnv holds an API server wired with custom Settings so that
// scope rules (including static-file filtering) are enforced during ingestion.
type scopeTestEnv struct {
	server   *server.Server
	url      string
	settings *config.Settings
	apiKey   string
}

// newScopeTestEnv starts a server with the given settings and applied_on_ingest=true.
func newScopeTestEnv(t *testing.T, settings *config.Settings) *scopeTestEnv {
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

	srv := server.NewServer(server.ServerConfig{
		ServiceAddr:          addr,
		NoAuth:               true,
		CORSAllowedOrigins:   "reflect-origin",
		Version:              "test-scope",
		DisableFetchResponse: true,
	}, taskQueue, db, repo, settings, nil)

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

	return &scopeTestEnv{
		server:   srv,
		url:      apiURL,
		settings: settings,
	}
}

func (env *scopeTestEnv) post(t *testing.T, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.url+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func (env *scopeTestEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, env.url+path, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// ============================================================
// Static file filtering — ingestion with applied_on_ingest=true
// ============================================================

func TestScope_StaticFile_IngestBlocked(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = true
	// IgnoreStaticFile and IgnoreStaticContentType are already set by default

	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	// Ingest a static image URL — should be filtered
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/assets/logo.png"
	}`)
	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 0, body.Imported, "static file .png should be filtered")
	assert.Equal(t, 1, body.Skipped, "static file .png should be skipped")
}

func TestScope_StaticFile_IngestMultipleFormats(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = true
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	staticURLs := []struct {
		url  string
		ext  string
	}{
		{"http://example.com/fonts/roboto.woff2", ".woff2"},
		{"http://example.com/img/photo.jpg", ".jpg"},
		{"http://example.com/vid/clip.mp4", ".mp4"},
		{"http://example.com/audio/song.mp3", ".mp3"},
		{"http://example.com/icon.svg", ".svg"},
		{"http://example.com/style/font.ttf", ".ttf"},
		{"http://example.com/bg.webp", ".webp"},
	}

	for _, tc := range staticURLs {
		resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
			"input_mode": "url",
			"content": "%s"
		}`, tc.url))
		var body server.IngestHTTPResponse
		readJSON(t, resp, &body)
		assert.Equal(t, 0, body.Imported, "static file %s should be filtered", tc.ext)
		assert.Equal(t, 1, body.Skipped, "static file %s should be skipped", tc.ext)
	}
}

func TestScope_StaticFile_NonStaticAllowed(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = true
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	// Normal API endpoints should be allowed
	normalURLs := []string{
		"http://example.com/api/v1/users?page=1",
		"http://example.com/login",
		"http://example.com/index.html",
		"http://example.com/app.js",
		"http://example.com/style.css",
	}

	for _, u := range normalURLs {
		resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
			"input_mode": "url",
			"content": "%s"
		}`, u))
		var body server.IngestHTTPResponse
		readJSON(t, resp, &body)
		assert.Equal(t, 1, body.Imported, "non-static URL %s should be imported", u)
	}
}

func TestScope_StaticFile_DisabledAllowsAll(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = true
	scope.IgnoreStaticFile = false // disable static file filtering
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	// Static file URL should be allowed when filtering is disabled
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/assets/logo.png"
	}`)
	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported, ".png should be imported when ignore_static_file is false")
	assert.Equal(t, 0, body.Skipped)
}

func TestScope_StaticFile_CurlModeBlocked(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = true
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	// Static file via curl mode should also be filtered
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "curl",
		"content": "curl http://example.com/assets/banner.jpg"
	}`)
	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 0, body.Imported, "static file via curl should be filtered")
	assert.Equal(t, 1, body.Skipped)
}

func TestScope_StaticFile_URLFileMixed(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = true
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	// Mix of static and non-static URLs
	content := "http://example.com/api/users\\nhttp://example.com/logo.png\\nhttp://example.com/login\\nhttp://example.com/font.woff2"
	resp := env.post(t, "/api/ingest-http", fmt.Sprintf(`{
		"input_mode": "url_file",
		"content": "%s"
	}`, content))
	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 2, body.Imported, "only non-static URLs should be imported")
	assert.Equal(t, 2, body.Skipped, "static URLs (.png, .woff2) should be skipped")
}

func TestScope_StaticFile_ScopeEndpointReflectsSettings(t *testing.T) {
	scope := config.DefaultScopeConfig()
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	resp := env.get(t, "/api/scope")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var scopeResp config.ScopeConfig
	readJSON(t, resp, &scopeResp)
	assert.True(t, scopeResp.IgnoreStaticFile, "scope response should show ignore_static_file=true")
	assert.NotEmpty(t, scopeResp.IgnoreStaticContentType, "scope response should include extension categories")
	assert.Contains(t, scopeResp.IgnoreStaticContentType, "images")
	assert.Contains(t, scopeResp.IgnoreStaticContentType, "fonts")
	assert.Contains(t, scopeResp.IgnoreStaticContentType, "video")
	assert.Contains(t, scopeResp.IgnoreStaticContentType, "audio")
}

func TestScope_StaticFile_CaseInsensitive(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = true
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	// Mixed case extensions should also be filtered
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/LOGO.PNG"
	}`)
	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 0, body.Imported, "uppercase .PNG should be filtered")
	assert.Equal(t, 1, body.Skipped)
}

func TestScope_StaticFile_BlockedEvenWithoutAppliedOnIngest(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = false // default — full scope not enforced during ingestion
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	// Static file filtering is unconditional — always blocks, even when
	// applied_on_ingest=false (only full scope rules respect that flag)
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/assets/logo.png"
	}`)
	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 0, body.Imported, "static file should be blocked even when applied_on_ingest=false")
	assert.Equal(t, 1, body.Skipped)
}

func TestScope_StaticFile_NonStaticAllowedWithoutAppliedOnIngest(t *testing.T) {
	scope := config.DefaultScopeConfig()
	scope.AppliedOnIngest = false
	// Add a host restriction — should NOT be enforced since applied_on_ingest=false
	scope.Host = config.ScopeRule{Include: []string{"*.restricted.com"}, Exclude: []string{}}
	settings := &config.Settings{Scope: *scope}
	env := newScopeTestEnv(t, settings)

	// Non-static URL for a host outside the scope restriction should still be
	// imported because applied_on_ingest=false (only static file check applies)
	resp := env.post(t, "/api/ingest-http", `{
		"input_mode": "url",
		"content": "http://example.com/api/users"
	}`)
	var body server.IngestHTTPResponse
	readJSON(t, resp, &body)
	assert.Equal(t, 1, body.Imported, "non-static URL should be imported when applied_on_ingest=false (host scope not enforced)")
}
