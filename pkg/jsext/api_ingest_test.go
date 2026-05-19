package jsext

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// newTestRepo creates an in-memory SQLite database with schema for testing.
func newTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.sqlite")
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        dbPath,
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   1000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	require.NoError(t, db.CreateSchema(context.Background()))
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

func setupIngestTestVM(t *testing.T, opts APIOptions) *sobek.Runtime {
	t.Helper()
	vm := sobek.New()
	vigolium := vm.NewObject()
	_ = vm.Set("vigolium", vigolium)
	registerFuncsUnchecked(vm, opts, ingestFuncDefs())
	return vm
}

func TestIngestURL(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupIngestTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.ingest.url("https://example.com/api/test")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(1), obj.Get("imported").ToInteger())
	assert.Equal(t, int64(0), obj.Get("skipped").ToInteger())
	assert.NotEmpty(t, obj.Get("uuid").String())
	assert.Equal(t, "", obj.Get("error").String())
}

func TestIngestURLEmpty(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupIngestTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.ingest.url("")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("imported").ToInteger())
	assert.Contains(t, obj.Get("error").String(), "url is required")
}

func TestIngestURLNoRepo(t *testing.T) {
	vm := setupIngestTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.ingest.url("https://example.com")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("imported").ToInteger())
	assert.Contains(t, obj.Get("error").String(), "database not available")
}

func TestIngestURLs(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupIngestTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.ingest.urls("https://example.com/a\nhttps://example.com/b\n# comment\n\n")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(2), obj.Get("imported").ToInteger())
	assert.Equal(t, int64(0), obj.Get("skipped").ToInteger())
}

func TestIngestURLsNoRepo(t *testing.T) {
	vm := setupIngestTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.ingest.urls("https://example.com")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("imported").ToInteger())
	errArr := obj.Get("errors").ToObject(vm)
	assert.Greater(t, errArr.Get("length").ToInteger(), int64(0))
}

func TestIngestCurl(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupIngestTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.ingest.curl("curl https://example.com/api -H 'Accept: application/json'")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(1), obj.Get("imported").ToInteger())
	assert.NotEmpty(t, obj.Get("uuid").String())
	assert.Equal(t, "", obj.Get("error").String())
}

func TestIngestCurlEmpty(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupIngestTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.ingest.curl("")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("imported").ToInteger())
	assert.Contains(t, obj.Get("error").String(), "curl command is required")
}

func TestIngestRaw(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupIngestTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.ingest.raw("GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(1), obj.Get("imported").ToInteger())
	assert.NotEmpty(t, obj.Get("uuid").String())
}

func TestIngestRawWithResponse(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupIngestTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.ingest.raw(
		"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
	)`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(1), obj.Get("imported").ToInteger())
}

func TestIngestRawEmpty(t *testing.T) {
	repo := newTestRepo(t)
	vm := setupIngestTestVM(t, APIOptions{Repository: repo})

	val, err := vm.RunString(`vigolium.ingest.raw("")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("imported").ToInteger())
	assert.Contains(t, obj.Get("error").String(), "raw request is required")
}

func TestIngestScopeFiltering(t *testing.T) {
	repo := newTestRepo(t)
	scopeCfg := config.ScopeConfig{
		Host: config.ScopeRule{
			Include: []string{"*.example.com"},
		},
	}
	matcher := config.NewScopeMatcher(scopeCfg)

	vm := setupIngestTestVM(t, APIOptions{
		Repository:   repo,
		ScopeMatcher: matcher,
	})

	// In scope
	val, err := vm.RunString(`vigolium.ingest.url("https://api.example.com/test")`)
	require.NoError(t, err)
	obj := val.ToObject(vm)
	assert.Equal(t, int64(1), obj.Get("imported").ToInteger())

	// Out of scope
	val, err = vm.RunString(`vigolium.ingest.url("https://evil.com/test")`)
	require.NoError(t, err)
	obj = val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("imported").ToInteger())
	assert.Equal(t, int64(1), obj.Get("skipped").ToInteger())
}

func TestIngestOpenAPINoRepo(t *testing.T) {
	vm := setupIngestTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.ingest.openapi("{}")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("imported").ToInteger())
	errArr := obj.Get("errors").ToObject(vm)
	assert.Greater(t, errArr.Get("length").ToInteger(), int64(0))
}

func TestIngestPostmanNoRepo(t *testing.T) {
	vm := setupIngestTestVM(t, APIOptions{})

	val, err := vm.RunString(`vigolium.ingest.postman("{}")`)
	require.NoError(t, err)

	obj := val.ToObject(vm)
	assert.Equal(t, int64(0), obj.Get("imported").ToInteger())
	errArr := obj.Get("errors").ToObject(vm)
	assert.Greater(t, errArr.Get("length").ToInteger(), int64(0))
}
