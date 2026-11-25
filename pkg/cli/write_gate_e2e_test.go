package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// methodCountingServer counts requests per "METHOD path".
func methodCountingServer(t *testing.T) (*httptest.Server, func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range hits {
			out[k] = v
		}
		return out
	}
}

// writeItemsSpec writes an OpenAPI document with GET /items, POST /items and
// DELETE /items/{id}, served from base.
func writeItemsSpec(t *testing.T, base string) string {
	t.Helper()
	spec := fmt.Sprintf(`{
  "openapi": "3.0.0",
  "info": {"title": "items", "version": "1"},
  "servers": [{"url": %q}],
  "paths": {
    "/items": {
      "get": {"responses": {"200": {"description": "ok"}}},
      "post": {
        "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}}}},
        "responses": {"201": {"description": "created"}}
      }
    },
    "/items/{id}": {
      "delete": {
        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
        "responses": {"204": {"description": "deleted"}}
      }
    }
  }
}`, base)
	path := filepath.Join(t.TempDir(), "items.json")
	require.NoError(t, os.WriteFile(path, []byte(spec), 0o600))
	return path
}

// writes counts the state-changing requests in hits.
func writes(hits map[string]int) int {
	n := 0
	for k, v := range hits {
		if strings.HasPrefix(k, "POST ") || strings.HasPrefix(k, "PUT ") ||
			strings.HasPrefix(k, "PATCH ") || strings.HasPrefix(k, "DELETE ") {
			n += v
		}
	}
	return n
}

// openStore opens a scratch store for assertions.
func openStore(t *testing.T, path string) *database.Repository {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

// VS5 end to end: an OpenAPI spec ingested into a scratch store sends
// nothing (ingest no longer fetches), its operations land as templates under
// an ingest scan row carrying the caller tags, a scan over the store sends
// GET /items but no POST or DELETE and reports the held-back templates as a
// caveat, and the same scan with --allow-writes sends them.
func TestIngestedWriteTemplatesNeverReplayedWithoutAllowWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := methodCountingServer(t)
	home := a3Home(t, "127.0.0.1")
	dbPath := filepath.Join(t.TempDir(), "store.sqlite")
	spec := writeItemsSpec(t, srv.URL)

	code, stdout, stderr := runA3(t, home, "ingest", "-i", spec, "-I", "openapi", "--db", dbPath,
		"--caller-tag", "engagement=e1", "--caller-tag", "leg=ingest")
	require.Equal(t, 0, code, "ingest\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Empty(t, hits(), "ingest sends nothing without --fetch-responses")

	repo := openStore(t, dbPath)
	ctx := context.Background()
	records, err := repo.GetRecordsByHostname(ctx, database.DefaultProjectUUID, "127.0.0.1", 100)
	require.NoError(t, err)
	require.NotEmpty(t, records, "the spec's operations are stored")
	var methods []string
	for _, r := range records {
		methods = append(methods, r.Method)
		assert.NotNil(t, r.RequestOnlyAtStore, "%s %s is stored as a template", r.Method, r.Path)
		require.NotEmpty(t, r.ScanUUID, "%s %s carries the ingest's scan row", r.Method, r.Path)
		row, err := repo.GetScanByUUID(ctx, r.ScanUUID)
		require.NoError(t, err)
		assert.Equal(t, []string{"engagement=e1", "leg=ingest"}, row.Tags, "the ingest's scan row carries the caller tags")
		assert.Equal(t, "ingest", row.Name)
	}
	assert.Contains(t, methods, "POST")
	assert.Contains(t, methods, "DELETE")

	scanArgs := []string{"scan", "-t", srv.URL + "/", "--db", dbPath, "--only", "dynamic-assessment",
		"--passive-only", "--events", "ndjson", "--caller-tag", "leg=sweep"}
	code, stdout, stderr = runA3(t, home, scanArgs...)
	require.Equal(t, 0, code, "scan\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	got := hits()
	assert.Positive(t, got["GET /items"], "the GET template is assessed: %v", got)
	assert.Zero(t, writes(got), "no POST/DELETE template is sent without --allow-writes: %v", got)

	var started, finished map[string]any
	sc := bufio.NewScanner(strings.NewReader(stdout))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var ev map[string]any
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev["type"] {
		case "scan.started":
			started = ev
		case "scan.finished":
			finished = ev
		}
	}
	require.NotNil(t, started, "scan.started on the stream:\n%s", stdout)
	assert.Equal(t, map[string]any{"leg": "sweep"}, started["caller_tags"])
	require.NotNil(t, finished, "scan.finished on the stream:\n%s", stdout)
	raw, _ := json.Marshal(finished["caveats"])
	assert.Contains(t, string(raw), database.LimitTemplatesSkippedUnsafeMethod, "the held-back templates are a caveat")

	scans, _, err := repo.ListScans(ctx, "", 100, 0)
	require.NoError(t, err)
	var tagged bool
	for _, s := range scans {
		if s.Name == "cli-scan" && slices.Equal(s.Tags, []string{"leg=sweep"}) {
			tagged = true
		}
	}
	assert.True(t, tagged, "the scan row carries --caller-tag")

	code, stdout, stderr = runA3(t, home, "scan", "-t", srv.URL+"/", "--db", dbPath, "--only", "dynamic-assessment",
		"--passive-only", "--allow-writes")
	require.Equal(t, 0, code, "scan --allow-writes\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	got = hits()
	assert.Positive(t, got["POST /items"], "--allow-writes sends the POST template: %v", got)
	assert.Positive(t, writes(got)-got["POST /items"], "--allow-writes sends the DELETE template: %v", got)
}

// --caller-tag and VIGOLIUM_CALLER_TAG merge (a flag wins for its key) into
// sorted k=v strings; a malformed tag is refused.
func TestResolveCallerTags(t *testing.T) {
	got, err := resolveCallerTags("engagement=e1, leg=a", []string{"leg=b", "job=j-9"})
	require.NoError(t, err)
	assert.Equal(t, []string{"engagement=e1", "job=j-9", "leg=b"}, got)
	assert.Equal(t, map[string]string{"engagement": "e1", "job": "j-9", "leg": "b"}, callerTagMap(got))

	none, err := resolveCallerTags("", nil)
	require.NoError(t, err)
	assert.Nil(t, none)

	for _, bad := range []string{"noequals", "=v", "bad key=v", "k=" + strings.Repeat("x", 300), "k=a\nb"} {
		_, err := resolveCallerTags("", []string{bad})
		assert.Error(t, err, "%q is refused", bad)
	}
}
