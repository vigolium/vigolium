package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// The input contract across ingest, replay and fuzz: each case is a form that
// used to fail, asserted to work now, and each error asserted to name the flag
// that fixes it. Driven through the real CLI in a child process (b5Env).

// burpPair is a raw request + "***" + response, the shape ingest stores
// without a refetch.
func burpPair(host, path string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n***\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
}

func TestIngestDirIsInput(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	e := newB5Env(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte(burpPair("dir.example", "/one")), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "skip.log"), []byte("not matched"), 0o600))

	// One matching file: it used to fail the blank-input check, and once past
	// it, to be replaced by the (empty) -i value.
	code, stdout, stderr := e.run(t, nil, "ingest", "--dir", dir, "--dir-glob", "*.txt", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	assert.EqualValues(t, 1, doc["records_ingested"])
	items, ok := doc["items"].([]any)
	require.True(t, ok)
	require.Len(t, items, 1, "ingest -j lists the record it stored")
	rec := items[0].(map[string]any)
	assert.Equal(t, "GET", rec["method"])
	assert.Contains(t, rec["url"], "dir.example/one")
	assert.Len(t, rec["uuid_short"], uuidShortLen)

	// Two matching files: a batch.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte(burpPair("dir.example", "/two")), 0o600))
	code, stdout, stderr = e.run(t, nil, "ingest", "--dir", dir, "--dir-glob", "*.txt", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.EqualValues(t, 2, oneDoc(t, stdout, stderr)["records_ingested"])
}

func TestIngestNoInputNamesDir(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "ingest", "-j")
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Contains(t, stdout+stderr, "--dir")
}

// blockingServer answers every request the way a Cloudflare block does.
func blockingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>Attention Required! | Cloudflare</html>"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestIngestNamesBlockedRecordsAndKeepsThemOnRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, _ := blockingServer(t)
	e := newB5Env(t)
	list := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(list, []byte(srv.URL+"/a\n"+srv.URL+"/b\n"), 0o600))

	code, stdout, stderr := e.run(t, nil, "ingest", "-i", list, "-j")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Contains(t, stdout+stderr, "blocked 2")
	assert.Contains(t, stdout+stderr, "--keep-blocked", "the error names the flag that fixes it")

	code, stdout, stderr = e.run(t, nil, "ingest", "-i", list, "--keep-blocked", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	assert.EqualValues(t, 2, doc["records_ingested"])

	// The kept pages carry the remark that says what they are.
	code, stdout, stderr = e.run(t, nil, "traffic", "-j", "--compact", "--fields", "url,remarks")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Contains(t, stdout, "blocked:")
}

func TestReplayRawRequestFileIsASource(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := countingServer(t)
	e := newB5Env(t)
	raw := filepath.Join(t.TempDir(), "req.txt")
	host := strings.TrimPrefix(srv.URL, "http://")
	require.NoError(t, os.WriteFile(raw, []byte("GET /raw HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), 0o600))

	code, stdout, stderr := e.run(t, nil, "replay", "--raw-request-file", raw, "-t", srv.URL, "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Positive(t, hits.Load())
}

func TestReplayAndFuzzInputAcceptsAPath(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := countingServer(t)
	e := newB5Env(t)
	req := filepath.Join(t.TempDir(), "req.txt")
	require.NoError(t, os.WriteFile(req, []byte("curl '"+srv.URL+"/p?id=1'"), 0o600))

	code, stdout, stderr := e.run(t, nil, "replay", "-i", req, "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Contains(t, stderr, "--input-file is the explicit form")
	before := hits.Load()
	assert.Positive(t, before)

	code, stdout, stderr = e.run(t, nil, "fuzz", "-i", req, "-p", "x", "--fuzz", "params", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Greater(t, hits.Load(), before)
}

func TestReplayUnparsedInputNamesRealFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	e := newB5Env(t)
	code, stdout, stderr := e.run(t, nil, "replay", "-i", "no-such-file-and-not-a-request", "-j")
	require.Equal(t, 1, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeInputUnparsed), errorCode(t, stdout))
	assert.Contains(t, stdout, "--input-file")
	assert.NotContains(t, stdout+stderr, "--input-type", "replay has no --input-type flag")
}
