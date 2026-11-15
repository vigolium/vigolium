package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A raw request to a plain-HTTP host, piped with its final blank line
// stripped, is parsed and sent over http (probed), not assumed https.
func TestReplayRawRequestSchemeAndTerminator(t *testing.T) {
	srv, hits := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	host := strings.TrimPrefix(srv.URL, "http://")
	raw := "GET /r?id=1 HTTP/1.1\r\nHost: " + host // no terminator

	code, stdout, stderr := runA3Stdin(t, home, raw, "replay", "-i", "-", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, int64(1), hits.Load(), "sent once, over plain http")
	var doc struct {
		OK    bool `json:"ok"`
		Items []struct {
			Target string `json:"target"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc), stdout)
	require.Len(t, doc.Items, 1)
	assert.True(t, doc.OK)
	assert.True(t, strings.HasPrefix(doc.Items[0].Target, "http://"), doc.Items[0].Target)
}

// ingest -I burpraw -t rebases the captured request onto -t instead of
// storing -t as a record of its own.
func TestIngestBurpRawRebasesOnTarget(t *testing.T) {
	srv, _ := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	db := filepath.Join(t.TempDir(), "i.sqlite")
	reqFile := filepath.Join(t.TempDir(), "req.txt")
	require.NoError(t, os.WriteFile(reqFile, []byte("GET /captured?x=1 HTTP/1.1\r\nHost: prod.example.com\r\n\r\n"), 0o600))

	code, stdout, stderr := runA3(t, home, "ingest", "-i", reqFile, "-I", "burpraw", "-t", srv.URL, "--db", db)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	code, stdout, stderr = runA3(t, home, "traffic", "--db", db, "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	var doc struct {
		Items []struct {
			URL string `json:"url"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc), stdout)
	require.Len(t, doc.Items, 1, "one record: the rebased request, not -t as well: %s", stdout)
	assert.True(t, strings.HasPrefix(doc.Items[0].URL, srv.URL+"/captured"), doc.Items[0].URL)
}

func TestURLShapedPositional(t *testing.T) {
	for v, want := range map[string]bool{
		"http://h/item?id=1": true,
		"/admin":             true,
		"item?id=1":          true,
		"admin":              false,
		"sessionid":          false,
		"a?b":                false,
	} {
		assert.Equal(t, want, urlShapedPositional(v), v)
	}
}

// replay <url> is refused with the -i form; a bulk selection matching several
// records needs --all-matches.
func TestReplayPositionalAndAllMatches(t *testing.T) {
	srv, hits := countingServer(t)
	home := a3Home(t, "127.0.0.1")
	db := filepath.Join(t.TempDir(), "r.sqlite")
	for _, p := range []string{"/a", "/b"} {
		code, stdout, stderr := runA3(t, home, "ingest", "-t", srv.URL+p, "--db", db)
		require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	before := hits.Load()

	code, stdout, _ := runA3(t, home, "replay", srv.URL+"/a", "--db", db, "-j")
	assert.Equal(t, ExitUsageError, code)
	assert.Contains(t, stdout, "replay -i")

	code, stdout, _ = runA3(t, home, "replay", "--host", "127.0.0.1", "--db", db, "-j")
	assert.Equal(t, ExitUsageError, code, stdout)
	assert.Contains(t, stdout, "--all-matches")
	assert.Equal(t, before, hits.Load(), "nothing sent")

	code, stdout, stderr := runA3(t, home, "replay", "--host", "127.0.0.1", "--db", db, "-j", "--all-matches")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, before+2, hits.Load())
}

// -t rewrites a Host header that named the old destination; any other Host,
// or --keep-host, is sent as written.
func TestApplyTargetOverrideHost(t *testing.T) {
	mk := func(host string) *replaySource {
		return &replaySource{Scheme: "https", Hostname: "prod.example.com", Port: 443,
			BaselineRequest: []byte("GET /x HTTP/1.1\r\nHost: " + host + "\r\n\r\n")}
	}
	src := mk("prod.example.com")
	require.NoError(t, applyTargetOverride(src, "http://127.0.0.1:8080", false))
	assert.Equal(t, "127.0.0.1:8080", rawHostHeader(src.BaselineRequest))
	assert.Equal(t, "http", src.Scheme)

	src = mk("prod.example.com")
	require.NoError(t, applyTargetOverride(src, "http://127.0.0.1:8080", true))
	assert.Equal(t, "prod.example.com", rawHostHeader(src.BaselineRequest), "--keep-host")

	src = mk("internal.vhost")
	require.NoError(t, applyTargetOverride(src, "http://127.0.0.1:8080", false))
	assert.Equal(t, "internal.vhost", rawHostHeader(src.BaselineRequest), "a deliberate vhost is kept")
}
