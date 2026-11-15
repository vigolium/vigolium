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
