package nuclei

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// nuclei JSONL output: one JSON object per line. The first entry carries a raw
// request, the second only a URL.
const testJSONL = `{"url":"http://example.com/api/users","request":{"raw":"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"}}
{"url":"https://example.com:8443/health"}
`

// writeTestFile writes content to a temp file with the given name suffix.
func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestName(t *testing.T) {
	assert.Equal(t, "nuclei", New().Name())
}

func TestParse_JSONL(t *testing.T) {
	tmpFile := writeTestFile(t, "out.jsonl", testJSONL)

	f := New()
	var results []*httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 2)

	// First entry was built from raw request.
	assert.Equal(t, "GET", results[0].Request().Method())
	assert.Equal(t, "example.com", results[0].Service().Host())
	assert.Contains(t, string(results[0].Request().Raw()), "/api/users")

	// Second entry was built from the URL alone.
	assert.Equal(t, "example.com", results[1].Service().Host())
	assert.Equal(t, 8443, results[1].Service().Port())
}

func TestParse_SkipsEntriesWithoutURL(t *testing.T) {
	content := `{"request":{"raw":"GET / HTTP/1.1\r\nHost: x\r\n\r\n"}}
{"url":"http://example.com/ok"}
`
	tmpFile := writeTestFile(t, "out.jsonl", content)

	f := New()
	var count int
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		count++
		return true
	})

	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestParse_Gzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write([]byte(testJSONL))
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	tmpFile := writeTestFile(t, "out.jsonl.gz", "")
	require.NoError(t, os.WriteFile(tmpFile, buf.Bytes(), 0644))

	f := New()
	var count int
	err = f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		count++
		return true
	})

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestParse_GzipInvalid(t *testing.T) {
	// File has .gz suffix but is not gzip data.
	tmpFile := writeTestFile(t, "bad.gz", "not gzip content")

	f := New()
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool { return true })
	assert.Error(t, err)
}

func TestParse_MissingFile(t *testing.T) {
	f := New()
	err := f.Parse(filepath.Join(t.TempDir(), "nope.jsonl"), func(rr *httpmsg.HttpRequestResponse) bool {
		return true
	})
	assert.Error(t, err)
}

func TestCount(t *testing.T) {
	tmpFile := writeTestFile(t, "out.jsonl", testJSONL)

	count, err := New().Count(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestCount_Gzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write([]byte(testJSONL))
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	tmpFile := filepath.Join(t.TempDir(), "out.jsonl.gz")
	require.NoError(t, os.WriteFile(tmpFile, buf.Bytes(), 0644))

	count, err := New().Count(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}
