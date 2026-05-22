package burpraw

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
)

// writeTestFile writes content to a temp file and returns its path.
func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "burp.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestName(t *testing.T) {
	assert.Equal(t, "burpraw", New().Name())
}

func TestParse_RequestOnly(t *testing.T) {
	raw := "GET /api/users HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Accept: application/json\r\n\r\n"
	tmpFile := writeTestFile(t, raw)

	f := New()
	var results []*httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 1)

	req := results[0].Request()
	assert.Equal(t, "GET", req.Method())
	assert.Equal(t, "example.com", results[0].Service().Host())
	assert.Contains(t, string(req.Raw()), "/api/users")
	assert.False(t, results[0].HasResponse())
}

func TestParse_RequestAndResponse(t *testing.T) {
	content := "POST /api/login HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 16\r\n\r\n" +
		`{"u":"a","p":"b"}` + "\r\n" +
		"***\r\n" +
		"HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"token":"xyz"}`
	tmpFile := writeTestFile(t, content)

	f := New()
	var results []*httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 1)

	req := results[0].Request()
	assert.Equal(t, "POST", req.Method())
	assert.Contains(t, string(req.Raw()), "/api/login")

	require.True(t, results[0].HasResponse())
	assert.Contains(t, string(results[0].Response().Raw()), "xyz")
}

func TestParse_EmptyFile(t *testing.T) {
	tmpFile := writeTestFile(t, "")

	f := New()
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool { return true })
	assert.Error(t, err)
}

func TestParse_MissingFile(t *testing.T) {
	f := New()
	err := f.Parse(filepath.Join(t.TempDir(), "nope.txt"), func(rr *httpmsg.HttpRequestResponse) bool {
		return true
	})
	assert.Error(t, err)
}

func TestSetOptions(t *testing.T) {
	f := New()
	f.SetOptions(formats.InputFormatOptions{SkipFormatValidation: true})
	assert.True(t, f.formatOpts.SkipFormatValidation)
}

func TestCount(t *testing.T) {
	count, err := New().Count("anything")
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}
