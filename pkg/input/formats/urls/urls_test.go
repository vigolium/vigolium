package urls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// writeTestFile writes content to a temp file and returns its path.
func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "urls.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestName(t *testing.T) {
	assert.Equal(t, "urls", New().Name())
}

func TestParse_MultipleURLs(t *testing.T) {
	content := "http://example.com/a\nhttps://example.com:8443/b\nhttp://localhost:8080/c\n"
	tmpFile := writeTestFile(t, content)

	f := New()
	var results []*httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 3)

	assert.Equal(t, "GET", results[0].Request().Method())
	assert.Equal(t, "example.com", results[0].Service().Host())
	assert.Equal(t, 8443, results[1].Service().Port())
	assert.Contains(t, string(results[2].Request().Raw()), "/c")
}

func TestParse_BlankLinesSkipped(t *testing.T) {
	content := "\nhttp://example.com/a\n\n   \nhttp://example.com/b\n\n"
	tmpFile := writeTestFile(t, content)

	f := New()
	var count int
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		count++
		return true
	})

	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestParse_MalformedURLSkipped(t *testing.T) {
	// A line that cannot be turned into a raw request is logged and skipped,
	// while the valid URL is still emitted.
	content := "http://example.com/ok\n://not-a-url\n"
	tmpFile := writeTestFile(t, content)

	f := New()
	var results []*httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "example.com", results[0].Service().Host())
}

func TestParse_MissingFile(t *testing.T) {
	f := New()
	err := f.Parse(filepath.Join(t.TempDir(), "does-not-exist.txt"), func(rr *httpmsg.HttpRequestResponse) bool {
		return true
	})
	assert.Error(t, err)
}

func TestCount(t *testing.T) {
	content := "http://example.com/a\n\nhttp://example.com/b\n   \nhttp://example.com/c\n"
	tmpFile := writeTestFile(t, content)

	count, err := New().Count(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestCount_MissingFile(t *testing.T) {
	_, err := New().Count(filepath.Join(t.TempDir(), "nope.txt"))
	assert.Error(t, err)
}
