package spider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsHTMLParseableContentType(t *testing.T) {
	cases := map[string]bool{
		"":                              true, // unknown → lenient, parse
		"text/html":                     true,
		"text/html; charset=utf-8":      true,
		"application/xhtml+xml":         true,
		"text/xml":                      true,
		"application/xml":               true,
		"text/plain":                    true, // other text/* → lenient
		"application/json":              false,
		"application/json; charset=utf": false,
		"text/javascript":               false,
		"application/javascript":        false,
		"text/css":                      false,
		"image/png":                     false,
		"font/woff2":                    false,
		"video/mp4":                     false,
		"application/octet-stream":      false,
		"application/pdf":               false,
		"application/grpc":              false,
		"application/wasm":              false,
	}
	for ct, want := range cases {
		if got := isHTMLParseableContentType(ct); got != want {
			t.Errorf("isHTMLParseableContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}

// TestNonHTMLSkipsDOMExtraction proves the state the MIME gate produces: a
// response marked not-HTML (HTML=nil) skips the DOM-dependent extractors (no
// <a href> harvested) while the raw-bytes inline scanner still runs (absolute
// URLs inside the body are still discovered).
func TestNonHTMLSkipsDOMExtraction(t *testing.T) {
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	// A body that LOOKS like HTML but is served as JSON: the <a href> must NOT be
	// harvested (parser skipped), but the absolute URL must still be found.
	body := `{"html":"<a href=\"/should-not-appear\">x</a>","cb":"https://api.example.com/v1/orders"}`

	// This is exactly what the coordinator builds for a non-HTML content type.
	response := NewHTTPResponseWithHTML(baseURL, map[string][]string{}, []byte(body), 0, nil, ErrNotHTMLContentType)

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)
	require.NoError(t, err)

	var paths []string
	for _, l := range result.Links {
		paths = append(paths, l.String())
	}
	assert.Contains(t, paths, "https://api.example.com/v1/orders",
		"inline scanner must still surface absolute URLs from non-HTML bodies")
	assert.NotContains(t, paths, "https://example.com/should-not-appear",
		"DOM extraction must be skipped for non-HTML bodies (no <a href> harvest)")
}
