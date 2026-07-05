package discovery

import (
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/discovery/payload"
	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
)

// TestExtractPathFromURL_PreservesEscapedBypass is a regression test for a
// path-normalization bypass template ("/%23/../FUZZ"). extractPathFromURL used to
// return the DECODED url.Path, turning "/%23/../" into "/#/../"; the "#" is a URL
// fragment delimiter, so any downstream re-parse for dedup collapsed every word to
// the root. It must now return the escaped (wire) path so "%23" survives.
func TestExtractPathFromURL_PreservesEscapedBypass(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://host/%23/../", "/%23/../"},
		{"https://host/%23/../FUZZ", "/%23/../FUZZ"},
		{"https://host/%2e%2e/", "/%2e%2e/"},
		{"https://host/..%2f", "/..%2f"},
		// Ordinary paths are unchanged (EscapedPath == Path).
		{"https://host/api/v1/", "/api/v1/"},
		{"https://host/", "/"},
		{"https://host", "/"},
		// Bare paths (no scheme/host) pass through untouched.
		{"/already/a/path", "/already/a/path"},
	}
	for _, c := range cases {
		if got := extractPathFromURL(c.in); got != c.want {
			t.Errorf("extractPathFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestWordlistTask_BypassBaseEmitsEscapedDistinctURLs verifies the end-to-end
// effect: a wordlist task built off an escaped bypass directory emits an escaped
// "/%23/../<word>" URL per word, and each normalizes to a DISTINCT dedup key (the
// bug collapsed the whole wordlist to one key, so only the first word was probed).
func TestWordlistTask_BypassBaseEmitsEscapedDistinctURLs(t *testing.T) {
	words := []string{"metrics", "admin.js", "health"}
	task := NewWordlistTask(&WordlistTaskConfig{
		TaskType:   ShortFilesNoExt,
		Provider:   payload.NewMockProvider(words...),
		SchemeHost: []byte("https://host"),
		Path:       []byte("/%23/../"), // escaped bypass dir, as extractPathFromURL now yields
		Depth:      0,
	})

	var urls []string
	err := task.Expand(context.Background(), func(u string, _ uint16) { urls = append(urls, u) })
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if len(urls) != len(words) {
		t.Fatalf("got %d urls, want %d: %v", len(urls), len(words), urls)
	}

	keys := make(map[string]string, len(urls))
	for i, u := range urls {
		// The escaped bypass prefix must be preserved on the wire.
		if !strings.Contains(u, "/%23/../") {
			t.Errorf("url %q lost the escaped bypass prefix", u)
		}
		if !strings.HasSuffix(u, words[i]) {
			t.Errorf("url %q does not end with word %q", u, words[i])
		}
		// And each word must dedupe distinctly (no collapse to root).
		k := dedup.HashRequest("GET", u, "")
		if prev, dup := keys[k]; dup {
			t.Fatalf("words produced the same dedup key: %q and %q -> %q", prev, u, k)
		}
		keys[k] = u
	}
}
