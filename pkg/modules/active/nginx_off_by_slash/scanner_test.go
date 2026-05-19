package nginx_off_by_slash

import (
	"testing"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, "nginx-off-by-slash", m.ID())
	assert.Equal(t, "Nginx Off-by-Slash", m.Name())
	assert.Equal(t, severity.High, m.Severity())
	assert.Equal(t, severity.Tentative, m.Confidence())
	assert.Equal(t, modkit.ScanScopeRequest, m.ScanScopes())
}

func TestModuleInjections(t *testing.T) {
	m := New()
	assert.Equal(t, []string{"..", "..;", "..%3B"}, m.injections)
}

func TestModuleSuffixes(t *testing.T) {
	m := New()
	assert.Greater(t, len(m.suffixes), 50, "expected at least 50 suffixes")
	assert.Contains(t, m.suffixes, "static")
	assert.Contains(t, m.suffixes, "etc/passwd")
	assert.Contains(t, m.suffixes, "assets")
}

func TestFirstPathSegment(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple path",
			path: "/static/js/app.js",
			want: "static",
		},
		{
			name: "single segment",
			path: "/images/",
			want: "images",
		},
		{
			name: "root path",
			path: "/",
			want: "",
		},
		{
			name: "empty path",
			path: "",
			want: "",
		},
		{
			name: "deep path",
			path: "/api/v1/users/123",
			want: "api",
		},
		{
			name: "path with leading double slash",
			path: "//static/file.css",
			want: "static",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstPathSegment(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetChecksum(t *testing.T) {
	urlx := parseTestURL(t, "https://example.com/static/file.css")

	c1 := getChecksum(urlx, "static")
	c2 := getChecksum(urlx, "static")
	assert.Equal(t, c1, c2, "same inputs should produce same checksum")

	c3 := getChecksum(urlx, "assets")
	assert.NotEqual(t, c1, c3, "different segments should produce different checksums")
}

func parseTestURL(t *testing.T, raw string) *urlutil.URL {
	t.Helper()
	u, err := urlutil.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", raw, err)
	}
	return u
}
