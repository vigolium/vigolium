package discovery

import (
	"net/url"
	"testing"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestNextJSManifestURLs(t *testing.T) {
	base := mustParseURL(t, "https://app.example.com/dashboard")

	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "buildId from __NEXT_DATA__",
			body: `<html><body><script id="__NEXT_DATA__" type="application/json">` +
				`{"buildId":"AbC123","props":{}}</script></body></html>`,
			want: []string{
				"https://app.example.com/_next/static/AbC123/_buildManifest.js",
				"https://app.example.com/_next/static/AbC123/_ssgManifest.js",
			},
		},
		{
			name: "buildId from referenced _buildManifest.js script src",
			body: `<html><head>` +
				`<script src="/_next/static/xY9-hash/_buildManifest.js" defer></script>` +
				`</head><body>app</body></html>`,
			want: []string{
				"https://app.example.com/_next/static/xY9-hash/_buildManifest.js",
				"https://app.example.com/_next/static/xY9-hash/_ssgManifest.js",
			},
		},
		{
			name: "not a Next.js page",
			body: `<html><body><h1>Plain old site</h1></body></html>`,
			want: nil,
		},
		{
			name: "next markers present but no derivable buildId",
			body: `<html><head><link href="/_next/static/css/app.css"></head><body>x</body></html>`,
			want: nil,
		},
		{
			name: "empty body",
			body: ``,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextJSManifestURLs(base, []byte(tt.body))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d urls %v, want %d %v", len(got), urlStrings(got), len(tt.want), tt.want)
			}
			for i, u := range got {
				if u.String() != tt.want[i] {
					t.Errorf("url[%d] = %q, want %q", i, u.String(), tt.want[i])
				}
			}
		})
	}
}

func TestNextJSManifestURLsNilBase(t *testing.T) {
	if got := nextJSManifestURLs(nil, []byte(`{"buildId":"x"}`)); got != nil {
		t.Errorf("nil base: got %v, want nil", urlStrings(got))
	}
}

func urlStrings(us []*url.URL) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.String()
	}
	return out
}

func TestDeriveAppRouterRoutes(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{"root page", "/_next/static/chunks/app/page-abc.js", []string{"/"}},
		{"nested page", "static/chunks/app/dashboard/settings/page-9f3c.js", []string{"/dashboard/settings"}},
		{"route group stripped", "static/chunks/app/(marketing)/about/page-x.js", []string{"/about"}},
		{"parallel slot stripped", "static/chunks/app/@modal/photo/page-z.js", []string{"/photo"}},
		{"route handler (api)", "static/chunks/app/api/users/route-y.js", []string{"/api/users"}},
		{"dynamic segment normalized", "static/chunks/app/blog/[slug]/page-d.js", []string{"/blog/1"}},
		{"catch-all normalized", "static/chunks/app/docs/[...slug]/page-x.js", []string{"/docs/1"}},
		{"page without hash", "static/chunks/app/profile/page.js", []string{"/profile"}},

		{"layout is not a route", "static/chunks/app/dashboard/layout-x.js", nil},
		{"loading is not a route", "static/chunks/app/dashboard/loading-x.js", nil},
		{"private folder excluded", "static/chunks/app/_components/widget/page-z.js", nil},
		{"pages-router chunk ignored", "static/chunks/pages/about-x.js", nil},
		{"webpack runtime ignored", "static/chunks/webpack-abc.js", nil},
		{"plain route ignored", "/dashboard", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveAppRouterRoutes(tt.path)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("route[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
