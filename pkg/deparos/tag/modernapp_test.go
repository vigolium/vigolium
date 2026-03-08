package tag

import (
	"testing"
)

func TestModernAppMatcher_Match(t *testing.T) {
	matcher := NewModernAppMatcher()

	tests := []struct {
		name      string
		path      string
		mimeType  string
		body      string
		wantMatch bool
	}{
		// Path filtering tests
		{
			name:      "root path with Next.js",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script id="__NEXT_DATA__" type="application/json">`,
			wantMatch: true,
		},
		{
			name:      "empty path with Next.js",
			path:      "",
			mimeType:  "text/html",
			body:      `<script id="__NEXT_DATA__" type="application/json">`,
			wantMatch: true,
		},
		{
			name:      "path without extension with React",
			path:      "/app",
			mimeType:  "text/html",
			body:      `<script>window.__REACT_DEVTOOLS_GLOBAL_HOOK__</script>`,
			wantMatch: true,
		},
		{
			name:      "path ending with slash with Vue",
			path:      "/dashboard/",
			mimeType:  "text/html",
			body:      `<script>window.__VUE__</script>`,
			wantMatch: true,
		},
		{
			name:      "deep path without extension",
			path:      "/dashboard/settings",
			mimeType:  "text/html",
			body:      `<script src="/_next/static/chunks/main.js"></script>`,
			wantMatch: true,
		},
		{
			name:      "path with js extension - should NOT match",
			path:      "/app.js",
			mimeType:  "text/html",
			body:      `<script id="__NEXT_DATA__">`,
			wantMatch: false,
		},
		{
			name:      "path with php extension - should NOT match",
			path:      "/api.php",
			mimeType:  "text/html",
			body:      `<script>window.__NUXT__</script>`,
			wantMatch: false,
		},
		{
			name:      "path with html extension - should NOT match",
			path:      "/page.html",
			mimeType:  "text/html",
			body:      `<script>window.__VUE__</script>`,
			wantMatch: false,
		},
		{
			name:      "deep path with extension - should NOT match",
			path:      "/path/to/file.css",
			mimeType:  "text/html",
			body:      `<script id="__NEXT_DATA__">`,
			wantMatch: false,
		},

		// Framework detection tests
		{
			name:      "Next.js __NEXT_DATA__",
			path:      "/",
			mimeType:  "text/html",
			body:      `<!DOCTYPE html><html><head></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script></body></html>`,
			wantMatch: true,
		},
		{
			name:      "Next.js static path",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script src="/_next/static/chunks/main-abc123.js"></script>`,
			wantMatch: true,
		},
		{
			name:      "React devtools hook",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script>if(window.__REACT_DEVTOOLS_GLOBAL_HOOK__)console.log('React')</script>`,
			wantMatch: true,
		},
		{
			name:      "React production bundle",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script src="/static/js/react.production.min.js"></script>`,
			wantMatch: true,
		},
		{
			name:      "Angular ng-version",
			path:      "/",
			mimeType:  "text/html",
			body:      `<html ng-version="15.0.0"><body><app-root></app-root></body></html>`,
			wantMatch: true,
		},
		{
			name:      "Angular ng-app",
			path:      "/",
			mimeType:  "text/html",
			body:      `<html ng-app="myApp"><body></body></html>`,
			wantMatch: true,
		},
		{
			name:      "Vue __VUE__",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script>window.__VUE__={}</script>`,
			wantMatch: true,
		},
		{
			name:      "Nuxt.js __NUXT__",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script>window.__NUXT__={}</script>`,
			wantMatch: true,
		},
		{
			name:      "Nuxt.js path",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script src="/_nuxt/entry.abc123.js"></script>`,
			wantMatch: true,
		},
		{
			name:      "SvelteKit",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script>__sveltekit.start()</script>`,
			wantMatch: true,
		},
		{
			name:      "SvelteKit app path",
			path:      "/",
			mimeType:  "text/html",
			body:      `<script type="module" src="/_app/immutable/entry/start.js"></script>`,
			wantMatch: true,
		},

		// Negative cases
		{
			name:      "static HTML - no framework",
			path:      "/",
			mimeType:  "text/html",
			body:      `<!DOCTYPE html><html><head><title>Static Page</title></head><body><h1>Hello World</h1></body></html>`,
			wantMatch: false,
		},
		{
			name:      "JSON response - should NOT match",
			path:      "/api/data",
			mimeType:  "application/json",
			body:      `{"__NEXT_DATA__": "fake"}`,
			wantMatch: false,
		},
		{
			name:      "empty body",
			path:      "/",
			mimeType:  "text/html",
			body:      "",
			wantMatch: false,
		},
		{
			name:      "WordPress site",
			path:      "/",
			mimeType:  "text/html",
			body:      `<!DOCTYPE html><html><head><link rel="stylesheet" href="/wp-content/themes/style.css"></head><body></body></html>`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &MatchInput{
				RequestPath:  tt.path,
				MIMEType:     tt.mimeType,
				ResponseBody: []byte(tt.body),
			}
			got := matcher.Match(input)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestModernAppMatcher_Tag(t *testing.T) {
	matcher := NewModernAppMatcher()
	if matcher.Tag() != TagModernApp {
		t.Errorf("Tag() = %v, want %v", matcher.Tag(), TagModernApp)
	}
}

func TestIsValidModernAppPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/", true},
		{"", true},
		{"/app", true},
		{"/dashboard", true},
		{"/dashboard/settings", true},
		{"/app/", true},
		{"/api/v1/", true},
		{"/deep/nested/path/", true},
		{"/app.js", false},
		{"/api.php", false},
		{"/file.html", false},
		{"/path/to/file.css", false},
		{"/static/main.chunk.js", false},
		{"/assets/style.css", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isValidModernAppPath(tt.path)
			if got != tt.want {
				t.Errorf("isValidModernAppPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsHTMLResponse(t *testing.T) {
	tests := []struct {
		mimeType string
		want     bool
	}{
		{"text/html", true},
		{"text/html; charset=utf-8", true},
		{"application/xhtml+xml", true},
		{"", true}, // Assume HTML if unknown
		{"application/json", false},
		{"text/javascript", false},
		{"text/css", false},
		{"image/png", false},
	}

	for _, tt := range tests {
		t.Run(tt.mimeType, func(t *testing.T) {
			got := isHTMLResponse(tt.mimeType)
			if got != tt.want {
				t.Errorf("isHTMLResponse(%q) = %v, want %v", tt.mimeType, got, tt.want)
			}
		})
	}
}
