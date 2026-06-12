package modkit

import "testing"

func TestIsStaticAssetContentType(t *testing.T) {
	t.Parallel()
	static := []string{
		"text/javascript",
		"application/javascript; charset=utf-8",
		"application/x-javascript",
		"text/css",
		"image/png",
		"image/svg+xml",
		"font/woff2",
		"application/font-woff",
		"video/mp4",
		"audio/mpeg",
		"application/wasm",
		"application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
	}
	for _, ct := range static {
		if !IsStaticAssetContentType(ct) {
			t.Errorf("IsStaticAssetContentType(%q) = false, want true", ct)
		}
	}

	notStatic := []string{
		"",
		"application/json",
		"application/json; charset=utf-8",
		"text/html",
		"text/plain",
		"application/xml",
		"text/event-stream",
		"application/vnd.api+json",
	}
	for _, ct := range notStatic {
		if IsStaticAssetContentType(ct) {
			t.Errorf("IsStaticAssetContentType(%q) = true, want false", ct)
		}
	}
}

func TestIsStaticAssetPath(t *testing.T) {
	t.Parallel()
	static := []string{
		"/css/images", "/assets/app", "/static/main", "/js/vendor",
		"/img/logo", "/bundles/app.css", "/x/y.png", "/_next/data/x",
		"/wp-content/uploads/file", "/fonts/inter", "/MEDIA/clip",
		"/app.js", "/styles/site",
	}
	for _, p := range static {
		if !IsStaticAssetPath(p) {
			t.Errorf("IsStaticAssetPath(%q) = false, want true", p)
		}
	}
	dynamic := []string{
		"/account/profile", "/api/me", "/dashboard", "/blog/post-1",
		"/", "/users/123", "/cssselector", "/imagine",
	}
	for _, p := range dynamic {
		if IsStaticAssetPath(p) {
			t.Errorf("IsStaticAssetPath(%q) = true, want false", p)
		}
	}
}
