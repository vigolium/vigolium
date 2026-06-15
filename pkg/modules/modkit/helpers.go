package modkit

import "strings"

// Truncate shortens a string to maxLen, appending "..." if truncated.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// IsJSOrTSContentType returns true if the content type indicates JavaScript or TypeScript.
func IsJSOrTSContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "typescript") ||
		strings.Contains(ct, "ecmascript")
}

// staticAssetContentTypes are response Content-Type fragments served by static
// assets and binary payloads — scripts, styles, fonts, images, media, archives.
// App-level signals (error strings, secrets, tech fingerprints, JSON-RPC method
// names, ...) found by substring/regex matching inside such bodies are almost
// always incidental: a token baked into a minified bundle, not a live signal.
// Body-matching detectors should skip these. This complements the URL-based
// utils.IsMediaAndJSURL, which only inspects the path extension and therefore
// misses assets served at extensionless or query-only routes — e.g. an SSO
// gateway returning text/javascript for /assets/index-*, the canonical source
// of false positives this gate exists to stop.
var staticAssetContentTypes = []string{
	"javascript",
	"typescript",
	"ecmascript",
	"text/css",
	"font/",
	"application/font",
	"image/",
	"audio/",
	"video/",
	"application/wasm",
	"application/octet-stream",
	"application/pdf",
	"application/zip",
	"application/gzip",
	"application/x-gzip",
}

// IsStaticAssetContentType reports whether the Content-Type header value belongs
// to a static asset / binary payload (script, style, font, image, media,
// archive) — content where a substring/regex match of an application-level
// signal is not trustworthy evidence. An empty/unknown content type returns
// false, so callers that depend on body inspection still run when the server
// omits the header. Parameters (e.g. "; charset=utf-8") are ignored.
func IsStaticAssetContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	for _, frag := range staticAssetContentTypes {
		if strings.Contains(ct, frag) {
			return true
		}
	}
	return false
}

// staticAssetExtensions are file-extension suffixes that mark a static asset or
// binary payload by URL path.
var staticAssetExtensions = []string{
	".js", ".mjs", ".cjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".map",
	".mp4", ".webm", ".mp3", ".ogg", ".wav",
	".pdf", ".zip", ".gz", ".br",
}

// staticAssetDirSegments are path segments that mark a static-asset route even
// when the URL carries no file extension (e.g. /css/images, /assets/app). A
// suffix-only extension test misses these, so any path containing one of these
// segments is treated as a static asset.
var staticAssetDirSegments = map[string]bool{
	"css": true, "js": true, "javascript": true, "scripts": true,
	"styles": true, "stylesheets": true, "images": true, "image": true,
	"img": true, "imgs": true, "assets": true, "asset": true,
	"static": true, "fonts": true, "font": true, "media": true,
	"dist": true, "build": true, "vendor": true, "public": true,
	"_next": true, "_nuxt": true, "wp-content": true,
}

// IsStaticAssetPath reports whether a URL path is a static-asset route, by
// file-extension suffix OR by containing a known static directory segment
// (e.g. /css/images has no extension but both segments are static). The segment
// check catches extensionless asset routes that a suffix-only test misses. This
// is the URL-path companion to IsStaticAssetContentType (header-based).
func IsStaticAssetPath(path string) bool {
	if HasStaticAssetExtension(path) {
		return true
	}
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		if seg != "" && staticAssetDirSegments[seg] {
			return true
		}
	}
	return false
}

// HasStaticAssetExtension reports whether a URL path ends in a known static-asset
// file extension (.js, .css, .map, fonts, images, archives, ...). Unlike
// IsStaticAssetPath it does NOT match by directory segment, so it won't classify
// an HTML document served from /assets/ or /public/ as static. Use it where
// precision matters — e.g. deciding whether to truncate a stored response body.
func HasStaticAssetExtension(path string) bool {
	p := strings.ToLower(path)
	for _, ext := range staticAssetExtensions {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// JSExtensions are file extensions for JavaScript/TypeScript source files.
var JSExtensions = []string{".js", ".ts", ".jsx", ".tsx"}

// JSExtensionsExtended includes JS/TS plus framework-specific file extensions.
var JSExtensionsExtended = []string{".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}

// HasJSExtension returns true if the URL path ends with a JS/TS extension.
func HasJSExtension(pathLower string) bool {
	for _, ext := range JSExtensions {
		if strings.HasSuffix(pathLower, ext) {
			return true
		}
	}
	return false
}
