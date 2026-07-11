package http

import (
	"path"
	"strings"
)

// Media MIME type prefixes to exclude from body storage
var mediaTypePrefixes = []string{
	"image/",
	"audio/",
	"video/",
	"font/",
}

// Specific MIME types to exclude
var excludedMIMETypes = map[string]bool{
	"application/octet-stream":      true,
	"application/font-woff":         true,
	"application/font-woff2":        true,
	"application/x-font-ttf":        true,
	"application/x-font-otf":        true,
	"application/vnd.ms-fontobject": true,
	"text/css":                      true,
}

// Media file extensions to exclude (lowercase, with dot)
var excludedExtensions = map[string]bool{
	// Images
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".svg": true, ".ico": true, ".bmp": true, ".tiff": true, ".tif": true,
	// Audio
	".mp3": true, ".wav": true, ".ogg": true, ".flac": true, ".aac": true, ".m4a": true,
	// Video
	".mp4": true, ".webm": true, ".mkv": true, ".avi": true, ".mov": true, ".wmv": true, ".flv": true,
	// Fonts
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	// CSS
	".css": true,
}

// IsMediaContent returns true if content should be excluded from body storage.
// Checks MIME type first, then falls back to URL extension.
func IsMediaContent(mimeType string, urlPath string) bool {
	if mimeType != "" {
		mt := strings.ToLower(mimeType)
		for _, prefix := range mediaTypePrefixes {
			if strings.HasPrefix(mt, prefix) {
				return true
			}
		}
		if excludedMIMETypes[mt] {
			if mt == "application/octet-stream" {
				return isMediaExtension(urlPath)
			}
			return true
		}
	}

	// Fallback to extension when MIME type missing or generic
	if mimeType == "" || mimeType == "application/octet-stream" {
		return isMediaExtension(urlPath)
	}
	return false
}

func isMediaExtension(urlPath string) bool {
	ext := strings.ToLower(path.Ext(urlPath))
	return excludedExtensions[ext]
}

// MaxSecretScanBodySize is the largest response body (bytes) any consumer scans
// for secrets. Above it the body is skipped: a multi-megabyte payload is far more
// likely a bundle, media asset, or encoded blob than a credential carrier, and
// scanning it dominates cost.
const MaxSecretScanBodySize = 10 * 1024 * 1024

// textMIMESubstrings are the media-type substrings (beyond the text/ prefix and
// +json/+xml suffixes) that mark a body as text-based for secret scanning.
var textMIMESubstrings = []string{
	"/json",
	"/javascript",
	"/x-javascript",
	"/xml",
	"/x-yaml",
	"/yaml",
}

// IsTextBasedMIME reports whether the MIME type indicates text-based content that
// could carry a secret in plaintext. An empty type is treated as text (many
// endpoints omit Content-Type on JSON/HTML). Runs once per response/record on the
// secret-scan hot path, so it holds no per-call allocations.
func IsTextBasedMIME(mimeType string) bool {
	if mimeType == "" {
		return true
	}
	mt := strings.ToLower(mimeType)
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	for _, t := range textMIMESubstrings {
		if strings.Contains(mt, t) {
			return true
		}
	}
	return strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml")
}

// ShouldScanBodyForSecrets is the single eligibility policy deciding whether a
// response body is worth scanning for secrets: it must be non-empty, within
// MaxSecretScanBodySize, not media content (by MIME type or URL path), and a
// text-based MIME. Centralizing it here keeps the three secret-scan callers — the
// passive module, the known-issue-scan batch, and the discovery crawl — from
// drifting (they previously diverged on the size cap and media filtering), so a
// large or mislabeled binary response can't slip into the detector on one path
// but not another.
func ShouldScanBodyForSecrets(contentType, urlPath string, bodyLen int) bool {
	if bodyLen == 0 || bodyLen > MaxSecretScanBodySize {
		return false
	}
	if IsMediaContent(contentType, urlPath) {
		return false
	}
	return IsTextBasedMIME(contentType)
}
