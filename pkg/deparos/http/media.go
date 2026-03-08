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
