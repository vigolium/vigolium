package wordlist

import (
	"bytes"
	"strings"
)

// PreprocessorRegistry manages content-type to preprocessor mapping.
type PreprocessorRegistry struct {
	preprocessors map[string]Preprocessor
	defaultPrep   Preprocessor
}

// NewPreprocessorRegistry creates a new registry with all built-in preprocessors.
func NewPreprocessorRegistry() *PreprocessorRegistry {
	registry := &PreprocessorRegistry{
		preprocessors: make(map[string]Preprocessor),
		defaultPrep:   &TextPreprocessor{},
	}

	// Register all preprocessors
	preprocessors := []Preprocessor{
		&HTMLPreprocessor{},
		&JSONPreprocessor{},
		&JSPreprocessor{},
		&CSSPreprocessor{},
		&TextPreprocessor{},
	}

	for _, p := range preprocessors {
		for _, ct := range p.ContentTypes() {
			registry.preprocessors[ct] = p
		}
	}

	return registry
}

// Get returns the appropriate preprocessor for the given content type.
func (r *PreprocessorRegistry) Get(contentType string) Preprocessor {
	// Normalize content type (extract media type only)
	mediaType := extractMediaType(contentType)

	// Direct match
	if p, ok := r.preprocessors[mediaType]; ok {
		return p
	}

	// Partial match for subtypes (e.g., "application/vnd.api+json" matches json)
	for ct, p := range r.preprocessors {
		if strings.Contains(mediaType, ct) || strings.Contains(ct, mediaType) {
			return p
		}
	}

	// Check for +json, +xml suffixes
	if strings.HasSuffix(mediaType, "+json") {
		if p, ok := r.preprocessors["application/json"]; ok {
			return p
		}
	}
	if strings.HasSuffix(mediaType, "+xml") {
		if p, ok := r.preprocessors["application/xml"]; ok {
			return p
		}
	}

	return r.defaultPrep
}

// GetContentType returns the ContentType enum for the given MIME type string.
func (r *PreprocessorRegistry) GetContentType(contentType string) ContentType {
	mediaType := extractMediaType(contentType)

	// Check exact matches first
	switch mediaType {
	case "text/html", "application/xhtml+xml":
		return ContentTypeHTML
	case "application/json", "text/json":
		return ContentTypeJSON
	case "application/javascript", "text/javascript", "application/x-javascript":
		return ContentTypeJavaScript
	case "text/css":
		return ContentTypeCSS
	case "text/plain":
		return ContentTypeText
	case "application/xml", "text/xml":
		return ContentTypeXML
	}

	// Check suffixes
	if strings.HasSuffix(mediaType, "+json") {
		return ContentTypeJSON
	}
	if strings.HasSuffix(mediaType, "+xml") {
		return ContentTypeXML
	}

	// Check contains
	if strings.Contains(mediaType, "javascript") || strings.Contains(mediaType, "ecmascript") {
		return ContentTypeJavaScript
	}
	if strings.Contains(mediaType, "json") {
		return ContentTypeJSON
	}
	if strings.Contains(mediaType, "html") {
		return ContentTypeHTML
	}
	if strings.Contains(mediaType, "xml") {
		return ContentTypeXML
	}
	if strings.Contains(mediaType, "css") {
		return ContentTypeCSS
	}

	return ContentTypeText
}

// extractMediaType extracts the media type from a Content-Type header value.
// e.g., "text/html; charset=utf-8" -> "text/html"
func extractMediaType(contentType string) string {
	if contentType == "" {
		return ""
	}
	// Split on semicolon and take first part
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}
	return strings.TrimSpace(strings.ToLower(contentType))
}

// DetectContentType attempts to detect content type from the first bytes of content.
func DetectContentType(data []byte) ContentType {
	// Trim leading whitespace
	data = bytes.TrimLeft(data, " \t\r\n")
	if len(data) == 0 {
		return ContentTypeText
	}

	// Check for HTML
	if len(data) >= 1 && data[0] == '<' {
		// Check for common HTML patterns
		lower := bytes.ToLower(data[:min(100, len(data))])
		if bytes.HasPrefix(lower, []byte("<!doctype")) ||
			bytes.HasPrefix(lower, []byte("<html")) ||
			bytes.HasPrefix(lower, []byte("<head")) ||
			bytes.HasPrefix(lower, []byte("<body")) ||
			bytes.HasPrefix(lower, []byte("<div")) ||
			bytes.HasPrefix(lower, []byte("<script")) ||
			bytes.HasPrefix(lower, []byte("<style")) ||
			bytes.HasPrefix(lower, []byte("<meta")) ||
			bytes.HasPrefix(lower, []byte("<link")) {
			return ContentTypeHTML
		}
		// Could be XML
		if bytes.HasPrefix(lower, []byte("<?xml")) {
			return ContentTypeXML
		}
		// Default to HTML for any < starting content
		return ContentTypeHTML
	}

	// Check for JSON
	if data[0] == '{' || data[0] == '[' {
		return ContentTypeJSON
	}

	// Check for JavaScript patterns
	lower := bytes.ToLower(data[:min(50, len(data))])
	jsPatterns := [][]byte{
		[]byte("function"),
		[]byte("var "),
		[]byte("let "),
		[]byte("const "),
		[]byte("class "),
		[]byte("import "),
		[]byte("export "),
		[]byte("(function"),
		[]byte("!function"),
		[]byte("\"use strict\""),
		[]byte("'use strict'"),
	}
	for _, pattern := range jsPatterns {
		if bytes.HasPrefix(lower, pattern) {
			return ContentTypeJavaScript
		}
	}

	// Check for CSS patterns
	cssPatterns := [][]byte{
		[]byte("."),
		[]byte("#"),
		[]byte("@import"),
		[]byte("@media"),
		[]byte("@font-face"),
		[]byte("@keyframes"),
		[]byte("body"),
		[]byte("html"),
		[]byte("*{"),
		[]byte("* {"),
	}
	for _, pattern := range cssPatterns {
		if bytes.HasPrefix(lower, pattern) {
			return ContentTypeCSS
		}
	}

	return ContentTypeText
}

// ShouldProcess returns true if the content type should be processed.
// Returns false for binary/media/font/audio types.
func ShouldProcess(contentType string) bool {
	mediaType := extractMediaType(contentType)
	if mediaType == "" {
		return true // Process if unknown
	}

	// Skip binary types
	skipPrefixes := []string{
		"image/",
		"audio/",
		"video/",
		"font/",
	}
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(mediaType, prefix) {
			return false
		}
	}

	// Skip specific binary types
	skipExact := []string{
		"application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
		"application/x-tar",
		"application/x-rar-compressed",
		"application/x-7z-compressed",
		"application/x-shockwave-flash",
		"application/wasm",
		"application/x-executable",
		"application/x-msdos-program",
		"application/x-msdownload",
	}
	for _, skip := range skipExact {
		if mediaType == skip {
			return false
		}
	}

	return true
}
