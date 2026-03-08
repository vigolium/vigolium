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
