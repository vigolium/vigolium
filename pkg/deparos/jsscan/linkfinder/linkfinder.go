// Package linkfinder extracts and filters paths/URLs from web content.
// Inspired by the LinkFinder approach but optimized for Deparos's validation pipeline.
//
// This package catches patterns that other extractors miss:
//   - Bare paths without scheme: /api/users
//   - Template literals: `/api/${id}`
//   - HTTP library calls: axios.post('/auth/login')
//   - Object notation: {url: '/api'}
package linkfinder

// ExtractPaths extracts API paths from JavaScript content using regex patterns.
// Returns normalized paths ready for discovery (template variables replaced).
func ExtractPaths(content []byte) []string {
	if len(content) == 0 {
		return nil
	}

	// Extract raw paths using all patterns
	seen := extractRawPaths(string(content))

	// Process, filter, and normalize extracted paths
	var paths []string
	for rawPath := range seen {
		// Clean up the match
		rawPath = cleanupMatch(rawPath)
		if rawPath == "" {
			continue
		}

		// Validate the match
		if !shouldKeepMatch(rawPath) {
			continue
		}

		// Normalize template variables in paths
		paths = append(paths, NormalizePathTemplates(rawPath)...)
	}

	return paths
}
