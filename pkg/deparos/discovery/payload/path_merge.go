package payload

import (
	"net/url"
	"strings"
)

// MergePathWithBase merges a stored path with current directory.
// Returns FULL merged path to test, or "" to skip.
//
// Cases:
//  1. Exact match: storedPath == currentDir → "" (skip)
//  2. Child: storedPath is child of currentDir → return storedPath (full path)
//  3. Parent: storedPath is parent of currentDir → "" (skip, prevents duplication)
//  4. Share common prefix (≥1 segment): return storedPath as-is (same site structure)
//  5. Suffix-prefix overlap: merge into full path
//  6. Unrelated (no common prefix, no overlap): append storedPath to currentDir
//
// Examples:
//   - currentDir="/api/v1/", storedPath="/api/v1/admin/" → "/api/v1/admin/" (child)
//   - currentDir="/api/v1/", storedPath="/api/v1/" → "" (exact match)
//   - currentDir="/api/v1/admin/", storedPath="/api/v1/" → "" (parent, skip)
//   - currentDir="/api/v1/", storedPath="/api/v2/" → "/api/v2/" (share "api", return as-is)
//   - currentDir="/A/B/Y/", storedPath="/A/B/X/sub/" → "/A/B/X/sub/" (share "A/B", return as-is)
//   - currentDir="/api/v1/admin/", storedPath="/v1/admin/users/" → "/api/v1/admin/users/" (suffix-prefix overlap)
//   - currentDir="/api/v1/", storedPath="/other/" → "/api/v1/other/" (no common prefix, append)
func MergePathWithBase(storedPath string, currentDir string) string {
	if storedPath == "" || storedPath == "/" {
		return ""
	}

	// Extract path from absolute URLs (defense against malformed data in storage)
	storedPath = extractPathFromAbsoluteURL(storedPath)
	if storedPath == "" || storedPath == "/" {
		return ""
	}

	// Root is special: all paths are children of root
	if currentDir == "" || currentDir == "/" {
		storedPath = normalizePath(storedPath)
		if !strings.HasPrefix(storedPath, "/") {
			storedPath = "/" + storedPath
		}
		return storedPath
	}

	storedPath = normalizePath(storedPath)
	currentDir = normalizePath(currentDir)

	// Ensure leading slash
	if !strings.HasPrefix(storedPath, "/") {
		storedPath = "/" + storedPath
	}
	if !strings.HasPrefix(currentDir, "/") {
		currentDir = "/" + currentDir
	}

	// Ensure trailing slash for consistent comparison
	currentDirSlash := currentDir
	if !strings.HasSuffix(currentDirSlash, "/") {
		currentDirSlash += "/"
	}
	storedNorm := storedPath
	if !strings.HasSuffix(storedNorm, "/") {
		storedNorm += "/"
	}

	// Case 1: Exact match → skip
	if storedNorm == currentDirSlash {
		return ""
	}

	// Case 2: storedPath is child of currentDir → return storedPath (full path)
	if strings.HasPrefix(storedNorm, currentDirSlash) {
		return storedPath
	}

	// Case 3: storedPath is PARENT of currentDir → skip (prevents infinite loops)
	if strings.HasPrefix(currentDirSlash, storedNorm) {
		return ""
	}

	// Case 4: Check if paths share common prefix segments
	// If they share ≥1 segment, return storedPath as-is (same site structure)
	commonPrefixCount := countCommonPrefixSegments(storedPath, currentDir)
	if commonPrefixCount >= 1 {
		// They share a common ancestor, return storedPath as-is
		return storedPath
	}

	// Case 5: Check for suffix-prefix overlap
	// E.g., currentDir=/api/v1/admin/, storedPath=/v1/admin/users/
	// Suffix "v1/admin" of currentDir matches prefix "v1/admin" of storedPath
	// → Merge to /api/v1/admin/users/
	currentSegs := splitPathSegments(currentDir)
	storedSegs := splitPathSegments(storedPath)

	if len(currentSegs) > 0 && len(storedSegs) > 0 {
		maxOverlap := min(len(currentSegs), len(storedSegs))
		overlapLen := 0

		for i := 1; i <= maxOverlap; i++ {
			suffix := currentSegs[len(currentSegs)-i:]
			prefix := storedSegs[:i]
			if segmentsEqual(suffix, prefix) {
				overlapLen = i
			}
		}

		if overlapLen > 0 {
			remaining := storedSegs[overlapLen:]
			if len(remaining) == 0 {
				// Full overlap - return currentDir path
				return currentDir
			}
			// Merge: currentDir + remaining segments
			result := strings.TrimSuffix(currentDir, "/") + "/" + strings.Join(remaining, "/")
			if strings.HasSuffix(storedPath, "/") && !strings.HasSuffix(result, "/") {
				result += "/"
			}
			return result
		}
	}

	// Case 6: Unrelated (no common prefix, no overlap) → append storedPath to currentDir
	result := strings.TrimSuffix(currentDir, "/") + "/" + strings.TrimPrefix(storedPath, "/")
	return result
}

// segmentsEqual compares two segment slices for equality.
func segmentsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// countCommonPrefixSegments counts how many leading segments are identical
// between storedPath and currentDir.
//
// Example:
//   - storedPath: /Mod_Rewrite_Shop/Details/network-attached-storage-dlink/1/
//   - currentDir: /Mod_Rewrite_Shop/Details/color-printer/
//   - Returns: 2 (Mod_Rewrite_Shop, Details)
func countCommonPrefixSegments(storedPath, currentDir string) int {
	storedSegs := splitPathSegments(storedPath)
	currentSegs := splitPathSegments(currentDir)

	if len(storedSegs) == 0 || len(currentSegs) == 0 {
		return 0
	}

	minLen := min(len(storedSegs), len(currentSegs))
	count := 0

	for i := 0; i < minLen; i++ {
		if storedSegs[i] == currentSegs[i] {
			count++
		} else {
			break
		}
	}

	return count
}

// extractPathFromAbsoluteURL extracts the path portion from a URL string.
// For absolute URLs (https://example.com/path), returns just the path (/path).
// For paths containing embedded URLs (e.g., /L0/https://domain/path from malformed data),
// extracts and returns only the valid path portion.
// For regular paths, returns unchanged.
func extractPathFromAbsoluteURL(path string) string {
	if path == "" {
		return ""
	}

	// Use url.Parse for clean URL handling
	u, err := url.Parse(path)
	if err != nil {
		return path
	}

	// Case 1: Absolute URL (has scheme and host)
	// e.g., "https://capital.com/risk-disclosure-policy" → "/risk-disclosure-policy"
	if u.Scheme != "" && u.Host != "" {
		p := u.Path
		if p == "" {
			p = "/"
		}
		// Keep query params for storedPath - they are stripped later by consumers (e.g., ExtractFilename)
		if u.RawQuery != "" {
			p = p + "?" + u.RawQuery
		}
		return p
	}

	// Case 2: Protocol-relative URL (no scheme but has host)
	// e.g., "//cdn.example.com/assets/app.js" → "/assets/app.js"
	// BUT: "//double//slash" also parses with Host="double"
	// Real hostnames contain dots, path segments usually don't
	if u.Host != "" {
		if strings.Contains(u.Host, ".") {
			p := u.Path
			if p == "" {
				p = "/"
			}
			// Keep query params for storedPath
			if u.RawQuery != "" {
				p = p + "?" + u.RawQuery
			}
			return p
		}
		// No dot = not a real hostname, just double slashes in path
		return path
	}

	// Case 3: Path with embedded URL
	// url.Parse treats "/L0/https://capital.com/path" as just a path
	// Detect and extract the embedded URL
	if idx := strings.Index(u.Path, "://"); idx > 0 {
		afterScheme := u.Path[idx+3:]
		slashIdx := strings.Index(afterScheme, "/")
		if slashIdx > 0 {
			return extractPathFromAbsoluteURL(afterScheme[slashIdx:])
		}
		return "/"
	}

	return path
}

// normalizePath collapses consecutive slashes and ensures leading slash.
func normalizePath(path string) string {
	if path == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(path))

	// Ensure leading slash
	if path[0] != '/' {
		b.WriteByte('/')
	}

	prevSlash := false
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if !prevSlash {
				b.WriteByte('/')
			}
			prevSlash = true
		} else {
			b.WriteByte(path[i])
			prevSlash = false
		}
	}

	return b.String()
}

// splitPathSegments splits path into non-empty segments.
func splitPathSegments(path string) []string {
	parts := strings.Split(path, "/")
	var segs []string
	for _, p := range parts {
		if p != "" {
			segs = append(segs, p)
		}
	}
	return segs
}
