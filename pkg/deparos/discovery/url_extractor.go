package discovery

import (
	"net/url"
	"strings"
)

// compoundExtensions contains known multi-part extensions that should be treated as single extensions.
// When we see "app.min.js", we want name="app", ext="min.js" (not name="app.min", ext="js").
var compoundExtensions = map[string]bool{
	// JavaScript build artifacts
	"min.js": true, "chunk.js": true, "bundle.js": true,
	"esm.js": true, "cjs.js": true, "mjs.js": true,
	// Archives
	"tar.gz": true, "tar.bz2": true, "tar.xz": true, "tar.zst": true,
}

// isCompoundExtension checks if ext is a known compound extension.
func isCompoundExtension(ext string) bool {
	return compoundExtensions[strings.ToLower(ext)]
}

// isHexHash checks if s is a hexadecimal hash (6-12 hex characters).
// Matches patterns like: b5ca88ec, 757b7acf, d5a27c78, abc123def
func isHexHash(s string) bool {
	n := len(s)
	if n < 6 || n > 12 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// ExtractFilename extracts filename (base name without extension) and extension from a URL path.
//
// Algorithm:
//  1. Extract filename from path (after last slash)
//  2. Split at last dot to separate name and extension
//  3. Handle compound extensions (e.g., min.js, tar.gz)
//  4. Handle hash patterns (e.g., app.b5ca88ec.js -> name="app", ext="js")
//
// Examples:
//   - "/admin/login.php" -> name="login", ext="php"
//   - "/api/users" -> name="users", ext=""
//   - "/archive.tar.gz" -> name="archive", ext="tar.gz" (compound extension)
//   - "/app.min.js" -> name="app", ext="min.js" (compound extension)
//   - "/app.b5ca88ec.js" -> name="app", ext="js" (hash stripped)
//   - "/surgeons.757b7acf.css" -> name="surgeons", ext="css" (hash stripped)
//   - "/" -> name="", ext="" (root path, skipped)
//   - "/.htaccess" -> name="", ext="htaccess" (dotfile)
func ExtractFilename(urlPath string) (name, extension string) {
	// Skip empty paths
	if urlPath == "" {
		return "", ""
	}

	// Skip root path
	if urlPath == "/" {
		return "", ""
	}

	// Strip query string - filenames should not contain query params
	if qIdx := strings.IndexByte(urlPath, '?'); qIdx >= 0 {
		urlPath = urlPath[:qIdx]
	}

	// Get filename from path (everything after last slash)
	lastSlash := strings.LastIndexByte(urlPath, '/')
	filename := urlPath
	if lastSlash >= 0 {
		filename = urlPath[lastSlash+1:]
	}

	// If no filename after slash, skip
	if filename == "" {
		return "", ""
	}

	// Find last dot for extension separation
	lastDot := strings.LastIndexByte(filename, '.')

	// No extension found - entire filename goes to observed names
	if lastDot == -1 {
		return filename, ""
	}

	// Handle filenames with multiple dots
	beforeDot := filename[:lastDot]
	if strings.Contains(beforeDot, ".") {
		ext := filename[lastDot+1:]
		secondLastDot := strings.LastIndexByte(beforeDot, '.')
		if secondLastDot != -1 {
			middlePart := beforeDot[secondLastDot+1:]
			namePart := beforeDot[:secondLastDot]

			// Check for hash pattern: name.hash.ext (e.g., app.b5ca88ec.js)
			if isHexHash(middlePart) {
				return namePart, ext
			}

			// Check for known compound extensions (e.g., min.js, tar.gz)
			potentialCompoundExt := middlePart + "." + ext
			if isCompoundExtension(potentialCompoundExt) {
				return namePart, potentialCompoundExt
			}
		}
		// Not a hash or compound extension - keep as name.middle, ext
		return beforeDot, ext
	}

	// Simple case: single dot
	name = filename[:lastDot]
	extension = filename[lastDot+1:]

	// Skip if extension is empty (filename ends with dot)
	// Still return name for observed collection
	if extension == "" {
		return name, ""
	}

	return name, extension
}

// FileMetadata holds all metadata extracted from a URL path in a single pass.
// Consolidates the results of ExtractFilename, ExtractRawFilename,
// ExtractPathForFuzzing, and ExtractPathSegments to avoid redundant parsing.
type FileMetadata struct {
	Name         string   // Hash-stripped filename (e.g., "app" from "app.b5ca88ec.js")
	Extension    string   // Extension (e.g., "js"), may be compound (e.g., "min.js")
	RawFilename  string   // Full filename preserving hashes (e.g., "app.b5ca88ec.js")
	RawExtension string   // Raw extension without hash stripping
	FuzzPath     string   // Directory path for fuzzing (e.g., "/api/v1/")
	Segments     []string // Individual non-empty path segments
}

// ExtractAllFileMetadata extracts all file metadata from a URL path in a single pass.
// This replaces separate calls to ExtractFilename, ExtractRawFilename,
// ExtractPathForFuzzing, and ExtractPathSegments.
func ExtractAllFileMetadata(urlPath string) FileMetadata {
	var m FileMetadata
	m.Name, m.Extension = ExtractFilename(urlPath)
	m.RawFilename, m.RawExtension = ExtractRawFilename(urlPath)
	m.FuzzPath = ExtractPathForFuzzing(urlPath)
	m.Segments = ExtractPathSegments(urlPath)
	return m
}

// ExtractRawFilename extracts the raw filename and extension from a URL path.
// Unlike ExtractFilename, this does NOT strip hashes - it preserves the full filename.
// Used for observedFiles which stores complete filenames like "app.b5ca88ec.js".
//
// Examples:
//   - "/admin/login.php" -> filename="login.php", ext="php"
//   - "/js/app.b5ca88ec.js" -> filename="app.b5ca88ec.js", ext="js"
//   - "/api/users" -> filename="users", ext=""
//   - "/" -> filename="", ext=""
func ExtractRawFilename(urlPath string) (filename, extension string) {
	if urlPath == "" || urlPath == "/" {
		return "", ""
	}

	// Get filename from path (after last slash)
	lastSlash := strings.LastIndexByte(urlPath, '/')
	fname := urlPath
	if lastSlash >= 0 {
		fname = urlPath[lastSlash+1:]
	}

	if fname == "" {
		return "", ""
	}

	// Find extension (after last dot)
	lastDot := strings.LastIndexByte(fname, '.')
	if lastDot == -1 || lastDot == 0 {
		return fname, ""
	}

	return fname, fname[lastDot+1:]
}

// ExtractDirectoryBreadcrumbs extracts all parent directories from a URL path.
// Returns directories in order from shallowest to deepest, all with trailing slashes.
//
// When spider discovers a file at /webmail/program/js/common.min.js, we can infer
// that directories /webmail/, /webmail/program/, and /webmail/program/js/ all exist.
// This function extracts those intermediate directories for recursive brute force.
//
// Examples:
//   - "/webmail/program/js/common.min.js" → ["/webmail/", "/webmail/program/", "/webmail/program/js/"]
//   - "/" → nil (root path)
//   - "/file.txt" → nil (file in root)
//   - "/admin/" → nil (single directory, excludes itself)
//   - "/admin/index.php" → ["/admin/"]
//   - "/a/b/c/" → ["/a/", "/a/b/"] (directory input - excludes itself)
//   - "//double//slashes//file.txt" → ["/double/", "/double/slashes/"] (normalized)
//   - "/api/v1/users/123/profile.json" → ["/api/", "/api/v1/", "/api/v1/users/", "/api/v1/users/123/"]
func ExtractDirectoryBreadcrumbs(urlPath string) []string {
	if urlPath == "" || urlPath == "/" {
		return nil
	}

	// Normalize: collapse consecutive slashes
	var normalized strings.Builder
	normalized.Grow(len(urlPath))
	prevSlash := false
	for _, c := range urlPath {
		if c == '/' {
			if !prevSlash {
				normalized.WriteRune(c)
			}
			prevSlash = true
		} else {
			normalized.WriteRune(c)
			prevSlash = false
		}
	}
	path := normalized.String()

	// Ensure starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Split into segments
	segments := strings.Split(path, "/")

	// Determine if input is a directory (ends with /)
	isDirectory := strings.HasSuffix(path, "/")

	// Calculate number of parent directories to extract
	// segments[0] is always empty (before leading /)
	// For file: "/a/b/c/file.txt" → ["", "a", "b", "c", "file.txt"] → want 3 dirs
	// For dir: "/a/b/c/" → ["", "a", "b", "c", ""] → want 2 dirs (exclude self)
	var numDirs int
	if isDirectory {
		// Exclude the trailing empty segment and the directory itself
		numDirs = len(segments) - 3
	} else {
		// Exclude the leading empty segment and the file
		numDirs = len(segments) - 2
	}

	if numDirs <= 0 {
		return nil
	}

	// Build directory paths incrementally
	result := make([]string, 0, numDirs)
	var current strings.Builder

	for i := 1; i <= numDirs; i++ {
		current.Reset()
		current.WriteByte('/')
		for j := 1; j <= i; j++ {
			if j > 1 {
				current.WriteByte('/')
			}
			current.WriteString(segments[j])
		}
		current.WriteByte('/')
		result = append(result, current.String())
	}

	return result
}

// ExpandSeedParents expands each seed URL into the URL itself plus every
// parent directory on the same scheme+host. Used when discovery.expand_seed_parents
// is enabled so that a target like https://h/ui/vault/auth seeds discovery and
// spidering with https://h/, https://h/ui/, https://h/ui/vault/, and the original.
//
// Behavior:
//   - The original URL is preserved (including any query/fragment) at the same
//     position in the output.
//   - Parent directories are inserted immediately after their seed, ordered
//     shallowest-first (root → deepest parent → original).
//   - Results are deduplicated globally across all seeds, with trailing-slash
//     equivalence so https://h/ and https://h match as the same entry.
//   - Non-HTTP(S) URLs and URLs that fail to parse are passed through unchanged.
//   - Root-level seeds (no parent path) are passed through unchanged.
func ExpandSeedParents(seeds []string) []string {
	if len(seeds) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(seeds)*2)
	result := make([]string, 0, len(seeds)*2)

	addOnce := func(raw string) {
		key := strings.TrimRight(raw, "/")
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		result = append(result, raw)
	}

	for _, seed := range seeds {
		trimmed := strings.TrimSpace(seed)
		if trimmed == "" {
			continue
		}

		u, err := url.Parse(trimmed)
		if err != nil || u.Scheme == "" || u.Host == "" {
			addOnce(trimmed)
			continue
		}

		breadcrumbs := ExtractDirectoryBreadcrumbs(u.Path)
		base := u.Scheme + "://" + u.Host

		// Always include the host root first so /, /ui/, /ui/vault/ are covered.
		if len(breadcrumbs) > 0 || (u.Path != "" && u.Path != "/") {
			addOnce(base + "/")
		}
		for _, dir := range breadcrumbs {
			addOnce(base + dir)
		}
		addOnce(trimmed)
	}

	return result
}

// ExtractPathForFuzzing extracts directory path from URL for fuzzing.
// Returns raw path with leading slash, trailing slash for directories.
// Stores raw path - overlap merging happens at task execution time via MergePathWithBase.
//
// Examples:
//   - "/api/v1/users/123" → "/api/v1/users/"
//   - "/admin/config.php" → "/admin/"
//   - "/file.txt" → "" (file in root)
//   - "/" → "" (root path)
//   - "/admin/" → "/admin/" (directory as-is)
func ExtractPathForFuzzing(urlPath string) string {
	if urlPath == "" || urlPath == "/" {
		return ""
	}

	// Check if it's a directory (ends with /)
	if strings.HasSuffix(urlPath, "/") {
		return urlPath
	}

	// It's a file - extract directory portion
	lastSlash := strings.LastIndexByte(urlPath, '/')
	if lastSlash <= 0 {
		// File in root, e.g., "/file.txt"
		return ""
	}

	// Return directory path with trailing slash
	return urlPath[:lastSlash+1]
}

// ExtractPathSegments extracts individual path segments for fuzzing.
// Returns non-empty segments without slashes.
//
// Examples:
//   - "/api/v1/users/123" → ["api", "v1", "users", "123"]
//   - "/admin/config.php" → ["admin", "config.php"]
//   - "/" → nil
//   - "" → nil
func ExtractPathSegments(urlPath string) []string {
	if urlPath == "" || urlPath == "/" {
		return nil
	}

	// Split by /
	parts := strings.Split(urlPath, "/")

	// Collect non-empty segments
	var segments []string
	for _, part := range parts {
		if part != "" {
			segments = append(segments, part)
		}
	}

	return segments
}

// commonTLDs contains TLDs and country codes to filter from host components.
// These are not useful for wordlist generation.
var commonTLDs = map[string]struct{}{
	// Generic TLDs
	"com": {}, "net": {}, "org": {}, "edu": {}, "gov": {}, "mil": {}, "int": {},
	"io": {}, "co": {}, "dev": {}, "app": {}, "ai": {}, "me": {}, "tv": {}, "info": {},
	"biz": {}, "name": {}, "pro": {}, "mobi": {}, "asia": {}, "tel": {}, "jobs": {},
	"travel": {}, "museum": {}, "coop": {}, "aero": {}, "xxx": {}, "post": {},
	// Country codes
	"uk": {}, "us": {}, "ca": {}, "au": {}, "de": {}, "fr": {}, "jp": {}, "cn": {},
	"ru": {}, "br": {}, "in": {}, "mx": {}, "es": {}, "it": {}, "nl": {}, "be": {},
	"ch": {}, "at": {}, "pl": {}, "se": {}, "no": {}, "dk": {}, "fi": {}, "ie": {},
	"pt": {}, "gr": {}, "cz": {}, "hu": {}, "ro": {}, "bg": {}, "hr": {}, "sk": {},
	"si": {}, "lt": {}, "lv": {}, "ee": {}, "cy": {}, "mt": {}, "lu": {}, "is": {},
	"nz": {}, "za": {}, "sg": {}, "hk": {}, "tw": {}, "kr": {}, "th": {}, "my": {},
	"ph": {}, "id": {}, "vn": {}, "ae": {}, "sa": {}, "il": {}, "tr": {}, "eg": {},
	"ng": {}, "ke": {}, "gh": {}, "ar": {}, "cl": {}, "pe": {}, "ve": {},
	"eu": {},
}

// ExtractHostComponents extracts meaningful parts from URL host for wordlist.
// Strips port, filters TLDs/SLDs, skips IP addresses and localhost.
//
// Examples:
//   - "brand.example.com" → ["brand", "example"]
//   - "api.v2.brand.example.co.uk" → ["api", "v2", "brand", "example"]
//   - "localhost:8080" → nil (localhost skipped)
//   - "192.168.1.1" → nil (IP address skipped)
//   - "example.com" → ["example"]
func ExtractHostComponents(host string) []string {
	if host == "" {
		return nil
	}

	// Strip port if present
	// Handle IPv6: [::1]:8080
	if strings.HasPrefix(host, "[") {
		// IPv6 address - skip entirely
		return nil
	}

	// Strip port from host:port
	if idx := strings.LastIndexByte(host, ':'); idx != -1 {
		host = host[:idx]
	}

	// Skip localhost
	if host == "localhost" {
		return nil
	}

	// Skip IP addresses (IPv4: all digits and dots)
	if isIPv4(host) {
		return nil
	}

	// Split by dot
	parts := strings.Split(host, ".")
	if len(parts) == 0 {
		return nil
	}

	// Filter out TLDs from the end
	var components []string
	for _, part := range parts {
		if part == "" {
			continue
		}
		if _, isTLD := commonTLDs[strings.ToLower(part)]; isTLD {
			continue
		}
		components = append(components, part)
	}

	if len(components) == 0 {
		return nil
	}

	return components
}

// isIPv4 checks if host is an IPv4 address (digits and dots only).
func isIPv4(host string) bool {
	if host == "" {
		return false
	}
	for _, c := range host {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	// Must have at least one dot to be valid IP
	return strings.ContainsRune(host, '.')
}
