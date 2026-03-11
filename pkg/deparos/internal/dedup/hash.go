package dedup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
)

// hashFNV64aHex computes FNV-1a 64-bit hash and returns hex string.
func hashFNV64aHex(s string) string {
	h := fnv.New64a()
	h.Write([]byte(s))
	return strconv.FormatUint(h.Sum64(), 16)
}

// staticExtensions defines file extensions where query params should be stripped
// for deduplication. These are typically versioned/cache-busted static assets.
var staticExtensions = map[string]bool{
	// Scripts
	".js": true, ".mjs": true, ".cjs": true,
	// Stylesheets
	".css": true,
	// Images
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".svg": true, ".ico": true, ".bmp": true, ".tiff": true, ".tif": true,
	// Audio
	".mp3": true, ".wav": true, ".ogg": true, ".flac": true, ".aac": true, ".m4a": true,
	// Video
	".mp4": true, ".webm": true, ".mkv": true, ".avi": true, ".mov": true, ".wmv": true, ".flv": true,
	// Fonts
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	// Maps
	".map": true,
}

// isStaticFile checks if URL path has a static file extension.
func isStaticFile(urlPath string) bool {
	ext := strings.ToLower(path.Ext(urlPath))
	return staticExtensions[ext]
}

// HashRequest creates a hash key for HTTP request deduplication.
// Always includes body hash for consistency - empty body produces consistent hash.
// Format: method|normalizedURL|bodyHash
func HashRequest(method, rawURL, body string) string {
	return method + "|" + NormalizeURL(rawURL) + "|" + hashFNV64aHex(body)
}

// HashFormStructure creates a structural hash for form deduplication.
// Uses sorted input field names (not values) to identify structurally identical forms.
// The caller must pass sortedInputNames already sorted.
// Format: normalizedURL|method|FNV64a(sorted_input_names)
func HashFormStructure(actionURL, method string, sortedInputNames []string) string {
	h := fnv.New64a()
	for i, name := range sortedInputNames {
		if i > 0 {
			h.Write([]byte{','})
		}
		h.Write([]byte(name))
	}
	inputHash := strconv.FormatUint(h.Sum64(), 16)
	return NormalizeURL(actionURL) + "|" + method + "|" + inputHash
}

// normalizePath normalizes a URL path.
// - Collapse multiple slashes: //api → /api
// - Resolve . and .. segments
// - Preserve trailing slash distinction
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}

	hasTrailingSlash := strings.HasSuffix(p, "/") && p != "/"
	cleaned := path.Clean(p)

	if hasTrailingSlash && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}

	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned
}

// collapseRepeatingSegments detects and collapses repeating path patterns.
// Example: "/a/b/c/a/b/c/" → "/a/b/c/"
//
// Only collapses when:
// - Pattern is at least 2 segments
// - Pattern repeats at least 2 times
// - Entire path is composed of complete repetitions
func collapseRepeatingSegments(p string) string {
	if p == "" || p == "/" {
		return p
	}

	hasTrailingSlash := strings.HasSuffix(p, "/")
	segments := strings.Split(strings.Trim(p, "/"), "/")
	n := len(segments)

	// Need at least 4 segments for pattern_len>=2 repeated 2x
	if n < 4 {
		return p
	}

	// Try pattern lengths from 2 to n/2
	for patLen := 2; patLen <= n/2; patLen++ {
		if n%patLen != 0 {
			continue
		}

		repetitions := n / patLen
		if repetitions < 2 {
			continue
		}

		pattern := segments[:patLen]
		isRepeating := true

		for rep := 1; rep < repetitions && isRepeating; rep++ {
			start := rep * patLen
			for i := 0; i < patLen; i++ {
				if segments[start+i] != pattern[i] {
					isRepeating = false
					break
				}
			}
		}

		if isRepeating {
			result := "/" + strings.Join(pattern, "/")
			if hasTrailingSlash {
				result += "/"
			}
			return result
		}
	}

	return p
}

// NormalizeURL normalizes a URL for consistent deduplication.
//   - Lowercase scheme and host
//   - Remove default ports (80 for http, 443 for https)
//   - Normalize path (clean + collapse repeating segments)
//   - For static files (js, css, images, fonts, etc.): strip query params
//   - For other URLs: sort query params by key, include values
//   - Strip fragments
func NormalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	if host, port, err := net.SplitHostPort(u.Host); err == nil {
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			u.Host = host
		}
	}

	// Normalize path: clean + collapse repeating segments
	u.Path = collapseRepeatingSegments(normalizePath(u.Path))

	// For static files, strip query params entirely (version hashes, cache busters)
	// For other URLs, include sorted key=value pairs
	if isStaticFile(u.Path) {
		u.RawQuery = ""
	} else {
		u.RawQuery = normalizeQueryParams(u.Query())
	}

	u.Fragment = ""
	// Clear ForceQuery to avoid trailing ? when query is empty (e.g., "api?" → "api")
	u.ForceQuery = false

	return u.String()
}

// normalizeQueryParams normalizes query parameters for deduplication.
// Returns sorted key=value pairs. Handles multiple values per key.
func normalizeQueryParams(params url.Values) string {
	if len(params) == 0 {
		return ""
	}

	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var pairs []string
	for _, key := range keys {
		values := params[key]
		sortedValues := make([]string, len(values))
		copy(sortedValues, values)
		sort.Strings(sortedValues)

		for _, val := range sortedValues {
			pairs = append(pairs, key+"="+val)
		}
	}

	return strings.Join(pairs, "&")
}

// ExtractQueryNames extracts and sorts query parameter names (keys only, no values).
// Used for node hash deduplication.
func ExtractQueryNames(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// extractJSONKeys extracts top-level keys from JSON object.
// Returns nil if body is not a valid JSON object.
func extractJSONKeys(body []byte) []string {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	return keys
}

// ExtractBodyKeys extracts and sorts keys from body (JSON or form-urlencoded).
// Detection is by syntax check, NOT by Content-Type header.
// Returns:
//   - For JSON objects: sorted comma-separated keys
//   - For form-urlencoded: sorted comma-separated keys
//   - For other formats: FNV hash of raw body
func ExtractBodyKeys(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return ""
	}

	// Try JSON first (starts with { for object)
	if trimmed[0] == '{' {
		if keys := extractJSONKeys(trimmed); keys != nil {
			sort.Strings(keys)
			return strings.Join(keys, ",")
		}
	}

	// Try form-urlencoded
	if values, err := url.ParseQuery(string(trimmed)); err == nil && len(values) > 0 {
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return strings.Join(keys, ",")
	}

	// Fallback: hash raw body
	return hashFNV64aHex(string(body))
}

// BuildNodeHash creates a unique hash for node deduplication.
// Hash components: scheme|host|method|statusCode|serverHeader|path|queryNames|bodyKeys
// This allows deduplication of requests with same semantic structure
// even if parameter values differ.
// IMPORTANT: scheme and host ensure uniqueness across different sites.
func BuildNodeHash(scheme, host, method string, statusCode int, serverHeader, urlPath, rawQuery string, body []byte) string {
	h := fnv.New64a()
	h.Write([]byte(scheme))
	h.Write([]byte("|"))
	h.Write([]byte(host))
	h.Write([]byte("|"))
	h.Write([]byte(method))
	h.Write([]byte("|"))
	h.Write([]byte(strconv.Itoa(statusCode)))
	h.Write([]byte("|"))
	h.Write([]byte(serverHeader))
	h.Write([]byte("|"))
	h.Write([]byte(urlPath))
	h.Write([]byte("|"))
	h.Write([]byte(ExtractQueryNames(rawQuery)))
	h.Write([]byte("|"))
	h.Write([]byte(ExtractBodyKeys(body)))
	return fmt.Sprintf("%016x", h.Sum64())
}
