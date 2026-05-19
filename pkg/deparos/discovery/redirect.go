package discovery

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// RedirectDetector handles redirect detection and analysis
type RedirectDetector struct {
	mu sync.RWMutex
	// Track discovered redirects to avoid loops
	discoveredRedirects map[string]bool
}

// NewRedirectDetector creates a new redirect detector
func NewRedirectDetector() *RedirectDetector {
	return &RedirectDetector{
		discoveredRedirects: make(map[string]bool),
	}
}

// RedirectInfo contains information about a detected redirect
type RedirectInfo struct {
	IsRedirect          bool
	IsTrailingSlash     bool
	StatusCode          int
	LocationHeader      string
	ResolvedLocation    string
	OriginalPath        []byte
	RedirectPath        []byte
	ShouldQueueRedirect bool
	ShouldMarkDirectory bool

	// Extracted path components from redirect target
	ExtractedDirPath   string // Directory portion (e.g., "/us/en/")
	ExtractedFilename  string // Filename without extension (e.g., "index")
	ExtractedExtension string // Extension (e.g., "html")
	IsSameHost         bool   // True if redirect stays on same host
}

// DetectRedirect analyzes an HTTP response for redirect patterns
func (rd *RedirectDetector) DetectRedirect(resp *http.Response, originalURL string, depth uint16, maxDepth uint16) (*RedirectInfo, error) {
	info := &RedirectInfo{
		StatusCode: resp.StatusCode,
	}

	// Only check 301 and 302 redirects
	if resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound {
		return info, nil
	}

	info.IsRedirect = true

	// Extract Location header
	locationHeader := resp.Header.Get("Location")
	if locationHeader == "" {
		return info, nil
	}
	info.LocationHeader = strings.TrimSpace(locationHeader)

	// Parse original URL
	origURL, err := url.Parse(originalURL)
	if err != nil {
		return info, err
	}

	// Parse and resolve redirect URL
	redirectURL, err := rd.parseAndNormalizeURL(info.LocationHeader, origURL)
	if err != nil {
		return info, err
	}
	// Store full URL for queueing, but we'll use path for comparison
	info.ResolvedLocation = redirectURL.String()

	// Get paths as bytes for comparison
	info.OriginalPath = []byte(origURL.Path)
	info.RedirectPath = []byte(redirectURL.Path)

	// Check for trailing slash redirect
	if rd.IsTrailingSlashRedirect(info.OriginalPath, info.RedirectPath) {
		info.IsTrailingSlash = true
		info.ShouldMarkDirectory = true
	}

	// Check if same host (for scope filtering)
	info.IsSameHost = (origURL.Host == redirectURL.Host)

	// Extract path components from non-trailing-slash redirects
	if !info.IsTrailingSlash {
		info.ExtractedDirPath = ExtractPathForFuzzing(redirectURL.Path)
		info.ExtractedFilename, info.ExtractedExtension = ExtractFilename(redirectURL.Path)
	}

	// Check if we should queue the redirect target
	if depth+1 <= maxDepth {
		// Check if not already discovered
		rd.mu.Lock()
		_, alreadyDiscovered := rd.discoveredRedirects[info.ResolvedLocation]
		if !alreadyDiscovered {
			info.ShouldQueueRedirect = true
			rd.discoveredRedirects[info.ResolvedLocation] = true
		}
		rd.mu.Unlock()
	}

	return info, nil
}

// IsTrailingSlashRedirect detects trailing slash redirects
// Exported for testing
func (rd *RedirectDetector) IsTrailingSlashRedirect(originalPath, redirectPath []byte) bool {
	// Check length: redirect must be exactly 1 byte longer
	if len(redirectPath) != len(originalPath)+1 {
		return false
	}

	// Check prefix: first N-1 bytes must match exactly
	if !bytes.Equal(originalPath, redirectPath[:len(originalPath)]) {
		return false
	}

	// Check last byte: must be forward slash (ASCII 47)
	if redirectPath[len(redirectPath)-1] != '/' {
		return false
	}

	return true
}

// parseAndNormalizeURL implements URL parsing and normalization
func (rd *RedirectDetector) parseAndNormalizeURL(location string, baseURL *url.URL) (*url.URL, error) {
	// Remove fragment
	if idx := strings.IndexByte(location, '#'); idx != -1 {
		location = location[:idx]
	}

	// Parse the location
	redirectURL, err := url.Parse(location)
	if err != nil {
		return nil, err
	}

	// Resolve relative URLs
	if !redirectURL.IsAbs() {
		redirectURL = baseURL.ResolveReference(redirectURL)
	}

	// Normalize the path
	redirectURL.Path = rd.NormalizePath(redirectURL.Path)

	return redirectURL, nil
}

// NormalizePath implements path normalization for redirect URLs
// Exported for testing
func (rd *RedirectDetector) NormalizePath(path string) string {
	// Remove fragment if present (should already be done, but just in case)
	if idx := strings.IndexByte(path, '#'); idx != -1 {
		path = path[:idx]
	}

	// Convert backslashes to forward slashes
	path = strings.ReplaceAll(path, "\\", "/")

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Remove /./ sequences
	for strings.Contains(path, "/./") {
		path = strings.ReplaceAll(path, "/./", "/")
	}

	// Collapse // to /
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}

	// Remove trailing /.
	if strings.HasSuffix(path, "/.") {
		path = path[:len(path)-2]
		if path == "" {
			path = "/"
		}
	}

	// Remember if path had trailing slash before processing
	hadTrailingSlash := strings.HasSuffix(path, "/") && !strings.HasSuffix(path, "/.")

	// Resolve /../ sequences
	segments := strings.Split(path, "/")
	var resolved []string
	for _, segment := range segments {
		if segment == ".." {
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
		} else if segment != "" && segment != "." {
			resolved = append(resolved, segment)
		}
	}

	// Reconstruct path
	result := "/" + strings.Join(resolved, "/")

	// Handle trailing /..
	if strings.HasSuffix(path, "/..") {
		// This case is handled by the segment resolution above
		// Just ensure we don't have an empty path
		if result == "" {
			result = "/"
		}
	}

	// Preserve trailing slash if it was present and not part of a special pattern
	if hadTrailingSlash && result != "/" {
		result += "/"
	}

	return result
}

// Reset clears the discovered redirects cache
func (rd *RedirectDetector) Reset() {
	rd.mu.Lock()
	rd.discoveredRedirects = make(map[string]bool)
	rd.mu.Unlock()
}
