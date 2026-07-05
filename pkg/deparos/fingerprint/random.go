package fingerprint

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// PathVariation represents different types of random path modifications.
// All variations modify ONLY the last segment to preserve directory structure.
// This ensures test paths stay within path-based catch-all patterns like /api/v1/*
type PathVariation int

const (
	VariationPrefix    PathVariation = iota // Prepend random to last segment: /api/file -> /api/{random}file
	VariationSuffix                         // Append random to last segment: /api/file -> /api/file{random}
	VariationExtension                      // Add random as fake extension: /api/file -> /api/file.{random}
	VariationMiddle                         // Insert random into middle: /api/file -> /api/fi{random}le
)

// GenerateRandomPaths generates 4 random non-existent path variations.
// All variations preserve the parent directory structure to stay within
// path-based catch-all patterns (e.g., /site/hc/static/site/*).
//
// Strategies:
// - Prefix:    Prepend random to last segment (detects suffix wildcards like *admin)
// - Suffix:    Append random to last segment (detects prefix wildcards like user*)
// - Extension: Add random as fake extension (detects extension-based routing)
// - Middle:    Insert random into middle (breaks both prefix AND suffix wildcards)
func GenerateRandomPaths(baseURL *url.URL) ([]string, error) {
	if baseURL == nil {
		return nil, fmt.Errorf("base URL is nil")
	}

	// Use the escaped (on-the-wire) path, not the decoded url.Path, so a
	// deliberately-crafted path-normalization bypass prefix (e.g. "/%23/../",
	// "//", "..;/") is preserved verbatim in the baseline probes instead of being
	// collapsed — otherwise the probes route to a different server layer than the
	// real request and the learned soft-404 baseline is meaningless.
	basePath := baseURL.EscapedPath()
	if basePath == "" {
		basePath = "/"
	}

	// Variation 1: Prepend 6-char hex to last segment (/api/users.json -> /api/{random}users.json)
	prefix, err := generateRandomHex(6)
	if err != nil {
		return nil, err
	}
	// Variation 2: Append 6-char hex before the extension (/api/users.json -> /api/users{random}.json)
	suffix, err := generateRandomHex(6)
	if err != nil {
		return nil, err
	}
	// Variation 3: Add 4-char hex as a fake extension (/api/users.json -> /api/users.json.{random})
	fakeExt, err := generateRandomHex(4)
	if err != nil {
		return nil, err
	}
	// Variation 4: Insert 9-char hex into the middle of the last segment (/api/users.json -> /api/us{random}ers.json)
	middle, err := generateRandomHex(9)
	if err != nil {
		return nil, err
	}

	return []string{
		prependToLastSegment(basePath, prefix),
		appendToLastSegment(basePath, suffix),
		addFakeExtension(basePath, fakeExt),
		insertIntoLastSegment(basePath, middle),
	}, nil
}

// GenerateRandomPathWithVariation generates a single random path with specific variation and length.
func GenerateRandomPathWithVariation(basePath string, variation PathVariation, length int) (string, error) {
	hex, err := generateRandomHex(length)
	if err != nil {
		return "", err
	}

	switch variation {
	case VariationPrefix:
		return prependToLastSegment(basePath, hex), nil
	case VariationSuffix:
		return appendToLastSegment(basePath, hex), nil
	case VariationExtension:
		return addFakeExtension(basePath, hex), nil
	case VariationMiddle:
		return insertIntoLastSegment(basePath, hex), nil
	default:
		return "", fmt.Errorf("unknown variation type: %d", variation)
	}
}

// prependToLastSegment prepends random string to the start of the last segment.
// Preserves parent directory structure to stay within path-based catch-alls.
//
// Files:
//
//	/api/users.json -> /api/{random}users.json
//	/site/default   -> /site/{random}default
//
// Directories:
//
//	/api/users/     -> /api/{random}users/
//	/site/hc/site/  -> /site/hc/{random}site/
func prependToLastSegment(basePath string, randomStr string) string {
	dir, seg, trailingSlash := splitLastSegment(basePath)
	if seg == "" {
		return "/" + randomStr
	}
	return rebuildPath(dir, randomStr+seg, trailingSlash)
}

// appendToLastSegment appends random string to the end of the last segment (before extension).
// Preserves parent directory structure to stay within path-based catch-alls.
//
// Files:
//
//	/api/users.json -> /api/users{random}.json
//	/site/default   -> /site/default{random}
//
// Directories:
//
//	/api/users/     -> /api/users{random}/
//	/site/hc/site/  -> /site/hc/site{random}/
func appendToLastSegment(basePath string, randomStr string) string {
	dir, seg, trailingSlash := splitLastSegment(basePath)
	if seg == "" {
		return "/" + randomStr
	}
	if ext := path.Ext(seg); ext != "" {
		// Insert before the extension.
		return rebuildPath(dir, strings.TrimSuffix(seg, ext)+randomStr+ext, trailingSlash)
	}
	// No extension: append to the segment.
	return rebuildPath(dir, seg+randomStr, trailingSlash)
}

// addFakeExtension adds random string as a fake extension to the last segment.
// Preserves parent directory structure to stay within path-based catch-alls.
//
// Files:
//
//	/api/users.json -> /api/users.json.{random}
//	/site/default   -> /site/default.{random}
//
// Directories:
//
//	/api/users/     -> /api/users.{random}/
//	/site/hc/site/  -> /site/hc/site.{random}/
func addFakeExtension(basePath string, randomStr string) string {
	dir, seg, trailingSlash := splitLastSegment(basePath)
	if seg == "" {
		return "/" + randomStr
	}
	return rebuildPath(dir, seg+"."+randomStr, trailingSlash)
}

// insertIntoLastSegment inserts random string into the middle of the last segment.
// This is the most effective at breaking wildcard patterns since it modifies
// both prefix and suffix of the filename.
// Preserves parent directory structure to stay within path-based catch-alls.
//
// Files:
//
//	/api/users.json -> /api/us{random}ers.json
//	/site/default   -> /site/def{random}ault
//
// Directories:
//
//	/api/users/     -> /api/us{random}ers/
//	/site/hc/site/  -> /site/hc/si{random}te/
func insertIntoLastSegment(basePath string, randomStr string) string {
	dir, seg, trailingSlash := splitLastSegment(basePath)
	if seg == "" {
		return "/" + randomStr
	}

	ext := path.Ext(seg)
	nameWithoutExt := strings.TrimSuffix(seg, ext)

	// Insert into middle of name
	var newName string
	if len(nameWithoutExt) > 1 {
		midpoint := len(nameWithoutExt) / 2
		newName = nameWithoutExt[:midpoint] + randomStr + nameWithoutExt[midpoint:]
	} else {
		// Name too short, just append
		newName = nameWithoutExt + randomStr
	}

	return rebuildPath(dir, newName+ext, trailingSlash)
}

// generateRandomHex generates random hex string of specified length.
func generateRandomHex(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	// Generate random bytes (need length/2 bytes for hex encoding)
	numBytes := (length + 1) / 2
	randomBytes := make([]byte, numBytes)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to hex string
	hexStr := hex.EncodeToString(randomBytes)

	// Truncate to desired length
	if len(hexStr) > length {
		hexStr = hexStr[:length]
	}

	return hexStr, nil
}

// BuildFullURL constructs full URL from base URL and path variation.
func BuildFullURL(baseURL *url.URL, pathVariation string) string {
	newURL := *baseURL // Copy
	SetWirePath(&newURL, pathVariation)
	return newURL.String()
}

// splitLastSegment splits an escaped path into its directory prefix (including the
// trailing slash) and last non-empty segment WITHOUT resolving dot-segments or
// collapsing slashes, so a path-normalization bypass prefix ("/%23/../", "//",
// "..;/") is preserved byte-for-byte. trailingSlash reports directory form.
func splitLastSegment(p string) (dir, seg string, trailingSlash bool) {
	if p == "" || p == "/" {
		return "", "", false
	}
	trailingSlash = strings.HasSuffix(p, "/")
	q := p
	if trailingSlash {
		q = strings.TrimSuffix(q, "/")
	}
	if idx := strings.LastIndex(q, "/"); idx >= 0 {
		return q[:idx+1], q[idx+1:], trailingSlash
	}
	return "", q, trailingSlash
}

// rebuildPath reassembles a dir prefix and (mutated) last segment, restoring the
// leading slash and any trailing slash.
func rebuildPath(dir, seg string, trailingSlash bool) string {
	out := dir + seg
	if !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	if trailingSlash && !strings.HasSuffix(out, "/") {
		out += "/"
	}
	return out
}

// SetWirePath assigns an escaped, on-the-wire path (e.g. "/%23/../abc") to u so
// that u.String()/RequestURI() emit it byte-for-byte, preserving bypass sequences
// (%23, .., //) that a naive u.Path assignment would collapse or double-encode.
// It mirrors net/url's EscapedPath invariant: RawPath is kept only when the
// default encoding of the decoded path differs from wirePath. (Not url.Parse,
// which would misread a leading "//" as a host.)
func SetWirePath(u *url.URL, wirePath string) {
	decoded, err := url.PathUnescape(wirePath)
	if err != nil {
		// Not valid percent-encoding — best effort: emit the segment verbatim.
		u.Path = wirePath
		u.RawPath = ""
		return
	}
	u.Path = decoded
	if (&url.URL{Path: decoded}).EscapedPath() == wirePath {
		u.RawPath = ""
	} else {
		u.RawPath = wirePath
	}
}
