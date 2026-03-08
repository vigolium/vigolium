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

	basePath := baseURL.Path
	if basePath == "" {
		basePath = "/"
	}

	paths := make([]string, 4)

	// Variation 1: Prepend 6-char hex to last segment
	// Example: /api/users.json -> /api/{random}users.json
	prefix, err := generateRandomHex(6)
	if err != nil {
		return nil, err
	}
	paths[0] = prependToLastSegment(basePath, prefix)

	// Variation 2: Append 6-char hex to last segment (before extension)
	// Example: /api/users.json -> /api/users{random}.json
	suffix, err := generateRandomHex(6)
	if err != nil {
		return nil, err
	}
	paths[1] = appendToLastSegment(basePath, suffix)

	// Variation 3: Add 4-char hex as fake extension
	// Example: /api/users.json -> /api/users.json.{random}
	fakeExt, err := generateRandomHex(4)
	if err != nil {
		return nil, err
	}
	paths[2] = addFakeExtension(basePath, fakeExt)

	// Variation 4: Insert 9-char hex into middle of last segment
	// Example: /api/users.json -> /api/us{random}ers.json
	middle, err := generateRandomHex(9)
	if err != nil {
		return nil, err
	}
	paths[3] = insertIntoLastSegment(basePath, middle)

	return paths, nil
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
	if basePath == "" || basePath == "/" {
		return "/" + randomStr
	}

	// Check if path ends with /
	endsWithSlash := strings.HasSuffix(basePath, "/")

	// Clean path (removes trailing slash)
	basePath = path.Clean(basePath)

	// Split into directory and file
	dir, file := path.Split(basePath)

	if file == "" {
		// After Clean, if file is empty, basePath was just "/"
		return "/" + randomStr
	}

	// Prepend random to the filename
	result := path.Join(dir, randomStr+file)
	if endsWithSlash {
		return result + "/"
	}
	return result
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
	if basePath == "" || basePath == "/" {
		return "/" + randomStr
	}

	// Check if path ends with /
	endsWithSlash := strings.HasSuffix(basePath, "/")

	// Clean path
	basePath = path.Clean(basePath)

	// Split into directory and file
	dir, file := path.Split(basePath)

	if file == "" {
		return "/" + randomStr
	}

	// Check if file has extension
	ext := path.Ext(file)
	if ext != "" {
		// Has extension: insert before extension
		nameWithoutExt := strings.TrimSuffix(file, ext)
		result := path.Join(dir, nameWithoutExt+randomStr+ext)
		if endsWithSlash {
			return result + "/"
		}
		return result
	}

	// No extension: append to filename
	result := path.Join(dir, file+randomStr)
	if endsWithSlash {
		return result + "/"
	}
	return result
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
	if basePath == "" || basePath == "/" {
		return "/" + randomStr
	}

	// Check if path ends with /
	endsWithSlash := strings.HasSuffix(basePath, "/")

	// Clean path
	basePath = path.Clean(basePath)

	// Simply append .{random} to the path
	result := basePath + "." + randomStr
	if endsWithSlash {
		return result + "/"
	}
	return result
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
	if basePath == "" || basePath == "/" {
		return "/" + randomStr
	}

	// Check if path ends with /
	endsWithSlash := strings.HasSuffix(basePath, "/")

	// Clean path
	basePath = path.Clean(basePath)

	// Split into directory and file
	dir, file := path.Split(basePath)

	if file == "" {
		return "/" + randomStr
	}

	// Get filename without extension
	ext := path.Ext(file)
	nameWithoutExt := strings.TrimSuffix(file, ext)

	// Insert into middle of name
	var newName string
	if len(nameWithoutExt) > 1 {
		midpoint := len(nameWithoutExt) / 2
		newName = nameWithoutExt[:midpoint] + randomStr + nameWithoutExt[midpoint:]
	} else {
		// Name too short, just append
		newName = nameWithoutExt + randomStr
	}

	result := path.Join(dir, newName+ext)
	if endsWithSlash {
		return result + "/"
	}
	return result
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
	newURL.Path = pathVariation
	return newURL.String()
}
