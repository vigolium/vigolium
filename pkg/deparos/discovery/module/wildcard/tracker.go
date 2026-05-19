package wildcard

import (
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
)

// PrefixTracker tracks path discoveries to detect wildcard prefixes.
// Uses hybrid detection: prefix matching + fingerprint comparison.
type PrefixTracker struct {
	mu               sync.RWMutex
	prefixData       map[string]*PrefixStats
	wildcardPrefixes map[string]struct{} // Confirmed wildcard prefixes
	allPaths         []string            // All discovered paths for prefix extraction
}

// PrefixStats holds statistics for a prefix.
type PrefixStats struct {
	Prefix        string
	Paths         []string                 // All paths matching this prefix
	Fingerprints  []*fingerprint.Signature // Fingerprints for each path
	Count         int
	IsWildcard    bool
	AvgSimilarity float64 // Average fingerprint similarity
	FirstSeen     time.Time
}

// NewPrefixTracker creates a new prefix tracker.
func NewPrefixTracker() *PrefixTracker {
	return &PrefixTracker{
		prefixData:       make(map[string]*PrefixStats),
		wildcardPrefixes: make(map[string]struct{}),
	}
}

// AddWithFingerprint records a new path with its response fingerprint.
func (t *PrefixTracker) AddWithFingerprint(prefix, fullPath string, fp *fingerprint.Signature) *PrefixStats {
	t.mu.Lock()
	defer t.mu.Unlock()

	stats, exists := t.prefixData[prefix]
	if !exists {
		stats = &PrefixStats{
			Prefix:    prefix,
			FirstSeen: time.Now(),
		}
		t.prefixData[prefix] = stats
	}

	stats.Paths = append(stats.Paths, fullPath)
	stats.Fingerprints = append(stats.Fingerprints, fp)
	stats.Count++

	t.allPaths = append(t.allPaths, fullPath)

	return stats
}

// Add records a path without fingerprint.
func (t *PrefixTracker) Add(prefix, fullPath string) *PrefixStats {
	return t.AddWithFingerprint(prefix, fullPath, nil)
}

// MarkWildcard marks a prefix as confirmed wildcard.
func (t *PrefixTracker) MarkWildcard(prefix string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.wildcardPrefixes[prefix] = struct{}{}
	if stats, ok := t.prefixData[prefix]; ok {
		stats.IsWildcard = true
	}
}

// IsWildcard checks if path matches any known wildcard prefix.
func (t *PrefixTracker) IsWildcard(path string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for prefix := range t.wildcardPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// GetStats returns stats for a prefix.
func (t *PrefixTracker) GetStats(prefix string) *PrefixStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if stats, ok := t.prefixData[prefix]; ok {
		// Return a copy
		return &PrefixStats{
			Prefix:        stats.Prefix,
			Paths:         append([]string{}, stats.Paths...),
			Fingerprints:  append([]*fingerprint.Signature{}, stats.Fingerprints...),
			Count:         stats.Count,
			IsWildcard:    stats.IsWildcard,
			AvgSimilarity: stats.AvgSimilarity,
			FirstSeen:     stats.FirstSeen,
		}
	}
	return nil
}

// ExtractCommonPrefix finds potential wildcard prefix from a new path.
// Only compares paths with the SAME parent directory and checks if the
// last segment shares a common prefix (e.g., /admin1, /admin2 → /admin).
// Paths like /assets/img/, /assets/css/ will NOT match because their
// last segments (img, css) have no common prefix.
func (t *PrefixTracker) ExtractCommonPrefix(newPath string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	newParent, newSegment := splitPathSegment(newPath)
	if newSegment == "" {
		return ""
	}

	// Compare with paths that have the SAME parent directory
	for _, existingPath := range t.allPaths {
		if existingPath == newPath {
			continue
		}

		existingParent, existingSegment := splitPathSegment(existingPath)
		if existingSegment == "" {
			continue
		}

		// Only compare if same parent directory
		if newParent != existingParent {
			continue
		}

		// Find common prefix of the last segments only
		segmentPrefix := longestCommonPrefix(existingSegment, newSegment)

		// Prefix must be meaningful (at least 3 chars) and not the full segment
		if len(segmentPrefix) >= 3 && segmentPrefix != existingSegment && segmentPrefix != newSegment {
			// Return full path prefix: parent + segment prefix
			return newParent + segmentPrefix
		}
	}

	return ""
}

// splitPathSegment splits a path into parent directory and last segment.
// Examples:
//   - "/assets/img/" → "/assets/", "img"
//   - "/admin123" → "/", "admin123"
//   - "/api/v1/users" → "/api/v1/", "users"
func splitPathSegment(path string) (parent, segment string) {
	// Remove trailing slash for processing
	cleanPath := strings.TrimSuffix(path, "/")
	if cleanPath == "" {
		return "/", ""
	}

	lastSlash := strings.LastIndex(cleanPath, "/")
	if lastSlash == -1 {
		return "/", cleanPath
	}

	parent = cleanPath[:lastSlash+1] // Include the slash
	segment = cleanPath[lastSlash+1:]
	return parent, segment
}

// GetWildcardPrefixes returns all confirmed wildcard prefixes.
func (t *PrefixTracker) GetWildcardPrefixes() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]string, 0, len(t.wildcardPrefixes))
	for prefix := range t.wildcardPrefixes {
		result = append(result, prefix)
	}
	return result
}

// PrefixCount returns the number of tracked prefixes.
func (t *PrefixTracker) PrefixCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.prefixData)
}

// WildcardCount returns the number of confirmed wildcard prefixes.
func (t *PrefixTracker) WildcardCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.wildcardPrefixes)
}

// longestCommonPrefix returns the longest common prefix of two strings.
func longestCommonPrefix(a, b string) string {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			return a[:i]
		}
	}
	return a[:minLen]
}
