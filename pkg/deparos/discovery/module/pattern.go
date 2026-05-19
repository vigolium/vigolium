package module

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// PatternType defines how patterns are matched.
type PatternType int

const (
	// Path-level patterns (match against full URL path)

	// PatternPathContains matches if path contains substring anywhere.
	// Example: value="admin" matches "/foo/admin/bar", "/administrator/"
	PatternPathContains PatternType = iota

	// PatternPathPrefix matches if path starts with value.
	// Example: value="/api/" matches "/api/v1/users"
	PatternPathPrefix

	// PatternPathSuffix matches if path ends with value.
	// Example: value="/admin/" matches "/panel/admin/"
	PatternPathSuffix

	// PatternPathExact matches exact path equality.
	// Example: value="/admin/" matches only "/admin/"
	PatternPathExact

	// PatternPathRegex matches path against regex pattern.
	// Example: value="^/api/v[0-9]+/" matches "/api/v1/", "/api/v2/"
	PatternPathRegex

	// Segment-level patterns (match against individual path segments)

	// PatternSegmentExact matches if any segment equals value exactly.
	// Example: value="backup" matches "/foo/backup/bar"
	PatternSegmentExact

	// PatternSegmentContains matches if any segment contains substring.
	// Example: value="bak" matches "/mybackup/", "/data-bak/"
	PatternSegmentContains

	// PatternSegmentPrefix matches if any segment starts with value.
	// Example: value="admin" matches "/adminpanel/foo"
	PatternSegmentPrefix

	// PatternSegmentSuffix matches if any segment ends with value.
	// Example: value="backup" matches "/mybackup/foo"
	PatternSegmentSuffix

	// PatternSegmentRegex matches if any segment matches regex pattern.
	// Example: value="^old" matches "/old/", "/old-data/", "/old_backup/"
	PatternSegmentRegex

	// File-level patterns (match against filename/extension)

	// PatternFileExtension matches file extension (case-insensitive).
	// Example: value="js" matches "/app.js", "/App.JS"
	PatternFileExtension

	// PatternFileName matches exact filename.
	// Example: value="config.json" matches "/any/path/config.json"
	PatternFileName

	// PatternFileGlob matches glob pattern against filename.
	// Example: value="*.min.js" matches "/foo/app.min.js"
	PatternFileGlob
)

// Pattern defines a matching pattern for modules.
type Pattern struct {
	// Type is the pattern matching strategy.
	Type PatternType

	// Value is the pattern value.
	Value string

	// Negated inverts the match (true = match when NOT matching).
	Negated bool

	// MatchFiles if true also matches file paths (not just directories).
	// Only relevant for file-level patterns (file_extension, file_name, file_glob).
	MatchFiles bool

	// compiled holds pre-compiled regex (for PatternPathRegex).
	compiled *regexp.Regexp
}

// NewPattern creates a new pattern.
func NewPattern(patternType PatternType, value string) Pattern {
	p := Pattern{
		Type:  patternType,
		Value: value,
	}
	if patternType == PatternPathRegex {
		p.compiled, _ = regexp.Compile(value)
	}
	return p
}

// NewNegatedPattern creates a negated pattern.
func NewNegatedPattern(patternType PatternType, value string) Pattern {
	p := NewPattern(patternType, value)
	p.Negated = true
	return p
}

// NewFilePattern creates a pattern that matches files.
func NewFilePattern(patternType PatternType, value string) Pattern {
	p := NewPattern(patternType, value)
	p.MatchFiles = true
	return p
}

// Compile pre-compiles regex patterns.
func (p *Pattern) Compile() error {
	if (p.Type == PatternPathRegex || p.Type == PatternSegmentRegex) && p.compiled == nil {
		var err error
		p.compiled, err = regexp.Compile(p.Value)
		return err
	}
	return nil
}

// Matches checks if the path matches this pattern.
func (p *Pattern) Matches(path string) bool {
	result := p.matchesInternal(path)
	if p.Negated {
		return !result
	}
	return result
}

// matchesInternal performs actual pattern matching.
func (p *Pattern) matchesInternal(path string) bool {
	switch p.Type {
	// Path-level patterns
	case PatternPathContains:
		return strings.Contains(path, p.Value)

	case PatternPathPrefix:
		return strings.HasPrefix(path, p.Value)

	case PatternPathSuffix:
		return strings.HasSuffix(path, p.Value)

	case PatternPathExact:
		return path == p.Value

	case PatternPathRegex:
		if p.compiled == nil {
			p.compiled, _ = regexp.Compile(p.Value)
		}
		if p.compiled != nil {
			return p.compiled.MatchString(path)
		}
		return false

	// Segment-level patterns
	case PatternSegmentExact:
		segments := strings.Split(path, "/")
		for _, seg := range segments {
			if seg == p.Value {
				return true
			}
		}
		return false

	case PatternSegmentContains:
		segments := strings.Split(path, "/")
		for _, seg := range segments {
			if strings.Contains(seg, p.Value) {
				return true
			}
		}
		return false

	case PatternSegmentPrefix:
		segments := strings.Split(path, "/")
		for _, seg := range segments {
			if strings.HasPrefix(seg, p.Value) {
				return true
			}
		}
		return false

	case PatternSegmentSuffix:
		segments := strings.Split(path, "/")
		for _, seg := range segments {
			if strings.HasSuffix(seg, p.Value) {
				return true
			}
		}
		return false

	case PatternSegmentRegex:
		if p.compiled == nil {
			p.compiled, _ = regexp.Compile(p.Value)
		}
		if p.compiled == nil {
			return false
		}
		segments := strings.Split(path, "/")
		for _, seg := range segments {
			if p.compiled.MatchString(seg) {
				return true
			}
		}
		return false

	// File-level patterns
	case PatternFileExtension:
		ext := filepath.Ext(path)
		// Handle both ".js" and "js" in pattern value
		patternExt := p.Value
		if !strings.HasPrefix(patternExt, ".") {
			patternExt = "." + patternExt
		}
		return strings.EqualFold(ext, patternExt)

	case PatternFileName:
		filename := filepath.Base(path)
		return filename == p.Value

	case PatternFileGlob:
		filename := filepath.Base(path)
		matched, _ := filepath.Match(p.Value, filename)
		return matched

	default:
		return false
	}
}

// String returns string representation of pattern type.
func (pt PatternType) String() string {
	switch pt {
	case PatternPathContains:
		return "path_contains"
	case PatternPathPrefix:
		return "path_prefix"
	case PatternPathSuffix:
		return "path_suffix"
	case PatternPathExact:
		return "path_exact"
	case PatternPathRegex:
		return "path_regex"
	case PatternSegmentExact:
		return "segment_exact"
	case PatternSegmentContains:
		return "segment_contains"
	case PatternSegmentPrefix:
		return "segment_prefix"
	case PatternSegmentSuffix:
		return "segment_suffix"
	case PatternSegmentRegex:
		return "segment_regex"
	case PatternFileExtension:
		return "file_extension"
	case PatternFileName:
		return "file_name"
	case PatternFileGlob:
		return "file_glob"
	default:
		return "unknown"
	}
}

// ParsePatternType parses pattern type from string.
// Returns error for invalid pattern types - no backward compatibility.
func ParsePatternType(s string) (PatternType, error) {
	switch strings.ToLower(s) {
	// Path-level patterns
	case "path_contains":
		return PatternPathContains, nil
	case "path_prefix":
		return PatternPathPrefix, nil
	case "path_suffix":
		return PatternPathSuffix, nil
	case "path_exact":
		return PatternPathExact, nil
	case "path_regex":
		return PatternPathRegex, nil

	// Segment-level patterns
	case "segment_exact":
		return PatternSegmentExact, nil
	case "segment_contains":
		return PatternSegmentContains, nil
	case "segment_prefix":
		return PatternSegmentPrefix, nil
	case "segment_suffix":
		return PatternSegmentSuffix, nil
	case "segment_regex":
		return PatternSegmentRegex, nil

	// File-level patterns
	case "file_extension":
		return PatternFileExtension, nil
	case "file_name":
		return PatternFileName, nil
	case "file_glob":
		return PatternFileGlob, nil

	default:
		return 0, fmt.Errorf("invalid pattern type: %q (valid types: path_contains, path_prefix, path_suffix, path_exact, path_regex, segment_exact, segment_contains, segment_prefix, segment_suffix, segment_regex, file_extension, file_name, file_glob)", s)
	}
}

// ValidPatternTypes returns all valid pattern type strings.
func ValidPatternTypes() []string {
	return []string{
		"path_contains", "path_prefix", "path_suffix", "path_exact", "path_regex",
		"segment_exact", "segment_contains", "segment_prefix", "segment_suffix", "segment_regex",
		"file_extension", "file_name", "file_glob",
	}
}

// PatternMatcher provides efficient pattern matching across multiple patterns.
type PatternMatcher struct {
	patterns []Pattern
}

// NewPatternMatcher creates a new pattern matcher.
func NewPatternMatcher(patterns []Pattern) *PatternMatcher {
	pm := &PatternMatcher{
		patterns: make([]Pattern, len(patterns)),
	}
	copy(pm.patterns, patterns)

	// Pre-compile all regex patterns
	for i := range pm.patterns {
		_ = pm.patterns[i].Compile()
	}

	return pm
}

// MatchesAny returns true if path matches any pattern.
func (pm *PatternMatcher) MatchesAny(path string) bool {
	for _, p := range pm.patterns {
		if p.Matches(path) {
			return true
		}
	}
	return false
}

// MatchesAll returns true if path matches all patterns.
func (pm *PatternMatcher) MatchesAll(path string) bool {
	for _, p := range pm.patterns {
		if !p.Matches(path) {
			return false
		}
	}
	return true
}

// GetMatching returns all patterns that match the path.
func (pm *PatternMatcher) GetMatching(path string) []Pattern {
	var matching []Pattern
	for _, p := range pm.patterns {
		if p.Matches(path) {
			matching = append(matching, p)
		}
	}
	return matching
}

// isFileOnlyPattern returns true for patterns that only make sense for files.
func isFileOnlyPattern(t PatternType) bool {
	return t == PatternFileExtension || t == PatternFileName || t == PatternFileGlob
}

// MatchesDirectory checks if path matches patterns for directory matching.
func (pm *PatternMatcher) MatchesDirectory(path string) bool {
	for _, p := range pm.patterns {
		// Skip file-only patterns unless MatchFiles is set
		if isFileOnlyPattern(p.Type) && !p.MatchFiles {
			continue
		}
		if p.Matches(path) {
			return true
		}
	}
	return false
}

// MatchesFile checks if path matches patterns for file matching.
func (pm *PatternMatcher) MatchesFile(path string) bool {
	for _, p := range pm.patterns {
		if p.Matches(path) {
			return true
		}
	}
	return false
}
