package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPattern_Matches(t *testing.T) {
	tests := []struct {
		name     string
		pattern  Pattern
		input    string
		expected bool
	}{
		// PATH-LEVEL PATTERNS

		// path_exact - full path equality
		{"path_exact match", NewPattern(PatternPathExact, "/js/"), "/js/", true},
		{"path_exact no match", NewPattern(PatternPathExact, "/js/"), "/css/", false},
		{"path_exact case sensitive", NewPattern(PatternPathExact, "/JS/"), "/js/", false},

		// path_prefix - path starts with value
		{"path_prefix match", NewPattern(PatternPathPrefix, "/api/"), "/api/v1/users", true},
		{"path_prefix match root", NewPattern(PatternPathPrefix, "/"), "/anything", true},
		{"path_prefix no match", NewPattern(PatternPathPrefix, "/api/"), "/users/api", false},

		// path_suffix - path ends with value
		{"path_suffix match", NewPattern(PatternPathSuffix, "/admin/"), "/panel/admin/", true},
		{"path_suffix match dir", NewPattern(PatternPathSuffix, "/css/"), "/static/css/", true},
		{"path_suffix no match", NewPattern(PatternPathSuffix, "/admin/"), "/admin/panel/", false},

		// path_contains - value appears anywhere in full path
		{"path_contains match", NewPattern(PatternPathContains, "backup"), "/data/backup/files", true},
		{"path_contains match anywhere", NewPattern(PatternPathContains, "admin"), "/superadministrator/", true},
		{"path_contains no match", NewPattern(PatternPathContains, "backup"), "/data/files", false},

		// path_regex - regex on full path
		{"path_regex match version", NewPattern(PatternPathRegex, `^/api/v[0-9]+/`), "/api/v2/users", true},
		{"path_regex match digits", NewPattern(PatternPathRegex, `\d+`), "/users/123/profile", true},
		{"path_regex match complex", NewPattern(PatternPathRegex, `^/v[0-9]+\.(json|xml)$`), "/v1.json", true},
		{"path_regex no match", NewPattern(PatternPathRegex, `^/api/v[0-9]+/`), "/users/v1/api", false},

		// SEGMENT-LEVEL PATTERNS

		// segment_exact - exact match on any path segment
		{"segment_exact match", NewPattern(PatternSegmentExact, "backup"), "/foo/backup/bar", true},
		{"segment_exact match single", NewPattern(PatternSegmentExact, "admin"), "/admin/", true},
		{"segment_exact no match (partial)", NewPattern(PatternSegmentExact, "backup"), "/mybackup/", false},
		{"segment_exact no match", NewPattern(PatternSegmentExact, "backup"), "/data/files", false},

		// segment_contains - substring in any segment
		{"segment_contains match", NewPattern(PatternSegmentContains, "backup"), "/mybackup/foo", true},
		{"segment_contains match any segment", NewPattern(PatternSegmentContains, "admin"), "/adminpanel/", true},
		{"segment_contains no match", NewPattern(PatternSegmentContains, "xyz"), "/data/files", false},

		// segment_prefix - segment starts with value
		{"segment_prefix match", NewPattern(PatternSegmentPrefix, "admin"), "/adminpanel/foo", true},
		{"segment_prefix match exact", NewPattern(PatternSegmentPrefix, "admin"), "/admin/", true},
		{"segment_prefix no match", NewPattern(PatternSegmentPrefix, "admin"), "/superadmin/", false},

		// segment_suffix - segment ends with value
		{"segment_suffix match", NewPattern(PatternSegmentSuffix, "backup"), "/mybackup/foo", true},
		{"segment_suffix match exact", NewPattern(PatternSegmentSuffix, "backup"), "/backup/", true},
		{"segment_suffix no match", NewPattern(PatternSegmentSuffix, "backup"), "/backups/", false},

		// segment_regex - regex on any path segment
		{"segment_regex match start", NewPattern(PatternSegmentRegex, "^old"), "/old/", true},
		{"segment_regex match start with suffix", NewPattern(PatternSegmentRegex, "^old"), "/old-data/", true},
		{"segment_regex match start with underscore", NewPattern(PatternSegmentRegex, "^old"), "/old_backup/", true},
		{"segment_regex no match folder", NewPattern(PatternSegmentRegex, "^old"), "/folder/", false},
		{"segment_regex no match suffix", NewPattern(PatternSegmentRegex, "^old"), "/myold/", false},
		{"segment_regex match word boundary", NewPattern(PatternSegmentRegex, `\badmin\b`), "/admin/", true},
		{"segment_regex no match word boundary", NewPattern(PatternSegmentRegex, `\badmin\b`), "/administrator/", false},

		// FILE-LEVEL PATTERNS

		// file_glob - glob pattern on filename
		{"file_glob match js file", NewPattern(PatternFileGlob, "*.js"), "app.js", true},
		{"file_glob match segment", NewPattern(PatternFileGlob, "*.js"), "/scripts/app.js", true},
		{"file_glob match prefix", NewPattern(PatternFileGlob, "config*"), "config.yaml", true},
		{"file_glob no match", NewPattern(PatternFileGlob, "*.js"), "app.css", false},

		// file_extension - file extension (case-insensitive)
		{"file_extension match with dot", NewPattern(PatternFileExtension, ".js"), "/scripts/app.js", true},
		{"file_extension match without dot", NewPattern(PatternFileExtension, "js"), "/scripts/app.js", true},
		{"file_extension match css", NewPattern(PatternFileExtension, ".css"), "/styles/main.css", true},
		{"file_extension case insensitive", NewPattern(PatternFileExtension, ".JS"), "/scripts/app.js", true},
		{"file_extension no match", NewPattern(PatternFileExtension, ".js"), "/scripts/app.css", false},
		// Note: filepath.Ext returns only last extension, so .min.js -> .js
		{"file_extension nested path", NewPattern(PatternFileExtension, ".js"), "/bundle.min.js", true},

		// file_name - exact filename match
		{"file_name match", NewPattern(PatternFileName, "config.json"), "/any/path/config.json", true},
		{"file_name match root", NewPattern(PatternFileName, "config.json"), "/config.json", true},
		{"file_name no match", NewPattern(PatternFileName, "config.json"), "/config.yaml", false},

		// NEGATED PATTERNS
		{"negated path_contains - match", NewNegatedPattern(PatternPathContains, "admin"), "/user/profile", true},
		{"negated path_contains - no match", NewNegatedPattern(PatternPathContains, "admin"), "/admin/panel", false},
		{"negated path_exact - match", NewNegatedPattern(PatternPathExact, "/js/"), "/css/", true},
		{"negated path_exact - no match", NewNegatedPattern(PatternPathExact, "/js/"), "/js/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pattern.Matches(tt.input)
			assert.Equal(t, tt.expected, result,
				"Pattern %s with value %q should match %q = %v",
				tt.pattern.Type, tt.pattern.Value, tt.input, tt.expected)
		})
	}
}

func TestPattern_Compile(t *testing.T) {
	t.Run("path_regex pattern compiles successfully", func(t *testing.T) {
		p := Pattern{Type: PatternPathRegex, Value: `^/api/v[0-9]+/`}
		err := p.Compile()
		require.NoError(t, err)
		assert.NotNil(t, p.compiled)
	})

	t.Run("segment_regex pattern compiles successfully", func(t *testing.T) {
		p := Pattern{Type: PatternSegmentRegex, Value: `^old`}
		err := p.Compile()
		require.NoError(t, err)
		assert.NotNil(t, p.compiled)
	})

	t.Run("invalid path_regex returns error", func(t *testing.T) {
		p := Pattern{Type: PatternPathRegex, Value: `[invalid`}
		err := p.Compile()
		assert.Error(t, err)
	})

	t.Run("invalid segment_regex returns error", func(t *testing.T) {
		p := Pattern{Type: PatternSegmentRegex, Value: `[invalid`}
		err := p.Compile()
		assert.Error(t, err)
	})

	t.Run("non-regex pattern compile is noop", func(t *testing.T) {
		p := Pattern{Type: PatternPathContains, Value: "admin"}
		err := p.Compile()
		require.NoError(t, err)
		assert.Nil(t, p.compiled)
	})
}

func TestNewPattern(t *testing.T) {
	t.Run("creates pattern with type and value", func(t *testing.T) {
		p := NewPattern(PatternPathPrefix, "/api/")
		assert.Equal(t, PatternPathPrefix, p.Type)
		assert.Equal(t, "/api/", p.Value)
		assert.False(t, p.Negated)
		assert.False(t, p.MatchFiles)
	})

	t.Run("regex pattern is pre-compiled", func(t *testing.T) {
		p := NewPattern(PatternPathRegex, `^/api/`)
		assert.NotNil(t, p.compiled)
	})
}

func TestNewNegatedPattern(t *testing.T) {
	p := NewNegatedPattern(PatternPathContains, "admin")
	assert.Equal(t, PatternPathContains, p.Type)
	assert.Equal(t, "admin", p.Value)
	assert.True(t, p.Negated)
}

func TestNewFilePattern(t *testing.T) {
	p := NewFilePattern(PatternFileExtension, ".js")
	assert.Equal(t, PatternFileExtension, p.Type)
	assert.Equal(t, ".js", p.Value)
	assert.True(t, p.MatchFiles)
}

func TestPatternType_String(t *testing.T) {
	tests := []struct {
		pt       PatternType
		expected string
	}{
		{PatternPathContains, "path_contains"},
		{PatternPathPrefix, "path_prefix"},
		{PatternPathSuffix, "path_suffix"},
		{PatternPathExact, "path_exact"},
		{PatternPathRegex, "path_regex"},
		{PatternSegmentExact, "segment_exact"},
		{PatternSegmentContains, "segment_contains"},
		{PatternSegmentPrefix, "segment_prefix"},
		{PatternSegmentSuffix, "segment_suffix"},
		{PatternFileExtension, "file_extension"},
		{PatternFileName, "file_name"},
		{PatternFileGlob, "file_glob"},
		{PatternType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pt.String())
		})
	}
}

func TestParsePatternType(t *testing.T) {
	tests := []struct {
		input       string
		expected    PatternType
		expectError bool
	}{
		// Valid pattern types
		{"path_contains", PatternPathContains, false},
		{"PATH_CONTAINS", PatternPathContains, false},
		{"path_prefix", PatternPathPrefix, false},
		{"path_suffix", PatternPathSuffix, false},
		{"path_exact", PatternPathExact, false},
		{"path_regex", PatternPathRegex, false},
		{"segment_exact", PatternSegmentExact, false},
		{"segment_contains", PatternSegmentContains, false},
		{"segment_prefix", PatternSegmentPrefix, false},
		{"segment_suffix", PatternSegmentSuffix, false},
		{"file_extension", PatternFileExtension, false},
		{"file_name", PatternFileName, false},
		{"file_glob", PatternFileGlob, false},

		// Invalid pattern types (old types no longer supported)
		{"contains", 0, true},
		{"prefix", 0, true},
		{"suffix", 0, true},
		{"exact", 0, true},
		{"regex", 0, true},
		{"extension", 0, true},
		{"glob", 0, true},
		{"unknown", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pt, err := ParsePatternType(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, pt)
			}
		})
	}
}

func TestPatternMatcher_MatchesAny(t *testing.T) {
	patterns := []Pattern{
		NewPattern(PatternPathSuffix, "/css/"),
		NewPattern(PatternPathSuffix, "/js/"),
		NewPattern(PatternPathContains, "admin"),
	}
	matcher := NewPatternMatcher(patterns)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"matches css suffix", "/static/css/", true},
		{"matches js suffix", "/assets/js/", true},
		{"matches contains admin", "/panel/admin/users", true},
		{"no match", "/api/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, matcher.MatchesAny(tt.path))
		})
	}
}

func TestPatternMatcher_MatchesAll(t *testing.T) {
	patterns := []Pattern{
		NewPattern(PatternPathPrefix, "/api/"),
		NewPattern(PatternPathContains, "v1"),
	}
	matcher := NewPatternMatcher(patterns)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"matches all", "/api/v1/users", true},
		{"matches only prefix", "/api/v2/users", false},
		{"matches only contains", "/users/v1/profile", false},
		{"matches none", "/users/profile", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, matcher.MatchesAll(tt.path))
		})
	}
}

func TestPatternMatcher_GetMatching(t *testing.T) {
	patterns := []Pattern{
		NewPattern(PatternPathSuffix, "/css/"),
		NewPattern(PatternPathSuffix, "/js/"),
		NewPattern(PatternPathContains, "static"),
	}
	matcher := NewPatternMatcher(patterns)

	t.Run("returns all matching patterns", func(t *testing.T) {
		matching := matcher.GetMatching("/static/css/")
		assert.Len(t, matching, 2) // css suffix + contains static
	})

	t.Run("returns empty for no matches", func(t *testing.T) {
		matching := matcher.GetMatching("/api/users")
		assert.Empty(t, matching)
	})
}

func TestPatternMatcher_MatchesDirectory(t *testing.T) {
	patterns := []Pattern{
		NewPattern(PatternPathSuffix, "/js/"),
		NewPattern(PatternFileExtension, ".js"), // Should be skipped for directory
	}
	matcher := NewPatternMatcher(patterns)

	t.Run("matches directory pattern", func(t *testing.T) {
		assert.True(t, matcher.MatchesDirectory("/assets/js/"))
	})

	t.Run("skips extension pattern without MatchFiles", func(t *testing.T) {
		// Extension patterns without MatchFiles should not match directories
		extensionOnly := []Pattern{
			NewPattern(PatternFileExtension, ".js"),
		}
		m := NewPatternMatcher(extensionOnly)
		assert.False(t, m.MatchesDirectory("/scripts/"))
	})

	t.Run("extension pattern with MatchFiles matches", func(t *testing.T) {
		filePatterns := []Pattern{
			NewFilePattern(PatternFileExtension, ".js"),
		}
		m := NewPatternMatcher(filePatterns)
		assert.True(t, m.MatchesDirectory("/scripts/app.js"))
	})
}

func TestPatternMatcher_MatchesFile(t *testing.T) {
	patterns := []Pattern{
		NewPattern(PatternFileExtension, ".js"),
		NewPattern(PatternPathContains, "min"),
	}
	matcher := NewPatternMatcher(patterns)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"matches extension", "/scripts/app.js", true},
		{"matches contains", "/bundle.min.css", true},
		{"matches both", "/bundle.min.js", true},
		{"no match", "/styles/main.css", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, matcher.MatchesFile(tt.path))
		})
	}
}

func TestPatternMatcher_Empty(t *testing.T) {
	matcher := NewPatternMatcher(nil)

	t.Run("MatchesAny returns false", func(t *testing.T) {
		assert.False(t, matcher.MatchesAny("/any/path"))
	})

	t.Run("MatchesAll returns true (vacuous truth)", func(t *testing.T) {
		assert.True(t, matcher.MatchesAll("/any/path"))
	})

	t.Run("GetMatching returns empty", func(t *testing.T) {
		assert.Empty(t, matcher.GetMatching("/any/path"))
	})
}
