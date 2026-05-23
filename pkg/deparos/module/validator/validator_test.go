package validator

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// ptrUint8 returns a pointer to a uint8 value for TaskActionConfig.Priority.
func ptrUint8(v uint8) *uint8 { return &v }

// validModuleConfig returns a ModuleConfig that should validate cleanly.
func validModuleConfig() *config.ModuleConfig {
	return &config.ModuleConfig{
		Enabled: true,
		BuiltIn: []string{"wildcard"},
		Custom: []config.CustomModuleConfig{
			{
				Name:     "api-module",
				Enabled:  true,
				Priority: 5,
				Patterns: []config.PatternConfig{
					{Type: "path_contains", Value: "api"},
					{Type: "path_regex", Value: "^/api/v[0-9]+/"},
				},
				Actions: config.ActionConfig{
					StopRecursion:     true,
					BlockTaskPatterns: []string{".*node_modules.*"},
					Tasks: []config.TaskActionConfig{
						{
							Wordlist:   config.WordlistShortFiles,
							Extensions: []string{"json", "xml"},
							Priority:   ptrUint8(7),
						},
					},
				},
			},
		},
	}
}

func TestSeverityString(t *testing.T) {
	assert.Equal(t, "error", SeverityError.String())
	assert.Equal(t, "warning", SeverityWarning.String())
	assert.Equal(t, "info", SeverityInfo.String())
	assert.Equal(t, "unknown", Severity(99).String())
}

func TestValidateConfig_NilConfig(t *testing.T) {
	result := ValidateConfig(nil, ValidateOptions{})
	require.NotNil(t, result)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.Errors)
	require.Len(t, result.Issues, 1)
	assert.Equal(t, SeverityError, result.Issues[0].Severity)
	assert.Equal(t, "config", result.Issues[0].Field)
}

func TestValidateConfig_Valid(t *testing.T) {
	result := ValidateConfig(validModuleConfig(), ValidateOptions{})
	require.NotNil(t, result)
	assert.True(t, result.Valid, "expected valid config, got issues: %+v", result.Issues)
	assert.Equal(t, 0, result.Errors)
	assert.Equal(t, 0, result.Warnings)

	require.Len(t, result.Modules, 1)
	summary := result.Modules[0]
	assert.Equal(t, "api-module", summary.Name)
	assert.True(t, summary.Enabled)
	assert.Equal(t, 5, summary.Priority)
	assert.Equal(t, 2, summary.PatternCount)
	// 1 task with 2 extensions => 2 task specs.
	assert.Equal(t, 2, summary.TaskCount)
}

func TestValidateConfig_TaskCountNoExtensions(t *testing.T) {
	cfg := &config.ModuleConfig{
		Custom: []config.CustomModuleConfig{
			{
				Name:     "no-ext",
				Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
				Actions: config.ActionConfig{
					Tasks: []config.TaskActionConfig{
						{Wordlist: config.WordlistShortFiles}, // no extensions => 1 task spec
					},
				},
			},
		},
	}
	result := ValidateConfig(cfg, ValidateOptions{})
	require.Len(t, result.Modules, 1)
	assert.Equal(t, 1, result.Modules[0].TaskCount)
}

func TestValidateConfig_InvalidBranches(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.ModuleConfig
		opts           ValidateOptions
		wantValid      bool
		minErrors      int
		minWarnings    int
		wantFieldSub   string // a substring expected in at least one issue Field
		wantMessageSub string // a substring expected in at least one issue Message
	}{
		{
			name: "missing name and no patterns",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						// Name empty, no patterns
					},
				},
			},
			wantValid:      false,
			minErrors:      2,
			wantFieldSub:   "name",
			wantMessageSub: "name is required",
		},
		{
			name: "pattern missing type",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Value: "x"}},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			wantMessageSub: "type is required",
		},
		{
			name: "pattern missing value",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "path_contains"}},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			wantMessageSub: "value is required",
		},
		{
			name: "invalid pattern type",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "not_a_type", Value: "x"}},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			wantMessageSub: "invalid pattern type",
		},
		{
			name: "invalid regex pattern value",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "path_regex", Value: "("}},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			wantMessageSub: "invalid regex",
		},
		{
			name: "glob double-star warning",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "file_glob", Value: "**/*.js"}},
					},
				},
			},
			wantValid:      true, // only a warning, not strict
			minWarnings:    1,
			wantMessageSub: "'**'",
		},
		{
			name: "glob double-star strict treated as invalid",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "file_glob", Value: "**/*.js"}},
					},
				},
			},
			opts:        ValidateOptions{Strict: true},
			wantValid:   false,
			minWarnings: 1,
		},
		{
			name: "invalid block_task_patterns regex",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
						Actions: config.ActionConfig{
							BlockTaskPatterns: []string{"["},
						},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			wantFieldSub:   "block_task_patterns",
			wantMessageSub: "invalid regex pattern",
		},
		{
			name: "invalid wordlist source",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
						Actions: config.ActionConfig{
							Tasks: []config.TaskActionConfig{
								{Wordlist: config.WordlistSource("bogus")},
							},
						},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			wantFieldSub:   "wordlist",
			wantMessageSub: "invalid wordlist source",
		},
		{
			name: "priority exceeds maximum",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
						Actions: config.ActionConfig{
							Tasks: []config.TaskActionConfig{
								{Wordlist: config.WordlistShortFiles, Priority: ptrUint8(20)},
							},
						},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			wantFieldSub:   "priority",
			wantMessageSub: "exceeds maximum",
		},
		{
			name: "custom wordlist missing file and inline",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
						Actions: config.ActionConfig{
							Tasks: []config.TaskActionConfig{
								{Wordlist: config.WordlistCustom},
							},
						},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			minWarnings:    1, // also emits empty-inline warning
			wantMessageSub: "custom wordlist requires",
		},
		{
			name: "custom wordlist both file and inline warns",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
						Actions: config.ActionConfig{
							Tasks: []config.TaskActionConfig{
								{
									Wordlist: config.WordlistCustom,
									File:     "/tmp/whatever.txt",
									Inline:   []string{"a", "b"},
								},
							},
						},
					},
				},
			},
			wantValid:      true,
			minWarnings:    1,
			wantMessageSub: "takes precedence",
		},
		{
			name: "extension with leading dot warns",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "m",
						Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
						Actions: config.ActionConfig{
							Tasks: []config.TaskActionConfig{
								{Wordlist: config.WordlistShortFiles, Extensions: []string{".php"}},
							},
						},
					},
				},
			},
			wantValid:      true,
			minWarnings:    1,
			wantFieldSub:   "extensions",
			wantMessageSub: "leading dot",
		},
		{
			name: "duplicate module names",
			cfg: &config.ModuleConfig{
				Custom: []config.CustomModuleConfig{
					{
						Name:     "dup",
						Patterns: []config.PatternConfig{{Type: "path_contains", Value: "a"}},
					},
					{
						Name:     "dup",
						Patterns: []config.PatternConfig{{Type: "path_contains", Value: "b"}},
					},
				},
			},
			wantValid:      false,
			minErrors:      1,
			wantFieldSub:   "modules",
			wantMessageSub: "duplicate module name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateConfig(tt.cfg, tt.opts)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantValid, result.Valid, "issues: %+v", result.Issues)
			assert.GreaterOrEqual(t, result.Errors, tt.minErrors, "issues: %+v", result.Issues)
			assert.GreaterOrEqual(t, result.Warnings, tt.minWarnings, "issues: %+v", result.Issues)

			if tt.wantFieldSub != "" {
				assert.True(t, anyIssueFieldContains(result.Issues, tt.wantFieldSub),
					"expected an issue field containing %q, issues: %+v", tt.wantFieldSub, result.Issues)
			}
			if tt.wantMessageSub != "" {
				assert.True(t, anyIssueMessageContains(result.Issues, tt.wantMessageSub),
					"expected an issue message containing %q, issues: %+v", tt.wantMessageSub, result.Issues)
			}
		})
	}
}

func TestValidateConfig_CheckWordlistsMissingFile(t *testing.T) {
	cfg := &config.ModuleConfig{
		Custom: []config.CustomModuleConfig{
			{
				Name:     "m",
				Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
				Actions: config.ActionConfig{
					Tasks: []config.TaskActionConfig{
						{
							Wordlist: config.WordlistCustom,
							File:     filepath.Join(t.TempDir(), "does-not-exist.txt"),
						},
					},
				},
			},
		},
	}
	result := ValidateConfig(cfg, ValidateOptions{CheckWordlists: true})
	assert.False(t, result.Valid)
	assert.True(t, anyIssueMessageContains(result.Issues, "custom wordlist file not found"),
		"issues: %+v", result.Issues)
}

func TestValidateConfig_CheckWordlistsExistingFile(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "words.txt")
	require.NoError(t, os.WriteFile(wl, []byte("alpha\nbeta\n"), 0o644))

	cfg := &config.ModuleConfig{
		Custom: []config.CustomModuleConfig{
			{
				Name:     "m",
				Patterns: []config.PatternConfig{{Type: "path_contains", Value: "x"}},
				Actions: config.ActionConfig{
					Tasks: []config.TaskActionConfig{
						{Wordlist: config.WordlistCustom, File: wl},
					},
				},
			},
		},
	}
	result := ValidateConfig(cfg, ValidateOptions{CheckWordlists: true})
	assert.True(t, result.Valid, "issues: %+v", result.Issues)
}

func TestValidateFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid yaml", func(t *testing.T) {
		path := filepath.Join(dir, "modules.yaml")
		yamlContent := `modules:
  built_in: [wildcard]
  custom:
    - name: api-module
      enabled: true
      priority: 5
      patterns:
        - type: path_contains
          value: api
      actions:
        stop_recursion: true
        tasks:
          - wordlist: short_files
            extensions: [json]
`
		require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o644))

		result, err := ValidateFile(path, ValidateOptions{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Valid, "issues: %+v", result.Issues)
		require.Len(t, result.Modules, 1)
		assert.Equal(t, "api-module", result.Modules[0].Name)
		assert.Greater(t, int64(result.Duration), int64(0))
	})

	t.Run("missing file returns validation error not error", func(t *testing.T) {
		result, err := ValidateFile(filepath.Join(dir, "nope.yaml"), ValidateOptions{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.Valid)
		assert.Equal(t, 1, result.Errors)
		require.Len(t, result.Issues, 1)
		assert.Equal(t, "file", result.Issues[0].Field)
	})

	t.Run("garbage yaml returns validation error", func(t *testing.T) {
		path := filepath.Join(dir, "garbage.yaml")
		require.NoError(t, os.WriteFile(path, []byte("modules: [this: is: not: valid"), 0o644))

		result, err := ValidateFile(path, ValidateOptions{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.False(t, result.Valid)
		assert.Equal(t, "file", result.Issues[0].Field)
	})
}

func TestLoadSampleLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wordlist.txt")
	content := "# comment line\n" +
		"\n" +
		"  alpha  \n" +
		"beta\n" +
		"# another comment\n" +
		"gamma\n" +
		"delta\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	t.Run("loads non-empty non-comment lines, trimmed", func(t *testing.T) {
		lines := LoadSampleLines(path, 10)
		assert.Equal(t, []string{"alpha", "beta", "gamma", "delta"}, lines)
	})

	t.Run("respects count limit", func(t *testing.T) {
		lines := LoadSampleLines(path, 2)
		assert.Equal(t, []string{"alpha", "beta"}, lines)
	})

	t.Run("missing file returns nil", func(t *testing.T) {
		assert.Nil(t, LoadSampleLines(filepath.Join(dir, "missing.txt"), 5))
	})
}

// anyIssueFieldContains reports whether any issue's Field contains sub.
func anyIssueFieldContains(issues []Issue, sub string) bool {
	for _, i := range issues {
		if contains(i.Field, sub) {
			return true
		}
	}
	return false
}

// anyIssueMessageContains reports whether any issue's Message contains sub.
func anyIssueMessageContains(issues []Issue, sub string) bool {
	for _, i := range issues {
		if contains(i.Message, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

// jsonRoundTrips asserts that the buffer contains valid JSON that unmarshals
// into the given target.
func jsonRoundTrips(t *testing.T, buf *bytes.Buffer, target any) {
	t.Helper()
	require.NotEmpty(t, buf.Bytes())
	require.NoError(t, json.Unmarshal(buf.Bytes(), target))
}
