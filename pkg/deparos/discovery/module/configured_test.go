package module

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/config"
)

func TestNewConfiguredModule(t *testing.T) {
	t.Run("creates module from config", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:        "test-module",
			Description: "Test module",
			Enabled:     true,
			Priority:    10,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "test"},
			},
		}

		m, err := NewConfiguredModule(cfg)

		require.NoError(t, err)
		assert.Equal(t, "test-module", m.Name())
		assert.Equal(t, "Test module", m.Description())
		assert.True(t, m.Enabled())
		assert.Equal(t, 10, m.Priority())
	})

	t.Run("compiles regex patterns", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "regex-module",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_regex", Value: `^/api/v[0-9]+/`},
			},
		}

		m, err := NewConfiguredModule(cfg)

		require.NoError(t, err)
		assert.NotNil(t, m)
	})

	t.Run("returns error for invalid regex", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "invalid",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_regex", Value: "[invalid"},
			},
		}

		_, err := NewConfiguredModule(cfg)

		assert.Error(t, err)
	})

	t.Run("compiles block patterns", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "blocker",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "test"},
			},
			Actions: config.ActionConfig{
				BlockTaskPatterns: []string{".*/css/.*", ".*/images/.*"},
			},
		}

		m, err := NewConfiguredModule(cfg)

		require.NoError(t, err)
		assert.Len(t, m.blockPatterns, 2)
	})

	t.Run("skips invalid block patterns", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "partial",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "test"},
			},
			Actions: config.ActionConfig{
				BlockTaskPatterns: []string{".*/valid/.*", "[invalid"},
			},
		}

		m, err := NewConfiguredModule(cfg)

		require.NoError(t, err)
		assert.Len(t, m.blockPatterns, 1) // Only valid pattern compiled
	})
}

func TestConfiguredModule_OnDirectoryMatch(t *testing.T) {
	t.Run("returns nil when path doesn't match", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "admin"},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		result, err := m.OnDirectoryMatch(context.Background(), &DirectoryEvent{
			Path: "/users/profile",
		})

		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("returns result when path matches", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "admin"},
			},
			Actions: config.ActionConfig{
				StopRecursion: true,
			},
		}
		m, _ := NewConfiguredModule(cfg)

		result, err := m.OnDirectoryMatch(context.Background(), &DirectoryEvent{
			Path: "/admin/settings",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.StopRecursion)
	})

	t.Run("creates tasks from config", func(t *testing.T) {
		prio := uint8(1)
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "js"},
			},
			Actions: config.ActionConfig{
				Tasks: []config.TaskActionConfig{
					{
						Wordlist:   config.WordlistObservedNames,
						Extensions: []string{".js", ".mjs"},
						Priority:   &prio,
					},
				},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		result, err := m.OnDirectoryMatch(context.Background(), &DirectoryEvent{
			Path: "/assets/js/",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		// Now creates 2 tasks (one per extension)
		require.Len(t, result.Tasks, 2)
		assert.Equal(t, config.WordlistObservedNames, result.Tasks[0].WordlistSource)
		assert.Equal(t, "js", result.Tasks[0].Extension) // normalized, first extension
		assert.Equal(t, uint8(1), result.Tasks[0].Priority)
		assert.Equal(t, config.WordlistObservedNames, result.Tasks[1].WordlistSource)
		assert.Equal(t, "mjs", result.Tasks[1].Extension) // normalized, second extension
		assert.Equal(t, uint8(1), result.Tasks[1].Priority)
	})

	t.Run("uses default priority when not specified", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "api"},
			},
			Actions: config.ActionConfig{
				Tasks: []config.TaskActionConfig{
					{
						Wordlist:   config.WordlistShortFiles,
						Extensions: []string{"json"},
					},
				},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		result, err := m.OnDirectoryMatch(context.Background(), &DirectoryEvent{
			Path: "/api/v1/",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Tasks, 1)
		assert.Equal(t, uint8(6), result.Tasks[0].Priority) // default
	})

	t.Run("creates multiple tasks", func(t *testing.T) {
		prio0 := uint8(0)
		prio5 := uint8(5)
		cfg := config.CustomModuleConfig{
			Name:    "backup",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "segment_contains", Value: "backup"},
			},
			Actions: config.ActionConfig{
				Tasks: []config.TaskActionConfig{
					{
						Wordlist:   config.WordlistObservedNames,
						Extensions: []string{"sql", "gz"},
						Priority:   &prio0,
					},
					{
						Wordlist:   config.WordlistShortFiles,
						Extensions: []string{"sql", "gz"},
						Priority:   &prio5,
					},
				},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		result, err := m.OnDirectoryMatch(context.Background(), &DirectoryEvent{
			Path: "/data/backup/",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Tasks, 4) // 2 TaskConfigs × 2 extensions each

		// Tasks from first TaskActionConfig (WordlistObservedNames, prio=0)
		assert.Equal(t, config.WordlistObservedNames, result.Tasks[0].WordlistSource)
		assert.Equal(t, "sql", result.Tasks[0].Extension)
		assert.Equal(t, uint8(0), result.Tasks[0].Priority)

		assert.Equal(t, config.WordlistObservedNames, result.Tasks[1].WordlistSource)
		assert.Equal(t, "gz", result.Tasks[1].Extension)
		assert.Equal(t, uint8(0), result.Tasks[1].Priority)

		// Tasks from second TaskActionConfig (WordlistShortFiles, prio=5)
		assert.Equal(t, config.WordlistShortFiles, result.Tasks[2].WordlistSource)
		assert.Equal(t, "sql", result.Tasks[2].Extension)
		assert.Equal(t, uint8(5), result.Tasks[2].Priority)

		assert.Equal(t, config.WordlistShortFiles, result.Tasks[3].WordlistSource)
		assert.Equal(t, "gz", result.Tasks[3].Extension)
		assert.Equal(t, uint8(5), result.Tasks[3].Priority)
	})

	t.Run("returns block patterns", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "static"},
			},
			Actions: config.ActionConfig{
				BlockTaskPatterns: []string{".*/css/.*", ".*/images/.*"},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		result, err := m.OnDirectoryMatch(context.Background(), &DirectoryEvent{
			Path: "/static/assets",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Len(t, result.BlockTaskPatterns, 2)
	})
}

func TestConfiguredModule_OnFileMatch(t *testing.T) {
	t.Run("returns nil when path doesn't match", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "file_extension", Value: ".js", MatchFiles: true},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		result, err := m.OnFileMatch(context.Background(), &FileEvent{
			Path: "/styles/main.css",
		})

		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("returns result when file matches", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "file_extension", Value: ".js", MatchFiles: true},
			},
			Actions: config.ActionConfig{
				SkipDefaultLogic: true,
			},
		}
		m, _ := NewConfiguredModule(cfg)

		result, err := m.OnFileMatch(context.Background(), &FileEvent{
			Path: "/scripts/app.js",
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.SkipDefaultLogic)
	})
}

func TestConfiguredModule_ShouldAddTask(t *testing.T) {
	t.Run("allows task when no block patterns", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "test"},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		task := &mockTask{baseURL: []byte("/any/path")}
		assert.True(t, m.ShouldAddTask(task))
	})

	t.Run("blocks task matching pattern", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "test"},
			},
			Actions: config.ActionConfig{
				BlockTaskPatterns: []string{".*/css/.*"},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		task := &mockTask{baseURL: []byte("/static/css/main.css")}
		assert.False(t, m.ShouldAddTask(task))
	})

	t.Run("allows task not matching block pattern", func(t *testing.T) {
		cfg := config.CustomModuleConfig{
			Name:    "test",
			Enabled: true,
			Patterns: []config.PatternConfig{
				{Type: "path_contains", Value: "test"},
			},
			Actions: config.ActionConfig{
				BlockTaskPatterns: []string{".*/css/.*"},
			},
		}
		m, _ := NewConfiguredModule(cfg)

		task := &mockTask{baseURL: []byte("/api/users")}
		assert.True(t, m.ShouldAddTask(task))
	})
}

func TestLoadConfiguredModules(t *testing.T) {
	t.Run("loads multiple modules", func(t *testing.T) {
		configs := []config.CustomModuleConfig{
			{
				Name:    "mod1",
				Enabled: true,
				Patterns: []config.PatternConfig{
					{Type: "path_contains", Value: "admin"},
				},
			},
			{
				Name:    "mod2",
				Enabled: true,
				Patterns: []config.PatternConfig{
					{Type: "path_prefix", Value: "/api/"},
				},
			},
		}

		modules, err := LoadConfiguredModules(configs)

		require.NoError(t, err)
		assert.Len(t, modules, 2)
		assert.Equal(t, "mod1", modules[0].Name())
		assert.Equal(t, "mod2", modules[1].Name())
	})

	t.Run("returns error on invalid config", func(t *testing.T) {
		configs := []config.CustomModuleConfig{
			{
				Name:    "valid",
				Enabled: true,
				Patterns: []config.PatternConfig{
					{Type: "path_contains", Value: "test"},
				},
			},
			{
				Name:    "invalid",
				Enabled: true,
				Patterns: []config.PatternConfig{
					{Type: "path_regex", Value: "[invalid"},
				},
			},
		}

		_, err := LoadConfiguredModules(configs)

		assert.Error(t, err)
	})

	t.Run("handles empty config", func(t *testing.T) {
		modules, err := LoadConfiguredModules(nil)

		require.NoError(t, err)
		assert.Nil(t, modules)
	})
}

func TestConfiguredModule_PatternTypes(t *testing.T) {
	tests := []struct {
		name     string
		pattern  config.PatternConfig
		path     string
		expected bool
	}{
		{
			name:     "path_exact match",
			pattern:  config.PatternConfig{Type: "path_exact", Value: "/admin/"},
			path:     "/admin/",
			expected: true,
		},
		{
			name:     "path_prefix match",
			pattern:  config.PatternConfig{Type: "path_prefix", Value: "/api/"},
			path:     "/api/v1/users",
			expected: true,
		},
		{
			name:     "path_suffix match",
			pattern:  config.PatternConfig{Type: "path_suffix", Value: "/settings/"},
			path:     "/user/settings/",
			expected: true,
		},
		{
			name:     "path_contains match",
			pattern:  config.PatternConfig{Type: "path_contains", Value: "admin"},
			path:     "/super/admin/panel",
			expected: true,
		},
		{
			name:     "path_regex match",
			pattern:  config.PatternConfig{Type: "path_regex", Value: `^/api/v[0-9]+/`},
			path:     "/api/v2/users",
			expected: true,
		},
		{
			name:     "segment_exact match",
			pattern:  config.PatternConfig{Type: "segment_exact", Value: "backup"},
			path:     "/foo/backup/bar",
			expected: true,
		},
		{
			name:     "segment_contains match",
			pattern:  config.PatternConfig{Type: "segment_contains", Value: "backup"},
			path:     "/foo/mybackup/bar",
			expected: true,
		},
		{
			name:     "negated match",
			pattern:  config.PatternConfig{Type: "path_contains", Value: "admin", Negated: true},
			path:     "/user/profile",
			expected: true,
		},
		{
			name:     "negated no match",
			pattern:  config.PatternConfig{Type: "path_contains", Value: "admin", Negated: true},
			path:     "/admin/panel",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.CustomModuleConfig{
				Name:     "test",
				Enabled:  true,
				Patterns: []config.PatternConfig{tt.pattern},
				Actions: config.ActionConfig{
					StopRecursion: true,
				},
			}
			m, err := NewConfiguredModule(cfg)
			require.NoError(t, err)

			result, err := m.OnDirectoryMatch(context.Background(), &DirectoryEvent{
				Path: tt.path,
			})

			require.NoError(t, err)
			if tt.expected {
				assert.NotNil(t, result)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}
