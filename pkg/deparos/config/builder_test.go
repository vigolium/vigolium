package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	b := NewBuilder()

	require.NotNil(t, b)
	require.NotNil(t, b.config)
	assert.Empty(t, b.errors)

	// Verify it starts with defaults
	assert.Equal(t, ModeFilesAndDirs, b.config.Target.Mode)
	assert.True(t, b.config.Target.Recursion.Enabled)
	assert.Equal(t, int16(16), b.config.Target.Recursion.MaxDepth)
}

func TestBuilder_WithStartURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid http URL",
			url:     "http://example.com/",
			wantErr: false,
		},
		{
			name:    "valid https URL",
			url:     "https://example.com/",
			wantErr: false,
		},
		{
			name:    "empty URL fails validation",
			url:     "",
			wantErr: true,
		},
		{
			name:    "invalid URL fails validation",
			url:     "not-a-url",
			wantErr: true,
		},
		{
			name:    "ftp scheme fails validation",
			url:     "ftp://example.com/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL(tt.url).
				Build()

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				assert.Equal(t, tt.url, cfg.Target.StartURL)
			}
		})
	}
}

func TestBuilder_WithDiscoveryMode(t *testing.T) {
	tests := []struct {
		name string
		mode DiscoveryMode
	}{
		{"files and dirs", ModeFilesAndDirs},
		{"files only", ModeFilesOnly},
		{"dirs only", ModeDirsOnly},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL("http://example.com/").
				WithDiscoveryMode(tt.mode).
				Build()

			require.NoError(t, err)
			assert.Equal(t, tt.mode, cfg.Target.Mode)
		})
	}
}

func TestBuilder_WithRecursion(t *testing.T) {
	var overflowDepth int16 = 32767
	overflowDepth++

	tests := []struct {
		name     string
		enabled  bool
		maxDepth int16
		wantErr  bool
	}{
		{
			name:     "enabled with valid depth",
			enabled:  true,
			maxDepth: 8,
			wantErr:  false,
		},
		{
			name:     "disabled with any depth",
			enabled:  false,
			maxDepth: 999,
			wantErr:  false,
		},
		{
			name:     "enabled with min depth",
			enabled:  true,
			maxDepth: 1,
			wantErr:  false,
		},
		{
			name:     "enabled with max depth",
			enabled:  true,
			maxDepth: 32767,
			wantErr:  false,
		},
		{
			name:     "enabled with zero depth fails",
			enabled:  true,
			maxDepth: 0,
			wantErr:  true,
		},
		{
			name:     "enabled with negative depth fails",
			enabled:  true,
			maxDepth: -1,
			wantErr:  true,
		},
		{
			name:     "enabled with too large depth fails",
			enabled:  true,
			maxDepth: overflowDepth, // Just over int16 max
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL("http://example.com/").
				WithRecursion(tt.enabled, tt.maxDepth).
				Build()

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.enabled, cfg.Target.Recursion.Enabled)
				assert.Equal(t, tt.maxDepth, cfg.Target.Recursion.MaxDepth)
			}
		})
	}
}

func TestBuilder_WithThreads(t *testing.T) {
	tests := []struct {
		name            string
		discoveryThread int
		wantErr         bool
	}{
		{
			name:            "valid default threads",
			discoveryThread: 4,
			wantErr:         false,
		},
		{
			name:            "valid min threads",
			discoveryThread: 1,
			wantErr:         false,
		},
		{
			name:            "valid max discovery threads",
			discoveryThread: 255,
			wantErr:         false,
		},
		{
			name:            "discovery threads zero fails",
			discoveryThread: 0,
			wantErr:         true,
		},
		{
			name:            "discovery threads exceeds limit",
			discoveryThread: 256,
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL("http://example.com/").
				WithThreads(tt.discoveryThread).
				Build()

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.discoveryThread, cfg.Engine.DiscoveryThreads)
			}
		})
	}
}

func TestBuilder_WithTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		wantErr bool
	}{
		{
			name:    "valid default timeout",
			timeout: 30 * time.Second,
			wantErr: false,
		},
		{
			name:    "valid min timeout",
			timeout: 1 * time.Second,
			wantErr: false,
		},
		{
			name:    "valid max timeout",
			timeout: 300 * time.Second,
			wantErr: false,
		},
		{
			name:    "timeout too short fails",
			timeout: 500 * time.Millisecond,
			wantErr: true,
		},
		{
			name:    "timeout too long fails",
			timeout: 301 * time.Second,
			wantErr: true,
		},
		{
			name:    "zero timeout fails",
			timeout: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL("http://example.com/").
				WithTimeout(tt.timeout).
				Build()

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.timeout, cfg.Engine.Timeout)
			}
		})
	}
}

func TestBuilder_WithCaseSensitivity(t *testing.T) {
	modes := []CaseSensitivityMode{
		CaseSensitive,
		CaseInsensitive,
		CaseAutoDetect,
	}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL("http://example.com/").
				WithCaseSensitivity(mode).
				Build()

			require.NoError(t, err)
			assert.Equal(t, mode, cfg.Engine.CaseSensitivity)
		})
	}
}

func TestBuilder_WithCustomExtensions(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		extensions []string
		wantErr    bool
	}{
		{
			name:       "enabled with extensions",
			enabled:    true,
			extensions: []string{"php", "asp"},
			wantErr:    false,
		},
		{
			name:       "disabled with empty list",
			enabled:    false,
			extensions: []string{},
			wantErr:    false,
		},
		{
			name:       "enabled with empty list fails",
			enabled:    true,
			extensions: []string{},
			wantErr:    true,
		},
		{
			name:       "enabled with nil keeps defaults (passes)",
			enabled:    true,
			extensions: nil, // nil means keep defaults
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL("http://example.com/").
				WithCustomExtensions(tt.enabled, tt.extensions).
				Build()

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.enabled, cfg.Extensions.TestCustom)
				if tt.extensions != nil {
					assert.Equal(t, tt.extensions, cfg.Extensions.CustomList)
				}
			}
		})
	}
}

func TestBuilder_WithBackupExtensions(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		extensions []string
		wantErr    bool
	}{
		{
			name:       "enabled with extensions",
			enabled:    true,
			extensions: []string{"bak", "old"},
			wantErr:    false,
		},
		{
			name:       "disabled with empty list",
			enabled:    false,
			extensions: []string{},
			wantErr:    false,
		},
		{
			name:       "enabled with empty list fails",
			enabled:    true,
			extensions: []string{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL("http://example.com/").
				WithBackupExtensions(tt.enabled, tt.extensions).
				Build()

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.enabled, cfg.Extensions.TestBackupExtensions)
				if tt.extensions != nil {
					assert.Equal(t, tt.extensions, cfg.Extensions.BackupExtensions)
				}
			}
		})
	}
}

func TestBuilder_FluentChaining(t *testing.T) {
	cfg, err := NewBuilder().
		WithStartURL("http://example.com/api/").
		WithDiscoveryMode(ModeFilesOnly).
		WithRecursion(true, 8).
		WithThreads(8).
		WithTimeout(60*time.Second).
		WithCaseSensitivity(CaseSensitive).
		WithCustomExtensions(true, []string{"php", "jsp"}).
		WithObservedNames(false).
		WithDerivedNames(false).
		WithNoExtension(false).
		Build()

	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify all settings applied
	assert.Equal(t, "http://example.com/api/", cfg.Target.StartURL)
	assert.Equal(t, ModeFilesOnly, cfg.Target.Mode)
	assert.True(t, cfg.Target.Recursion.Enabled)
	assert.Equal(t, int16(8), cfg.Target.Recursion.MaxDepth)
	assert.Equal(t, 8, cfg.Engine.DiscoveryThreads)
	assert.Equal(t, 60*time.Second, cfg.Engine.Timeout)
	assert.Equal(t, CaseSensitive, cfg.Engine.CaseSensitivity)
	assert.True(t, cfg.Extensions.TestCustom)
	assert.Equal(t, []string{"php", "jsp"}, cfg.Extensions.CustomList)
	assert.False(t, cfg.Filenames.UseObservedNames)
	assert.False(t, cfg.Filenames.EnableNumericFuzzing)
	assert.False(t, cfg.Extensions.TestNoExtension)
}

func TestBuilder_Reset(t *testing.T) {
	b := NewBuilder().
		WithStartURL("http://example.com/").
		WithDiscoveryMode(ModeFilesOnly)

	// Build first config
	cfg1, err := b.Build()
	require.NoError(t, err)
	assert.Equal(t, "http://example.com/", cfg1.Target.StartURL)
	assert.Equal(t, ModeFilesOnly, cfg1.Target.Mode)

	// Reset and build new config
	cfg2, err := b.Reset().
		WithStartURL("http://other.com/").
		WithDiscoveryMode(ModeDirsOnly).
		Build()

	require.NoError(t, err)
	assert.Equal(t, "http://other.com/", cfg2.Target.StartURL)
	assert.Equal(t, ModeDirsOnly, cfg2.Target.Mode)

	// Verify original config unchanged
	assert.Equal(t, "http://example.com/", cfg1.Target.StartURL)
	assert.Equal(t, ModeFilesOnly, cfg1.Target.Mode)
}

func TestBuilder_MultipleErrors(t *testing.T) {
	// Validation fails fast on first error (empty URL)
	_, err := NewBuilder().
		WithStartURL("").       // empty URL error (stops here)
		WithRecursion(true, 0). // invalid depth error (not reached)
		WithThreads(0).         // invalid threads error (not reached)
		Build()

	require.Error(t, err)
	// Should contain URL error (first validation failure)
	errMsg := err.Error()
	assert.Contains(t, errMsg, "URL")
}

func TestQuickConfig(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid URL",
			url:     "http://example.com/",
			wantErr: false,
		},
		{
			name:    "empty URL fails",
			url:     "",
			wantErr: true,
		},
		{
			name:    "invalid URL fails",
			url:     "not-a-url",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := QuickConfig(tt.url)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				assert.Equal(t, tt.url, cfg.Target.StartURL)
				// Verify defaults are used
				assert.Equal(t, ModeFilesAndDirs, cfg.Target.Mode)
				assert.Equal(t, 40, cfg.Engine.DiscoveryThreads)
			}
		})
	}
}

func TestBuilder_WithWordlists(t *testing.T) {
	// Create temp wordlist files for testing
	tmpDir := t.TempDir()
	shortFileWordlist := filepath.Join(tmpDir, "short_files.txt")
	longFileWordlist := filepath.Join(tmpDir, "long_files.txt")
	shortDirWordlist := filepath.Join(tmpDir, "short_dirs.txt")
	longDirWordlist := filepath.Join(tmpDir, "long_dirs.txt")

	require.NoError(t, os.WriteFile(shortFileWordlist, []byte("admin\nconfig\n"), 0644))
	require.NoError(t, os.WriteFile(longFileWordlist, []byte("administrator\nconfiguration\n"), 0644))
	require.NoError(t, os.WriteFile(shortDirWordlist, []byte("admin\napi\n"), 0644))
	require.NoError(t, os.WriteFile(longDirWordlist, []byte("administrator\napplication\n"), 0644))

	tests := []struct {
		name        string
		paths       [4]string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid with all paths provided",
			paths:   [4]string{shortFileWordlist, longFileWordlist, shortDirWordlist, longDirWordlist},
			wantErr: false,
		},
		{
			name:    "valid with partial paths",
			paths:   [4]string{shortFileWordlist, "", shortDirWordlist, ""},
			wantErr: false,
		},
		{
			name:    "valid with no paths (all disabled)",
			paths:   [4]string{"", "", "", ""},
			wantErr: false,
		},
		{
			name:        "error when wordlist file does not exist",
			paths:       [4]string{"/nonexistent/wordlist.txt", "", "", ""},
			wantErr:     true,
			errContains: "not found",
		},
		{
			name:        "error when directory provided instead of file",
			paths:       [4]string{tmpDir, "", "", ""},
			wantErr:     true,
			errContains: "not a regular file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewBuilder().
				WithStartURL("http://example.com/").
				WithWordlists(tt.paths[0], tt.paths[1], tt.paths[2], tt.paths[3]).
				Build()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, cfg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				assert.Equal(t, tt.paths[0], cfg.Filenames.Wordlists.ShortFilePath)
				assert.Equal(t, tt.paths[1], cfg.Filenames.Wordlists.LongFilePath)
				assert.Equal(t, tt.paths[2], cfg.Filenames.Wordlists.ShortDirPath)
				assert.Equal(t, tt.paths[3], cfg.Filenames.Wordlists.LongDirPath)
			}
		})
	}
}

func TestWordlistConfig_HasMethods(t *testing.T) {
	// Create temp wordlist
	tmpDir := t.TempDir()
	wordlist := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(wordlist, []byte("test\n"), 0644))

	cfg, err := NewBuilder().
		WithStartURL("http://example.com/").
		WithWordlists(wordlist, "", wordlist, "").
		Build()

	require.NoError(t, err)

	// Test Has* helper methods
	assert.True(t, cfg.Filenames.Wordlists.HasShortFiles())
	assert.False(t, cfg.Filenames.Wordlists.HasLongFiles())
	assert.True(t, cfg.Filenames.Wordlists.HasShortDirs())
	assert.False(t, cfg.Filenames.Wordlists.HasLongDirs())
}

func TestBuilder_WithObservedExtensions(t *testing.T) {
	cfg, err := NewBuilder().
		WithStartURL("http://example.com/").
		WithObservedExtensions(false).
		Build()

	require.NoError(t, err)
	assert.False(t, cfg.Extensions.TestObserved)
}
