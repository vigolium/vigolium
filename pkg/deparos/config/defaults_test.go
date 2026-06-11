package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultConfig verifies that all default values are correctly set.
func TestDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	require.NotNil(t, cfg)

	t.Run("target defaults", func(t *testing.T) {
		// StartURL has no default (must be provided by user)
		assert.Empty(t, cfg.Target.StartURL)

		// Mode: files_and_dirs
		assert.Equal(t, ModeFilesAndDirs, cfg.Target.Mode)

		// Recursion enabled by default
		assert.True(t, cfg.Target.Recursion.Enabled)

		// Max depth: 16
		assert.Equal(t, int16(16), cfg.Target.Recursion.MaxDepth)
	})

	t.Run("filename defaults", func(t *testing.T) {
		// No wordlist paths set by default (user must provide them)
		assert.Empty(t, cfg.Filenames.Wordlists.ShortFilePath)
		assert.Empty(t, cfg.Filenames.Wordlists.LongFilePath)
		assert.Empty(t, cfg.Filenames.Wordlists.ShortDirPath)
		assert.Empty(t, cfg.Filenames.Wordlists.LongDirPath)

		// Has* methods should return false for empty paths
		assert.False(t, cfg.Filenames.Wordlists.HasShortFiles())
		assert.False(t, cfg.Filenames.Wordlists.HasLongFiles())
		assert.False(t, cfg.Filenames.Wordlists.HasShortDirs())
		assert.False(t, cfg.Filenames.Wordlists.HasLongDirs())

		// Observed and derived names enabled
		assert.True(t, cfg.Filenames.UseObservedNames, "observed names should be enabled")
		assert.False(t, cfg.Filenames.EnableNumericFuzzing, "numeric fuzzing should be opt-in (disabled by default)")
	})

	t.Run("extension defaults", func(t *testing.T) {
		// Custom extensions testing enabled
		assert.True(t, cfg.Extensions.TestCustom, "custom extensions should be enabled")

		// Custom extensions list should match DefaultCustomExtensions
		assert.Equal(t, DefaultCustomExtensions, cfg.Extensions.CustomList, "custom extensions should match defaults")

		// Observed extensions testing enabled
		assert.True(t, cfg.Extensions.TestObserved, "observed extensions should be enabled")

		// Backup extensions testing enabled
		assert.True(t, cfg.Extensions.TestBackupExtensions, "backup extensions should be enabled")

		// Backup extensions list should match DefaultBackupExtensions
		assert.Equal(t, DefaultBackupExtensions, cfg.Extensions.BackupExtensions, "backup extensions should match defaults")

		// Test no extension enabled
		assert.True(t, cfg.Extensions.TestNoExtension, "no extension testing should be enabled")
	})

	t.Run("engine defaults", func(t *testing.T) {
		// Case sensitivity: auto-detect
		assert.Equal(t, CaseAutoDetect, cfg.Engine.CaseSensitivity, "case sensitivity should be auto-detect")

		// Discovery threads: 40
		assert.Equal(t, 40, cfg.Engine.DiscoveryThreads, "discovery threads should be 40")

		// Timeout: 10 seconds
		assert.Equal(t, 10*time.Second, cfg.Engine.Timeout, "timeout should be 10 seconds")
	})
}

func TestDefaultCustomExtensions(t *testing.T) {
	// Verify the exported default list matches expectations
	assert.Len(t, DefaultCustomExtensions, 6, "should have 6 default custom extensions")

	// Verify order (matters for consistent behavior)
	expected := []string{"php", "asp", "aspx", "jsp", "jspa", "do"}
	for i, ext := range expected {
		assert.Equal(t, ext, DefaultCustomExtensions[i],
			"extension at index %d should be %s", i, ext)
	}
}

func TestAllowedObservedExtensions(t *testing.T) {
	// Verify the whitelist contains expected extensions
	assert.Len(t, AllowedObservedExtensions, 98, "should have 98 allowed extensions")

	// Verify key extensions are in the whitelist, including the server-side
	// route extensions used by the extension-confirm pipeline.
	expectedExtensions := []string{
		"php", "asp", "aspx", "jsp", "html", "htm", "js", "txt", "xml",
		"bak", "backup", "old", "tmp", "log", "conf", "ini", "cfg",
		"action", "do", "jspx", "ashx", "asmx", "cgi",
	}
	for _, ext := range expectedExtensions {
		_, exists := AllowedObservedExtensions[ext]
		assert.True(t, exists, "extension %q should be in allowed list", ext)
	}

	// Verify media extensions are NOT in the whitelist (these should be filtered)
	notAllowedExtensions := []string{
		"mp4", "mp3", "wav", "avi", "mov", "webm", "mkv", "flv",
		"css", "scss", "sass", "less",
		"woff", "woff2", "ttf", "eot", "otf",
		"png", "bmp", "ico", "webp", "tiff", "tif", "svg",
		"json", // Not in user's whitelist
	}
	for _, ext := range notAllowedExtensions {
		_, exists := AllowedObservedExtensions[ext]
		assert.False(t, exists, "extension %q should NOT be in allowed list", ext)
	}
}

func TestDefaultBackupExtensions(t *testing.T) {
	// Verify the exported default list has 36 items
	assert.Len(t, DefaultBackupExtensions, 36, "should have 36 backup extensions")

	// Verify critical backup extensions are present
	criticalBackups := []string{"bak", "old", "tmp", "backup"}
	for _, ext := range criticalBackups {
		assert.Contains(t, DefaultBackupExtensions, ext,
			"should contain critical backup extension: %s", ext)
	}

	// Verify archive formats are present
	archiveFormats := []string{"zip", "tar", "gz"}
	for _, ext := range archiveFormats {
		assert.Contains(t, DefaultBackupExtensions, ext,
			"should contain archive format: %s", ext)
	}

	// Verify config file extensions are present
	configExts := []string{"conf", "ini"}
	for _, ext := range configExts {
		assert.Contains(t, DefaultBackupExtensions, ext,
			"should contain config extension: %s", ext)
	}
}

func TestDefaultConfig_IsValid(t *testing.T) {
	// Default config should be valid except for missing StartURL
	cfg := NewDefaultConfig()

	// Without URL, should fail validation
	err := cfg.Validate()
	require.Error(t, err, "default config without URL should fail validation")
	assert.ErrorIs(t, err, ErrEmptyURL)

	// With URL, should pass validation
	cfg.Target.StartURL = "http://example.com/"
	err = cfg.Validate()
	require.NoError(t, err, "default config with URL should pass validation")
}

func TestDefaultConfig_ThreadLimits(t *testing.T) {
	cfg := NewDefaultConfig()

	// Discovery threads should be within valid range
	assert.GreaterOrEqual(t, cfg.Engine.DiscoveryThreads, 1, "discovery threads >= 1")
	assert.LessOrEqual(t, cfg.Engine.DiscoveryThreads, 255, "discovery threads <= 255")
}

func TestDefaultConfig_RecursionLimits(t *testing.T) {
	cfg := NewDefaultConfig()

	// Max depth should be within valid range when recursion is enabled
	if cfg.Target.Recursion.Enabled {
		assert.GreaterOrEqual(t, cfg.Target.Recursion.MaxDepth, int16(1), "max depth >= 1")
		assert.LessOrEqual(t, cfg.Target.Recursion.MaxDepth, int16(32767), "max depth <= 32767")
	}
}

func TestDefaultConfig_TimeoutLimits(t *testing.T) {
	cfg := NewDefaultConfig()

	// Timeout should be within valid range
	assert.GreaterOrEqual(t, cfg.Engine.Timeout, 1*time.Second, "timeout >= 1s")
	assert.LessOrEqual(t, cfg.Engine.Timeout, 300*time.Second, "timeout <= 300s")
}

func TestDefaultConfig_ExtensionListsNotEmpty(t *testing.T) {
	cfg := NewDefaultConfig()

	// If custom extensions are enabled, list must not be empty
	if cfg.Extensions.TestCustom {
		assert.NotEmpty(t, cfg.Extensions.CustomList, "custom list should not be empty when enabled")
	}

	// If backup extensions are enabled, list must not be empty
	if cfg.Extensions.TestBackupExtensions {
		assert.NotEmpty(t, cfg.Extensions.BackupExtensions, "backup extensions should not be empty when enabled")
	}
}

func TestDefaultConfig_WordlistsEmpty(t *testing.T) {
	cfg := NewDefaultConfig()

	// All wordlist paths should be empty by default (user must provide them)
	assert.Empty(t, cfg.Filenames.Wordlists.ShortFilePath)
	assert.Empty(t, cfg.Filenames.Wordlists.LongFilePath)
	assert.Empty(t, cfg.Filenames.Wordlists.ShortDirPath)
	assert.Empty(t, cfg.Filenames.Wordlists.LongDirPath)
}

// TestDefaultsMatchDefaults verifies that defaults match expected values.
func TestDefaultsMatchDefaults(t *testing.T) {
	cfg := NewDefaultConfig()

	// These values should match expected defaults
	assert.Equal(t, ModeFilesAndDirs, cfg.Target.Mode, "mode should match defaults")
	assert.True(t, cfg.Target.Recursion.Enabled, "recursion should match defaults")
	assert.Equal(t, int16(16), cfg.Target.Recursion.MaxDepth, "max depth should match defaults")
	assert.Equal(t, 40, cfg.Engine.DiscoveryThreads, "discovery threads should match defaults")
	assert.Equal(t, CaseAutoDetect, cfg.Engine.CaseSensitivity, "case sensitivity should match defaults")
}
