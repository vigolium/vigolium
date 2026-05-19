package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  func() *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid default configuration",
			config: func() *Config {
				cfg := NewDefaultConfig()
				cfg.Target.StartURL = "http://example.com/"
				return cfg
			},
			wantErr: false,
		},
		{
			name: "valid https URL",
			config: func() *Config {
				cfg := NewDefaultConfig()
				cfg.Target.StartURL = "https://example.com/app/"
				return cfg
			},
			wantErr: false,
		},
		{
			name: "valid with custom settings",
			config: func() *Config {
				cfg := NewDefaultConfig()
				cfg.Target.StartURL = "http://example.com/"
				cfg.Target.Mode = ModeFilesOnly
				cfg.Target.Recursion.MaxDepth = 8
				cfg.Engine.DiscoveryThreads = 8
				return cfg
			},
			wantErr: false,
		},
		{
			name: "invalid target config propagates",
			config: func() *Config {
				cfg := NewDefaultConfig()
				cfg.Target.StartURL = ""
				return cfg
			},
			wantErr: true,
			errMsg:  "target config",
		},
		{
			name: "invalid extension config propagates",
			config: func() *Config {
				cfg := NewDefaultConfig()
				cfg.Target.StartURL = "http://example.com/"
				cfg.Extensions.TestCustom = true
				cfg.Extensions.CustomList = []string{}
				return cfg
			},
			wantErr: true,
			errMsg:  "extension config",
		},
		{
			name: "invalid engine config propagates",
			config: func() *Config {
				cfg := NewDefaultConfig()
				cfg.Target.StartURL = "http://example.com/"
				cfg.Engine.DiscoveryThreads = 300
				return cfg
			},
			wantErr: true,
			errMsg:  "engine config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config().Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTargetConfig_Validate(t *testing.T) {
	var overflowDepth int16 = 32767
	overflowDepth++

	tests := []struct {
		name    string
		target  TargetConfig
		wantErr error
	}{
		{
			name: "valid http URL",
			target: TargetConfig{
				StartURL: "http://example.com/",
				Mode:     ModeFilesAndDirs,
				Recursion: RecursionConfig{
					Enabled:  true,
					MaxDepth: 16,
				},
			},
			wantErr: nil,
		},
		{
			name: "valid https URL",
			target: TargetConfig{
				StartURL: "https://secure.example.com/app/",
				Mode:     ModeFilesAndDirs,
				Recursion: RecursionConfig{
					Enabled:  true,
					MaxDepth: 16,
				},
			},
			wantErr: nil,
		},
		{
			name: "valid URL with port",
			target: TargetConfig{
				StartURL: "http://example.com:8080/api/",
				Mode:     ModeFilesAndDirs,
				Recursion: RecursionConfig{
					Enabled:  true,
					MaxDepth: 16,
				},
			},
			wantErr: nil,
		},
		{
			name: "valid URL with query parameters",
			target: TargetConfig{
				StartURL: "http://example.com/?id=123",
				Mode:     ModeFilesAndDirs,
				Recursion: RecursionConfig{
					Enabled:  true,
					MaxDepth: 16,
				},
			},
			wantErr: nil,
		},
		{
			name: "empty URL",
			target: TargetConfig{
				StartURL: "",
			},
			wantErr: ErrEmptyURL,
		},
		{
			name: "invalid URL format",
			target: TargetConfig{
				StartURL: "not a url",
			},
			wantErr: ErrInvalidURLScheme, // url.Parse succeeds but scheme is empty
		},
		{
			name: "ftp scheme not allowed",
			target: TargetConfig{
				StartURL: "ftp://example.com/",
			},
			wantErr: ErrInvalidURLScheme,
		},
		{
			name: "file scheme not allowed",
			target: TargetConfig{
				StartURL: "file:///etc/passwd",
			},
			wantErr: ErrInvalidURLScheme,
		},
		{
			name: "missing host",
			target: TargetConfig{
				StartURL: "http://",
			},
			wantErr: ErrMissingHost,
		},
		{
			name: "recursion disabled with invalid depth is OK",
			target: TargetConfig{
				StartURL: "http://example.com/",
				Recursion: RecursionConfig{
					Enabled:  false,
					MaxDepth: overflowDepth, // invalid but ignored when disabled
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.target.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRecursionConfig_Validate(t *testing.T) {
	var overflowDepth int16 = 32767
	overflowDepth++
	var wayOverDepth int16 = 32767
	wayOverDepth += 100

	tests := []struct {
		name      string
		recursion RecursionConfig
		wantErr   bool
	}{
		{
			name: "valid default depth",
			recursion: RecursionConfig{
				Enabled:  true,
				MaxDepth: 16,
			},
			wantErr: false,
		},
		{
			name: "valid min depth",
			recursion: RecursionConfig{
				Enabled:  true,
				MaxDepth: 1,
			},
			wantErr: false,
		},
		{
			name: "valid max depth",
			recursion: RecursionConfig{
				Enabled:  true,
				MaxDepth: 32767,
			},
			wantErr: false,
		},
		{
			name: "disabled recursion ignores depth",
			recursion: RecursionConfig{
				Enabled:  false,
				MaxDepth: overflowDepth,
			},
			wantErr: false,
		},
		{
			name: "depth zero is invalid",
			recursion: RecursionConfig{
				Enabled:  true,
				MaxDepth: 0,
			},
			wantErr: true,
		},
		{
			name: "negative depth is invalid",
			recursion: RecursionConfig{
				Enabled:  true,
				MaxDepth: -1,
			},
			wantErr: true,
		},
		{
			name: "depth exceeds int16 max",
			recursion: RecursionConfig{
				Enabled:  true,
				MaxDepth: overflowDepth,
			},
			wantErr: true,
		},
		{
			name: "depth way too high",
			recursion: RecursionConfig{
				Enabled:  true,
				MaxDepth: wayOverDepth,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.recursion.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidDepth)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFilenameConfig_Validate(t *testing.T) {
	tests := []struct {
		name     string
		filename FilenameConfig
		wantErr  error
	}{
		{
			name: "valid default config",
			filename: FilenameConfig{
				Wordlists:            WordlistConfig{}, // Empty paths = disabled
				UseObservedNames:     true,
				EnableNumericFuzzing: true,
			},
			wantErr: nil,
		},
		{
			name: "valid with all options disabled",
			filename: FilenameConfig{
				Wordlists:            WordlistConfig{},
				UseObservedNames:     false,
				EnableNumericFuzzing: false,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filename.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestExtensionConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		extension ExtensionConfig
		wantErr   error
	}{
		{
			name: "valid default config",
			extension: ExtensionConfig{
				TestCustom:           true,
				CustomList:           []string{"php", "asp", "aspx"},
				TestBackupExtensions: true,
				BackupExtensions:     []string{"bak", "old", "tmp"},
			},
			wantErr: nil,
		},
		{
			name: "custom disabled with empty list is OK",
			extension: ExtensionConfig{
				TestCustom: false,
				CustomList: []string{},
			},
			wantErr: nil,
		},
		{
			name: "variants disabled with empty list is OK",
			extension: ExtensionConfig{
				TestBackupExtensions: false,
				BackupExtensions:     []string{},
			},
			wantErr: nil,
		},
		{
			name: "custom enabled with empty list is error",
			extension: ExtensionConfig{
				TestCustom: true,
				CustomList: []string{},
			},
			wantErr: ErrEmptyCustomList,
		},
		{
			name: "custom enabled with nil list is error",
			extension: ExtensionConfig{
				TestCustom: true,
				CustomList: nil,
			},
			wantErr: ErrEmptyCustomList,
		},
		{
			name: "variants enabled with empty list is error",
			extension: ExtensionConfig{
				TestBackupExtensions: true,
				BackupExtensions:     []string{},
			},
			wantErr: ErrEmptyBackupExtensions,
		},
		{
			name: "variants enabled with nil list is error",
			extension: ExtensionConfig{
				TestBackupExtensions: true,
				BackupExtensions:     nil,
			},
			wantErr: ErrEmptyBackupExtensions,
		},
		{
			name: "all tests disabled is valid",
			extension: ExtensionConfig{
				TestCustom:           false,
				TestObserved:         false,
				TestBackupExtensions: false,
				TestNoExtension:      false,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.extension.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEngineConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		engine  EngineConfig
		wantErr error
	}{
		{
			name: "valid default config",
			engine: EngineConfig{
				DiscoveryThreads: 4,
				Timeout:          30 * time.Second,
			},
			wantErr: nil,
		},
		{
			name: "valid min threads",
			engine: EngineConfig{
				DiscoveryThreads: 1,
				Timeout:          30 * time.Second,
			},
			wantErr: nil,
		},
		{
			name: "valid max discovery threads",
			engine: EngineConfig{
				DiscoveryThreads: 255,
				Timeout:          30 * time.Second,
			},
			wantErr: nil,
		},
		{
			name: "valid min timeout",
			engine: EngineConfig{
				DiscoveryThreads: 4,
				Timeout:          1 * time.Second,
			},
			wantErr: nil,
		},
		{
			name: "valid max timeout",
			engine: EngineConfig{
				DiscoveryThreads: 4,
				Timeout:          300 * time.Second,
			},
			wantErr: nil,
		},
		{
			name: "discovery threads zero",
			engine: EngineConfig{
				DiscoveryThreads: 0,
				Timeout:          30 * time.Second,
			},
			wantErr: ErrInvalidThreads,
		},
		{
			name: "discovery threads negative",
			engine: EngineConfig{
				DiscoveryThreads: -1,
				Timeout:          30 * time.Second,
			},
			wantErr: ErrInvalidThreads,
		},
		{
			name: "discovery threads exceeds limit",
			engine: EngineConfig{
				DiscoveryThreads: 256,
				Timeout:          30 * time.Second,
			},
			wantErr: ErrInvalidThreads,
		},
		{
			name: "discovery threads way too high",
			engine: EngineConfig{
				DiscoveryThreads: 1000,
				Timeout:          30 * time.Second,
			},
			wantErr: ErrInvalidThreads,
		},
		{
			name: "timeout too short",
			engine: EngineConfig{
				DiscoveryThreads: 4,
				Timeout:          500 * time.Millisecond,
			},
			wantErr: ErrInvalidTimeout,
		},
		{
			name: "timeout zero",
			engine: EngineConfig{
				DiscoveryThreads: 4,
				Timeout:          0,
			},
			wantErr: ErrInvalidTimeout,
		},
		{
			name: "timeout too long",
			engine: EngineConfig{
				DiscoveryThreads: 4,
				Timeout:          301 * time.Second,
			},
			wantErr: ErrInvalidTimeout,
		},
		{
			name: "timeout way too long",
			engine: EngineConfig{
				DiscoveryThreads: 4,
				Timeout:          3600 * time.Second,
			},
			wantErr: ErrInvalidTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.engine.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()

	validFile := filepath.Join(tmpDir, "valid.txt")
	require.NoError(t, os.WriteFile(validFile, []byte("test content"), 0644))

	readOnlyFile := filepath.Join(tmpDir, "readonly.txt")
	require.NoError(t, os.WriteFile(readOnlyFile, []byte("readonly"), 0444))

	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0755))

	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name:    "valid readable file",
			path:    validFile,
			wantErr: nil,
		},
		{
			name:    "valid readonly file",
			path:    readOnlyFile,
			wantErr: nil,
		},
		{
			name:    "nonexistent file",
			path:    "/nonexistent/path/file.txt",
			wantErr: ErrFileNotFound,
		},
		{
			name:    "directory instead of file",
			path:    subDir,
			wantErr: ErrNotRegularFile,
		},
		{
			name:    "tmpDir is directory",
			path:    tmpDir,
			wantErr: ErrNotRegularFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.path)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
