package kingfisher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/toolexec"
)

func TestKingfisherPlatform(t *testing.T) {
	osName, archName, err := kingfisherPlatform()
	if err != nil {
		t.Skipf("Unsupported platform: %v", err)
	}

	if osName != "darwin" && osName != "linux" {
		t.Errorf("unexpected OS: %s", osName)
	}

	if archName != "x64" && archName != "arm64" {
		t.Errorf("unexpected arch: %s", archName)
	}
}

func TestResolveCacheDir(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		dir, err := toolexec.ResolveCacheDir("", "kingfisher")
		if err != nil {
			t.Fatalf("ResolveCacheDir: %v", err)
		}
		if dir == "" {
			t.Error("expected non-empty cache dir")
		}
		if filepath.Base(dir) != "kingfisher" {
			t.Errorf("expected subdir kingfisher, got %s", filepath.Base(dir))
		}
	})

	t.Run("override", func(t *testing.T) {
		custom := "/tmp/custom-cache"
		dir, err := toolexec.ResolveCacheDir(custom, "kingfisher")
		if err != nil {
			t.Fatalf("ResolveCacheDir: %v", err)
		}
		if dir != custom {
			t.Errorf("expected %s, got %s", custom, dir)
		}
	})
}

func TestNewDownloader(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{
		CacheDir:    tmpDir,
		HTTPTimeout: 10 * time.Second,
	}

	d, err := NewDownloader(config)
	if err != nil {
		t.Fatalf("NewDownloader: %v", err)
	}

	if d.CacheDir() != tmpDir {
		t.Errorf("expected cache dir %s, got %s", tmpDir, d.CacheDir())
	}
}

func TestIsBinaryValid(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("non-existent", func(t *testing.T) {
		if toolexec.IsBinaryValid("/nonexistent/path") {
			t.Error("expected false for non-existent file")
		}
	})

	t.Run("valid executable", func(t *testing.T) {
		binaryPath := filepath.Join(tmpDir, "test-binary")
		if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\necho test"), 0755); err != nil {
			t.Fatal(err)
		}
		if !toolexec.IsBinaryValid(binaryPath) {
			t.Error("expected true for valid executable")
		}
	})

	t.Run("non-executable", func(t *testing.T) {
		nonExecPath := filepath.Join(tmpDir, "non-exec")
		if err := os.WriteFile(nonExecPath, []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}
		if toolexec.IsBinaryValid(nonExecPath) {
			t.Error("expected false for non-executable file")
		}
	})
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "version file format",
			input:    "v1.0.0\n2024-01-01T00:00:00Z",
			expected: []string{"v1.0.0", "2024-01-01T00:00:00Z"},
		},
		{
			name:     "single line",
			input:    "single",
			expected: []string{"single"},
		},
		{
			name:     "empty",
			input:    "",
			expected: nil,
		},
		{
			name:     "spaced lines",
			input:    "  spaced  \n  lines  ",
			expected: []string{"spaced", "lines"},
		},
		{
			name:     "trailing newline",
			input:    "line1\nline2\n",
			expected: []string{"line1", "line2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toolexec.SplitLines(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d lines, got %d: %v", len(tt.expected), len(result), result)
			}
			for i := range result {
				if i < len(tt.expected) && result[i] != tt.expected[i] {
					t.Errorf("line %d: expected %q, got %q", i, tt.expected[i], result[i])
				}
			}
		})
	}
}

func TestDownloader_Clear(t *testing.T) {
	tmpDir := t.TempDir()
	config := &Config{
		CacheDir:    tmpDir,
		HTTPTimeout: 10 * time.Second,
	}

	d, err := NewDownloader(config)
	if err != nil {
		t.Fatalf("NewDownloader: %v", err)
	}

	// Create fake cached files
	binaryPath := filepath.Join(tmpDir, binaryName)
	if err := os.WriteFile(binaryPath, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	versionPath := filepath.Join(tmpDir, "version.txt")
	if err := os.WriteFile(versionPath, []byte("v1.0.0\n2024-01-01"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := d.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	if _, err := os.Stat(binaryPath); !os.IsNotExist(err) {
		t.Error("binary should be removed after Clear")
	}
	if _, err := os.Stat(versionPath); !os.IsNotExist(err) {
		t.Error("version file should be removed after Clear")
	}
}
