package jstangle

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewExtractor_WithNilConfig(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	extractor, err := NewExtractor(nil)

	if err != nil {
		t.Fatalf("NewExtractor(nil) failed: %v", err)
	}

	if extractor == nil {
		t.Fatal("expected non-nil extractor")
	}

	if extractor.CacheDir() == "" {
		t.Error("expected non-empty cache dir")
	}
}

func TestNewExtractor_WithCustomCacheDir(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	customDir := filepath.Join(tmpDir, "custom")

	extractor, err := NewExtractor(&Config{CacheDir: customDir})

	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	if extractor.CacheDir() != customDir {
		t.Errorf("CacheDir() = %q, want %q", extractor.CacheDir(), customDir)
	}

	// Directory should be created
	if _, err := os.Stat(customDir); os.IsNotExist(err) {
		t.Error("cache directory was not created")
	}
}

func TestNewExtractor_UnsupportedPlatform(t *testing.T) {
	if isEmbeddedBinaryValid() {
		t.Skip("skipping: valid jstangle binary available for this platform")
	}

	_, err := NewExtractor(nil)

	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("expected ErrUnsupportedPlatform, got %v", err)
	}
}

func TestExtractor_GetBinary(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	binary, err := extractor.GetBinary()

	if err != nil {
		t.Fatalf("GetBinary failed: %v", err)
	}

	if binary == nil {
		t.Fatal("expected non-nil binary")
	}

	if binary.Path == "" {
		t.Error("expected non-empty path")
	}

	if binary.Checksum == "" {
		t.Error("expected non-empty checksum")
	}

	if binary.ExtractedAt.IsZero() {
		t.Error("expected non-zero ExtractedAt")
	}

	// Binary should exist
	if _, err := os.Stat(binary.Path); os.IsNotExist(err) {
		t.Errorf("binary path %q does not exist", binary.Path)
	}

	// Binary should be executable
	info, err := os.Stat(binary.Path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm()&0111 == 0 {
		t.Error("binary should be executable")
	}
}

func TestExtractor_GetBinary_Cached(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	// First call - extracts binary
	binary1, err := extractor.GetBinary()
	if err != nil {
		t.Fatalf("first GetBinary failed: %v", err)
	}

	// Second call - should return cached
	binary2, err := extractor.GetBinary()
	if err != nil {
		t.Fatalf("second GetBinary failed: %v", err)
	}

	if binary1.Path != binary2.Path {
		t.Error("cached binary should have same path")
	}
	if binary1.Checksum != binary2.Checksum {
		t.Error("cached binary should have same checksum")
	}
}

func TestExtractor_GetBinary_LoadsFromDisk(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()

	// First extractor - extracts binary
	extractor1, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	binary1, err := extractor1.GetBinary()
	if err != nil {
		t.Fatalf("first GetBinary failed: %v", err)
	}

	// Second extractor with same cache dir - should load from disk
	extractor2, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	binary2, err := extractor2.GetBinary()
	if err != nil {
		t.Fatalf("second GetBinary failed: %v", err)
	}

	if binary1.Path != binary2.Path {
		t.Error("should load same binary from disk")
	}
	if binary1.Checksum != binary2.Checksum {
		t.Error("should have same checksum from disk")
	}
}

func TestExtractor_Clear(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	// Extract binary
	binary, err := extractor.GetBinary()
	if err != nil {
		t.Fatalf("GetBinary failed: %v", err)
	}

	binaryPath := binary.Path
	checksumPath := filepath.Join(tmpDir, ChecksumFileName)

	// Verify files exist
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Fatal("binary should exist before clear")
	}
	if _, err := os.Stat(checksumPath); os.IsNotExist(err) {
		t.Fatal("checksum file should exist before clear")
	}

	// Clear
	err = extractor.Clear()
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Verify files are removed
	if _, err := os.Stat(binaryPath); !os.IsNotExist(err) {
		t.Error("binary should be removed after clear")
	}
	if _, err := os.Stat(checksumPath); !os.IsNotExist(err) {
		t.Error("checksum file should be removed after clear")
	}
}

func TestExtractor_Clear_ThenGetBinary(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	// Extract, clear, then extract again
	_, err = extractor.GetBinary()
	if err != nil {
		t.Fatalf("first GetBinary failed: %v", err)
	}

	err = extractor.Clear()
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	binary, err := extractor.GetBinary()
	if err != nil {
		t.Fatalf("second GetBinary failed: %v", err)
	}

	if binary == nil {
		t.Fatal("expected non-nil binary after re-extraction")
	}

	if _, err := os.Stat(binary.Path); os.IsNotExist(err) {
		t.Error("binary should exist after re-extraction")
	}
}

func TestExtractor_ConcurrentGetBinary(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	results := make(chan *CachedBinary, numGoroutines)
	errs := make(chan error, numGoroutines)

	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			binary, getErr := extractor.GetBinary()
			if getErr != nil {
				errs <- getErr
				return
			}
			results <- binary
		}()
	}

	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Errorf("concurrent GetBinary error: %v", err)
	}

	// All results should have the same path
	var firstPath string
	for binary := range results {
		if firstPath == "" {
			firstPath = binary.Path
		} else if binary.Path != firstPath {
			t.Errorf("inconsistent paths: %q vs %q", binary.Path, firstPath)
		}
	}
}

func TestExtractor_ChecksumValidation(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	binary, err := extractor.GetBinary()
	if err != nil {
		t.Fatalf("GetBinary failed: %v", err)
	}

	// Verify checksum matches embedded checksum
	embeddedSum := getEmbeddedChecksum()
	if binary.Checksum != embeddedSum {
		t.Errorf("checksum mismatch: got %q, want %q", binary.Checksum, embeddedSum)
	}

	// SHA256 should be 64 hex characters
	if len(binary.Checksum) != 64 {
		t.Errorf("checksum length = %d, want 64", len(binary.Checksum))
	}
}

func TestExtractor_ChecksumFile(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	_, err = extractor.GetBinary()
	if err != nil {
		t.Fatalf("GetBinary failed: %v", err)
	}

	// Read checksum file
	checksumPath := filepath.Join(tmpDir, ChecksumFileName)
	data, err := os.ReadFile(checksumPath)
	if err != nil {
		t.Fatalf("failed to read checksum file: %v", err)
	}

	lines := splitLines(string(data))
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines in checksum file, got %d", len(lines))
	}

	// First line is checksum
	if len(lines[0]) != 64 {
		t.Errorf("first line should be 64-char checksum, got %d chars", len(lines[0]))
	}

	// Second line is timestamp
	_, err = time.Parse(time.RFC3339, lines[1])
	if err != nil {
		t.Errorf("second line should be RFC3339 timestamp: %v", err)
	}
}

func TestExtractor_InvalidChecksumFile(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()

	// Create invalid checksum file
	checksumPath := filepath.Join(tmpDir, ChecksumFileName)
	if err := os.WriteFile(checksumPath, []byte("invalid"), 0644); err != nil {
		t.Fatalf("failed to write invalid checksum: %v", err)
	}

	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	// GetBinary should still work (extract fresh)
	binary, err := extractor.GetBinary()
	if err != nil {
		t.Fatalf("GetBinary failed: %v", err)
	}

	if binary == nil {
		t.Fatal("expected non-nil binary")
	}
}

func TestExtractor_MismatchedChecksum(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()

	// Create checksum file with wrong checksum
	checksumPath := filepath.Join(tmpDir, ChecksumFileName)
	wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"
	checksumData := wrongChecksum + "\n" + time.Now().Format(time.RFC3339)
	if err := os.WriteFile(checksumPath, []byte(checksumData), 0644); err != nil {
		t.Fatalf("failed to write checksum: %v", err)
	}

	// Create a dummy binary
	binaryPath := filepath.Join(tmpDir, binaryName)
	if err := os.WriteFile(binaryPath, []byte("dummy"), 0755); err != nil {
		t.Fatalf("failed to write dummy binary: %v", err)
	}

	extractor, err := NewExtractor(&Config{CacheDir: tmpDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	// GetBinary should re-extract due to checksum mismatch
	binary, err := extractor.GetBinary()
	if err != nil {
		t.Fatalf("GetBinary failed: %v", err)
	}

	// Should have correct checksum now
	if binary.Checksum != getEmbeddedChecksum() {
		t.Error("checksum should match embedded after re-extraction")
	}
}

func TestExtractor_CacheDir(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	tmpDir := t.TempDir()
	customDir := filepath.Join(tmpDir, "custom-cache")

	extractor, err := NewExtractor(&Config{CacheDir: customDir})
	if err != nil {
		t.Fatalf("NewExtractor failed: %v", err)
	}

	if extractor.CacheDir() != customDir {
		t.Errorf("CacheDir() = %q, want %q", extractor.CacheDir(), customDir)
	}
}

func TestResolveCacheDir_Override(t *testing.T) {
	override := "/custom/path"
	result, err := resolveCacheDir(override)

	if err != nil {
		t.Fatalf("resolveCacheDir failed: %v", err)
	}

	if result != override {
		t.Errorf("resolveCacheDir(%q) = %q, want %q", override, result, override)
	}
}

func TestResolveCacheDir_Default(t *testing.T) {
	result, err := resolveCacheDir("")

	if err != nil {
		t.Fatalf("resolveCacheDir failed: %v", err)
	}

	if result == "" {
		t.Error("expected non-empty default cache dir")
	}

	// Should end with "jstangle"
	if filepath.Base(result) != DefaultCacheSubdir {
		t.Errorf("cache dir should end with %q, got %q", DefaultCacheSubdir, filepath.Base(result))
	}
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "simple",
			input: "line1\nline2\nline3",
			want:  []string{"line1", "line2", "line3"},
		},
		{
			name:  "with empty lines",
			input: "line1\n\nline2\n\nline3",
			want:  []string{"line1", "line2", "line3"},
		},
		{
			name:  "with whitespace",
			input: "  line1  \n  line2  ",
			want:  []string{"line1", "line2"},
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "only whitespace",
			input: "  \n  \n  ",
			want:  nil,
		},
		{
			name:  "single line",
			input: "single",
			want:  []string{"single"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitLines(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitLines() returned %d items, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitLines()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGetEmbeddedChecksum(t *testing.T) {
	if !isEmbeddedBinaryValid() {
		t.Skip("skipping: no valid jstangle binary available")
	}

	checksum1 := getEmbeddedChecksum()
	checksum2 := getEmbeddedChecksum()

	if checksum1 == "" {
		t.Error("expected non-empty checksum")
	}

	if checksum1 != checksum2 {
		t.Error("embedded checksum should be consistent (cached)")
	}

	if len(checksum1) != 64 {
		t.Errorf("checksum length = %d, want 64", len(checksum1))
	}
}

func TestConstants(t *testing.T) {
	if DefaultCacheSubdir != "jstangle" {
		t.Errorf("DefaultCacheSubdir = %q, want jstangle", DefaultCacheSubdir)
	}

	if ChecksumFileName != "checksum.txt" {
		t.Errorf("ChecksumFileName = %q, want checksum.txt", ChecksumFileName)
	}
}
