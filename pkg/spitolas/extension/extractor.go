package extension

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// GetExtensionPaths extracts all registered extensions and returns their paths.
// Uses ~/.cache/spitolas/ as cache directory.
func GetExtensionPaths() ([]string, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, ext := range registry {
		path, err := extractExtension(ext, cacheDir)
		if err != nil {
			return nil, fmt.Errorf("failed to extract %s: %w", ext.Name(), err)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func getCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home dir: %w", err)
	}
	return filepath.Join(home, ".cache", "spitolas"), nil
}

// extractExtension extracts a single extension to cache
func extractExtension(ext Extension, cacheDir string) (string, error) {
	extractDir := filepath.Join(cacheDir, fmt.Sprintf("%s-%s", ext.Name(), ext.Version()))
	markerFile := filepath.Join(extractDir, ".extracted")

	// Check if already extracted with correct version
	if data, err := os.ReadFile(markerFile); err == nil && string(data) == ext.Version() {
		if manifestPath := findManifest(extractDir); manifestPath != "" {
			return filepath.Dir(manifestPath), nil
		}
	}

	// Clean old cache and extract fresh
	if err := os.RemoveAll(extractDir); err != nil {
		return "", fmt.Errorf("failed to clean old cache: %w", err)
	}
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache dir: %w", err)
	}

	if err := extractZip(ext.ZipData(), extractDir); err != nil {
		return "", fmt.Errorf("failed to extract: %w", err)
	}

	// Write marker file
	if err := os.WriteFile(markerFile, []byte(ext.Version()), 0644); err != nil {
		return "", fmt.Errorf("failed to write marker: %w", err)
	}

	manifestPath := findManifest(extractDir)
	if manifestPath == "" {
		return "", fmt.Errorf("manifest.json not found")
	}

	return filepath.Dir(manifestPath), nil
}

func findManifest(dir string) string {
	var result string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == "manifest.json" {
			result = path
			return filepath.SkipAll
		}
		return nil
	})
	return result
}

func extractZip(data []byte, dest string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	for _, f := range r.File {
		path := filepath.Join(dest, f.Name)
		if !isInsideDir(path, dest) {
			return fmt.Errorf("invalid file path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, f.Mode()); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		if err := extractFile(f, path); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer func() { _ = outFile.Close() }()

	_, err = io.Copy(outFile, rc)
	return err
}

func isInsideDir(path, baseDir string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absBase, absPath)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && rel != ".." && len(rel) > 0 && rel[0] != '.'
}
