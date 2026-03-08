package spitolas

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ulikunitz/xz"
)

// BrowserEngine represents the type of browser engine to use.
type BrowserEngine string

const (
	// EngineChromium is the standard Chromium browser
	EngineChromium BrowserEngine = "chromium"
	// EngineUngoogled is the Ungoogled-Chromium browser (Linux only)
	EngineUngoogled BrowserEngine = "ungoogled"
	// EngineFingerprint is the Fingerprint-Chromium browser (Linux only for embedding)
	EngineFingerprint BrowserEngine = "fingerprint"
)

// GetChromiumPath returns the path to the embedded Chromium binary.
// It extracts the browser to a cache directory if not already extracted.
// If cacheDir is empty, uses ~/.cache/spitolas/
// Deprecated: Use GetBrowserPath(EngineChromium, cacheDir) instead.
func GetChromiumPath(cacheDir string) (string, error) {
	return GetBrowserPath(EngineChromium, cacheDir)
}

// GetBrowserPath returns the path to the embedded browser binary for the specified engine.
// It extracts the browser to a cache directory if not already extracted.
// If cacheDir is empty, uses ~/.cache/spitolas/
func GetBrowserPath(engine BrowserEngine, cacheDir string) (string, error) {
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home dir: %w", err)
		}
		cacheDir = filepath.Join(home, ".cache", "spitolas")
	}

	var version, binaryPath string
	var archiveData []byte
	var isZip bool

	switch engine {
	case EngineChromium:
		if chromiumVersion == "" || chromiumZip == nil {
			return "", fmt.Errorf("no embedded chromium available in this build")
		}
		version = chromiumVersion
		binaryPath = chromiumBinaryPath
		archiveData = chromiumZip
		isZip = true
	case EngineUngoogled:
		// Ungoogled-chromium is only available on Linux
		if ungoogledVersion == "" || ungoogledChromiumTarXz == nil {
			return "", fmt.Errorf("ungoogled-chromium is only available on Linux")
		}
		version = ungoogledVersion
		binaryPath = ungoogledBinaryPath
		archiveData = ungoogledChromiumTarXz
		isZip = false
	case EngineFingerprint:
		if fingerprintVersion == "" || fingerprintArchive == nil {
			return "", fmt.Errorf("no embedded fingerprint-chromium available in this build")
		}
		version = fingerprintVersion
		binaryPath = fingerprintBinaryPath
		archiveData = fingerprintArchive
		isZip = false
	default:
		return "", fmt.Errorf("unknown browser engine: %s", engine)
	}

	extractDir := filepath.Join(cacheDir, string(engine)+"-"+version)
	markerFile := filepath.Join(extractDir, ".extracted")
	binPath := filepath.Join(extractDir, binaryPath)

	// Check if already extracted
	if data, err := os.ReadFile(markerFile); err == nil && string(data) == version {
		if _, err := os.Stat(binPath); err == nil {
			return binPath, nil
		}
	}

	// Clean old cache and extract fresh
	if err := os.RemoveAll(extractDir); err != nil {
		return "", fmt.Errorf("failed to clean old cache: %w", err)
	}
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache dir: %w", err)
	}

	// Extract based on archive type
	if isZip {
		if err := extractZip(archiveData, extractDir); err != nil {
			return "", fmt.Errorf("failed to extract browser: %w", err)
		}
	} else {
		if err := extractTarXz(archiveData, extractDir); err != nil {
			return "", fmt.Errorf("failed to extract browser: %w", err)
		}
	}

	// Make binary executable
	if err := os.Chmod(binPath, 0755); err != nil {
		return "", fmt.Errorf("failed to chmod binary: %w", err)
	}

	// Write marker file with version
	if err := os.WriteFile(markerFile, []byte(version), 0644); err != nil {
		return "", fmt.Errorf("failed to write marker: %w", err)
	}

	return binPath, nil
}

// extractZip extracts a zip archive from memory to the destination directory.
func extractZip(data []byte, dest string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}

	for _, f := range r.File {
		// Security: prevent zip slip attack
		path := filepath.Join(dest, f.Name)
		if !isInsideDir(path, dest) {
			return fmt.Errorf("invalid file path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, f.Mode()); err != nil {
				return fmt.Errorf("failed to create dir %s: %w", path, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("failed to create parent dir for %s: %w", path, err)
		}

		if err := extractFile(f, path); err != nil {
			return err
		}
	}

	return nil
}

// extractFile extracts a single file from the zip archive.
func extractFile(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("failed to open %s in zip: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()

	outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", destPath, err)
	}
	defer func() { _ = outFile.Close() }()

	if _, err := io.Copy(outFile, rc); err != nil {
		return fmt.Errorf("failed to write %s: %w", destPath, err)
	}

	return nil
}

// isInsideDir checks if the path is inside the base directory (zip slip prevention).
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

// extractTarXz extracts a tar.xz archive from memory to the destination directory.
func extractTarXz(data []byte, dest string) error {
	// Create xz reader
	xzReader, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create xz reader: %w", err)
	}

	// Create tar reader
	tarReader := tar.NewReader(xzReader)

	// Extract all files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Security: prevent tar slip attack
		path := filepath.Join(dest, header.Name)
		if !isInsideDir(path, dest) {
			return fmt.Errorf("invalid file path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(path, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create dir %s: %w", path, err)
			}
		case tar.TypeReg:
			// Create regular file
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %w", path, err)
			}

			outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", path, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				_ = outFile.Close()
				return fmt.Errorf("failed to write %s: %w", path, err)
			}
			_ = outFile.Close()
		case tar.TypeSymlink:
			// Create symlink
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return fmt.Errorf("failed to create parent dir for symlink %s: %w", path, err)
			}
			if err := os.Symlink(header.Linkname, path); err != nil {
				return fmt.Errorf("failed to create symlink %s: %w", path, err)
			}
		default:
			// Skip other types (links, etc.)
			continue
		}
	}

	return nil
}
