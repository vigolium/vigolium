package toolexec

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// extractFromZIP extracts a named binary from a ZIP archive in memory.
func extractFromZIP(zipData []byte, binaryName, destPath string, maxSize int64) error {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("%w: zip open: %v", ErrExtractionFailed, err)
	}

	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if name == binaryName || name == binaryName+".exe" {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("%w: open entry: %v", ErrExtractionFailed, err)
			}

			outFile, err := os.Create(destPath)
			if err != nil {
				_ = rc.Close()
				return fmt.Errorf("%w: create dest: %v", ErrExtractionFailed, err)
			}

			_, err = io.Copy(outFile, io.LimitReader(rc, maxSize))
			_ = outFile.Close()
			_ = rc.Close()
			if err != nil {
				_ = os.Remove(destPath)
				return fmt.Errorf("%w: extract: %v", ErrExtractionFailed, err)
			}

			return nil
		}
	}

	return fmt.Errorf("%w: binary not found in archive", ErrExtractionFailed)
}

// extractFromTGZ extracts a named binary from a .tgz stream.
func extractFromTGZ(r io.Reader, binaryName, destPath string, maxSize int64) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: gzip open: %v", ErrExtractionFailed, err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%w: binary not found in archive", ErrExtractionFailed)
		}
		if err != nil {
			return fmt.Errorf("%w: tar read: %v", ErrExtractionFailed, err)
		}

		if header.Typeflag == tar.TypeReg &&
			(header.Name == binaryName || filepath.Base(header.Name) == binaryName) {

			outFile, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("%w: create dest: %v", ErrExtractionFailed, err)
			}

			_, err = io.Copy(outFile, io.LimitReader(tr, maxSize))
			_ = outFile.Close()
			if err != nil {
				_ = os.Remove(destPath)
				return fmt.Errorf("%w: extract: %v", ErrExtractionFailed, err)
			}

			return nil
		}
	}
}
