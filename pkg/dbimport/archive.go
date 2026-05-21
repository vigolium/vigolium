// Package dbimport provides reusable importers for audit folders,
// archive bundles (.tar.gz, .tgz, .zip), and JSONL exports. Both the CLI
// (`vigolium import`) and the REST API (`POST /api/import`) call into this
// package so the parsing, validation, and DB-write logic stays in one place.
package dbimport

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ArchiveExt inspects a path and returns one of: ".tar.gz", ".tgz", ".zip",
// ".jsonl", ".ndjson", ".json", or "" (unknown). Lowercased, includes leading dot.
func ArchiveExt(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		return ".tar.gz"
	case strings.HasSuffix(lower, ".tgz"):
		return ".tgz"
	case strings.HasSuffix(lower, ".zip"):
		return ".zip"
	case strings.HasSuffix(lower, ".jsonl"):
		return ".jsonl"
	case strings.HasSuffix(lower, ".ndjson"):
		return ".ndjson"
	case strings.HasSuffix(lower, ".json"):
		return ".json"
	}
	return ""
}

// ExtractArchiveToDir extracts a .tar.gz / .tgz / .zip into a fresh temp dir
// and returns its path. The caller must defer cleanup().
func ExtractArchiveToDir(archivePath string) (dir string, cleanup func(), err error) {
	cleanup = func() {}
	tmpDir, err := os.MkdirTemp("", "vigolium-extract-*")
	if err != nil {
		return "", cleanup, fmt.Errorf("failed to create extract dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tmpDir) }

	ext := ArchiveExt(archivePath)
	switch ext {
	case ".tar.gz", ".tgz":
		err = extractTarGzInto(archivePath, tmpDir)
	case ".zip":
		err = extractZipInto(archivePath, tmpDir)
	default:
		err = fmt.Errorf("unsupported archive extension %q (want .tar.gz, .tgz, or .zip)", ext)
	}
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return tmpDir, cleanup, nil
}

func extractTarGzInto(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	cleanDest := filepath.Clean(destDir) + string(os.PathSeparator)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		fPath := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(fPath, cleanDest) {
			return fmt.Errorf("illegal file path in archive: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(fPath, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(fPath), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return err
			}
			_ = out.Close()
		}
	}
	return nil
}

func extractZipInto(archivePath, destDir string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()

	cleanDest := filepath.Clean(destDir) + string(os.PathSeparator)
	for _, zf := range zr.File {
		fPath := filepath.Join(destDir, zf.Name)
		if !strings.HasPrefix(fPath, cleanDest) {
			return fmt.Errorf("illegal file path in archive: %s", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(fPath, zf.Mode()); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fPath), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zf.Mode())
		if err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			_ = out.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			_ = rc.Close()
			_ = out.Close()
			return err
		}
		_ = rc.Close()
		_ = out.Close()
	}
	return nil
}

// CopyDirContents recursively copies the contents of src into dst, creating
// dst if needed. Symlinks are skipped; only regular files and dirs are copied.
// File modes are preserved best-effort.
func CopyDirContents(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source %q is not a directory", src)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	mode := os.FileMode(0o644)
	if info, err := in.Stat(); err == nil {
		mode = info.Mode().Perm()
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
