package cli

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

const (
	tsPlaceholder      = "{ts}"
	projectPlaceholder = "{project-uuid}"
)

// expandOutputPlaceholders replaces {ts} with a UTC timestamp formatted as
// 2026-04-26T14-05-30Z and {project-uuid} with the active project's UUID.
// Project resolution only runs if the placeholder is present.
func expandOutputPlaceholders(s string) (string, error) {
	if !strings.Contains(s, "{") {
		return s, nil
	}
	if strings.Contains(s, tsPlaceholder) {
		s = strings.ReplaceAll(s, tsPlaceholder, nowFilenameTS())
	}
	if strings.Contains(s, projectPlaceholder) {
		proj, err := resolveProjectUUID()
		if err != nil {
			return "", fmt.Errorf("cannot expand %s: %w", projectPlaceholder, err)
		}
		s = strings.ReplaceAll(s, projectPlaceholder, proj)
	}
	return s, nil
}

func nowFilenameTS() string {
	return time.Now().UTC().Format("2006-01-02T15-04-05Z")
}

// resolveImportInput prepares a user-supplied import argument for downstream
// processing. For gs:// (or gcs://) URIs it downloads to a temp file. For local
// paths it passes through. The caller must defer cleanup().
func resolveImportInput(ctx context.Context, arg string) (localPath string, cleanup func(), err error) {
	cleanup = func() {}
	if !storage.IsGCSURI(arg) {
		return arg, cleanup, nil
	}
	arg = storage.NormalizeGCSURI(arg)

	sc, err := requireStorageClient()
	if err != nil {
		return "", cleanup, err
	}
	bucketProj, key, err := storage.ParseGCSPath(arg)
	if err != nil {
		return "", cleanup, err
	}

	ext := dbimport.ArchiveExt(key)
	if ext == "" {
		ext = filepath.Ext(key)
	}
	tmpFile, err := os.CreateTemp("", "vigolium-import-*"+ext)
	if err != nil {
		return "", cleanup, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	if err := sc.DownloadToFile(ctx, bucketProj, key, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", cleanup, fmt.Errorf("failed to download %s: %w", arg, err)
	}
	cleanup = func() { _ = os.Remove(tmpPath) }

	fmt.Fprintf(os.Stderr, "%s Downloaded %s\n", terminal.InfoSymbol(), terminal.Gray(arg))
	return tmpPath, cleanup, nil
}

// resolveExportOutput prepares a user-supplied output target. For gs:// (or
// gcs://) URIs it returns a temp file path; the returned finalize() uploads
// the temp file to the bucket and removes it. For local paths it passes
// through and finalize() is a no-op. The {ts} placeholder is expanded for
// both branches.
func resolveExportOutput(ctx context.Context, arg string) (localPath string, finalize func() error, err error) {
	finalize = func() error { return nil }
	if arg == "" {
		return "", finalize, nil
	}
	arg, err = expandOutputPlaceholders(arg)
	if err != nil {
		return "", finalize, err
	}
	if !storage.IsGCSURI(arg) {
		return arg, finalize, nil
	}
	arg = storage.NormalizeGCSURI(arg)

	sc, err := requireStorageClient()
	if err != nil {
		return "", finalize, err
	}
	bucketProj, key, err := storage.ParseGCSPath(arg)
	if err != nil {
		return "", finalize, err
	}

	if activeProj, perr := resolveProjectUUID(); perr == nil && activeProj != bucketProj {
		fmt.Fprintf(os.Stderr, "%s Storage URL project (%s) differs from active project (%s)\n",
			terminal.InfoSymbol(), terminal.Gray(bucketProj), terminal.Gray(activeProj))
	}

	ext := dbimport.ArchiveExt(key)
	if ext == "" {
		ext = filepath.Ext(key)
	}
	tmpFile, err := os.CreateTemp("", "vigolium-export-*"+ext)
	if err != nil {
		return "", finalize, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	finalize = func() error {
		defer func() { _ = os.Remove(tmpPath) }()
		if err := sc.UploadFile(ctx, bucketProj, key, tmpPath); err != nil {
			return fmt.Errorf("failed to upload to %s: %w", arg, err)
		}
		fmt.Fprintf(os.Stderr, "%s Uploaded export to %s\n",
			terminal.SuccessSymbol(), terminal.Gray(arg))
		return nil
	}
	return tmpPath, finalize, nil
}

// bundleFolderToFile writes srcDir into archivePath. Format is chosen by the
// archivePath extension: .zip → zip, anything else → tar.gz.
func bundleFolderToFile(srcDir, archivePath string) error {
	if strings.HasSuffix(strings.ToLower(archivePath), ".zip") {
		return createZip(srcDir, archivePath)
	}
	return createTarGz(srcDir, archivePath)
}

func createTarGz(srcDir, archivePath string) error {
	out, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	gw := gzip.NewWriter(out)
	defer func() { _ = gw.Close() }()
	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})
}

func createZip(srcDir, archivePath string) error {
	out, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	zw := zip.NewWriter(out)
	defer func() { _ = zw.Close() }()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		} else {
			hdr.Method = zip.Deflate
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(w, f)
		return err
	})
}

// uploadImportSource bundles (if a folder) and uploads the import source to
// cloud storage under the active project. If explicitKey is empty, a key under
// imports/ is auto-derived. Folder bundles default to .tar.gz unless
// explicitKey ends in .zip. Returns the resulting gs:// URL.
func uploadImportSource(ctx context.Context, srcPath, explicitKey string) (string, error) {
	sc, err := requireStorageClient()
	if err != nil {
		return "", err
	}
	activeProj, err := resolveProjectUUID()
	if err != nil {
		return "", err
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		return "", err
	}

	wantZip := strings.HasSuffix(strings.ToLower(explicitKey), ".zip")
	ts := nowFilenameTS()

	if info.IsDir() {
		archiveExt := ".tar.gz"
		if wantZip {
			archiveExt = ".zip"
		}
		key := explicitKey
		if key == "" {
			key = fmt.Sprintf("imports/%s-%s%s", filepath.Base(srcPath), ts, archiveExt)
		}

		tmp, err := os.CreateTemp("", "vigolium-import-bundle-*"+archiveExt)
		if err != nil {
			return "", fmt.Errorf("failed to create temp bundle: %w", err)
		}
		tmpPath := tmp.Name()
		_ = tmp.Close()
		defer func() { _ = os.Remove(tmpPath) }()

		if err := bundleFolderToFile(srcPath, tmpPath); err != nil {
			return "", fmt.Errorf("failed to bundle %s: %w", srcPath, err)
		}
		if err := sc.UploadFile(ctx, activeProj, key, tmpPath); err != nil {
			return "", err
		}
		return storage.StorageURL(activeProj, key), nil
	}

	// Single file: upload as-is.
	key := explicitKey
	if key == "" {
		ext := dbimport.ArchiveExt(srcPath)
		if ext == "" {
			ext = filepath.Ext(srcPath)
		}
		base := strings.TrimSuffix(filepath.Base(srcPath), ext)
		key = fmt.Sprintf("imports/%s-%s%s", base, ts, ext)
	}
	if err := sc.UploadFile(ctx, activeProj, key, srcPath); err != nil {
		return "", err
	}
	return storage.StorageURL(activeProj, key), nil
}
