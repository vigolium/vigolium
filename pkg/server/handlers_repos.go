package server

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

const maxUploadSize = 500 << 20 // 500 MB

// repoUploadsDir returns the base directory for uploaded repos.
func repoUploadsDir(settings *config.Settings) string {
	base := config.ExpandPath(settings.SourceAware.StoragePath)
	return filepath.Join(base, "uploads")
}

// HandleRepoUpload handles POST /api/repos/upload — accepts a zip/tar.gz/tar archive
// and extracts it into a unique directory. Returns the repo ID and path for use with
// POST /api/scans/run source field.
func (h *Handlers) HandleRepoUpload(c fiber.Ctx) error {
	if int64(len(c.Body())) > maxUploadSize {
		return c.Status(fiber.StatusRequestEntityTooLarge).JSON(ErrorResponse{
			Error: fmt.Sprintf("request body exceeds maximum size of %d MB", maxUploadSize>>20),
		})
	}

	file, err := c.FormFile("file")
	if err != nil || file == nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrMissingFile.Error(),
		})
	}

	// Determine archive type from filename
	name := strings.ToLower(file.Filename)
	var archiveType string
	switch {
	case strings.HasSuffix(name, ".zip"):
		archiveType = "zip"
	case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz"):
		archiveType = "tar.gz"
	case strings.HasSuffix(name, ".tar"):
		archiveType = "tar"
	default:
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: ErrUnsupportedArchive.Error(),
		})
	}

	repoID := uuid.New().String()
	destDir := filepath.Join(repoUploadsDir(h.settings), repoID)

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create upload directory: " + err.Error(),
		})
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		_ = os.RemoveAll(destDir)
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to open uploaded file: " + err.Error(),
		})
	}
	defer func() { _ = src.Close() }()

	// Save to temp file for extraction (zip needs random access)
	tmpFile, err := os.CreateTemp("", "vigolium-upload-*")
	if err != nil {
		_ = os.RemoveAll(destDir)
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create temp file: " + err.Error(),
		})
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := io.Copy(tmpFile, src); err != nil {
		_ = tmpFile.Close()
		_ = os.RemoveAll(destDir)
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to save uploaded file: " + err.Error(),
		})
	}
	_ = tmpFile.Close()

	// Extract
	switch archiveType {
	case "zip":
		err = extractZip(tmpPath, destDir)
	case "tar.gz":
		err = extractTarGz(tmpPath, destDir)
	case "tar":
		err = extractTar(tmpPath, destDir)
	}

	if err != nil {
		_ = os.RemoveAll(destDir)
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to extract archive: " + err.Error(),
		})
	}

	zap.L().Info("Repo uploaded", zap.String("repo_id", repoID), zap.String("path", destDir))

	return c.Status(fiber.StatusOK).JSON(RepoUploadResponse{
		RepoID:  repoID,
		Source:  destDir,
		Message: "repository uploaded and extracted",
	})
}

// HandleRepoDelete handles DELETE /api/repos/:id — removes an uploaded repo directory.
func (h *Handlers) HandleRepoDelete(c fiber.Ctx) error {
	repoID := c.Params("id")
	if repoID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "repo ID is required",
		})
	}

	// Validate UUID format to prevent path traversal
	if _, err := uuid.Parse(repoID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid repo ID format",
		})
	}

	repoDir := filepath.Join(repoUploadsDir(h.settings), repoID)

	info, err := os.Stat(repoDir)
	if err != nil || !info.IsDir() {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: ErrRepoNotFound.Error(),
		})
	}

	if err := os.RemoveAll(repoDir); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to delete repo: " + err.Error(),
		})
	}

	zap.L().Info("Repo deleted", zap.String("repo_id", repoID))

	return c.JSON(RepoDeleteResponse{
		RepoID:  repoID,
		Message: "repository deleted",
	})
}

// cloneRepoForAPI clones a git URL into the configured storage directory.
// Mirrors the logic in pkg/cli/source_add.go:cloneGitRepo but accepts settings directly.
func cloneRepoForAPI(gitURL string, settings *config.Settings) (string, error) {
	storagePath := config.ExpandPath(settings.SourceAware.StoragePath)
	cloneDepth := settings.SourceAware.CloneDepth
	if cloneDepth <= 0 {
		cloneDepth = 1
	}

	dirName, err := gitURLToDirName(gitURL)
	if err != nil {
		return "", fmt.Errorf("invalid git URL: %w", err)
	}

	destPath := filepath.Join(storagePath, dirName)

	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return "", fmt.Errorf("failed to create storage directory %s: %w", storagePath, err)
	}

	// Idempotent: skip clone if directory already exists
	if info, statErr := os.Stat(destPath); statErr == nil && info.IsDir() {
		return destPath, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := []string{"clone", fmt.Sprintf("--depth=%d", cloneDepth), gitURL, destPath}
	cmd := exec.CommandContext(ctx, "git", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git clone failed: %w\n%s", err, string(output))
	}

	zap.L().Info("Cloned repo for API scan", zap.String("url", gitURL), zap.String("path", destPath))
	return destPath, nil
}

// gitURLToDirName derives a filesystem-safe directory name from a git URL.
// Duplicated from pkg/cli/source_add.go to avoid circular dependency.
func gitURLToDirName(rawURL string) (string, error) {
	normalized := rawURL
	if strings.HasPrefix(rawURL, "git@") {
		normalized = strings.Replace(rawURL, ":", "/", 1)
		normalized = strings.Replace(normalized, "git@", "https://", 1)
	}

	// Quick parse — only need host + path
	// Remove scheme
	after := normalized
	if idx := strings.Index(after, "://"); idx >= 0 {
		after = after[idx+3:]
	}

	// Split host / path
	slashIdx := strings.Index(after, "/")
	if slashIdx < 0 {
		return "", fmt.Errorf("no repository path in URL: %s", rawURL)
	}
	host := after[:slashIdx]
	path := after[slashIdx+1:]
	path = strings.TrimSuffix(path, ".git")
	if path == "" {
		return "", fmt.Errorf("no repository path in URL: %s", rawURL)
	}

	safePath := strings.ReplaceAll(path, "/", "_")
	return host + "_" + safePath, nil
}

// --- Archive extraction helpers ---

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		target := filepath.Join(destDir, f.Name)
		// Prevent zip slip
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in archive: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}

		if err := extractZipFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractZipFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, rc)
	return err
}

func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	return extractTarReader(tar.NewReader(gz), destDir)
}

func extractTar(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return extractTarReader(tar.NewReader(f), destDir)
}

func extractTarReader(tr *tar.Reader, destDir string) error {
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)
		// Prevent path traversal
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in archive: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
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
