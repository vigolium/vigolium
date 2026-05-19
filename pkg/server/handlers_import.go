package server

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/storage"
)

// ImportRequest is the JSON body for POST /api/import when pointing the
// server at a cloud-stored archive instead of uploading bytes. URL must be
// gs:// (or gcs:// alias). AgenticScanUUID, when set, attaches findings to
// an existing scan row in the same project instead of creating a new one.
type ImportRequest struct {
	URL             string `json:"url"`
	AgenticScanUUID string `json:"agentic_scan_uuid,omitempty"`
}

// ImportResponse is the success response for POST /api/import.
type ImportResponse struct {
	AgenticScanUUID string         `json:"agentic_scan_uuid,omitempty"`
	CreatedNew      bool           `json:"created_new"`
	RecordsImported int            `json:"records_imported"`
	FindingsTotal   int            `json:"findings_total"`
	FindingsSaved   int            `json:"findings_saved"`
	FindingsSkipped int            `json:"findings_skipped"`
	ParseErrors     int            `json:"parse_errors,omitempty"`
	Severity        map[string]int `json:"severity,omitempty"`
	SessionDir      string         `json:"session_dir,omitempty"`
	StorageURL      string         `json:"storage_url,omitempty"`
}

// HandleImport handles POST /api/import — imports scan data into the database
// from one of three input shapes, dispatched on Content-Type:
//
//   - multipart/form-data with file=*.jsonl|*.ndjson: bulk JSONL import.
//   - multipart/form-data with file=*.tar.gz|*.tgz|*.zip: archive containing
//     archon audit output or JSONL files.
//   - application/json with {"url": "gs://..."}: backend fetches the archive
//     or JSONL from cloud storage, then imports it.
//
// All shapes accept an optional `agentic_scan_uuid` to attach imported
// findings to an existing scan instead of creating a new one. For multipart
// requests it's a form field; for JSON it's a body field.
func (h *Handlers) HandleImport(c fiber.Ctx) error {
	if h.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: ErrDatabaseRequired.Error(),
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := getProjectUUID(c)
	ctx := c.Context()
	contentType := strings.ToLower(c.Get("Content-Type"))

	switch {
	case strings.HasPrefix(contentType, "multipart/form-data"):
		return h.importFromMultipart(c, ctx, projectUUID)
	case strings.HasPrefix(contentType, "application/json"):
		return h.importFromJSON(c, ctx, projectUUID)
	default:
		return c.Status(fiber.StatusUnsupportedMediaType).JSON(ErrorResponse{
			Error: "Content-Type must be multipart/form-data or application/json",
			Code:  fiber.StatusUnsupportedMediaType,
		})
	}
}

func (h *Handlers) importFromMultipart(c fiber.Ctx, ctx context.Context, projectUUID string) error {
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "file form field is required",
			Code:  fiber.StatusBadRequest,
		})
	}
	agenticScanUUID := strings.TrimSpace(c.FormValue("agentic_scan_uuid"))

	localPath, cleanup, err := persistMultipartToTemp(file)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to persist upload: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	defer cleanup()

	return h.runImportAndRespond(c, ctx, localPath, projectUUID, agenticScanUUID, file.Filename)
}

func (h *Handlers) importFromJSON(c fiber.Ctx, ctx context.Context, projectUUID string) error {
	var req ImportRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
	url := strings.TrimSpace(req.URL)
	if url == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "url is required for JSON body",
			Code:  fiber.StatusBadRequest,
		})
	}
	url = storage.NormalizeGCSURI(url)
	if !storage.IsGCSURI(url) {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "url must be a gs:// or gcs:// address",
			Code:  fiber.StatusBadRequest,
		})
	}

	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: "cloud storage is not enabled",
			Code:  fiber.StatusServiceUnavailable,
		})
	}
	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create storage client",
			Code:  fiber.StatusInternalServerError,
		})
	}
	bucketProj, key, err := storage.ParseGCSPath(url)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid storage URL: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	ext := dbimport.ArchiveExt(key)
	if ext == "" {
		ext = filepath.Ext(key)
	}
	tmpFile, err := os.CreateTemp("", "vigolium-import-*"+ext)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to allocate temp file: " + err.Error(),
			Code:  fiber.StatusInternalServerError,
		})
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	cleanup := func() { _ = os.Remove(tmpPath) }
	defer cleanup()

	if err := sc.DownloadToFile(ctx, bucketProj, key, tmpPath); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "failed to download from storage: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	return h.runImportAndRespond(c, ctx, tmpPath, projectUUID, req.AgenticScanUUID, url)
}

// runImportAndRespond invokes dbimport.ImportPath and returns the response.
// originalSource is recorded as StorageURL on archon imports when it is a
// gs:// URL; otherwise it serves only as a debug breadcrumb.
func (h *Handlers) runImportAndRespond(c fiber.Ctx, ctx context.Context, localPath, projectUUID, agenticScanUUID, originalSource string) error {
	opts := dbimport.Options{
		OriginalSource:     originalSource,
		AgenticScanUUID:    strings.TrimSpace(agenticScanUUID),
		SessionDirArchiver: h.serverSessionDirArchiver(),
	}

	result, err := dbimport.ImportPath(ctx, h.repo, localPath, projectUUID, opts)
	if err != nil {
		zap.L().Warn("import failed",
			zap.String("project_uuid", projectUUID),
			zap.String("source", originalSource),
			zap.Error(err))
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	return c.JSON(ImportResponse{
		AgenticScanUUID: result.AgenticScanUUID(),
		CreatedNew:      result.CreatedNew,
		RecordsImported: result.RecordsImported,
		FindingsTotal:   result.FindingsTotal,
		FindingsSaved:   result.FindingsSaved,
		FindingsSkipped: result.FindingsSkipped,
		ParseErrors:     result.ParseErrors,
		Severity:        result.SeverityCounts,
		SessionDir:      result.SessionDir,
		StorageURL:      result.StorageURL,
	})
}

// serverSessionDirArchiver mirrors the CLI's archon archival behavior: copy
// the imported archon source folder into <agent.sessions_dir>/<uuid>/archon.
// Returns nil when the server has no usable sessions dir, in which case
// dbimport simply skips the copy.
func (h *Handlers) serverSessionDirArchiver() func(string, string) (string, error) {
	if h.settings == nil {
		return nil
	}
	base := h.settings.Agent.EffectiveSessionsDir()
	if base == "" {
		return nil
	}
	return func(scanUUID, srcDir string) (string, error) {
		sessionDir, err := agent.EnsureSessionDir(base, scanUUID)
		if err != nil {
			zap.L().Warn("import: failed to create session dir",
				zap.String("scan_uuid", scanUUID),
				zap.Error(err))
			return "", nil
		}
		dst := filepath.Join(sessionDir, "archon")
		if entries, statErr := os.ReadDir(dst); statErr == nil && len(entries) > 0 {
			return sessionDir, nil
		}
		if err := dbimport.CopyDirContents(srcDir, dst); err != nil {
			zap.L().Warn("import: failed to copy archon source",
				zap.String("scan_uuid", scanUUID),
				zap.Error(err))
			return "", nil
		}
		return sessionDir, nil
	}
}

// persistMultipartToTemp streams an uploaded file to a temp location so the
// downstream importer can re-open it from disk (the multipart File doesn't
// outlive the request, and on-disk paths are what ImportPath expects). The
// caller must defer cleanup().
func persistMultipartToTemp(fh *multipart.FileHeader) (string, func(), error) {
	cleanup := func() {}
	ext := dbimport.ArchiveExt(fh.Filename)
	if ext == "" {
		ext = filepath.Ext(fh.Filename)
	}
	tmpFile, err := os.CreateTemp("", "vigolium-import-*"+ext)
	if err != nil {
		return "", cleanup, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup = func() { _ = os.Remove(tmpPath) }

	src, err := fh.Open()
	if err != nil {
		_ = tmpFile.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("open uploaded file: %w", err)
	}
	defer func() { _ = src.Close() }()

	if _, err := io.Copy(tmpFile, src); err != nil {
		_ = tmpFile.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("copy upload to temp: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close temp file: %w", err)
	}
	return tmpPath, cleanup, nil
}
