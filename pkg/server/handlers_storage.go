package server

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/storage"
	"go.uber.org/zap"
)

// HandleStorageUploadSource handles POST /api/storage/upload-source.
// Accepts multipart file upload and stores it in <bucket>/<project-uuid>/ugc/<filename>.
func (h *Handlers) HandleStorageUploadSource(c fiber.Ctx) error {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: "cloud storage is not enabled",
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := c.Locals("project_uuid").(string)

	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "file field is required",
			Code:  fiber.StatusBadRequest,
		})
	}

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create storage client",
			Code:  fiber.StatusInternalServerError,
		})
	}

	f, err := file.Open()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to open uploaded file",
			Code:  fiber.StatusInternalServerError,
		})
	}
	defer f.Close()

	filename := filepath.Base(file.Filename)
	key := storage.UGCKey(filename)

	if err := sc.Upload(context.Background(), projectUUID, key, f, file.Size, file.Header.Get("Content-Type")); err != nil {
		zap.L().Error("Failed to upload source to storage", zap.Error(err))
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to upload file to storage",
			Code:  fiber.StatusInternalServerError,
		})
	}

	storageURL := storage.StorageURL(projectUUID, key)
	return c.JSON(StorageUploadResponse{
		StorageURL: storageURL,
		Key:        key,
		Filename:   filename,
		Size:       file.Size,
		Message:    "source uploaded successfully",
	})
}

// HandleStorageDownloadSource handles GET /api/storage/source/:key.
// Downloads a source file from <bucket>/<project-uuid>/ugc/:key.
func (h *Handlers) HandleStorageDownloadSource(c fiber.Ctx) error {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: "cloud storage is not enabled",
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := c.Locals("project_uuid").(string)
	key := c.Params("key")
	if key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "key parameter is required",
			Code:  fiber.StatusBadRequest,
		})
	}

	cleanKey, validateErr := storage.ValidateKey(key)
	if validateErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid key: " + validateErr.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
	fullKey := storage.UGCKey(cleanKey)

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create storage client",
			Code:  fiber.StatusInternalServerError,
		})
	}

	reader, err := sc.Download(context.Background(), projectUUID, fullKey)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
			Error: "file not found in storage",
			Code:  fiber.StatusNotFound,
		})
	}
	defer reader.Close()

	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", key))
	c.Set("Content-Type", "application/octet-stream")
	_, err = io.Copy(c.Response().BodyWriter(), reader)
	return err
}

// HandleStorageDownloadResults handles GET /api/storage/results/:scan-uuid.
// Downloads the result bundle for a native scan or agentic scan.
func (h *Handlers) HandleStorageDownloadResults(c fiber.Ctx) error {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: "cloud storage is not enabled",
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := c.Locals("project_uuid").(string)
	scanUUID := c.Params("scan-uuid")
	if scanUUID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "scan-uuid parameter is required",
			Code:  fiber.StatusBadRequest,
		})
	}
	if _, err := storage.ValidateKey(scanUUID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid scan UUID: " + err.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create storage client",
			Code:  fiber.StatusInternalServerError,
		})
	}

	keys := []string{
		storage.NativeScanResultKey(scanUUID),
		storage.AgenticScanResultKey(scanUUID),
	}

	for _, key := range keys {
		reader, err := sc.Download(context.Background(), projectUUID, key)
		if err != nil {
			continue
		}
		defer reader.Close()

		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(key)))
		c.Set("Content-Type", "application/zip")
		_, err = io.Copy(c.Response().BodyWriter(), reader)
		return err
	}

	return c.Status(fiber.StatusNotFound).JSON(ErrorResponse{
		Error: "no results found for this scan UUID",
		Code:  fiber.StatusNotFound,
	})
}

// HandleStoragePresign handles POST /api/storage/presign.
// Generates presigned URLs for direct upload/download.
func (h *Handlers) HandleStoragePresign(c fiber.Ctx) error {
	if h.settings == nil || !h.settings.Storage.IsEnabled() {
		return c.Status(fiber.StatusServiceUnavailable).JSON(ErrorResponse{
			Error: "cloud storage is not enabled",
			Code:  fiber.StatusServiceUnavailable,
		})
	}

	projectUUID := c.Locals("project_uuid").(string)

	var req StoragePresignRequest
	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid request body",
			Code:  fiber.StatusBadRequest,
		})
	}

	if req.Key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "key is required",
			Code:  fiber.StatusBadRequest,
		})
	}
	cleanKey, validateErr := storage.ValidateKey(req.Key)
	if validateErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error: "invalid key: " + validateErr.Error(),
			Code:  fiber.StatusBadRequest,
		})
	}
	req.Key = cleanKey

	sc, err := storage.NewClient(&h.settings.Storage)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to create storage client",
			Code:  fiber.StatusInternalServerError,
		})
	}

	expiry := 1 * time.Hour
	if req.ExpirySeconds > 0 {
		expiry = time.Duration(req.ExpirySeconds) * time.Second
	}

	var url string
	switch req.Method {
	case "PUT", "put":
		url, err = sc.PresignedPutURL(context.Background(), projectUUID, req.Key, expiry)
	default:
		url, err = sc.PresignedGetURL(context.Background(), projectUUID, req.Key, expiry)
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error: "failed to generate presigned URL",
			Code:  fiber.StatusInternalServerError,
		})
	}

	return c.JSON(StoragePresignResponse{
		URL:    url,
		Key:    req.Key,
		Method: strings.ToUpper(req.Method),
		Expiry: int(expiry.Seconds()),
	})
}

// --- Storage request/response types ---

// StorageUploadResponse is the response for POST /api/storage/upload-source.
type StorageUploadResponse struct {
	StorageURL string `json:"storage_url"`
	Key        string `json:"key"`
	Filename   string `json:"filename"`
	Size       int64  `json:"size"`
	Message    string `json:"message"`
}

// StoragePresignRequest is the request body for POST /api/storage/presign.
type StoragePresignRequest struct {
	Key           string `json:"key"`
	Method        string `json:"method,omitempty"` // GET (default) or PUT
	ExpirySeconds int    `json:"expiry_seconds,omitempty"`
}

// StoragePresignResponse is the response for POST /api/storage/presign.
type StoragePresignResponse struct {
	URL    string `json:"url"`
	Key    string `json:"key"`
	Method string `json:"method"`
	Expiry int    `json:"expiry_seconds"`
}
