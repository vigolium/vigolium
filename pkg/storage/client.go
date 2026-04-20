package storage

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

const (
	SchemeGCS          = "gs://"
	PathNativeScans    = "native-scans"
	PathAgenticScans   = "agentic-scans"
	PathUGC            = "ugc"
	ResultsBundleName  = "results.zip"
)

// NativeScanResultKey returns the storage key for a native scan result bundle.
func NativeScanResultKey(scanUUID string) string {
	return fmt.Sprintf("%s/%s/%s", PathNativeScans, scanUUID, ResultsBundleName)
}

// AgenticScanResultKey returns the storage key for an agentic scan result bundle.
func AgenticScanResultKey(runUUID string) string {
	return fmt.Sprintf("%s/%s/%s", PathAgenticScans, runUUID, ResultsBundleName)
}

// UGCKey returns the storage key for a user-uploaded file.
func UGCKey(filename string) string {
	return fmt.Sprintf("%s/%s", PathUGC, filename)
}

// StorageURL builds a gs:// URL from project UUID and key.
func StorageURL(projectUUID, key string) string {
	return fmt.Sprintf("%s%s/%s", SchemeGCS, projectUUID, key)
}

var ErrPathTraversal = fmt.Errorf("path contains traversal or invalid characters")

// ValidateKey rejects keys that attempt path traversal or project scope escape.
// Returns the cleaned key or an error.
func ValidateKey(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key must not be empty")
	}
	cleaned := filepath.ToSlash(filepath.Clean(key))
	cleaned = strings.TrimPrefix(cleaned, "/")

	if cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, "../") ||
		strings.Contains(cleaned, "/../") ||
		strings.HasSuffix(cleaned, "/..") {
		return "", ErrPathTraversal
	}
	if strings.ContainsAny(cleaned, "\\") {
		return "", ErrPathTraversal
	}
	return cleaned, nil
}

// ValidateProjectUUID rejects project UUIDs that contain path separators or traversal.
func ValidateProjectUUID(projectUUID string) error {
	if projectUUID == "" {
		return fmt.Errorf("project UUID must not be empty")
	}
	if strings.ContainsAny(projectUUID, "/\\") || strings.Contains(projectUUID, "..") {
		return ErrPathTraversal
	}
	return nil
}

// Client wraps minio-go to provide project-scoped object storage operations.
type Client struct {
	mc     *minio.Client
	bucket string
}

// NewClient creates a storage client from the StorageConfig.
func NewClient(cfg *config.StorageConfig) (*Client, error) {
	if !cfg.IsEnabled() {
		return nil, fmt.Errorf("storage is not enabled")
	}

	endpoint := cfg.EffectiveEndpoint()
	if endpoint == "" {
		return nil, fmt.Errorf("storage endpoint is required")
	}

	opts := &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.EffectiveUseSSL(),
		Region: cfg.Region,
	}

	if cfg.EffectivePathStyle() {
		opts.BucketLookup = minio.BucketLookupPath
	}

	mc, err := minio.New(endpoint, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}

	return &Client{mc: mc, bucket: cfg.Bucket}, nil
}

// objectKey builds a project-scoped object path: <projectUUID>/<key>.
// Returns an error if either value contains traversal sequences.
func objectKey(projectUUID, key string) (string, error) {
	if err := ValidateProjectUUID(projectUUID); err != nil {
		return "", fmt.Errorf("invalid project UUID %q: %w", projectUUID, err)
	}
	cleanKey, err := ValidateKey(key)
	if err != nil {
		return "", fmt.Errorf("invalid storage key %q: %w", key, err)
	}
	return projectUUID + "/" + cleanKey, nil
}

func (c *Client) Upload(ctx context.Context, projectUUID, key string, reader io.Reader, size int64, contentType string) error {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	objKey, err := objectKey(projectUUID, key)
	if err != nil {
		return err
	}
	_, err = c.mc.PutObject(ctx, c.bucket, objKey, reader, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return fmt.Errorf("failed to upload %s: %w", objKey, err)
	}
	zap.L().Info("storage: uploaded object", zap.String("bucket", c.bucket), zap.String("key", objKey), zap.Int64("size", size))
	return nil
}

func (c *Client) UploadFile(ctx context.Context, projectUUID, key, filePath string) error {
	objKey, err := objectKey(projectUUID, key)
	if err != nil {
		return err
	}
	_, err = c.mc.FPutObject(ctx, c.bucket, objKey, filePath, minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to upload file %s to %s: %w", filePath, objKey, err)
	}
	zap.L().Info("storage: uploaded file", zap.String("bucket", c.bucket), zap.String("key", objKey))
	return nil
}

// Download returns a reader for the specified object. Caller must close the returned reader.
func (c *Client) Download(ctx context.Context, projectUUID, key string) (io.ReadCloser, error) {
	objKey, err := objectKey(projectUUID, key)
	if err != nil {
		return nil, err
	}
	obj, err := c.mc.GetObject(ctx, c.bucket, objKey, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", objKey, err)
	}
	return obj, nil
}

func (c *Client) DownloadToFile(ctx context.Context, projectUUID, key, destPath string) error {
	objKey, err := objectKey(projectUUID, key)
	if err != nil {
		return err
	}
	if err := c.mc.FGetObject(ctx, c.bucket, objKey, destPath, minio.GetObjectOptions{}); err != nil {
		return fmt.Errorf("failed to download %s to %s: %w", objKey, destPath, err)
	}
	zap.L().Info("storage: downloaded file", zap.String("key", objKey), zap.String("dest", destPath))
	return nil
}

func (c *Client) PresignedGetURL(ctx context.Context, projectUUID, key string, expiry time.Duration) (string, error) {
	objKey, err := objectKey(projectUUID, key)
	if err != nil {
		return "", err
	}
	u, err := c.mc.PresignedGetObject(ctx, c.bucket, objKey, expiry, url.Values{})
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned GET URL for %s: %w", objKey, err)
	}
	return u.String(), nil
}

func (c *Client) PresignedPutURL(ctx context.Context, projectUUID, key string, expiry time.Duration) (string, error) {
	objKey, err := objectKey(projectUUID, key)
	if err != nil {
		return "", err
	}
	u, err := c.mc.PresignedPutObject(ctx, c.bucket, objKey, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned PUT URL for %s: %w", objKey, err)
	}
	return u.String(), nil
}

func (c *Client) List(ctx context.Context, projectUUID, prefix string) ([]ObjectInfo, error) {
	fullPrefix, err := objectKey(projectUUID, prefix)
	if err != nil {
		return nil, err
	}
	var objects []ObjectInfo
	for obj := range c.mc.ListObjects(ctx, c.bucket, minio.ListObjectsOptions{
		Prefix:    fullPrefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", obj.Err)
		}
		key := strings.TrimPrefix(obj.Key, projectUUID+"/")
		objects = append(objects, ObjectInfo{
			Key:          key,
			Size:         obj.Size,
			LastModified: obj.LastModified,
			ContentType:  obj.ContentType,
		})
	}
	return objects, nil
}

func (c *Client) Delete(ctx context.Context, projectUUID, key string) error {
	objKey, err := objectKey(projectUUID, key)
	if err != nil {
		return err
	}
	if err := c.mc.RemoveObject(ctx, c.bucket, objKey, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("failed to delete %s: %w", objKey, err)
	}
	return nil
}

// ObjectInfo represents metadata for a listed object.
type ObjectInfo struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	ContentType  string    `json:"content_type"`
}

// ParseGCSPath parses a gs://<project-uuid>/<key> URI into project UUID and key.
// Returns empty strings if the URI doesn't match the expected format.
func ParseGCSPath(uri string) (projectUUID, key string, err error) {
	if !strings.HasPrefix(uri, SchemeGCS) {
		return "", "", fmt.Errorf("not a gs:// URI: %s", uri)
	}
	path := strings.TrimPrefix(uri, SchemeGCS)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid gs:// URI (expected gs://<project-uuid>/<key>): %s", uri)
	}
	if err := ValidateProjectUUID(parts[0]); err != nil {
		return "", "", fmt.Errorf("invalid project UUID in gs:// URI: %w", err)
	}
	cleanKey, err := ValidateKey(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid key in gs:// URI: %w", err)
	}
	return parts[0], cleanKey, nil
}

// DownloadAndExtractSource downloads a zip from storage and extracts it to a temp directory.
// Returns the path to the extracted source and the temp root directory.
// Callers should defer os.RemoveAll(tmpRoot) to clean up.
func (c *Client) DownloadAndExtractSource(ctx context.Context, projectUUID, key string) (string, string, error) {
	tmpDir, err := os.MkdirTemp("", "vigolium-source-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	zipPath := filepath.Join(tmpDir, "source.zip")
	if err := c.DownloadToFile(ctx, projectUUID, key, zipPath); err != nil {
		os.RemoveAll(tmpDir)
		return "", "", err
	}

	destDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("failed to create extract dir: %w", err)
	}

	if err := extractZip(zipPath, destDir); err != nil {
		os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("failed to extract source zip: %w", err)
	}

	os.Remove(zipPath)
	zap.L().Info("storage: extracted source", zap.String("dir", destDir))
	return destDir, tmpDir, nil
}

// BundleAndUploadResults creates a zip of the given directory and uploads it.
// Returns the storage URL (gs://<project>/<key>).
func (c *Client) BundleAndUploadResults(ctx context.Context, projectUUID, key, sourceDir string) (string, error) {
	tmpFile, err := os.CreateTemp("", "vigolium-results-*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temp zip: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := createZip(tmpFile, sourceDir); err != nil {
		tmpFile.Close()
		return "", fmt.Errorf("failed to create results zip: %w", err)
	}
	tmpFile.Close()

	if err := c.UploadFile(ctx, projectUUID, key, tmpPath); err != nil {
		return "", err
	}

	storageURL := StorageURL(projectUUID, key)
	return storageURL, nil
}

// BundleAndUploadFiles creates a zip of specific files and uploads it.
// filePaths is a map of arcName → localPath.
func (c *Client) BundleAndUploadFiles(ctx context.Context, projectUUID, key string, filePaths map[string]string) (string, error) {
	tmpFile, err := os.CreateTemp("", "vigolium-results-*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temp zip: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	zw := zip.NewWriter(tmpFile)
	for arcName, localPath := range filePaths {
		f, openErr := os.Open(localPath)
		if openErr != nil {
			zap.L().Warn("storage: skipping file for bundle", zap.String("file", localPath), zap.Error(openErr))
			continue
		}
		fw, createErr := zw.Create(arcName)
		if createErr != nil {
			f.Close()
			continue
		}
		_, _ = io.Copy(fw, f)
		f.Close()
	}
	zw.Close()
	tmpFile.Close()

	if err := c.UploadFile(ctx, projectUUID, key, tmpPath); err != nil {
		return "", err
	}

	storageURL := StorageURL(projectUUID, key)
	return storageURL, nil
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fPath := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(fPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fPath, f.Mode())
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fPath), 0755); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func createZip(w io.Writer, sourceDir string) error {
	zw := zip.NewWriter(w)
	defer zw.Close()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			if relPath == "." {
				return nil
			}
			_, err := zw.Create(relPath + "/")
			return err
		}

		fw, err := zw.Create(relPath)
		if err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(fw, f)
		return err
	})
}
