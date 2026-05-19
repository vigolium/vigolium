package storage

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
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
	// SchemeGCS is the canonical Google Cloud Storage URI scheme used by
	// gsutil and emitted by every URL we generate (StorageURL, exports, etc.).
	SchemeGCS = "gs://"
	// SchemeGCSAlias is accepted on input as a synonym for SchemeGCS so users
	// who type "gcs://" (the service abbreviation) get the same behavior.
	// Output is always normalized to SchemeGCS.
	SchemeGCSAlias    = "gcs://"
	PathNativeScans   = "native-scans"
	PathAgenticScans  = "agentic-scans"
	PathUGC           = "ugc"
	ResultsBundleName = "results.tar.gz"
)

// IsGCSURI reports whether s starts with the canonical SchemeGCS prefix or the
// SchemeGCSAlias synonym. Use this instead of strings.HasPrefix(s, "gs://")
// at any user-input boundary so "gcs://" works interchangeably.
func IsGCSURI(s string) bool {
	return strings.HasPrefix(s, SchemeGCS) || strings.HasPrefix(s, SchemeGCSAlias)
}

// NormalizeGCSURI rewrites a "gcs://" prefix to "gs://" so downstream code
// can keep matching a single canonical form. URIs that already use the
// canonical prefix (or neither) are returned unchanged.
func NormalizeGCSURI(s string) string {
	if strings.HasPrefix(s, SchemeGCSAlias) {
		return SchemeGCS + strings.TrimPrefix(s, SchemeGCSAlias)
	}
	return s
}

// StripBucketPrefix collapses gsutil-style "gs://<bucket>/<rest>" URIs to the
// project-relative "gs://<rest>" form expected by ParseGCSPath. The console's
// upload path emits gs://<bucket>/<projectUUID>/<key> (lib/storage-shared.ts),
// while ParseGCSPath expects gs://<projectUUID>/<key>; without this collapse
// the two layers disagree on whether the first segment is the bucket or the
// project. URIs whose first segment doesn't match bucket — and non-gs:// URIs
// — are returned unchanged.
func StripBucketPrefix(uri, bucket string) string {
	if bucket == "" || !IsGCSURI(uri) {
		return uri
	}
	canonical := NormalizeGCSURI(uri)
	rest := strings.TrimPrefix(canonical, SchemeGCS)
	first, remainder, ok := strings.Cut(rest, "/")
	if !ok || first != bucket {
		return uri
	}
	return SchemeGCS + remainder
}

// NativeScanResultKey returns the storage key for a native scan result bundle.
func NativeScanResultKey(scanUUID string) string {
	return fmt.Sprintf("%s/%s/%s", PathNativeScans, scanUUID, ResultsBundleName)
}

// AgenticScanResultKey returns the storage key for an agentic scan result bundle.
func AgenticScanResultKey(agenticScanUUID string) string {
	return fmt.Sprintf("%s/%s/%s", PathAgenticScans, agenticScanUUID, ResultsBundleName)
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
	if err := ValidateProjectUUID(projectUUID); err != nil {
		return nil, fmt.Errorf("invalid project UUID %q: %w", projectUUID, err)
	}
	var fullPrefix string
	if prefix == "" {
		fullPrefix = projectUUID + "/"
	} else {
		cleanPrefix, err := ValidateKey(prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid storage prefix %q: %w", prefix, err)
		}
		fullPrefix = projectUUID + "/" + cleanPrefix
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

// Exists reports whether the object at projectUUID/key is present in the
// bucket. minio's GetObject is lazy and only fails on first Read, so callers
// that want to fall back to a different key on miss should probe with Exists
// first instead of relying on Download error handling.
func (c *Client) Exists(ctx context.Context, projectUUID, key string) (bool, error) {
	objKey, err := objectKey(projectUUID, key)
	if err != nil {
		return false, err
	}
	_, err = c.mc.StatObject(ctx, c.bucket, objKey, minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	if errResp := minio.ToErrorResponse(err); errResp.StatusCode == 404 || errResp.Code == "NoSuchKey" {
		return false, nil
	}
	return false, fmt.Errorf("failed to stat %s: %w", objKey, err)
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
// The "gcs://" alias is accepted and normalized to the canonical "gs://" form
// before parsing. Returns empty strings if the URI doesn't match the expected format.
func ParseGCSPath(uri string) (projectUUID, key string, err error) {
	uri = NormalizeGCSURI(uri)
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

// DownloadAndExtractSource downloads an archive from storage and extracts it to
// a temp directory. The format is dispatched off the key's extension to match
// the formats the console upload route accepts (zip, tar.gz/tgz, tar).
// Returns the path to the extracted source and the temp root directory.
// Callers should defer os.RemoveAll(tmpRoot) to clean up.
func (c *Client) DownloadAndExtractSource(ctx context.Context, projectUUID, key string) (string, string, error) {
	tmpDir, err := os.MkdirTemp("", "vigolium-source-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	ext := archiveExt(key)
	archivePath := filepath.Join(tmpDir, "source"+ext)
	if err := c.DownloadToFile(ctx, projectUUID, key, archivePath); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", err
	}

	destDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("failed to create extract dir: %w", err)
	}

	if err := extractArchive(archivePath, destDir, ext); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", "", fmt.Errorf("failed to extract source archive: %w", err)
	}

	_ = os.Remove(archivePath)
	zap.L().Info("storage: extracted source", zap.String("dir", destDir))
	return destDir, tmpDir, nil
}

// archiveExt returns the canonical archive extension for a storage key. The
// console upload route classifies uploads into .zip / .tar.gz (incl. .tgz) /
// .tar; matching that set here keeps the download/extract path symmetrical.
// Unknown extensions fall through to .tar.gz to preserve historical behavior.
func archiveExt(key string) string {
	lower := strings.ToLower(key)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return ".tar.gz"
	case strings.HasSuffix(lower, ".zip"):
		return ".zip"
	case strings.HasSuffix(lower, ".tar"):
		return ".tar"
	}
	return ".tar.gz"
}

func extractArchive(archivePath, destDir, ext string) error {
	switch ext {
	case ".zip":
		return extractZip(archivePath, destDir)
	case ".tar":
		return extractTar(archivePath, destDir)
	default:
		return extractTarGz(archivePath, destDir)
	}
}

// BundleAndUploadResults creates a tar.gz of the given directory and uploads it.
func (c *Client) BundleAndUploadResults(ctx context.Context, projectUUID, key, sourceDir string) (string, error) {
	tmpFile, err := os.CreateTemp("", "vigolium-results-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("failed to create temp archive: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := createTarGz(tmpFile, sourceDir); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("failed to create results archive: %w", err)
	}
	_ = tmpFile.Close()

	if err := c.UploadFile(ctx, projectUUID, key, tmpPath); err != nil {
		return "", err
	}

	return StorageURL(projectUUID, key), nil
}

// BundleAndUploadFiles creates a tar.gz of specific files and uploads it.
// filePaths is a map of arcName → localPath.
func (c *Client) BundleAndUploadFiles(ctx context.Context, projectUUID, key string, filePaths map[string]string) (string, error) {
	tmpFile, err := os.CreateTemp("", "vigolium-results-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("failed to create temp archive: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	gw := gzip.NewWriter(tmpFile)
	tw := tar.NewWriter(gw)
	for arcName, localPath := range filePaths {
		f, openErr := os.Open(localPath)
		if openErr != nil {
			zap.L().Warn("storage: skipping file for bundle", zap.String("file", localPath), zap.Error(openErr))
			continue
		}
		info, statErr := f.Stat()
		if statErr != nil {
			_ = f.Close()
			continue
		}
		hdr := &tar.Header{
			Name: arcName,
			Size: info.Size(),
			Mode: int64(info.Mode()),
		}
		if writeErr := tw.WriteHeader(hdr); writeErr != nil {
			_ = f.Close()
			continue
		}
		_, _ = io.Copy(tw, f)
		_ = f.Close()
	}
	_ = tw.Close()
	_ = gw.Close()
	_ = tmpFile.Close()

	if err := c.UploadFile(ctx, projectUUID, key, tmpPath); err != nil {
		return "", err
	}

	return StorageURL(projectUUID, key), nil
}

func extractTarGz(archivePath, destDir string) error {
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

	return extractTarStream(tar.NewReader(gr), destDir)
}

func extractTar(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return extractTarStream(tar.NewReader(f), destDir)
}

func extractTarStream(tr *tar.Reader, destDir string) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		fPath := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(fPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in archive: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(fPath, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(fPath), 0755); err != nil {
				return err
			}
			outFile, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				_ = outFile.Close()
				return err
			}
			_ = outFile.Close()
		}
	}
	return nil
}

func extractZip(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()

	cleanDest := filepath.Clean(destDir) + string(os.PathSeparator)
	for _, f := range r.File {
		fPath := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(fPath, cleanDest) {
			return fmt.Errorf("illegal file path in archive: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fPath, f.Mode()); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fPath), 0755); err != nil {
			return err
		}
		out, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			_ = out.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			_ = out.Close()
			_ = rc.Close()
			return err
		}
		_ = out.Close()
		_ = rc.Close()
	}
	return nil
}

func createTarGz(w io.Writer, sourceDir string) error {
	gw := gzip.NewWriter(w)
	defer func() { _ = gw.Close() }()
	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = relPath

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
