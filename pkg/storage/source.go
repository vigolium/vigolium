package storage

import (
	"context"
	"fmt"
	"os"

	"github.com/vigolium/vigolium/internal/config"
)

// ResolveGCSSource downloads and extracts a gs://<project>/<key> archive into
// a temp directory. The returned cleanup must be invoked once the run is done
// to remove the temp tree. When projectUUID is empty, it falls back to the
// project component parsed from the URI.
func ResolveGCSSource(storageCfg *config.StorageConfig, sourcePath, projectUUID string) (extractedPath string, cleanup func(), err error) {
	noop := func() {}

	if !storageCfg.IsEnabled() {
		return "", noop, fmt.Errorf("storage is not enabled in config — cannot download gs:// source")
	}

	sc, err := NewClient(storageCfg)
	if err != nil {
		return "", noop, fmt.Errorf("create storage client: %w", err)
	}

	sourcePath = StripBucketPrefix(sourcePath, storageCfg.Bucket)
	gcsProject, key, err := ParseGCSPath(sourcePath)
	if err != nil {
		return "", noop, err
	}
	if projectUUID == "" {
		projectUUID = gcsProject
	}

	extracted, tmpRoot, err := sc.DownloadAndExtractSource(context.Background(), projectUUID, key)
	if err != nil {
		return "", noop, fmt.Errorf("download source from storage: %w", err)
	}

	return extracted, func() { _ = os.RemoveAll(tmpRoot) }, nil
}
