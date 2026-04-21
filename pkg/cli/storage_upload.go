package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

func uploadNativeScanResults(settings *config.Settings, opts *types.Options, repo *database.Repository) {
	if !opts.UploadResults {
		return
	}
	if !settings.Storage.IsEnabled() {
		zap.L().Warn("--upload-results specified but storage is not enabled in config")
		return
	}

	sc, err := storage.NewClient(&settings.Storage)
	if err != nil {
		zap.L().Warn("Failed to create storage client for result upload", zap.Error(err))
		return
	}

	files := make(map[string]string)
	if opts.Output != "" {
		for _, format := range opts.OutputFormats {
			path := opts.OutputPathForFormat(format)
			arcName := filepath.Base(path)
			files[arcName] = path
		}
	}

	// Include the native scan's runtime.log when persist_logs is enabled and
	// the file exists on disk for this scan.
	runtimeLog := filepath.Join(
		settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(),
		opts.ScanUUID,
		config.RuntimeLogFilename,
	)
	if fi, err := os.Stat(runtimeLog); err == nil && !fi.IsDir() {
		files[config.RuntimeLogFilename] = runtimeLog
	}

	if len(files) == 0 {
		zap.L().Info("storage: no result files to upload")
		return
	}

	key := storage.NativeScanResultKey(opts.ScanUUID)
	storageURL, err := sc.BundleAndUploadFiles(context.Background(), opts.ProjectUUID, key, files)
	if err != nil {
		zap.L().Warn("Failed to upload scan results", zap.Error(err))
		return
	}

	if repo != nil {
		if updateErr := repo.UpdateScanStorageURL(context.Background(), opts.ScanUUID, storageURL); updateErr != nil {
			zap.L().Warn("Failed to update scan storage URL", zap.Error(updateErr))
		}
	}

	fmt.Fprintf(os.Stderr, "  %s Results uploaded to %s\n", terminal.SuccessSymbol(), terminal.Gray(storageURL))
}

func uploadAgenticScanResults(settings *config.Settings, projectUUID, runID, sessionDir string, repo *database.Repository) {
	if !settings.Storage.IsEnabled() {
		zap.L().Warn("--upload-results specified but storage is not enabled in config")
		return
	}

	if sessionDir == "" {
		return
	}

	sc, err := storage.NewClient(&settings.Storage)
	if err != nil {
		zap.L().Warn("Failed to create storage client for result upload", zap.Error(err))
		return
	}

	key := storage.AgenticScanResultKey(runID)
	storageURL, err := sc.BundleAndUploadResults(context.Background(), projectUUID, key, sessionDir)
	if err != nil {
		zap.L().Warn("Failed to upload agentic scan results", zap.Error(err))
		return
	}

	if repo != nil {
		if updateErr := repo.UpdateAgenticScanStorageURL(context.Background(), runID, storageURL); updateErr != nil {
			zap.L().Warn("Failed to update agentic scan storage URL", zap.Error(updateErr))
		}
	}

	fmt.Fprintf(os.Stderr, "  %s Results uploaded to %s\n", terminal.SuccessSymbol(), terminal.Gray(storageURL))
}
