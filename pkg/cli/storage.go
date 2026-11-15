package cli

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/apicontract"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/storage"
)

var storageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Interact with cloud object storage (uploads, downloads, presigned URLs)",
	Long: `Manage cloud-storage objects for the active project. Mirrors the REST endpoints under /api/storage/.

Subcommands: ls, upload, download, results, presign.

Requires storage.enabled: true in vigolium-configs.yaml together with driver, bucket,
access_key, and secret_key.`,
}

func init() {
	rootCmd.AddCommand(storageCmd)
}

// openStorageClient builds a connected storage client and resolves the active
// project. Every storage subcommand explicitly requests storage, so a disabled
// configuration is an error (nonzero exit) rather than a silent success —
// automation must be able to tell "listed nothing" from "storage was off". The
// disabled-storage error and client construction are shared with
// requireStorageClient; this variant additionally resolves the project UUID.
func openStorageClient() (*storage.Client, string, error) {
	sc, err := requireStorageClient()
	if err != nil {
		return nil, "", err
	}
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return nil, "", err
	}
	return sc, projectUUID, nil
}

// requireStorageClient builds a connected storage client, returning a clear
// error (with remediation) if storage is disabled. Used both for the opt-in
// storage subcommands (via openStorageClient) and where storage is mandatory
// (e.g. the user passed a gs:// URL).
func requireStorageClient() (*storage.Client, error) {
	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return nil, err
	}
	if !settings.Storage.IsEnabled() {
		return nil, codedErrorf(apicontract.CodeStorageDisabled, "cloud storage is not enabled; enable with `vigolium config set storage.enabled true` "+
			"(or set %s=true), then set storage.driver, storage.bucket, storage.access_key, and storage.secret_key",
			config.StorageEnabledEnvVar)
	}
	sc, err := storage.NewClient(&settings.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}
	return sc, nil
}
