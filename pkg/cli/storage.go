package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
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

// openStorageClient resolves the active project, loads settings, and returns a
// connected storage client. When storage is disabled in config, it prints a tip
// to the user and returns (nil, "", nil) so the caller can bail without error.
func openStorageClient() (*storage.Client, string, error) {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	if !settings.Storage.IsEnabled() {
		fmt.Printf("%s Cloud storage is not enabled.\n", terminal.WarningSymbol())
		fmt.Printf("  Enable with: %s\n", terminal.Cyan("vigolium config set storage.enabled true"))
		fmt.Printf("  Or set env: %s\n", terminal.Cyan(config.StorageEnabledEnvVar+"=true"))
		fmt.Printf("  Then set %s, %s, %s, and %s in your config file.\n",
			terminal.Gray("storage.bucket"),
			terminal.Gray("storage.driver"),
			terminal.Gray("storage.access_key"),
			terminal.Gray("storage.secret_key"))
		return nil, "", nil
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return nil, "", err
	}

	sc, err := storage.NewClient(&settings.Storage)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create storage client: %w", err)
	}
	return sc, projectUUID, nil
}

// requireStorageClient builds a connected storage client, returning a clear
// error if storage is disabled. Use this when storage is not optional (e.g. the
// user passed a gs:// URL); for opt-in commands, use openStorageClient instead.
func requireStorageClient() (*storage.Client, error) {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}
	if !settings.Storage.IsEnabled() {
		return nil, fmt.Errorf("cloud storage is not enabled; enable with: vigolium config set storage.enabled true (or set %s=true)", config.StorageEnabledEnvVar)
	}
	sc, err := storage.NewClient(&settings.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}
	return sc, nil
}

// humanBytes formats a byte count for table display.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n2 := n / unit; n2 >= unit; n2 /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
