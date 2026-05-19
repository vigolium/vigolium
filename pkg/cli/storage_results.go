package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var storageResultsCmd = &cobra.Command{
	Use:   "results <scan-uuid>",
	Short: "Download the result bundle for a scan",
	Long:  "Download the results.tar.gz for a native or agentic scan run. Tries native-scans/<uuid> first, then agentic-scans/<uuid>, matching GET /api/storage/results/:scan-uuid.",
	Args:  cobra.ExactArgs(1),
	RunE:  runStorageResults,
}

func init() {
	storageResultsCmd.Flags().StringP("output", "o", "", "Write to this file (default: results-<uuid>.tar.gz in cwd)")
	storageCmd.AddCommand(storageResultsCmd)
}

func runStorageResults(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}
	if sc == nil {
		return nil
	}

	scanUUID := args[0]
	if _, err := storage.ValidateKey(scanUUID); err != nil {
		return fmt.Errorf("invalid scan UUID: %w", err)
	}

	output, _ := cmd.Flags().GetString("output")
	if output == "" {
		output = fmt.Sprintf("results-%s.tar.gz", scanUUID)
	}

	keys := []string{
		storage.NativeScanResultKey(scanUUID),
		storage.AgenticScanResultKey(scanUUID),
	}

	var lastErr error
	for _, key := range keys {
		reader, err := sc.Download(context.Background(), projectUUID, key)
		if err != nil {
			lastErr = err
			continue
		}
		defer func() { _ = reader.Close() }()

		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", output, err)
		}
		if _, err := io.Copy(f, reader); err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to write %s: %w", output, err)
		}
		if err := f.Close(); err != nil {
			return err
		}

		abs, _ := filepath.Abs(output)
		fmt.Fprintf(os.Stderr, "%s Downloaded %s → %s\n",
			terminal.SuccessSymbol(), terminal.Cyan(key), terminal.Gray(abs))
		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("not found")
	}
	return fmt.Errorf("no results found for scan %s: %w", scanUUID, lastErr)
}
