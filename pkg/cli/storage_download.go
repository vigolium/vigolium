package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var storageDownloadCmd = &cobra.Command{
	Use:     "download <key>",
	Aliases: []string{"get"},
	Short:   "Download an object from cloud storage",
	Long:    "Download an object from the active project's storage by full key (e.g. ugc/foo.tar.gz). Streams to stdout by default; use -o to write to a file.",
	Args:    cobra.ExactArgs(1),
	RunE:    runStorageDownload,
}

func init() {
	storageDownloadCmd.Flags().StringP("output", "o", "", "Write to this file instead of stdout")
	storageCmd.AddCommand(storageDownloadCmd)
}

func runStorageDownload(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}
	if sc == nil {
		return nil
	}

	key := args[0]
	output, _ := cmd.Flags().GetString("output")

	if output != "" {
		if err := sc.DownloadToFile(context.Background(), projectUUID, key, output); err != nil {
			return err
		}
		abs, _ := filepath.Abs(output)
		fmt.Fprintf(os.Stderr, "%s Downloaded %s → %s\n",
			terminal.SuccessSymbol(), terminal.Cyan(key), terminal.Gray(abs))
		return nil
	}

	reader, err := sc.Download(context.Background(), projectUUID, key)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	_, err = io.Copy(os.Stdout, reader)
	return err
}
