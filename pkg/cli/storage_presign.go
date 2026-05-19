package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var storagePresignCmd = &cobra.Command{
	Use:   "presign",
	Short: "Generate a presigned upload or download URL",
	Long:  "Generate a presigned URL for direct GET (download) or PUT (upload) against the active project's storage. Mirrors POST /api/storage/presign.",
	RunE:  runStoragePresign,
}

func init() {
	storagePresignCmd.Flags().String("key", "", "Object key (required)")
	storagePresignCmd.Flags().String("method", "GET", "HTTP method: GET or PUT")
	storagePresignCmd.Flags().Duration("expiry", time.Hour, "URL validity duration (e.g. 30m, 1h, 24h)")
	storagePresignCmd.Flags().Bool("json", false, "Output as JSON")
	_ = storagePresignCmd.MarkFlagRequired("key")
	storageCmd.AddCommand(storagePresignCmd)
}

func runStoragePresign(cmd *cobra.Command, _ []string) error {
	defer closeDatabaseOnExit()

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}
	if sc == nil {
		return nil
	}

	key, _ := cmd.Flags().GetString("key")
	methodFlag, _ := cmd.Flags().GetString("method")
	expiry, _ := cmd.Flags().GetDuration("expiry")
	jsonOut, _ := cmd.Flags().GetBool("json")

	method := strings.ToUpper(methodFlag)
	var url string
	switch method {
	case "GET":
		url, err = sc.PresignedGetURL(context.Background(), projectUUID, key, expiry)
	case "PUT":
		url, err = sc.PresignedPutURL(context.Background(), projectUUID, key, expiry)
	default:
		return fmt.Errorf("invalid --method %q: must be GET or PUT", methodFlag)
	}
	if err != nil {
		return err
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"url":            url,
			"key":            key,
			"method":         method,
			"expiry_seconds": int(expiry.Seconds()),
		})
	}

	fmt.Printf("%s Presigned %s URL (valid %s):\n", terminal.SuccessSymbol(), method, expiry)
	fmt.Println(url)
	return nil
}
