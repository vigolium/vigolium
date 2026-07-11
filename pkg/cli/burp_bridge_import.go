package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func importBurpTrafficToDB(
	ctx context.Context,
	repo *database.Repository,
	bridgeURL string,
	query burpbridge.Query,
	projectUUID string,
) (burpbridge.ImportResult, error) {
	client, err := burpbridge.New(bridgeURL)
	if err != nil {
		return burpbridge.ImportResult{}, err
	}
	return burpbridge.ImportIntoRepository(ctx, client, repo, query, projectUUID)
}

func writeBurpImportResult(
	w io.Writer,
	bridgeURL string,
	result burpbridge.ImportResult,
	jsonOutput bool,
) {
	if jsonOutput {
		output := struct {
			Source    string `json:"source"`
			BridgeURL string `json:"bridge_url"`
			burpbridge.ImportResult
		}{Source: burpbridge.Source, BridgeURL: bridgeURL, ImportResult: result}
		_ = json.NewEncoder(w).Encode(output)
		return
	}
	_, _ = fmt.Fprintf(w, "%s Imported Burp traffic: %d selected, %d inserted, %d updated, %d unchanged",
		terminal.SuccessSymbol(), result.Selected, result.Inserted, result.Updated, result.Unchanged)
	if result.Skipped > 0 {
		_, _ = fmt.Fprintf(w, ", %d skipped", result.Skipped)
	}
	_, _ = fmt.Fprintln(w)
	if result.Oversized > 0 {
		_, _ = fmt.Fprintf(w, "  %s %d record(s) exceeded the %d MiB per-message safety limit and were not imported\n",
			terminal.WarningSymbol(), result.Oversized, burpbridge.MaxImportBytes/(1024*1024))
	}
	for _, message := range result.Errors {
		_, _ = fmt.Fprintf(w, "  %s %s\n", terminal.WarningSymbol(), message)
	}
}

func writeBurpSiteMapSaveResult(w io.Writer, result burpbridge.SiteMapSaveResult) {
	_, _ = fmt.Fprintf(w, "%s Saved Vigolium traffic to Burp Site map: %d selected, %d added",
		terminal.SuccessSymbol(), result.Selected, result.Added)
	if result.Skipped > 0 {
		_, _ = fmt.Fprintf(w, ", %d skipped", result.Skipped)
	}
	_, _ = fmt.Fprintln(w)
	for _, message := range result.Errors {
		_, _ = fmt.Fprintf(w, "  %s %s\n", terminal.WarningSymbol(), message)
	}
}
