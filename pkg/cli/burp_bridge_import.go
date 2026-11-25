package cli

import (
	"context"
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
	// The invocation's scans row (--caller-tag lands on it), stamped on every
	// row the import inserts.
	scanUUID := newInvocationScanRow(invocationScanImport).ensure(ctx, repo, projectUUID, bridgeURL)
	return burpbridge.ImportIntoRepository(ctx, client, repo, query, projectUUID, scanUUID)
}

// burpImportResultJSON builds the -j document for a live-bridge import.
//
// ImportResult already carries the resolved source, so it is not restated here
// — one `source` key, written from the vendor that actually answered rather
// than from a compile-time constant.
func burpImportResultJSON(bridgeURL string, result burpbridge.ImportResult) any {
	return struct {
		BridgeURL string `json:"bridge_url"`
		burpbridge.ImportResult
	}{BridgeURL: bridgeURL, ImportResult: result}
}

// writeBurpImportResult renders the human summary of a live-bridge import. The
// -j document is built by burpImportResultJSON and written through the shared
// stdout encoder, which is also what latches the one-document contract.
func writeBurpImportResult(w io.Writer, result burpbridge.ImportResult) {
	_, _ = fmt.Fprintf(w, "%s Imported %s traffic: %d selected, %d inserted, %d updated, %d unchanged",
		terminal.SuccessSymbol(), burpbridge.VendorNameForSource(result.Source),
		result.Selected, result.Inserted, result.Updated, result.Unchanged)
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
