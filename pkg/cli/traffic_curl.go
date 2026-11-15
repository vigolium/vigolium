package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// trafficCurlConflicts are the traffic modes --curl cannot be combined with:
// each renders (or sends, or stores) the records some other way.
var trafficCurlConflicts = []string{
	"replay", "raw", "burp", "markdown", "tree", "tui", "group-by",
	"save-to-burp", "save-to-vigolium-db",
}

// validateTrafficCurlFlags rejects what is knowable from the flags alone.
func validateTrafficCurlFlags(cmd *cobra.Command) error {
	if !trafficCurl {
		if trafficRedactAuth {
			return usageErrorf("--redact-auth only applies with --curl")
		}
		return nil
	}
	for _, name := range trafficCurlConflicts {
		if flagOn(cmd, name) {
			return usageErrorf("--curl cannot be combined with --%s: one renders curl commands, the other a different view of the records", name)
		}
	}
	return nil
}

// renderTrafficCurl prints the matched records as curl commands, or under -j
// an envelope of {uuid, method, url, curl, argv} items. Records that cannot be
// rendered (no stored request) are reported, not silently dropped.
func renderTrafficCurl(cmd *cobra.Command, records []*database.HTTPRecord, total int64, extra []envOpt) error {
	if err := checkCurlCount(len(records), trafficAll, "records"); err != nil {
		return err
	}
	items := make([]curlItem, 0, len(records))
	var skipped []string
	for _, rec := range records {
		it, err := recordCurl(rec, trafficRedactAuth || jsonRedactOn)
		if err != nil {
			skipped = append(skipped, rec.UUID)
			continue
		}
		it.UUID = rec.UUID
		items = append(items, it)
	}
	noteCurlCredentials(items)
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "%s %d record(s) have no stored request to render: %s\n",
			terminal.WarningSymbol(), len(skipped), strings.Join(skipped, ", "))
	}

	if globalJSON {
		projectUUID, err := effectiveProjectUUID()
		if err != nil {
			return err
		}
		opts := append([]envOpt{
			withProjectScope(projectUUID),
			withDBPath(resolvedReadDBPath()),
			withExtra("skipped", len(skipped)),
			withExtra("redacted", trafficRedactAuth),
		}, extra...)
		if len(items) > 0 {
			opts = append(opts, withQuery("traffic", "--uuid", items[0].UUID, "--json", "--full-body"))
		}
		return emitRead(cmd, "", items, total, trafficOffset, trafficLimit, opts...)
	}
	if len(items) == 0 {
		fmt.Fprintf(os.Stderr, "%s No HTTP records to render.\n", terminal.InfoSymbol())
		return nil
	}
	printCurlItems(items, func(it curlItem) string { return it.UUID })
	return nil
}
