package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `finding --curl` renders the request that proves each selected finding as a
// curl command; `--curl-all` renders every linked record. Nothing is sent.

var (
	findingCurl       bool
	findingCurlAll    bool
	findingRedactAuth bool
)

func init() {
	// Registered here rather than in finding.go's init: findingCmd is a
	// package-level value, so its flag set exists before any init runs.
	f := findingCmd.Flags()
	f.BoolVar(&findingCurl, "curl", false, "Render each selected finding's proving request (its stored evidence, else its first linked record) as a curl command; -j gives {id, finding_hash, record_uuid, curl, argv}")
	f.BoolVar(&findingCurlAll, "curl-all", false, "Like --curl, but render every HTTP record linked to each finding")
	f.BoolVar(&findingRedactAuth, "redact-auth", false, "With --curl/--curl-all: replace Authorization/Cookie/API-key header values with <redacted>")
}

// findingCurlConflicts are the finding modes --curl cannot be combined with.
var findingCurlConflicts = []string{"raw", "burp", "markdown", "tree", "tui", "push-to-burp", "to-repeater", "with-records"}

// validateFindingCurlFlags rejects what is knowable from the flags alone.
func validateFindingCurlFlags(cmd *cobra.Command) error {
	if !findingCurl && !findingCurlAll {
		if findingRedactAuth {
			return usageErrorf("--redact-auth only applies with --curl or --curl-all")
		}
		return nil
	}
	for _, name := range findingCurlConflicts {
		if flagOn(cmd, name) {
			return usageErrorf("--curl cannot be combined with --%s: one renders curl commands, the other a different view of the findings", name)
		}
	}
	return nil
}

// renderFindingCurl renders the selected findings' requests.
func renderFindingCurl(ctx context.Context, cmd *cobra.Command, db *database.DB, findings []*database.Finding, total int64, projectUUID string) error {
	byUUID := loadFindingRecordsOrWarn(ctx, db, findings)
	items := make([]curlItem, 0, len(findings))
	var skipped []int64
	for _, f := range findings {
		var rendered []curlItem
		if findingCurlAll {
			rendered = findingRecordCurls(f, byUUID)
			if len(rendered) == 0 {
				if it, ok := findingEvidenceCurl(f); ok {
					rendered = append(rendered, it)
				}
			}
		} else if it, ok := findingEvidenceCurl(f); ok {
			rendered = append(rendered, it)
		} else if all := findingRecordCurls(f, byUUID); len(all) > 0 {
			rendered = all[:1]
		}
		if len(rendered) == 0 {
			skipped = append(skipped, f.ID)
			continue
		}
		for i := range rendered {
			rendered[i].ID = f.ID
			rendered[i].FindingHash = f.FindingHash
		}
		items = append(items, rendered...)
	}
	noteCurlCredentials(items)
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "%s %d finding(s) have no stored request to render: %v\n",
			terminal.WarningSymbol(), len(skipped), skipped)
	}

	if globalJSON {
		opts := []envOpt{
			withProjectScope(projectUUID),
			withDBPath(resolvedReadDBPath()),
			withExtra("findings_total", total),
			withExtra("skipped", len(skipped)),
			withExtra("redacted", findingRedactAuth),
		}
		if len(items) > 0 {
			opts = append(opts, withQuery("finding", "--id", fmt.Sprint(items[0].ID), "--json", "--with-records"))
		}
		return emitRead(cmd, "", items, int64(len(items)), 0, len(items), opts...)
	}
	if len(items) == 0 {
		fmt.Fprintf(os.Stderr, "%s No finding requests to render.\n", terminal.InfoSymbol())
		return nil
	}
	printCurlItems(items, func(it curlItem) string {
		label := fmt.Sprintf("finding #%d", it.ID)
		if it.RecordUUID != "" {
			label += " record " + it.RecordUUID
		}
		return label
	})
	return nil
}

// findingEvidenceCurl renders the request stored on the finding itself — the
// one the module sent when it proved the issue.
func findingEvidenceCurl(f *database.Finding) (curlItem, bool) {
	if strings.TrimSpace(f.Request) == "" {
		return curlItem{}, false
	}
	target := findingURLValue(f)
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return curlItem{}, false
	}
	raw := []byte(f.Request)
	cmd, err := httpmsg.ToCurl(raw, u.Scheme+"://"+u.Host, httpmsg.CurlOptions{RedactAuth: findingRedactAuth})
	if err != nil {
		return curlItem{}, false
	}
	method, _ := httpmsg.GetMethod(raw)
	return curlItemFrom(cmd, method, cmd.Argv[len(cmd.Argv)-1]), true
}

// findingRecordCurls renders every linked record that holds a request.
func findingRecordCurls(f *database.Finding, byUUID map[string]*database.HTTPRecord) []curlItem {
	var out []curlItem
	for _, rec := range recordsForFinding(byUUID, f) {
		if len(rec.RawRequest) == 0 {
			continue
		}
		it, err := recordCurl(rec, findingRedactAuth || jsonRedactOn)
		if err != nil {
			continue
		}
		it.RecordUUID = rec.UUID
		out = append(out, it)
	}
	return out
}
