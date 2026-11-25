package burpbridge

import (
	"context"
	"fmt"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const importBatchSize = 200

// RecordUpserter is the database operation needed by the bridge importer.
// database.Repository implements it directly.
type RecordUpserter interface {
	UpsertCapturedRecord(context.Context, *httpmsg.HttpRequestResponse, string, string, database.Capture) (string, string, error)
}

type ImportResult struct {
	// Source is the http_records.source label written to every stored row —
	// the vendor the listener reported. Surfaced so the CLI can name what it
	// imported from instead of assuming Burp.
	Source    string   `json:"source"`
	Matched   int64    `json:"matched"`
	Selected  int      `json:"selected"`
	Inserted  int      `json:"inserted"`
	Updated   int      `json:"updated"`
	Unchanged int      `json:"unchanged"`
	Skipped   int      `json:"skipped"`
	Oversized int      `json:"oversized"`
	Errors    []string `json:"errors,omitempty"`
}

func (r ImportResult) Stored() int { return r.Inserted + r.Updated + r.Unchanged }

// ImportIntoRepository copies the selected live Proxy history into the
// database. It pages the listener so temporary refs remain inspectable, and
// uses the snapshot upsert path so repeated imports are idempotent while a
// changed response refreshes the existing row.
//
// Each stored row's sent_at is the capture time the listener reported for it
// (the search summary's time), not the time of the import; created_at stays
// the insert time. scanUUID ("" for none) is stamped on every new row: the
// importing invocation's scans row.
func ImportIntoRepository(
	ctx context.Context,
	client *Client,
	repo RecordUpserter,
	query Query,
	projectUUID string,
	scanUUID string,
) (ImportResult, error) {
	result := ImportResult{Source: Source}
	query.ProjectUUID = projectUUID
	query.IncludeRaw = false
	if query.Location == "" {
		query.Location = "proxy_history"
	}

	nextOffset := max(query.Offset, 0)
	remaining := query.Limit
	for {
		pageSize := importBatchSize
		if remaining > 0 {
			pageSize = min(pageSize, remaining)
		}
		pageQuery := query
		pageQuery.Offset = nextOffset
		pageQuery.Limit = pageSize
		page, err := client.Query(ctx, pageQuery)
		if err != nil {
			return result, err
		}
		if result.Matched == 0 {
			result.Matched = page.Total
		}
		result.Source = page.Source
		if len(page.Records) == 0 {
			break
		}

		for _, summary := range page.Records {
			result.Selected++
			inspection, err := client.InspectWithLimit(ctx, summary.UUID, projectUUID, MaxImportBytes)
			if err != nil {
				result.Skipped++
				result.addError(fmt.Sprintf("%s: %v", summary.URL, err))
				continue
			}
			if inspection.RequestTruncated || inspection.ResponseTruncated {
				result.Skipped++
				result.Oversized++
				continue
			}
			rr, err := database.RecordToHttpRequestResponse(inspection.Record)
			if err != nil {
				result.Skipped++
				result.addError(fmt.Sprintf("%s: %v", summary.URL, err))
				continue
			}
			// Label the persisted row with the vendor that actually answered.
			// The inspect reply is preferred over the page's because it is the
			// reply this row came from; both fall back to Burp identically, so
			// a listener that reports nothing still writes what it always did.
			_, outcome, err := repo.UpsertCapturedRecord(ctx, rr, inspection.Source(), projectUUID,
				database.Capture{SentAt: summary.SentAt, ScanUUID: scanUUID})
			if err != nil {
				return result, fmt.Errorf("store bridge record %s: %w", summary.URL, err)
			}
			switch outcome {
			case "inserted":
				result.Inserted++
			case "updated":
				result.Updated++
			default:
				result.Unchanged++
			}
		}

		count := len(page.Records)
		nextOffset += count
		if remaining > 0 {
			remaining -= count
			if remaining <= 0 {
				break
			}
		}
		if page.Total > 0 && int64(nextOffset) >= page.Total {
			break
		}
	}
	return result, nil
}

func (r *ImportResult) addError(message string) {
	if len(r.Errors) < 10 {
		r.Errors = append(r.Errors, message)
	}
}
