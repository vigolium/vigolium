package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// replayBulkRequested reports whether the positional search term or any
// bulk-selection flag switched replay into "iterate the matching stored records"
// mode. A fuzzy term, --all, or any record filter triggers it; the single-source
// flags (--record-uuid/--finding-id/--input) stay in single mode.
func replayBulkRequested(fuzzy string) bool {
	return replayAll ||
		fuzzy != "" ||
		replayBulkHost != "" ||
		len(replayBulkMethods) > 0 ||
		len(replayBulkStatus) > 0 ||
		replayBulkPath != "" ||
		replayBulkSource != "" ||
		len(replayBulkSearch) > 0 ||
		replayBulkHeaderSearch != "" ||
		replayBulkBody != "" ||
		len(replayBulkExclude) > 0 ||
		replayBulkExcludeHeader != "" ||
		replayBulkExcludeBody != "" ||
		replayBulkFrom != "" ||
		replayBulkTo != ""
}

// runReplayBulk re-sends every stored record matching the bulk filters through
// the replay diff engine, concurrently. Each record is re-sent verbatim.
// Where the results go is the plan's call (streamOutputPlan): per-record diff
// tables, a JSONL stream (one replayOutput per record) to stdout or --output,
// and/or one -j envelope with every record as a row, written once the batch is
// done. cmd names the envelope's command (`replay`, or `traffic` for the
// --replay shortcut).
func runReplayBulk(ctx context.Context, cmd *cobra.Command, rr *replayRun, filters database.QueryFilters, plan streamOutputPlan) error {
	if replayRecordUUID != "" || replayFindingID > 0 || replayInput != "" || replayInputFile != "" {
		return fmt.Errorf("bulk selection (a positional search term or --all/--host/--method/--status/--path/--source/--search/--body/--exclude-search/--exclude-body/--from/--to) can't be combined with --record-uuid/--finding-id/--input")
	}

	// Bulk replay re-sends the stored requests, so a --glob-db merge must keep
	// the bodies.
	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		return fmt.Errorf("bulk replay requires database access: %w", err)
	}

	// Selection goes through the shared traffic path so bulk replay sees the
	// same records `vigolium traffic` lists — including live Burp Proxy history
	// merged in when -B/--burp-bridge-url is set. Replay re-sends the stored
	// request bytes, so the raw columns are always fetched.
	records, err := selectTrafficRecords(ctx, db, filters, true, replayBurpBridgeURL)
	if err != nil {
		return fmt.Errorf("query records: %w", err)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "No matching records to replay.")
		if plan.envelope {
			return emitReplayBulkEnvelope(cmd, nil)
		}
		return nil
	}

	// The static --header overlay is host-independent, so parse it once here
	// rather than per record. When --auth-session is set the overlay also needs
	// a per-host auth merge, which recordEntry resolves per record.
	staticOverlay, err := parseReplayHeaderFlags()
	if err != nil {
		return err
	}

	concurrency := replayConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	via := "the diff engine"
	if rr.withBrowser {
		via = "a browser"
	}
	fmt.Fprintf(os.Stderr, "%s Replaying %d record(s) through %s (concurrency %d)...\n",
		terminal.InfoSymbol(), len(records), via, concurrency)

	// JSONL sink. One object per line keeps each entry the existing stable
	// replayOutput shape while streaming as records complete. Only opened when
	// the plan has a stream — otherwise it would create (and truncate) an -o
	// file that nothing then writes to.
	var enc *json.Encoder
	if plan.stream {
		noteLegacyBulkDefault(plan)
		e, closeOut, oerr := openStreamEncoder(plan)
		if oerr != nil {
			return oerr
		}
		defer closeOut()
		enc = e
	}

	var (
		wg    sync.WaitGroup
		outMu sync.Mutex
		sem   = make(chan struct{}, concurrency)
		// collected holds every entry for the -j envelope, in completion order.
		collected []*replayOutput
		// attempted and failed feed the run's outcome (sendOutcomeError).
		attempted, failed int
	)

	for _, rec := range records {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(rec *database.HTTPRecord) {
			defer wg.Done()
			defer func() { <-sem }()

			entry := rr.recordEntry(ctx, rec, staticOverlay)

			// Render off-lock: building the table (width computation, coloring)
			// under the shared mutex would serialize every worker's formatting
			// behind one tty write. The lock then covers a single Write, which
			// is also what keeps concurrent blocks from interleaving.
			var buf bytes.Buffer
			if plan.human && entry.Error == "" {
				_ = emitReplayPretty(&buf, entry)
				// Blank line between per-record blocks so a bulk human run
				// reads as separate entries rather than one wall of tables.
				buf.WriteByte('\n')
			}

			outMu.Lock()
			defer outMu.Unlock()
			attempted++
			if replayEntryFailed(entry) {
				failed++
			}
			if enc != nil {
				emitBulkEntry(enc, entry)
			}
			if plan.envelope {
				collected = append(collected, entry)
			}
			if plan.human {
				if entry.Error != "" {
					fmt.Fprintf(os.Stderr, "%s replay %s: %s\n", terminal.ErrorPrefix(), entry.Source, entry.Error)
					return
				}
				_, _ = os.Stdout.Write(buf.Bytes())
			}
		}(rec)
	}
	wg.Wait()

	saveReplayJar(rr.pj)
	if plan.envelope {
		if err := emitReplayBulkEnvelope(cmd, collected); err != nil {
			return err
		}
	}
	return sendOutcomeError("replay", attempted, failed)
}

// recordEntry replays one stored record and returns its output. On any
// per-record failure it returns a replayOutput carrying Error (Result nil) so
// one bad record surfaces without aborting the batch. Does no I/O to the shared
// output sink — the caller serializes that.
func (rr *replayRun) recordEntry(ctx context.Context, rec *database.HTTPRecord, staticOverlay map[string]string) *replayOutput {
	src := sourceFromDBRecord(rec)

	// The static --header overlay is the common case; only re-resolve per host
	// when --auth-session needs a host-specific merge.
	overlay := staticOverlay
	if replayAuthSession != "" {
		ov, err := buildReplayOverlay(ctx, src)
		if err != nil {
			return bulkErrorEntry(src, err)
		}
		overlay = ov
	}

	if replayTargetURL != "" {
		if err := applyTargetOverride(src, replayTargetURL); err != nil {
			return bulkErrorEntry(src, err)
		}
	}

	out, err := rr.one(ctx, src, overlay)
	if err != nil {
		return bulkErrorEntry(src, err)
	}
	return out
}

// bulkErrorEntry builds the error-carrying output line for a failed record.
func bulkErrorEntry(src *replaySource, err error) *replayOutput {
	return &replayOutput{Source: src.OriginLabel, RecordUUID: src.RecordUUID, Error: err.Error()}
}

// emitBulkEntry writes one JSONL line; errors are surfaced to stderr rather
// than aborting the stream.
func emitBulkEntry(enc *json.Encoder, out *replayOutput) {
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "%s replay: could not encode result: %v\n", terminal.WarningSymbol(), err)
	}
}

// buildReplayBulkFilters maps replay's bulk flags (plus the positional fuzzy
// term) to a record query, tracking the selection surface of `vigolium traffic`.
// Project scoping follows effectiveProjectUUID (off under -S/--stateless). --all
// lifts the -n/--limit cap.
func buildReplayBulkFilters(fuzzy string) (database.QueryFilters, error) {
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return database.QueryFilters{}, err
	}

	dateFrom, dateTo, derr := parseDateRangeFlags(replayBulkFrom, replayBulkTo,
		timeFilterFromLabel, timeFilterToLabel)
	if derr != nil {
		return database.QueryFilters{}, derr
	}

	// --all lifts the cap: a zero Limit means "no LIMIT clause" in the query.
	limit := replayBulkLimit
	if replayAll {
		limit = 0
	}
	return database.QueryFilters{
		ProjectUUID:         projectUUID,
		HostPattern:         replayBulkHost,
		Methods:             replayBulkMethods,
		StatusCodes:         replayBulkStatus,
		PathPattern:         replayBulkPath,
		Source:              replayBulkSource,
		FuzzyTerm:           fuzzy,
		SearchTerms:         replayBulkSearch,
		HeaderSearch:        replayBulkHeaderSearch,
		BodySearch:          replayBulkBody,
		ExcludeTerms:        replayBulkExclude,
		ExcludeHeaderSearch: replayBulkExcludeHeader,
		ExcludeBodySearch:   replayBulkExcludeBody,
		DateFrom:            dateFrom,
		DateTo:              dateTo,
		Limit:               limit,
		Offset:              replayBulkOffset,
		SortBy:              replayBulkSort,
		SortAsc:             replayBulkAsc,
	}, nil
}

// sourceFromDBRecord builds a replaySource from an already-loaded record,
// avoiding the extra GetRecordByUUID round-trip sourceFromRecord does.
func sourceFromDBRecord(rec *database.HTTPRecord) *replaySource {
	return &replaySource{
		BaselineRequest:      rec.RawRequest,
		BaselineResponse:     rec.RawResponse,
		BaselineStatus:       rec.StatusCode,
		BaselineResponseTime: rec.ResponseTimeMs,
		Scheme:               rec.Scheme,
		Hostname:             rec.Hostname,
		Port:                 rec.Port,
		URL:                  rec.URL,
		RecordUUID:           rec.UUID,
		OriginLabel:          fmt.Sprintf("record %s", rec.UUID),
	}
}
