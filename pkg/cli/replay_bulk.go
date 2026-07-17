package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// replayBulkRequested reports whether any bulk-selection flag switched replay
// into "iterate the matching stored records" mode. --all or any record filter
// triggers it; the single-source flags (--record-uuid/--finding-id/--input)
// stay in single mode.
func replayBulkRequested() bool {
	return replayAll ||
		replayBulkHost != "" ||
		len(replayBulkMethods) > 0 ||
		len(replayBulkStatus) > 0 ||
		replayBulkPath != "" ||
		replayBulkSource != "" ||
		replayBulkSearch != "" ||
		replayBulkBody != ""
}

// runReplayBulk re-sends every stored record matching the bulk filters through
// the replay engine, concurrently. Results stream as JSONL (one replayOutput
// per record) to stdout / --output, or as per-record diff tables under
// --pretty. Any --mutate is applied to each record that has that insertion
// point; without it each record is re-sent verbatim.
func runReplayBulk(ctx context.Context, rr *replayRun) error {
	if replayRecordUUID != "" || replayFindingID > 0 || replayInput != "" || replayInputFile != "" {
		return fmt.Errorf("bulk selection flags (--all/--host/--method/--status/--path/--source/--search/--body) can't be combined with --record-uuid/--finding-id/--input")
	}

	// Bulk replay re-sends the stored requests, so a --glob-db merge must keep
	// the bodies.
	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		return fmt.Errorf("bulk replay requires database access: %w", err)
	}

	filters, err := buildReplayBulkFilters()
	if err != nil {
		return err
	}

	records, err := database.NewQueryBuilder(db, filters).Execute(ctx)
	if err != nil {
		return fmt.Errorf("query records: %w", err)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "No matching records to replay.")
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
	fmt.Fprintf(os.Stderr, "%s Replaying %d record(s) through the mutation/diff engine (concurrency %d)...\n",
		terminal.InfoSymbol(), len(records), concurrency)

	// JSONL sink. One object per line keeps each entry the existing stable
	// replayOutput shape while streaming as records complete.
	w, closeOut, err := openReplayOutputWriter()
	if err != nil {
		return err
	}
	defer closeOut()
	enc := json.NewEncoder(w)

	var (
		wg    sync.WaitGroup
		outMu sync.Mutex
		sem   = make(chan struct{}, concurrency)
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

			// Serialize only the output write; the replay itself ran concurrently.
			outMu.Lock()
			defer outMu.Unlock()
			if replayPretty {
				if entry.Error != "" {
					fmt.Fprintf(os.Stderr, "%s replay %s: %s\n", terminal.ErrorPrefix(), entry.Source, entry.Error)
				} else {
					_ = emitReplayPretty(entry)
				}
			} else {
				emitBulkEntry(enc, entry)
			}
		}(rec)
	}
	wg.Wait()

	saveReplayJar(rr.pj)
	return nil
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

// buildReplayBulkFilters maps replay's bulk flags to a record query. Project
// scoping follows effectiveProjectUUID (off under -S/--stateless). --all lifts
// the -n/--limit cap.
func buildReplayBulkFilters() (database.QueryFilters, error) {
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return database.QueryFilters{}, err
	}
	limit := replayBulkLimit
	if replayAll {
		limit = 0
	}
	return database.QueryFilters{
		ProjectUUID: projectUUID,
		HostPattern: replayBulkHost,
		Methods:     replayBulkMethods,
		StatusCodes: replayBulkStatus,
		PathPattern: replayBulkPath,
		Source:      replayBulkSource,
		SearchTerm:  replayBulkSearch,
		BodySearch:  replayBulkBody,
		Limit:       limit,
		SortBy:      "created_at",
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
		RecordUUID:           rec.UUID,
		OriginLabel:          fmt.Sprintf("record %s", rec.UUID),
	}
}
