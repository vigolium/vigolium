package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// globBurpSelector applies the parts of the record selection that only exist
// across files, which a single merged database would have got from SQL and from
// http_records' uuid primary key: dedup by uuid (the merged path deduped via
// INSERT OR IGNORE), the global --offset skip, and the -n/--limit budget.
// Everything else — host/status/search/sort — still runs as SQL inside each file.
//
// The budget is spent in file order rather than over a globally sorted set,
// because streaming never holds one. For a Site map copy that is immaterial: the
// order records arrive in does not change what Burp ends up holding.
type globBurpSelector struct {
	seen      map[string]struct{}
	skip      int  // records still to be dropped for --offset
	remaining int  // records still allowed by --limit; meaningless when unlimited
	unlimited bool // --all, or any zero --limit
}

func newGlobBurpSelector(limit, offset int) *globBurpSelector {
	return &globBurpSelector{
		seen:      make(map[string]struct{}),
		skip:      offset,
		remaining: limit,
		unlimited: limit <= 0,
	}
}

// fetchLimit is the LIMIT to put on one file's query: enough to cover both the
// records still owed and any --offset yet to be burned, or 0 (no LIMIT) when
// unlimited. Asking for skip+remaining rather than remaining matters because the
// rows that satisfy the offset are drawn from the same per-file result set.
func (s *globBurpSelector) fetchLimit() int {
	if s.unlimited {
		return 0
	}
	return s.remaining + s.skip
}

// done reports whether the --limit budget is spent, so the remaining files can be
// left unopened rather than queried and discarded.
func (s *globBurpSelector) done() bool { return !s.unlimited && s.remaining <= 0 }

// take filters one file's query result down to the records that should actually
// be sent, consuming the offset and the limit budget as it goes.
func (s *globBurpSelector) take(records []*database.HTTPRecord) []*database.HTTPRecord {
	selected := make([]*database.HTTPRecord, 0, len(records))
	for _, record := range records {
		if s.done() {
			break
		}
		// A uuid seen in an earlier file was already offered to Burp (or already
		// consumed by the offset), so it must not count twice either way.
		if _, dup := s.seen[record.UUID]; dup {
			continue
		}
		s.seen[record.UUID] = struct{}{}
		if s.skip > 0 {
			s.skip--
			continue
		}
		selected = append(selected, record)
		if !s.unlimited {
			s.remaining--
		}
	}
	return selected
}

// saveGlobToBurp is the --glob-db path for `traffic --save-to-burp`: it lists the
// matched files up front, then opens, ships and closes them one at a time.
//
// The merged path (openGlobDB) cannot serve this mode. It copies every matched
// file into ONE in-memory SQLite before the first WHERE runs, and --save-to-burp
// is precisely the mode that cannot skip the raw bodies (they are what gets sent,
// so trafficRendersRawBodies is true) — so the whole request/response corpus is
// held in RAM, and --all then materializes it a second time as Go structs to hand
// to the bridge. Over a few hundred result files that is tens of gigabytes, and
// the process spends its time in swap before it has sent a single record.
// Streaming bounds peak memory by the largest single file instead of the sum of
// all of them, and the per-file progress makes an hour-long copy observable
// rather than silent.
//
// It is also why this path does not fall through to the listing: rendering the
// table afterwards would re-query the whole corpus a third time (and, with -B
// set, pull Burp's entire proxy history to merge into it). The save summary is
// the output.
func saveGlobToBurp(ctx context.Context, cmd *cobra.Command, pattern string, filters database.QueryFilters) error {
	matches, err := globDBMatches(pattern)
	if err != nil {
		return err
	}

	client, err := burpbridge.New(trafficBurpBridgeURL)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "%s Saving to Burp from %d file(s) matched by %s — one at a time\n",
		terminal.InfoSymbol(), len(matches), terminal.Cyan(pattern))

	selector := newGlobBurpSelector(filters.Limit, filters.Offset)
	aggregate := burpbridge.SiteMapSaveResult{}
	started := time.Now()
	var read, unreadable int

	for i, path := range matches {
		if err := ctx.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "%s Stopped after %d file(s): %v\n", terminal.WarningSymbol(), i, err)
			break
		}
		if selector.done() {
			fmt.Fprintf(os.Stderr, "%s Reached the --limit of %d record(s); %d file(s) left unread\n",
				terminal.InfoSymbol(), filters.Limit, len(matches)-i)
			break
		}

		records, err := readTrafficSourceFile(ctx, path, filters, selector.fetchLimit())
		if err != nil {
			unreadable++
			fmt.Fprintf(os.Stderr, "  %s %s %s — skipped: %v\n",
				terminal.WarningSymbol(), globProgressIndex(i+1, len(matches)),
				terminal.Cyan(filepath.Base(path)), err)
			continue
		}
		read++

		selected := selector.take(records)
		if len(selected) == 0 {
			continue
		}

		result := client.SaveRecordsToSiteMap(ctx, selected)
		aggregate.Add(result)

		fmt.Fprintf(os.Stderr, "  %s %s — %d sent, %d added (%d added overall, %s)\n",
			globProgressIndex(i+1, len(matches)), terminal.Cyan(filepath.Base(path)),
			result.Selected, result.Added, aggregate.Added, time.Since(started).Round(time.Second))
	}

	if read == 0 {
		//vigolium:not-usage every source failed to read, after I/O
		return fmt.Errorf("--glob-db %q: none of the %d matched file(s) could be read", pattern, len(matches))
	}

	fmt.Fprintf(os.Stderr, "%s Read %d of %d file(s) in %s",
		terminal.InfoSymbol(), read, len(matches), time.Since(started).Round(time.Second))
	if unreadable > 0 {
		fmt.Fprintf(os.Stderr, ", %d unreadable", unreadable)
	}
	fmt.Fprintln(os.Stderr)
	writeBurpSiteMapSaveResult(os.Stderr, aggregate)

	if globalJSON {
		// items:[aggregate]; the per-run counters stay at the top level, and
		// --json-legacy-keys renders the aggregate under its old name, `result`.
		env := newMachineEnvelope(cmd, "result", aggregate, 1, 0, 1).
			With("pattern", pattern).
			With("files", len(matches)).
			With("files_read", read).
			With("unreadable", unreadable).
			With("duration_ms", time.Since(started).Milliseconds())
		if err := writeAgentJSON(env); err != nil {
			return err
		}
	}

	if aggregate.Added == 0 && aggregate.Skipped > 0 {
		return fmt.Errorf("no selected records could be saved to Burp")
	}
	return nil
}

// globProgressIndex renders "[ 12/854]" with the counter right-aligned to the
// total's width, so the per-file lines stay in one column down a long run.
func globProgressIndex(n, total int) string {
	width := len(strconv.Itoa(total))
	return fmt.Sprintf("[%*d/%d]", width, n, total)
}

// readTrafficSourceFile opens one --glob-db match, runs the traffic filters
// against it, and closes it again — the unit of work the streaming save is built
// from. limit is the per-file LIMIT (0 = no limit); the offset is applied across
// files by globBurpSelector, not here, so the query always starts at 0.
//
// A plain SQLite result file is queried in place, with no copy, so the memory
// cost is the result set rather than the file. Anything else a glob can match (a
// JSONL export, an archive, an audit folder) has no queryable form on disk and is
// loaded into a throwaway database through the same importer the merged path uses.
func readTrafficSourceFile(
	ctx context.Context,
	path string,
	filters database.QueryFilters,
	limit int,
) ([]*database.HTTPRecord, error) {
	db, closeDB, err := openGlobSourceFile(ctx, path)
	if err != nil {
		return nil, err
	}
	defer closeDB()

	fileFilters := filters
	fileFilters.Offset = 0
	fileFilters.Limit = limit
	// The bodies are the payload here, so this query never omits them.
	return database.NewQueryBuilder(db, fileFilters).Execute(ctx)
}
