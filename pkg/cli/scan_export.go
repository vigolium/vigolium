package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// finishFSExport writes the post-scan flat filesystem tree (the `fs` format)
// for a persisted run, scoped to the scan's project. Stateless runs are handled
// by finishStatelessExport (their temp DB is whole-run-scoped and opts.Output is
// blanked), so this no-ops for them. The base defaults to "vigolium" in the cwd
// when no -o was given, matching the documented fs behavior.
//
// Like maybeGenerateReports, a failure is returned rather than printed: `--format
// fs` is a requested output, and a run that wrote no tree has not delivered it.
func finishFSExport(db *database.DB, opts *types.Options) error {
	if !opts.HasFormat("fs") || opts.Stateless {
		return nil
	}
	base := opts.Output
	if len(opts.OutputFormats) > 1 {
		base = opts.OutputBasePath()
	}
	filters := database.QueryFilters{ProjectUUID: exportProjectScope(opts)}
	stats, err := writeFSExport(context.Background(), db, filters, base, fsExportOptions{omitResponse: opts.OmitResponse})
	if err != nil {
		return fmt.Errorf("export fs tree: %w", err)
	}
	fsPrintSummary(stats)
	return nil
}

// exportedFile records one materialized file/directory for the unified stateless
// export summary printed at the end of finishStatelessExport. detail is an
// optional parenthetical (e.g. "53 records").
type exportedFile struct {
	label  string // format name: console, jsonl, sqlite, html, fs, …
	path   string
	detail string
}

// fsExportOutputs turns an fs-export result into unified summary rows — one per
// directory actually written (traffic and/or findings) — so the fs format lists
// alongside the other formats instead of printing its own separate block.
func fsExportOutputs(stats fsExportStats) []exportedFile {
	var out []exportedFile
	if stats.TrafficDir != "" {
		out = append(out, exportedFile{label: "fs", path: stats.TrafficDir, detail: fmt.Sprintf("%d records", stats.Traffic)})
	}
	if stats.FindingsDir != "" {
		out = append(out, exportedFile{label: "fs", path: stats.FindingsDir, detail: fmt.Sprintf("%d findings", stats.Findings)})
	}
	return out
}

// displayExportPath renders an export destination as an absolute path with the
// home directory collapsed to "~", so the summary shows exactly where a file
// landed regardless of the cwd. Falls back to the raw path if it can't be made
// absolute.
func displayExportPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return terminal.ShortenHome(abs)
}

// printExportSummary lists every materialized output under one aligned "Exports"
// header, so a multi-format run reports its files consistently instead of
// interleaving differently-shaped per-format "exported to" messages. Paths are
// shown absolute (home collapsed to "~"). No-ops when nothing was written.
func printExportSummary(outputs []exportedFile) {
	if len(outputs) == 0 {
		return
	}
	labelW := 0
	for _, o := range outputs {
		if len(o.label) > labelW {
			labelW = len(o.label)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.InfoSymbol(), terminal.BoldAqua("Exports"))
	for _, o := range outputs {
		noteScanArtifact(o.label, o.path)
		line := fmt.Sprintf("  %-*s  %s", labelW, o.label, terminal.Cyan(displayExportPath(o.path)))
		if o.detail != "" {
			line += "  " + terminal.Gray("("+o.detail+")")
		}
		fmt.Fprintln(os.Stderr, line)
	}
}

// finishStatelessExport writes the full database export to the output file(s)
// when running in stateless mode. StandardWriter's live file output is
// suppressed in stateless mode, so every requested format (console, jsonl,
// html, report, pdf) is materialized here from the database, then listed under a
// single unified "Exports" summary.
//
// Every format is attempted even after one fails — a caller that asked for jsonl
// AND sqlite is better served by the one that can be written than by neither —
// and the formats that did not land are joined into the returned error. Callers
// fold that into their result with recordExportFailure; the per-format detail is
// already on stderr by then, so the error's job is only to make the failure
// reachable by exit code and by the terminal event.
func finishStatelessExport(db *database.DB, opts *types.Options, outputPath string, skipConsole bool) error {
	if !opts.Stateless {
		return nil
	}
	ctx := context.Background()
	if outputPath == "" {
		// Every file-based format needs an explicit -o, but fs defaults its base
		// to the cwd ("vigolium"), so it still writes a tree with no -o.
		if opts.HasFormat("fs") {
			stats, err := writeFSExport(ctx, db, database.QueryFilters{}, "", fsExportOptions{omitResponse: opts.OmitResponse})
			if err != nil {
				return fmt.Errorf("export fs tree: %w", err)
			}
			printExportSummary(fsExportOutputs(stats))
		}
		// Reports that need no path (github) stream to stdout.
		var failures []error
		for _, rf := range reportFormats {
			if rf.needsOutputPath || !opts.HasFormat(rf.format) {
				continue
			}
			if err := generateReportFromDB(ctx, db, "", opts.OmitResponse, "", "", rf, nil); err != nil {
				failures = append(failures, fmt.Errorf("generate %s %s: %w", rf.label, reportDestination(""), err))
			}
		}
		return errors.Join(failures...)
	}

	basePath := types.StripFormatExtension(outputPath)

	// Materialize every requested format, collecting one row per output file/dir,
	// then print them together under a single "Exports" summary. Failures print
	// inline (they're not successes to list); the trailing summary lists only what
	// was actually written, and the joined failures go back to the caller.
	var outputs []exportedFile
	var failures []error
	// One place decides what a per-format outcome does, so a format cannot be
	// added that collects its failure but forgets to report it. Nothing is printed
	// here: the joined failures become the command's error, which the root handler
	// renders once — the exporters used to print too, so a failing run announced
	// the same cause twice in two wordings. recordExportFailure owns the one case
	// where that render does not happen (an earlier failure already won).
	record := func(e exportedFile, err error) {
		if err != nil {
			failures = append(failures, err)
			return
		}
		outputs = append(outputs, e)
	}
	for _, format := range opts.OutputFormats {
		outPath := types.FormatOutputPath(basePath, format)
		switch format {
		case "console":
			if skipConsole {
				// A transcript was captured to this path; do not overwrite it.
				continue
			}
			record(exportStatelessConsole(ctx, db, outPath, opts.OmitResponse))
		case "jsonl":
			record(exportStatelessJSONL(ctx, db, opts, outPath))
		case "sqlite":
			record(exportStatelessSQLite(ctx, db, outPath))
		case "fs":
			// The stateless temp DB holds only this run → whole-DB tree ("").
			// Several rows per success, so it cannot go through record.
			stats, err := writeFSExport(ctx, db, database.QueryFilters{}, outPath, fsExportOptions{omitResponse: opts.OmitResponse})
			if err != nil {
				record(exportedFile{}, fmt.Errorf("export fs tree %s: %w", outPath, err))
				continue
			}
			outputs = append(outputs, fsExportOutputs(stats)...)
		default:
			for _, rf := range reportFormats {
				if rf.format != format {
					continue
				}
				if rf.beforeMsg != "" {
					fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), rf.beforeMsg)
				}
				// Capture the report's body-trim summary (HTML only) so it lands as
				// the row's detail in the unified "Exports" list instead of a long
				// inline note printed mid-run.
				var trim output.ReportTrimInfo
				// Stateless temp DB holds only this run → whole-DB report ("").
				err := generateReportFromDB(ctx, db, outPath, opts.OmitResponse, "", "", rf, func(t output.ReportTrimInfo) { trim = t })
				if err != nil {
					record(exportedFile{}, fmt.Errorf("generate %s %s: %w", rf.label, outPath, err))
					continue
				}
				record(exportedFile{label: rf.format, path: outPath, detail: trim.Summary()}, nil)
			}
		}
	}
	printExportSummary(outputs)
	return errors.Join(failures...)
}

// exportProjectScope returns the project filter for a post-scan export: empty
// (whole DB) for stateless runs, whose temp DB holds only this scan; the run's
// project (defaulting to DefaultProjectUUID) for persisted runs, so the export
// is scoped to this scan's project on a shared DB. Shared by the jsonl and
// report post-scan exporters so their scopes stay in sync.
func exportProjectScope(opts *types.Options) string {
	if opts.Stateless {
		return ""
	}
	if opts.ProjectUUID != "" {
		return opts.ProjectUUID
	}
	return database.DefaultProjectUUID
}

// encodeJSONL writes each item to w as a unified {"type":...,"data":...} envelope
// line, returning the number written. Callers query first (so a query failure
// never leaves a created-but-empty output file) and encode into an already-open
// writer here.
func encodeJSONL(w io.Writer, items []any) (int, error) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}

// streamJSONLExport streams the unified {"type":...,"data":...} envelope to w,
// encoding each item as it is read from the database so the full result set is
// never held in memory. Returns the per-type tally the export summary prints
// (counts.total is the number of lines written). A mid-stream write error aborts
// and is returned; callers writing to a file should stage to a temp path (see
// streamJSONLToFile) so a partial stream never replaces a good file.
//
// SetEscapeHTML(false) is load-bearing and shared with encodeJSONL: payload
// evidence is full of & < >, which Go escapes by default.
func streamJSONLExport(ctx context.Context, db *database.DB, w io.Writer, omitResponse bool, projectUUID string) (exportCounts, error) {
	return streamScopedJSONLExport(ctx, db, w, omitResponse, projectUUID, "")
}

// streamScopedJSONLExport is streamJSONLExport narrowed to one scan when
// scanUUID is non-empty (the scan row, its records and its findings; see
// streamExportData).
// The post-scan `--format jsonl` stream passes the scan's UUID; `vigolium
// export` passes "" and stays the whole-project path.
func streamScopedJSONLExport(ctx context.Context, db *database.DB, w io.Writer, omitResponse bool, projectUUID, scanUUID string) (exportCounts, error) {
	counts := newExportCounts()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	err := streamExportData(ctx, db, scanExportScope, omitResponse, projectUUID, scanUUID, func(item any) error {
		if err := enc.Encode(item); err != nil {
			return err
		}
		counts.add(item)
		return nil
	})
	return counts, err
}

// streamJSONLToFile streams the JSONL envelope to outputPath atomically: it
// writes to a temp sibling and renames into place on success, so a failed or
// partial export never replaces or half-writes the destination file. Returns the
// number of records written.
func streamJSONLToFile(ctx context.Context, db *database.DB, outputPath string, omitResponse bool, projectUUID, scanUUID string) (int, error) {
	var counts exportCounts
	err := atomicfile.Write(outputPath, func(w *bufio.Writer) error {
		var werr error
		counts, werr = streamScopedJSONLExport(ctx, db, w, omitResponse, projectUUID, scanUUID)
		return werr
	})
	if err != nil {
		return 0, err
	}
	return counts.total, nil
}

// writeJSONLExport streams the (optionally project- and scan-scoped) database
// export to w. projectUUID == "" exports the whole DB; scanUUID == "" keeps
// every scan of the project. Used for the stdout path, where there is no output
// file to leave half-written on error.
func writeJSONLExport(ctx context.Context, db *database.DB, w io.Writer, omitResponse bool, projectUUID, scanUUID string) (int, error) {
	counts, err := streamScopedJSONLExport(ctx, db, w, omitResponse, projectUUID, scanUUID)
	return counts.total, err
}

// exportStatelessJSONL writes all records in the (temporary) database to a JSONL
// file. Used only in stateless mode, where the temp DB holds just this run, so
// the whole-DB export is implicitly scoped to the current scan. The query runs
// before the file is created so a query failure leaves no empty output file.
func exportStatelessJSONL(ctx context.Context, db *database.DB, opts *types.Options, outputPath string) (exportedFile, error) {
	n, err := streamJSONLToFile(ctx, db, outputPath, opts.OmitResponse, "", "")
	if err != nil {
		return exportedFile{}, fmt.Errorf("export jsonl %s: %w", outputPath, err)
	}
	return exportedFile{label: "jsonl", path: outputPath, detail: fmt.Sprintf("%d records", n)}, nil
}

// exportStatelessSQLite materializes the stateless run's database to a
// standalone SQLite file via VACUUM INTO, which produces a clean, fully
// checkpointed copy (WAL contents included, page freelist compacted) from the
// live connection. The result is a self-contained .sqlite the operator can open
// later with `vigolium finding/traffic -S --db <file>.sqlite`.
//
// The export is staged and then renamed into place. VACUUM INTO refuses to
// overwrite, so SOMETHING has to clear the way for a re-export, and this used to
// delete the destination (plus its -wal/-shm sidecars) before running the
// VACUUM. That made every failure destructive: a full disk, a cancelled context,
// a Ctrl-C mid-copy, and the operator was left with neither the new export nor
// the previous one they had just overwritten. Staging costs nothing — the stage
// sits in the destination's own directory, so publishing it is a same-filesystem
// rename, which is atomic and cannot half-replace the old file.
func exportStatelessSQLite(ctx context.Context, db *database.DB, outputPath string) (exportedFile, error) {
	// CreateTemp reserves a name no concurrent writer can guess, in the
	// destination's own directory so publishing is a same-filesystem rename, and
	// proves that directory is writable before the VACUUM does any work. VACUUM
	// INTO then needs the name free, so the reservation is released immediately —
	// a predictable stage name would be cheaper but lets anyone with write access
	// to a shared output directory (-o /tmp/scan.sqlite) pre-empt it.
	stage, err := os.CreateTemp(filepath.Dir(outputPath), "."+filepath.Base(outputPath)+".*.partial")
	if err == nil {
		err = stage.Close()
	}
	var stagePath string
	if err == nil {
		stagePath = stage.Name()
		err = os.Remove(stagePath)
	}
	if err != nil {
		return exportedFile{}, fmt.Errorf("prepare sqlite export %s: %w", outputPath, err)
	}
	// Unconditional: after a successful rename the stage no longer exists and this
	// is a no-op, so nothing has to track whether we got that far. VACUUM INTO
	// closes its target and journals it in delete mode, so there are no sidecars
	// of its own to collect.
	defer func() { _ = os.Remove(stagePath) }()

	// stagePath derives from the operator-supplied outputPath (not
	// attacker-controlled); single-quote escape keeps a path with quotes from
	// breaking the statement.
	stmt := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(stagePath, "'", "''"))
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return exportedFile{}, fmt.Errorf("export sqlite %s: %w", outputPath, err)
	}
	// A kept OAST session's keys let whoever holds them read its callbacks;
	// they stay in the operator's store and never travel in an export.
	if err := database.RedactOASTSessionKeysInFile(ctx, stagePath); err != nil {
		return exportedFile{}, fmt.Errorf("redact sqlite export %s: %w", outputPath, err)
	}
	// The old sidecars belong to the file being replaced, not to the stage. Left
	// behind they would describe a database that no longer exists, and SQLite
	// would rather trust a stale -wal than the fresh file next to it.
	for _, p := range []string{outputPath + "-wal", outputPath + "-shm"} {
		_ = os.Remove(p)
	}
	if err := os.Rename(stagePath, outputPath); err != nil {
		return exportedFile{}, fmt.Errorf("publish sqlite export %s: %w", outputPath, err)
	}
	return exportedFile{label: "sqlite", path: outputPath}, nil
}

// finishScanJSONLExport emits the post-scan unified JSONL envelope for a scan
// run with --format jsonl. Persisted runs are scoped to the scan's project AND
// to this scan (opts.ScanUUID): the scan row and the findings it produced, the
// same scope maybeGenerateReports gives the html/report files. Without the scan
// filter `scan -t X -j` dumped every finding the project had ever stored. HTTP
// records are scoped the same way: the rows this scan stored plus the evidence
// its findings cite (database.WhereScanRecords). `vigolium export` remains the
// whole-project path. Stateless runs export the whole temp
// DB, which holds only this run. Output goes to the -o file or, when
// no -o was given, to stdout. Stateless runs WITH -o are materialized by
// finishStatelessExport (all formats), so only the stateless no-output case is
// handled here (otherwise jsonl results would be silently discarded with the
// temp DB). CI output keeps its own emitter and never sets DeferredJSONLExport.
func finishScanJSONLExport(db *database.DB, opts *types.Options) error {
	if !opts.DeferredJSONLExport {
		return nil
	}
	if opts.Stateless && opts.Output != "" {
		return nil
	}
	ctx := context.Background()
	projectUUID := exportProjectScope(opts)
	scanUUID := ""
	if !opts.Stateless {
		scanUUID = opts.ScanUUID
	}

	if opts.Output == "" {
		// No -o: stream the envelope to stdout once the scan completes. A failure
		// here is reported like any other: the stream is the artifact, and a
		// consumer that read a truncated envelope needs to know it was truncated.
		if _, err := writeJSONLExport(ctx, db, os.Stdout, opts.OmitResponse, projectUUID, scanUUID); err != nil {
			return fmt.Errorf("export jsonl to stdout: %w", err)
		}
		return nil
	}

	// Single format honors the literal -o path the user gave; with multiple
	// formats each writes to its own extension-qualified path so the jsonl
	// export never collides with the live console / html / report files.
	outPath := opts.Output
	if len(opts.OutputFormats) > 1 {
		outPath = opts.OutputPathForFormat("jsonl")
	}
	n, err := streamJSONLToFile(ctx, db, outPath, opts.OmitResponse, projectUUID, scanUUID)
	if err != nil {
		return fmt.Errorf("export jsonl %s: %w", outPath, err)
	}
	fmt.Fprintf(os.Stderr, "%s Results exported to %s (%d records)\n",
		terminal.InfoSymbol(), terminal.Cyan(outPath), n)
	noteScanArtifact("jsonl", outPath)
	return nil
}

// exportStatelessConsole writes all database records to a plain-text file using
// the same human-readable layout as the live console output (minus ANSI colors
// and the phase prefix, which don't belong in a file). Used for stateless runs
// with the default console format so -o always produces a populated file even
// when the phase only ingests HTTP records (e.g. discovery) and emits no
// findings.
func exportStatelessConsole(ctx context.Context, db *database.DB, outputPath string, omitResponse bool) (exportedFile, error) {
	var lines int
	err := atomicfile.Write(outputPath, func(w *bufio.Writer) error {
		return streamExportData(ctx, db, fullExportScope, omitResponse, "", "", func(item any) error {
			env, ok := item.(exportEnvelope)
			if !ok {
				return nil
			}
			var line string
			switch env.Type {
			case "http_record":
				line = consoleHTTPRecordLine(env.Data)
			case "finding":
				line = consoleFindingLine(env.Data)
			}
			if line == "" {
				return nil
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
			lines++
			return nil
		})
	})
	if err != nil {
		return exportedFile{}, fmt.Errorf("export console %s: %w", outputPath, err)
	}
	return exportedFile{label: "console", path: outputPath, detail: fmt.Sprintf("%d lines", lines)}, nil
}

// consoleHTTPRecordLine renders an HTTP record export item as a plain-text
// console-style line: [status] METHOD content-type url
func consoleHTTPRecordLine(data any) string {
	r, ok := data.(*database.HTTPRecord)
	if !ok {
		return ""
	}
	return fmt.Sprintf("[%d] %s %s %s", r.StatusCode, r.Method, shortContentType(r.ResponseContentType), r.URL)
}

// consoleFindingLine renders a finding export item as a plain-text
// console-style line: [severity] [module-id] location [extracted-results]
func consoleFindingLine(data any) string {
	f, ok := data.(*database.Finding)
	if !ok {
		return ""
	}
	loc := f.URL
	if len(f.MatchedAt) > 0 && f.MatchedAt[0] != "" {
		loc = f.MatchedAt[0]
	}
	if loc == "" {
		loc = f.Hostname
	}
	line := fmt.Sprintf("[%s] [%s] %s", strings.ToUpper(f.Severity), f.ModuleID, loc)
	if len(f.ExtractedResults) > 0 {
		line += " [" + output.EscapeOneLine(strings.Join(f.ExtractedResults, ",")) + "]"
	}
	return line
}

// shortContentType trims parameters from a content type
// (application/json; charset=utf-8 → application/json), returning "-" when empty.
func shortContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if ct = strings.TrimSpace(ct); ct == "" {
		return "-"
	}
	return ct
}
