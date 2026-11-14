package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// generateReportFromDB queries data from the database and generates a report at
// the specified output path using the given generator function. projectUUID
// scopes the query: "" exports the whole DB (stateless temp DB), a non-empty
// value scopes to one project so a persisted report matches the sibling jsonl
// export and never leaks other projects' findings. scanUUID further restricts the
// findings to a single scan (empty = all of the project's), so a persisted scan's
// report reflects that run rather than the project's whole history.
func generateReportFromDB(ctx context.Context, db *database.DB, outputPath string, omitResponse bool, projectUUID, scanUUID string, rf reportFormatEntry, onTrim func(output.ReportTrimInfo)) error {
	autoTarget, autoDuration := computeReportMeta(ctx, db)
	meta := output.HTMLReportMeta{
		Title:           "Vigolium Scan Report",
		Version:         getVersion(),
		ScanDuration:    autoDuration,
		ScanTarget:      autoTarget,
		ReportSharedURL: scanReportSharedURL,
		// nil keeps the generator's default inline "Note:" line; the stateless
		// export path passes a collector so the trim summary folds into "Exports".
		OnTrim: onTrim,
	}
	// A stateless run renders from its temp DB, which is gone once the command
	// exits, so its reports carry no follow-up commands.
	applyReportFlags(&meta, globalStateless)
	// Prefer the streaming generator when the format has one: it renders the
	// report by pulling rows one at a time instead of loading the whole result
	// set into memory. The HTML renderer derives the displayed request/response
	// bodies from the raw bytes (HTTPRecord.MarshalJSON) and only then drops the
	// redundant raw_request/raw_response copies, so those columns MUST be loaded;
	// honor only an explicit --omit-response, never force it on here.
	if rf.streamGenerate != nil {
		produce := func(emit func(any) error) error {
			// Reports render the whole envelope: --export-only documents itself as
			// narrowing the jsonl stream, and a report with its findings silently
			// removed is worse than no report.
			return streamExportData(ctx, db, fullExportScope, omitResponse, projectUUID, scanUUID, emit)
		}
		return rf.streamGenerate(produce, outputPath, meta)
	}
	// Materialized branch: MUST carry scanUUID too. The streaming branch above
	// already scoped to the current scan, but `report`, `pdf` and `sarif` have no
	// streaming generator, so they fell through here and rendered the project's
	// whole finding history as if it were this run's result — contradicting this
	// function's own contract and, for sarif, re-reporting every historical finding
	// to GitHub code scanning on each scan.
	items, err := queryExportData(ctx, db, omitResponse, projectUUID, scanUUID)
	if err != nil {
		return err
	}
	return rf.generate(items, outputPath, meta)
}

// parseFormats splits a comma-separated format string, defaulting to "console".
func parseFormats(raw string) []string {
	if formats := clicommon.SplitCSV(raw); len(formats) > 0 {
		return formats
	}
	return []string{"console"}
}

// normalizeScanFormats canonicalizes aliases in place and rejects anything the
// scan surface of the output format table does not accept. Shared by
// reconcileOutputFormats and planAgentStateless so a format accepted by
// `scan -S` is accepted by `agent autopilot -S` too — both materialize their
// output through the same exporter (finishStatelessExport).
func normalizeScanFormats(formats []string) error {
	for i, f := range formats {
		of, err := output.Lookup(f, output.SurfaceScan)
		if err != nil {
			return usageErrorf("invalid --format value %q; valid formats: %s",
				strings.TrimSpace(f), strings.Join(output.Names(output.SurfaceScan), ", "))
		}
		formats[i] = of.Name
	}
	return nil
}

// githubToStdout reports whether the github format will write its workflow
// commands to stdout: it was requested and there is no -o to name a file.
func githubToStdout(formats []string, outputPath string) bool {
	if outputPath != "" {
		return false
	}
	return slices.ContainsFunc(formats, func(f string) bool { return output.CanonicalFormat(f) == "github" })
}

// reconcileOutputFormats applies --json and --ci-output-format overrides to
// OutputFormats and validates the result. Shared by scan and scan-url commands.
//
// -j no longer becomes --format jsonl: it is the scan document, written once
// after the run (scan_document.go), so it only reserves stdout for that
// document. The jsonl export runs when --format jsonl is given, and only then.
func reconcileOutputFormats(opts *types.Options) error {
	if err := validateReportFlags(); err != nil {
		return err
	}
	// The github format's workflow commands own stdout when there is no -o. The
	// -j document and the CI jsonl stream want stdout too, and a consumer
	// parsing either would choke on the other.
	if githubToStdout(opts.OutputFormats, opts.Output) {
		if globalJSON {
			return usageErrorf("--format github writes workflow commands to stdout and cannot be combined with -j/--json; pass -o FILE to write them to a file instead")
		}
		if globalCIOutput {
			return usageErrorf("--format github cannot be combined with --ci-output-format, which replaces --format with a jsonl stream on stdout")
		}
	}
	opts.StdoutDocument = globalJSON && !globalCIOutput
	if opts.HasFormat("jsonl") {
		opts.JSONOutput = true
	}
	if globalCIOutput {
		opts.CIOutput = true
		opts.OutputFormats = []string{"jsonl"}
		opts.JSONOutput = true
		opts.Silent = true
	}
	if err := normalizeScanFormats(opts.OutputFormats); err != nil {
		return err
	}
	// The sqlite format dumps this run's database to a standalone file, which is
	// only well-defined in stateless mode (a per-run temp DB). A persisted run
	// writes into the shared project DB, where "this scan's sqlite" is ambiguous.
	if opts.HasFormat("sqlite") && !globalStateless {
		return usageErrorf("--format sqlite requires -S/--stateless (it exports the standalone per-run database; for the persisted DB use `vigolium export`)")
	}
	// Route jsonl through the post-scan project-scoped envelope export so the
	// scan output matches `vigolium export`/stateless. CI output keeps its own
	// findings-only emitter (see outputScanResult), so leave it on the legacy
	// live path.
	opts.DeferredJSONLExport = opts.HasFormat("jsonl") && !opts.CIOutput
	return nil
}

// reportFormatEntry is one post-run report format, as the scan commands and
// the REST server render it: the format table's renderer for the name.
type reportFormatEntry struct {
	format string
	label  string
	// generate materializes all items, then renders. Used when streamGenerate
	// is nil, and as the fallback path for the streaming generators.
	generate func([]any, string, output.HTMLReportMeta) error
	// streamGenerate, when set, renders the report by pulling items one at a
	// time from a producer, so the result set never lives in memory at once.
	streamGenerate func(output.ReportItemProducer, string, output.HTMLReportMeta) error
	beforeMsg      string // optional stderr message before generation
	// needsOutputPath is false for a report that streams to stdout without -o
	// (github).
	needsOutputPath bool
}

// reportFormatEntries derives the report entries a surface renders from the
// output format table, in table order.
func reportFormatEntries(s output.Surface) []reportFormatEntry {
	var out []reportFormatEntry
	for _, f := range output.ReportFormats(s) {
		e := reportFormatEntry{
			format:          f.Name,
			label:           f.Label,
			generate:        f.Render,
			streamGenerate:  f.RenderStream,
			needsOutputPath: f.NeedsOutputPath,
		}
		if f.NeedsChrome {
			e.beforeMsg = "Generating " + f.Label + " (headless Chrome)..."
		}
		out = append(out, e)
	}
	return out
}

// reportFormats are the report formats the scan commands render after the run.
var reportFormats = reportFormatEntries(output.SurfaceScan)

// formatNeedsOutput reports whether a format writes a file the command cannot
// name on its own, so `--format X` without -o must be rejected rather than
// silently producing nothing. Shared by the scan commands and `export`/`import`.
//
// The answer is the format table's NeedsOutputPath, and an unknown format
// defaults to true: stated the other way round, a newly added format would
// default to "needs no -o" and silently no-op, which is exactly how `sarif`
// shipped able to be requested and unable to be written.
func formatNeedsOutput(format string) bool {
	f, ok := output.FormatByName(format)
	if !ok {
		return true
	}
	return f.NeedsOutputPath
}

// maybeGenerateReports generates all requested file-based reports post-scan and
// returns the joined per-format failures.
//
// Every format named on the command line is a requested output, and a scan that
// could not write one did not do what it was asked. It used to print "Failed to
// generate html" to stderr and exit 0, so a CI job that asked for a report and
// read the exit code was told the run succeeded while the file it was about to
// publish did not exist. The error now reaches the caller, which folds it in
// with recordExportFailure.
//
// Nothing is printed for a failure here, for the same reason as
// finishStatelessExport: the root handler renders the returned error once, and
// printing as well announced the same cause twice in two wordings. Each format
// is still attempted independently, so one unwritable destination does not cost
// the others.
func maybeGenerateReports(db *database.DB, opts *types.Options) error {
	// No -o renders only the reports that stream to stdout (github); the rest
	// were rejected by validation before the scan ran. On a stateless run an
	// empty opts.Output means finishStatelessExport owns the reports (it blanks
	// the field while it does), stdout ones included.
	stdoutOnly := opts.Output == ""
	if stdoutOnly && opts.Stateless {
		return nil
	}
	ctx := context.Background()
	// Scope the report's findings to this scan on a persisted (shared) DB, so a
	// re-run's report reflects that run rather than the project's whole history. A
	// stateless run's temp DB already holds only this scan, so it needs no filter.
	scanScope := ""
	if !opts.Stateless {
		scanScope = opts.ScanUUID
	}
	var failures []error
	for _, rf := range reportFormats {
		if !opts.HasFormat(rf.format) {
			continue
		}
		if stdoutOnly && rf.needsOutputPath {
			continue
		}
		outPath := ""
		if !stdoutOnly {
			outPath = opts.OutputPathForFormat(rf.format)
		}
		if rf.beforeMsg != "" {
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), rf.beforeMsg)
		}
		if err := generateReportFromDB(ctx, db, outPath, opts.OmitResponse, exportProjectScope(opts), scanScope, rf, nil); err != nil {
			failures = append(failures, fmt.Errorf("generate %s %s: %w", rf.label, reportDestination(outPath), err))
			continue
		}
		fmt.Fprintf(os.Stderr, "%s %s: %s\n", terminal.InfoSymbol(), rf.label, terminal.Cyan(reportDestination(outPath)))
		noteScanArtifact(rf.format, outPath)
	}
	return errors.Join(failures...)
}

// reportDestination names where a report went, for messages: its path, or
// "stdout" for a report rendered without one.
func reportDestination(path string) string {
	if path == "" {
		return "stdout"
	}
	return path
}
