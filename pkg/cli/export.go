package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

var (
	topExportFormat       string
	topExportOutput       string
	topExportOnly         []string
	topExportExclude      []string
	topExportOmitResponse bool
	topExportSearch       string
	topExportLimit        int
	topExportTitle        string
	topExportSeverity     string
	topExportTarget       string
	topExportDuration     string
	topExportGeneratedAt  string
	topExportReportURL    string
	topExportScanUUIDs    []string

	// topExportNoURLDedup belongs to `vigolium export` alone. The post-scan
	// exporters never set it: their JSONL is the documented per-run artifact and
	// changing its row count by default would break every consumer counting on
	// one row per URL.
	topExportNoURLDedup bool
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export database tables and module registry",
	Long: `Export the contents of one or more database tables (HTTP records, findings, scans, modules, OAST interactions, source repos, scopes) into JSONL, HTML, Markdown, PDF, SARIF, or a bundle archive.

--format sarif writes a SARIF 2.1.0 log of the findings, for ingestion by GitHub code scanning, DefectDojo, the VS Code SARIF Viewer and other aggregators. Code findings anchor to their source file (with line number) so they can be annotated onto a diff; HTTP findings anchor to their URL and carry the proof exchange in the standard webRequest/webResponse fields.

Use --only to choose which tables to include, --omit-response to drop raw HTTP request/response bytes (keeps metadata, smaller files), and --search to fuzzy-filter rows before export. HTML and bundle output require -o/--output.

Multiple formats can be combined in one run (--format html,markdown,bundle). The database is read once and every format is rendered from that one result set (fs is the exception — it streams its own record and finding cursors). With more than one format, -o/--output is the shared base path and each format appends its own extension (report.html, report.md, report.tar.gz); a single format still uses -o verbatim.

The --format bundle (alias gz) emits a .tar.gz archive containing export.jsonl, report.html, manifest.json, and any agent session directories matching --scan-uuid <uuid> (repeatable).

JSONL coverage is a view, not a lossless archive: HTTP exchanges sharing a URL collapse to the first one (plus any exchange a finding links to), and only confirmed findings are emitted. Pass --no-url-dedup for every stored exchange; use --format sqlite on a stateless scan, or copy the database file, when you need the complete store.`,
	RunE: runExportCmd,
}

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.Flags().StringVar(&topExportFormat, "format", "jsonl", "Export format(s), comma-separated: "+output.FormatsHelp(output.SurfaceExport))
	exportCmd.Flags().StringVarP(&topExportOutput, "output", "o", "", "Output file path or gs://<project>/<key> URL (required for html; base path when multiple formats are given); supports {ts} and {project-uuid} placeholders")
	exportCmd.Flags().StringSliceVar(&topExportOnly, "only", nil,
		"Export only these tables (repeatable: "+strings.Join(exportTypeNames(), ", ")+"; aliases like http_record, finding, scan accepted). Applies to every format")
	exportCmd.Flags().BoolVar(&topExportOmitResponse, "omit-response", false,
		"Omit raw HTTP request/response bytes (keeps metadata, smaller files)")
	exportCmd.Flags().BoolVar(&topExportNoURLDedup, "no-url-dedup", false,
		"Emit every stored HTTP exchange; by default exchanges sharing a URL collapse to the first one (plus any a finding links to)")
	exportCmd.Flags().StringVar(&topExportSearch, "search", "",
		"Fuzzy search filter across URLs, paths, hostnames, methods, content types, and sources")
	exportCmd.Flags().IntVar(&topExportLimit, "limit", 0,
		"Maximum number of records to export per table (0 = unlimited)")
	exportCmd.Flags().StringSliceVar(&topExportExclude, "exclude", nil,
		"Exclude these tables (comma-separated, same names as --only, e.g. scans,oast). The module registry is left out unless --only names modules")
	exportCmd.Flags().StringVar(&topExportTitle, "report-title", "",
		"Custom title for the HTML report (default: \"Vigolium Static Report\")")
	exportCmd.Flags().StringVar(&topExportTarget, "report-target", "",
		"Target name for the report (e.g. repository name or URL)")
	exportCmd.Flags().StringVar(&topExportDuration, "report-duration", "",
		"Human-readable scan duration for the report (e.g. \"10h42m5s\")")
	exportCmd.Flags().StringVar(&topExportGeneratedAt, "report-generated-at", "",
		"ISO timestamp for report generation (e.g. \"2026-04-18T03:00:00Z\")")
	exportCmd.Flags().StringVar(&topExportReportURL, "report-url", "",
		"URL for the \"Raw Report URL\" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL)")
	exportCmd.Flags().StringVar(&topExportSeverity, "severity", "",
		"Filter findings by severity (comma-separated: critical,high,medium,low,info)")
	exportCmd.Flags().StringSliceVar(&topExportScanUUIDs, "scan-uuid", nil,
		"Agentic scan UUID(s) whose session directories to include in --format bundle (repeatable)")
	registerReportFlags(exportCmd.Flags())
	exportCmd.Flags().BoolVarP(&globalStateless, "stateless", "S", false,
		"Read from --db (a standalone .sqlite or .jsonl export) instead of your project DB; never writes to it")
	exportCmd.Flags().StringVar(&globalGlobDB, "glob-db", "",
		"Export across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S")
	exportCmd.Flags().BoolVar(&globalGlobStrict, "glob-strict", false,
		"Fail the read on the first --glob-db source that cannot be imported, instead of skipping it with a warning")
}

// exportScope decides which envelope types an export emits.
//
// It is passed to streamExportData rather than read from a package global,
// because the gate is shared by every format - jsonl, html, report, pdf, sarif,
// bundle and the stateless console dump all stream through that one function.
// A caller that wants to narrow ONE of them (the scan's `--export-only`, which
// documents itself as limiting the jsonl envelope) must therefore be able to say
// so without the other formats seeing it: a global made `run probe -o r.html
// --format html` render a report with no findings in it.
//
// The zero value means "everything", so a caller with no opinion passes
// fullExportScope and reads as such.
type exportScope struct {
	// only lists the canonical types to keep (exportRecordTypes). Empty keeps
	// every type that is not implicitly excluded.
	only []string
	// exclude lists canonical types to drop.
	exclude []string
}

// fullExportScope emits every envelope type except the implicitly excluded
// ones (the module registry).
var fullExportScope = exportScope{}

// newExportScope builds a scope from already-validated --only values (see
// parseExportScope); an unknown name is kept verbatim and so matches nothing.
func newExportScope(only []string) exportScope {
	scope := fullExportScope
	for _, v := range only {
		if t, ok := lookupExportType(v); ok {
			if !slices.Contains(scope.only, t.Name) {
				scope.only = append(scope.only, t.Name)
			}
		} else if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			scope.only = append(scope.only, v)
		}
	}
	return scope
}

// parseExportScope validates --only and --exclude against the record-type
// table (aliases accepted) and builds the scope. A type in both is a usage
// error: the two flags would contradict each other.
func parseExportScope(onlyFlag string, only []string, excludeFlag string, exclude []string) (exportScope, error) {
	o, err := canonicalExportTypes(onlyFlag, only)
	if err != nil {
		return exportScope{}, err
	}
	x, err := canonicalExportTypes(excludeFlag, exclude)
	if err != nil {
		return exportScope{}, err
	}
	for _, t := range o {
		if slices.Contains(x, t) {
			return exportScope{}, usageErrorf("%s and %s both name %q", onlyFlag, excludeFlag, t)
		}
	}
	return exportScope{only: o, exclude: x}, nil
}

// includes reports whether the given canonical type should be included.
func (s exportScope) includes(dataType string) bool {
	if slices.Contains(s.exclude, dataType) {
		return false
	}
	if len(s.only) > 0 {
		return slices.Contains(s.only, dataType)
	}
	t, ok := lookupExportType(dataType)
	return !ok || !t.ImplicitlyExcluded
}

// topExportScope is the scope the `vigolium export` command's --only and
// --exclude build. Unknown names were rejected by validateExportOnly.
func topExportScope() exportScope {
	scope, err := parseExportScope("--only", topExportOnly, "--exclude", topExportExclude)
	if err != nil {
		return newExportScope(topExportOnly)
	}
	return scope
}

// shouldExport returns true if the given data type should be included in the
// `vigolium export` command's own pre-flight checks (exportNeedsDB). The
// streaming path takes an explicit exportScope instead.
func shouldExport(dataType string) bool {
	return topExportScope().includes(dataType)
}

// exportEnvelope wraps each exported item with a type tag for JSONL output.
type exportEnvelope struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// exportQuery is everything that selects the rows of one export: which record
// types, the row filters, and the project and scan the rows belong to. Every
// caller of streamExportData builds one; `vigolium export` derives its own
// from the command's flags (topExportQuery), the post-scan exporters pass only
// a scope, a project and a scan.
type exportQuery struct {
	scope        exportScope
	omitResponse bool
	// noURLDedup emits every stored HTTP exchange instead of collapsing
	// exchanges that share a URL.
	noURLDedup bool
	search     string
	severity   []string
	limit      int
	// projectUUID filters every table to one project; "" is the whole store.
	projectUUID string
	// scanUUID narrows the export to one native scan's rows.
	scanUUID string
	// from and to bound the rows by their own timestamp (sent_at for records,
	// found_at for findings, created_at for scans, interacted_at for OAST).
	from, to *time.Time
}

// topExportQuery is the query `vigolium export` runs: its flags, for the given
// project ("" = every project).
func topExportQuery(projectUUID string) exportQuery {
	q := exportQuery{
		scope:        topExportScope(),
		omitResponse: topExportOmitResponse,
		noURLDedup:   topExportNoURLDedup,
		search:       topExportSearch,
		limit:        topExportLimit,
		projectUUID:  projectUUID,
	}
	if topExportSeverity != "" {
		q.severity = strings.Split(strings.ToLower(topExportSeverity), ",")
	}
	return q
}

// limitQuery applies the per-table row limit.
func (q exportQuery) limitQuery(sq *bun.SelectQuery) *bun.SelectQuery {
	if q.limit > 0 {
		return sq.Limit(int64(q.limit))
	}
	return sq
}

// timeRange applies the from/to bounds to a single-table query on column.
func (q exportQuery) timeRange(sq *bun.SelectQuery, column string) *bun.SelectQuery {
	if q.from != nil {
		sq = sq.Where("? >= ?", bun.Ident(column), *q.from)
	}
	if q.to != nil {
		sq = sq.Where("? <= ?", bun.Ident(column), *q.to)
	}
	return sq
}

// scopeProjectBun applies a project_uuid filter to a single-table bun query when
// projectUUID is non-empty. An empty projectUUID means whole-DB (the default
// `vigolium export` / stateless temp-DB behavior); a non-empty value scopes the
// query to one project (the per-scan `--format jsonl` export).
func scopeProjectBun(q *bun.SelectQuery, projectUUID string) *bun.SelectQuery {
	if projectUUID != "" {
		return q.Where("project_uuid = ?", projectUUID)
	}
	return q
}

// exportFormatSpec is one requested format after alias normalization: the
// canonical name, the token the user actually typed (so errors quote their
// spelling), and the output path assigned to it.
type exportFormatSpec struct {
	format string
	raw    string
	path   string
}

// parseExportFormats splits a comma-separated --format value into canonical
// format specs, rejecting unknown names and collapsing duplicates (`html,html`
// renders once). Order is preserved so formats materialize in the order asked
// for.
func parseExportFormats(raw string) ([]exportFormatSpec, error) {
	parts := strings.Split(raw, ",")
	specs := make([]exportFormatSpec, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		token := strings.TrimSpace(p)
		if token == "" {
			continue
		}
		f, err := output.Lookup(token, output.SurfaceExport)
		if err != nil {
			return nil, usageErrorf("unsupported format %q; valid formats: %s", token, strings.Join(output.Names(output.SurfaceExport), ", "))
		}
		canonical := f.Name
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		specs = append(specs, exportFormatSpec{format: canonical, raw: token})
	}
	if len(specs) == 0 {
		return nil, usageErrorf("--format requires at least one format; valid formats: %s", strings.Join(output.Names(output.SurfaceExport), ", "))
	}
	return specs, nil
}

// exportFormatNames lists the canonical format names of a spec set, for messages.
func exportFormatNames(specs []exportFormatSpec) []string {
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		names = append(names, s.format)
	}
	return names
}

// assignExportPaths gives every format its output path. A single format keeps the
// -o value verbatim, so `--format html -o report` still writes exactly "report".
// Multiple formats derive one path each off the shared base — extension stripped,
// then re-appended per format — because one -o cannot name them all.
func assignExportPaths(specs []exportFormatSpec, base string) {
	if len(specs) == 1 {
		specs[0].path = base
		return
	}
	stem := types.StripFormatExtension(base)
	for i := range specs {
		specs[i].path = types.FormatOutputPath(stem, specs[i].format)
	}
}

// validateExportFormatPath enforces the per-format output requirements against
// the path the format actually resolved to.
func validateExportFormatPath(s exportFormatSpec) error {
	if formatNeedsOutput(s.format) && s.path == "" {
		return usageErrorf("--format %s requires -o/--output to specify the report file path", s.raw)
	}
	if s.format == "bundle" && !strings.HasSuffix(s.path, ".tar.gz") && !strings.HasSuffix(s.path, ".tgz") {
		return usageErrorf("--format %s requires -o ending in .tar.gz or .tgz (got %q)", s.raw, s.path)
	}
	return nil
}

// validateExportOnly rejects unknown --only/--exclude table names.
func validateExportOnly() error {
	_, err := parseExportScope("--only", topExportOnly, "--exclude", topExportExclude)
	return err
}

// validateExportFormatsScope refuses a format that renders none of the record
// types --only/--exclude leave (csv with --only http would write a
// header-only file while the receipt counted the records it never wrote), and
// notes on stderr any type --only names that a format leaves out.
func validateExportFormatsScope(specs []exportFormatSpec) error {
	scope := topExportScope()
	for _, s := range specs {
		supported := exportTypesForFormat(s.format)
		var rendered, ignored []string
		for _, t := range exportRecordTypes {
			if !scope.includes(t.Name) {
				continue
			}
			if t.supportsFormat(s.format) {
				rendered = append(rendered, t.Name)
			} else if slices.Contains(scope.only, t.Name) {
				ignored = append(ignored, t.Name)
			}
		}
		if len(rendered) == 0 {
			return usageErrorf("--format %s renders %s, but --only/--exclude leave none of them; add one to --only or drop it",
				s.raw, strings.Join(supported, ", "))
		}
		if len(ignored) > 0 {
			fmt.Fprintf(os.Stderr, "%s --format %s does not render %s (it renders %s)\n",
				terminal.WarningSymbol(), s.raw, strings.Join(ignored, ", "), strings.Join(supported, ", "))
		}
	}
	return nil
}

// exportNeedsDB reports whether any requested table lives in the database.
// Modules come from the in-memory registry, so a modules-only export needs none.
func exportNeedsDB() bool {
	return shouldExport("http") || shouldExport("findings") || shouldExport("scans") ||
		shouldExport("oast") || shouldExport("source-repos") || shouldExport("scopes")
}

func runExportCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	if err := validateExportOnly(); err != nil {
		return err
	}
	if err := validateReportFlags(); err != nil {
		return err
	}

	specs, err := parseExportFormats(topExportFormat)
	if err != nil {
		return err
	}

	// One -o cannot name three files, so a multi-format run needs a base to
	// derive them from.
	if len(specs) > 1 && topExportOutput == "" {
		return fmt.Errorf("multiple --format values (%s) require -o/--output to specify the base output path",
			strings.Join(exportFormatNames(specs), ", "))
	}

	// Expand {ts}/{project-uuid} ONCE on the base, before deriving per-format
	// paths: {ts} is stamped at expansion time, so resolving it per format would
	// let a slow renderer (pdf shells out to headless Chrome) land on a later
	// second than its siblings and scatter one run across several timestamps.
	base, err := expandOutputPlaceholders(topExportOutput)
	if err != nil {
		return err
	}
	assignExportPaths(specs, base)

	for _, s := range specs {
		if err := validateExportFormatPath(s); err != nil {
			return err
		}
	}
	if err := validateExportFormatsScope(specs); err != nil {
		return err
	}
	if err := validateExportJSON(specs); err != nil {
		return err
	}

	ctx := context.Background()
	run := &exportRun{multi: len(specs) > 1}
	// Nil-safe when no format ever opened the DB (a modules-only jsonl export).
	defer closeDatabaseOnExit()

	var (
		outputs []exportedFile
		failed  []string
	)
	for _, s := range specs {
		outs, err := run.runFormat(ctx, s)
		if err != nil {
			// A single format keeps the bare error (and the exact message it
			// always had). In a multi-format run one format that cannot render
			// must not discard the siblings that already succeeded, so the
			// failure is reported here and the run continues.
			if !run.multi {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s Failed to export %s: %v\n", terminal.ErrorPrefix(), s.format, err)
			failed = append(failed, s.format)
			continue
		}
		outputs = append(outputs, outs...)
	}

	if run.multi {
		printMultiExportSummary(exportFormatNames(specs), run.items, outputs, run.printProjectScope)
		if run.itemsSet {
			run.counts, run.countsSet = countExportItems(run.items), true
		}
	}
	var failErr error
	if len(failed) > 0 {
		// Each failure printed its own reason above; this only carries the
		// non-zero exit and names which formats to look for.
		failErr = fmt.Errorf("%d of %d formats failed: %s", len(failed), len(specs), strings.Join(failed, ", "))
	}
	if globalJSON {
		if err := emitExportReceipt(cmd, run, outputs, failErr); err != nil {
			return err
		}
	}
	return failErr
}

// validateExportJSON: under -j stdout carries the one result document, so a
// format that would stream to stdout (jsonl or github without -o) has nowhere
// to go. Refused before anything is read, like `storage download -j`.
func validateExportJSON(specs []exportFormatSpec) error {
	if !globalJSON {
		return nil
	}
	for _, s := range specs {
		if s.path == "" && s.format != "fs" {
			return usageErrorf("export -j needs -o <path>: without it the %s export is written to stdout, "+
				"where the -j document goes (drop -j for the stream itself)", s.format)
		}
	}
	return nil
}

// exportFileView is one artifact `export -j` / `db export -j` wrote.
type exportFileView struct {
	Format string `json:"format"`
	Path   string `json:"path"`
	Detail string `json:"detail,omitempty"`
}

// exportReceiptExtras are the top-level keys of the export receipt.
type exportReceiptExtras struct {
	// Counts tallies the exported items by type (http_record, finding, scan,
	// …) plus total; absent for a format that does not count (fs).
	Counts map[string]int `json:"counts,omitempty"`
}

func exportFileViews(outputs []exportedFile) []exportFileView {
	views := make([]exportFileView, 0, len(outputs))
	for _, o := range outputs {
		views = append(views, exportFileView{Format: o.label, Path: receiptPath(o.path), Detail: o.detail})
	}
	return views
}

// receiptPath is a written file's path as a receipt reports it: absolute for a
// local file, so it does not depend on the caller's working directory; a
// gs:// URL as given.
func receiptPath(p string) string {
	if p == "" || strings.Contains(p, "://") {
		return p
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// emitExportReceipt prints `export -j`: the files written as items, the item
// counts, and the project filter applied. A multi-format run with a failed
// format still lists what landed, with ok:false and the error.
func emitExportReceipt(cmd *cobra.Command, run *exportRun, outputs []exportedFile, failErr error) error {
	views := exportFileViews(outputs)
	opts := []envOpt{withProjectScope(run.projectUUID)}
	if run.countsSet {
		opts = append(opts, withExtra("counts", run.counts.view()))
	}
	if failErr != nil {
		opts = append(opts, withResultFailure(failErr))
	}
	return emitRead(cmd, "", views, int64(len(views)), 0, len(views), opts...)
}

// view renders the tally as {type: n, …, "total": n}.
func (c exportCounts) view() map[string]int {
	out := make(map[string]int, len(c.byType)+1)
	for k, v := range c.byType {
		out[k] = v
	}
	out["total"] = c.total
	return out
}

// exportRun carries the state shared by every format in one `vigolium export`
// invocation: the database handle, the materialized envelope set, and the
// auto-detected report metadata. Each is built at most once, so exporting three
// formats reads the database once instead of three times. fs is the one format
// that does not render from the shared set — writeFSExport streams its own
// record and finding cursors, because queryExportData dedupes and re-sorts rows
// the fs tree is meant to carry verbatim.
//
// Sharing one item slice across renderers is safe because they treat it as
// read-only — the HTML/bundle body trimming rewrites each item's marshaled JSON
// rather than the structs behind it.
type exportRun struct {
	db *database.DB

	// itemsSet and metaSet are needed because both memos have legitimate empty
	// values — an empty database yields no items, and computeReportMeta returns
	// ("","") when it finds no scan row — so the zero value cannot stand in for
	// "not loaded yet". The db handle needs no such flag: openExportDB never
	// returns (nil, nil).
	items    []any
	itemsSet bool

	metaTarget   string
	metaDuration string
	metaSet      bool

	// projectUUID is the project filter every format in this run applies, or ""
	// for the whole database. Resolved once in openDB, after the source is open,
	// so a --project-name lookup hits the source being exported.
	//
	// It used to be hardcoded "" at four call sites, so `export --project-uuid X`
	// exported every project while the {project-uuid} placeholder in -o named X —
	// a file whose name asserted a scope its contents did not have. The default
	// is still whole-DB: `vigolium export` with no project flag is the documented
	// way to dump a store.
	projectUUID string

	// multi records that more than one format was requested, which switches the
	// per-format count blocks off in favor of one unified summary at the end.
	multi bool

	// counts is the last tally a format reported, for the -j receipt.
	counts    exportCounts
	countsSet bool
}

// openDB opens the export database once per run and resolves the project filter
// against it.
//
// The order is load-bearing: resolveProjectUUID looks a --project-name up
// through the opened handle and memoizes the answer for the process, so
// resolving before the source is open would pin a UUID from the default store
// and then filter the exported source by it.
func (r *exportRun) openDB() (*database.DB, error) {
	if r.db != nil {
		return r.db, nil
	}
	db, err := openExportDB()
	if err != nil {
		return nil, err
	}
	r.db = db
	if explicitProjectSelected() {
		if r.projectUUID, err = resolveProjectUUID(); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// loadItems materializes the export envelopes once and reuses them for every
// later format. db may be nil (a modules-only export needs no database).
func (r *exportRun) loadItems(ctx context.Context, db *database.DB) ([]any, error) {
	if r.itemsSet {
		return r.items, nil
	}
	items, err := queryExportData(ctx, db, topExportQuery(r.projectUUID))
	if err != nil {
		return nil, err
	}
	r.items, r.itemsSet = items, true
	return items, nil
}

// reportMeta auto-detects the report target and duration once per run.
func (r *exportRun) reportMeta(ctx context.Context, db *database.DB) (target, duration string) {
	if !r.metaSet {
		r.metaTarget, r.metaDuration = computeReportMeta(ctx, db)
		r.metaSet = true
	}
	return r.metaTarget, r.metaDuration
}

// printStats prints the per-format count block. Suppressed in a multi-format run,
// where every format renders the same result set and the counts are reported once
// by printMultiExportSummary instead.
func (r *exportRun) printStats(format, outputPath string, counts exportCounts) {
	r.counts, r.countsSet = counts, true
	if r.multi {
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s Export summary (format: %s)\n", terminal.InfoSymbol(), terminal.Cyan(format))
	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "  Output: %s\n", terminal.Cyan(outputPath))
	}
	r.printProjectScope()
	printExportTally(counts)
}

// printProjectScope states which project the counts below it cover. Stated
// rather than left to be inferred: the default is the whole database, and an
// operator who expected their active project to apply has no other way to find
// out that it did not.
func (r *exportRun) printProjectScope() {
	if r.projectUUID != "" {
		fmt.Fprintf(os.Stderr, "  Project: %s\n", terminal.Cyan(r.projectUUID))
		return
	}
	fmt.Fprintf(os.Stderr, "  Project: %s\n", terminal.Gray("all (no --project-uuid/--project-name)"))
}

// runFormat materializes one requested format at its resolved path, returning the
// files it wrote for the multi-format summary.
func (r *exportRun) runFormat(ctx context.Context, s exportFormatSpec) ([]exportedFile, error) {
	// fs writes a directory tree rather than a single file, so it is not a gs://
	// upload target and skips the file-oriented output resolution below.
	if s.format == "fs" {
		return r.exportFS(ctx, s.path)
	}

	// Resolve gs:// outputs to a temp file plus an uploader.
	localPath, finalize, err := resolveExportOutput(ctx, s.path)
	if err != nil {
		return nil, err
	}

	var outs []exportedFile
	switch s.format {
	case "jsonl":
		outs, err = r.exportJSONL(ctx, localPath)
	case "bundle":
		outs, err = r.exportBundle(ctx, localPath)
	default:
		outs, err = r.exportReport(ctx, s.format, localPath)
	}
	if err != nil {
		return nil, err
	}
	if err := finalize(); err != nil {
		return nil, err
	}
	// A gs:// destination wrote through a temp file; report where the user asked
	// for it, not the scratch path finalize() has already uploaded and removed.
	if localPath != s.path {
		for i := range outs {
			outs[i].path = s.path
		}
	}
	return outs, nil
}

// exportReport renders one of the document formats (html, report, pdf, markdown)
// from the run's shared item set.
func (r *exportRun) exportReport(ctx context.Context, format, outputPath string) ([]exportedFile, error) {
	rf, ok := reportGenerator(format)
	if !ok {
		return nil, fmt.Errorf("unsupported format %q; valid formats: %s", format, strings.Join(output.Names(output.SurfaceExport), ", "))
	}
	generate, defaultTitle := rf.Render, rf.DefaultTitle
	if rf.NeedsChrome {
		fmt.Fprintf(os.Stderr, "%s Generating %s (headless Chrome)...\n", terminal.InfoSymbol(), rf.Label)
	}

	db, err := r.openDB()
	if err != nil {
		return nil, err
	}
	items, err := r.loadItems(ctx, db)
	if err != nil {
		return nil, err
	}

	title := defaultTitle
	if topExportTitle != "" {
		title = topExportTitle
	}

	autoTarget, autoDuration := r.reportMeta(ctx, db)

	duration := autoDuration
	if topExportDuration != "" {
		duration = topExportDuration
	}
	target := autoTarget
	if topExportTarget != "" {
		target = topExportTarget
	}

	meta := output.HTMLReportMeta{
		Title:           title,
		Version:         getVersion(),
		ScanDuration:    duration,
		ScanTarget:      target,
		GeneratedAt:     topExportGeneratedAt,
		ReportSharedURL: topExportReportURL,
	}
	applyReportFlags(&meta, false)
	if err := generate(items, outputPath, meta); err != nil {
		return nil, err
	}
	r.printStats(format, outputPath, countExportItems(items))
	if outputPath == "" {
		return nil, nil // streamed to stdout (github); nothing to list
	}
	return []exportedFile{{label: format, path: outputPath}}, nil
}

// reportGenerator resolves a document/report format (alias-aware,
// case-insensitive) to its row in the output format table, renderer bound. It
// is shared by `vigolium export` and the `vigolium import --format <fmt> -o
// <file>` post-import shortcut, so both render through the same table; each
// caller checks its own surface (output.Lookup) before rendering.
func reportGenerator(format string) (output.OutputFormat, bool) {
	f, ok := output.FormatByName(format)
	if !ok || f.Kind != output.KindReport || f.Render == nil {
		return output.OutputFormat{}, false
	}
	return f, true
}

// computeReportMeta auto-detects scanTarget and scanDuration from the database,
// within projectUUID ("" = every project). It checks agentic_scans first, then
// falls back to the scans table. When multiple rows exist, target becomes
// "multiple" and duration "N/A".
func computeReportMeta(ctx context.Context, db *database.DB) (target, duration string) {
	// Try agentic_scans first.
	var agenticScans []database.AgenticScan
	err := db.NewSelect().Model(&agenticScans).
		Column("target_url", "duration_ms", "started_at", "completed_at").
		Where("status IN (?)", bun.List(database.CompletedAgenticScanStatuses)).
		OrderExpr("created_at DESC").
		Limit(2).
		Scan(ctx)
	if err == nil && len(agenticScans) > 0 {
		if len(agenticScans) == 1 {
			target = agenticScans[0].TargetURL
			if agenticScans[0].DurationMs > 0 {
				d := time.Duration(agenticScans[0].DurationMs) * time.Millisecond
				duration = d.Round(time.Second).String()
			}
		} else {
			target = "multiple"
			duration = "N/A"
		}
		return
	}

	// Fall back to native scans.
	var scans []database.Scan
	err = db.NewSelect().Model(&scans).
		Column("target", "started_at", "finished_at").
		Where("status = ?", "completed").
		OrderExpr("created_at DESC").
		Limit(2).
		Scan(ctx)
	if err == nil && len(scans) > 0 {
		if len(scans) == 1 {
			target = scans[0].Target
			if !scans[0].FinishedAt.IsZero() {
				d := scans[0].FinishedAt.Sub(scans[0].StartedAt)
				if d > 0 {
					duration = d.Round(time.Second).String()
				}
			}
		} else {
			target = "multiple"
			duration = "N/A"
		}
	}
	return
}

// exportJSONL writes the run's shared item set as JSONL, to outputPath or stdout.
func (r *exportRun) exportJSONL(ctx context.Context, outputPath string) ([]exportedFile, error) {
	// Modules don't need DB access, so handle the modules-only case without opening DB.
	var db *database.DB
	if exportNeedsDB() {
		var err error
		if db, err = r.openDB(); err != nil {
			return nil, err
		}
	}

	// Materialize only when another format in this run will need the same set
	// anyway (loadItems is the memo that keeps a multi-format run to one database
	// read). On its own, jsonl has no reason to hold the result set: it writes
	// each envelope out in the order it is read, so streaming turns a peak
	// proportional to the whole corpus into a constant one. On an 854-file glob
	// that is the difference between a 6.1 GB peak and a few hundred MB.
	var items []any
	streaming := !r.multi && !r.itemsSet
	if !streaming {
		var err error
		if items, err = r.loadItems(ctx, db); err != nil {
			return nil, err
		}
	}

	// write produces the whole document into w. Shared by the stdout and the -o
	// branch so the bytes cannot drift between them; it reports the counts the
	// summary prints.
	write := func(w io.Writer) (exportCounts, error) {
		if streaming {
			counts, err := streamJSONLWithQuery(ctx, db, w, topExportQuery(r.projectUUID))
			if err != nil {
				return counts, err
			}
			return counts, nil
		}
		if _, err := encodeJSONL(w, items); err != nil {
			return exportCounts{}, err
		}
		return countExportItems(items), nil
	}

	// Stdout has nothing to protect: there is no previous artifact and no
	// partially-published file, so a failure mid-stream is just a truncated pipe
	// the exit code already reports. Buffered all the same, so a streamed export
	// costs one write(2) per buffer rather than one per record — which is what
	// the -o branch already gets from atomicfile's *bufio.Writer.
	if outputPath == "" {
		out := bufio.NewWriter(os.Stdout)
		counts, err := write(out)
		if err != nil {
			return nil, fmt.Errorf("failed to encode record: %w", err)
		}
		if err := out.Flush(); err != nil {
			return nil, fmt.Errorf("failed to write export: %w", err)
		}
		r.printStats("jsonl", "", counts)
		return nil, nil // streamed to stdout; nothing to list
	}

	// A named output is staged and renamed. os.Create truncated before the first
	// query ran, so a read failure — now that reads are strict — destroyed the
	// previous export and left a partial file a consumer could not tell from a
	// complete one. 0o666 under the umask reproduces os.Create's mode exactly.
	var counts exportCounts
	if err := atomicfile.WriteFile(outputPath, 0o666, func(w *bufio.Writer) error {
		var werr error
		counts, werr = write(w)
		return werr
	}); err != nil {
		return nil, fmt.Errorf("export jsonl %s: %w", outputPath, err)
	}
	r.printStats("jsonl", outputPath, counts)
	return []exportedFile{{label: "jsonl", path: outputPath}}, nil
}

// exportCounts is the per-type tally behind the export summary. It is a value
// rather than something derived from the item slice so the streaming path — which
// never holds that slice — reports the identical block.
type exportCounts struct {
	byType map[string]int
	total  int
}

func newExportCounts() exportCounts {
	return exportCounts{byType: make(map[string]int)}
}

// add records one emitted envelope.
func (c *exportCounts) add(item any) {
	if env, ok := item.(exportEnvelope); ok {
		c.byType[env.Type]++
	}
	c.total++
}

// countExportItems tallies an already-materialized item slice, for the formats
// that render from one.
func countExportItems(items []any) exportCounts {
	counts := newExportCounts()
	for _, item := range items {
		counts.add(item)
	}
	return counts
}

// printExportTally prints a counted tally in the stable type order.
func printExportTally(counts exportCounts) {
	typeOrder := []struct{ key, label string }{
		{"http_record", "HTTP records"},
		{"finding", "Findings"},
		{"scan", "Scans"},
		{"module", "Modules"},
		{"oast_interaction", "OAST interactions"},
		{"source_repo", "Source repos"},
		{"scope", "Scopes"},
	}
	for _, t := range typeOrder {
		if c, ok := counts.byType[t.key]; ok && c > 0 {
			fmt.Fprintf(os.Stderr, "  %-20s %d\n", t.label, c)
		}
	}
	fmt.Fprintf(os.Stderr, "  %-20s %d\n", "Total", counts.total)
}

// printMultiExportSummary reports a multi-format run once: the shared item counts,
// then every file written listed under one "Exports" header (reusing the scan
// commands' summary renderer).
func printMultiExportSummary(formats []string, items []any, outputs []exportedFile, scope func()) {
	if len(outputs) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s Export summary (formats: %s)\n", terminal.InfoSymbol(), terminal.Cyan(strings.Join(formats, ", ")))
	scope()
	printExportTally(countExportItems(items))
	printExportSummary(outputs)
}

// exportFS writes the whole DB to a flat <base>-traffic/ + <base>-findings/
// filesystem tree (the `fs` format). Honors --search, --severity, --limit, and
// --omit-response; defaults the base to "vigolium" in the cwd when no -o is set.
func (r *exportRun) exportFS(ctx context.Context, outputPath string) ([]exportedFile, error) {
	db, err := r.openDB()
	if err != nil {
		return nil, err
	}

	var severities []string
	if topExportSeverity != "" {
		severities = strings.Split(topExportSeverity, ",")
	}
	filters := database.QueryFilters{
		ProjectUUID: r.projectUUID,
		FuzzyTerm:   topExportSearch,
		Severity:    severities,
		Limit:       topExportLimit,
	}
	stats, err := writeFSExport(ctx, db, filters, outputPath, fsExportOptions{omitResponse: topExportOmitResponse})
	if err != nil {
		return nil, err
	}
	if !r.multi {
		fsPrintSummary(stats)
	}
	return fsExportOutputs(stats), nil
}

// queryExportData collects the envelopes of q into a slice ready for
// serialization, for the formats that render from one.
func queryExportData(ctx context.Context, db *database.DB, q exportQuery) ([]any, error) {
	var items []any
	err := streamExportData(ctx, db, q, func(item any) error {
		items = append(items, item)
		return nil
	})
	return items, err
}

// streamExportData emits every export envelope to emit() as soon as it is read
// from the database, so the full result set never lives in memory at once.
// queryExportData is now a thin collector over this, so streamed output is
// byte-identical to the legacy materialized path: same envelope order (scans,
// http_records, findings, modules, oast, scopes), same per-row shape, same
// URL-dedup and --exclude semantics. The two large tables (http_records,
// findings) are read with a row cursor — only one row is live at a time; the
// small tables are loaded then emitted.
//
// Reads are strict: a query, row-scan or cursor error anywhere in the stream
// aborts the export and is returned. It used to warn and continue, which meant
// a table that could not be read produced an export silently missing it — a
// consumer reading that file has no way to tell "this scan found no findings"
// from "the findings table could not be read", and the artifact it publishes is
// indistinguishable from a complete one. An error returned by emit (a
// downstream write failure) is likewise fatal and propagated immediately.
//
// The one thing still reported rather than returned is the host-facts
// missing-count notice below: those facts are decoration on records that were
// themselves read successfully, so their absence is incompleteness to announce,
// not a failed read.
//
// When q.omitResponse is true the bulky raw_request/raw_response columns are
// not selected for http_records (honoring an explicit --omit-response). Report
// renderers must NOT force this on: they derive the displayed request/response
// bodies from the raw bytes via HTTPRecord.MarshalJSON before trimming the
// redundant raw copies, so excluding the columns blanks the report body.
func streamExportData(ctx context.Context, db *database.DB, q exportQuery, emit func(any) error) error {
	scope, projectUUID, scanUUID := q.scope, q.projectUUID, q.scanUUID
	emitItem := func(typ string, data any) error {
		return emit(exportEnvelope{Type: typ, Data: data})
	}

	// --- Scans ---
	if scope.includes("scans") && db != nil {
		var scans []*database.Scan
		sq := scopeProjectBun(db.NewSelect().Model(&scans).OrderExpr("created_at DESC"), projectUUID)
		// A scan-scoped export (the post-scan report/jsonl of one run) carries
		// only that run's scan row, not every scan the project ever ran.
		if scanUUID != "" {
			sq = sq.Where("uuid = ?", scanUUID)
		}
		if q.search != "" {
			p := database.LikeContains(q.search)
			sq = sq.Where(database.WithLikeEscape("(uuid LIKE ? OR status LIKE ? OR error_message LIKE ?)"), p, p, p)
		}
		sq = q.limitQuery(q.timeRange(sq, "created_at"))
		if err := sq.Scan(ctx); err != nil {
			return fmt.Errorf("export scans: %w", err)
		}
		for _, s := range scans {
			if err := emitItem("scan", s); err != nil {
				return err
			}
		}
	}

	// --- HTTP Records (cursor-streamed) ---
	if scope.includes("http") && db != nil {
		if err := streamHTTPRecords(ctx, db, q, emitItem); err != nil {
			return err
		}
	}

	// --- Findings (cursor-streamed) ---
	if scope.includes("findings") && db != nil {
		if err := streamFindings(ctx, db, q, emitItem); err != nil {
			return err
		}
	}

	// --- Modules (in-memory registry, no DB needed) ---
	if scope.includes("modules") {
		emCfg := loadEnabledModulesConfig()

		for _, m := range modules.GetActiveModules() {
			entry := moduleJSONEntry{
				ID:                   m.ID(),
				Name:                 m.Name(),
				Type:                 "active",
				Description:          m.Description(),
				ShortDescription:     m.ShortDescription(),
				ConfirmationCriteria: m.ConfirmationCriteria(),
				Severity:             m.Severity().String(),
				Confidence:           m.Confidence().String(),
				ScanScope:            scanScopeNames(m.ScanScopes()),
				Enabled:              emCfg.ActiveEnabled(m.ID()),
			}
			if err := emitItem("module", entry); err != nil {
				return err
			}
		}
		for _, m := range modules.GetPassiveModules() {
			entry := moduleJSONEntry{
				ID:                   m.ID(),
				Name:                 m.Name(),
				Type:                 "passive",
				Description:          m.Description(),
				ShortDescription:     m.ShortDescription(),
				ConfirmationCriteria: m.ConfirmationCriteria(),
				Severity:             m.Severity().String(),
				Confidence:           m.Confidence().String(),
				ScanScope:            scanScopeNames(m.ScanScopes()),
				Enabled:              emCfg.PassiveEnabled(m.ID()),
			}
			if err := emitItem("module", entry); err != nil {
				return err
			}
		}
	}

	// --- OAST Interactions ---
	if scope.includes("oast") && db != nil {
		var interactions []*database.OASTInteraction
		sq := scopeProjectBun(db.NewSelect().Model(&interactions).OrderExpr("interacted_at DESC"), projectUUID)
		if q.search != "" {
			p := database.LikeContains(q.search)
			sq = sq.Where(database.WithLikeEscape("(protocol LIKE ? OR module_id LIKE ? OR unique_id LIKE ? OR full_id LIKE ? OR target_url LIKE ?)"), p, p, p, p, p)
		}
		sq = q.limitQuery(q.timeRange(sq, "interacted_at"))
		if err := sq.Scan(ctx); err != nil {
			return fmt.Errorf("export oast interactions: %w", err)
		}
		for _, i := range interactions {
			if err := emitItem("oast_interaction", i); err != nil {
				return err
			}
		}
	}

	// --- Scopes ---
	if scope.includes("scopes") && db != nil {
		var scopes []*database.Scope
		sq := scopeProjectBun(db.NewSelect().Model(&scopes).Where("enabled = ?", true).OrderExpr("priority ASC"), projectUUID)
		if q.search != "" {
			p := database.LikeContains(q.search)
			sq = sq.Where(database.WithLikeEscape("(name LIKE ? OR host_pattern LIKE ? OR path_pattern LIKE ?)"), p, p, p)
		}
		sq = q.limitQuery(sq)
		if err := sq.Scan(ctx); err != nil {
			return fmt.Errorf("export scopes: %w", err)
		}
		for _, s := range scopes {
			if err := emitItem("scope", s); err != nil {
				return err
			}
		}
	}

	return nil
}

// findingReferencedRecordUUIDs returns the set of http_record UUIDs that at least
// one finding links to (via finding_records), scoped to projectUUID (empty =
// whole DB). These records are a finding's exact proof exchange, so streamHTTPRecords
// must never drop them in its per-URL dedup. The subquery form is
// dialect-agnostic (SQLite and PostgreSQL).
//
// Strict: a read failure is returned rather than degraded into an empty set.
// Falling back to plain URL-dedup looks harmless but silently drops the exact
// attack exchanges findings cite, which is the one class of record an export
// exists to carry.
func findingReferencedRecordUUIDs(ctx context.Context, db *database.DB, projectUUID string) (map[string]struct{}, error) {
	referenced := make(map[string]struct{})
	if db == nil {
		return referenced, nil
	}
	sqlText := "SELECT DISTINCT record_uuid FROM finding_records WHERE finding_id IN (SELECT id FROM findings"
	var args []any
	if projectUUID != "" {
		sqlText += " WHERE project_uuid = ?"
		args = append(args, projectUUID)
	}
	sqlText += ")"
	var uuids []string
	if err := db.NewRaw(sqlText, args...).Scan(ctx, &uuids); err != nil {
		return nil, fmt.Errorf("load finding-referenced records: %w", err)
	}
	for _, u := range uuids {
		referenced[u] = struct{}{}
	}
	return referenced, nil
}

// streamHTTPRecords reads http_records with a row cursor and emits one envelope
// per unique URL (first occurrence wins, matching the legacy in-memory dedup),
// holding only a single record in memory at a time. The one exception: a record
// that a finding links to is ALWAYS emitted, even when another record already
// claimed its URL — otherwise the per-URL dedup could drop the exact attack
// exchange a finding proves, leaving replay/Burp/report evidence pointing at a
// different same-URL record. `export --no-url-dedup` turns the collapse off
// entirely, which also makes the finding-reference lookup unnecessary.
//
// omitResponse drops the raw_request/raw_response columns from the SELECT
// entirely. Reads are strict: a query, row-scan or cursor error is returned.
func streamHTTPRecords(ctx context.Context, db *database.DB, q exportQuery, emitItem func(string, any) error) error {
	projectUUID, scanUUID := q.projectUUID, q.scanUUID
	qb := database.NewQueryBuilder(db, database.QueryFilters{
		ProjectUUID: projectUUID,
		FuzzyTerm:   q.search,
		Limit:       q.limit,
		DateFrom:    q.from,
		DateTo:      q.to,
	})
	if q.omitResponse {
		qb = qb.OmitBodies()
	}
	query := qb.BuildRecordsQuery()
	// A scan-scoped export (the post-scan jsonl/report of one run) carries the
	// exchanges that run stored plus the evidence its findings cite, not every
	// record the project ever accumulated. `vigolium export` passes "".
	if scanUUID != "" {
		query = database.WhereScanRecords(query, scanUUID)
	}
	rows, err := query.Rows(ctx)
	if err != nil {
		return fmt.Errorf("export http records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Only needed to protect proof exchanges from the dedup; with the dedup off
	// every record is emitted anyway, so the query is skipped rather than run and
	// ignored.
	var referenced map[string]struct{}
	if !q.noURLDedup {
		if referenced, err = findingReferencedRecordUUIDs(ctx, db, projectUUID); err != nil {
			return err
		}
	}

	// The run's stored host observations, loaded once for the whole pass.
	//
	// Previously each record's DNS/TLS facts were read straight out of the
	// process caches at emit time, which made the output depend on what those
	// bounded caches still held: on a sweep past 8192 hosts the ones resolved
	// first had been evicted, so their facts were silently absent from an export
	// of the very run that resolved them. The stored rows do not evict, and they
	// also answer for a process that did no probing at all - an `export` of a
	// database someone else's scan wrote.
	facts := database.NewStoredHostFacts(ctx, database.NewRepository(db), projectUUID, scanUUID)

	seen := make(map[string]struct{})
	for rows.Next() {
		r := new(database.HTTPRecord)
		if err := db.ScanRow(ctx, rows, r); err != nil {
			return fmt.Errorf("export http records: scan row: %w", err)
		}
		if !q.noURLDedup {
			// A finding-referenced record is that finding's proof — emit it even
			// when its URL was already claimed by an earlier (non-attack) record.
			_, isReferenced := referenced[r.UUID]
			if _, dup := seen[r.URL]; dup && !isReferenced {
				continue
			}
			seen[r.URL] = struct{}{}
		}
		// WithFacts, not the bare record: this is the export of a run that may
		// have resolved/probed the hosts it recorded. A process with neither
		// stored observations nor a warm cache gets the bare record back
		// unchanged.
		if err := emitItem("http_record", database.WithFacts(facts, r)); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("export http records: %w", err)
	}
	// Incompleteness is reported rather than left to be inferred from absent
	// keys. HostFacts.Empty() collapses "never probed", "probed and genuinely
	// empty" and "probed then lost", and only saying so distinguishes an export
	// that is missing data from hosts that had none.
	if n := facts.MissingCount(); n > 0 && facts.Stored() > 0 {
		fmt.Fprintf(os.Stderr, "%s %d endpoint(s) exported without host facts (no stored observation and nothing cached)\n",
			terminal.WarningSymbol(), n)
	}
	return nil
}

// streamFindings reads findings with a row cursor and emits one envelope per
// row, holding only a single finding in memory at a time. Filters mirror the
// legacy findings query exactly (search, severity, limit, found_at DESC).
// Reads are strict: a query, row-scan or cursor error is returned.
func streamFindings(ctx context.Context, db *database.DB, eq exportQuery, emitItem func(string, any) error) error {
	scanUUID := eq.scanUUID
	q := scopeProjectBun(db.NewSelect().Model((*database.Finding)(nil)).OrderExpr("found_at DESC"), eq.projectUUID)
	// Confirmed findings only. E0 observations / E1 candidates are persisted in
	// the same table but must not surface in a report's "Findings" section as if
	// they were confirmed vulnerabilities — mirror the default record_kind guard
	// the FindingsQueryBuilder applies everywhere else (query.go applyFindingFilters).
	q = q.Where("(f.record_kind IS NULL OR f.record_kind = '' OR f.record_kind = ?)", database.RecordKindFinding)
	// Post-scan report scope: restrict to the current scan's findings so a re-run's
	// report reflects that run, not the project's whole history. maybeGenerateReports
	// and finishScanJSONLExport pass the scan uuid; `vigolium export` passes ""
	// (project-wide), parallel to how projectUUID is threaded.
	// A finding the scan re-detected counts even when a dedup merge kept an
	// older row (see database.QueryFilters.ObservedInScan).
	if scanUUID != "" {
		q = q.Where("(f.scan_uuid = ? OR EXISTS (SELECT 1 FROM finding_observations o WHERE o.finding_id = f.id AND o.scan_uuid = ?))", scanUUID, scanUUID)
	}
	if eq.search != "" {
		p := database.LikeContains(eq.search)
		q = q.Where(database.WithLikeEscape("(module_id LIKE ? OR module_name LIKE ? OR description LIKE ? OR matched_at LIKE ? OR severity LIKE ? OR url LIKE ? OR hostname LIKE ? OR extracted_results LIKE ?)"), p, p, p, p, p, p, p, p)
	}
	if len(eq.severity) > 0 {
		q = q.Where("LOWER(severity) IN (?)", bun.List(eq.severity))
	}
	q = eq.limitQuery(eq.timeRange(q, "f.found_at"))
	rows, err := q.Rows(ctx)
	if err != nil {
		return fmt.Errorf("export findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		f := new(database.Finding)
		if err := db.ScanRow(ctx, rows, f); err != nil {
			return fmt.Errorf("export findings: scan row: %w", err)
		}
		if err := emitItem("finding", f); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("export findings: %w", err)
	}
	return nil
}
