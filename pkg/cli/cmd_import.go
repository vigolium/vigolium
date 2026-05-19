package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var importCmd = &cobra.Command{
	Use:   "import <path|gs://...>",
	Short: "Import scan data from archon output folder, JSONL, or compressed archive",
	Long: `Import scan data into the database from various sources.

Supported inputs:
  - Archon output folder: contains audit-state.json and findings-draft/
  - JSONL file: exported data with {"type": "...", "data": {...}} envelopes
    Supports http_record and finding types (e.g. from 'vigolium export --format jsonl')
  - .tar.gz / .tgz / .zip archive containing either of the above
  - gs://<project-uuid>/<key> URL to any of the above (downloaded then imported)

Use --upload to push the local source to cloud storage after a successful import,
or --upload-key=<key> to choose an explicit storage key (folders are bundled to
tar.gz unless the key ends in .zip).

Use --format with -o/--output to write a report in the same step, e.g.
'vigolium import ./archon --format html -o archon-report.html'. This replaces
the import-then-export two-step: when the import created an archon audit the
report is scoped to that audit's findings. Formats mirror 'vigolium export':
html, report, pdf, markdown (alias md).`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	importCmd.Flags().Bool("upload", false, "Upload the local import source to cloud storage after import")
	importCmd.Flags().String("upload-key", "", "Explicit storage key for --upload (default: imports/<basename>-<ts>.<ext>)")
	importCmd.Flags().String("format", "", "Also write a report after import: html, report, pdf, or markdown (md). Mirrors `vigolium export --format`.")
	importCmd.Flags().StringP("output", "o", "", "Report output path or gs://<project>/<key> URL (required when --format is set; supports {ts})")
	rootCmd.AddCommand(importCmd)
}

func runImport(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	ctx := context.Background()
	// Normalize "gcs://" (alias) to canonical "gs://" so the downstream
	// HasPrefix checks and DB-stored StorageURL stay consistent.
	inputArg := storage.NormalizeGCSURI(args[0])
	upload, _ := cmd.Flags().GetBool("upload")
	uploadKey, _ := cmd.Flags().GetString("upload-key")
	if uploadKey != "" {
		upload = true
	}
	if upload && strings.HasPrefix(inputArg, "gs://") {
		fmt.Fprintf(os.Stderr, "%s --upload is ignored when input is already in cloud storage\n", terminal.WarningSymbol())
		upload = false
	}

	// Validate report flags up front so a typo fails before the import work,
	// not after it has already mutated the database.
	reportFormat, _ := cmd.Flags().GetString("format")
	reportOutput, _ := cmd.Flags().GetString("output")
	if reportFormat != "" {
		if _, _, ok := reportGenerator(reportFormat); !ok {
			return fmt.Errorf("--format %q is not a report format; use html, report, pdf, or markdown", reportFormat)
		}
		if reportOutput == "" {
			return fmt.Errorf("--format %s requires -o/--output for the report path", reportFormat)
		}
	}

	localPath, cleanup, err := resolveImportInput(ctx, inputArg)
	if err != nil {
		return err
	}
	defer cleanup()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	repo := database.NewRepository(db)

	opts := dbimport.Options{
		OriginalSource:     inputArg,
		SessionDirArchiver: cliSessionDirArchiver,
	}

	result, err := dbimport.ImportPath(ctx, repo, localPath, projectUUID, opts)
	if err != nil {
		return err
	}
	printImportResult(localPath, result)

	if reportFormat != "" {
		if err := emitImportReport(ctx, db, result, reportFormat, reportOutput); err != nil {
			return fmt.Errorf("import succeeded but report generation failed: %w", err)
		}
	}

	if upload {
		uploadSrc := inputArg
		if strings.HasPrefix(inputArg, "gs://") {
			uploadSrc = localPath
		}
		url, err := uploadImportSource(ctx, uploadSrc, uploadKey)
		if err != nil {
			return fmt.Errorf("import succeeded but upload failed: %w", err)
		}
		fmt.Printf("%s Source uploaded to %s\n", terminal.SuccessSymbol(), terminal.Gray(url))
	}
	return nil
}

// cliSessionDirArchiver copies an archon source folder into the per-run agent
// session directory keyed by scan UUID and returns the resulting session dir.
// Best-effort: failures are logged to stderr and result in an empty return so
// the import still completes. Mirrors the prior in-CLI helper.
func cliSessionDirArchiver(scanUUID, srcDir string) (string, error) {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}
	sessionDir, err := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), scanUUID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create session dir for %s: %v\n", terminal.WarningSymbol(), scanUUID, err)
		return "", nil
	}
	dst := filepath.Join(sessionDir, "archon")
	if entries, statErr := os.ReadDir(dst); statErr == nil && len(entries) > 0 {
		fmt.Fprintf(os.Stderr, "%s Session dir %s already populated; skipping copy\n", terminal.WarningSymbol(), dst)
		return sessionDir, nil
	}
	if err := dbimport.CopyDirContents(srcDir, dst); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to copy archon source into session dir: %v\n", terminal.WarningSymbol(), err)
		return "", nil
	}
	return sessionDir, nil
}

// printImportResult renders a CLI summary for the import (JSON when -j, human
// otherwise). The shape mirrors the pre-refactor format so existing
// CLI consumers and tests don't break.
func printImportResult(localPath string, r *dbimport.Result) {
	if r == nil {
		return
	}

	if globalJSON {
		out := map[string]interface{}{}
		if uuid := r.AgenticScanUUID(); uuid != "" {
			out["agentic_scan_uuid"] = uuid
		}
		if r.RecordsImported > 0 {
			out["records_imported"] = r.RecordsImported
		}
		out["findings_total"] = r.FindingsTotal
		out["findings_saved"] = r.FindingsSaved
		out["findings_skipped"] = r.FindingsSkipped
		if len(r.SeverityCounts) > 0 {
			out["severity"] = r.SeverityCounts
		}
		if r.ParseErrors > 0 {
			out["parse_errors"] = r.ParseErrors
		}
		if r.SessionDir != "" {
			out["session_dir"] = r.SessionDir
		}
		if r.StorageURL != "" {
			out["storage_url"] = r.StorageURL
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}

	fmt.Fprint(os.Stderr, GetBanner())
	if r.AgenticScan != nil {
		scan := r.AgenticScan
		fmt.Printf("%s Imported archon audit: %d findings (%d new, %d duplicates skipped)\n",
			terminal.SuccessSymbol(), r.FindingsTotal, r.FindingsSaved, r.FindingsSkipped)
		fmt.Printf("  Agent run: %s (mode=%s, status=%s)\n", scan.UUID, scan.Mode, scan.Status)
		if scan.TargetURL != "" {
			fmt.Printf("  Target:   %s\n", terminal.BoldCyan(scan.TargetURL))
		}
		if scan.Model != "" {
			fmt.Printf("  Model:    %s\n", terminal.Cyan(scan.Model))
		}
	} else {
		fmt.Printf("%s Imported JSONL data from %s\n", terminal.SuccessSymbol(), localPath)
		if r.RecordsImported > 0 {
			fmt.Printf("  HTTP records: %d imported\n", r.RecordsImported)
		}
		if r.FindingsTotal > 0 {
			fmt.Printf("  Findings: %d total (%d new, %d duplicates skipped)\n", r.FindingsTotal, r.FindingsSaved, r.FindingsSkipped)
		}
	}

	if sev := r.SeverityCounts; sev["high"] > 0 || sev["critical"] > 0 || sev["medium"] > 0 || sev["low"] > 0 {
		fmt.Printf("  Severity: %s, %s, %s, %s\n",
			terminal.BoldMagenta(fmt.Sprintf("%d critical", sev["critical"])),
			terminal.BoldRed(fmt.Sprintf("%d high", sev["high"])),
			terminal.BoldYellow(fmt.Sprintf("%d medium", sev["medium"])),
			terminal.BoldGreen(fmt.Sprintf("%d low", sev["low"])),
		)
	}
	if r.SessionDir != "" {
		fmt.Printf("  Session:  %s\n", terminal.Gray(r.SessionDir))
	}
	if r.StorageURL != "" {
		fmt.Printf("  Storage:  %s\n", terminal.Gray(r.StorageURL))
	}
	if r.ParseErrors > 0 {
		fmt.Printf("  %s %d lines could not be parsed\n", terminal.WarningSymbol(), r.ParseErrors)
	}
	for typ, count := range r.SkippedTypes {
		fmt.Printf("  Skipped %d %q entries\n", count, typ)
	}
}

// emitImportReport renders a static report for the data just imported, reusing
// the exact generators behind `vigolium export` (single source of truth via
// reportGenerator). When the import created an archon AgenticScan the report is
// scoped to that audit's findings; otherwise it falls back to all findings in
// the project DB. This collapses the historical import-then-export two-step
// into one command.
func emitImportReport(ctx context.Context, db *database.DB, result *dbimport.Result, format, outputArg string) error {
	gen, defaultTitle, ok := reportGenerator(format)
	if !ok {
		return fmt.Errorf("unsupported report format %q", format)
	}

	localOutput, finalize, err := resolveExportOutput(ctx, outputArg)
	if err != nil {
		return err
	}

	scanUUID := result.AgenticScanUUID()
	var findings []*database.Finding
	q := db.NewSelect().Model(&findings).OrderExpr("found_at DESC")
	if scanUUID != "" {
		q = q.Where("agentic_scan_uuid = ?", scanUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return fmt.Errorf("query findings for report: %w", err)
	}
	items := make([]any, 0, len(findings))
	for _, f := range findings {
		items = append(items, exportEnvelope{Type: "finding", Data: f})
	}

	meta := output.HTMLReportMeta{
		Title:   defaultTitle,
		Version: getVersion(),
	}
	if s := result.AgenticScan; s != nil {
		meta.ScanTarget = s.TargetURL
		if meta.ScanTarget == "" {
			meta.ScanTarget = s.SourcePath
		}
		if s.DurationMs > 0 {
			meta.ScanDuration = (time.Duration(s.DurationMs) * time.Millisecond).Round(time.Second).String()
		}
	}

	if format == "pdf" {
		fmt.Fprintf(os.Stderr, "%s Generating PDF report (headless Chrome)...\n", terminal.InfoSymbol())
	}
	if err := gen(items, localOutput, meta); err != nil {
		return err
	}
	if err := finalize(); err != nil {
		return err
	}

	scope := "all findings in project"
	if scanUUID != "" {
		scope = "imported audit " + scanUUID
	}
	fmt.Printf("%s Report written: %s (%d findings, %s, format=%s)\n",
		terminal.SuccessSymbol(), terminal.Cyan(outputArg), len(findings), scope, format)
	return nil
}
