package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	scanCoverageLimit  int
	scanCoverageOffset int
)

var scanCoverageCmd = &cobra.Command{
	Use:   "coverage <scan>",
	Short: "Which module finished on which record: a scan's dynamic-assessment coverage ledger",
	Long: `List a scan's coverage ledger as (record, module) cells: done is true when
the module finished on that record (scan_record_progress.done_bits, decoded
against the scan's coverage module order, scans.coverage_modules).

Rows are records in record_uuid order, each expanded over the coverage modules
in their stored order. -n/--offset page the cells; total counts them all. A scan
that ran no dynamic assessment has no cells. Per-module totals (calls, requests,
findings, errors, skips by reason) are module_stats on 'scan status -j'.

A scan is a full UUID, a UUID prefix (8+ characters), "latest" or "previous".`,
	Example: FormatExamples(
		"# Which modules finished on which records",
		"vigolium scan coverage 7c0e…-uuid -j",
		"# The next page of cells",
		"vigolium scan coverage 7c0e…-uuid -j -n 500 --offset 500",
	),
	Args: cobra.ExactArgs(1),
	RunE: runScanCoverage,
}

func init() {
	scanCmd.AddCommand(scanCoverageCmd)
	f := scanCoverageCmd.Flags()
	f.IntVarP(&scanCoverageLimit, "limit", "n", 1000, "Return at most N (record, module) cells (0 = all)")
	f.IntVar(&scanCoverageOffset, "offset", 0, "Skip the first N cells (follow output_budget.next_offset)")
}

func runScanCoverage(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	ref := strings.TrimSpace(args[0])
	if ref == "" {
		return usageErrorf("scan coverage needs a scan UUID")
	}
	if scanCoverageLimit < 0 || scanCoverageOffset < 0 {
		return usageErrorf("-n/--limit and --offset must not be negative")
	}
	projectUUID, err := effectiveProjectUUID()
	if err != nil {
		return err
	}
	db, err := openReadDB(globDBSkipSet{Records: true, RecordFileMap: true})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	repo := database.NewRepository(db)
	ctx := context.Background()
	scan, err := repo.ResolveScanRef(ctx, projectUUID, ref)
	if errors.Is(err, database.ErrScanNotFound) {
		return clicommon.NewCodedError(apicontract.CodeScanNotFound, err)
	}
	if err != nil {
		return err
	}
	cells, total, err := repo.ScanCoverage(ctx, scan.ProjectUUID, scan.UUID, scanCoverageOffset, scanCoverageLimit)
	if err != nil {
		return err
	}
	if globalJSON {
		return emitRead(cmd, "", cells, total, scanCoverageOffset, scanCoverageLimit, withDBPath(resolvedReadDBPath()))
	}
	done := 0
	for _, c := range cells {
		if c.Done {
			done++
		}
	}
	_, _ = fmt.Fprintf(os.Stdout, "%s scan %s: %d of %d cells shown, %d done\n",
		terminal.InfoSymbol(), terminal.BoldCyan(scan.UUID), len(cells), total, done)
	for _, c := range cells {
		mark := terminal.Gray("·")
		if c.Done {
			mark = terminal.Green("✓")
		}
		_, _ = fmt.Fprintf(os.Stdout, "  %s %s  %s\n", mark, c.RecordUUID, c.ModuleID)
	}
	return nil
}

// moduleStatsView carries the stored per-module ledger (scans.module_stats)
// onto scan.finished and `scan status -j`; nil when the scan stored none.
func moduleStatsView(stats map[string]database.ModuleStat) map[string]scanevents.ModuleStat {
	if len(stats) == 0 {
		return nil
	}
	out := make(map[string]scanevents.ModuleStat, len(stats))
	for id, s := range stats {
		out[id] = scanevents.ModuleStat{
			Invocations: s.Invocations,
			Requests:    s.Requests,
			Findings:    s.Findings,
			Errors:      s.Errors,
			Skips:       s.Skips,
		}
	}
	return out
}
