package cli

import (
	"context"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/database"
)

// scanPrintFinding backs the --print-finding flag on the native scan commands
// (scan, scan-url, scan-request, run). When set, the run's findings are rendered
// to stdout as Markdown after the scan completes — the same description + matched
// evidence + request/response (```http fences) view as `vigolium finding
// --markdown`, inline, with no follow-up command needed. It forces the scan
// through the Runner path (see needsRunnerScan) so the findings and their linked
// HTTP records land in a database to render from, which the fast in-memory direct
// path does not provide.
var scanPrintFinding bool

// maybePrintScanFindings renders this scan's findings as Markdown to stdout when
// --print-finding is set. The findings are scoped to the run by project + scan
// UUID, so it renders exactly this scan's results whether they live in a
// stateless temp DB or the shared project DB. It reuses displayFindingsMarkdown
// (the `finding --markdown` renderer), so the linked request/response evidence is
// identical. A no-op when the flag is off, no DB is available, or the scan
// produced no findings — honoring "print the findings if there are any".
func maybePrintScanFindings(ctx context.Context, db *database.DB, projectUUID, scanUUID string) {
	if !scanPrintFinding || db == nil {
		return
	}
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{
		ProjectUUID:    projectUUID,
		ObservedInScan: scanUUID,
	}).Execute(ctx)
	if err != nil {
		zap.L().Warn("--print-finding: failed to query findings", zap.Error(err))
		return
	}
	if len(findings) == 0 {
		return
	}
	if err := displayFindingsMarkdown(ctx, db, findings); err != nil {
		zap.L().Warn("--print-finding: failed to render findings", zap.Error(err))
	}
}
