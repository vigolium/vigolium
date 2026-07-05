package cli

import (
	"context"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/database"
)

// scanPrintTraffic and scanPrintTrafficTree back the --print-traffic and
// --print-traffic-tree flags on the native scan commands (scan, scan-url,
// scan-request, run). They mirror --print-finding (see scanPrintFinding): after
// the scan completes, the run's HTTP traffic is rendered to stdout — either as
// the host/path hierarchy tree (--print-traffic-tree, same view as `vigolium
// traffic --tree`) or the raw request/response dump (--print-traffic, same view
// as `vigolium traffic --raw`), inline, with no follow-up command needed. Both
// force the scan through the Runner path (see needsRunnerScan) so the traffic
// lands in a database to render from, which the fast in-memory direct path does
// not provide. Both may be set together (tree printed first, then raw).
var (
	scanPrintTraffic     bool
	scanPrintTrafficTree bool
)

// maybePrintScanTraffic renders this scan's HTTP traffic to stdout when
// --print-traffic and/or --print-traffic-tree is set. Records carry no
// scan_uuid, so the traffic is scoped by project — exactly this run's records
// in a stateless temp DB (the intended pairing, like --print-finding), or the
// whole project's traffic in a shared DB. It reuses displayTree / displayRaw
// (the `traffic --tree` / `traffic --raw` renderers) so the output is identical.
// A no-op when both flags are off, no DB is available, or the scan produced no
// traffic.
func maybePrintScanTraffic(ctx context.Context, db *database.DB, projectUUID string) {
	if !hasPrintTrafficFlags() || db == nil {
		return
	}
	records, err := database.NewQueryBuilder(db, database.QueryFilters{
		ProjectUUID: projectUUID,
	}).Execute(ctx)
	if err != nil {
		zap.L().Warn("print-traffic: failed to query traffic", zap.Error(err))
		return
	}
	if len(records) == 0 {
		return
	}
	if scanPrintTrafficTree {
		if err := displayTree(records); err != nil {
			zap.L().Warn("--print-traffic-tree: failed to render traffic", zap.Error(err))
		}
	}
	if scanPrintTraffic {
		if err := displayRaw(records); err != nil {
			zap.L().Warn("--print-traffic: failed to render traffic", zap.Error(err))
		}
	}
}

// hasPrintTrafficFlags reports whether either post-scan traffic printer was
// requested. Grouping the pair keeps needsRunnerScan and maybePrintScanTraffic's
// guard from spelling out the same disjunction (and its negation) in two shapes.
func hasPrintTrafficFlags() bool {
	return scanPrintTraffic || scanPrintTrafficTree
}
