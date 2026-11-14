package runner

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/oast"
	"go.uber.org/zap"
)

// daLedger is the dynamic-assessment phase's coverage ledger and tier split.
// Record-major dispatch would give the first records every module within the
// phase deadline and the tail none, and a curtailed run would save nothing for
// the next one. With the ledger the phase runs the cheap in-band tier over
// every record first, then the expensive tier, and records each record ×
// module outcome so a resumed scan picks up where it stopped.
type daLedger struct {
	writer   *database.ProgressWriter
	ordinals map[string]int
	tiers    map[string]int
	maxTier  int
	pass0    []modules.ActiveModule
	pass1    []modules.ActiveModule
}

// pass0Share is the most of the remaining phase deadline the first (cheap)
// pass may take; whatever it does not use is the second pass's.
const pass0Share = 0.6

// isTier0Module reports whether m runs in the first pass: per-host modules,
// and in-band / boolean modules (ModuleClassPriority <= boolean cost) of at
// most moderate intensity. Timing, browser and out-of-band modules, and heavy
// or intrusive ones, run in the second.
func isTier0Module(m modules.ActiveModule) bool {
	if m.ScanScopes().Has(modules.ScanScopeHost) {
		return true
	}
	return modules.ModuleClassPriority(m) <= modkit.ClassCostBoolean &&
		modules.ModuleTierRank(m.Tags()) <= modules.TierRankModerate
}

// splitTiers partitions active modules into the two passes, keeping order.
func splitTiers(active []modules.ActiveModule) (pass0, pass1 []modules.ActiveModule) {
	for _, m := range active {
		if isTier0Module(m) {
			pass0 = append(pass0, m)
		} else {
			pass1 = append(pass1, m)
		}
	}
	return pass0, pass1
}

// prepareDALedger builds the phase's ledger: module ordinals (the scan's
// stored scans.coverage_modules order, extended with any new module so a
// resumed scan's bits keep their meaning), the tier of each active module,
// and the progress writer.
func (r *Runner) prepareDALedger(ctx context.Context, scanUUID string, active []modules.ActiveModule, passive []modules.PassiveModule) *daLedger {
	if r.repository == nil || scanUUID == "" {
		return nil
	}
	stored, err := r.repository.ScanCoverageModules(ctx, scanUUID)
	if err != nil {
		zap.L().Debug("coverage ledger: reading stored module order failed", zap.Error(err))
	}
	ids := append([]string(nil), stored...)
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}
	var added []string
	for _, m := range active {
		if !seen[m.ID()] {
			added = append(added, m.ID())
			seen[m.ID()] = true
		}
	}
	for _, m := range passive {
		if !seen[m.ID()] {
			added = append(added, m.ID())
			seen[m.ID()] = true
		}
	}
	sort.Strings(added)
	ids = append(ids, added...)
	if len(added) > 0 {
		if err := r.repository.SetScanCoverageModules(ctx, scanUUID, ids); err != nil {
			zap.L().Warn("coverage ledger: storing module order failed; ledger disabled for this phase", zap.Error(err))
			return nil
		}
	}

	l := &daLedger{ordinals: make(map[string]int, len(ids)), tiers: make(map[string]int, len(active))}
	for i, id := range ids {
		l.ordinals[id] = i
	}
	l.pass0, l.pass1 = splitTiers(active)
	if len(l.pass0) == 0 {
		// Only expensive modules: one pass at tier 0.
		l.pass0, l.pass1 = l.pass1, nil
	}
	for _, m := range l.pass0 {
		l.tiers[m.ID()] = 0
	}
	for _, m := range l.pass1 {
		l.tiers[m.ID()] = 1
	}
	if len(l.pass1) > 0 {
		l.maxTier = 1
	}
	l.writer = database.NewProgressWriter(r.repository)
	return l
}

func (l *daLedger) spec(runsPassives bool) *core.LedgerSpec {
	return &core.LedgerSpec{Writer: l.writer, Ordinals: l.ordinals, Tiers: l.tiers, MaxTier: l.maxTier, RunsPassives: runsPassives}
}

// runTieredRound runs one feedback round as tier passes over one snapshot
// window: pass 0 (cheap modules, passives, feedback) over every record
// without moving the durable cursor, bounded to pass0Share of the remaining
// phase time; then pass 1 (the rest) over the same window, which commits the
// cursor. Records the ledger shows finished for a pass's tier are skipped, and
// a record's finished modules / passive stage are skipped within a pass.
func (r *Runner) runTieredRound(
	ctx context.Context,
	infra *phaseInfra,
	round int,
	inScopeHosts []database.HostTarget,
	passiveModules []modules.PassiveModule,
	baseCfg core.ExecutorConfig,
	oastService *oast.Service,
	l *daLedger,
) (daRoundResult, error) {
	// Single pass: all active modules at tier 0, committing the cursor.
	if len(l.pass1) == 0 {
		cfg := baseCfg
		cfg.Ledger = l.spec(true)
		src := r.newDASource(infra, inScopeHosts).WithCoverage(0)
		return r.runDAPass(ctx, infra, round, l.pass0, passiveModules, cfg, oastService, src)
	}

	// Pass 0, bounded to a share of the remaining phase time.
	pass0Ctx, cancel0 := ctx, context.CancelFunc(func() {})
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left > 0 {
			pass0Ctx, cancel0 = context.WithTimeout(ctx, time.Duration(float64(left)*pass0Share))
		}
	}
	cfg0 := baseCfg
	cfg0.Ledger = l.spec(true)
	src0 := r.newDASource(infra, inScopeHosts).WithoutCursorCommit().WithCoverage(0)
	res0, err := r.runDAPass(pass0Ctx, infra, round, l.pass0, passiveModules, cfg0, oastService, src0)
	cancel0()
	if err != nil {
		return res0, err
	}
	// Pass 1 reads the ledger: pass 0's rows must be written first.
	l.writer.Flush()
	boundAt, boundID, ok := src0.Bound()
	if !ok {
		return res0, nil // empty window: nothing for pass 1 either
	}
	if ctx.Err() != nil {
		return res0, nil
	}

	// Pass 1 over the same window; it owns the cursor commit. Passives already
	// ran in pass 0 (passive_done), so it runs active modules only.
	cfg1 := baseCfg
	cfg1.Ledger = l.spec(false)
	src1 := r.newDASource(infra, inScopeHosts).WithBound(boundAt, boundID).WithCoverage(1)
	res1, err := r.runDAPass(ctx, infra, round, l.pass1, nil, cfg1, oastService, src1)
	res1.processed += res0.processed
	res1.moduleMetrics = mergeModuleMetrics(res0.moduleMetrics, res1.moduleMetrics)
	return res1, err
}

// close drains the ledger writer at phase end. Nil-safe.
func (l *daLedger) close() {
	if l != nil {
		l.writer.Close()
	}
}

// mergeModuleMetrics adds b's per-module counters into a copy of a.
func mergeModuleMetrics(a, b map[string]stats.ModuleStatsSnapshot) map[string]stats.ModuleStatsSnapshot {
	out := make(map[string]stats.ModuleStatsSnapshot, len(a)+len(b))
	maps.Copy(out, a)
	for id, m := range b {
		cur := out[id]
		cur.Add(m)
		out[id] = cur
	}
	return out
}

// resumeScanRow re-opens an existing scan row for --resume-scan: it must exist
// in this scan's project; its status goes back to running.
func (r *Runner) resumeScanRow(ctx context.Context, scanUUID string) error {
	scan, err := r.repository.GetScanByUUID(ctx, scanUUID)
	if err != nil || scan == nil {
		return fmt.Errorf("--resume-scan %s: scan not found", scanUUID)
	}
	project := r.options.ProjectUUID
	if project == "" {
		project = database.DefaultProjectUUID
	}
	if scan.ProjectUUID != "" && scan.ProjectUUID != project {
		return fmt.Errorf("--resume-scan %s: scan belongs to another project", scanUUID)
	}
	_, err = r.repository.DB().NewUpdate().Model((*database.Scan)(nil)).
		Set("status = ?", "running").
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scanUUID).
		Exec(ctx)
	return err
}
