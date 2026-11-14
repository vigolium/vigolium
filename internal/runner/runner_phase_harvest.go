package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// runExternalHarvestPhase runs external intelligence harvesting as a standalone phase.
//
// The phase never contacts the target. Harvested URLs come from third-party
// archives and are persisted as request-only stubs (has_response=false,
// source=harvest). When a later phase reaches the target, the harvest-probe step
// that follows checks them first (runHarvestProbePhase); whatever survives is
// fetched by those phases with the scan's own session, hooks and limiter. It used to push every archived URL
// through an executor, which fetched a baseline for each one: an unbounded,
// unauthenticated, hook-less GET sweep of the live target from a phase that is
// documented — and planned (SkipsTarget) — as target-silent.
func (r *Runner) runExternalHarvestPhase(ctx context.Context, infra *phaseInfra) error {
	if len(r.options.Targets) == 0 {
		return nil
	}

	phaseStart := time.Now()
	r.harvestStubs = nil

	// The archive queries normally ran here, alone, although they send nothing
	// to the target. When the phase loop started them in the background at
	// scan start (startHarvestPrefetch), join that work instead: the phase then
	// costs only the wait for whatever is still outstanding.
	var (
		src   source.InputSource
		stats func() harvester.Stats
	)
	if p := r.takeHarvestPrefetch(); p != nil {
		err := p.wait(ctx)
		defer p.stop() // closes the drained archive source
		if err != nil {
			return fmt.Errorf("external harvest: read source: %w", err)
		}
		if p.src == nil {
			zap.L().Warn("ExternalHarvest: no source could be built, skipping")
			return nil
		}
		src, stats = p.replay(), p.src.Stats
	} else {
		built := r.buildExternalHarvesterSource()
		if built == nil {
			zap.L().Warn("ExternalHarvest: no source could be built, skipping")
			return nil
		}
		src, stats = built, built.Stats
	}

	r.printPhaseStart("ExternalHarvest", "harvest URLs from external intelligence sources")

	ehDetail := "Mode: " + terminal.HiBlue("request-only") + " (archived URLs are stored, never fetched from the target)"
	if budget := PhaseSpeedDetail(r.settings, "external_harvester", 0); budget != "" {
		ehDetail += ", " + budget
	}
	r.printPhaseDetail(ehDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(r.options.Targets)

	zap.L().Info("ExternalHarvest: storing harvested URLs as request-only records")

	stored, err := r.ingestHarvestStubs(ctx, infra, src)
	if err != nil {
		return err
	}
	r.reportHarvestShaping(stats())

	// Increment processed_count for external harvest phase
	if r.repository != nil && stored > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, stored); err != nil {
			zap.L().Warn("ExternalHarvest: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("ExternalHarvest", fmt.Sprintf("completed — %s items ingested in %s",
		terminal.Orange(fmt.Sprintf("%d", stored)), terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("ExternalHarvest: completed", zap.Int64("stored", stored))
	return nil
}

// ingestHarvestStubs drains src and persists each in-scope URL as a request-only
// record. It sends nothing to the target: no baseline, no pre-hook, no passive
// module. Scope is matched on host and path alone, the same pre-request check the
// executor applies before it would have fetched anything.
//
// Returns how many records are in the store for this harvest (a URL already
// recorded counts, since the repository adopts the existing row). Each stored
// row is also queued on r.harvestStubs for the harvest-probe step. A cancelled
// context ends the phase with what was stored so far and no error, matching the
// executor-based phase it replaces.
func (r *Runner) ingestHarvestStubs(ctx context.Context, infra *phaseInfra, src source.InputSource) (int64, error) {
	defer func() { _ = src.Close() }()

	var stored, outOfScope, failed int64
	for {
		item, err := src.Next(ctx)
		if err != nil {
			if source.IsEOF(err) || ctx.Err() != nil {
				break
			}
			return stored, fmt.Errorf("external harvest: read source: %w", err)
		}
		if item == nil || item.Request == nil || item.Request.Request() == nil {
			continue
		}
		req := item.Request
		if infra != nil && infra.scopeMatcher != nil && req.Service() != nil &&
			!infra.scopeMatcher.InScopeRequest(req.Service().Host(), req.Request().Path(), "", "") {
			outOfScope++
			continue
		}
		if r.repository == nil {
			continue
		}
		id, err := r.repository.SaveRecordWithLineage(ctx, req, database.RecordSourceHarvest, r.options.ProjectUUID, database.RecordLineage{ScanUUID: r.options.ScanUUID})
		if err != nil {
			failed++
			zap.L().Debug("ExternalHarvest: failed to store harvested URL",
				zap.String("url", req.Target()), zap.Error(err))
			continue
		}
		stored++
		r.harvestStubs = append(r.harvestStubs, harvestStub{uuid: id, req: req})
	}

	if outOfScope > 0 || failed > 0 {
		zap.L().Info("ExternalHarvest: skipped harvested URLs",
			zap.Int64("out_of_scope", outOfScope), zap.Int64("store_failed", failed))
	}
	return stored, nil
}

// reportHarvestShaping prints how many harvested URLs survived normalization and
// sampling, and records any bound a source stopped at (cdx_max_rows) as a phase
// limit, so a capped archive query is reported rather than looking complete.
func (r *Runner) reportHarvestShaping(st harvester.Stats) {
	if st.Raw > 0 {
		r.printPhaseFeedback("ExternalHarvest", fmt.Sprintf(
			"kept %s of %s harvested URLs (duplicate %d, static %d, invalid %d, over per_shape %d, over max_urls %d)",
			terminal.Orange(fmt.Sprintf("%d", st.Kept)), terminal.Orange(fmt.Sprintf("%d", st.Raw)),
			st.Duplicate, st.Static, st.Invalid, st.OverShape, st.OverDomainCap))
	}
	tracker := r.currentPhase.Load()
	for _, code := range st.Limits {
		r.printPhaseFeedback("ExternalHarvest", "stopped at limit "+terminal.Orange(code)+" — the archive index was not read to the end")
		tracker.noteLimit(code)
	}
}
