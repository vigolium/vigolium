package runner

import (
	"context"
	"fmt"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// seedCLITargets ingests CLI targets into the database without running deparos or modules.
// This is used when discovery is skipped but downstream phases (KnownIssueScan, DynamicAssessment)
// need DB records to operate on.
func (r *Runner) seedCLITargets(ctx context.Context, infra *phaseInfra) error {
	r.printPhaseStart("Seed", "ingest CLI targets into database (discovery skipped)")

	authWalls := newAuthWallCollector()

	executorCfg := core.ExecutorConfig{
		OnModuleError:  r.noteModuleError,
		Phase:          string(PhaseSeed),
		Workers:        r.options.Concurrency,
		Services:       infra.svc,
		HTTPRequester:  infra.httpRequester,
		Repository:     r.repository,
		ScanUUID:       infra.scanUUID,
		ProjectUUID:    r.options.ProjectUUID,
		ScopeMatcher:   infra.scopeMatcher,
		PauseCtrl:      r.pauseCtrl,
		OnTraffic:      r.makeOnTraffic("seed"),
		OnAuthWall:     authWalls.Observe,
		OnRecordStored: r.onRecordStored(),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, r.inputSource, nil, nil)
	_, err := executor.Execute(ctx)
	r.currentPhase.Load().noteExecution(executor.Report())
	if err != nil {
		return err
	}

	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Seed: failed to increment processed count", zap.Error(err))
		}
	}

	zap.L().Info("Seed: CLI targets ingested", zap.Int64("processed", executor.Processed()))
	r.printPhaseComplete("Seed", fmt.Sprintf("completed — %s items ingested",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed()))))
	r.reportAuthWalls("Seed", authWalls)
	return nil
}
