package runner

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

func (r *Runner) runDiscoveryPhase(ctx context.Context, infra *phaseInfra) error {
	phaseStart := time.Now()

	var sources []source.InputSource
	var discoveryTargets []string

	var discoverSrc *source.DeparosDiscoverySource
	if r.options.DiscoverEnabled && len(r.options.Targets) > 0 {
		additionalTargets, err := r.getInScopeHostURLs(ctx, infra.scopeMatcher)
		if err != nil {
			zap.L().Warn("Discovery: failed to get DB hosts for deparos expansion", zap.Error(err))
		}

		enrichTargets := false
		if r.settings != nil {
			enrichTargets = r.settings.Discovery.EnrichTargets
		}
		if enrichTargets && r.repository != nil {
			pathTargets, pathErr := r.repository.GetDistinctPaths(ctx, r.options.ProjectUUID)
			if pathErr != nil {
				zap.L().Warn("Discovery: failed to get DB paths for enrichment", zap.Error(pathErr))
			} else if len(pathTargets) > 0 {
				pathURLs := buildDiscoveryTargetsFromPaths(pathTargets)
				additionalTargets = dedupTargets(additionalTargets, pathURLs)
				zap.L().Info("Discovery: enriched targets with paths from prior phases",
					zap.Int("path_targets", len(pathURLs)))
			}
		}

		discoveryTargets = dedupTargets(r.options.Targets, additionalTargets)
		deparosCfg := r.buildDeparosConfig(additionalTargets)
		discoverSrc, err = source.NewDeparosDiscoverySource(deparosCfg)
		if err != nil {
			zap.L().Warn("Failed to initialize deparos discovery", zap.Error(err))
		} else {
			sources = append(sources, discoverSrc)
		}
	} else {
		discoveryTargets = r.options.Targets
	}

	sources = append(sources, r.inputSource)

	var compositeSource source.InputSource
	if len(sources) == 1 {
		compositeSource = sources[0]
	} else {
		compositeSource = source.NewConcurrentMultiSource(sources...)
	}

	r.printPhaseStart("Discovery", "ingest inputs and discover directories, files, and hidden endpoints via Deparos content discovery")
	r.printPhaseDetail(fmt.Sprintf("Sources: deparos-discover=%s",
		terminal.HiTeal(fmt.Sprintf("%v", r.options.DiscoverEnabled))))

	speedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if r.settings != nil {
		discPace := r.settings.ScanningPace.ResolvePhase("discovery")
		if discPace.MaxDuration > 0 {
			speedDetail += fmt.Sprintf(", max-duration=%s", terminal.HiTeal(discPace.MaxDuration.String()))
		}
		if discPace.DurationFactor > 0 {
			speedDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", discPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(speedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(discoveryTargets)

	enrichTargetsEnabled := false
	if r.settings != nil {
		enrichTargetsEnabled = r.settings.Discovery.EnrichTargets
	}
	if !enrichTargetsEnabled && !r.options.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("enrich discovery targets with discovered paths via"), terminal.HiCyan("vigolium config discovery.enrich_targets=true"))
	}

	zap.L().Info("Discovery: ingesting input into database")

	var discoveryRecordWriter *database.RecordWriter
	if r.repository != nil {
		discoveryRecordWriter = database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
	}

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		RecordWriter:  discoveryRecordWriter,
		ScanUUID:      infra.scanUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("discovery"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	var discoveryPassive []modules.PassiveModule
	if r.settings != nil && len(r.settings.Discovery.PassiveModuleTags) > 0 {
		ids := modules.ResolveModuleTags(r.settings.Discovery.PassiveModuleTags)
		if len(ids) > 0 {
			discoveryPassive = modules.GetPassiveModulesByIDs(ids)
			if len(discoveryPassive) > 0 {
				zap.L().Info("Discovery: passive modules enabled",
					zap.Int("count", len(discoveryPassive)),
					zap.Strings("tags", r.settings.Discovery.PassiveModuleTags))
			}
		}
	}

	executor := core.NewExecutor(executorCfg, compositeSource, nil, discoveryPassive)
	_, err := executor.Execute(ctx)
	if discoveryRecordWriter != nil {
		discoveryRecordWriter.Close()
	}
	if err != nil {
		return err
	}

	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("Discovery: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("Discovery", fmt.Sprintf("completed — %s items ingested (deparos=%s) in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())),
		terminal.HiTeal(fmt.Sprintf("%v", r.options.DiscoverEnabled)),
		terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("Discovery: completed", zap.Int64("processed", executor.Processed()))

	if discoverSrc != nil {
		stats := discoverSrc.Stats()
		if stats.TotalDiscovered > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("discovered %s records — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.TotalDiscovered)),
				formatStatusCodeArray(stats.AllCodes)))
		}
		if stats.HardDedupRemoved > 0 {
			r.printPhaseFeedback("Discovery", fmt.Sprintf("deduplicated %s redundant records — %s",
				terminal.Orange(fmt.Sprintf("%d", stats.HardDedupRemoved)),
				formatStatusCodeArray(stats.DedupedCodes)))
		}
	}

	return nil
}

// seedCLITargets ingests CLI targets into the database without running deparos or modules.
// This is used when discovery is skipped but downstream phases (KnownIssueScan, DynamicAssessment)
// need DB records to operate on.
func (r *Runner) seedCLITargets(ctx context.Context, infra *phaseInfra) error {
	r.printPhaseStart("Seed", "ingest CLI targets into database (discovery skipped)")

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("seed"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, r.inputSource, nil, nil)
	_, err := executor.Execute(ctx)
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
	return nil
}

// runSpideringPhase runs browser-based crawling using spitolas.
// Captured traffic is stored in vigolium's HTTPRecord table via RepositoryWriter.
// Targets are merged from CLI targets and in-scope hosts discovered by prior phases.
func (r *Runner) runSpideringPhase(ctx context.Context, infra *phaseInfra) error {
	if r.repository == nil {
		return fmt.Errorf("spidering requires a database repository")
	}

	phaseStart := time.Now()
	r.printPhaseStart("Spidering", "browser-based crawling to discover dynamic content and API endpoints")

	settingsCfg := r.settings.Spidering
	maxDuration := settingsCfg.MaxDurationParsed()
	if r.options.SpideringMaxDuration > 0 {
		maxDuration = r.options.SpideringMaxDuration
	}

	targets := r.options.Targets
	dbHosts, err := r.getInScopeHostURLs(ctx, infra.scopeMatcher)
	if err != nil {
		zap.L().Warn("Spidering: failed to get DB hosts", zap.Error(err))
	}
	targets = dedupTargets(targets, dbHosts)
	zap.L().Info("Spidering: merged targets",
		zap.Int("cli", len(r.options.Targets)),
		zap.Int("from_db", len(dbHosts)),
		zap.Int("total", len(targets)))

	if r.heuristicsResults != nil {
		before := len(targets)
		targets = filterTargetsByHeuristics(targets, r.heuristicsResults, func(hr *HeuristicsResult) bool {
			return hr.SkipSpidering
		})
		if skipped := before - len(targets); skipped > 0 {
			zap.L().Info("Spidering: targets filtered by heuristics",
				zap.Int("skipped", skipped), zap.Int("remaining", len(targets)))
		}
		if len(targets) == 0 {
			r.printPhaseComplete("Spidering", "skipped — all targets excluded by heuristics check")
			return nil
		}
	}

	configDetail := fmt.Sprintf("Config: max-duration=%s, strategy=%s, headless=%s",
		terminal.HiTeal(maxDuration.String()),
		terminal.HiTeal(settingsCfg.Strategy),
		terminal.HiTeal(fmt.Sprintf("%v", settingsCfg.Headless)))
	if r.settings != nil {
		spiderPace := r.settings.ScanningPace.ResolvePhase("spidering")
		if spiderPace.DurationFactor > 0 {
			configDetail += fmt.Sprintf(" (duration_factor=%s)", terminal.HiBlue(fmt.Sprintf("%.1f", spiderPace.DurationFactor)))
		}
	}
	r.printPhaseDetail(configDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(targets)))
	r.printVerboseTargets(targets)

	var totalStates, totalActions, totalRecords int
	for _, target := range targets {
		zap.L().Info("Spidering target", zap.String("target", target))

		cfg := spitolas.SpiderConfig{
			TargetURL:           target,
			MaxDepth:            settingsCfg.MaxDepth,
			MaxStates:           settingsCfg.MaxStates,
			MaxDuration:         maxDuration,
			MaxConsecutiveFails: settingsCfg.MaxConsecutiveFails,
			Headless:            settingsCfg.Headless,
			BrowserCount:        settingsCfg.BrowserCount,
			Strategy:            settingsCfg.Strategy,
			IncludeResponseBody: settingsCfg.IncludeResponseBody,
			IncludeHeaders:      true,
			Silent:              r.options.Silent,
			Verbose:             r.options.Verbose,
			BrowserEngine:       settingsCfg.BrowserEngine,
			BrowserPath:         settingsCfg.BrowserPath,
			NoCDP:               settingsCfg.NoCDP,
			NoForms:             settingsCfg.NoForms,
			ProxyURL:            r.options.ProxyURL,
		}

		if infra.scopeMatcher != nil && !infra.scopeMatcher.IsPassAll() {
			sm := infra.scopeMatcher
			cfg.ScopeFilter = func(host, path string) bool {
				return sm.InScopeRequest(host, path, "", "")
			}
		}

		rw := database.NewRecordWriter(r.repository, database.RecordWriterConfig{})
		timeoutCtx, cancel := context.WithTimeout(ctx, maxDuration)
		result, err := spitolas.RunSpider(timeoutCtx, cfg, rw)
		cancel()
		rw.Close()

		if err != nil {
			zap.L().Error("Spidering failed",
				zap.String("target", target), zap.Error(err))
			continue
		}

		totalStates += result.StatesDiscovered
		totalActions += result.ActionsExecuted
		totalRecords += result.RecordsSaved

		zap.L().Info("Spidering completed for target",
			zap.String("target", target),
			zap.Int("states", result.StatesDiscovered),
			zap.Int("actions", result.ActionsExecuted),
			zap.Int("records_saved", result.RecordsSaved))
	}

	if r.repository != nil && totalRecords > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, int64(totalRecords)); err != nil {
			zap.L().Warn("Spidering: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("Spidering", fmt.Sprintf("completed — %s records, %s states, %s actions in %s",
		terminal.Orange(fmt.Sprintf("%d", totalRecords)),
		terminal.Orange(fmt.Sprintf("%d", totalStates)),
		terminal.Orange(fmt.Sprintf("%d", totalActions)),
		terminal.HiPurple(fmtDuration(elapsed))))
	return nil
}
