package runner

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// deduplicateFindings runs finding deduplication and prints feedback if any were
// removed. It runs two passes: the URL-keyed pass (same module/severity/URL fired
// many times) followed by the value-keyed pass (same extracted value — e.g. one
// leaked secret — reported once per URL).
//
// When hostnames are supplied the passes are scoped to those hosts, so a per-round
// caller (dynamic-assessment) doesn't full-scan a growing project-wide findings
// table every feedback round. An empty list dedupes project-wide.
func (r *Runner) deduplicateFindings(ctx context.Context, phase string, hostnames ...string) {
	if r.repository == nil {
		return
	}
	deleted, grouped, err := r.repository.DeduplicateFindings(ctx, r.options.ProjectUUID, hostnames...)
	if err != nil {
		zap.L().Warn("Finding deduplication failed", zap.String("phase", phase), zap.Error(err))
	} else if deleted > 0 {
		r.printPhaseFeedback(phase, fmt.Sprintf("grouped %s findings into %s (deduplicated %s redundant findings with identical module/URL)",
			terminal.Orange(fmt.Sprintf("%d", deleted+grouped)),
			terminal.Orange(fmt.Sprintf("%d", grouped)),
			terminal.Orange(fmt.Sprintf("%d", deleted))))
		r.scanLogger.Info(phase, fmt.Sprintf("grouped %d findings into %d (%d duplicates merged)", deleted+grouped, grouped, deleted))
	}

	r.groupFindingsByValue(ctx, phase, hostnames...)
}

// groupFindingsByValue collapses findings that repeat the same extracted value
// across many URLs (e.g. one leaked secret reported once per page) into a single
// finding, merging the URLs into MatchedAt. Gated by known_issue_scan.group_by_value.
// Optional hostnames scope the pass to those hosts (empty = project-wide).
func (r *Runner) groupFindingsByValue(ctx context.Context, phase string, hostnames ...string) {
	if r.repository == nil {
		return
	}
	gc := r.resolveFindingGrouping()
	if !gc.Enabled {
		return
	}
	deleted, grouped, err := r.repository.GroupFindingsByValue(ctx, r.options.ProjectUUID, database.GroupFindingOptions{
		PerHost:   gc.PerHost,
		Tags:      gc.Tags,
		ByModule:  gc.ByModule,
		MaxURLs:   gc.MaxURLs,
		Hostnames: hostnames,
	})
	if err != nil {
		zap.L().Warn("Finding value-grouping failed", zap.String("phase", phase), zap.Error(err))
		return
	}
	if deleted > 0 {
		r.printPhaseFeedback(phase, fmt.Sprintf("grouped %s findings into %s by shared value (e.g. one secret across many URLs)",
			terminal.Orange(fmt.Sprintf("%d", deleted+grouped)),
			terminal.Orange(fmt.Sprintf("%d", grouped))))
		r.scanLogger.Info(phase, fmt.Sprintf("value-grouped %d findings into %d (%d duplicates merged)", deleted+grouped, grouped, deleted))
	}
}

// finalizeFindingGrouping runs a single project-wide finding dedup + grouping pass
// at scan completion, covering every host regardless of which phases ran.
//
// The per-phase passes are each scoped: dynamic-assessment dedups only the in-scope
// hostnames (see runDynamicAssessmentRound), and the only project-wide pass
// otherwise lives in the known-issue-scan phase. So a scan that skips known-issue-scan
// — or whose crawl redirects/expands findings onto hosts outside the original scope
// set (e.g. a target that 301s to www.* or pulls in third-party CDN/analytics hosts)
// — leaves those findings untouched by any grouping pass and ships them ungrouped:
// dozens of near-identical per-asset Low/Info rows instead of one-per-host.
//
// This final pass closes that gap. It is project-wide (no hostnames) and idempotent:
// when a prior pass already collapsed everything there is nothing left to merge, so it
// scans the findings table, deletes nothing, and prints nothing. Runs on r.ctx (the
// un-bounded parent), not the --scanning-max-duration-bounded ctx, so it still groups
// after the scan budget fires — mirroring the scan-record finalization. The guard for a
// nil repository lives in deduplicateFindings, so a no-DB scan is already a no-op here.
func (r *Runner) finalizeFindingGrouping() {
	r.deduplicateFindings(r.ctx, "Finalize")
}

// resolveAllModules combines getModulesToExecute() with JS extension modules.
func (r *Runner) resolveAllModules(infra *phaseInfra) ([]modules.ActiveModule, []modules.PassiveModule) {
	var activeModules []modules.ActiveModule
	var passiveModules []modules.PassiveModule

	if !r.options.ExtensionsOnly {
		activeModules, passiveModules = r.getModulesToExecute()
	}

	// Append JS extension modules
	if infra.jsEngine != nil {
		jsMods := infra.jsEngine.ActiveModules()
		if len(jsMods) > 0 {
			activeModules = append(activeModules, jsMods...)
			zap.L().Info("JS active modules loaded", zap.Int("count", len(jsMods)))
		}
		jsPassive := infra.jsEngine.PassiveModules()
		if len(jsPassive) > 0 {
			passiveModules = append(passiveModules, jsPassive...)
			zap.L().Info("JS passive modules loaded", zap.Int("count", len(jsPassive)))
		}
	}

	return activeModules, passiveModules
}

// getModulesToExecute returns the active and passive modules to execute based on options.
func (r *Runner) getModulesToExecute() ([]modules.ActiveModule, []modules.PassiveModule) {
	var activeModules []modules.ActiveModule
	var passiveModules []modules.PassiveModule

	// Get active modules
	activeUsingAll := false
	if len(r.options.Modules) > 0 {
		if r.options.Modules[0] == "all" {
			activeModules = modules.GetActiveModules()
			activeUsingAll = true
		} else {
			activeModules = modules.GetActiveModulesByIDs(r.options.Modules)
		}
	}

	// Get passive modules
	passiveUsingAll := false
	if len(r.options.PassiveModules) > 0 {
		if r.options.PassiveModules[0] == "all" {
			passiveModules = modules.GetPassiveModules()
			passiveUsingAll = true
		} else {
			passiveModules = modules.GetPassiveModulesByIDs(r.options.PassiveModules)
		}
	}

	// Filter modules based on enabled_modules config (only when CLI uses "all").
	// A config allowlist is a deliberate selection, so it also opts out of the
	// intensity tier ceiling below.
	activeNarrowedByConfig := false
	passiveNarrowedByConfig := false
	if r.settings != nil {
		if activeUsingAll && !isAllModules(r.settings.DynamicAssessment.EnabledModules.ActiveModules) {
			activeModules = modules.GetActiveModulesByIDs(r.settings.DynamicAssessment.EnabledModules.ActiveModules)
			activeNarrowedByConfig = true
			zap.L().Info("Active modules filtered by config", zap.Strings("ids", r.settings.DynamicAssessment.EnabledModules.ActiveModules))
		}

		if passiveUsingAll && !isAllModules(r.settings.DynamicAssessment.EnabledModules.PassiveModules) {
			passiveModules = modules.GetPassiveModulesByIDs(r.settings.DynamicAssessment.EnabledModules.PassiveModules)
			passiveNarrowedByConfig = true
			zap.L().Info("Passive modules filtered by config", zap.Strings("ids", r.settings.DynamicAssessment.EnabledModules.PassiveModules))
		}
	}

	// Apply the intensity tier ceiling. This only narrows a broad ("all")
	// selection: an explicit -m / --module-tag list or a config allowlist
	// reflects deliberate intent and runs verbatim regardless of intensity.
	ceiling := intensityTierCeiling(r.options.Intensity)
	if activeUsingAll && !activeNarrowedByConfig {
		activeModules = r.filterActiveModulesByTier(activeModules, ceiling)
	}
	if passiveUsingAll && !passiveNarrowedByConfig {
		passiveModules = r.filterPassiveModulesByTier(passiveModules, ceiling)
	}

	// Sort by execution priority to keep scheduling policy aligned with the executor.
	if len(activeModules) > 0 {
		sortActiveModulesByPriority(activeModules)
		zap.L().Info("Active modules to execute", zap.Int("count", len(activeModules)))
	}

	if len(passiveModules) > 0 {
		sortPassiveModulesByPriority(passiveModules)
		zap.L().Info("Passive modules to execute", zap.Int("count", len(passiveModules)))
	}

	return activeModules, passiveModules
}

func sortActiveModulesByPriority(mods []modules.ActiveModule) {
	sort.SliceStable(mods, func(i, j int) bool {
		return moduleExecutionPriority(mods[i]) < moduleExecutionPriority(mods[j])
	})
}

func sortPassiveModulesByPriority(mods []modules.PassiveModule) {
	sort.SliceStable(mods, func(i, j int) bool {
		return moduleExecutionPriority(mods[i]) < moduleExecutionPriority(mods[j])
	})
}

func moduleExecutionPriority(m modules.Module) int {
	if prioritized, ok := m.(modules.Prioritized); ok {
		return prioritized.Priority()
	}
	return 100
}

// isAllModules returns true when the list is empty or contains only "all".
func isAllModules(ids []string) bool {
	return len(ids) == 0 || (len(ids) == 1 && ids[0] == "all")
}

// resolveMaxParamShapeSamples resolves the dynamic-assessment param-shape
// coalescing cap from settings. Mirroring the MaxFeedbackRounds convention, a
// zero/unset value (including when a scanning profile overlays the
// dynamic-assessment section and resets it) falls back to the built-in default;
// a negative value disables coalescing.
func (r *Runner) resolveMaxParamShapeSamples() int {
	if r.settings == nil {
		return database.DefaultMaxParamShapeSamples
	}
	v := r.settings.DynamicAssessment.MaxParamShapeSamples
	switch {
	case v < 0:
		return 0 // explicitly disabled
	case v == 0:
		return database.DefaultMaxParamShapeSamples
	default:
		return v
	}
}

// adaptiveHostLimiterSettings reads the adaptive per-host rate-limiter knobs from
// scanning-pace settings, returning (enabled, minPerHost, ceilingPerHost). The
// limiter applies its own defaults for zero min/ceiling, so unset values pass
// through as 0. Defaults to disabled when settings is nil.
func adaptiveHostLimiterSettings(settings *config.Settings) (bool, int, int) {
	if settings == nil {
		return false, 0, 0
	}
	sp := settings.ScanningPace
	return sp.AdaptivePerHost, sp.MinPerHost, sp.MaxPerHostCeiling
}

// filterOutPassiveModule removes a passive module with the given ID from the list.
func filterOutPassiveModule(mods []modules.PassiveModule, id string) []modules.PassiveModule {
	result := make([]modules.PassiveModule, 0, len(mods))
	for _, m := range mods {
		if m.ID() != id {
			result = append(result, m)
		}
	}
	return result
}

// buildModulesString returns a comma-separated string of module IDs for scan record storage.
func (r *Runner) buildModulesString(active []modules.ActiveModule, passive []modules.PassiveModule) string {
	ids := make([]string, 0, len(active)+len(passive))
	for _, m := range active {
		ids = append(ids, m.ID())
	}
	for _, m := range passive {
		ids = append(ids, m.ID())
	}
	return strings.Join(ids, ",")
}
