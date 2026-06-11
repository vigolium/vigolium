package runner

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// deduplicateFindings runs finding deduplication and prints feedback if any were
// removed. It runs two passes: the URL-keyed pass (same module/severity/URL fired
// many times) followed by the value-keyed pass (same extracted value — e.g. one
// leaked secret — reported once per URL).
func (r *Runner) deduplicateFindings(ctx context.Context, phase string) {
	if r.repository == nil {
		return
	}
	deleted, grouped, err := r.repository.DeduplicateFindings(ctx, r.options.ProjectUUID)
	if err != nil {
		zap.L().Warn("Finding deduplication failed", zap.String("phase", phase), zap.Error(err))
	} else if deleted > 0 {
		r.printPhaseFeedback(phase, fmt.Sprintf("grouped %s findings into %s (deduplicated %s redundant findings with identical module/URL)",
			terminal.Orange(fmt.Sprintf("%d", deleted+grouped)),
			terminal.Orange(fmt.Sprintf("%d", grouped)),
			terminal.Orange(fmt.Sprintf("%d", deleted))))
		r.scanLogger.Info(phase, fmt.Sprintf("grouped %d findings into %d (%d duplicates merged)", deleted+grouped, grouped, deleted))
	}

	r.groupFindingsByValue(ctx, phase)
}

// groupFindingsByValue collapses findings that repeat the same extracted value
// across many URLs (e.g. one leaked secret reported once per page) into a single
// finding, merging the URLs into MatchedAt. Gated by known_issue_scan.group_by_value.
func (r *Runner) groupFindingsByValue(ctx context.Context, phase string) {
	if r.repository == nil {
		return
	}
	gc := r.resolveFindingGrouping()
	if !gc.Enabled {
		return
	}
	deleted, grouped, err := r.repository.GroupFindingsByValue(ctx, r.options.ProjectUUID, database.GroupFindingOptions{
		PerHost: gc.PerHost,
		Tags:    gc.Tags,
		MaxURLs: gc.MaxURLs,
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

	// Filter modules based on enabled_modules config (only when CLI uses "all")
	if r.settings != nil {
		if activeUsingAll && !isAllModules(r.settings.DynamicAssessment.EnabledModules.ActiveModules) {
			activeModules = modules.GetActiveModulesByIDs(r.settings.DynamicAssessment.EnabledModules.ActiveModules)
			zap.L().Info("Active modules filtered by config", zap.Strings("ids", r.settings.DynamicAssessment.EnabledModules.ActiveModules))
		}

		if passiveUsingAll && !isAllModules(r.settings.DynamicAssessment.EnabledModules.PassiveModules) {
			passiveModules = modules.GetPassiveModulesByIDs(r.settings.DynamicAssessment.EnabledModules.PassiveModules)
			zap.L().Info("Passive modules filtered by config", zap.Strings("ids", r.settings.DynamicAssessment.EnabledModules.PassiveModules))
		}
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
