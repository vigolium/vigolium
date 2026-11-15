package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpstack"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/yamlext"
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
		PerHost:       gc.PerHost,
		Tags:          gc.Tags,
		ByModule:      gc.ByModule,
		ByRule:        gc.ByRule,
		BundleSuspect: gc.BundleSuspect,
		MaxURLs:       gc.MaxURLs,
		Hostnames:     hostnames,
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

// resolveAllModules combines getModulesToExecute() with the JS/YAML extension
// modules that survive the module selection (see filterExtensionModules).
func (r *Runner) resolveAllModules(infra *phaseInfra) ([]modules.ActiveModule, []modules.PassiveModule) {
	var activeModules []modules.ActiveModule
	var passiveModules []modules.PassiveModule

	if !r.options.ExtensionsOnly {
		activeModules, passiveModules = r.getModulesToExecute()
	}

	if infra.jsEngine != nil {
		sel := r.selectExtensionModules(infra.jsEngine)
		activeModules = append(activeModules, sel.Active...)
		passiveModules = append(passiveModules, sel.Passive...)
		if sel.loaded() > 0 {
			summary := sel.summary()
			zap.L().Info("Extension modules selected",
				zap.Int("active", len(sel.Active)),
				zap.Int("passive", len(sel.Passive)),
				zap.Int("skipped", sel.skipped()),
				zap.String("summary", summary))
			if r.scanLogger != nil {
				r.scanLogger.Info("dynamic-assessment", summary)
			}
		}
	}

	return activeModules, passiveModules
}

// ErrUnknownExtensionModule is what the run fails with when --module-id (or a
// REST module list) names an ext- ID that no loaded extension carries. It is a
// command-line mistake, so the CLI maps it to exit 2 (usage_error); it is raised
// while the infrastructure is built, before any phase sends traffic.
var ErrUnknownExtensionModule = errors.New("unknown extension module")

// extensionSelection is the outcome of filterExtensionModules: the extension
// modules that run, the reasons the others do not, and the ext- IDs the
// selection named that match no loaded extension.
type extensionSelection struct {
	Active  []modules.ActiveModule
	Passive []modules.PassiveModule
	// Skipped counts dropped extension modules per reason, in skip-reason order.
	Skipped map[string]int
	// Unknown lists ext- IDs named exactly (--module-id / REST) that match no
	// loaded extension. -m patterns are fuzzy and never land here.
	Unknown []string
}

// Skip reasons reported in the extension selection summary.
const (
	extSkipPassiveOnly = "--passive-only"
	extSkipNoPassive   = "--no-passive"
	extSkipNotSelected = "not selected"
	extSkipDirLoaded   = "directory-loaded, narrowed selection"
)

var extSkipOrder = []string{extSkipPassiveOnly, extSkipNoPassive, extSkipNotSelected, extSkipDirLoaded}

func (s extensionSelection) skipped() int {
	n := 0
	for _, c := range s.Skipped {
		n += c
	}
	return n
}

func (s extensionSelection) loaded() int { return len(s.Active) + len(s.Passive) + s.skipped() }

// summary renders e.g. "extensions: 2 active, 1 passive selected; 3 skipped (--passive-only)".
func (s extensionSelection) summary() string {
	out := fmt.Sprintf("extensions: %d active, %d passive selected", len(s.Active), len(s.Passive))
	if n := s.skipped(); n > 0 {
		var reasons []string
		for _, reason := range extSkipOrder {
			if c := s.Skipped[reason]; c > 0 {
				reasons = append(reasons, fmt.Sprintf("%d %s", c, reason))
			}
		}
		out += fmt.Sprintf("; %d skipped (%s)", n, strings.Join(reasons, ", "))
	}
	return out
}

// selectExtensionModules applies the run's module selection to the engine's
// loaded extension modules.
func (r *Runner) selectExtensionModules(engine *jsext.Engine) extensionSelection {
	if engine == nil {
		return filterExtensionModules(nil, nil, r.options, nil)
	}
	return filterExtensionModules(engine.ActiveModules(), engine.PassiveModules(), r.options, r.explicitExtensionIDs(engine))
}

// filterExtensionModules narrows the loaded JS/YAML extension modules with the
// same selection that narrows the built-in modules, so a hand-picked scan runs
// what was picked:
//
//   - --passive-only (opts.Modules empty, passive selected) drops every active
//     extension. Pre/post hooks are not modules and stay: they only shape
//     traffic other modules send.
//   - --no-passive (opts.PassiveModules empty) drops every passive extension.
//   - A category whose selection is narrowed (exact IDs rather than "all") keeps
//     only the extensions the selection names when it names any: an ext- ID in
//     opts.Modules/opts.PassiveModules (--module-id), a -m pattern that fuzzy-
//     matches an extension (opts.ModulePatterns), or a --module-tag an extension
//     carries (opts.ModuleTags). When it names none, only extensions loaded from
//     an explicitly named file (--ext / custom_dir, the explicit set) still run;
//     extension-directory auto-loads are dropped.
//   - A category left at "all" keeps every extension of that category.
//
// explicit holds the module IDs (ext-<id>) loaded from explicitly named files.
func filterExtensionModules(active []modules.ActiveModule, passive []modules.PassiveModule, opts *types.Options, explicit map[string]bool) extensionSelection {
	sel := extensionSelection{Skipped: map[string]int{}}
	if opts == nil {
		opts = &types.Options{Modules: []string{"all"}, PassiveModules: []string{"all"}}
	}

	all := make([]modules.Module, 0, len(active)+len(passive))
	loaded := make(map[string]bool, len(active)+len(passive))
	for _, m := range active {
		all = append(all, m)
		loaded[m.ID()] = true
	}
	for _, m := range passive {
		all = append(all, m)
		loaded[m.ID()] = true
	}

	// The extension IDs the selection names.
	named := map[string]bool{}
	patterns := make(map[string]bool, len(opts.ModulePatterns))
	for _, p := range opts.ModulePatterns {
		patterns[strings.ToLower(p)] = true
	}
	seenUnknown := map[string]bool{}
	for _, list := range [][]string{opts.Modules, opts.PassiveModules} {
		for _, id := range list {
			if !strings.HasPrefix(id, ExtensionModulePrefix) {
				continue
			}
			switch {
			case loaded[id]:
				named[id] = true
			case patterns[strings.ToLower(id)]:
				// An unmatched -m pattern passed through verbatim by the CLI;
				// fuzzy matching below decides what it selects.
			case !seenUnknown[id]:
				seenUnknown[id] = true
				sel.Unknown = append(sel.Unknown, id)
			}
		}
	}
	if len(opts.ModulePatterns) > 0 {
		if matched := modules.MatchModulePatterns(opts.ModulePatterns, all); len(matched) != 1 || matched[0] != "all" {
			for _, id := range matched {
				named[id] = true
			}
		}
	}
	for _, id := range modules.MatchModuleTags(opts.ModuleTags, all) {
		named[id] = true
	}

	// keep reports whether an extension survives its category's narrowing, and
	// the skip reason when it does not.
	keep := func(id string, narrowed bool) (bool, string) {
		switch {
		case !narrowed:
			return true, ""
		case len(named) > 0:
			return named[id], extSkipNotSelected
		default:
			return explicit[id], extSkipDirLoaded
		}
	}

	passiveOnly := len(opts.Modules) == 0 && len(opts.PassiveModules) > 0
	activeNarrowed := !isAllModules(opts.Modules)
	for _, m := range active {
		if passiveOnly {
			sel.Skipped[extSkipPassiveOnly]++
			continue
		}
		if ok, reason := keep(m.ID(), activeNarrowed); !ok {
			sel.Skipped[reason]++
			continue
		}
		sel.Active = append(sel.Active, m)
	}

	noPassive := len(opts.PassiveModules) == 0
	passiveNarrowed := !isAllModules(opts.PassiveModules)
	for _, m := range passive {
		if noPassive {
			sel.Skipped[extSkipNoPassive]++
			continue
		}
		if ok, reason := keep(m.ID(), passiveNarrowed); !ok {
			sel.Skipped[reason]++
			continue
		}
		sel.Passive = append(sel.Passive, m)
	}
	return sel
}

// ExtensionModulePrefix is the ID prefix every JS/YAML extension module carries
// (the jsext and yamlext module constructors prepend it to the script's id).
const ExtensionModulePrefix = "ext-"

// explicitExtensionIDs returns the module IDs of the extensions loaded from an
// explicitly named file (--ext, or extensions.custom_dir), as opposed to those
// auto-loaded from the extension directory. Explicit means the operator asked
// for that file, so a narrowed module selection that names no extension still
// runs it.
func (r *Runner) explicitExtensionIDs(engine *jsext.Engine) map[string]bool {
	if engine == nil || r.settings == nil {
		return nil
	}
	paths := map[string]bool{}
	for _, p := range r.settings.DynamicAssessment.Extensions.CustomDir {
		paths[filepath.Clean(config.ExpandPath(p))] = true
	}
	if len(paths) == 0 {
		return nil
	}
	ids := map[string]bool{}
	for _, s := range engine.Scripts() {
		if s != nil && paths[filepath.Clean(s.Path)] {
			ids[ExtensionModulePrefix+s.Metadata.ID] = true
		}
	}
	// The engine does not keep YAML definitions, so re-read the explicit ones for
	// their IDs. A file that failed to load was already reported by the engine.
	for p := range paths {
		if !yamlext.IsYAMLExtension(p) {
			continue
		}
		if def, err := yamlext.LoadExtension(p); err == nil && def != nil {
			ids[ExtensionModulePrefix+def.ID] = true
		}
	}
	return ids
}

// validateExtensionSelection fails the run before any phase sends traffic when
// the module selection names an ext- ID that no loaded extension carries. It is
// a no-op when the plan does not run the dynamic-assessment phase, the only one
// that executes extension modules.
func (r *Runner) validateExtensionSelection(plan NativeScanPlan, engine *jsext.Engine) error {
	if !planRunsPhase(plan, PhaseDynamicAssessment) {
		return nil
	}
	sel := r.selectExtensionModules(engine)
	if len(sel.Unknown) == 0 {
		return nil
	}
	hint := "no extensions are loaded; pass --ext <file> or --ext-dir <dir>"
	if engine != nil && len(engine.ActiveModules())+len(engine.PassiveModules()) > 0 {
		var ids []string
		for _, m := range engine.ActiveModules() {
			ids = append(ids, m.ID())
		}
		for _, m := range engine.PassiveModules() {
			ids = append(ids, m.ID())
		}
		sort.Strings(ids)
		hint = "loaded extensions: " + strings.Join(ids, ", ")
	}
	return fmt.Errorf("%w: module selection names %s, which matches no loaded extension (%s)",
		ErrUnknownExtensionModule, strings.Join(sel.Unknown, ", "), hint)
}

// ErrEmptyModuleSelection is what the run fails with when an explicit module
// selection (-m, --module-tag, --module-id) resolves to no module at all, built
// in or extension. The CLI maps it to exit 2: running zero modules and reporting
// "completed" read as a clean assessment of a selection that was a typo.
var ErrEmptyModuleSelection = errors.New("module selection matches no module")

// validateModuleSelection fails the run before any phase sends traffic when an
// explicit module selection resolves to nothing. Only the selection is judged,
// not what the intensity tier or the config allowlist later withholds from it.
func (r *Runner) validateModuleSelection(plan NativeScanPlan, engine *jsext.Engine) error {
	if !planRunsPhase(plan, PhaseDynamicAssessment) {
		return nil
	}
	// Modules holds the resolved -m/--module-tag/--module-id selection: nil for
	// none (--passive-only), ["all"] when nothing narrowed it, else IDs — with
	// any unmatched pattern or tag carried through verbatim.
	ids := r.options.Modules
	if !explicitIDs(ids) {
		return nil
	}
	if len(modules.GetActiveModulesByIDs(ids))+len(modules.GetPassiveModulesByIDs(ids)) > 0 {
		return nil
	}
	if engine != nil {
		if sel := r.selectExtensionModules(engine); len(sel.Active)+len(sel.Passive) > 0 {
			return nil
		}
	}
	typed := append([]string(nil), r.options.ModulePatterns...)
	for _, t := range r.options.ModuleTags {
		typed = append(typed, "tag:"+t)
	}
	if len(typed) == 0 {
		typed = ids
	}
	return fmt.Errorf("%w: %s (list modules with: vigolium module ls)",
		ErrEmptyModuleSelection, strings.Join(typed, ", "))
}

// explicitIDs reports whether a module ID list names specific modules (not
// nil = none, not ["all"]).
func explicitIDs(ids []string) bool {
	return len(ids) > 0 && !(len(ids) == 1 && ids[0] == "all")
}

// countExtensionModules counts the JS/YAML extension modules in a module set.
func countExtensionModules(active []modules.ActiveModule, passive []modules.PassiveModule) int {
	n := 0
	for _, m := range active {
		if strings.HasPrefix(m.ID(), ExtensionModulePrefix) {
			n++
		}
	}
	for _, m := range passive {
		if strings.HasPrefix(m.ID(), ExtensionModulePrefix) {
			n++
		}
	}
	return n
}

// planRunsPhase reports whether the plan has phase as an enabled step.
func planRunsPhase(plan NativeScanPlan, phase NativePhase) bool {
	for _, step := range plan.Steps {
		if step.Phase == phase && step.Enabled {
			return true
		}
	}
	return false
}

// getModulesToExecute returns the active and passive modules to execute based
// on options: FilterModulesForRun (the selection the scan plan reports too),
// plus a log line for everything a gate dropped.
func (r *Runner) getModulesToExecute() ([]modules.ActiveModule, []modules.PassiveModule) {
	sel := FilterModulesForRun(r.options, r.settings)
	if sel.ActiveByConfig {
		zap.L().Info("Active modules filtered by config", zap.Strings("ids", r.settings.DynamicAssessment.EnabledModules.ActiveModules))
	}
	if sel.PassiveByConfig {
		zap.L().Info("Passive modules filtered by config", zap.Strings("ids", r.settings.DynamicAssessment.EnabledModules.PassiveModules))
	}
	intensity := r.intensityLabel()
	logTierDeferred(intensity, "Active", sel.TierCeiling, sel.activeTier)
	logTierDeferred(intensity, "Passive", sel.TierCeiling, sel.passiveTier)
	logRiskWithheld(intensity, "Active", sel.activeRisk)
	logRiskWithheld(intensity, "Passive", sel.passiveRisk)
	logHygieneSuppressed(intensity, "Active", sel.activeHygiene)
	logHygieneSuppressed(intensity, "Passive", sel.passiveHygiene)
	if len(sel.Active) > 0 {
		zap.L().Info("Active modules to execute", zap.Int("count", len(sel.Active)))
	}
	if len(sel.Passive) > 0 {
		zap.L().Info("Passive modules to execute", zap.Int("count", len(sel.Passive)))
	}
	return sel.Active, sel.Passive
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

// newHostLimiter builds the per-host concurrency limiter every scan path uses.
//
// One constructor because the config literal is identical everywhere and only
// its MaxPerHost differs: three hand-written copies had already started to drift
// (the eviction and WAF-pacing defaults were restated in each, and one dropped
// the fallback below). maxPerHost <= 0 means "not chosen" and falls back to the
// common scanning_pace value, then to types.DefaultMaxPerHost.
func newHostLimiter(maxPerHost int, settings *config.Settings, noWafPacing bool) *hostlimit.HostRateLimiter {
	if maxPerHost <= 0 && settings != nil && settings.ScanningPace.MaxPerHost > 0 {
		maxPerHost = settings.ScanningPace.MaxPerHost
	}
	if maxPerHost <= 0 {
		maxPerHost = types.DefaultMaxPerHost
	}
	// The standalone stacks' limiter (httpstack), with the scan's WAF pacing;
	// the constructor drops reactive WAF pacing when Adaptive is on.
	cfg := httpstack.HostLimiterConfig(maxPerHost, 0, true, noWafPacing)
	cfg.Adaptive, cfg.MinPerHost, cfg.CeilingPerHost = adaptiveHostLimiterSettings(settings)
	return hostlimit.NewHostRateLimiter(cfg)
}
