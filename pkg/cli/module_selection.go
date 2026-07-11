package cli

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// registerModuleSelectionFlags registers --module-id and --passive-only, the
// precise module-selection flags for the scan / scan-url / scan-request
// commands. They complement -m/--module-tag (fuzzy, active-only narrowing):
//
//	--module-id ID   run exactly these module IDs, matched against BOTH the
//	                 active and passive registries (so a passive module such as
//	                 js-beautify can be selected on its own). Repeatable.
//	--passive-only   run only passive modules (no active scanning); combine with
//	                 --module-id to restrict to specific passive modules.
func registerModuleSelectionFlags(flags *pflag.FlagSet) {
	flags.StringSliceVar(&globalModuleIDs, "module-id", nil,
		"Run exactly these module IDs (exact match against active AND passive modules, repeatable). Unlike -m, also selects passive modules.")
	flags.BoolVar(&globalPassiveOnly, "passive-only", false,
		"Run only passive modules (no active scanning). Combine with --module-id to narrow to specific passive modules.")
}

// resolveModuleSelection computes the active and passive module ID selections
// for a scan, using the runner's sentinel convention (nil = none, ["all"] = all,
// else exact IDs). It owns the defaults — active from -m/--module-tag, passive =
// all — and layers the --module-id / --passive-only / --no-passive overrides, so
// the "all" seed lives in exactly one place. Used by the pipeline path
// (scan / scan-url / scan-request via Options); the direct path seeds its own
// defaults (both categories narrowed by -m) and calls applyModuleSelectionOverrides.
func resolveModuleSelection(noPassive bool) (active, passive []string) {
	active = resolveModules()
	passive = []string{"all"}
	applyModuleSelectionOverrides(&active, &passive, noPassive)
	return active, passive
}

// applyModuleSelectionOverrides layers --module-id / --passive-only / --no-passive
// on top of the caller's default active/passive ID selections, in place. It uses
// the runner's sentinel convention (nil = none, ["all"] = all, else exact IDs), so
// leaving both new flags unset preserves the caller's existing behavior exactly.
func applyModuleSelectionOverrides(active, passive *[]string, noPassive bool) {
	if len(globalModuleIDs) > 0 {
		// Exact IDs apply to both registries; each fetch keeps only the IDs that
		// actually exist as an active (resp. passive) module.
		*active = globalModuleIDs
		*passive = globalModuleIDs
	}
	if globalPassiveOnly {
		*active = nil
		if len(globalModuleIDs) == 0 {
			*passive = []string{"all"}
		}
	}
	if noPassive {
		*passive = nil
	}
}

// autoSkipKnownIssueScanForModuleSelection auto-appends the known-issue-scan
// phase to opts.SkipPhases when the operator has narrowed the scan to specific
// modules (via --module-id or -m/--modules). Hand-picking a handful of modules is
// a targeted, "polite" scan, so the broad Nuclei/secret-scan known-issue-scan pass
// is auto-skipped — matching an explicit `--skip known-issue-scan` — with a
// console note. It is a no-op when --only is set (which is mutually exclusive with
// --skip), when no module narrowing is active, when known-issue-scan is already
// off or already skipped. Silent under --silent.
func autoSkipKnownIssueScanForModuleSelection(opts *types.Options) {
	if opts == nil || opts.OnlyPhase != "" {
		return
	}
	if len(globalModuleIDs) == 0 && len(globalModules) == 0 {
		return
	}
	if !opts.KnownIssueScanEnabled {
		return
	}
	kis := string(runner.PhaseKnownIssueScan)
	for _, p := range opts.SkipPhases {
		if runner.NormalizeNativePhase(p) == kis {
			return // operator already skipped it explicitly
		}
	}
	opts.SkipPhases = append(opts.SkipPhases, kis)
	if !opts.Silent {
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			terminal.TipPrefix(),
			terminal.Gray("narrowed module selection (--module-id/-m) — auto-enabling --skip known-issue-scan (targeted scans stay polite; pass --only known-issue-scan to run it)"))
	}
}

// selectModulesByIDs resolves sentinel active/passive ID slices (nil = none,
// ["all"] = all, else exact IDs) into concrete module instances. Used by the
// direct single-request path (scan-url / scan-request).
func selectModulesByIDs(activeIDs, passiveIDs []string) ([]modules.ActiveModule, []modules.PassiveModule) {
	var active []modules.ActiveModule
	var passive []modules.PassiveModule
	if len(activeIDs) > 0 {
		if activeIDs[0] == "all" {
			active = modules.GetActiveModules()
		} else {
			active = modules.GetActiveModulesByIDs(activeIDs)
		}
	}
	if len(passiveIDs) > 0 {
		if passiveIDs[0] == "all" {
			passive = modules.GetPassiveModules()
		} else {
			passive = modules.GetPassiveModulesByIDs(passiveIDs)
		}
	}
	return active, passive
}

// validateModuleSelectionFlags rejects contradictory combinations and warns about
// --module-id values that match no known module. noPassive is the command's
// --no-passive value.
func validateModuleSelectionFlags(noPassive bool) error {
	if globalPassiveOnly && noPassive {
		return fmt.Errorf("--passive-only and --no-passive are mutually exclusive (nothing would run)")
	}
	if len(globalModuleIDs) == 0 {
		return nil
	}

	known := make(map[string]struct{})
	for _, id := range modules.GetActiveModulesID() {
		known[id] = struct{}{}
	}
	for _, id := range modules.GetPassiveModulesID() {
		known[id] = struct{}{}
	}
	for _, id := range globalModuleIDs {
		if _, ok := known[id]; !ok {
			zap.L().Warn("--module-id does not match any known module (exact match required; use -m for fuzzy matching)",
				zap.String("id", id))
		}
	}
	return nil
}
