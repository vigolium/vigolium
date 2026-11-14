package runner

import (
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/types"
)

// ModuleSelection is the built-in module set a run executes, plus what the
// broad-selection gates dropped and why. FilterModulesForRun builds it; the
// runner (getModulesToExecute) and the scan plan (ResolvePlan) both read it, so
// the plan's module counts are the runner's by construction.
type ModuleSelection struct {
	Active  []modules.ActiveModule
	Passive []modules.PassiveModule

	// TierCeiling is the intensity's tier rank ceiling.
	TierCeiling int
	// ActiveByConfig / PassiveByConfig report a dynamic-assessment
	// enabled_modules allowlist narrowing an "all" selection.
	ActiveByConfig, PassiveByConfig bool
	// Dropped module ids per gate, active then passive.
	TierDeferred      []string
	RiskWithheld      []string
	HygieneSuppressed []string

	// Per-category drops, for the runner's log lines.
	activeTier, passiveTier, activeRisk, passiveRisk, activeHygiene, passiveHygiene []string
}

// tierNames maps a tier rank to its tag, for the plan.
var tierNames = map[int]string{
	modules.TierRankLight:     modules.TagTierLight,
	modules.TierRankModerate:  modules.TagTierModerate,
	modules.TierRankHeavy:     modules.TagTierHeavy,
	modules.TierRankIntrusive: modules.TagTierIntrusive,
}

// FilterModulesForRun resolves the built-in modules a scan with these options
// and settings runs. Pure: no logging, no I/O.
//
// Sentinel convention for opts.Modules / opts.PassiveModules: a nil/empty
// slice selects ZERO modules for that category; []string{"all"} selects every
// module; any other list selects those IDs. Callers disable a whole category by
// leaving its slice empty — e.g. scan-url's --no-passive nils PassiveModules and
// server's --passive-only nils Modules. Do not make an empty slice default to
// "all" without updating those callers.
//
// The gates below (config allowlist, intensity tier ceiling, risk:high
// withholding, hardening advisories) only narrow a broad ("all") selection: an
// explicit -m / --module-tag list or a config allowlist reflects deliberate
// intent and runs verbatim.
func FilterModulesForRun(opts *types.Options, settings *config.Settings) ModuleSelection {
	var sel ModuleSelection
	if opts == nil {
		return sel
	}

	activeUsingAll := false
	if len(opts.Modules) > 0 {
		if opts.Modules[0] == "all" {
			sel.Active = modules.GetActiveModules()
			activeUsingAll = true
		} else {
			sel.Active = modules.GetActiveModulesByIDs(opts.Modules)
		}
	}
	passiveUsingAll := false
	if len(opts.PassiveModules) > 0 {
		if opts.PassiveModules[0] == "all" {
			sel.Passive = modules.GetPassiveModules()
			passiveUsingAll = true
		} else {
			sel.Passive = modules.GetPassiveModulesByIDs(opts.PassiveModules)
		}
	}

	// A config allowlist is a deliberate selection, so it also opts out of the
	// gates below.
	if settings != nil {
		if activeUsingAll && !isAllModules(settings.DynamicAssessment.EnabledModules.ActiveModules) {
			sel.Active = modules.GetActiveModulesByIDs(settings.DynamicAssessment.EnabledModules.ActiveModules)
			sel.ActiveByConfig = true
		}
		if passiveUsingAll && !isAllModules(settings.DynamicAssessment.EnabledModules.PassiveModules) {
			sel.Passive = modules.GetPassiveModulesByIDs(settings.DynamicAssessment.EnabledModules.PassiveModules)
			sel.PassiveByConfig = true
		}
	}
	gateActive := activeUsingAll && !sel.ActiveByConfig
	gatePassive := passiveUsingAll && !sel.PassiveByConfig

	sel.TierCeiling = scanTierCeiling(opts)
	if gateActive {
		sel.Active, sel.activeTier = partitionModules(sel.Active, aboveTier[modules.ActiveModule](sel.TierCeiling))
	}
	if gatePassive {
		sel.Passive, sel.passiveTier = partitionModules(sel.Passive, aboveTier[modules.PassiveModule](sel.TierCeiling))
	}

	// risk:high modules (state-changing or target-degrading probes) are
	// withheld below deep unless the operator opted in.
	if !RiskyPayloadsAllowed(opts, settings) {
		if gateActive {
			sel.Active, sel.activeRisk = partitionModules(sel.Active, isRiskHigh[modules.ActiveModule])
		}
		if gatePassive {
			sel.Passive, sel.passiveRisk = partitionModules(sel.Passive, isRiskHigh[modules.PassiveModule])
		}
	}

	// The hardening-advisory gate, with one extra escape hatch: a selection
	// naming any hygiene module keeps the whole family (HygieneGateActive).
	if HygieneGateActive(opts, settings) {
		if gateActive {
			sel.Active, sel.activeHygiene = partitionModules(sel.Active, isHygiene[modules.ActiveModule])
		}
		if gatePassive {
			sel.Passive, sel.passiveHygiene = partitionModules(sel.Passive, isHygiene[modules.PassiveModule])
		}
	}

	// Execution priority order, aligned with the executor's scheduling policy.
	sortActiveModulesByPriority(sel.Active)
	sortPassiveModulesByPriority(sel.Passive)

	sel.TierDeferred = append(append([]string(nil), sel.activeTier...), sel.passiveTier...)
	sel.RiskWithheld = append(append([]string(nil), sel.activeRisk...), sel.passiveRisk...)
	sel.HygieneSuppressed = append(append([]string(nil), sel.activeHygiene...), sel.passiveHygiene...)
	return sel
}
