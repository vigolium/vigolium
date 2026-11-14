package runner

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// intensityTierCeiling maps a resolved scan intensity to the maximum module
// tier rank that runs. A module runs when its tier rank is <= the ceiling;
// untagged modules (modules.TierAlwaysOn == 0) always run.
//
//	quick    -> moderate   drops the heavy blind/timing probes and the rare
//	                       intrusive checks for a fast pass
//	balanced -> intrusive  runs the full battery including the intrusive checks
//	                       (this is the default; the tier gate only trims at quick)
//	deep     -> intrusive  runs everything
//
// Profile-name aliases ("lite"/"standard"/"full") and the empty string (which
// defaults to balanced) are accepted so the ceiling is robust to either the
// raw --intensity value or a resolved profile name. balanced and deep share the
// intrusive ceiling — deep still differs via its other deep-only behaviors
// (scope expansion, full dashboard sweep, ScanContext.DeepScan), not the tier gate.
// scanTierCeiling is the module tier ceiling for a scan: --safe caps it at
// moderate; otherwise the typed --intensity decides, else the RESOLVED
// scanning profile (a config default_profile or --scanning-profile quick is the
// quick preset too, and used to run intrusive modules because only the
// --intensity spelling was consulted).
func scanTierCeiling(opts *types.Options) int {
	if opts == nil {
		return intensityTierCeiling("")
	}
	if opts.Safe {
		return modules.TierRankModerate
	}
	if opts.Intensity != "" {
		return intensityTierCeiling(opts.Intensity)
	}
	return intensityTierCeiling(opts.ScanningProfile)
}

func intensityTierCeiling(intensity string) int {
	switch strings.ToLower(strings.TrimSpace(intensity)) {
	case "quick", "lite":
		return modules.TierRankModerate
	default: // "", "balanced", "standard", "deep", "full"
		return modules.TierRankIntrusive
	}
}

// resolveAllowRiskyPayloads resolves the operator's risky-payload opt-in.
// Precedence follows the config chain: an explicit --allow-risky-payloads
// (true or false) wins; otherwise dynamic-assessment.allow_risky_payloads from
// the merged global → project → profile settings; otherwise off. Deep intensity
// is applied separately (RiskyPayloadsAllowed), so this is the opt-in alone.
func resolveAllowRiskyPayloads(opts *types.Options, settings *config.Settings) bool {
	if opts != nil && opts.AllowRiskyPayloads != nil {
		return *opts.AllowRiskyPayloads
	}
	return settings != nil && settings.DynamicAssessment.AllowRiskyPayloads
}

// RiskyPayloadsAllowed reports whether risk:high payloads and modules run for a
// scan with these options and settings: always at --intensity deep, otherwise
// only with the --allow-risky-payloads / config opt-in.
func RiskyPayloadsAllowed(opts *types.Options, settings *config.Settings) bool {
	if opts != nil && opts.Safe {
		return false // --safe: never, whatever the intensity or opt-in says
	}
	if opts != nil && isDeepIntensity(opts.Intensity) {
		return true
	}
	return resolveAllowRiskyPayloads(opts, settings)
}

// isDeepIntensity matches the deep preset and its profile-name alias.
func isDeepIntensity(intensity string) bool {
	switch strings.ToLower(strings.TrimSpace(intensity)) {
	case "deep", "full":
		return true
	}
	return false
}

func (r *Runner) riskyPayloadsAllowed() bool {
	if r == nil {
		return false
	}
	return RiskyPayloadsAllowed(r.options, r.settings)
}

// loginCredsPolicy resolves the spider's common-credential login pass for an
// intensity in one place: enabled off at quick/lite (a fast pass never makes
// active login attempts), on with the full documented list at deep/full, and on
// with the minimal set (admin:admin, admin:123456) otherwise — balanced and the
// empty default. This mirrors intensityTierCeiling's alias split; the two
// coupled decisions live in a single switch so they can't drift.
func loginCredsPolicy(intensity string) (enabled, fullList bool) {
	switch strings.ToLower(strings.TrimSpace(intensity)) {
	case "quick", "lite":
		return false, false
	case "deep", "full":
		return true, true
	default: // "", "balanced", "standard"
		return true, false
	}
}

// accountActions is the resolved register/login-attempt permission plus where
// each value came from ("" = the built-in default).
type accountActions struct {
	register, login, fullList   bool
	registerSource, loginSource string
	conflicts                   []string
}

// resolveAccountActions resolves register/login-attempt permission.
// Precedence: explicit config (spidering.interaction.*) wins over the intensity
// default, in both directions — a deny survives --intensity deep, and an
// explicit allow survives --intensity quick. Intensity only picks a default and
// only ever sizes the credential list.
//
// Registration has no intensity default at all: it is a write, and a work
// budget is not an authorization. It is on only when spidering.interaction.
// register_account or the legacy spidering.self_register says so, with the
// explicit interaction key winning a disagreement.
func resolveAccountActions(sp config.SpideringConfig, intensity string) accountActions {
	var a accountActions
	a.login, a.fullList = loginCredsPolicy(intensity)
	if a.login {
		a.loginSource = policySourceIntensity
	}
	if v := sp.Interaction.LoginAttempts; v != nil {
		a.login = *v
		a.loginSource = policySourceConfig
	}

	if sp.SelfRegister {
		a.register = true
		a.registerSource = policySourceSelfRegister
	}
	if v := sp.Interaction.RegisterAccount; v != nil {
		if sp.SelfRegister && !*v {
			a.conflicts = append(a.conflicts, "spidering.interaction.register_account=false overrides spidering.self_register=true")
		}
		a.register = *v
		a.registerSource = policySourceConfig
	}
	return a
}

// hygieneModulesEnabled reports whether the hardening-advisory family (modules
// tagged modules.TagHygiene — missing security headers, weak TLS protocol/cipher
// policy, cookie attributes, CSP/HSTS/SRI audits) runs at this intensity.
//
// They are off below deep. Each fires on nearly every response of nearly every
// host, so at the default intensity they produce one near-identical Info/Low row
// per crawled URL and bury the exploitable findings — the same reasoning that
// keeps the known-issue scan at critical+high by default (see
// config.DefaultKnownIssueScanConfig). Nothing downstream consumes them: unlike
// the Info-tier fingerprints and endpoint/param observers, no tech tag, surface
// score, or active module reads a hygiene finding.
//
// The alias split mirrors intensityTierCeiling/loginCredsPolicy. Operators get
// them back per-scan with --intensity deep, --module-tag hygiene, or
// --module-id <id>, and globally with dynamic-assessment.hygiene_modules.
func hygieneModulesEnabled(intensity string) bool {
	switch strings.ToLower(strings.TrimSpace(intensity)) {
	case "deep", "full":
		return true
	default: // "", "balanced", "standard", "quick", "lite"
		return false
	}
}

// resolveHygieneModules resolves whether hygiene modules run for this scan.
// Precedence: an explicit config value (dynamic-assessment.hygiene_modules) wins
// over the intensity default, so an operator who wants the hardening advisories
// in every report — or who wants them suppressed even at deep — says so once.
// Unset (nil) falls through to hygieneModulesEnabled.
func resolveHygieneModules(opts *types.Options, settings *config.Settings) bool {
	if settings != nil && settings.DynamicAssessment.HygieneModules != nil {
		return *settings.DynamicAssessment.HygieneModules
	}
	intensity := ""
	if opts != nil {
		intensity = opts.Intensity
	}
	return hygieneModulesEnabled(intensity)
}

func (r *Runner) resolveHygieneModules() bool {
	if r == nil {
		return hygieneModulesEnabled("")
	}
	return resolveHygieneModules(r.options, r.settings)
}

// selectsHygieneModule reports whether an explicit module ID selection names at
// least one hygiene module. `--module-tag hygiene` resolves to exact IDs for the
// active category but leaves the passive category on the "all" sentinel, so
// without this check the passive two-thirds of the family would be gated away by
// the very selection that asked for it.
func selectsHygieneModule(ids []string) bool {
	if len(ids) == 0 || ids[0] == "all" {
		return false
	}
	for _, m := range modules.GetActiveModulesByIDs(ids) {
		if modules.IsHygieneModule(m.Tags()) {
			return true
		}
	}
	for _, m := range modules.GetPassiveModulesByIDs(ids) {
		if modules.IsHygieneModule(m.Tags()) {
			return true
		}
	}
	return false
}

// HygieneGateActive reports whether a scan with these options and settings
// suppresses the hardening-advisory family: the resolved policy says no AND the
// operator has not named one of them explicitly.
//
// Exported because the CLI prints its own pre-scan banner before a Runner
// exists, and a banner that counts modules the scan will not run makes the gate
// look like a lost finding. Both banners and the module filter read this.
func HygieneGateActive(opts *types.Options, settings *config.Settings) bool {
	if opts == nil {
		return false
	}
	return !resolveHygieneModules(opts, settings) &&
		!selectsHygieneModule(opts.Modules) &&
		!selectsHygieneModule(opts.PassiveModules)
}

// countHygieneModules returns how many of the given modules carry TagHygiene.
func countHygieneModules[T modules.Module](mods []T) int {
	n := 0
	for _, m := range mods {
		if modules.IsHygieneModule(m.Tags()) {
			n++
		}
	}
	return n
}

// HygieneBannerCounts adjusts a scan banner's module counts for the
// hardening-advisory gate and returns the note to append, empty when the family
// runs. One implementation for the two pre-scan banners (CLI and runner).
func HygieneBannerCounts(opts *types.Options, settings *config.Settings, active []modules.ActiveModule, passive []modules.PassiveModule) (activeCount, passiveCount int, note string) {
	activeCount, passiveCount = len(active), len(passive)
	if !HygieneGateActive(opts, settings) {
		return activeCount, passiveCount, ""
	}
	activeHygiene, passiveHygiene := countHygieneModules(active), countHygieneModules(passive)
	if activeHygiene+passiveHygiene == 0 {
		return activeCount, passiveCount, ""
	}
	// Point at the knob that is actually holding them back: --intensity deep does
	// nothing when the config already forced them off.
	hint := "--intensity deep or --module-tag hygiene to include"
	if settings != nil && settings.DynamicAssessment.HygieneModules != nil {
		hint = "off via dynamic-assessment.hygiene_modules"
	}
	return activeCount - activeHygiene, passiveCount - passiveHygiene,
		terminal.Gray(fmt.Sprintf("(%d hardening advisories off; %s)", activeHygiene+passiveHygiene, hint))
}

// partitionModules splits mods into the ones drop keeps and the ids of the
// ones it drops. The pure half of every module filter below: the runner's
// filters log what they dropped, FilterModulesForRun (and so the scan plan)
// only counts it.
func partitionModules[T modules.Module](mods []T, drop func(T) bool) (kept []T, dropped []string) {
	if len(mods) == 0 {
		return mods, nil
	}
	kept = make([]T, 0, len(mods))
	for _, m := range mods {
		if drop(m) {
			dropped = append(dropped, m.ID())
			continue
		}
		kept = append(kept, m)
	}
	return kept, dropped
}

func isHygiene[T modules.Module](m T) bool { return modules.IsHygieneModule(m.Tags()) }

func isRiskHigh[T modules.Module](m T) bool { return modules.IsRiskHighModule(m.Tags()) }

func aboveTier[T modules.Module](ceiling int) func(T) bool {
	return func(m T) bool { return modules.ModuleTierRank(m.Tags()) > ceiling }
}

// filterHygieneModules drops modules tagged modules.TagHygiene and logs what was
// suppressed. Shared by the active and passive filters; kind labels the log line.
func filterHygieneModules[T modules.Module](r *Runner, mods []T, kind string) []T {
	kept, dropped := partitionModules(mods, isHygiene[T])
	logHygieneSuppressed(r.intensityLabel(), kind, dropped)
	return kept
}

func logHygieneSuppressed(intensity, kind string, dropped []string) {
	if len(dropped) > 0 {
		zap.L().Info(kind+" hardening-advisory modules suppressed (use --intensity deep, --module-tag hygiene, or dynamic-assessment.hygiene_modules)",
			zap.String("intensity", intensity),
			zap.Int("suppressed", len(dropped)),
			zap.Strings("ids", dropped))
	}
}

// intensityLabel returns the resolved intensity for logging, tolerating a nil
// options (e.g. in unit tests that exercise the filters directly).
func (r *Runner) intensityLabel() string {
	if r == nil || r.options == nil {
		return ""
	}
	return r.options.Intensity
}

// filterModulesByTier drops modules whose tier rank exceeds the ceiling and logs
// what was deferred. It is shared by the active and passive filters (both element
// types embed modules.Module); kind labels the log line ("Active"/"Passive").
func filterModulesByTier[T modules.Module](r *Runner, mods []T, ceiling int, kind string) []T {
	kept, dropped := partitionModules(mods, aboveTier[T](ceiling))
	logTierDeferred(r.intensityLabel(), kind, ceiling, dropped)
	return kept
}

func logTierDeferred(intensity, kind string, ceiling int, dropped []string) {
	if len(dropped) > 0 {
		zap.L().Info(kind+" modules deferred by intensity tier",
			zap.String("intensity", intensity),
			zap.Int("ceiling", ceiling),
			zap.Int("deferred", len(dropped)),
			zap.Strings("ids", dropped))
	}
}

// filterRiskHighModules drops modules tagged modules.TagRiskHigh and logs what
// was withheld. Shared by the active and passive filters; kind labels the log.
func filterRiskHighModules[T modules.Module](r *Runner, mods []T, kind string) []T {
	kept, dropped := partitionModules(mods, isRiskHigh[T])
	logRiskWithheld(r.intensityLabel(), kind, dropped)
	return kept
}

func logRiskWithheld(intensity, kind string, dropped []string) {
	if len(dropped) > 0 {
		zap.L().Info(kind+" risk:high modules withheld (use --intensity deep, --allow-risky-payloads, or -m <id>)",
			zap.String("intensity", intensity),
			zap.Int("withheld", len(dropped)),
			zap.Strings("ids", dropped))
	}
}

// filterActiveModulesByTier drops active modules whose tier rank exceeds the ceiling.
func (r *Runner) filterActiveModulesByTier(mods []modules.ActiveModule, ceiling int) []modules.ActiveModule {
	return filterModulesByTier(r, mods, ceiling, "Active")
}

// filterActiveHygieneModules drops active hardening-advisory modules.
func (r *Runner) filterActiveHygieneModules(mods []modules.ActiveModule) []modules.ActiveModule {
	return filterHygieneModules(r, mods, "Active")
}

// filterPassiveHygieneModules drops passive hardening-advisory modules. Most of
// the family is passive, so unlike the tier gate this one does real work.
func (r *Runner) filterPassiveHygieneModules(mods []modules.PassiveModule) []modules.PassiveModule {
	return filterHygieneModules(r, mods, "Passive")
}
