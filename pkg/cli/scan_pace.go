package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// paceEnabledPhases lists the paceable phases this invocation will actually run,
// in execution order. Only phases that will run appear in the scan.started pace
// table — a table naming a phase the scan skipped is one a consumer has to
// filter before it can trust.
//
// Derived from the scan plan rather than from a copied set of predicates:
// BuildNativeScanPlan already answers "does this run phase X", and a second
// answer in this package would drift the first time a phase gate changes.
func paceEnabledPhases(opts *types.Options) []string {
	var out []string
	for _, phase := range plannedPhaseIDs(opts) {
		if pacePhases[phase] {
			out = append(out, phase)
		}
	}
	return out
}

// applyPhasePaceOverrides copies every `--flag phase=N` qualifier into the
// matching scanning_pace section, so one invocation can run two phases at
// different rates.
//
// Iterating each knob's own map (rather than packing the three into a struct
// first) keeps PRESENCE and VALUE together. Packing them lost the per-knob "was
// set" bit, so the writer had to re-derive it with `> 0` — which silently
// dropped `--rate-limit known-issue-scan=0`, the one value the flag's own error
// text documents as meaningful ("0 means unlimited").
func applyPhasePaceOverrides(settings *config.Settings, opts *types.Options) {
	running := map[string]bool{}
	for _, p := range paceEnabledPhases(opts) {
		running[p] = true
	}
	for _, knob := range []struct {
		k     *paceKnob
		field func(*config.PhasePace) *int
		// paceField names this dial in config.PhasePaceSupports terms, so the
		// "does this phase enforce it" question has one answer for the warning
		// here, the pace table, and the phase headers.
		paceField string
	}{
		{rateLimitKnob, func(p *config.PhasePace) *int { return &p.RateLimit }, config.PaceFieldRateLimit},
		{concurrencyKnob, func(p *config.PhasePace) *int { return &p.Concurrency }, config.PaceFieldConcurrency},
		{maxPerHostKnob, func(p *config.PhasePace) *int { return &p.MaxPerHost }, config.PaceFieldMaxPerHost},
	} {
		for _, phase := range sortedKeys(knob.k.perPhase) {
			// An unsupported dial is still written into the section — the value is
			// what the operator typed, and a later release that teaches the phase to
			// read it should not need the flag re-typed — but it is announced, and
			// resolvedPaceTable omits it so no consumer reads it as effective.
			//
			// A warning rather than an error for the same reason as the
			// not-running case below: failing the scan would make the flag hostile
			// to reuse, and the defect was silence, not permissiveness.
			if running[phase] && !config.PhasePaceSupports(phase, knob.paceField) {
				fmt.Fprintf(os.Stderr, "%s --%s override for phase %q is not enforced — that phase does not apply %s\n",
					terminal.WarnPrefix(), knob.k.flagName, phase, knob.paceField)
			}
			if !running[phase] {
				// A warning rather than an error: --only/--skip and the strategy
				// all change which phases run, and failing a scan because a pace
				// qualifier outlived a phase selection would make the flag hostile
				// to reuse across invocations. But say it loudly — silence here is
				// the failure mode the flag exists to remove.
				fmt.Fprintf(os.Stderr, "%s --%s override for phase %q ignored — this scan does not run that phase\n",
					terminal.WarnPrefix(), knob.k.flagName, phase)
				continue
			}
			// Section is never nil here: pacePhases is derived from the same
			// vocabulary, and Set already rejected anything outside it.
			if section := settings.ScanningPace.Section(phase); section != nil {
				*knob.field(section) = knob.k.perPhase[phase]
			}
		}
	}
}

// sortedKeys returns a map's keys in a stable order, so warnings and applied
// overrides do not reorder run to run.
func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolvedPaceTable returns the effective pace of every phase this scan runs,
// keyed by canonical phase id. Entries identical to the global pace are dropped:
// the table exists to show where a phase DIFFERS, and one that restates the
// global values for five phases buries the one line that matters.
//
// A field the phase does not ENFORCE is left at zero rather than reported, so the
// table says only what is true. It used to carry the resolved value for all three
// dials on every phase — a driver reading `scan.started` was told spidering ran at
// 100 rps and 40 per host, neither of which the crawler has any way to apply.
func resolvedPaceTable(settings *config.Settings, opts *types.Options) (scanevents.Pace, map[string]scanevents.Pace) {
	globalPace := scanevents.Pace{
		RateLimit:   opts.RateLimit,
		Concurrency: opts.Concurrency,
		MaxPerHost:  opts.MaxPerHost,
	}
	if settings == nil {
		return globalPace, nil
	}
	table := map[string]scanevents.Pace{}
	for _, phase := range paceEnabledPhases(opts) {
		resolved := settings.ScanningPace.ResolvePhase(phase)
		entry := scanevents.Pace{}
		if config.PhasePaceSupports(phase, config.PaceFieldRateLimit) {
			entry.RateLimit = resolved.RateLimit
			// Discovery enforces only an EXPLICIT rate; it does not inherit the
			// global 100 rps default (triage C13). Reporting the resolved value
			// would advertise a ceiling the crawl does not apply, which is the same
			// class of lie the support table exists to remove.
			if phase == "discovery" {
				entry.RateLimit = settings.ScanningPace.DiscoveryRateLimit(opts)
			}
			// Same rule for the known-issue scan: explicit, else its own 20 rps.
			if phase == "known-issue-scan" {
				entry.RateLimit = settings.ScanningPace.KnownIssueScanRateLimit(opts)
			}
		}
		if config.PhasePaceSupports(phase, config.PaceFieldConcurrency) {
			entry.Concurrency = resolved.Concurrency
		}
		if config.PhasePaceSupports(phase, config.PaceFieldMaxPerHost) {
			entry.MaxPerHost = resolved.MaxPerHost
		}
		// A phase that enforces NO pace field is omitted rather than reported as
		// three zeros. Spidering is the case: it runs one browser and has no
		// limiter, no rate and no host semaphore, and "concurrency 0" would be a
		// worse answer than no answer. For every phase that remains, concurrency
		// is enforced, and a zero rate_limit or max_per_host means exactly what a
		// zero means everywhere else in this vocabulary — unlimited.
		if entry == (scanevents.Pace{}) {
			continue
		}
		if entry != globalPace {
			table[phase] = entry
		}
	}
	if len(table) == 0 {
		return globalPace, nil
	}
	return globalPace, table
}
