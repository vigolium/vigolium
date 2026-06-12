package runner

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/types"
)

type NativePhase string

const (
	PhaseHeuristicsCheck   NativePhase = "heuristics-check"
	PhaseExternalHarvest   NativePhase = "external-harvest"
	PhaseSpidering         NativePhase = "spidering"
	PhaseDiscovery         NativePhase = "discovery"
	PhaseTargetedReSpider  NativePhase = "targeted-respider"
	PhaseSeed              NativePhase = "seed"
	PhaseKnownIssueScan    NativePhase = "known-issue-scan"
	PhaseDynamicAssessment NativePhase = "dynamic-assessment"
)

// ValidOnlyPhasesDesc and ValidSkipPhasesDesc are the human-readable phase lists
// rendered in --only/--skip validation error messages. Kept here so CLI and server
// error messages don't drift when aliases change.
const (
	ValidOnlyPhasesDesc = "ingestion, discovery (deparos), spidering (spitolas), external-harvest, dynamic-assessment (dast, audit, assessment), known-issue-scan (cve, kis), extension (ext)"
	ValidSkipPhasesDesc = "discovery (deparos), external-harvest, spidering (spitolas), dynamic-assessment (dast, audit, assessment), known-issue-scan (cve, kis)"
)

type NativePhaseStep struct {
	Phase   NativePhase
	Enabled bool
}

type NativeScanPlan struct {
	Steps []NativePhaseStep
}

func BuildNativeScanPlan(opts *types.Options) NativeScanPlan {
	steps := []NativePhaseStep{
		{Phase: PhaseHeuristicsCheck, Enabled: opts.HeuristicsCheck != "" && opts.HeuristicsCheck != "none"},
		{Phase: PhaseExternalHarvest, Enabled: opts.ExternalHarvestEnabled},
		{Phase: PhaseSpidering, Enabled: opts.SpideringEnabled},
		{Phase: PhaseDiscovery, Enabled: !opts.SkipIngestion},
		// Re-spider rich/SPA routes that discovery surfaced after the one-shot
		// browser crawl. Rides along only when browsers are allowed (spidering
		// enabled), discovery ran, and an assessment phase will consume the new
		// records. The config toggle + runtime gates are checked in the phase.
		{Phase: PhaseTargetedReSpider, Enabled: opts.SpideringEnabled && !opts.SkipIngestion && !opts.SkipDynamicAssessment},
		{Phase: PhaseSeed, Enabled: opts.SkipIngestion && !opts.ScanOnReceive && (opts.KnownIssueScanEnabled || !opts.SkipDynamicAssessment)},
		{Phase: PhaseDynamicAssessment, Enabled: !opts.SkipDynamicAssessment},
		{Phase: PhaseKnownIssueScan, Enabled: opts.KnownIssueScanEnabled},
	}
	return NativeScanPlan{Steps: steps}
}

// parseOnlyPhases parses a comma-separated --only value into a normalized
// set + ordered slice. Empty entries are skipped, duplicates collapse, and an
// unknown phase produces an error using the canonical phase list.
func parseOnlyPhases(raw string) (map[string]bool, []string, error) {
	parts := strings.Split(raw, ",")
	allowed := make(map[string]bool, len(parts))
	normalized := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n := NormalizeNativePhase(p)
		switch n {
		case "ingestion", "discovery", "external-harvest", "spidering",
			"known-issue-scan", "dynamic-assessment", "extension":
		default:
			return nil, nil, fmt.Errorf("invalid --only value %q; valid phases: %s", p, ValidOnlyPhasesDesc)
		}
		if !allowed[n] {
			allowed[n] = true
			normalized = append(normalized, n)
		}
	}
	if len(allowed) == 0 {
		return nil, nil, fmt.Errorf("--only requires at least one phase; valid phases: %s", ValidOnlyPhasesDesc)
	}
	return allowed, normalized, nil
}

// OnlyPhaseSet returns the set of normalized phases listed in a comma-separated
// --only value. Callers use it to gate behavior that depends on which phases
// are active (e.g. validating that --format=html was scoped to phases that
// produce a report). Returns nil for empty input.
func OnlyPhaseSet(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		set[NormalizeNativePhase(p)] = true
	}
	return set
}

func NormalizeNativePhase(phase string) string {
	switch phase {
	case "deparos":
		return "discovery"
	case "discover":
		return "discovery"
	case "spitolas":
		return "spidering"
	case "ext":
		return "extension"
	case "audit", "dast", "assessment":
		return "dynamic-assessment"
	case "cve", "kis", "known-issues":
		return "known-issue-scan"
	default:
		return phase
	}
}

func ApplyNativePhaseSelection(opts *types.Options, enableExtensions func()) error {
	if opts.OnlyPhase != "" && len(opts.SkipPhases) > 0 {
		return fmt.Errorf("--only and --skip are mutually exclusive; use one or the other")
	}

	for i := range opts.SkipPhases {
		opts.SkipPhases[i] = NormalizeNativePhase(opts.SkipPhases[i])
	}

	if opts.OnlyPhase != "" {
		allowed, normalized, err := parseOnlyPhases(opts.OnlyPhase)
		if err != nil {
			return err
		}
		opts.OnlyPhase = strings.Join(normalized, ",")

		opts.DiscoverEnabled = allowed["discovery"]
		opts.ExternalHarvestEnabled = allowed["external-harvest"]
		opts.SpideringEnabled = allowed["spidering"]
		opts.KnownIssueScanEnabled = allowed["known-issue-scan"]
		opts.SkipIngestion = !allowed["discovery"] && !allowed["ingestion"]
		opts.SkipDynamicAssessment = !allowed["dynamic-assessment"] && !allowed["extension"]
		if allowed["extension"] {
			opts.ExtensionsOnly = true
			if enableExtensions != nil {
				enableExtensions()
			}
		}
		opts.HeuristicsCheck = "none"
	}

	if len(opts.SkipPhases) > 0 {
		for _, phase := range opts.SkipPhases {
			switch phase {
			case "discovery", "ingestion":
				opts.SkipIngestion = true
			case "external-harvest":
				opts.ExternalHarvestEnabled = false
			case "spidering":
				opts.SpideringEnabled = false
			case "known-issue-scan":
				opts.KnownIssueScanEnabled = false
			case "dynamic-assessment":
				opts.SkipDynamicAssessment = true
			default:
				return fmt.Errorf("invalid --skip value %q; valid phases: %s", phase, ValidSkipPhasesDesc)
			}
		}
	}

	return nil
}
