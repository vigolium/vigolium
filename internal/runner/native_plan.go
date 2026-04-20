package runner

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/types"
)

type NativePhase string

const (
	PhaseHeuristicsCheck NativePhase = "heuristics-check"
	PhaseExternalHarvest NativePhase = "external-harvest"
	PhaseSpidering       NativePhase = "spidering"
	PhaseSAST            NativePhase = "sast"
	PhaseDiscovery       NativePhase = "discovery"
	PhaseSeed            NativePhase = "seed"
	PhaseKnownIssueScan  NativePhase = "known-issue-scan"
	PhaseDynamicAssessment NativePhase = "dynamic-assessment"
)

// ValidOnlyPhasesDesc and ValidSkipPhasesDesc are the human-readable phase lists
// rendered in --only/--skip validation error messages. Kept here so CLI and server
// error messages don't drift when aliases change.
const (
	ValidOnlyPhasesDesc = "ingestion, discovery (deparos), spidering (spitolas), external-harvest, known-issue-scan, sast, dynamic-assessment (dast, audit, assessment), extension (ext)"
	ValidSkipPhasesDesc = "discovery (deparos), external-harvest, spidering (spitolas), known-issue-scan, sast, dynamic-assessment (dast, audit, assessment)"
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
		{Phase: PhaseSAST, Enabled: opts.SASTEnabled},
		{Phase: PhaseDiscovery, Enabled: !opts.SkipIngestion},
		{Phase: PhaseSeed, Enabled: opts.SkipIngestion && !opts.ScanOnReceive && (opts.KnownIssueScanEnabled || !opts.SkipDynamicAssessment)},
		{Phase: PhaseKnownIssueScan, Enabled: opts.KnownIssueScanEnabled},
		{Phase: PhaseDynamicAssessment, Enabled: !opts.SkipDynamicAssessment},
	}
	return NativeScanPlan{Steps: steps}
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
	default:
		return phase
	}
}

func ApplyNativePhaseSelection(opts *types.Options, enableExtensions func()) error {
	if opts.OnlyPhase != "" && len(opts.SkipPhases) > 0 {
		return fmt.Errorf("--only and --skip are mutually exclusive; use one or the other")
	}

	opts.OnlyPhase = NormalizeNativePhase(opts.OnlyPhase)
	for i := range opts.SkipPhases {
		opts.SkipPhases[i] = NormalizeNativePhase(opts.SkipPhases[i])
	}

	if opts.OnlyPhase != "" {
		switch opts.OnlyPhase {
		case "ingestion":
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.KnownIssueScanEnabled = false
			opts.SkipDynamicAssessment = true
		case "discovery":
			opts.DiscoverEnabled = true
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.KnownIssueScanEnabled = false
			opts.SkipDynamicAssessment = true
		case "external-harvest":
			opts.ExternalHarvestEnabled = true
			opts.DiscoverEnabled = false
			opts.SpideringEnabled = false
			opts.KnownIssueScanEnabled = false
			opts.SkipIngestion = true
			opts.SkipDynamicAssessment = true
		case "spidering":
			opts.SpideringEnabled = true
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.KnownIssueScanEnabled = false
			opts.SkipIngestion = true
			opts.SkipDynamicAssessment = true
		case "known-issue-scan":
			opts.KnownIssueScanEnabled = true
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.SkipIngestion = true
			opts.SkipDynamicAssessment = true
		case "dynamic-assessment":
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.KnownIssueScanEnabled = false
			opts.SkipIngestion = true
			opts.SkipDynamicAssessment = false
		case "sast":
			opts.SASTEnabled = true
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.KnownIssueScanEnabled = false
			opts.SkipIngestion = true
			opts.SkipDynamicAssessment = true
		case "extension":
			opts.DiscoverEnabled = false
			opts.ExternalHarvestEnabled = false
			opts.SpideringEnabled = false
			opts.KnownIssueScanEnabled = false
			opts.SkipIngestion = true
			opts.SkipDynamicAssessment = false
			opts.ExtensionsOnly = true
			if enableExtensions != nil {
				enableExtensions()
			}
		default:
			return fmt.Errorf("invalid --only value %q; valid phases: %s", opts.OnlyPhase, ValidOnlyPhasesDesc)
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
			case "sast":
				opts.SASTEnabled = false
			case "dynamic-assessment":
				opts.SkipDynamicAssessment = true
			default:
				return fmt.Errorf("invalid --skip value %q; valid phases: %s", phase, ValidSkipPhasesDesc)
			}
		}
	}

	return nil
}
