package agent

import (
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// ResolveAutopilotIntensity merges intensity preset values with user-provided overrides.
// The changed map indicates which fields were explicitly set by the user (CLI flag or API field).
// Explicit values in current take precedence over the preset.
func ResolveAutopilotIntensity(intensity agenttypes.Intensity, current agenttypes.AutopilotIntensityPreset, changed map[string]bool) agenttypes.AutopilotIntensityPreset {
	preset, ok := agenttypes.AutopilotPresets[intensity]
	if !ok {
		preset = agenttypes.AutopilotPresets[agenttypes.IntensityBalanced]
	}

	result := preset
	if changed["max-commands"] {
		result.MaxCommands = current.MaxCommands
	}
	if changed["timeout"] {
		result.Timeout = current.Timeout
	}
	if changed["audit-mode"] || changed["no-audit"] {
		result.AuditDriverMode = current.AuditDriverMode
	}
	if changed["browser"] {
		result.Browser = current.Browser
	}
	if changed["no-prescan"] {
		result.NoPrescan = current.NoPrescan
	}

	return result
}

// ResolveSwarmIntensity merges intensity preset values with user-provided overrides.
// The changed map indicates which fields were explicitly set by the user (CLI flag or API field).
// Explicit values in current take precedence over the preset.
func ResolveSwarmIntensity(intensity agenttypes.Intensity, current agenttypes.SwarmIntensityPreset, changed map[string]bool) agenttypes.SwarmIntensityPreset {
	preset, ok := agenttypes.SwarmPresets[intensity]
	if !ok {
		preset = agenttypes.SwarmPresets[agenttypes.IntensityBalanced]
	}

	result := preset
	if changed["discover"] {
		result.Discover = current.Discover
	}
	if changed["code-audit"] {
		result.CodeAudit = current.CodeAudit
	}
	if changed["triage"] {
		result.Triage = current.Triage
	}
	if changed["max-iterations"] {
		result.MaxIterations = current.MaxIterations
	}
	if changed["audit"] {
		result.Audit = current.Audit
	}
	if changed["max-plan-records"] {
		result.MaxPlanRecords = current.MaxPlanRecords
	}
	if changed["master-batch-size"] {
		result.MasterBatchSize = current.MasterBatchSize
	}
	if changed["batch-concurrency"] {
		result.BatchConcurrency = current.BatchConcurrency
	}
	if changed["probe-concurrency"] {
		result.ProbeConcurrency = current.ProbeConcurrency
	}
	if changed["browser"] {
		result.Browser = current.Browser
	}
	if changed["auth"] {
		result.Auth = current.Auth
	}
	if changed["swarm-duration"] {
		result.SwarmDuration = current.SwarmDuration
	}

	return result
}

// ResolveAuditDriverIntensity merges intensity preset values with user-provided overrides.
// The changed map indicates which fields were explicitly set by the user (CLI flag or API field).
// Explicit values in current take precedence over the preset.
//
// Note: audit also accepts operational modes (revisit, confirm, merge, diff,
// status, mock) that are not intensity-driven. Callers must pass changed["mode"]=true
// (or changed["modes"]=true for a chain) when the user supplied an explicit
// --mode / --modes field, which then bypasses the preset's chain entirely.
//
// Mode and Modes are kept consistent on the result: Mode is always Modes[0]
// so single-mode consumers stay correct even when a chain preset is selected.
func ResolveAuditDriverIntensity(intensity agenttypes.Intensity, current agenttypes.AuditDriverIntensityPreset, changed map[string]bool) agenttypes.AuditDriverIntensityPreset {
	preset, ok := agenttypes.AuditDriverPresets[intensity]
	if !ok {
		preset = agenttypes.AuditDriverPresets[agenttypes.IntensityBalanced]
	}

	result := preset
	switch {
	case changed["modes"]:
		result.Modes = current.Modes
	case changed["mode"]:
		// Single explicit --mode collapses the chain to that one mode.
		result.Modes = []string{current.Mode}
	}
	// Keep Mode == Modes[0] for the single-mode consumers (settings.yaml
	// audit cfg, piolium single-mode resolution) that never chain.
	if len(result.Modes) > 0 {
		result.Mode = result.Modes[0]
	} else if result.Mode != "" {
		result.Modes = []string{result.Mode}
	}
	if changed["timeout"] {
		result.Timeout = current.Timeout
	}
	if changed["commit-depth"] {
		result.CommitDepth = current.CommitDepth
	}

	return result
}

// ResolveNativeScanIntensity validates the intensity string and returns the
// corresponding scanning profile name. It also sets opts.Intensity for logging.
func ResolveNativeScanIntensity(intensityStr string) (profileName string, resolvedIntensity string, err error) {
	intensity, err := agenttypes.ValidateIntensity(intensityStr)
	if err != nil {
		return "", "", err
	}
	return agenttypes.NativeScanIntensityProfiles[intensity], string(intensity), nil
}
