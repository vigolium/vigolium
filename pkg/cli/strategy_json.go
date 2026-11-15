package cli

import (
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// `vigolium strategy` is a pure discovery surface: it exists to answer "what can
// I pass to --strategy, --only, --skip, --intensity, and --scanning-profile".
// That is exactly the question a driver asks before it can invoke anything else,
// and the command answered it with an ANSI-colored table on stdout — under -j
// too, with exit 0, so a consumer's parse failed for a reason the exit status
// did not mention.
//
// The vocabularies are read from their canonical owners (runner.PhaseVocabulary,
// agenttypes' presets, the ScanningStrategy config) rather than restated here,
// so a phase or intensity added upstream appears in this output without a second
// edit. A value that is runnable but undiscoverable is the failure mode this
// whole surface exists to prevent.

// strategyEntry reports which phases a named strategy turns on. The booleans are
// named for the canonical phase ids so a consumer can cross-reference `phases`
// without a mapping table.
type strategyEntry struct {
	Name              string `json:"name"`
	Default           bool   `json:"default"`
	ExternalHarvest   bool   `json:"external_harvest"`
	Discovery         bool   `json:"discovery"`
	Spidering         bool   `json:"spidering"`
	KnownIssueScan    bool   `json:"known_issue_scan"`
	DynamicAssessment bool   `json:"dynamic_assessment"`
}

type intensityEntry struct {
	Name    string `json:"name"`
	Default bool   `json:"default"`
	// NativeProfile is the native-scan profile this intensity selects.
	NativeProfile        string `json:"native_profile"`
	AutopilotMaxCommands int    `json:"autopilot_max_commands"`
	// AutopilotTimeout is rendered compactly ("6h", "1.5h") rather than as Go's
	// full "6h0m0s". Both are accepted by time.ParseDuration, and the compact
	// form is what the human table shows, so the two views agree literally.
	AutopilotTimeout   string   `json:"autopilot_timeout"`
	SwarmMaxIterations int      `json:"swarm_max_iterations"`
	SwarmTriage        bool     `json:"swarm_triage"`
	SwarmAuth          bool     `json:"swarm_auth"`
	AuditModes         []string `json:"audit_modes"`
}

type agentModeEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type profileEntry struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Path        string `json:"path"`
}

// emitStrategyJSON writes the discovery view. `items` carries the strategies —
// the thing the command is named for — with the other vocabularies as siblings,
// so the envelope's total/limit describe something meaningful.
func emitStrategyJSON(cmd *cobra.Command, cfg *config.ScanningStrategyConfig) error {
	strategies := strategyCatalog(cfg)
	profiles, profilesDir := profileCatalog(cfg)

	env := newMachineEnvelope(cmd, "strategies", strategies,
		int64(len(strategies)), 0, len(strategies))
	env.With("default_strategy", cfg.DefaultStrategy)
	if cfg.ScanningProfile != "" {
		env.With("scanning_profile", cfg.ScanningProfile)
	}
	env.With("phases", runner.PhaseVocabulary())
	env.With("intensities", scanIntensityCatalog())
	env.With("agent_modes", agentModeCatalog())
	env.With("profiles", profiles)
	if profilesDir != "" {
		env.With("profiles_dir", profilesDir)
	}
	return writeAgentJSON(env)
}

// strategyCatalog reports which phases each named strategy turns on.
func strategyCatalog(cfg *config.ScanningStrategyConfig) []strategyEntry {
	names := cfg.StrategyNames()
	out := make([]strategyEntry, 0, len(names))
	for _, name := range names {
		phases, _ := cfg.GetStrategy(name)
		out = append(out, strategyEntry{
			Name:              name,
			Default:           name == cfg.DefaultStrategy,
			ExternalHarvest:   phases.ExternalHarvesting,
			Discovery:         phases.Discovery,
			Spidering:         phases.Spidering,
			KnownIssueScan:    phases.KnownIssueScan,
			DynamicAssessment: phases.DynamicAssessment,
		})
	}
	return out
}

// scanIntensityCatalog is the one list of intensity levels and what each tunes,
// read by both the human table (printScanIntensities) and the -j discovery view,
// so the two cannot disagree about the ordering or which level is the default.
func scanIntensityCatalog() []intensityEntry {
	levels := []agenttypes.Intensity{
		agenttypes.IntensityQuick, agenttypes.IntensityBalanced, agenttypes.IntensityDeep,
	}
	out := make([]intensityEntry, 0, len(levels))
	for _, in := range levels {
		ap := agenttypes.AutopilotPresets[in]
		sw := agenttypes.SwarmPresets[in]
		au := agenttypes.AuditDriverPresets[in]
		out = append(out, intensityEntry{
			Name:                 string(in),
			Default:              in == agenttypes.IntensityBalanced,
			NativeProfile:        agenttypes.NativeScanIntensityProfiles[in],
			AutopilotMaxCommands: ap.MaxCommands,
			AutopilotTimeout:     humanHours(ap.Timeout),
			SwarmMaxIterations:   sw.MaxIterations,
			SwarmTriage:          sw.Triage,
			SwarmAuth:            sw.Auth,
			AuditModes:           append([]string(nil), au.Modes...),
		})
	}
	return out
}

// profileCatalog lists the installed scanning profiles and the directory they
// came from. An absent list is an empty slice, never nil: a consumer must not
// have to distinguish "no profiles installed" from "this field was omitted".
func profileCatalog(cfg *config.ScanningStrategyConfig) ([]profileEntry, string) {
	names, _ := cfg.ListProfiles()
	if len(names) == 0 {
		return []profileEntry{}, ""
	}
	out := make([]profileEntry, 0, len(names))
	for _, name := range names {
		path := cfg.ResolveProfilePath(name)
		out = append(out, profileEntry{
			Name:        name,
			Description: config.ProfileDescription(path),
			Path:        config.ContractPath(path),
		})
	}
	return out, config.ContractPath(config.ExpandPath(cfg.ProfilesDir))
}
