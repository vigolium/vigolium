package agenttypes

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// InputType identifies the format of a raw input string.
type InputType string

const (
	InputTypeURL        InputType = "url"
	InputTypeCurl       InputType = "curl"
	InputTypeBurp       InputType = "burp"
	InputTypeRaw        InputType = "raw"
	InputTypeBase64     InputType = "base64"
	InputTypeRecordUUID InputType = "record_uuid"
	InputTypeUnknown    InputType = "unknown"
)

// AutopilotPipelineResult holds the outcome of an autopilot pipeline run.
type AutopilotPipelineResult struct {
	ArchonFindingsCount int
	Duration            time.Duration
	SessionDir          string
}

// SwarmPhase constants for the agent swarm mode.
// Phases prefixed with "native-" are executed by native Go code without AI agent involvement.
const (
	SwarmPhaseNormalize      = "native-normalize"
	SwarmPhaseAuth           = "auth"
	SwarmPhaseSourceAnalysis = "source-analysis"
	SwarmPhaseCodeAudit      = "code-audit"
	SwarmPhaseSAST           = "native-sast"
	SwarmPhaseSASTReview     = "sast-review"
	SwarmPhaseDiscover       = "native-discover"
	SwarmPhasePlan           = "plan"
	SwarmPhaseExtension      = "native-extension"
	SwarmPhaseScan           = "native-scan"
	SwarmPhaseTriage         = "triage"
	SwarmPhaseRescan         = "native-rescan"
)

// SwarmPhaseAliases maps legacy phase names to their current constant values.
// This provides backward compatibility for checkpoints, --start-from, and --skip flags.
var SwarmPhaseAliases = map[string]string{
	"normalize": SwarmPhaseNormalize,
	"sast":      SwarmPhaseSAST,
	"discover":  SwarmPhaseDiscover,
	"extension": SwarmPhaseExtension,
	"scan":      SwarmPhaseScan,
	"rescan":    SwarmPhaseRescan,
}

// NormalizeSwarmPhase resolves a phase name, accepting both current and legacy names.
func NormalizeSwarmPhase(phase string) string {
	if mapped, ok := SwarmPhaseAliases[phase]; ok {
		return mapped
	}
	return phase
}

// PhaseSkipped returns true if the given phase is in the skip list.
func PhaseSkipped(skipPhases []string, phase string) bool {
	for _, s := range skipPhases {
		if strings.EqualFold(s, phase) {
			return true
		}
	}
	return false
}

// ScanIntent holds structured parameters extracted from a natural language scan prompt.
type ScanIntent struct {
	Apps    []AppIntent   `json:"apps"`
	Raw     string        `json:"raw"`
	Cleanup *SetupCleanup `json:"cleanup,omitempty"` // resources created during SDK-based setup
}

// SetupCleanup tracks resources created during SDK-based intent setup
// that need to be cleaned up when the scan completes.
type SetupCleanup struct {
	DockerProjects []string `json:"docker_projects,omitempty"`
	Containers     []string `json:"containers,omitempty"`
	CloneDirs      []string `json:"-"` // populated locally, not from JSON
}

// Cleanup stops docker containers/projects created during setup.
// Safe to call on nil receiver.
func (sc *SetupCleanup) Cleanup() {
	if sc == nil {
		return
	}
	ctx := context.Background()
	for _, project := range sc.DockerProjects {
		zap.L().Info("Stopping docker compose project from setup", zap.String("project", project))
		cmd := exec.CommandContext(ctx, "docker", "compose", "-p", project, "down", "--timeout", "10")
		if err := cmd.Run(); err != nil {
			zap.L().Warn("Failed to stop docker project", zap.String("project", project), zap.Error(err))
		}
	}
	for _, container := range sc.Containers {
		cmd := exec.CommandContext(ctx, "docker", "rm", "-f", container)
		_ = cmd.Run()
	}
}

// IntentParseConfig holds optional configuration for intent parsing.
type IntentParseConfig struct {
	SessionsDir string
}

// IntentParseOption is a functional option for ParseScanIntent.
type IntentParseOption func(*IntentParseConfig)

// WithSessionsDir sets the sessions directory used for SDK-based setup (clone targets, etc.).
func WithSessionsDir(dir string) IntentParseOption {
	return func(c *IntentParseConfig) { c.SessionsDir = dir }
}

// AppIntent holds parameters for a single application to scan.
type AppIntent struct {
	Target      string   `json:"target,omitempty"`       // URL if mentioned
	SourcePath  string   `json:"source_path,omitempty"`  // filesystem path if mentioned
	Focus       string   `json:"focus,omitempty"`        // vulnerability focus if mentioned
	Instruction string   `json:"instruction,omitempty"`  // leftover context
	Discover    bool     `json:"discover,omitempty"`     // implied by target + source combo
	CodeAudit   bool     `json:"code_audit,omitempty"`   // implied by source-only
	Archon      string   `json:"archon,omitempty"`       // "lite", "scan", "deep", or "" (background archon-audit)
	Diff        string   `json:"diff,omitempty"`         // PR URL, git ref range (main...branch), or HEAD~N
	Files       []string `json:"files,omitempty"`        // specific files to focus on (relative to source)
	Browser     bool     `json:"browser,omitempty"`      // enable browser-based interaction
	MaxCommands int      `json:"max_commands,omitempty"` // command limit override
	Timeout     string   `json:"timeout,omitempty"`      // duration string (e.g. "2h", "30m")
	Intensity   string   `json:"intensity,omitempty"`    // "quick", "balanced", "deep"
}

// AuditAgentConfig configures a background archon-audit run.
type AuditAgentConfig struct {
	PluginDir   string
	Mode        string // "deep", "scan", or "lite"
	Platform    string // "claude" (default), "codex", or "opencode"
	SourcePath  string
	SessionDir  string
	ProjectUUID string
	ScanUUID    string

	// ParentRunUUID is the autopilot/swarm AgentRun UUID that spawned this audit.
	ParentRunUUID string

	SyncInterval time.Duration // how often to sync audit-state.json (default: 30s)
	StreamWriter io.Writer     // optional: stream audit output in real-time
}

// AuditAgentStatus summarizes the current state of the background audit.
type AuditAgentStatus struct {
	Running         bool   `json:"running"`
	Status          string `json:"status"`
	Mode            string `json:"mode"`
	Phase           string `json:"current_phase"`
	CompletedPhases int    `json:"completed_phases"`
	TotalPhases     int    `json:"total_phases"`
}

// ---------------------------------------------------------------------------
// Intensity presets
// ---------------------------------------------------------------------------

// Intensity represents the scan intensity level.
type Intensity string

const (
	IntensityQuick    Intensity = "quick"
	IntensityBalanced Intensity = "balanced"
	IntensityDeep     Intensity = "deep"
)

// ValidateIntensity normalizes and validates an intensity string.
// Returns IntensityBalanced for empty input.
func ValidateIntensity(s string) (Intensity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "balanced":
		return IntensityBalanced, nil
	case "quick":
		return IntensityQuick, nil
	case "deep":
		return IntensityDeep, nil
	default:
		return "", fmt.Errorf("invalid intensity %q: must be quick, balanced, or deep", s)
	}
}

// AutopilotIntensityPreset holds the preset values for autopilot at a given intensity.
type AutopilotIntensityPreset struct {
	MaxCommands int
	Timeout     time.Duration
	ArchonMode  string
	Browser     bool
	SkipSAST    bool
}

// SwarmIntensityPreset holds the preset values for swarm at a given intensity.
type SwarmIntensityPreset struct {
	Discover         bool
	CodeAudit        bool // applied only when source is provided
	Triage           bool
	MaxIterations    int
	Archon           string // archon mode when source is provided; empty = disabled
	MaxPlanRecords   int
	MasterBatchSize  int
	BatchConcurrency int
	ProbeConcurrency int
	Browser          bool
	Auth             bool // applied only when browser is enabled
	SwarmDuration    time.Duration
	SkipSAST         bool
}

// AutopilotPresets maps intensity levels to autopilot preset values.
var AutopilotPresets = map[Intensity]AutopilotIntensityPreset{
	IntensityQuick: {
		MaxCommands: 30,
		Timeout:     1 * time.Hour,
		ArchonMode:  "lite",
		Browser:     false,
		SkipSAST:    true,
	},
	IntensityBalanced: {
		MaxCommands: 100,
		Timeout:     6 * time.Hour,
		ArchonMode:  "scan",
		Browser:     false,
		SkipSAST:    false,
	},
	IntensityDeep: {
		MaxCommands: 300,
		Timeout:     12 * time.Hour,
		ArchonMode:  "deep",
		Browser:     true,
		SkipSAST:    false,
	},
}

// SwarmPresets maps intensity levels to swarm preset values.
var SwarmPresets = map[Intensity]SwarmIntensityPreset{
	IntensityQuick: {
		Discover:         false,
		CodeAudit:        false,
		Triage:           false,
		MaxIterations:    1,
		Archon:           "lite",
		MaxPlanRecords:   5,
		MasterBatchSize:  5,
		BatchConcurrency: 2,
		ProbeConcurrency: 15,
		Browser:          false,
		Auth:             false,
		SwarmDuration:    2 * time.Hour,
		SkipSAST:         true,
	},
	IntensityBalanced: {
		Discover:         false,
		CodeAudit:        true,
		Triage:           false,
		MaxIterations:    3,
		Archon:           "scan",
		MaxPlanRecords:   10,
		MasterBatchSize:  5,
		BatchConcurrency: 3,
		ProbeConcurrency: 10,
		Browser:          false,
		Auth:             false,
		SwarmDuration:    12 * time.Hour,
		SkipSAST:         false,
	},
	IntensityDeep: {
		Discover:         true,
		CodeAudit:        true,
		Triage:           true,
		MaxIterations:    5,
		Archon:           "deep",
		MaxPlanRecords:   20,
		MasterBatchSize:  10,
		BatchConcurrency: 5,
		ProbeConcurrency: 5,
		Browser:          true,
		Auth:             true,
		SwarmDuration:    24 * time.Hour,
		SkipSAST:         false,
	},
}

// NativeScanIntensityProfiles maps intensity levels to scanning profile names
// for native (non-agent) scan mode.
var NativeScanIntensityProfiles = map[Intensity]string{
	IntensityQuick:    "quick",
	IntensityBalanced: "standard",
	IntensityDeep:     "full",
}

// ExpandHome expands ~ prefix to the user's home directory.
func ExpandHome(path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home + path[1:]
	}
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home
	}
	return path
}
