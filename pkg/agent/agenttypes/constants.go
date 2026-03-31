package agenttypes

import (
	"context"
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

// AutopilotPhase identifies a phase in the autopilot pipeline.
type AutopilotPhase string

const (
	AutopilotPhaseRecon         AutopilotPhase = "recon"
	AutopilotPhaseVulnAnalysis  AutopilotPhase = "vuln-analysis"
	AutopilotPhaseNativeScan    AutopilotPhase = "native-scan"
	AutopilotPhaseExploitVerify AutopilotPhase = "exploit-verify"
	AutopilotPhaseReport        AutopilotPhase = "report"
)

// VulnClass identifies a vulnerability class for specialist agents.
type VulnClass string

const (
	VulnClassInjection VulnClass = "injection"
	VulnClassXSS       VulnClass = "xss"
	VulnClassAuth      VulnClass = "auth"
	VulnClassSSRF      VulnClass = "ssrf"
	VulnClassAuthz     VulnClass = "authz"
)

// ToVulnClasses converts string slice to VulnClass slice.
func ToVulnClasses(ss []string) []VulnClass {
	result := make([]VulnClass, len(ss))
	for i, s := range ss {
		result[i] = VulnClass(s)
	}
	return result
}

// AutopilotPipelineResult holds the outcome of an autopilot pipeline run.
type AutopilotPipelineResult struct {
	VulnQueues     map[VulnClass]*VulnQueue
	Evidence       map[VulnClass][]ExploitationEvidence
	TotalFindings  int
	Confirmed      int
	FalsePositives int
	PhasesRun      []AutopilotPhase
	PhaseTimings   map[AutopilotPhase]time.Duration
	PhaseFailed    map[AutopilotPhase]bool // tracks which phases failed
	Duration       time.Duration
	SessionDir     string
}

// AutopilotCheckpoint captures autopilot pipeline state for checkpoint/resume.
type AutopilotCheckpoint struct {
	CompletedPhases             []AutopilotPhase          `json:"completed_phases"`
	TargetURL                   string                    `json:"target_url"`
	VulnQueues                  map[VulnClass]*VulnQueue  `json:"vuln_queues,omitempty"`
	ExtensionDir                string                    `json:"extension_dir,omitempty"`
	Timestamp                   time.Time                 `json:"timestamp"`
	CompletedSpecialists        map[VulnClass]bool        `json:"completed_specialists,omitempty"`
	CompletedExploitSpecialists map[VulnClass]bool        `json:"completed_exploit_specialists,omitempty"`
}

// LastPhase returns the last completed phase, or "" if none.
func (cp *AutopilotCheckpoint) LastPhase() AutopilotPhase {
	if cp == nil || len(cp.CompletedPhases) == 0 {
		return ""
	}
	return cp.CompletedPhases[len(cp.CompletedPhases)-1]
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
	Target      string `json:"target,omitempty"`      // URL if mentioned
	SourcePath  string `json:"source_path,omitempty"` // filesystem path if mentioned
	Focus       string `json:"focus,omitempty"`       // vulnerability focus if mentioned
	Instruction string `json:"instruction,omitempty"` // leftover context
	Discover    bool   `json:"discover,omitempty"`    // implied by target + source combo
	CodeAudit   bool   `json:"code_audit,omitempty"`  // implied by source-only
	Archon      string `json:"archon,omitempty"`      // "lite", "scan", "deep", or "" (background archon-audit)
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
