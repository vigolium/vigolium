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
	FindingsCount      int
	FindingsSaved      int
	FindingsBySeverity map[string]int
	OperatorFindingsCount    int // findings reported by the autonomous operator via report_finding
	VerifiedFindingCount     int
	Degraded                 bool
	Warnings                 []string
	BrowserDecision          string
	ArtifactsDir             string
	Duration                 time.Duration
	SessionDir               string
}

// AutopilotPhase constants for the agent autopilot mode console output.
const (
	AutopilotPhaseAudit    = "audit"
	AutopilotPhaseAutopilot = "autopilot"
)

// SwarmPhase constants for the agent swarm mode.
// Phases prefixed with "native-" are executed by native Go code without AI agent involvement.
const (
	SwarmPhaseNormalize       = "native-normalize"
	SwarmPhaseAuth            = "auth"
	SwarmPhaseSourceAnalysis  = "source-analysis"
	SwarmPhaseCodeAudit       = "code-audit"
	SwarmPhaseDiscover        = "native-discover"
	SwarmPhaseRecon           = "native-recon"
	SwarmPhasePlan            = "plan"
	SwarmPhaseExtension       = "native-extension"
	SwarmPhaseScan            = "native-scan"
	SwarmPhaseDiscoverReentry = "native-discover-reentry"
	SwarmPhaseReplanOnEmpty   = "replan-on-empty"
	SwarmPhaseTriage          = "triage"
	SwarmPhaseRescan          = "native-rescan"
)

// Record source labels used in HTTPRecord.Source to attribute where a
// record came from. Stable values used in DB rows and JSON exports.
const (
	RecordSourceDiscoverReentry = "swarm-discover-reentry"
)

// SwarmPhaseAliases maps legacy phase names to their current constant values.
// This provides backward compatibility for checkpoints, --start-from, and --skip flags.
var SwarmPhaseAliases = map[string]string{
	"normalize": SwarmPhaseNormalize,
	"discover":  SwarmPhaseDiscover,
	"recon":     SwarmPhaseRecon,
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

// WithSessionsDir sets the sessions directory used by intent-setup runs
// (clone targets, docker workdirs, etc.) when the agent must take real
// side effects before returning an intent.
func WithSessionsDir(dir string) IntentParseOption {
	return func(c *IntentParseConfig) { c.SessionsDir = dir }
}

// IntentCredentialSet represents a role/credential pair extracted from a prompt.
type IntentCredentialSet struct {
	Name     string `json:"name,omitempty"`
	Role     string `json:"role,omitempty"` // "primary" or "compare"
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// AppIntent holds parameters for a single application to scan.
type AppIntent struct {
	Target          string                `json:"target,omitempty"`            // URL if mentioned
	SourcePath      string                `json:"source_path,omitempty"`       // filesystem path if mentioned
	Focus           string                `json:"focus,omitempty"`             // vulnerability focus if mentioned
	Instruction     string                `json:"instruction,omitempty"`       // leftover context
	Discover        bool                  `json:"discover,omitempty"`          // implied by target + source combo
	CodeAudit       bool                  `json:"code_audit,omitempty"`        // implied by source-only
	Audit          string                `json:"audit,omitempty"`            // "lite", "balanced", "deep", or "" (background vigolium-audit)
	Piolium         string                `json:"piolium,omitempty"`           // piolium mode: "lite", "balanced", "deep", "longshot", etc., or "" (auto-pick / unset)
	Diff            string                `json:"diff,omitempty"`              // PR URL, git ref range (main...branch), or HEAD~N
	Files           []string              `json:"files,omitempty"`             // specific files to focus on (relative to source)
	Browser         bool                  `json:"browser,omitempty"`           // enable browser-based interaction
	MaxCommands     int                   `json:"max_commands,omitempty"`      // command limit override
	Timeout         string                `json:"timeout,omitempty"`           // duration string (e.g. "2h", "30m")
	Intensity       string                `json:"intensity,omitempty"`         // "quick", "balanced", "deep"
	Credentials     string                `json:"credentials,omitempty"`       // compact credential hint, e.g. "admin/admin123"
	CredentialSets  []IntentCredentialSet `json:"credential_sets,omitempty"`   // structured roles/accounts
	AuthRequired    bool                  `json:"auth_required,omitempty"`     // explicit auth intent from prompt
	RequiresBrowser bool                  `json:"requires_browser,omitempty"`  // explicit browser requirement from prompt
	BrowserStartURL string                `json:"browser_start_url,omitempty"` // explicit login/start URL
	FocusRoutes     []string              `json:"focus_routes,omitempty"`      // explicit auth/browser focus routes
}

// AuditDriverAgent identifies the underlying CLI/SDK adapter the embedded
// vigolium-audit binary will drive on this run. Maps to vigolium-audit's `--agent`
// (claude|codex). Empty falls back to claude (vigolium-audit default).
type AuditDriverAgent string

const (
	AuditDriverAgentClaude AuditDriverAgent = "claude"
	AuditDriverAgentCodex  AuditDriverAgent = "codex"
)

// AuditDriverAuthFlags are the one-shot auth overrides vigolium-audit accepts.
// Empty fields mean "inherit ambient auth" — audit falls back to the
// agent CLI's standard credential store.
type AuditDriverAuthFlags struct {
	APIKey        string // --api-key
	OAuthToken    string // --oauth-token
	OAuthCredFile string // --oauth-cred-file
}

// AuthOverride is a per-run BYOK bundle the operator passes via the
// `vigolium agent audit` CLI flags or the /api/agent/run/audit body. At
// most one of APIKey / OAuthToken / OAuthCredFile should be set
// (validated centrally; see agent.ValidateAuthOverride). Empty struct =
// inherit agent.olium.* config, which is the existing pre-BYOK behavior.
//
// Same struct flows to both audit drivers:
//   - audit: the resolver folds it into AuditDriverAuthFlags so vigolium-audit
//     gets --api-key / --oauth-token / --oauth-cred-file directly.
//   - piolium: vigolium maps it to env vars on the pi subprocess (pi has
//     no equivalent CLI flags), and stages oauth_cred_file at
//     <pi-agent-dir>/auth.json with backup-and-restore for codex.
//
// Agent is the resolved audit-style identity ("claude" or "codex") this
// auth applies to. The CLI/REST entry point fills it in from
// --provider / `agent` (or, when those are empty, from
// agent.olium.provider). It exists on AuthOverride rather than being
// re-derived inside each driver so both audit and piolium see the same
// answer to "is this a claude key or a codex key?".
type AuthOverride struct {
	APIKey        string
	OAuthToken    string
	OAuthCredFile string
	Agent         string
}

// IsZero reports whether no override fields are set. Used by callers to
// short-circuit the resolver and keep the existing inherit-config path.
// Agent alone is not significant — it carries no secret on its own and a
// bare Agent string with no key fields means "no override".
func (o AuthOverride) IsZero() bool {
	return o.APIKey == "" && o.OAuthToken == "" && o.OAuthCredFile == ""
}

// AuditDriverInvocation collects the agent + auth tuple the audit launcher
// needs to compose vigolium-audit invocation args. Returned by
// ResolveAuditDriverInvocation so each entry point shares one resolution
// path.
type AuditDriverInvocation struct {
	Agent AuditDriverAgent
	Auth  AuditDriverAuthFlags
}

// Args renders the invocation as the slice of CLI flags appended to
// `audit run`. The agent flag is always emitted (defaulting to
// claude); auth flags are emitted only when non-empty.
func (i AuditDriverInvocation) Args() []string {
	agent := i.Agent
	if agent == "" {
		agent = AuditDriverAgentClaude
	}
	args := []string{"--agent", string(agent)}
	if i.Auth.APIKey != "" {
		args = append(args, "--api-key", i.Auth.APIKey)
	}
	if i.Auth.OAuthToken != "" {
		args = append(args, "--oauth-token", i.Auth.OAuthToken)
	}
	if i.Auth.OAuthCredFile != "" {
		args = append(args, "--oauth-cred-file", i.Auth.OAuthCredFile)
	}
	return args
}

// HarnessSpec describes the on-disk layout, slash-command shape, and DB
// metadata for an audit-flavored audit harness. Audit (claude/codex)
// and piolium (pi) share the same parser and audit-state.json
// schema but differ in folder names, slash command, env-var prefix, and DB
// import metadata.
type HarnessSpec struct {
	// Name is the harness identifier. "audit" and "piolium" are recognized.
	// An empty Name defaults to audit for backward compatibility.
	Name string
	// SourceFolder is the directory the harness writes under <source>/ during
	// the run (e.g. "audit", "piolium").
	SourceFolder string
	// SessionSubdir is where vigolium syncs the harness output under the
	// session dir (e.g. "vigolium-results", "piolium").
	SessionSubdir string
	// EnvPrefix is the prefix for env vars exported to the agent process
	// (e.g. "ARCHON_", "PIOLIUM_").
	EnvPrefix string
	// DBMode populates database.AgenticScan.Mode (e.g. "audit", "piolium").
	DBMode string
	// DBAgentName populates database.AgenticScan.AgentName (e.g. "vigolium-audit",
	// "piolium").
	DBAgentName string
	// DBInputType populates database.AgenticScan.InputType.
	DBInputType string
	// FindingIDPrefix is the module_id prefix on imported findings (e.g.
	// "audit" → "audit:c1-...", "piolium" → "piolium:c1-...").
	FindingIDPrefix string
	// FindingTag is added to every imported finding's tag list.
	FindingTag string
}

// AuditAgentConfig configures a background audit- or piolium-flavored audit run.
type AuditAgentConfig struct {
	// Harness selects the audit harness flavor. Zero-valued (empty Name)
	// is treated as the audit harness for backward compatibility.
	Harness HarnessSpec

	Mode        string // "deep", "balanced", "lite", "merge", "revisit", etc.
	Platform    string // "audit" (embedded vigolium-audit binary) or "pi" (piolium)
	SourcePath  string
	SessionDir  string
	ProjectUUID string
	ScanUUID    string

	// Modes is the mode chain for this run. Empty (or single-element)
	// behaves exactly like the legacy single-Mode path. With >1 element:
	//   - audit: rendered as `--modes a,b,c` (audit owns the sequential
	//     execution, stop-on-non-complete, and aggregate cost cap).
	//   - piolium: the chain is driven by PioliumChainScanner, which runs
	//     one `pi` subprocess per supported mode in the same source dir and
	//     collapses them into a single aggregated AgenticScan row.
	// EffectiveModes() normalizes this to always return at least one mode.
	Modes []string

	// ForceAgenticScanUUID, when non-empty, overrides the UUID the runner
	// would otherwise derive. Set by PioliumChainScanner so every per-mode
	// inner runner imports its findings under the one aggregated child row.
	ForceAgenticScanUUID string

	// SuppressAgenticScanRow makes the runner skip AgenticScan row
	// create/progress/finalize bookkeeping while STILL importing findings
	// (under the shared UUID) and computing the cost summary. Used for the
	// per-mode inner runners of a piolium chain — the chain scanner owns
	// the single aggregated row instead.
	SuppressAgenticScanRow bool

	// KeepSourceOutputDir suppresses the per-run cleanup of
	// <source>/<harness>/ after the subprocess exits. The piolium chain
	// sets it on every mode except the last so a later confirm/revisit
	// mode can read the prior mode's on-disk audit-state.json.
	KeepSourceOutputDir bool

	// KeepRaw maps to vigolium-audit's `--keep-raw` flag: opt out of the
	// deep/confirm auto-prune of raw scanner output, draft findings, and
	// intermediate workspaces so the operator can review them under
	// <source>/vigolium-results/ (and the synced session copy). Audit-only;
	// ignored for the piolium harness.
	KeepRaw bool

	// AuditDriverInvocation carries the `--agent` + auth-override args the
	// vigolium-audit binary needs. Resolved by callers from OliumConfig (or a
	// CLI override) and passed through to buildAuditAgentCommand.
	// Empty Agent falls back to claude (vigolium-audit's own default).
	// Ignored for the piolium harness.
	AuditDriverInvocation AuditDriverInvocation

	// ParentAgenticScanUUID is the autopilot/swarm AgenticScan UUID that spawned this audit.
	ParentAgenticScanUUID string

	SyncInterval time.Duration // how often to sync audit-state.json (default: 30s)
	StreamWriter io.Writer     // optional: stream audit output in real-time

	// Stream enables Claude's stream-json output format and live rendering via
	// the claudestream package. Only meaningful for the "claude" platform and
	// when StreamWriter is non-nil. Other platforms ignore this flag.
	Stream bool

	// ShowThinking opts into rendering the agent's internal thinking blocks
	// (audit NDJSON `thinking` events) to the live stream. Off by default
	// because thinking is very noisy and chains often hundreds of blocks
	// per phase. The CLI flag `--show-thinking` (and the equivalent REST
	// field) sets this.
	ShowThinking bool

	// CommitScanLimit caps deep-mode commit archaeology to at most N commits.
	// 0 keeps the upstream default (500).
	CommitScanLimit int
	// CommitScanSince caps deep-mode commit archaeology to commits since this
	// git date expression. Empty keeps the upstream default ("60 days ago").
	CommitScanSince string

	// AdditionalArgs are appended verbatim to the agent process argv after
	// the harness-specific args. Used by piolium for --plm-* passthroughs
	// (e.g. --plm-phase-retries, --plm-longshot-limit). Ignored for audit.
	AdditionalArgs []string

	// PiProvider and PiModel, when set, are passed to `pi` as
	// `--provider <name> --model <id>` so a single audit run can override
	// the user's defaultProvider/defaultModel from ~/.pi/agent/settings.json.
	// Only consumed by the pi platform; ignored for audit.
	PiProvider string
	PiModel    string

	// StreamDecoder, when non-nil, decodes the agent process's stdout as
	// line-oriented JSON and renders it to render. Raw lines are mirrored
	// to raw (typically <sessionDir>/audit-stream.jsonl) for replay.
	// Claude has a built-in default; piolium passes pistream.Stream.
	StreamDecoder func(stream io.Reader, render io.Writer, raw io.Writer) error

	// AuthOverride carries per-run BYOK creds (api key, oauth token, or
	// codex cred file) supplied via the audit CLI flags or REST body. It
	// has already been folded into AuditDriverInvocation by the resolver, so
	// the audit launch path does NOT consult this field directly. The
	// piolium launcher reads it to (a) inject ANTHROPIC_API_KEY /
	// CLAUDE_CODE_OAUTH_TOKEN / OPENAI_API_KEY env on the pi subprocess
	// and (b) stage a codex cred file at <pi-agent-dir>/auth.json for
	// the duration of the run. Empty = no override (inherit ambient
	// auth from agent.olium.* / pi settings).
	AuthOverride AuthOverride
}

// EffectiveModes normalizes the run's mode chain. It always returns at
// least one mode: cfg.Modes when set, otherwise the single cfg.Mode (and
// "lite" as the last-resort default, matching the legacy behavior).
func (c AuditAgentConfig) EffectiveModes() []string {
	var out []string
	for _, m := range c.Modes {
		if s := strings.TrimSpace(m); s != "" {
			out = append(out, s)
		}
	}
	if len(out) > 0 {
		return out
	}
	if s := strings.TrimSpace(c.Mode); s != "" {
		return []string{s}
	}
	return []string{"lite"}
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

// Scanning strategy names accepted by runner.LaunchParams.ScanningStrategy
// and the run_scan tool's enum. Centralized here so preset wiring and tests
// stay in lockstep with the runner's expectations.
const (
	ScanStrategyLite     = "lite"
	ScanStrategyBalanced = "balanced"
	ScanStrategyDeep     = "deep"
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
	AuditDriverMode  string
	Browser     bool
	// NativeScanStrategy is the scanning_strategy passed to the pre-scan
	// kicked off in target-only autopilot runs (no --source). Maps onto the
	// runner.LaunchParams.ScanningStrategy enum: "lite"|"balanced"|"deep".
	// The pre-scan seeds http_records and findings into the DB before the
	// operator agent loop starts, so the agent has real traffic to reason
	// about and richer raw material for custom JS extensions.
	NativeScanStrategy string
	// NoPrescan disables the autopilot pre-scan entirely. Default false;
	// flipped true via the --no-prescan flag for operators who already ran
	// a scan or want a cold-start blackbox session.
	NoPrescan bool
}

// AuditDriverIntensityPreset holds the preset values for the foreground audit
// audit (vigolium agent audit / POST /api/agent/run/audit) at a given
// intensity. Mode maps onto the audit harness mode string (lite/balanced/deep).
// Modes carries the full mode chain — a single-element slice for the simple
// presets, multi-element for chained presets (deep = [deep, confirm]). Mode
// stays populated with Modes[0] for the many single-mode consumers
// (settings.yaml audit config, piolium ResolvePioliumAuditConfig) that do not
// chain. Timeout is only consumed by the API path; the CLI audit command runs
// as a foreground process and takes no overall timeout flag.
type AuditDriverIntensityPreset struct {
	Mode        string
	Modes       []string
	Timeout     time.Duration
	CommitDepth int // git clone --depth (0 = full history, used for deep commit archaeology)
}

// SwarmIntensityPreset holds the preset values for swarm at a given intensity.
type SwarmIntensityPreset struct {
	Discover         bool
	CodeAudit        bool // applied only when source is provided
	Triage           bool
	MaxIterations    int
	Audit           string // audit mode when source is provided; empty = disabled
	MaxPlanRecords   int
	MasterBatchSize  int
	BatchConcurrency int
	ProbeConcurrency int
	Browser          bool
	Auth             bool // applied only when browser is enabled
	SwarmDuration    time.Duration
}

// AutopilotPresets maps intensity levels to autopilot preset values.
var AutopilotPresets = map[Intensity]AutopilotIntensityPreset{
	IntensityQuick: {
		MaxCommands:        150,
		Timeout:            1 * time.Hour,
		AuditDriverMode:         "lite",
		Browser:            true,
		NativeScanStrategy: ScanStrategyLite,
	},
	IntensityBalanced: {
		MaxCommands:        500,
		Timeout:            6 * time.Hour,
		AuditDriverMode:         "balanced",
		Browser:            true,
		NativeScanStrategy: ScanStrategyBalanced,
	},
	IntensityDeep: {
		MaxCommands:        1500,
		Timeout:            12 * time.Hour,
		AuditDriverMode:         "deep",
		Browser:            true,
		NativeScanStrategy: ScanStrategyDeep,
	},
}

// SwarmPresets maps intensity levels to swarm preset values.
var SwarmPresets = map[Intensity]SwarmIntensityPreset{
	IntensityQuick: {
		Discover:         true,
		CodeAudit:        false,
		Triage:           false,
		MaxIterations:    1,
		Audit:           "lite",
		MaxPlanRecords:   10,
		MasterBatchSize:  5,
		BatchConcurrency: 2,
		ProbeConcurrency: 15,
		Browser:          true,
		Auth:             false,
		SwarmDuration:    2 * time.Hour,
	},
	IntensityBalanced: {
		Discover:         true,
		CodeAudit:        true,
		Triage:           true,
		MaxIterations:    3,
		Audit:           "balanced",
		MaxPlanRecords:   25,
		MasterBatchSize:  5,
		BatchConcurrency: 3,
		ProbeConcurrency: 10,
		Browser:          true,
		Auth:             false,
		SwarmDuration:    12 * time.Hour,
	},
	IntensityDeep: {
		Discover:         true,
		CodeAudit:        true,
		Triage:           true,
		MaxIterations:    5,
		Audit:           "deep",
		MaxPlanRecords:   50,
		MasterBatchSize:  10,
		BatchConcurrency: 5,
		ProbeConcurrency: 5,
		Browser:          true,
		Auth:             true,
		SwarmDuration:    24 * time.Hour,
	},
}

// AuditDriverPresets maps intensity levels to audit preset values.
//
// deep intensity chains [deep, confirm]: a full audit followed by a
// confirmation pass that boots the target and executes PoCs against the
// findings deep surfaced. quick/balanced stay single-mode. Mode is the
// first element of Modes so single-mode consumers keep working unchanged.
var AuditDriverPresets = map[Intensity]AuditDriverIntensityPreset{
	IntensityQuick: {
		Mode:        "lite",
		Modes:       []string{"lite"},
		Timeout:     1 * time.Hour,
		CommitDepth: 1,
	},
	IntensityBalanced: {
		Mode:        "balanced",
		Modes:       []string{"balanced"},
		Timeout:     6 * time.Hour,
		CommitDepth: 1,
	},
	IntensityDeep: {
		Mode:        "deep",
		Modes:       []string{"deep", "confirm"},
		Timeout:     12 * time.Hour,
		CommitDepth: 0, // full history — deep mode runs commit archaeology
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
