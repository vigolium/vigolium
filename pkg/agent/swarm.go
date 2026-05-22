package agent

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	agentprompt "github.com/vigolium/vigolium/pkg/agent/prompt"
	"github.com/vigolium/vigolium/pkg/audit/claudecost"
	"github.com/vigolium/vigolium/pkg/database"

	"go.uber.org/zap"
)

// SwarmConfig configures an agent swarm run.
type SwarmConfig struct {
	// Inputs: raw input strings (URL, curl, raw HTTP, Burp XML, or record UUID)
	Inputs    []string  // raw input strings
	InputType InputType // explicit type (auto-detected if empty)

	// Source analysis
	SourcePath  string                  // path to application source code (triggers source analysis phase)
	Files       []string                // specific files to include (relative to SourcePath)
	DiffContext *agenttypes.DiffContext // non-nil when --diff or --last-commits was provided

	// Custom instruction
	Instruction string // user-provided custom instruction appended to agent prompts

	// ForceExtensions forces the Phase-2 extension agent to run even when the
	// plan agent decides built-in modules are sufficient. Bound to --with-extensions
	// on the CLI. Has no effect when DryRun is true (DryRun still skips Phase 2).
	ForceExtensions bool

	// Scanning parameters
	VulnType         string   // optional: focus on specific vulnerability type
	Focus            string   // optional: broad strategic hint (e.g. "API injection", "auth bypass")
	ModuleNames      []string // optional: explicit module IDs to use
	OnlyPhase        string   // isolate a single phase (empty = all phases)
	SkipPhases       []string // skip specific phases (empty = skip none)
	MaxIterations    int      // max triage-rescan loops (default 3)
	BatchConcurrency int      // max parallel master agent batches (0 = default 3)
	MaxMasterRetries int      // max master agent retries on parse failure (0 = default 3)
	SAMaxConcurrency int      // max parallel source analysis sub-agents (0 = default 3)

	// Agent
	AgentName          string
	DryRun             bool
	ShowPrompt         bool   // print rendered prompts to stderr before executing
	SourceAnalysisOnly bool   // run only source analysis phase and exit
	CodeAudit          bool   // enable AI security code audit phase (--code-audit)
	Browser            bool   // enable agent-browser integration (--browser)
	Auth               bool   // run browser-based auth phase before discovery (--browser-auth, requires Browser)
	Credentials        string // optional credentials for browser auth phase (--credentials)
	CredentialSets     []agenttypes.IntentCredentialSet
	AuthRequired       bool
	RequiresBrowser    bool
	BrowserStartURL    string
	FocusRoutes        []string

	// Context truncation
	MaxResponseBodyBytes int // max response body size in context; 0 = default 4096
	MaxPlanRecords       int // max records sent to plan agent; 0 = no cap (ship the full surface)

	// Tuning: batching, probing, retries
	MasterBatchSize  int           // max records per master agent batch; 0 = default 5
	ProbeConcurrency int           // max parallel probe requests; 0 = default 10
	ProbeTimeout     time.Duration // per-request probe timeout; 0 = default 10s
	MaxProbeBodySize int           // max response body bytes during probing; 0 = default 2MB

	// ReconExtraHeaders, when set, is injected onto every recon probe
	// (and into the prompt-context's TechStack rendering). Populated by
	// the CLI from --cookie / --header / --auth-config so that recon
	// fingerprints authenticated pages instead of the public landing.
	ReconExtraHeaders map[string]string

	// Project/scan

	ProjectUUID string
	ScanUUID    string

	// Session directory base path for agent artifacts
	SessionsDir string

	// SessionDir is the pre-created session directory for this run.
	// When set, the swarm runner uses it directly instead of creating one.
	SessionDir string

	// AgenticScanUUID overrides the auto-generated agent run UUID.
	// When set (e.g. by CLI), the swarm runner uses this UUID for the DB record,
	// ensuring it matches the pre-created session directory name.
	AgenticScanUUID string

	// ResumeDir is the session directory of a previous run to resume from.
	// When set, the swarm runner loads the checkpoint and skips completed phases.
	ResumeDir string

	// Streaming
	StreamWriter     io.Writer
	Verbose          bool // when true, agent calls render a per-tool result preview alongside the standard one-liner
	ProgressCallback func(ProgressEvent)

	// ScanFunc runs the scan with the given module filters and extensions.
	ScanFunc ScanFunc

	// DiscoverFunc runs native discovery+spidering before master agent planning.
	// When set, the swarm runner executes discovery and feeds discovered records
	// into the master agent alongside the original inputs.
	DiscoverFunc func(ctx context.Context) error

	// SourceAnalysisCallback is called after source analysis completes to allow
	// the caller to process session config (e.g., convert to auth-config.yaml)
	// and extensions before the scan phase.
	SourceAnalysisCallback func(result *SourceAnalysisResult) error

	// BrowserAuthCallback is fired after the browser-based auth phase writes
	// an auth-config.yaml to the session dir. The CLI uses this to thread
	// the captured session into the discovery + scan funcs so the native
	// spider (and downstream scan) crawl post-login surface. Empty path =
	// auth phase ran but produced no config; the caller may treat that as
	// a soft failure.
	BrowserAuthCallback func(authConfigPath string) error

	// PhaseCallback is called when a swarm phase starts.
	PhaseCallback func(phase string)

	// Audit is the background-audit cfg slot — backed by either audit or
	// piolium per AuditHarness. Requires SourcePath to be non-empty. Field
	// name is legacy; the runtime is harness-agnostic.
	Audit *config.AuditAgentConfig

	// AuditHarness selects which harness backs the Audit cfg. Zero-valued
	// defaults to audit for backward compat.
	AuditHarness HarnessSpec
}

// Prompt template constants for the agent swarm mode.
const (
	SwarmPromptPlan       = "agent-swarm-plan"
	SwarmPromptExtensions = "agent-swarm-extensions"
	SwarmPromptCodeAudit  = "swarm-code-audit"
	SwarmPromptTriage     = "agent-swarm-triage"
	SwarmPromptAuth       = "agent-swarm-auth"
)

// SwarmRunner orchestrates AI-guided targeted vulnerability scanning.
type SwarmRunner struct {
	engine *Engine
	repo   *database.Repository

	// extensionCache memoises successful runExtensionAgent results within
	// a process lifetime, keyed by a hash of (target + focus areas +
	// module tags). Keeps repeat planner runs on the same target — e.g.
	// rescan loops, batched fan-out, or two `vigolium agent swarm` calls
	// against the same site in one shell session — from re-invoking the
	// extension LLM round when the plan inputs haven't materially changed.
	extensionCache sync.Map // map[string]extensionCacheEntry
}

// extensionCacheEntry is a stored result from a successful extension-agent
// call. RawOutput is preserved so the merged plan's transcript stays
// faithful even on cache hits.
type extensionCacheEntry struct {
	Plan      *SwarmPlan
	RawOutput string
}

type swarmRecordStats struct {
	Initial   int
	Source    int
	Discovery int
}

// NewSwarmRunner creates a swarm runner.
func NewSwarmRunner(engine *Engine, repo *database.Repository) *SwarmRunner {
	return &SwarmRunner{
		engine: engine,
		repo:   repo,
	}
}

// persistPhase updates the agent run's current phase in the database.
func (s *SwarmRunner) persistPhase(ctx context.Context, agenticScan *database.AgenticScan) {
	if s.repo != nil {
		if err := s.repo.UpdateAgenticScan(ctx, agenticScan); err != nil {
			zap.L().Debug("Failed to persist phase update", zap.Error(err))
		}
	}
}

// probeConfig returns a ProbeConfig from the swarm's tuning parameters.
func (cfg *SwarmConfig) probeConfig() ProbeConfig {
	return ProbeConfig{
		Concurrency: cfg.ProbeConcurrency,
		Timeout:     cfg.ProbeTimeout,
		MaxBodySize: cfg.MaxProbeBodySize,
	}
}

// Run executes the full agent swarm pipeline.
func (s *SwarmRunner) Run(ctx context.Context, cfg SwarmConfig) (*SwarmResult, error) {
	start := time.Now()

	// Set up context cache for DB enrichment across phases. ttl=0 means
	// entries live for the full run; we explicitly InvalidateContextCache
	// after phases that mutate findings/records (native scan, rescan), which
	// is the only real staleness window. A short TTL would just guarantee
	// misses on a multi-minute swarm.
	if s.engine != nil {
		s.engine.SetContextCache(agentprompt.NewContextCache(0))
	}

	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 3
	}
	// Resolve tuning defaults
	if cfg.MasterBatchSize <= 0 {
		cfg.MasterBatchSize = 5
	}
	// Resolve agent name to default if empty — ensures the DB record has the effective name
	if cfg.AgentName == "" && s.engine != nil && s.engine.settings != nil {
		cfg.AgentName = s.engine.settings.Agent.DefaultAgent
	}
	var protocol, model string
	if s.engine != nil && s.engine.settings != nil {
		protocol, model = s.engine.settings.Agent.BackendMeta()
	}
	// Create agent run record — use pre-assigned UUID if provided (e.g. from CLI session dir)
	agenticScanUUID := cfg.AgenticScanUUID
	if agenticScanUUID == "" {
		agenticScanUUID = uuid.New().String()
	}
	agenticScan := &database.AgenticScan{
		UUID:        agenticScanUUID,
		ProjectUUID: cfg.ProjectUUID,
		ScanUUID:    cfg.ScanUUID,
		Mode:        "swarm",
		AgentName:   cfg.AgentName,
		Protocol:    protocol,
		Model:       model,
		VulnType:    cfg.VulnType,
		ModuleNames: cfg.ModuleNames,
		SourcePath:  cfg.SourcePath,
		SourceType:  database.InferSourceType(cfg.SourcePath),
		SessionDir:  cfg.SessionDir,
		Status:      "running",
		StartedAt:   start,
	}
	if len(cfg.Inputs) > 0 {
		agenticScan.InputRaw = cfg.Inputs[0]
	}

	if s.repo != nil {
		// Upsert: when the API handler / CLI pre-inserted a row under our
		// agenticScanUUID, double-inserting would hit the unique constraint and log
		// a spurious warning. Probe first; update-with-OmitZero keeps any
		// caller-set fields (target_url, parent_run_uuid, …) intact.
		if existing, _ := s.repo.GetAgenticScan(ctx, agenticScanUUID); existing != nil {
			if err := s.repo.UpdateAgenticScan(ctx, agenticScan); err != nil {
				zap.L().Warn("Failed to seed existing agent run record", zap.Error(err))
			}
		} else {
			if err := s.repo.CreateAgenticScan(ctx, agenticScan); err != nil {
				zap.L().Warn("Failed to create agent run record", zap.Error(err))
			}
		}
	}

	result := &SwarmResult{AgenticScanUUID: agenticScanUUID}

	// Fail fast on a broken olium provider so callers don't pay for
	// normalize + discovery before the very first LLM call dies on a
	// missing credential. Mirrors autopilot's RunAutonomous preflight.
	var err error
	if s.engine != nil {
		if perr := s.engine.Preflight(cfg.AgentName); perr != nil {
			err = fmt.Errorf("swarm preflight failed: %w", perr)
		}
	}

	// Execute phases (skipped on preflight failure)
	if err == nil {
		err = s.runSwarmPipeline(ctx, cfg, agenticScan, result)
	}

	// Finalize
	result.Duration = time.Since(start)
	now := time.Now()
	agenticScan.CompletedAt = now
	agenticScan.DurationMs = result.Duration.Milliseconds()
	agenticScan.FindingCount = result.TotalFindings

	// Pull cumulative token usage from the engine accumulator. Every
	// Engine.Run call during the pipeline (plan, source-analysis sub-agents,
	// triage, code-audit, repair) contributes here.
	if s.engine != nil {
		result.TokenUsage = s.engine.TokenUsage()
	}
	usage := claudecost.Usage{
		InputTokens:  int64(result.TokenUsage.InputTokens),
		OutputTokens: int64(result.TokenUsage.OutputTokens),
	}
	agenticScan.TotalInputTokens = usage.InputTokens
	agenticScan.TotalOutputTokens = usage.OutputTokens
	agenticScan.EstimatedCostUSD = usage.Price(agenticScan.Model)
	// Mirror the totals into the JSONB column so the existing per-phase
	// renderer in `vigolium agent session` surfaces them. Real per-phase
	// breakdown would require snapshotting the engine accumulator before
	// and after each pipeline phase — out of scope here; one rollup entry
	// is enough to keep operators from seeing an empty Token Usage block.
	if usage.InputTokens > 0 || usage.OutputTokens > 0 {
		agenticScan.TokenUsage = map[string]interface{}{
			"swarm": map[string]interface{}{
				"input_tokens":  usage.InputTokens,
				"output_tokens": usage.OutputTokens,
			},
		}
	}

	if err != nil {
		agenticScan.Status = "failed"
		agenticScan.ErrorMessage = err.Error()
	} else if result.Degraded {
		agenticScan.Status = "completed_with_warnings"
		agenticScan.ErrorMessage = strings.Join(result.Warnings, "\n")
	} else {
		agenticScan.Status = "completed"
	}

	if s.repo != nil {
		if updateErr := s.repo.UpdateAgenticScan(ctx, agenticScan); updateErr != nil {
			zap.L().Warn("Failed to update agent run record", zap.Error(updateErr))
		}
	}

	if err != nil {
		return result, err
	}
	return result, nil
}

func (s *SwarmRunner) emitPhase(cfg SwarmConfig, phase string) {
	if cfg.PhaseCallback != nil {
		cfg.PhaseCallback(phase)
	}
	printPhaseLine(phase, fmt.Sprintf("phase started: %s", phase))
}

func (s *SwarmRunner) addWarning(result *SwarmResult, format string, args ...interface{}) {
	if result == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	result.Degraded = true
	result.Warnings = append(result.Warnings, msg)
}

func (s *SwarmRunner) currentMaxFindingID(ctx context.Context, projectUUID string) int64 {
	if s.repo == nil || projectUUID == "" {
		return 0
	}
	var maxID int64
	if err := s.repo.DB().NewSelect().
		Model((*database.Finding)(nil)).
		ColumnExpr("COALESCE(MAX(id), 0)").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &maxID); err != nil {
		zap.L().Debug("Failed to query max finding id", zap.Error(err))
		return 0
	}
	return maxID
}

func (s *SwarmRunner) writeSwarmCheckpoint(sessionDir string, projectUUID string, completedPhases []string, targetURL string, recordCount int, plan *SwarmPlan, extensionDir string, triageRound int, extensionRenames map[string]string, result *SwarmResult, stats swarmRecordStats) error {
	cp := &SwarmCheckpoint{
		CompletedPhases:  append([]string(nil), completedPhases...),
		TargetURL:        targetURL,
		RecordCount:      recordCount,
		Plan:             plan,
		ExtensionDir:     extensionDir,
		Timestamp:        time.Now(),
		TriageRound:      triageRound,
		ExtensionRenames: extensionRenames,
		InitialRecords:   stats.Initial,
		SourceRecords:    stats.Source,
		DiscoveryRecords: stats.Discovery,
	}
	if result != nil {
		cp.LastFindingID = s.currentMaxFindingID(context.Background(), projectUUID)
		cp.Warnings = append(cp.Warnings, result.Warnings...)
	}
	return writeCheckpoint(sessionDir, cp)
}

// phaseCompleted returns true if the given phase is in the checkpoint's completed list.
// It normalizes legacy phase names for backward compatibility with old checkpoints.
func phaseCompleted(cp *SwarmCheckpoint, phase string) bool {
	if cp == nil {
		return false
	}
	normalized := NormalizeSwarmPhase(phase)
	for _, p := range cp.CompletedPhases {
		if NormalizeSwarmPhase(p) == normalized {
			return true
		}
	}
	return false
}
