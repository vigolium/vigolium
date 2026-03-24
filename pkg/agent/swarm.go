package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/session"
	"github.com/vigolium/vigolium/pkg/terminal"

	"go.uber.org/zap"
)

// SwarmConfig configures an agent swarm run.
type SwarmConfig struct {
	// Inputs: raw input strings (URL, curl, raw HTTP, Burp XML, or record UUID)
	Inputs    []string  // raw input strings
	InputType InputType // explicit type (auto-detected if empty)

	// Source analysis
	SourcePath string   // path to application source code (triggers source analysis phase)
	Files      []string // specific files to include (relative to SourcePath)

	// Custom instruction
	Instruction string // user-provided custom instruction appended to agent prompts

	// Scanning parameters
	VulnType         string   // optional: focus on specific vulnerability type
	Focus            string   // optional: broad strategic hint (e.g. "API injection", "auth bypass")
	ModuleNames      []string // optional: explicit module IDs to use
	OnlyPhase        string   // isolate a single phase (empty = all phases)
	SkipPhases       []string // skip specific phases (empty = skip none)
	MaxIterations    int      // max triage-rescan loops (default 3)
	BatchConcurrency int      // max parallel master agent batches (0 = min(batch_count, NumCPU))
	MaxMasterRetries int      // max master agent retries on parse failure (0 = default 3)
	SAMaxConcurrency int      // max parallel source analysis sub-agents (0 = default 3)

	// Agent
	AgentName   string
	AgentACPCmd string // ad-hoc ACP command override (e.g. "traecli acp")

	// Terminal capability: custom slash commands and sub-agents
	SlashCommands []string // custom slash commands available inside the ACP session (e.g. /security-review)
	CustomAgents  []string // agent backend names the agent can invoke via "vigolium agent query --agent=X"
	MaxCommands   int      // max terminal commands per session (0 = default 50)

	DryRun             bool
	ShowPrompt         bool   // print rendered prompts to stderr before executing
	SourceAnalysisOnly bool   // run only source analysis phase and exit
	CodeAudit          bool   // enable AI security code audit phase (--code-audit)

	// Context truncation
	MaxResponseBodyBytes int // max response body size in context; 0 = default 4096
	MaxPlanRecords       int // max records sent to plan agent; 0 = default 10

	// Tuning: batching, probing, retries
	MasterBatchSize  int           // max records per master agent batch; 0 = default 5
	ProbeConcurrency int           // max parallel probe requests; 0 = default 10
	ProbeTimeout     time.Duration // per-request probe timeout; 0 = default 10s
	MaxProbeBodySize int           // max response body bytes during probing; 0 = default 2MB

	// Project/scan

	ProjectUUID string
	ScanUUID    string

	// Session directory base path for agent artifacts
	SessionsDir string

	// SessionDir is the pre-created session directory for this run.
	// When set, the swarm runner uses it directly instead of creating one.
	SessionDir string

	// RunUUID overrides the auto-generated agent run UUID.
	// When set (e.g. by CLI), the swarm runner uses this UUID for the DB record,
	// ensuring it matches the pre-created session directory name.
	RunUUID string

	// ResumeDir is the session directory of a previous run to resume from.
	// When set, the swarm runner loads the checkpoint and skips completed phases.
	ResumeDir string

	// Streaming
	StreamWriter     io.Writer
	ProgressCallback func(ProgressEvent)

	// ScanFunc runs the scan with the given module filters and extensions.
	ScanFunc ScanFunc

	// DiscoverFunc runs native discovery+spidering before master agent planning.
	// When set, the swarm runner executes discovery and feeds discovered records
	// into the master agent alongside the original inputs.
	DiscoverFunc func(ctx context.Context) error

	// SASTFunc runs the native SAST phase (ast-grep route extraction + secret detection).
	// When set and --source is provided, the swarm runner executes SAST and then
	// spawns a sub-agent to review the findings and validate extracted routes.
	SASTFunc func(ctx context.Context) error

	// SourceAnalysisCallback is called after source analysis completes to allow
	// the caller to process session config (e.g., convert to auth-config.yaml)
	// and extensions before the scan phase.
	SourceAnalysisCallback func(result *SourceAnalysisResult) error

	// PhaseCallback is called when a swarm phase starts.
	PhaseCallback func(phase string)
}

// SwarmPhase constants for the agent swarm mode.
// Phases prefixed with "native-" are executed by native Go code without AI agent involvement.
const (
	SwarmPhaseNormalize      = "native-normalize"
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

// swarmPhaseAliases maps legacy phase names to their current constant values.
// This provides backward compatibility for checkpoints, --start-from, and --skip flags.
var swarmPhaseAliases = map[string]string{
	"normalize": SwarmPhaseNormalize,
	"sast":      SwarmPhaseSAST,
	"discover":  SwarmPhaseDiscover,
	"extension": SwarmPhaseExtension,
	"scan":      SwarmPhaseScan,
	"rescan":    SwarmPhaseRescan,
}

// NormalizeSwarmPhase resolves a phase name, accepting both current and legacy names.
func NormalizeSwarmPhase(phase string) string {
	if mapped, ok := swarmPhaseAliases[phase]; ok {
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

// Prompt template constants for the agent swarm mode.
const (
	SwarmPromptPlan       = "agent-swarm-plan"
	SwarmPromptExtensions = "agent-swarm-extensions"
	SwarmPromptCodeAudit  = "swarm-code-audit"
	SwarmPromptSASTReview = "swarm-sast-review"
	SwarmPromptTriage     = "agent-swarm-triage"
)

// SwarmPhaseDescription returns a short description of what a swarm phase does.
func SwarmPhaseDescription(phase string) string {
	switch phase {
	case SwarmPhaseNormalize:
		return "parse and normalize input targets into scannable HTTP records"
	case SwarmPhaseSourceAnalysis:
		return "analyze source code for routes, auth flows, and security-relevant patterns"
	case SwarmPhaseCodeAudit:
		return "AI security code audit — identify business logic flaws, data flow issues, and framework misconfigurations"
	case SwarmPhaseSAST:
		return "run static analysis tools for route extraction and secret detection"
	case SwarmPhaseSASTReview:
		return "AI review of SAST findings to filter noise and enrich context"
	case SwarmPhaseDiscover:
		return "crawl and spider targets to discover additional endpoints"
	case SwarmPhasePlan:
		return "AI-generated attack plan selecting modules, focus areas, and custom extensions"
	case SwarmPhaseExtension:
		return "generate and load custom JS scanner extensions from the attack plan"
	case SwarmPhaseScan:
		return "execute native Go scanner modules against all collected HTTP records"
	case SwarmPhaseTriage:
		return "AI triage of scan findings to validate, deduplicate, and assign severity"
	case SwarmPhaseRescan:
		return "re-scan with adjusted parameters based on triage feedback"
	default:
		return ""
	}
}

// SwarmPhasePrompt returns the prompt template name for a given swarm phase, if any.
func SwarmPhasePrompt(phase string) string {
	switch phase {
	case SwarmPhaseCodeAudit:
		return SwarmPromptCodeAudit
	case SwarmPhaseSASTReview:
		return SwarmPromptSASTReview
	case SwarmPhasePlan:
		return SwarmPromptPlan
	case SwarmPhaseTriage:
		return SwarmPromptTriage
	default:
		return ""
	}
}

// SwarmRunner orchestrates AI-guided targeted vulnerability scanning.
type SwarmRunner struct {
	engine *Engine
	repo   *database.Repository
}

// NewSwarmRunner creates a swarm runner.
func NewSwarmRunner(engine *Engine, repo *database.Repository) *SwarmRunner {
	return &SwarmRunner{
		engine: engine,
		repo:   repo,
	}
}

// persistPhase updates the agent run's current phase in the database.
func (s *SwarmRunner) persistPhase(ctx context.Context, agentRun *database.AgentRun) {
	if s.repo != nil {
		if err := s.repo.UpdateAgentRun(ctx, agentRun); err != nil {
			zap.L().Debug("Failed to persist phase update", zap.Error(err))
		}
	}
}

// probeConfig returns a ProbeConfig from the swarm's tuning parameters.
func (cfg *SwarmConfig) probeConfig() ProbeConfig {
	return cfg.probeConfig()
}

// Run executes the full agent swarm pipeline.
func (s *SwarmRunner) Run(ctx context.Context, cfg SwarmConfig) (*SwarmResult, error) {
	start := time.Now()

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
	// Create agent run record — use pre-assigned UUID if provided (e.g. from CLI session dir)
	runUUID := cfg.RunUUID
	if runUUID == "" {
		runUUID = "agt-" + uuid.New().String()
	}
	agentRun := &database.AgentRun{
		UUID:        runUUID,
		ProjectUUID: cfg.ProjectUUID,
		ScanUUID:    cfg.ScanUUID,
		Mode:        "swarm",
		AgentName:   cfg.AgentName,
		VulnType:    cfg.VulnType,
		ModuleNames: cfg.ModuleNames,
		Status:      "running",
		StartedAt:   start,
	}
	if len(cfg.Inputs) > 0 {
		agentRun.InputRaw = cfg.Inputs[0]
	}

	if s.repo != nil {
		if err := s.repo.CreateAgentRun(ctx, agentRun); err != nil {
			zap.L().Warn("Failed to create agent run record", zap.Error(err))
		}
	}

	result := &SwarmResult{AgentRunUUID: runUUID}

	// Execute phases
	err := s.runSwarmPipeline(ctx, cfg, agentRun, result)

	// Finalize
	result.Duration = time.Since(start)
	now := time.Now()
	agentRun.CompletedAt = now
	agentRun.DurationMs = result.Duration.Milliseconds()
	agentRun.FindingCount = result.TotalFindings

	if err != nil {
		agentRun.Status = "failed"
		agentRun.ErrorMessage = err.Error()
	} else {
		agentRun.Status = "completed"
	}

	if s.repo != nil {
		if updateErr := s.repo.UpdateAgentRun(ctx, agentRun); updateErr != nil {
			zap.L().Warn("Failed to update agent run record", zap.Error(updateErr))
		}
	}

	if err != nil {
		return result, err
	}
	return result, nil
}

func (s *SwarmRunner) runSwarmPipeline(ctx context.Context, cfg SwarmConfig, agentRun *database.AgentRun, result *SwarmResult) error {
	phaseTimings := make(map[string]time.Duration)

	// Use pre-created session directory or create one
	sessionDir := cfg.SessionDir
	if cfg.ResumeDir != "" {
		sessionDir = cfg.ResumeDir
	}
	if sessionDir == "" {
		var sdErr error
		sessionDir, sdErr = EnsureSessionDir(cfg.SessionsDir, agentRun.UUID)
		if sdErr != nil {
			zap.L().Warn("Failed to create session dir, falling back to temp dirs", zap.Error(sdErr))
		}
	}
	result.SessionDir = sessionDir
	cfg.SessionDir = sessionDir // ensure downstream functions can access the resolved session dir

	// Checkpoint/resume support
	var checkpoint *SwarmCheckpoint
	if cfg.ResumeDir != "" {
		cp, cpErr := loadCheckpoint(cfg.ResumeDir)
		if cpErr != nil {
			zap.L().Warn("Failed to load checkpoint, starting fresh", zap.Error(cpErr))
		} else {
			checkpoint = cp
			zap.L().Info("Resuming from checkpoint",
				zap.String("last_phase", cp.LastPhase()),
				zap.Strings("completed", cp.CompletedPhases))
		}
	}

	// completedPhases accumulates phases as they complete, used for checkpoint writes.
	var completedPhases []string

	// Phase 1: Normalize inputs
	phaseStart := time.Now()
	agentRun.CurrentPhase = SwarmPhaseNormalize
	s.persistPhase(ctx, agentRun)

	records, targetURL, err := s.normalizeInputs(ctx, cfg)
	if err != nil {
		return fmt.Errorf("input normalization failed: %w", err)
	}

	if targetURL != "" {
		agentRun.TargetURL = targetURL
	}
	agentRun.InputType = string(cfg.InputType)
	if agentRun.InputType == "" && len(cfg.Inputs) > 0 {
		agentRun.InputType = string(DetectInputType(cfg.Inputs[0]))
	}

	// Probe records that don't have responses to enrich them with live data
	probeRecordsWithConfig(ctx, records, cfg.probeConfig())

	// Save records to DB
	var recordUUIDs []string
	if s.repo != nil {
		for _, rr := range records {
			savedUUID, saveErr := s.repo.SaveRecord(ctx, rr, "agent-swarm", cfg.ProjectUUID)
			if saveErr != nil {
				zap.L().Debug("Failed to save input record", zap.Error(saveErr))
				continue
			}
			recordUUIDs = append(recordUUIDs, savedUUID)
		}
		agentRun.RecordCount = len(recordUUIDs)
		result.TotalRecords = len(recordUUIDs)
	}

	// Save normalized inputs to session dir
	writeInputsToSessionDir(sessionDir, records, cfg.SourcePath)
	phaseTimings[SwarmPhaseNormalize] = time.Since(phaseStart)
	completedPhases = append(completedPhases, SwarmPhaseNormalize)
	zap.L().Info("Agent swarm phase completed", zap.String("phase", SwarmPhaseNormalize), zap.Int("records", len(records)))

	fmt.Fprintf(os.Stderr, "%s Phase [%s] %s input records\n",
		terminal.InfoSymbol(),
		terminal.BoldOrange(SwarmPhaseNormalize),
		terminal.Orange(fmt.Sprintf("%d", len(records))))

	// Phase 1.5: Agentic source analysis (LLM explores codebase first).
	// Phase 1.6: Native SAST (ast-grep route extraction + secret detection).
	//
	// These run sequentially — source analysis first, then SAST — so that:
	// 1. LLM-discovered routes with rich parameters, headers, and auth are ingested first
	// 2. Session config (auth tokens) from source analysis is available for SAST probing
	// 3. ast-grep routes that overlap with LLM routes get deduplicated in favor of richer records
	var sourceExtensions []GeneratedExtension
	if cfg.SourcePath != "" && !phaseCompleted(checkpoint, SwarmPhaseSourceAnalysis) {
		phaseStart = time.Now()
		agentRun.CurrentPhase = SwarmPhaseSourceAnalysis
		s.persistPhase(ctx, agentRun)

		var saRecords []*httpmsg.HttpRequestResponse
		var saNotesSlice []string
		var saExtensions []GeneratedExtension
		var sastRecords []*httpmsg.HttpRequestResponse
		var sastNotesSlice []string
		var sastExtensions []GeneratedExtension
		var discoveredSessionConfig *AgentSessionConfig

		// --- Phase 1.5: Agentic source analysis ---
		s.emitPhase(cfg, SwarmPhaseSourceAnalysis)

		saCfg := SourceAnalysisConfig{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			TargetURL:      targetURL,
			SourcePath:     cfg.SourcePath,
			Files:          cfg.Files,
			Instruction:    cfg.Instruction,
			SessionKey: SwarmPhaseSourceAnalysis,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			StreamWriter:   cfg.StreamWriter,
			SessionDir:     sessionDir,
			MaxConcurrency: cfg.SAMaxConcurrency,
		}

		// Run source analysis with retry on transient errors
		type saResultBundle struct {
			result         *SourceAnalysisResult
			rawOutput      string
			renderedPrompt string
		}
		saBundle, saErr := retryAgentCall(ctx, RetryConfig{MaxRetries: 1}, func(ctx context.Context, _ int) (saResultBundle, error) {
			r, raw, prompt, err := s.engine.RunSourceAnalysisParallel(ctx, saCfg)
			return saResultBundle{r, raw, prompt}, err
		})
		saResult := saBundle.result
		saRawOutput := saBundle.rawOutput
		saRenderedPrompt := saBundle.renderedPrompt

		writePromptToSessionDir(sessionDir, "source-analysis-prompt.md", saRenderedPrompt)
		if sessionDir != "" && saRawOutput != "" {
			outputPath := filepath.Join(sessionDir, "source-analysis-output.md")
			_ = os.WriteFile(outputPath, []byte(saRawOutput), 0644)
			printPhaseLine("source-analysis", fmt.Sprintf("%s output: %s",
				terminal.SymbolStart, terminal.ShortenHome(outputPath)))
		}

		if saErr != nil {
			zap.L().Warn("Source analysis failed, continuing with input records only", zap.Error(saErr))
		} else if saResult != nil {
			printPhaseLine("source-analysis", fmt.Sprintf("result: %d http_records, %d extensions  has_session_config=%v",
				len(saResult.HTTPRecords), len(saResult.Extensions), saResult.SessionConfig != nil))

			filteredRecords, filteredNotes := filterSourceRecordsByHostname(saResult.HTTPRecords, targetURL)
			if len(filteredRecords) > 0 {
				printPhaseLine("source-analysis", fmt.Sprintf("appending source-discovered routes  total=%d hostname_matched=%d",
					len(saResult.HTTPRecords), len(filteredRecords)))
				saRecords = filteredRecords
				saNotesSlice = filteredNotes
			}
			if len(saResult.Extensions) > 0 {
				saExtensions = append(saExtensions, saResult.Extensions...)
			}
			if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
				vr := ValidateSessionConfigDetailed(saResult.SessionConfig)

				if len(vr.Invalid) > 0 {
					printPhaseLine("source-analysis", fmt.Sprintf("session config: %d valid, %d invalid — attempting LLM repair",
						len(vr.Valid), len(vr.Invalid)))
					// Build a config from invalid entries for repair
					invalidCfg := &AgentSessionConfig{}
					for _, inv := range vr.Invalid {
						invalidCfg.Sessions = append(invalidCfg.Sessions, inv.Entry)
					}
					repaired := RepairInvalidSessionConfig(ctx, s.engine, invalidCfg, targetURL, repairConfig{
						AgentName:    cfg.AgentName,
						AgentACPCmd:  cfg.AgentACPCmd,
						ShowPrompt:   cfg.ShowPrompt,
						ExploreNotes: saResult.SessionExploreNotes,
					})
					if repaired != nil {
						printPhaseLine("source-analysis", fmt.Sprintf("LLM repaired %d session entries", len(repaired.Sessions)))
						vr.Valid = append(vr.Valid, repaired.Sessions...)
					} else if len(vr.Valid) == 0 {
						printPhaseLine("source-analysis", "LLM session config repair failed, continuing without auth")
					}
				}

				if len(vr.Valid) > 0 {
					saResult.SessionConfig = &AgentSessionConfig{Sessions: vr.Valid}
				} else {
					saResult.SessionConfig = nil
				}
			}
			if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
				writeSessionConfigToDir(saResult.SessionConfig, sessionDir)
				discoveredSessionConfig = saResult.SessionConfig

				// Convert login flow URLs into HTTP records so they are ingested
				// into the http_records table alongside source-discovered routes.
				loginRecords := SessionConfigToHTTPRecords(saResult.SessionConfig)
				if len(loginRecords) > 0 {
					loginFiltered, loginNotes := filterSourceRecordsByHostname(loginRecords, targetURL)
					if len(loginFiltered) > 0 {
						printPhaseLine("source-analysis", fmt.Sprintf("appending login endpoint records  count=%d", len(loginFiltered)))
						saRecords = append(saRecords, loginFiltered...)
						saNotesSlice = append(saNotesSlice, loginNotes...)
					}
				}
			}
			if cfg.SourceAnalysisCallback != nil {
				if cbErr := cfg.SourceAnalysisCallback(saResult); cbErr != nil {
					zap.L().Warn("Source analysis callback failed", zap.Error(cbErr))
				}
			}
		}

		// Hydrate session config immediately after source analysis so that
		// both the source-discovered records AND the subsequent SAST phase
		// can use real auth tokens for probing.
		var authHeaders map[string]string
		if discoveredSessionConfig != nil {
			authHeaders = hydrateSessionConfig(discoveredSessionConfig)
			if len(authHeaders) > 0 {
				printPhaseLine("source-analysis", fmt.Sprintf("hydrated auth headers  count=%d", len(authHeaders)))
			}

			// Persist hydrated session config to SessionHostname table so the
			// normal route ingest phase and future scans can reuse these sessions.
			if s.repo != nil && targetURL != "" {
				hostname := hostnameFromURL(targetURL)
				if hostname != "" {
					rows := AgentSessionConfigToSessionHostnames(
						discoveredSessionConfig, cfg.ProjectUUID, cfg.ScanUUID, hostname, "agent-swarm-source",
					)
					if len(authHeaders) > 0 {
						now := time.Now()
						for _, r := range rows {
							r.HydratedAt = &now
						}
					}
					if len(rows) > 0 {
						if shErr := s.repo.SaveSessionHostnames(ctx, rows); shErr != nil {
							zap.L().Warn("Failed to persist session config to database", zap.Error(shErr))
						} else {
							printPhaseLine("source-analysis", fmt.Sprintf("persisted session config  hostname=%s sessions=%d", hostname, len(rows)))
						}
					}
				}
			}
		}

		// Fallback: load auth headers from session_hostnames DB table
		// when source analysis didn't discover any session config.
		if len(authHeaders) == 0 && s.repo != nil && targetURL != "" {
			hostname := hostnameFromURL(targetURL)
			if hostname != "" {
				dbRows, dbErr := s.repo.GetSessionHostnamesByHostname(ctx, cfg.ProjectUUID, hostname)
				if dbErr == nil && len(dbRows) > 0 {
					authHeaders = AuthHeadersFromSessionHostnames(dbRows)
					if len(authHeaders) > 0 {
						printPhaseLine("source-analysis", fmt.Sprintf("loaded auth headers from DB  hostname=%s count=%d", hostname, len(authHeaders)))
					}
				}
			}
		}

		// Print session/auth stats
		if discoveredSessionConfig != nil && len(discoveredSessionConfig.Sessions) > 0 {
			sessionCount := len(discoveredSessionConfig.Sessions)
			authCount := len(authHeaders)
			if authCount > 0 {
				printPhaseLine("source-analysis", fmt.Sprintf("%s sessions: %d discovered, %d auth tokens obtained",
					terminal.SymbolBullet, sessionCount, authCount))
			} else {
				printPhaseLine("source-analysis", fmt.Sprintf("%s sessions: %d discovered, no auth tokens obtained",
					terminal.SymbolBullet, sessionCount))
			}
		}

		// Replace hardcoded auth headers in source-discovered records with session headers.
		if len(authHeaders) > 0 && len(saRecords) > 0 {
			ReplaceAuthHeadersInHTTPRR(saRecords, authHeaders)
		}

		// Validate, auth-inject, probe, and save source-analysis records to DB
		// before running SAST so they are available for deduplication.
		s.validateProbeAndSave(ctx, saRecords, saNotesSlice, authHeaders, "agent-swarm-source", cfg.ProjectUUID, cfg.probeConfig())

		if len(saRecords) > 0 {
			printPhaseLine("source-analysis", fmt.Sprintf("%s source analysis routes: %d %s",
				terminal.SymbolBullet, len(saRecords), formatRouteStatusSummary(saRecords)))
		}

		// --- Phase 1.55: AI Code Audit (conditional, only if --code-audit) ---
		// Runs after source analysis so it can use the discovered routes and auth flows
		// as context, avoiding redundant codebase reads. Produces findings directly.
		if cfg.CodeAudit && !phaseCompleted(checkpoint, SwarmPhaseCodeAudit) {
			s.emitPhase(cfg, SwarmPhaseCodeAudit)

			// When source analysis ran successfully, reuse the explore session
			// so the code audit agent has full codebase context without re-reading.
			reuseExploreSession := saRawOutput != ""
			codeAuditFindings, caErr := s.runCodeAudit(ctx, cfg, targetURL, sessionDir, saRawOutput, reuseExploreSession)
			if caErr != nil {
				zap.L().Warn("Code audit failed, continuing", zap.Error(caErr))
			} else if codeAuditFindings > 0 {
				printPhaseLine("code-audit", fmt.Sprintf("%s %d findings saved to database",
					terminal.SymbolBullet, codeAuditFindings))
			} else {
				printPhaseLine("code-audit", "no findings")
			}
			completedPhases = append(completedPhases, SwarmPhaseCodeAudit)
		}

		// --- Phase 1.6: Native SAST (runs after source analysis) ---
		// The SourceAnalysisCallback has already written the auth config file,
		// so SASTFunc picks it up via the shared pointer. ast-grep probes now
		// run with real auth tokens and LLM-discovered routes are already in DB
		// for deduplication.
		if cfg.SASTFunc != nil {
			s.emitPhase(cfg, SwarmPhaseSAST)

			if sastErr := cfg.SASTFunc(ctx); sastErr != nil {
				zap.L().Warn("SAST phase failed, continuing without SAST results", zap.Error(sastErr))
			} else {
				s.emitPhase(cfg, SwarmPhaseSASTReview)
				sastReviewResult := s.runSASTReview(ctx, cfg, targetURL, sessionDir)
				if sastReviewResult != nil {
					if len(sastReviewResult.HTTPRecords) > 0 {
						validatedRecords, validatedNotes := filterSourceRecordsByHostname(sastReviewResult.HTTPRecords, targetURL)
						if len(validatedRecords) > 0 {
							printPhaseLine("source-analysis", fmt.Sprintf("appending SAST-review validated routes  count=%d", len(validatedRecords)))
							sastRecords = validatedRecords
							sastNotesSlice = validatedNotes
						}
					}
					if len(sastReviewResult.Extensions) > 0 {
						sastExtensions = append(sastExtensions, sastReviewResult.Extensions...)
					}
				}
			}
		}

		// Merge results
		records = append(records, saRecords...)
		records = append(records, sastRecords...)
		result.TotalRecords = len(records)
		sourceExtensions = append(sourceExtensions, saExtensions...)
		sourceExtensions = append(sourceExtensions, sastExtensions...)

		// Validate, auth-inject, probe, and save SAST-review records to DB
		s.validateProbeAndSave(ctx, sastRecords, sastNotesSlice, authHeaders, "agent-swarm-source", cfg.ProjectUUID, cfg.probeConfig())

		// Re-probe unprobed ast-grep records. The native SAST runner probes via
		// httpRequester.Execute which goes through clustering/rate-limiting middleware
		// and may silently fail. Use a simple HTTP client as fallback.
		if s.repo != nil && targetURL != "" {
			hostname := hostnameFromURL(targetURL)
			if hostname != "" {
				s.reprobeUnprobedRecords(ctx, cfg.ProjectUUID, hostname, authHeaders, "agent-swarm-source")
				s.reprobeUnprobedRecords(ctx, cfg.ProjectUUID, hostname, authHeaders, "ast-grep")
			}
		}

		// Print combined stats
		if len(saRecords) > 0 || len(sastRecords) > 0 {
			allRoutes := append(saRecords, sastRecords...)
			printPhaseLine("source-analysis", fmt.Sprintf("%s routes discovered: %d (source-analysis: %d, sast: %d) %s",
				terminal.SymbolBullet, len(allRoutes), len(saRecords), len(sastRecords),
				formatRouteStatusSummary(allRoutes)))
		}

		// Write source-discovered extensions to session dir immediately as artifacts.
		// These will be merged with plan-phase extensions later, but writing them now
		// ensures they are preserved even if subsequent phases fail.
		if sessionDir != "" && len(sourceExtensions) > 0 {
			writeSourceExtensionsToSessionDir(sourceExtensions, sessionDir)
		}

		phaseTimings[SwarmPhaseSourceAnalysis] = time.Since(phaseStart)
		completedPhases = append(completedPhases, SwarmPhaseSourceAnalysis)

		printPhaseLine("source-analysis", fmt.Sprintf("%s completed — %d routes, %d extensions in %s",
			terminal.SymbolSuccess, len(saRecords)+len(sastRecords), len(sourceExtensions),
			phaseTimings[SwarmPhaseSourceAnalysis].Round(time.Second)))

		// Write checkpoint after source analysis
		if cpErr := writeCheckpoint(sessionDir, &SwarmCheckpoint{
			CompletedPhases: completedPhases,
			TargetURL:       targetURL,
			RecordCount:     len(records),
			Timestamp:       time.Now(),
		}); cpErr != nil {
			zap.L().Warn("Failed to write checkpoint after source analysis", zap.Error(cpErr))
		}
	}

	// Early exit for --source-analysis-only
	if cfg.SourceAnalysisOnly {
		result.TotalRecords = len(records)
		result.PhaseTimings = phaseTimings
		return nil
	}

	// Phase 1.7: Optional discovery (when DiscoverFunc is provided)
	if cfg.DiscoverFunc != nil && !phaseCompleted(checkpoint, SwarmPhaseDiscover) {
		phaseStart = time.Now()
		s.emitPhase(cfg, SwarmPhaseDiscover)
		agentRun.CurrentPhase = SwarmPhaseDiscover
		s.persistPhase(ctx, agentRun)

		if discoverErr := cfg.DiscoverFunc(ctx); discoverErr != nil {
			zap.L().Warn("Discovery phase failed, continuing with input records", zap.Error(discoverErr))
		} else if s.repo != nil {
			// Query discovered records from DB and merge with existing records
			discoveredRecords := s.queryDiscoveredRecords(ctx, cfg, targetURL)
			if len(discoveredRecords) > 0 {
				zap.L().Info("Merging discovered records from discovery phase",
					zap.Int("discovered", len(discoveredRecords)),
					zap.Int("existing", len(records)))
				records = deduplicateRecords(append(records, discoveredRecords...))
				result.TotalRecords = len(records)
			}
		}
		phaseTimings[SwarmPhaseDiscover] = time.Since(phaseStart)
		completedPhases = append(completedPhases, SwarmPhaseDiscover)

		fmt.Fprintf(os.Stderr, "  %s Total records after discovery: %s\n",
			terminal.Cyan(terminal.SymbolBullet),
			terminal.Orange(fmt.Sprintf("%d", len(records))))
	}

	// Filter records for plan phase: select the most interesting ones to keep context focused
	planRecords := selectPlanRecords(records, cfg.MaxPlanRecords)
	if len(planRecords) < len(records) {
		zap.L().Info("Filtered records for plan phase",
			zap.Int("total", len(records)),
			zap.Int("selected", len(planRecords)))
		fmt.Fprintf(os.Stderr, "  %s Selected %s of %s records for planning (most interesting)\n",
			terminal.Cyan(terminal.SymbolBullet),
			terminal.Orange(fmt.Sprintf("%d", len(planRecords))),
			terminal.Orange(fmt.Sprintf("%d", len(records))))
	}

	// Phase 2: Master agent — analyze and plan (batched if > 5 records)
	phaseStart = time.Now()
	var plan *SwarmPlan
	var sessionID string
	var masterRawOutput string
	var masterRenderedPrompt string
	var sessionIDs []string
	var batchProv *BatchProvenance

	// Resume: restore plan from checkpoint if available
	if checkpoint != nil && phaseCompleted(checkpoint, SwarmPhasePlan) && checkpoint.Plan != nil {
		plan = checkpoint.Plan
		zap.L().Info("Restored plan from checkpoint",
			zap.Int("module_tags", len(plan.ModuleTags)))
	} else {
		s.emitPhase(cfg, SwarmPhasePlan)
		agentRun.CurrentPhase = SwarmPhasePlan
		s.persistPhase(ctx, agentRun)

		if len(planRecords) <= cfg.MasterBatchSize {
			plan, sessionID, masterRawOutput, masterRenderedPrompt, err = s.runMasterAgent(ctx, cfg, planRecords, targetURL)
		} else {
			zap.L().Info("Batching master agent calls",
				zap.Int("records", len(planRecords)),
				zap.Int("batch_size", cfg.MasterBatchSize),
				zap.Int("batches", (len(planRecords)+cfg.MasterBatchSize-1)/cfg.MasterBatchSize))
			plan, sessionID, masterRawOutput, masterRenderedPrompt, sessionIDs, batchProv, err = s.runMasterAgentBatched(ctx, cfg, planRecords, targetURL, cfg.MasterBatchSize)
		}

		// Save rendered prompt and raw output to session dir regardless of parse success
		writePromptToSessionDir(sessionDir, "master-prompt.md", masterRenderedPrompt)
		if sessionDir != "" && masterRawOutput != "" {
			_ = os.WriteFile(filepath.Join(sessionDir, "master-output.md"), []byte(masterRawOutput), 0644)
		}

		if err != nil {
			return fmt.Errorf("master agent failed: %w", err)
		}
	}
	phaseTimings[SwarmPhasePlan] = time.Since(phaseStart)

	if plan != nil {
		extCount := len(plan.Extensions) + len(plan.QuickChecks) + len(plan.Snippets)
		fmt.Fprintf(os.Stderr, "%s %s  %s\n",
			terminal.Aqua(terminal.SymbolSuccess),
			terminal.Aqua("Plan"),
			terminal.Muted(fmt.Sprintf("completed — %d extensions, %d focus areas in %s",
				extCount, len(plan.FocusAreas),
				phaseTimings[SwarmPhasePlan].Round(time.Second))))
	}

	result.SessionID = sessionID
	result.SessionIDs = sessionIDs

	// Log plan summary (all modules run by default, MODULE_TAGS/IDs are informational only)
	if plan != nil {
		zap.L().Info("Swarm plan summary",
			zap.Int("focus_areas", len(plan.FocusAreas)),
			zap.Int("extensions", len(plan.Extensions)),
			zap.Int("quick_checks", len(plan.QuickChecks)),
			zap.Bool("needs_extensions", plan.NeedsExtensions),
			zap.String("needs_extensions_reason", plan.NeedsExtensionsReason))

		// Print plan stats to console
		fmt.Fprintf(os.Stderr, "  %s Total HTTP records: %s\n",
			terminal.Cyan(terminal.SymbolBullet),
			terminal.Orange(fmt.Sprintf("%d", len(records))))
		if len(plan.ModuleTags) > 0 {
			fmt.Fprintf(os.Stderr, "  %s Module tags: %s\n",
				terminal.Cyan(terminal.SymbolBullet),
				terminal.Cyan(strings.Join(plan.ModuleTags, ", ")))
		}
		if len(plan.FocusAreas) > 0 {
			fmt.Fprintf(os.Stderr, "  %s Focus areas: %s\n",
				terminal.Cyan(terminal.SymbolBullet),
				strings.Join(plan.FocusAreas, ", "))
		}
		if plan.NeedsExtensionsReason != "" {
			decision := "no"
			if plan.NeedsExtensions {
				decision = "yes"
			}
			fmt.Fprintf(os.Stderr, "  %s Needs extensions: %s — %s\n",
				terminal.Cyan(terminal.SymbolBullet),
				terminal.Orange(decision),
				plan.NeedsExtensionsReason)
		}
	}

	if cfg.DryRun {
		result.SwarmPlan = plan
		result.PhaseTimings = phaseTimings
		return nil
	}

	result.SwarmPlan = plan
	result.BatchProvenance = batchProv
	agentRun.SessionID = sessionID
	if plan != nil {
		planJSON, _ := json.Marshal(plan)
		agentRun.AttackPlan = string(planJSON)

		// Write plan to session dir for inspection
		if sessionDir != "" {
			_ = os.WriteFile(filepath.Join(sessionDir, "swarm-plan.json"), planJSON, 0644)
		}

		completedPhases = append(completedPhases, SwarmPhasePlan)

		// Write checkpoint after planning
		if cpErr := writeCheckpoint(sessionDir, &SwarmCheckpoint{
			CompletedPhases: completedPhases,
			TargetURL:       targetURL,
			RecordCount:     len(records),
			Plan:            plan,
			Timestamp:       time.Now(),
		}); cpErr != nil {
			zap.L().Warn("Failed to write checkpoint after plan phase", zap.Error(cpErr))
		}
	}

	// Phase 3: Generate and write extensions (quick_checks + snippets + full extensions)
	// Merge source-analysis extensions with plan extensions by filename (plan wins on collision)
	phaseStart = time.Now()
	var allExtensions []GeneratedExtension
	var extensionRenames map[string]string
	if plan != nil {
		// Lint and convert quick_checks into full JS extensions
		if len(plan.QuickChecks) > 0 {
			var validQCs []QuickCheck
			for _, qc := range plan.QuickChecks {
				issues := LintQuickCheck(qc)
				hasErr := false
				for _, iss := range issues {
					if iss.Severity == "error" {
						hasErr = true
						zap.L().Warn("Dropping invalid quick_check",
							zap.String("id", qc.ID), zap.String("issue", iss.Message))
					}
				}
				if !hasErr {
					validQCs = append(validQCs, qc)
				}
			}
			if len(validQCs) > 0 {
				qcExts := GenerateQuickCheckExtensions(validQCs)
				plan.Extensions = append(plan.Extensions, qcExts...)
				zap.L().Info("Generated quick check extensions", zap.Int("count", len(qcExts)))
			}
			if dropped := len(plan.QuickChecks) - len(validQCs); dropped > 0 {
				zap.L().Warn("Dropped invalid quick checks", zap.Int("dropped", dropped))
			}
		}
		// Lint and convert snippets into full JS extensions
		if len(plan.Snippets) > 0 {
			var validSnips []Snippet
			for _, snip := range plan.Snippets {
				issues := LintSnippet(snip)
				hasErr := false
				for _, iss := range issues {
					if iss.Severity == "error" {
						hasErr = true
						zap.L().Warn("Dropping invalid snippet",
							zap.String("id", snip.ID), zap.String("issue", iss.Message))
					}
				}
				if !hasErr {
					validSnips = append(validSnips, snip)
				}
			}
			if len(validSnips) > 0 {
				snipExts := GenerateSnippetExtensions(validSnips)
				plan.Extensions = append(plan.Extensions, snipExts...)
				zap.L().Info("Generated snippet extensions", zap.Int("count", len(snipExts)))
			}
			if dropped := len(plan.Snippets) - len(validSnips); dropped > 0 {
				zap.L().Warn("Dropped invalid snippets", zap.Int("dropped", dropped))
			}
		}
		mergeResult := mergeExtensionsTracked(sourceExtensions, plan.Extensions)
		allExtensions = mergeResult.Extensions
		extensionRenames = mergeResult.Renames
		if len(extensionRenames) > 0 {
			for orig, renamed := range extensionRenames {
				fmt.Fprintf(os.Stderr, "  %s Extension renamed: %s → %s (collision with different code)\n",
					terminal.Yellow(terminal.SymbolBullet), orig, renamed)
			}
		}
	} else if len(sourceExtensions) > 0 {
		allExtensions = sourceExtensions
	}

	// Validate extension syntax before writing to disk
	preValidationCount := len(allExtensions)
	if preValidationCount > 0 {
		validExts, invalidExts := ValidateExtensionSyntax(allExtensions)
		allExtensions = validExts

		// Attempt LLM repair for invalid extensions.
		// Pass plan context so garbled extensions can be regenerated from intent.
		if len(invalidExts) > 0 {
			rc := repairConfig{
				AgentName:   cfg.AgentName,
				AgentACPCmd: cfg.AgentACPCmd,
				ShowPrompt:  cfg.ShowPrompt,
				TargetURL:   targetURL,
			}
			if plan != nil {
				rc.FocusAreas = plan.FocusAreas
				rc.ModuleTags = plan.ModuleTags
			}
			repaired := RepairExtensionsWithLLM(ctx, s.engine, invalidExts, rc)
			if len(repaired) > 0 {
				zap.L().Info("LLM repaired extensions",
					zap.Int("repaired", len(repaired)),
					zap.Int("still_invalid", len(invalidExts)-len(repaired)))
				allExtensions = append(allExtensions, repaired...)
			}
		}

		if len(allExtensions) == 0 {
			zap.L().Error("All generated extensions failed syntax validation",
				zap.Int("dropped", preValidationCount))
			fmt.Fprintf(os.Stderr, "%s All %d generated extensions failed syntax validation — scanning without custom extensions\n",
				terminal.WarningSymbol(), preValidationCount)
		} else if len(allExtensions) < preValidationCount {
			zap.L().Warn("Some extensions failed syntax validation",
				zap.Int("valid", len(allExtensions)),
				zap.Int("dropped", preValidationCount-len(allExtensions)))
		}
	}

	var extensionDir string
	if len(allExtensions) > 0 {
		s.emitPhase(cfg, SwarmPhaseExtension)
		agentRun.CurrentPhase = SwarmPhaseExtension
		s.persistPhase(ctx, agentRun)

		dir, writeErr := writeExtensionsToDir(allExtensions, sessionDir)
		if writeErr != nil {
			zap.L().Warn("Failed to write generated extensions", zap.Error(writeErr))
		} else {
			extensionDir = dir
		}

		// Print extension stats
		sourceExtCount := len(sourceExtensions)
		planExtCount := len(allExtensions) - sourceExtCount
		if planExtCount < 0 {
			planExtCount = 0
		}
		fmt.Fprintf(os.Stderr, "  %s Extensions: %s generated (source: %s, plan: %s)\n",
			terminal.Cyan(terminal.SymbolBullet),
			terminal.BoldYellow(fmt.Sprintf("%d", len(allExtensions))),
			terminal.Orange(fmt.Sprintf("%d", sourceExtCount)),
			terminal.Orange(fmt.Sprintf("%d", planExtCount)))
		for _, ext := range allExtensions {
			fmt.Fprintf(os.Stderr, "    %s %s %s\n",
				terminal.Gray("-"),
				terminal.BoldCyan(ext.Filename+":"),
				ext.Reason)
		}
	}
	phaseTimings[SwarmPhaseExtension] = time.Since(phaseStart)
	completedPhases = append(completedPhases, SwarmPhaseExtension)

	// Phase 4: Execute scan (full scan with all modules by default)
	if cfg.ScanFunc != nil && !phaseCompleted(checkpoint, SwarmPhaseScan) {
		phaseStart = time.Now()
		s.emitPhase(cfg, SwarmPhaseScan)
		agentRun.CurrentPhase = SwarmPhaseScan
		s.persistPhase(ctx, agentRun)

		scanReq := ScanRequest{ExtensionDir: extensionDir}
		if plan != nil {
			scanReq.ModuleTags = plan.ModuleTags
			scanReq.ModuleIDs = plan.ModuleIDs
		}
		if err := cfg.ScanFunc(ctx, scanReq); err != nil {
			// Log the error but continue — a partial scan failure (e.g. session
			// init on an auto-generated auth config) should not abort the entire
			// swarm. Triage and report phases can still process any findings
			// that were collected before the error.
			zap.L().Warn("Scan phase encountered an error, continuing with remaining phases", zap.Error(err))
			printPhaseLine(string(SwarmPhaseScan), fmt.Sprintf("scan error (non-fatal): %v", err))
		}
		phaseTimings[SwarmPhaseScan] = time.Since(phaseStart)
		completedPhases = append(completedPhases, SwarmPhaseScan)

		// Print scan phase completion with finding count
		scanFindings := 0
		if s.repo != nil {
			counts, countErr := database.CountFindingsBySeverity(ctx, s.repo.DB(), cfg.ProjectUUID)
			if countErr == nil {
				for _, c := range counts {
					scanFindings += int(c)
				}
			}
		}
		scanSummary := fmt.Sprintf("completed — %d findings in %s",
			scanFindings, phaseTimings[SwarmPhaseScan].Round(time.Second))
		if len(allExtensions) > 0 {
			scanSummary += fmt.Sprintf(" (%d custom extensions loaded)", len(allExtensions))
		}
		fmt.Fprintf(os.Stderr, "%s %s  %s\n",
			terminal.Aqua(terminal.SymbolSuccess),
			terminal.Aqua("Native scan"),
			terminal.Muted(scanSummary))

		// Write checkpoint after scan
		if cpErr := writeCheckpoint(sessionDir, &SwarmCheckpoint{
			CompletedPhases:  completedPhases,
			TargetURL:        targetURL,
			RecordCount:      len(records),
			Plan:             plan,
			ExtensionDir:     extensionDir,
			Timestamp:        time.Now(),
			ExtensionRenames: extensionRenames,
		}); cpErr != nil {
			zap.L().Warn("Failed to write checkpoint after scan phase", zap.Error(cpErr))
		}
	}

	// Phase 5-6: Triage loop (skippable via --skip triage)
	triageSkipped := PhaseSkipped(cfg.SkipPhases, SwarmPhaseTriage)
	if triageSkipped {
		zap.L().Info("Skipping triage and rescan phases (--skip triage)")
		fmt.Fprintf(os.Stderr, "%s %s  %s\n",
			terminal.Aqua(terminal.SymbolSuccess),
			terminal.Aqua("Triage"),
			terminal.Muted("skipped"))
	} else {
		phaseStart = time.Now()
		s.emitPhase(cfg, SwarmPhaseTriage)
		agentRun.CurrentPhase = SwarmPhaseTriage
		s.persistPhase(ctx, agentRun)

		completedPhases = append(completedPhases, SwarmPhaseTriage)
		if err := s.runTriageLoop(ctx, cfg, agentRun, result, sessionDir, extensionDir, checkpoint, extensionRenames, completedPhases); err != nil {
			zap.L().Warn("Triage failed, continuing with scan results", zap.Error(err))
		}
		phaseTimings[SwarmPhaseTriage] = time.Since(phaseStart)

		triageSummary := fmt.Sprintf("completed — %d confirmed, %d false positives, %d iterations in %s",
			result.Confirmed, result.FalsePositives, result.Iterations,
			phaseTimings[SwarmPhaseTriage].Round(time.Second))
		fmt.Fprintf(os.Stderr, "%s %s  %s\n",
			terminal.Aqua(terminal.SymbolSuccess),
			terminal.Aqua("Triage"),
			terminal.Muted(triageSummary))
	}

	// Count total findings with severity breakdown
	if s.repo != nil {
		counts, countErr := database.CountFindingsBySeverity(ctx, s.repo.DB(), cfg.ProjectUUID)
		if countErr == nil {
			total := 0
			sevCounts := make(map[string]int, len(counts))
			for sev, c := range counts {
				total += int(c)
				sevCounts[sev] = int(c)
			}
			result.TotalFindings = total
			result.SeverityCounts = sevCounts
		}
	}

	// Set phase timings on result
	result.PhaseTimings = phaseTimings

	// Log session directory for user inspection
	if sessionDir != "" {
		zap.L().Info("Agent session artifacts", zap.String("session_dir", sessionDir))
	}

	return nil
}

func (s *SwarmRunner) emitPhase(cfg SwarmConfig, phase string) {
	if cfg.PhaseCallback != nil {
		cfg.PhaseCallback(phase)
	}
	printPhaseLine(phase, fmt.Sprintf("phase started: %s", phase))
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

func (s *SwarmRunner) normalizeInputs(ctx context.Context, cfg SwarmConfig) ([]*httpmsg.HttpRequestResponse, string, error) {
	var allRecords []*httpmsg.HttpRequestResponse
	var targetURL string

	for _, input := range cfg.Inputs {
		records, err := NormalizeInput(ctx, input, cfg.InputType, s.repo)
		if err != nil {
			return nil, "", fmt.Errorf("failed to normalize input: %w", err)
		}
		allRecords = append(allRecords, records...)
	}

	// Extract target URL from first record
	if len(allRecords) > 0 && allRecords[0].Request() != nil {
		if u, err := allRecords[0].URL(); err == nil {
			targetURL = u.String()
		}
	}

	return allRecords, targetURL, nil
}

// buildTerminalPromptContext generates prompt text describing available custom
// agents and slash commands. Returns empty string when nothing is configured.
func buildTerminalPromptContext(customAgents, slashCommands []string) string {
	if len(customAgents) == 0 && len(slashCommands) == 0 {
		return ""
	}
	var b strings.Builder
	if len(customAgents) > 0 {
		b.WriteString("\n\n## Available Custom Agents\n\nYou can invoke the following custom agents via terminal:\n")
		for _, a := range customAgents {
			fmt.Fprintf(&b, "- `vigolium agent query --agent=%s --prompt \"<your analysis request>\"`\n", a)
		}
	}
	if len(slashCommands) > 0 {
		b.WriteString("\n\n## Available Slash Commands\n\nThe following custom slash commands are available in this session:\n")
		for _, cmd := range slashCommands {
			fmt.Fprintf(&b, "- `%s`\n", cmd)
		}
	}
	return b.String()
}

// selectPlanRecords filters and ranks records for the plan phase, returning
// at most maxRecords of the most "interesting" ones. Interesting means the
// request has query parameters, a body, or uses a non-GET method. Static
// asset requests are deprioritised. This keeps the plan agent context small
// and focused on attackable surface.
func selectPlanRecords(records []*httpmsg.HttpRequestResponse, maxRecords int) []*httpmsg.HttpRequestResponse {
	if maxRecords <= 0 {
		maxRecords = 10
	}
	if len(records) <= maxRecords {
		return records
	}

	// Static file extensions to deprioritise
	staticExts := map[string]bool{
		".css": true, ".js": true, ".png": true, ".jpg": true, ".jpeg": true,
		".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
		".ttf": true, ".eot": true, ".map": true, ".webp": true, ".avif": true,
	}

	type scored struct {
		record *httpmsg.HttpRequestResponse
		score  int
		index  int // preserve original order for tie-breaking
	}

	scored_records := make([]scored, 0, len(records))
	for i, rr := range records {
		s := 0
		req := rr.Request()
		if req == nil {
			scored_records = append(scored_records, scored{rr, s, i})
			continue
		}

		// Non-GET methods are more interesting (POST, PUT, DELETE, PATCH)
		method := strings.ToUpper(req.Method())
		if method != "GET" && method != "HEAD" && method != "OPTIONS" {
			s += 3
		}

		// Has request body
		if len(req.Body()) > 0 {
			s += 3
		}

		// Has query parameters (check for '?' in path)
		path := req.Path()
		if strings.Contains(path, "?") {
			s += 2
		}

		// Check for interesting content types
		ct := strings.ToLower(req.Header("Content-Type"))
		if strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "form") {
			s += 1
		}

		// Has auth-related headers
		if req.HasHeader("Authorization") || req.HasHeader("Cookie") || req.HasHeader("X-API-Key") {
			s += 1
		}

		// Penalise static assets
		pathLower := strings.ToLower(path)
		if qIdx := strings.Index(pathLower, "?"); qIdx >= 0 {
			pathLower = pathLower[:qIdx]
		}
		if dotIdx := strings.LastIndex(pathLower, "."); dotIdx >= 0 {
			if staticExts[pathLower[dotIdx:]] {
				s -= 5
			}
		}

		// Penalise error responses (4xx/5xx without body suggest less interesting endpoints)
		if rr.HasResponse() {
			sc := rr.Response().StatusCode()
			if sc == 404 || sc == 405 {
				s -= 3
			} else if sc >= 400 {
				s -= 1
			}
		}

		scored_records = append(scored_records, scored{rr, s, i})
	}

	// Sort by score descending, then by original index ascending (stable-ish)
	sort.Slice(scored_records, func(i, j int) bool {
		if scored_records[i].score != scored_records[j].score {
			return scored_records[i].score > scored_records[j].score
		}
		return scored_records[i].index < scored_records[j].index
	})

	// Diversity-aware selection: greedy pick that penalizes records sharing
	// the same path prefix as already-selected records. This ensures the plan
	// agent sees a diverse set of endpoints rather than 10 variants of /api/users.
	type candidate struct {
		scored
		prefix string
	}
	candidates := make([]candidate, len(scored_records))
	for i, sr := range scored_records {
		prefix := ""
		if sr.record.Request() != nil {
			p := sr.record.Request().Path()
			if qIdx := strings.Index(p, "?"); qIdx >= 0 {
				p = p[:qIdx]
			}
			// Use first two path segments as prefix: /api/users/123 → /api/users
			parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
			if len(parts) > 2 {
				prefix = "/" + strings.Join(parts[:2], "/")
			} else {
				prefix = "/" + strings.Join(parts, "/")
			}
		}
		candidates[i] = candidate{scored: sr, prefix: prefix}
	}

	selected := make([]scored, 0, maxRecords)
	prefixCount := make(map[string]int)
	used := make(map[int]bool) // track used indices

	for len(selected) < maxRecords {
		bestIdx := -1
		bestEffective := -100
		for i, c := range candidates {
			if used[i] {
				continue
			}
			// Effective score: base score minus penalty for duplicate prefixes
			effective := c.score
			if c.prefix != "" {
				effective -= prefixCount[c.prefix] * 2
			}
			if effective > bestEffective || (effective == bestEffective && bestIdx >= 0 && c.index < candidates[bestIdx].index) {
				bestEffective = effective
				bestIdx = i
			}
		}
		if bestIdx < 0 {
			break
		}
		used[bestIdx] = true
		selected = append(selected, candidates[bestIdx].scored)
		if candidates[bestIdx].prefix != "" {
			prefixCount[candidates[bestIdx].prefix]++
		}
	}

	// Re-sort by original index to preserve request order
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].index < selected[j].index
	})

	result := make([]*httpmsg.HttpRequestResponse, len(selected))
	for i, s := range selected {
		result[i] = s.record
	}
	return result
}

// buildSmartHTTPContext builds a formatted HTTP context string for the master agent prompt.
// It always includes full raw requests and response headers, but truncates response bodies
// to maxRespBytes to manage token usage.
func buildSmartHTTPContext(records []*httpmsg.HttpRequestResponse, maxRespBytes int) string {
	if maxRespBytes <= 0 {
		maxRespBytes = 2048
	}

	var rc strings.Builder
	for i, rr := range records {
		if i > 0 {
			rc.WriteString("\n---\n\n")
		}
		fmt.Fprintf(&rc, "### Request %d\n\n", i+1)
		if rr.Request() != nil {
			rc.WriteString("```http\n")
			rc.Write(rr.Request().Raw())
			rc.WriteString("\n```\n")
		}
		if rr.Response() != nil && len(rr.Response().Raw()) > 0 {
			respRaw := rr.Response().Raw()
			// Split response into headers and body
			headerEnd := bytes.Index(respRaw, []byte("\r\n\r\n"))
			if headerEnd < 0 {
				headerEnd = bytes.Index(respRaw, []byte("\n\n"))
			}

			rc.WriteString("\n```http\n")
			if headerEnd >= 0 {
				// Write full headers
				rc.Write(respRaw[:headerEnd])
				rc.WriteString("\r\n\r\n")
				// Truncate body if needed
				body := respRaw[headerEnd+4:] // skip \r\n\r\n
				if bytes.HasPrefix(respRaw[headerEnd:], []byte("\n\n")) {
					body = respRaw[headerEnd+2:]
				}
				if len(body) > maxRespBytes {
					rc.Write(body[:maxRespBytes])
					fmt.Fprintf(&rc, "\n... (truncated from %d bytes)", len(body))
				} else {
					rc.Write(body)
				}
			} else {
				// No header/body split found, truncate whole response
				if len(respRaw) > maxRespBytes {
					rc.Write(respRaw[:maxRespBytes])
					fmt.Fprintf(&rc, "\n... (truncated from %d bytes)", len(respRaw))
				} else {
					rc.Write(respRaw)
				}
			}
			rc.WriteString("\n```\n")
		}
	}
	return rc.String()
}

// runMasterAgent orchestrates the two-phase plan+extension agent flow.
// Phase 1 (plan) produces module tags, IDs, focus areas, and notes using a
// simple markdown-section format that is highly resistant to LLM output errors.
// Phase 2 (extensions) is conditional — it only runs when the plan indicates
// custom extensions are needed — and produces JavaScript code blocks in isolation.
// If Phase 2 fails, the plan from Phase 1 is still valid and the scan proceeds
// without custom extensions (graceful degradation).
func (s *SwarmRunner) runMasterAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string) (plan *SwarmPlan, sessionID string, rawOutput string, renderedPrompt string, err error) {
	// Pre-compute request context once for both phases
	requestContext := buildSmartHTTPContext(records, cfg.MaxResponseBodyBytes)

	// Phase 1: Plan agent — analyze and select modules (no code generation)
	plan, sessionID, rawOutput, renderedPrompt, err = s.runPlanAgent(ctx, cfg, records, targetURL, requestContext)
	if err != nil {
		return nil, sessionID, rawOutput, renderedPrompt, err
	}
	if cfg.DryRun || plan == nil {
		return plan, sessionID, rawOutput, renderedPrompt, nil
	}

	// Normalize parsed plan: clean tags/IDs, strip inline commentary
	normalizePlan(plan)

	// Phase 2: Extension agent — generate custom JS extensions (conditional)
	if planNeedsExtensions(plan) {
		extPlan, extSessionID, extRaw, _, extErr := s.runExtensionAgent(ctx, cfg, records, targetURL, plan, requestContext)
		if extErr != nil {
			// Graceful degradation: log the error but proceed with the plan from Phase 1
			zap.L().Warn("Extension agent failed — scanning without custom extensions",
				zap.Error(extErr))
			fmt.Fprintf(os.Stderr, "%s Extension agent failed — scanning without custom extensions: %s\n",
				terminal.WarningSymbol(), extErr.Error())
		} else if extPlan != nil {
			// Merge extensions into the main plan
			plan.Extensions = append(plan.Extensions, extPlan.Extensions...)
			plan.QuickChecks = append(plan.QuickChecks, extPlan.QuickChecks...)
			plan.Snippets = append(plan.Snippets, extPlan.Snippets...)

			// Append extension agent output artifacts
			rawOutput += "\n\n--- Extension Agent ---\n\n" + extRaw
			if extSessionID != "" {
				sessionID = extSessionID // use the latest session ID
			}
		}
	}

	return plan, sessionID, rawOutput, renderedPrompt, nil
}

// runPlanAgent executes Phase 1: analysis and module selection.
// The prompt asks for markdown sections only (no JSON, no code), making parsing robust.
func (s *SwarmRunner) runPlanAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, requestContext string) (plan *SwarmPlan, sessionID string, rawOutput string, renderedPrompt string, err error) {
	hostname := ""
	if targetURL != "" {
		hostname = hostnameFromURL(targetURL)
	}

	planSessionID := uuid.New().String()
	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: SwarmPromptPlan,
		TargetURL:      targetURL,
		Hostname:       hostname,
		SourcePath:     cfg.SourcePath,
		Instruction:    cfg.Instruction,
		SessionKey:     SwarmPhasePlan,
		SessionID:      planSessionID,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		SessionWeight:  3,
		SlashCommands:  cfg.SlashCommands,
		CustomAgents:   cfg.CustomAgents,
		MaxCommands:    cfg.MaxCommands,
	}

	// Resolve effective vuln focus: --vuln-type takes precedence, --focus is a broader hint
	effectiveVulnType := cfg.VulnType
	if effectiveVulnType == "" && cfg.Focus != "" {
		effectiveVulnType = cfg.Focus
	}

	if effectiveVulnType != "" {
		header := "## Vulnerability Focus"
		if cfg.VulnType == "" && cfg.Focus != "" {
			header = "## Focus Area"
		}
		opts.Append = fmt.Sprintf("%s\n\n%s", header, effectiveVulnType)
	}

	// Inject terminal context: custom agents and slash commands
	terminalContext := buildTerminalPromptContext(cfg.CustomAgents, cfg.SlashCommands)
	opts.Append += terminalContext

	// Retry loop — retries on both parse failures and transient ACP errors (timeouts, etc.).
	maxAttempts := cfg.MaxMasterRetries
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	var lastSessionID string
	var lastRawOutput string
	var lastRenderedPrompt string
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		extraContext := requestContext
		if attempt > 1 && lastErr != nil {
			zap.L().Info("retrying plan agent",
				zap.Int("attempt", attempt),
				zap.Error(lastErr))
			opts.Append = buildPlanRetryFeedback(effectiveVulnType, lastErr, lastRawOutput) + terminalContext
			extraContext = retryTruncateContext(records)
		}

		result, runErr := s.engine.RunWithExtra(ctx, opts, map[string]string{
			"RequestContext": extraContext,
			"VulnType":       effectiveVulnType,
		})
		if runErr != nil {
			if isRetryableAgentError(ctx, runErr) && attempt < maxAttempts {
				zap.L().Warn("plan agent execution failed (retryable), will retry",
					zap.Int("attempt", attempt),
					zap.Error(runErr))
				lastErr = runErr
				continue
			}
			return nil, "", "", "", fmt.Errorf("plan agent execution failed: %w", runErr)
		}

		lastSessionID = result.SessionID
		lastRawOutput = result.RawOutput
		lastRenderedPrompt = result.RenderedPrompt

		WriteSDKSessionEntry(cfg.SessionDir, SDKSessionEntry{
			SessionID: planSessionID,
			Phase:     SwarmPhasePlan,
			AgentName: cfg.AgentName,
			Timestamp: time.Now(),
		})

		if cfg.DryRun {
			return nil, result.SessionID, result.RawOutput, result.RenderedPrompt, nil
		}

		parsed, parseErr := ParseSwarmPlan(result.RawOutput)
		if parseErr != nil {
			zap.L().Debug("plan agent raw output (parse failed)",
				zap.String("output", result.RawOutput),
				zap.Int("attempt", attempt))
			lastErr = parseErr
			continue
		}

		return parsed, result.SessionID, result.RawOutput, result.RenderedPrompt, nil
	}

	return nil, lastSessionID, lastRawOutput, lastRenderedPrompt, fmt.Errorf("failed to parse plan after %d attempts: %w", maxAttempts, lastErr)
}

// runExtensionAgent executes Phase 2: custom extension generation.
// It receives the parsed plan as context so the agent focuses only on writing code.
// This is isolated from the plan phase — if it fails, the plan is still valid.
func (s *SwarmRunner) runExtensionAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, plan *SwarmPlan, requestContext string) (extPlan *SwarmPlan, sessionID string, rawOutput string, renderedPrompt string, err error) {
	hostname := ""
	if targetURL != "" {
		hostname = hostnameFromURL(targetURL)
	}

	// Build plan context summary for the extension agent
	planContext := buildPlanContext(plan)

	extPhaseSessionID := uuid.New().String()
	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: SwarmPromptExtensions,
		TargetURL:      targetURL,
		Hostname:       hostname,
		SourcePath:     cfg.SourcePath,
		Instruction:    cfg.Instruction,
		SessionKey:     SwarmPhaseExtension,
		SessionID:      extPhaseSessionID,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		SessionWeight:  2,
		SlashCommands:  cfg.SlashCommands,
		CustomAgents:   cfg.CustomAgents,
		MaxCommands:    cfg.MaxCommands,
	}

	// Resolve effective vuln focus for extension agent
	extVulnType := cfg.VulnType
	if extVulnType == "" && cfg.Focus != "" {
		extVulnType = cfg.Focus
	}

	const maxExtRetries = 3
	var result *Result
	for extAttempt := 1; extAttempt <= maxExtRetries; extAttempt++ {
		var runErr error
		result, runErr = s.engine.RunWithExtra(ctx, opts, map[string]string{
			"RequestContext": requestContext,
			"PlanContext":    planContext,
			"VulnType":       extVulnType,
		})
		if runErr == nil {
			break
		}
		if isRetryableAgentError(ctx, runErr) && extAttempt < maxExtRetries {
			zap.L().Warn("extension agent failed (retryable), will retry",
				zap.Int("attempt", extAttempt),
				zap.Error(runErr))
			continue
		}
		return nil, "", "", "", fmt.Errorf("extension agent execution failed: %w", runErr)
	}

	WriteSDKSessionEntry(cfg.SessionDir, SDKSessionEntry{
		SessionID: extPhaseSessionID,
		Phase:     SwarmPhaseExtension,
		AgentName: cfg.AgentName,
		Timestamp: time.Now(),
	})

	if cfg.DryRun {
		return nil, result.SessionID, result.RawOutput, result.RenderedPrompt, nil
	}

	// Parse extensions from the output — we only care about extensions, quick_checks, snippets
	parsed, parseErr := ParseSwarmExtensions(result.RawOutput)
	if parseErr != nil {
		return nil, result.SessionID, result.RawOutput, result.RenderedPrompt,
			fmt.Errorf("extension agent output unparseable: %w", parseErr)
	}

	return parsed, result.SessionID, result.RawOutput, result.RenderedPrompt, nil
}

// buildPlanContext formats the plan as a readable summary for the extension agent prompt.
func buildPlanContext(plan *SwarmPlan) string {
	var sb strings.Builder

	if len(plan.ModuleTags) > 0 {
		sb.WriteString("**Module tags:** ")
		sb.WriteString(strings.Join(plan.ModuleTags, ", "))
		sb.WriteString("\n\n")
	}
	if len(plan.ModuleIDs) > 0 {
		sb.WriteString("**Module IDs:** ")
		sb.WriteString(strings.Join(plan.ModuleIDs, ", "))
		sb.WriteString("\n\n")
	}
	if len(plan.FocusAreas) > 0 {
		sb.WriteString("**Focus areas:**\n")
		for _, fa := range plan.FocusAreas {
			fmt.Fprintf(&sb, "- %s\n", fa)
		}
		sb.WriteString("\n")
	}
	if plan.Notes != "" {
		sb.WriteString("**Notes:** ")
		sb.WriteString(plan.Notes)
		sb.WriteString("\n")
	}

	return sb.String()
}

// planNeedsExtensions checks whether the plan indicates custom extensions are needed.
// It checks the NEEDS_EXTENSIONS section, and also considers focus areas / notes
// that suggest non-standard attack surfaces.
func planNeedsExtensions(plan *SwarmPlan) bool {
	if plan == nil {
		return false
	}

	// Check the NEEDS_EXTENSIONS field parsed from the markdown section
	if plan.NeedsExtensions {
		return true
	}

	// If the plan already has extensions (from legacy flow or hybrid parse), skip
	if len(plan.Extensions) > 0 || len(plan.QuickChecks) > 0 || len(plan.Snippets) > 0 {
		return false
	}

	return false
}

// normalizePlan cleans up parsed plan fields: lowercases tags/IDs, strips
// inline commentary, removes duplicates, and trims whitespace.
func normalizePlan(plan *SwarmPlan) {
	if plan == nil {
		return
	}

	plan.ModuleTags = normalizeStringSlice(plan.ModuleTags)
	plan.ModuleIDs = normalizeStringSlice(plan.ModuleIDs)

	// Deduplicate focus areas (exact match), strip empty/meaningless entries
	if len(plan.FocusAreas) > 0 {
		seen := make(map[string]bool, len(plan.FocusAreas))
		deduped := make([]string, 0, len(plan.FocusAreas))
		for _, fa := range plan.FocusAreas {
			fa = strings.TrimSpace(fa)
			// Skip empty entries or lone bullet characters
			if len(fa) <= 1 || seen[fa] {
				continue
			}
			seen[fa] = true
			deduped = append(deduped, fa)
		}
		plan.FocusAreas = deduped
	}

	plan.Notes = strings.TrimSpace(plan.Notes)
}

// normalizeStringSlice lowercases, trims whitespace, strips inline parenthetical
// commentary (e.g., "sqli (common in login forms)" → "sqli"), and deduplicates.
func normalizeStringSlice(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		// Strip inline parenthetical commentary: "sqli (reason)" → "sqli"
		if idx := strings.Index(item, "("); idx > 0 {
			item = strings.TrimSpace(item[:idx])
		}
		// Strip trailing commentary after " - " or " — "
		if idx := strings.Index(item, " - "); idx > 0 {
			item = strings.TrimSpace(item[:idx])
		}
		if idx := strings.Index(item, " — "); idx > 0 {
			item = strings.TrimSpace(item[:idx])
		}
		item = strings.ToLower(item)
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// buildPlanRetryFeedback constructs error feedback for plan agent retries.
// Simpler than the old buildRetryFeedback since the plan agent outputs no code.
func buildPlanRetryFeedback(vulnType string, parseErr error, rawOutput string) string {
	var sb strings.Builder
	if vulnType != "" {
		fmt.Fprintf(&sb, "## Vulnerability Focus\n\n%s\n\n", vulnType)
	}
	sb.WriteString("## CRITICAL: Your previous output could not be parsed\n\n")
	fmt.Fprintf(&sb, "Parse error: %s\n\n", parseErr.Error())

	if rawOutput != "" {
		snippet := rawOutput
		if len(snippet) > 500 {
			snippet = snippet[:500] + "..."
		}
		fmt.Fprintf(&sb, "Your previous output (truncated):\n```\n%s\n```\n\n", snippet)
	}

	sb.WriteString("You MUST use the markdown section format. Requirements:\n")
	sb.WriteString("1. Use `## MODULE_TAGS` heading followed by a comma-separated list on the next line.\n")
	sb.WriteString("2. Use `## MODULE_IDS` heading followed by a comma-separated list on the next line.\n")
	sb.WriteString("3. Use `## FOCUS_AREAS` heading followed by a bulleted list.\n")
	sb.WriteString("4. Use `## NOTES` heading followed by free-text notes.\n")
	sb.WriteString("5. Do NOT output JSON or code blocks. Only markdown sections.\n")
	return sb.String()
}

// retryTruncateContext produces a compact method+URL summary of the request
// records, suitable for retry attempts where sending the full raw HTTP is wasteful.
func retryTruncateContext(records []*httpmsg.HttpRequestResponse) string {
	var sb strings.Builder
	for i, rr := range records {
		if i > 0 {
			sb.WriteString("\n")
		}
		method := "???"
		reqURL := "???"
		if rr.Request() != nil {
			method = rr.Request().Method()
			if u, err := rr.URL(); err == nil {
				reqURL = u.String()
			}
		}
		fmt.Fprintf(&sb, "- %s %s", method, reqURL)
	}
	return sb.String()
}


// writeExtensionsToDir writes extensions to the session dir if available, otherwise to a temp dir.
func writeExtensionsToDir(extensions []GeneratedExtension, sessionDir string) (string, error) {
	if sessionDir != "" {
		return WriteExtensionsToSessionDir(extensions, sessionDir)
	}
	return WriteExtensionsToTempDir(extensions, "vigolium-swarm-ext-*")
}

// writeSessionConfigToDir writes session config JSON to the session directory.
func writeSessionConfigToDir(cfg *AgentSessionConfig, sessionDir string) {
	if sessionDir == "" {
		return
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		zap.L().Warn("Failed to marshal session config", zap.Error(err))
		return
	}
	path := filepath.Join(sessionDir, "session-config.json")
	if writeErr := os.WriteFile(path, data, 0644); writeErr != nil {
		zap.L().Warn("Failed to write session config", zap.Error(writeErr))
		return
	}
	zap.L().Info("Session config written", zap.String("path", path))
}

// writeSourceExtensionsToSessionDir writes source-analysis/SAST-review generated extensions
// to the session directory immediately when discovered. This ensures extensions are
// preserved as artifacts even if subsequent phases fail. The extensions/ subdirectory
// is used, matching the same location that the final merged extensions are written to.
func writeSourceExtensionsToSessionDir(extensions []GeneratedExtension, sessionDir string) {
	if len(extensions) == 0 || sessionDir == "" {
		return
	}
	extDir := filepath.Join(sessionDir, "extensions")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		zap.L().Warn("Failed to create extensions dir for source extensions", zap.Error(err))
		return
	}
	for i, ext := range extensions {
		filename := sanitizeExtensionFilename(ext.Filename, i)
		path := filepath.Join(extDir, filename)
		if writeErr := os.WriteFile(path, []byte(ext.Code), 0644); writeErr != nil {
			zap.L().Warn("Failed to write source extension",
				zap.String("filename", filename),
				zap.Error(writeErr))
			continue
		}
		zap.L().Info("Source extension written to session dir",
			zap.String("filename", filename),
			zap.String("reason", ext.Reason))
	}
}

// writePromptToSessionDir saves a rendered prompt to the session directory.
func writePromptToSessionDir(sessionDir, filename, prompt string) {
	if sessionDir == "" || prompt == "" {
		return
	}
	path := filepath.Join(sessionDir, filename)
	if err := os.WriteFile(path, []byte(prompt), 0644); err != nil {
		zap.L().Warn("Failed to write prompt to session dir",
			zap.String("filename", filename), zap.Error(err))
		return
	}
	zap.L().Debug("Prompt written to session dir", zap.String("path", path))
}

// writeInputsToSessionDir saves the normalized input records and source path as JSON to the session directory.
func writeInputsToSessionDir(sessionDir string, records []*httpmsg.HttpRequestResponse, sourcePath string) {
	if sessionDir == "" || (len(records) == 0 && sourcePath == "") {
		return
	}
	type inputRecord struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers,omitempty"`
		Body    string            `json:"body,omitempty"`
	}
	type inputsFile struct {
		SourcePath string        `json:"source_path,omitempty"`
		Records    []inputRecord `json:"records"`
	}
	var inputRecords []inputRecord
	for _, rr := range records {
		ir := inputRecord{}
		if rr.Request() != nil {
			ir.Method = rr.Request().Method()
			if u, err := rr.URL(); err == nil {
				ir.URL = u.String()
			}
			ir.Headers = make(map[string]string)
			for _, h := range rr.Request().Headers() {
				ir.Headers[h.Name] = h.Value
			}
			if body := rr.Request().Body(); len(body) > 0 {
				ir.Body = string(body)
			}
		}
		inputRecords = append(inputRecords, ir)
	}
	out := inputsFile{
		SourcePath: sourcePath,
		Records:    inputRecords,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		zap.L().Warn("Failed to marshal inputs", zap.Error(err))
		return
	}
	path := filepath.Join(sessionDir, "inputs.json")
	if writeErr := os.WriteFile(path, data, 0644); writeErr != nil {
		zap.L().Warn("Failed to write inputs to session dir", zap.Error(writeErr))
		return
	}
	zap.L().Debug("Inputs written to session dir", zap.String("path", path), zap.Int("count", len(inputRecords)))
}

// ExtensionMergeResult holds the merged extensions plus any rename tracking info.
type ExtensionMergeResult struct {
	Extensions []GeneratedExtension
	Renames    map[string]string // original filename -> renamed filename
}

// mergeExtensionsTracked combines source-analysis and plan extensions by filename,
// tracking any renames that occur during collision resolution.
// On collision with identical code, the duplicate is dropped.
// On collision with different code, the plan extension is renamed with a -2, -3 suffix.
func mergeExtensionsTracked(source, plan []GeneratedExtension) ExtensionMergeResult {
	renames := make(map[string]string)

	if len(source) == 0 {
		return ExtensionMergeResult{Extensions: plan, Renames: renames}
	}
	if len(plan) == 0 {
		return ExtensionMergeResult{Extensions: source, Renames: renames}
	}

	existing := make(map[string]string, len(source))  // filename -> code
	nameSet := make(map[string]bool, len(source))     // maintained for deduplicateExtensionFilename
	result := make([]GeneratedExtension, 0, len(source)+len(plan))

	// Source extensions first
	for _, ext := range source {
		existing[ext.Filename] = ext.Code
		nameSet[ext.Filename] = true
		result = append(result, ext)
	}

	// Plan extensions: rename on collision with different code, skip on identical code
	for _, ext := range plan {
		if existingCode, collision := existing[ext.Filename]; collision {
			if existingCode == ext.Code {
				zap.L().Info("Skipping duplicate extension (same content)",
					zap.String("filename", ext.Filename))
				continue
			}
			// Different code — rename to avoid losing the extension
			originalName := ext.Filename
			ext.Filename = deduplicateExtensionFilename(ext.Filename, nameSet)
			renames[originalName] = ext.Filename
			zap.L().Info("Renamed colliding extension",
				zap.String("original", originalName),
				zap.String("new_filename", ext.Filename))
		}
		existing[ext.Filename] = ext.Code
		nameSet[ext.Filename] = true
		result = append(result, ext)
	}

	return ExtensionMergeResult{Extensions: result, Renames: renames}
}

// queryDiscoveredRecords fetches HTTP records from the database that were created
// during the discovery phase for the target hostname.
func (s *SwarmRunner) queryDiscoveredRecords(ctx context.Context, cfg SwarmConfig, targetURL string) []*httpmsg.HttpRequestResponse {
	if s.repo == nil || targetURL == "" {
		return nil
	}

	hostname := hostnameFromURL(targetURL)
	if hostname == "" {
		return nil
	}

	dbRecords, err := s.repo.GetRecordsByHostname(ctx, cfg.ProjectUUID, hostname, 500)
	if err != nil {
		zap.L().Warn("Failed to query discovered records", zap.Error(err))
		return nil
	}

	var records []*httpmsg.HttpRequestResponse
	for _, dbRec := range dbRecords {
		rr, parseErr := httpmsg.ParseRawRequestWithURL(string(dbRec.RawRequest), dbRec.URL)
		if parseErr != nil {
			continue
		}
		records = append(records, rr)
	}
	return records
}

// deduplicateRecords removes duplicate records by method+URL.
func deduplicateRecords(records []*httpmsg.HttpRequestResponse) []*httpmsg.HttpRequestResponse {
	seen := make(map[string]bool, len(records))
	var result []*httpmsg.HttpRequestResponse
	for _, rr := range records {
		key := ""
		if rr.Request() != nil {
			key = rr.Request().Method()
			if u, err := rr.URL(); err == nil {
				key += " " + u.String()
			}
		}
		if key != "" && seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, rr)
	}
	return result
}

// filterSourceRecordsByHostname converts AgentHTTPRecords to HttpRequestResponse,
// keeping only those whose hostname matches the target URL's hostname.
// Relative URLs are resolved against the target URL using net/url.ResolveReference
// for correct path handling (e.g., "../api/v2", "/api/users", "endpoint").
// Returns records and a parallel slice of notes (aligned 1:1 with records).
func filterSourceRecordsByHostname(agentRecords []AgentHTTPRecord, targetURL string) ([]*httpmsg.HttpRequestResponse, []string) {
	if targetURL == "" {
		return nil, nil
	}
	targetParsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil
	}
	targetHost := targetParsed.Host // includes port

	// Build a base URL for resolving relative references.
	// Ensure it ends with "/" so relative paths resolve correctly against the origin.
	baseURL := &url.URL{
		Scheme: targetParsed.Scheme,
		Host:   targetParsed.Host,
		Path:   "/",
	}

	// Normalize records first — fix garbled URLs, truncated bodies, malformed headers.
	normalized, dropped := NormalizeAgentRecords(agentRecords)
	if dropped > 0 {
		zap.L().Info("Normalized agent records",
			zap.Int("input", len(agentRecords)),
			zap.Int("normalized", len(normalized)),
			zap.Int("dropped", dropped))
	}

	var filtered []*httpmsg.HttpRequestResponse
	var notes []string
	skipped := 0
	for _, rec := range normalized {
		recURL := rec.URL

		// Resolve relative URLs against the target base using standard URL resolution.
		if !strings.HasPrefix(recURL, "http://") && !strings.HasPrefix(recURL, "https://") {
			ref, refErr := url.Parse(recURL)
			if refErr != nil {
				skipped++
				continue
			}
			recURL = baseURL.ResolveReference(ref).String()
		}

		recParsed, parseErr := url.Parse(recURL)
		if parseErr != nil {
			skipped++
			continue
		}
		if recParsed.Host != targetHost {
			skipped++
			continue
		}

		// Rewrite the record URL to be fully qualified
		rec.URL = recURL
		rr, convertErr := ToHTTPRequestResponse(rec)
		if convertErr != nil {
			zap.L().Debug("Skipping source record", zap.String("url", rec.URL), zap.Error(convertErr))
			skipped++
			continue
		}
		filtered = append(filtered, rr)
		notes = append(notes, rec.Notes)
	}

	if skipped > 0 {
		zap.L().Debug("Filtered source records by hostname",
			zap.String("target_host", targetHost),
			zap.Int("matched", len(filtered)),
			zap.Int("skipped", skipped))
	}

	return filtered, notes
}

// runMasterAgentBatched calls the master agent in parallel batches when there are many records.
// Each batch produces a SwarmPlan; plans are merged incrementally as results arrive.
// On first error, remaining in-flight batches are cancelled and the partial merged plan is returned.
func (s *SwarmRunner) runMasterAgentBatched(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, batchSize int) (*SwarmPlan, string, string, string, []string, *BatchProvenance, error) {
	// Pre-compute batch boundaries
	type batchRange struct {
		start, end, num int
	}
	var batches []batchRange
	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		batches = append(batches, batchRange{start: i, end: end, num: len(batches) + 1})
	}

	type batchResult struct {
		plan      *SwarmPlan
		sessionID string
		rawOutput string
		prompt    string
		batchNum  int
		err       error
	}

	resultsCh := make(chan batchResult, len(batches))
	batchConcurrency := cfg.BatchConcurrency
	if batchConcurrency <= 0 {
		batchConcurrency = runtime.NumCPU()
	}
	if batchConcurrency > len(batches) {
		batchConcurrency = len(batches)
	}
	sem := make(chan struct{}, batchConcurrency)
	gCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, b := range batches {
		b := b
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Acquire semaphore or bail on cancellation
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-gCtx.Done():
				resultsCh <- batchResult{err: gCtx.Err()}
				return
			}

			zap.L().Info("Running master agent batch",
				zap.Int("batch", b.num),
				zap.Int("batch_start", b.start),
				zap.Int("batch_end", b.end),
				zap.Int("total_records", len(records)))

			batch := records[b.start:b.end]
			plan, sid, rawOutput, prompt, err := s.runMasterAgent(gCtx, cfg, batch, targetURL)
			if err != nil {
				cancel() // Cancel remaining batches on first error
				resultsCh <- batchResult{err: fmt.Errorf("master agent batch %d-%d failed: %w", b.start, b.end, err)}
				return
			}
			if cfg.ProgressCallback != nil {
				cfg.ProgressCallback(ProgressEvent{
					Phase:    "plan",
					SubPhase: "batch",
					Current:  b.num,
					Total:    len(batches),
					Message:  fmt.Sprintf("master agent batch %d/%d completed", b.num, len(batches)),
				})
			}
			resultsCh <- batchResult{
				plan:      plan,
				sessionID: sid,
				rawOutput: rawOutput,
				prompt:    prompt,
				batchNum:  b.num,
			}
		}()
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect all results, then merge plans once at the end to avoid O(n²) intermediate merges.
	var plans []*SwarmPlan
	var lastSessionID string
	var allSessionIDs []string
	var allRawOutputs []string
	var allRenderedPrompts []string
	var firstErr error

	var failedBatches int
	for r := range resultsCh {
		if r.err != nil {
			failedBatches++
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		if r.sessionID != "" {
			lastSessionID = r.sessionID
			allSessionIDs = append(allSessionIDs, r.sessionID)
		}
		if r.rawOutput != "" {
			allRawOutputs = append(allRawOutputs, r.rawOutput)
		}
		if r.prompt != "" {
			allRenderedPrompts = append(allRenderedPrompts, r.prompt)
		}
		if r.plan != nil {
			plans = append(plans, r.plan)
		}
	}

	combinedRaw := strings.Join(allRawOutputs, "\n\n---\n\n")
	lastPrompt := ""
	if len(allRenderedPrompts) > 0 {
		lastPrompt = allRenderedPrompts[len(allRenderedPrompts)-1]
	}

	// Merge all collected plans in one pass
	var mergedPlan *SwarmPlan
	var batchProv *BatchProvenance
	if len(plans) == 1 {
		mergedPlan = plans[0]
	} else if len(plans) > 1 {
		mergedPlan, batchProv = mergeSwarmPlans(plans)
	}

	if firstErr != nil {
		zap.L().Warn("Batch execution had failures",
			zap.Int("failed", failedBatches),
			zap.Int("succeeded", len(plans)),
			zap.Int("total", len(batches)),
			zap.Error(firstErr))
		return mergedPlan, lastSessionID, combinedRaw, lastPrompt, allSessionIDs, batchProv, firstErr
	}

	return mergedPlan, lastSessionID, combinedRaw, lastPrompt, allSessionIDs, batchProv, nil
}

// mergeSwarmPlans combines multiple SwarmPlans by deduplicating module tags,
// module IDs, extensions (by filename, last wins), and focus areas.
// When merging multiple plans, batch provenance is returned separately
// to track which batch contributed each tag, ID, extension, and focus area.
func mergeSwarmPlans(plans []*SwarmPlan) (*SwarmPlan, *BatchProvenance) {
	tagSet := make(map[string]bool)
	idSet := make(map[string]bool)
	focusSet := make(map[string]bool)
	extMap := make(map[string]GeneratedExtension)
	extNames := make(map[string]bool) // maintained alongside extMap to avoid rebuilding per collision
	qcMap := make(map[string]QuickCheck)
	snipMap := make(map[string]Snippet)
	var notes []string

	// Provenance tracking (batch number is 1-indexed)
	trackProvenance := len(plans) > 1
	var prov *BatchProvenance
	if trackProvenance {
		prov = &BatchProvenance{
			ModuleTags: make(map[string]int),
			ModuleIDs:  make(map[string]int),
			Extensions: make(map[string]int),
			FocusAreas: make(map[string]int),
		}
	}

	for batchIdx, p := range plans {
		batchNum := batchIdx + 1
		for _, t := range p.ModuleTags {
			if !tagSet[t] && prov != nil {
				prov.ModuleTags[t] = batchNum
			}
			tagSet[t] = true
		}
		for _, id := range p.ModuleIDs {
			if !idSet[id] && prov != nil {
				prov.ModuleIDs[id] = batchNum
			}
			idSet[id] = true
		}
		for _, fa := range p.FocusAreas {
			if !focusSet[fa] && prov != nil {
				prov.FocusAreas[fa] = batchNum
			}
			focusSet[fa] = true
		}
		for _, ext := range p.Extensions {
			if existingExt, collision := extMap[ext.Filename]; collision && existingExt.Code != ext.Code {
				// Rename on collision with different code
				ext.Filename = deduplicateExtensionFilename(ext.Filename, extNames)
				zap.L().Info("Renamed colliding batch extension",
					zap.String("new_filename", ext.Filename),
					zap.Int("batch", batchNum))
			}
			extMap[ext.Filename] = ext
			extNames[ext.Filename] = true
			if prov != nil {
				prov.Extensions[ext.Filename] = batchNum
			}
		}
		for _, qc := range p.QuickChecks {
			qcMap[qc.ID] = qc
		}
		for _, snip := range p.Snippets {
			snipMap[snip.ID] = snip
		}
		if p.Notes != "" {
			notes = append(notes, p.Notes)
		}
	}

	merged := &SwarmPlan{
		ModuleTags: sortedKeys(tagSet),
		ModuleIDs:  sortedKeys(idSet),
		FocusAreas: sortedKeys(focusSet),
		Notes:      strings.Join(notes, "; "),
	}
	for _, ext := range extMap {
		merged.Extensions = append(merged.Extensions, ext)
	}
	for _, qc := range qcMap {
		merged.QuickChecks = append(merged.QuickChecks, qc)
	}
	for _, snip := range snipMap {
		merged.Snippets = append(merged.Snippets, snip)
	}
	return merged, prov
}

// sortedKeys returns sorted keys from a boolean set map.
func sortedKeys(s map[string]bool) []string {
	result := make([]string, 0, len(s))
	for k := range s {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

func (s *SwarmRunner) runTriageLoop(ctx context.Context, cfg SwarmConfig, agentRun *database.AgentRun, result *SwarmResult, sessionDir string, extensionDir string, checkpoint *SwarmCheckpoint, extensionRenames map[string]string, completedPhases []string) error {
	// Determine triage resume point from checkpoint
	triageResumeRound := 0
	if checkpoint != nil && checkpoint.TriageRound > 0 {
		triageResumeRound = checkpoint.TriageRound
		zap.L().Info("Resuming triage from checkpoint",
			zap.Int("resume_round", triageResumeRound))
	}

	triageCfg := TriageLoopConfig{
		Engine:         s.engine,
		Repository:     s.repo,
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: SwarmPromptTriage,
		TargetURL:      agentRun.TargetURL,
		Hostname:       hostnameFromURL(agentRun.TargetURL),
		SourcePath:     cfg.SourcePath,
		Instruction:    cfg.Instruction,
		SessionKey:     SwarmPhaseTriage,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		SlashCommands:  cfg.SlashCommands,
		CustomAgents:   cfg.CustomAgents,
		MaxCommands:    cfg.MaxCommands,
		MaxRounds:                 cfg.MaxIterations,
		MaxFindingsPerTriageBatch: 25,
		ResumeFromRound:           triageResumeRound,
		ProgressCallback:          cfg.ProgressCallback,
		ScanFunc:                  cfg.ScanFunc,
		SessionDir:     sessionDir,
		ExtensionDir:   extensionDir,
		OnRescan: func() {
			s.emitPhase(cfg, SwarmPhaseRescan)
			agentRun.CurrentPhase = SwarmPhaseRescan
			s.persistPhase(ctx, agentRun)
		},
		OnTriageRoundComplete: func(round int) {
			if cpErr := writeCheckpoint(sessionDir, &SwarmCheckpoint{
				CompletedPhases:  completedPhases,
				TargetURL:        agentRun.TargetURL,
				RecordCount:      result.TotalRecords,
				Plan:             result.SwarmPlan,
				ExtensionDir:     extensionDir,
				TriageRound:      round + 1, // next round to resume from
				ExtensionRenames: extensionRenames,
				Timestamp:        time.Now(),
			}); cpErr != nil {
				zap.L().Warn("Failed to write checkpoint after triage round", zap.Int("round", round), zap.Error(cpErr))
			}
		},
	}

	loopResult, err := RunTriageLoop(ctx, triageCfg)
	if err != nil {
		return err
	}

	result.TriageResults = loopResult.TriageResults
	result.Confirmed += loopResult.Confirmed
	result.FalsePositives += loopResult.FalsePositives
	result.Iterations = len(loopResult.TriageResults)

	// Store last triage result in agent run record
	if len(loopResult.TriageResults) > 0 {
		lastTriage := loopResult.TriageResults[len(loopResult.TriageResults)-1]
		triageJSON, _ := json.Marshal(lastTriage)
		agentRun.TriageResult = string(triageJSON)
	}

	return nil
}

// runSASTReview spawns a sub-agent to review SAST findings and validate extracted routes.
// It queries SAST findings from the database, formats them for the agent, and parses
// the response as a SourceAnalysisResult (validated routes + optional extensions).
func (s *SwarmRunner) runSASTReview(ctx context.Context, cfg SwarmConfig, targetURL string, sessionDir string) *SourceAnalysisResult {
	if s.repo == nil {
		zap.L().Warn("SAST review skipped: no database repository")
		return nil
	}

	// Query SAST findings from DB
	sastFindings, err := database.NewFindingsQueryBuilder(s.repo.DB(), database.QueryFilters{
		ProjectUUID: cfg.ProjectUUID,
		ModuleType:  database.ModuleTypeSAST,
		Limit:       200,
	}).Execute(ctx)
	if err != nil {
		zap.L().Warn("Failed to query SAST findings", zap.Error(err))
		return nil
	}

	// Also query code-audit findings if they exist, so the SAST review
	// can validate them alongside SAST findings.
	codeAuditModuleID := "agent-" + SwarmPromptCodeAudit
	allAgentFindings, caErr := database.NewFindingsQueryBuilder(s.repo.DB(), database.QueryFilters{
		ProjectUUID: cfg.ProjectUUID,
		ModuleType:  database.ModuleTypeAgent,
		Limit:       100,
	}).Execute(ctx)
	if caErr != nil {
		zap.L().Debug("Failed to query agent findings for SAST review", zap.Error(caErr))
	}
	for _, f := range allAgentFindings {
		if f.ModuleID == codeAuditModuleID {
			sastFindings = append(sastFindings, f)
		}
	}

	if len(sastFindings) == 0 {
		zap.L().Info("No SAST findings to review")
		return nil
	}

	// Format findings for the agent prompt
	var findingsSummary strings.Builder
	for i, f := range sastFindings {
		if i > 0 {
			findingsSummary.WriteString("\n---\n")
		}
		fmt.Fprintf(&findingsSummary, "### Finding %d\n", i+1)
		fmt.Fprintf(&findingsSummary, "- **Module**: %s (%s)\n", f.ModuleName, f.ModuleID)
		fmt.Fprintf(&findingsSummary, "- **Severity**: %s\n", f.Severity)
		fmt.Fprintf(&findingsSummary, "- **Source**: %s\n", f.FindingSource)
		if f.Description != "" {
			fmt.Fprintf(&findingsSummary, "- **Description**: %s\n", f.Description)
		}
		if len(f.MatchedAt) > 0 {
			fmt.Fprintf(&findingsSummary, "- **Matched at**: %s\n", strings.Join(f.MatchedAt, ", "))
		}
		if len(f.Tags) > 0 {
			fmt.Fprintf(&findingsSummary, "- **Tags**: %s\n", strings.Join(f.Tags, ", "))
		}
	}

	// Also query SAST-extracted routes from DB (these were ingested by the SAST phase)
	hostname := hostnameFromURL(targetURL)
	var routesSummary string
	if hostname != "" {
		dbRecords, recErr := s.repo.GetRecordsByHostname(ctx, cfg.ProjectUUID, hostname, 100)
		if recErr == nil && len(dbRecords) > 0 {
			var rs strings.Builder
			for i, rec := range dbRecords {
				if i >= 100 {
					fmt.Fprintf(&rs, "\n... and %d more routes", len(dbRecords)-100)
					break
				}
				fmt.Fprintf(&rs, "- %s %s\n", rec.Method, rec.URL)
			}
			routesSummary = rs.String()
		}
	}

	sastReviewSessionID := uuid.New().String()
	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: SwarmPromptSASTReview,
		TargetURL:      targetURL,
		Hostname:       hostname,
		SourcePath:     cfg.SourcePath,
		Instruction:    cfg.Instruction,
		SessionKey:     SwarmPhaseSASTReview,
		SessionID:      sastReviewSessionID,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		SlashCommands:  cfg.SlashCommands,
		CustomAgents:   cfg.CustomAgents,
		MaxCommands:    cfg.MaxCommands,
	}

	agentResult, runErr := s.engine.RunWithExtra(ctx, opts, map[string]string{
		"SASTFindings":     findingsSummary.String(),
		"SASTFindingCount": fmt.Sprintf("%d", len(sastFindings)),
		"DiscoveredRoutes": routesSummary,
	})
	if runErr != nil {
		zap.L().Warn("SAST review agent failed", zap.Error(runErr))
		return nil
	}

	WriteSDKSessionEntry(sessionDir, SDKSessionEntry{
		SessionID: sastReviewSessionID,
		Phase:     SwarmPhaseSASTReview,
		AgentName: cfg.AgentName,
		Timestamp: time.Now(),
	})

	// Save prompt and output to session dir
	writePromptToSessionDir(sessionDir, "sast-review-prompt.md", agentResult.RenderedPrompt)
	if sessionDir != "" && agentResult.RawOutput != "" {
		_ = os.WriteFile(filepath.Join(sessionDir, "sast-review-output.md"), []byte(agentResult.RawOutput), 0644)
	}

	if cfg.DryRun {
		return nil
	}

	// Parse as SourceAnalysisResult (validated routes + optional extensions).
	// ParseSourceAnalysisResult now handles multi-block output and falls back to
	// extracting extensions even when JSON parsing fails entirely.
	saResult, parseErr := ParseSourceAnalysisResult(agentResult.RawOutput)
	if parseErr != nil {
		zap.L().Warn("Failed to parse SAST review result", zap.Error(parseErr))
		return nil
	}

	zap.L().Info("SAST review completed",
		zap.Int("validated_routes", len(saResult.HTTPRecords)),
		zap.Int("extensions", len(saResult.Extensions)))

	// Write extensions to session dir immediately as .js files.
	// This ensures they are persisted as artifacts even if subsequent phases fail
	// or the caller doesn't handle the returned extensions.
	if sessionDir != "" && len(saResult.Extensions) > 0 {
		writeSourceExtensionsToSessionDir(saResult.Extensions, sessionDir)
	}

	// Validate and write session config to session dir if the SAST review produced one
	if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
		vr := ValidateSessionConfigDetailed(saResult.SessionConfig)
		if len(vr.Invalid) > 0 {
			invalidCfg := &AgentSessionConfig{}
			for _, inv := range vr.Invalid {
				invalidCfg.Sessions = append(invalidCfg.Sessions, inv.Entry)
			}
			repaired := RepairInvalidSessionConfig(ctx, s.engine, invalidCfg, targetURL, repairConfig{
				AgentName:   cfg.AgentName,
				AgentACPCmd: cfg.AgentACPCmd,
				ShowPrompt:  cfg.ShowPrompt,
			})
			if repaired != nil {
				vr.Valid = append(vr.Valid, repaired.Sessions...)
			}
		}
		if len(vr.Valid) > 0 {
			saResult.SessionConfig = &AgentSessionConfig{Sessions: vr.Valid}
		} else {
			saResult.SessionConfig = nil
		}
	}
	if sessionDir != "" && saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
		writeSessionConfigToDir(saResult.SessionConfig, sessionDir)
	}

	return saResult
}

// runCodeAudit performs an AI-driven security code audit that identifies business logic flaws,
// data flow vulnerabilities, and framework misconfigurations that static analysis tools miss.
// It receives source analysis output as context (routes, auth flows) to avoid redundant codebase reads.
// Findings are saved directly to the database with module_type "agent-code-audit".
func (s *SwarmRunner) runCodeAudit(ctx context.Context, cfg SwarmConfig, targetURL string, sessionDir string, sourceAnalysisNotes string, reuseExploreSession bool) (int, error) {
	if s.repo == nil {
		return 0, fmt.Errorf("code audit skipped: no database repository")
	}

	hostname := hostnameFromURL(targetURL)

	// Build extra context for the prompt
	extra := map[string]string{
		"TargetURL": targetURL,
		"Hostname":  hostname,
	}

	// Determine session key: reuse the explore session when available,
	// so the agent already has full codebase context from source analysis.
	sessionKey := SwarmPhaseCodeAudit
	if reuseExploreSession && s.engine.sdkPool != nil {
		sessionKey = "sa-explore" // reuse explore session (multi-turn)
		// Context is already in the session — don't append raw notes.
	} else if sourceAnalysisNotes != "" {
		// Fallback: pass source analysis notes as extra context.
		extra["SourceAnalysisContext"] = sourceAnalysisNotes
	}

	// Query existing routes from DB to give the agent endpoint context
	if hostname != "" {
		dbRecords, recErr := s.repo.GetRecordsByHostname(ctx, cfg.ProjectUUID, hostname, 100)
		if recErr == nil && len(dbRecords) > 0 {
			var rs strings.Builder
			for i, rec := range dbRecords {
				if i >= 100 {
					fmt.Fprintf(&rs, "\n... and %d more routes", len(dbRecords)-100)
					break
				}
				fmt.Fprintf(&rs, "- %s %s\n", rec.Method, rec.URL)
			}
			extra["DiscoveredRoutes"] = rs.String()
		}
	}

	codeAuditSessionID := uuid.New().String()
	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: SwarmPromptCodeAudit,
		TargetURL:      targetURL,
		Hostname:       hostname,
		SourcePath:     cfg.SourcePath,
		Files:          cfg.Files,
		Instruction:    cfg.Instruction,
		SessionKey:     sessionKey,
		SessionID:      codeAuditSessionID,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		SlashCommands:  cfg.SlashCommands,
		CustomAgents:   cfg.CustomAgents,
		MaxCommands:    cfg.MaxCommands,
	}

	agentResult, runErr := s.engine.RunWithExtra(ctx, opts, extra)
	if runErr != nil {
		return 0, fmt.Errorf("code audit agent failed: %w", runErr)
	}

	WriteSDKSessionEntry(sessionDir, SDKSessionEntry{
		SessionID: codeAuditSessionID,
		Phase:     SwarmPhaseCodeAudit,
		AgentName: cfg.AgentName,
		Timestamp: time.Now(),
	})

	// Save prompt and output to session dir
	writePromptToSessionDir(sessionDir, "code-audit-prompt.md", agentResult.RenderedPrompt)
	if sessionDir != "" && agentResult.RawOutput != "" {
		_ = os.WriteFile(filepath.Join(sessionDir, "code-audit-output.md"), []byte(agentResult.RawOutput), 0644)
	}

	if cfg.DryRun {
		return 0, nil
	}

	// Parse findings from agent output
	findings, parseErr := ParseFindings(agentResult.RawOutput)
	if parseErr != nil {
		zap.L().Warn("Failed to parse code audit findings", zap.Error(parseErr))
		return 0, nil
	}

	if len(findings) == 0 {
		zap.L().Info("Code audit produced no findings")
		return 0, nil
	}

	// Save findings to database
	saved, skipped, ingestErr := s.engine.ingestFindings(ctx, findings, opts)
	if ingestErr != nil {
		return saved, fmt.Errorf("failed to ingest code audit findings: %w", ingestErr)
	}

	zap.L().Info("Code audit completed",
		zap.Int("findings", len(findings)),
		zap.Int("saved", saved),
		zap.Int("skipped", skipped))

	return saved, nil
}

// probeRecords sends HTTP requests for records that don't have responses,
// enriching them with live response data. This ensures records saved to the
// database have response bodies, status codes, and headers for the scanner
// modules to analyze. Records are probed concurrently with a bounded worker pool.
// validateProbeAndSave filters records with valid URLs, injects auth headers,
// probes them for live responses, and saves them to the database.
// Records that fail the first probe are retried once.
// The optional notes slice (aligned 1:1 with records) is persisted as remarks.
func (s *SwarmRunner) validateProbeAndSave(ctx context.Context, records []*httpmsg.HttpRequestResponse, notes []string, authHeaders map[string]string, source, projectUUID string, pc ProbeConfig) {
	if len(records) == 0 {
		return
	}

	var valid []*httpmsg.HttpRequestResponse
	var validNotes []string
	for i, rr := range records {
		if rr.Request() == nil {
			continue
		}
		if u, urlErr := rr.URL(); urlErr != nil || u == nil || u.Host == "" {
			zap.L().Debug("Skipping record with invalid URL", zap.String("source", source), zap.Error(urlErr))
			continue
		}
		valid = append(valid, rr)
		if i < len(notes) {
			validNotes = append(validNotes, notes[i])
		} else {
			validNotes = append(validNotes, "")
		}
	}

	if len(authHeaders) > 0 {
		injectAuthHeaders(valid, authHeaders)
	}
	if len(valid) > 0 {
		probeRecordsWithConfig(ctx, valid, pc)

		// Retry probe for records that still have no response (transient failures).
		var unprobed []int
		for i, rr := range valid {
			if !rr.HasResponse() {
				unprobed = append(unprobed, i)
			}
		}
		if len(unprobed) > 0 {
			zap.L().Info("Retrying probe for records with no response",
				zap.Int("count", len(unprobed)))
			retry := make([]*httpmsg.HttpRequestResponse, len(unprobed))
			for j, idx := range unprobed {
				retry[j] = valid[idx]
			}
			probeRecordsWithConfig(ctx, retry, pc)
			for j, idx := range unprobed {
				valid[idx] = retry[j]
			}
		}
	}
	if s.repo != nil && len(valid) > 0 {
		var savedCount int
		remarksMap := make(map[string][]string)
		for i, rr := range valid {
			savedUUID, saveErr := s.repo.SaveRecord(ctx, rr, source, projectUUID)
			if saveErr != nil {
				zap.L().Debug("Failed to save record", zap.String("source", source), zap.Error(saveErr))
			} else {
				savedCount++
				if i < len(validNotes) && validNotes[i] != "" && savedUUID != "" {
					remarksMap[savedUUID] = []string{validNotes[i]}
				}
			}
		}
		if savedCount > 0 {
			zap.L().Info("Saved records to database", zap.String("source", source), zap.Int("count", savedCount))
		}
		if len(remarksMap) > 0 {
			if err := s.repo.AppendRemarks(ctx, remarksMap); err != nil {
				zap.L().Warn("Failed to append remarks from agent notes", zap.Error(err))
			}
		}
	}
}

// ProbeConfig holds tuning parameters for HTTP record probing.
type ProbeConfig struct {
	Concurrency  int           // max parallel probe requests; 0 = default 10
	Timeout      time.Duration // per-request probe timeout; 0 = default 10s
	MaxBodySize  int           // max response body bytes; 0 = default 2MB
	OnProgress   func(completed, total int) // optional progress callback
}

func (pc ProbeConfig) effectiveConcurrency() int {
	if pc.Concurrency <= 0 {
		return 10
	}
	return pc.Concurrency
}

func (pc ProbeConfig) effectiveTimeout() time.Duration {
	if pc.Timeout <= 0 {
		return 10 * time.Second
	}
	return pc.Timeout
}

func (pc ProbeConfig) effectiveMaxBodySize() int {
	if pc.MaxBodySize <= 0 {
		return 2 * 1024 * 1024
	}
	return pc.MaxBodySize
}

func probeRecords(ctx context.Context, records []*httpmsg.HttpRequestResponse) {
	probeRecordsWithConfig(ctx, records, ProbeConfig{})
}

func probeRecordsWithConfig(ctx context.Context, records []*httpmsg.HttpRequestResponse, pc ProbeConfig) {
	maxConcurrency := pc.effectiveConcurrency()
	probeTimeout := pc.effectiveTimeout()
	maxBody := pc.effectiveMaxBodySize()

	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Don't follow redirects — capture the redirect response itself
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	// Count probeable records for progress reporting
	var probeable int
	for _, rr := range records {
		if !rr.HasResponse() && rr.Request() != nil && rr.Target() != "" {
			probeable++
		}
	}

	var completed atomic.Int64 // atomic counter for progress
	for i, rr := range records {
		if rr.HasResponse() {
			continue
		}
		if rr.Request() == nil {
			continue
		}
		targetURL := rr.Target()
		if targetURL == "" {
			continue
		}

		wg.Add(1)
		idx := i
		go func(rec *httpmsg.HttpRequestResponse, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			probed := probeSingleRecordWithLimit(ctx, client, rec, target, maxBody)
			if probed != nil {
				records[idx] = probed
			}
			done := int(completed.Add(1))
			if pc.OnProgress != nil {
				pc.OnProgress(done, probeable)
			}
		}(rr, targetURL)
	}

	wg.Wait()
}

// probeSingleRecord sends an HTTP request for a single record and returns
// the record with the response attached, or nil if probing failed.
func probeSingleRecord(ctx context.Context, client *http.Client, rr *httpmsg.HttpRequestResponse, targetURL string) *httpmsg.HttpRequestResponse {
	return probeSingleRecordWithLimit(ctx, client, rr, targetURL, 2*1024*1024)
}

// probeSingleRecordWithLimit sends an HTTP request with a configurable body size limit.
func probeSingleRecordWithLimit(ctx context.Context, client *http.Client, rr *httpmsg.HttpRequestResponse, targetURL string, maxBody int) *httpmsg.HttpRequestResponse {
	method := "GET"
	if rr.Request() != nil {
		method = rr.Request().Method()
	}

	var bodyReader io.Reader
	if rr.Request() != nil && len(rr.Request().Body()) > 0 {
		bodyReader = bytes.NewReader(rr.Request().Body())
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		zap.L().Debug("Failed to build probe request", zap.String("url", targetURL), zap.Error(err))
		return nil
	}

	// Copy headers from the original request
	if rr.Request() != nil {
		for _, h := range rr.Request().Headers() {
			httpReq.Header.Add(h.Name, h.Value)
		}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		zap.L().Debug("Probe request failed", zap.String("url", targetURL), zap.Error(err))
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body (limit size to avoid memory issues)
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBody)))
	if err != nil {
		zap.L().Debug("Failed to read probe response", zap.String("url", targetURL), zap.Error(err))
		return nil
	}

	// Build raw HTTP response
	var rawResp bytes.Buffer
	fmt.Fprintf(&rawResp, "%s %s\r\n", resp.Proto, resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&rawResp, "%s: %s\r\n", k, v)
		}
	}
	rawResp.WriteString("\r\n")
	rawResp.Write(body)

	httpResp := httpmsg.NewHttpResponse(rawResp.Bytes())
	return rr.WithResponse(httpResp)
}

// reprobeUnprobedRecords queries ast-grep records without responses from the DB
// and probes them using a simple HTTP client. This acts as a fallback for records
// that the native SAST runner's httpRequester failed to probe.
func (s *SwarmRunner) reprobeUnprobedRecords(ctx context.Context, projectUUID, hostname string, authHeaders map[string]string, source string) {
	ReprobeUnprobedRecords(ctx, s.repo, projectUUID, hostname, authHeaders, source)
}

// hydrateSessionConfig executes login flows for all sessions in the agent session config,
// populates their Headers maps with extracted credentials, and returns the primary
// session's auth headers for immediate use. Mutates cfg.Sessions[].Headers in place
// so that callers (e.g. AgentSessionConfigToSessionHostnames) see the hydrated values.
func hydrateSessionConfig(cfg *AgentSessionConfig) map[string]string {
	if cfg == nil || len(cfg.Sessions) == 0 {
		return nil
	}

	var primaryHeaders map[string]string

	for i := range cfg.Sessions {
		entry := &cfg.Sessions[i]

		// Prefer static headers if provided (agent may have discovered hardcoded tokens)
		if len(entry.Headers) > 0 {
			zap.L().Info("Using static auth headers from source analysis",
				zap.String("session", entry.Name),
				zap.Int("header_count", len(entry.Headers)))
			if primaryHeaders == nil {
				primaryHeaders = entry.Headers
			}
			continue
		}

		// Execute login flow to obtain real credentials
		if entry.Login == nil {
			continue
		}

		sess := &session.Session{
			Name: entry.Name,
			Role: session.Role(entry.Role),
			Login: &session.LoginFlow{
				URL:         entry.Login.URL,
				Method:      entry.Login.Method,
				ContentType: entry.Login.ContentType,
				Body:        entry.Login.Body,
			},
		}
		for _, rule := range entry.Login.Extract {
			sess.Login.Extract = append(sess.Login.Extract, session.ExtractRule{
				Source:  session.ExtractSource(rule.Source),
				Name:    rule.Name,
				Path:    rule.Path,
				ApplyAs: rule.ApplyAs,
			})
		}

		// Use the session manager to execute the login flow
		mgr, mgrErr := session.NewManager([]*session.Session{sess})
		if mgrErr != nil {
			zap.L().Debug("Failed to create session manager for hydration",
				zap.String("session", entry.Name), zap.Error(mgrErr))
			continue
		}
		if hydErr := mgr.HydrateSessions(); hydErr != nil {
			zap.L().Debug("Failed to hydrate session from source analysis",
				zap.String("session", entry.Name), zap.Error(hydErr))
			continue
		}

		headers := mgr.PrimaryHeaders()
		if len(headers) > 0 {
			result := make(map[string]string, len(headers))
			for _, h := range headers {
				parts := strings.SplitN(h, ": ", 2)
				if len(parts) == 2 {
					result[parts[0]] = parts[1]
				}
			}
			if len(result) > 0 {
				zap.L().Info("Hydrated auth headers via login flow",
					zap.String("session", entry.Name),
					zap.Int("header_count", len(result)))
				// Store hydrated headers back on the entry for persistence
				entry.Headers = result
				if primaryHeaders == nil {
					primaryHeaders = result
				}
			}
		}
	}

	return primaryHeaders
}

// formatRouteStatusSummary returns a parenthesized summary of HTTP status code
// classes for probed records, e.g. "(2xx: 45, 3xx: 5, 4xx: 12, 5xx: 2, no-response: 3)".
func formatRouteStatusSummary(records []*httpmsg.HttpRequestResponse) string {
	var s2xx, s3xx, s4xx, s5xx, noResp int
	for _, rr := range records {
		if !rr.HasResponse() {
			noResp++
			continue
		}
		code := rr.Response().StatusCode()
		switch {
		case code >= 200 && code < 300:
			s2xx++
		case code >= 300 && code < 400:
			s3xx++
		case code >= 400 && code < 500:
			s4xx++
		case code >= 500:
			s5xx++
		default:
			noResp++
		}
	}
	var parts []string
	if s2xx > 0 {
		parts = append(parts, terminal.Green(fmt.Sprintf("2xx: %d", s2xx)))
	}
	if s3xx > 0 {
		parts = append(parts, terminal.Cyan(fmt.Sprintf("3xx: %d", s3xx)))
	}
	if s4xx > 0 {
		parts = append(parts, terminal.Yellow(fmt.Sprintf("4xx: %d", s4xx)))
	}
	if s5xx > 0 {
		parts = append(parts, terminal.Red(fmt.Sprintf("5xx: %d", s5xx)))
	}
	if noResp > 0 {
		parts = append(parts, terminal.Muted(fmt.Sprintf("no-response: %d", noResp)))
	}
	if len(parts) == 0 {
		return ""
	}
	return terminal.Muted("(") + strings.Join(parts, terminal.Muted(", ")) + terminal.Muted(")")
}

// injectAuthHeaders adds discovered auth headers to records that don't already
// have authentication. This ensures probing uses real credentials instead of
// requiring each record to independently carry auth info.
// Records are replaced in-place in the slice with new instances carrying auth headers.
func injectAuthHeaders(records []*httpmsg.HttpRequestResponse, authHeaders map[string]string) {
	if len(authHeaders) == 0 {
		return
	}

	injected := 0
	for i, rr := range records {
		if rr.Request() == nil {
			continue
		}

		// Skip records that already have auth headers
		hasAuth := false
		for _, h := range rr.Request().Headers() {
			if isAuthHeader(h.Name) {
				hasAuth = true
				break
			}
		}
		if hasAuth {
			continue
		}

		// Build a new request with auth headers added
		newReq := rr.Request()
		for k, v := range authHeaders {
			newReq = newReq.WithAddedHeader(k, v)
		}

		records[i] = httpmsg.NewHttpRequestResponse(newReq, rr.Response())
		injected++
	}

	if injected > 0 {
		zap.L().Info("Injected auth headers into source-discovered records",
			zap.Int("injected", injected), zap.Int("total", len(records)))
	}
}
