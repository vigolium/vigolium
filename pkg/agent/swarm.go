package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
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
	VulnType      string   // optional: focus on specific vulnerability type
	ModuleNames   []string // optional: explicit module IDs to use
	OnlyPhase     string   // isolate a single phase (empty = all phases)
	SkipPhases    []string // skip specific phases (empty = skip none)
	MaxIterations int      // max triage-rescan loops (default 3)

	// Agent
	AgentName          string
	AgentACPCmd        string // ad-hoc ACP command override (e.g. "traecli acp")
	DryRun             bool
	ShowPrompt         bool // print rendered prompts to stderr before executing
	SourceAnalysisOnly bool // run only source analysis phase and exit

	// Project/scan
	ProjectUUID string
	ScanUUID    string

	// Session directory base path for agent artifacts
	SessionsDir string

	// SessionDir is the pre-created session directory for this run.
	// When set, the swarm runner uses it directly instead of creating one.
	SessionDir string

	// ResumeDir is the session directory of a previous run to resume from.
	// When set, the swarm runner loads the checkpoint and skips completed phases.
	ResumeDir string

	// Streaming
	StreamWriter io.Writer

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
const (
	SwarmPhaseNormalize      = "normalize"
	SwarmPhaseSourceAnalysis = "source-analysis"
	SwarmPhaseSAST           = "sast"
	SwarmPhaseSASTReview     = "sast-review"
	SwarmPhaseDiscover       = "discover"
	SwarmPhasePlan           = "plan"
	SwarmPhaseExtension      = "extension"
	SwarmPhaseScan           = "scan"
	SwarmPhaseTriage         = "triage"
	SwarmPhaseRescan         = "rescan"
)

// Prompt template constants for the agent swarm mode.
const (
	SwarmPromptMaster         = "agent-swarm-master"
	SwarmPromptSourceAnalysis = "agent-swarm-source-analysis"
	SwarmPromptSASTReview     = "swarm-sast-review"
	SwarmPromptTriage         = "agent-swarm-triage"
)

// SwarmPhasePrompt returns the prompt template name for a given swarm phase, if any.
func SwarmPhasePrompt(phase string) string {
	switch phase {
	case SwarmPhaseSourceAnalysis:
		return SwarmPromptSourceAnalysis
	case SwarmPhaseSASTReview:
		return SwarmPromptSASTReview
	case SwarmPhasePlan:
		return SwarmPromptMaster
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

// Run executes the full agent swarm pipeline.
func (s *SwarmRunner) Run(ctx context.Context, cfg SwarmConfig) (*SwarmResult, error) {
	start := time.Now()

	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 3
	}
	// Create agent run record
	runUUID := "agt-" + uuid.New().String()
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
	if sessionDir != "" {
		fmt.Fprintf(os.Stderr, "◆ Session: %s\n", terminal.ShortenHome(sessionDir))
	}

	// Checkpoint/resume support
	var checkpoint *SwarmCheckpoint
	if cfg.ResumeDir != "" {
		cp, cpErr := loadCheckpoint(cfg.ResumeDir)
		if cpErr != nil {
			zap.L().Warn("Failed to load checkpoint, starting fresh", zap.Error(cpErr))
		} else {
			checkpoint = cp
			zap.L().Info("Resuming from checkpoint",
				zap.String("last_phase", cp.LastPhase),
				zap.Strings("completed", cp.CompletedPhases))
		}
	}

	// Phase 1: Normalize inputs
	phaseStart := time.Now()
	s.emitPhase(cfg, SwarmPhaseNormalize)
	agentRun.CurrentPhase = SwarmPhaseNormalize

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
	writeInputsToSessionDir(sessionDir, records)
	phaseTimings[SwarmPhaseNormalize] = time.Since(phaseStart)

	// Phase 1.5 + 1.6: Source analysis and SAST run in parallel when both are available.
	var sourceExtensions []GeneratedExtension
	if cfg.SourcePath != "" && !phaseCompleted(checkpoint, SwarmPhaseSourceAnalysis) {
		phaseStart = time.Now()
		agentRun.CurrentPhase = SwarmPhaseSourceAnalysis

		// Shared state for parallel results
		var mu sync.Mutex
		var saRecords []*httpmsg.HttpRequestResponse
		var saExtensions []GeneratedExtension
		var sastRecords []*httpmsg.HttpRequestResponse
		var sastExtensions []GeneratedExtension

		hasSAST := cfg.SASTFunc != nil
		var wg sync.WaitGroup

		// Goroutine 1: Source analysis
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.emitPhase(cfg, SwarmPhaseSourceAnalysis)

			saCfg := SourceAnalysisConfig{
				AgentName:      cfg.AgentName,
				AgentACPCmd:    cfg.AgentACPCmd,
				TargetURL:      targetURL,
				SourcePath:     cfg.SourcePath,
				Files:          cfg.Files,
				Instruction:    cfg.Instruction,
				PromptTemplate: SwarmPromptSourceAnalysis,
				DryRun:         cfg.DryRun,
				ShowPrompt:     cfg.ShowPrompt,
				ScanUUID:       cfg.ScanUUID,
				ProjectUUID:    cfg.ProjectUUID,
				StreamWriter:   cfg.StreamWriter,
			}

			saResult, saRawOutput, saRenderedPrompt, saErr := s.engine.RunSourceAnalysisParallel(ctx, saCfg)

			writePromptToSessionDir(sessionDir, "prompt-source-analysis.md", saRenderedPrompt)
			if sessionDir != "" && saRawOutput != "" {
				_ = os.WriteFile(filepath.Join(sessionDir, "source-analysis-output.md"), []byte(saRawOutput), 0644)
			}

			if saErr != nil {
				zap.L().Warn("Source analysis failed, continuing with input records only", zap.Error(saErr))
				return
			}
			if saResult == nil {
				return
			}

			filteredRecords := filterSourceRecordsByHostname(saResult.HTTPRecords, targetURL)

			mu.Lock()
			defer mu.Unlock()
			if len(filteredRecords) > 0 {
				zap.L().Info("Appending source-discovered routes",
					zap.Int("total_discovered", len(saResult.HTTPRecords)),
					zap.Int("hostname_matched", len(filteredRecords)))
				saRecords = filteredRecords
			}
			if len(saResult.Extensions) > 0 {
				saExtensions = append(saExtensions, saResult.Extensions...)
			}
			if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
				writeSessionConfigToDir(saResult.SessionConfig, sessionDir)
			}
			if cfg.SourceAnalysisCallback != nil {
				if cbErr := cfg.SourceAnalysisCallback(saResult); cbErr != nil {
					zap.L().Warn("Source analysis callback failed", zap.Error(cbErr))
				}
			}
		}()

		// Goroutine 2: SAST + SAST review (if available)
		if hasSAST {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.emitPhase(cfg, SwarmPhaseSAST)

				if sastErr := cfg.SASTFunc(ctx); sastErr != nil {
					zap.L().Warn("SAST phase failed, continuing without SAST results", zap.Error(sastErr))
					return
				}

				s.emitPhase(cfg, SwarmPhaseSASTReview)
				sastReviewResult := s.runSASTReview(ctx, cfg, targetURL, sessionDir)
				if sastReviewResult == nil {
					return
				}

				mu.Lock()
				defer mu.Unlock()
				if len(sastReviewResult.HTTPRecords) > 0 {
					validatedRecords := filterSourceRecordsByHostname(sastReviewResult.HTTPRecords, targetURL)
					if len(validatedRecords) > 0 {
						zap.L().Info("Appending SAST-review validated routes",
							zap.Int("validated", len(validatedRecords)))
						sastRecords = validatedRecords
					}
				}
				if len(sastReviewResult.Extensions) > 0 {
					sastExtensions = append(sastExtensions, sastReviewResult.Extensions...)
				}
			}()
		}

		wg.Wait()

		// Merge results from both goroutines
		records = append(records, saRecords...)
		records = append(records, sastRecords...)
		result.TotalRecords = len(records)
		sourceExtensions = append(sourceExtensions, saExtensions...)
		sourceExtensions = append(sourceExtensions, sastExtensions...)

		phaseTimings[SwarmPhaseSourceAnalysis] = time.Since(phaseStart)

		// Write checkpoint after source analysis
		_ = writeCheckpoint(sessionDir, &SwarmCheckpoint{
			CompletedPhases: []string{SwarmPhaseNormalize, SwarmPhaseSourceAnalysis},
			TargetURL:       targetURL,
			RecordCount:     len(records),
			LastPhase:       SwarmPhaseSourceAnalysis,
			Timestamp:       time.Now(),
		})
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
	}

	// Phase 2: Master agent — analyze and plan (batched if > 5 records)
	phaseStart = time.Now()
	var plan *SwarmPlan
	var sessionID string
	var masterRawOutput string
	var masterRenderedPrompt string
	var sessionIDs []string

	// Resume: restore plan from checkpoint if available
	if checkpoint != nil && phaseCompleted(checkpoint, SwarmPhasePlan) && checkpoint.Plan != nil {
		plan = checkpoint.Plan
		zap.L().Info("Restored plan from checkpoint",
			zap.Int("module_tags", len(plan.ModuleTags)))
	} else {
		s.emitPhase(cfg, SwarmPhasePlan)
		agentRun.CurrentPhase = SwarmPhasePlan

		const masterBatchSize = 5
		if len(records) <= masterBatchSize {
			plan, sessionID, masterRawOutput, masterRenderedPrompt, err = s.runMasterAgent(ctx, cfg, records, targetURL)
		} else {
			plan, sessionID, masterRawOutput, masterRenderedPrompt, sessionIDs, err = s.runMasterAgentBatched(ctx, cfg, records, targetURL, masterBatchSize)
		}

		// Save rendered prompt and raw output to session dir regardless of parse success
		writePromptToSessionDir(sessionDir, "prompt-master.md", masterRenderedPrompt)
		if sessionDir != "" && masterRawOutput != "" {
			_ = os.WriteFile(filepath.Join(sessionDir, "master-agent-output.md"), []byte(masterRawOutput), 0644)
		}

		if err != nil {
			return fmt.Errorf("master agent failed: %w", err)
		}
	}
	phaseTimings[SwarmPhasePlan] = time.Since(phaseStart)

	result.SessionID = sessionID
	result.SessionIDs = sessionIDs

	if cfg.DryRun {
		result.SwarmPlan = plan
		result.PhaseTimings = phaseTimings
		return nil
	}

	result.SwarmPlan = plan
	agentRun.SessionID = sessionID
	if plan != nil {
		planJSON, _ := json.Marshal(plan)
		agentRun.AttackPlan = string(planJSON)

		// Write plan to session dir for inspection
		if sessionDir != "" {
			_ = os.WriteFile(filepath.Join(sessionDir, "swarm-plan.json"), planJSON, 0644)
		}

		// Write checkpoint after planning
		_ = writeCheckpoint(sessionDir, &SwarmCheckpoint{
			CompletedPhases: []string{SwarmPhaseNormalize, SwarmPhaseSourceAnalysis, SwarmPhaseDiscover, SwarmPhasePlan},
			TargetURL:       targetURL,
			RecordCount:     len(records),
			Plan:            plan,
			LastPhase:       SwarmPhasePlan,
			Timestamp:       time.Now(),
		})
	}

	// Phase 3: Generate and write extensions (quick_checks + snippets + full extensions)
	// Merge source-analysis extensions with plan extensions by filename (plan wins on collision)
	phaseStart = time.Now()
	var allExtensions []GeneratedExtension
	if plan != nil {
		// Convert quick_checks and snippets into full JS extensions
		if len(plan.QuickChecks) > 0 {
			qcExts := GenerateQuickCheckExtensions(plan.QuickChecks)
			plan.Extensions = append(plan.Extensions, qcExts...)
			zap.L().Info("Generated quick check extensions", zap.Int("count", len(qcExts)))
		}
		if len(plan.Snippets) > 0 {
			snipExts := GenerateSnippetExtensions(plan.Snippets)
			plan.Extensions = append(plan.Extensions, snipExts...)
			zap.L().Info("Generated snippet extensions", zap.Int("count", len(snipExts)))
		}
		allExtensions = mergeExtensions(sourceExtensions, plan.Extensions)
	} else if len(sourceExtensions) > 0 {
		allExtensions = sourceExtensions
	}

	// Validate extension syntax before writing to disk
	if len(allExtensions) > 0 {
		allExtensions = ValidateExtensionSyntax(allExtensions)
	}

	var extensionDir string
	if len(allExtensions) > 0 {
		s.emitPhase(cfg, SwarmPhaseExtension)
		agentRun.CurrentPhase = SwarmPhaseExtension

		dir, writeErr := writeExtensionsToDir(allExtensions, sessionDir)
		if writeErr != nil {
			zap.L().Warn("Failed to write generated extensions", zap.Error(writeErr))
		} else {
			extensionDir = dir
		}
	}
	phaseTimings[SwarmPhaseExtension] = time.Since(phaseStart)

	// Phase 4: Execute scan (full scan with all modules by default)
	if cfg.ScanFunc != nil && !phaseCompleted(checkpoint, SwarmPhaseScan) {
		phaseStart = time.Now()
		s.emitPhase(cfg, SwarmPhaseScan)
		agentRun.CurrentPhase = SwarmPhaseScan

		if err := cfg.ScanFunc(ctx, ScanRequest{ExtensionDir: extensionDir}); err != nil {
			return fmt.Errorf("scan execution failed: %w", err)
		}
		phaseTimings[SwarmPhaseScan] = time.Since(phaseStart)

		// Write checkpoint after scan
		_ = writeCheckpoint(sessionDir, &SwarmCheckpoint{
			CompletedPhases: []string{SwarmPhaseNormalize, SwarmPhaseSourceAnalysis, SwarmPhaseDiscover, SwarmPhasePlan, SwarmPhaseExtension, SwarmPhaseScan},
			TargetURL:       targetURL,
			RecordCount:     len(records),
			Plan:            plan,
			ExtensionDir:    extensionDir,
			LastPhase:       SwarmPhaseScan,
			Timestamp:       time.Now(),
		})
	}

	// Phase 5-6: Triage loop
	phaseStart = time.Now()
	s.emitPhase(cfg, SwarmPhaseTriage)
	agentRun.CurrentPhase = SwarmPhaseTriage

	if err := s.runTriageLoop(ctx, cfg, agentRun, result, sessionDir, extensionDir); err != nil {
		zap.L().Warn("Triage failed, continuing with scan results", zap.Error(err))
	}
	phaseTimings[SwarmPhaseTriage] = time.Since(phaseStart)

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
	zap.L().Info("Agent swarm phase started", zap.String("phase", phase))
}

// phaseCompleted returns true if the given phase is in the checkpoint's completed list.
func phaseCompleted(cp *SwarmCheckpoint, phase string) bool {
	if cp == nil {
		return false
	}
	for _, p := range cp.CompletedPhases {
		if p == phase {
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

func (s *SwarmRunner) runMasterAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string) (plan *SwarmPlan, sessionID string, rawOutput string, renderedPrompt string, err error) {
	// Build request context for the prompt
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
			respRaw := string(rr.Response().Raw())
			if len(respRaw) > 4096 {
				respRaw = respRaw[:4096] + "\n... (truncated)"
			}
			rc.WriteString("\n```http\n")
			rc.WriteString(respRaw)
			rc.WriteString("\n```\n")
		}
	}
	requestContext := rc.String()

	hostname := ""
	if targetURL != "" {
		hostname = hostnameFromURL(targetURL)
	}

	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: SwarmPromptMaster,
		TargetURL:      targetURL,
		Hostname:       hostname,
		Instruction:    cfg.Instruction,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		SessionWeight:  3, // master agent sessions are high-priority for pool eviction
	}

	// Pass request context and vuln type as extra template data
	opts.Append = ""
	if cfg.VulnType != "" {
		opts.Append = fmt.Sprintf("## Vulnerability Focus\n\n%s", cfg.VulnType)
	}

	// We need to pass the request context to the template.
	// Use the engine's context enrichment, but also inject our request context.
	// The template uses {{.Extra.RequestContext}} and {{.Extra.VulnType}}.

	// Retry loop: LLMs sometimes produce garbled JSON (especially with embedded
	// JavaScript code in JSON strings). Retry up to 2 additional times on parse failure.
	const maxAttempts = 3
	var lastSessionID string
	var lastRawOutput string
	var lastRenderedPrompt string
	var lastParseErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// On retry, use a truncated method+URL summary instead of the full raw
		// HTTP context to reduce token cost and avoid repeating verbose payloads.
		extraContext := requestContext
		if attempt > 1 {
			zap.L().Info("retrying master agent (previous output was unparseable)",
				zap.Int("attempt", attempt),
				zap.Error(lastParseErr))
			opts.Append = buildRetryFeedback(cfg.VulnType, lastParseErr, lastRawOutput)
			extraContext = retryTruncateContext(records)
		}

		result, runErr := s.engine.RunWithExtra(ctx, opts, map[string]string{
			"RequestContext": extraContext,
			"VulnType":       cfg.VulnType,
		})
		if runErr != nil {
			return nil, "", "", "", fmt.Errorf("master agent execution failed: %w", runErr)
		}

		lastSessionID = result.SessionID
		lastRawOutput = result.RawOutput
		lastRenderedPrompt = result.RenderedPrompt

		if cfg.DryRun {
			return nil, result.SessionID, result.RawOutput, result.RenderedPrompt, nil
		}

		parsed, parseErr := ParseSwarmPlan(result.RawOutput)
		if parseErr != nil {
			zap.L().Debug("master agent raw output (parse failed)",
				zap.String("output", result.RawOutput),
				zap.Int("attempt", attempt))
			lastParseErr = parseErr
			continue
		}

		return parsed, result.SessionID, result.RawOutput, result.RenderedPrompt, nil
	}

	return nil, lastSessionID, lastRawOutput, lastRenderedPrompt, fmt.Errorf("failed to parse swarm plan after %d attempts: %w", maxAttempts, lastParseErr)
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

// buildRetryFeedback constructs an error-feedback appendix for retry attempts,
// telling the agent what went wrong and reminding it of the expected format.
func buildRetryFeedback(vulnType string, parseErr error, rawOutput string) string {
	var sb strings.Builder
	if vulnType != "" {
		fmt.Fprintf(&sb, "## Vulnerability Focus\n\n%s\n\n", vulnType)
	}
	sb.WriteString("## CRITICAL: Your previous output contained broken JSON\n\n")
	fmt.Fprintf(&sb, "Parse error: %s\n\n", parseErr.Error())

	// Show a snippet of the broken output so the agent can see the corruption
	if rawOutput != "" {
		snippet := rawOutput
		if len(snippet) > 500 {
			snippet = snippet[:500] + "..."
		}
		fmt.Fprintf(&sb, "Your previous output (truncated):\n```\n%s\n```\n\n", snippet)
	}

	sb.WriteString("You MUST use the markdown section format. Requirements:\n")
	sb.WriteString("1. Use `## MODULE_TAGS` heading followed by a comma-separated list of tags on the next line.\n")
	sb.WriteString("2. Use `## FOCUS_AREAS` heading followed by a bulleted list.\n")
	sb.WriteString("3. Use `## NOTES` heading followed by free-text notes.\n")
	sb.WriteString("4. For extensions, use `#### filename.js` heading followed by a fenced ```javascript code block.\n")
	sb.WriteString("5. Do NOT output a raw JSON blob. Use markdown sections.\n")
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

// writeInputsToSessionDir saves the normalized input records as JSON to the session directory.
func writeInputsToSessionDir(sessionDir string, records []*httpmsg.HttpRequestResponse) {
	if sessionDir == "" || len(records) == 0 {
		return
	}
	type inputRecord struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers,omitempty"`
		Body    string            `json:"body,omitempty"`
	}
	var inputs []inputRecord
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
		inputs = append(inputs, ir)
	}
	data, err := json.MarshalIndent(inputs, "", "  ")
	if err != nil {
		zap.L().Warn("Failed to marshal inputs", zap.Error(err))
		return
	}
	path := filepath.Join(sessionDir, "inputs.json")
	if writeErr := os.WriteFile(path, data, 0644); writeErr != nil {
		zap.L().Warn("Failed to write inputs to session dir", zap.Error(writeErr))
		return
	}
	zap.L().Debug("Inputs written to session dir", zap.String("path", path), zap.Int("count", len(inputs)))
}

// mergeExtensions combines source-analysis and plan extensions by filename.
// On collision with identical code, the duplicate is dropped.
// On collision with different code, the plan extension is renamed with a -2, -3 suffix.
func mergeExtensions(source, plan []GeneratedExtension) []GeneratedExtension {
	if len(source) == 0 {
		return plan
	}
	if len(plan) == 0 {
		return source
	}

	existing := make(map[string]string, len(source)) // filename -> code
	result := make([]GeneratedExtension, 0, len(source)+len(plan))

	// Source extensions first
	for _, ext := range source {
		existing[ext.Filename] = ext.Code
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
			nameSet := make(map[string]bool, len(existing))
			for k := range existing {
				nameSet[k] = true
			}
			ext.Filename = deduplicateExtensionFilename(ext.Filename, nameSet)
			zap.L().Info("Renamed colliding extension",
				zap.String("new_filename", ext.Filename))
		}
		existing[ext.Filename] = ext.Code
		result = append(result, ext)
	}

	return result
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
func filterSourceRecordsByHostname(agentRecords []AgentHTTPRecord, targetURL string) []*httpmsg.HttpRequestResponse {
	if targetURL == "" {
		return nil
	}
	targetParsed, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	targetHost := targetParsed.Host // includes port

	var filtered []*httpmsg.HttpRequestResponse
	for _, rec := range agentRecords {
		// For relative URLs, resolve against the target URL
		recURL := rec.URL
		if !strings.HasPrefix(recURL, "http://") && !strings.HasPrefix(recURL, "https://") {
			recURL = strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(recURL, "/")
		}

		recParsed, parseErr := url.Parse(recURL)
		if parseErr != nil {
			continue
		}
		if recParsed.Host != targetHost {
			continue
		}

		// Rewrite the record URL to be fully qualified
		rec.URL = recURL
		rr, convertErr := ToHTTPRequestResponse(rec)
		if convertErr != nil {
			zap.L().Debug("Skipping source record", zap.String("url", rec.URL), zap.Error(convertErr))
			continue
		}
		filtered = append(filtered, rr)
	}
	return filtered
}

// runMasterAgentBatched calls the master agent in parallel batches when there are many records.
// Each batch produces a SwarmPlan; plans are merged by deduplicating tags, IDs, and extensions.
func (s *SwarmRunner) runMasterAgentBatched(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, batchSize int) (*SwarmPlan, string, string, string, []string, error) {
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
	}

	results := make([]batchResult, len(batches))

	// Run batches in parallel with bounded concurrency
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(3)

	for idx, b := range batches {
		idx, b := idx, b
		g.Go(func() error {
			zap.L().Info("Running master agent batch",
				zap.Int("batch", b.num),
				zap.Int("batch_start", b.start),
				zap.Int("batch_end", b.end),
				zap.Int("total_records", len(records)))

			batch := records[b.start:b.end]
			plan, sid, rawOutput, prompt, err := s.runMasterAgent(gCtx, cfg, batch, targetURL)
			if err != nil {
				return fmt.Errorf("master agent batch %d-%d failed: %w", b.start, b.end, err)
			}
			results[idx] = batchResult{
				plan:      plan,
				sessionID: sid,
				rawOutput: rawOutput,
				prompt:    prompt,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		// Return partial results for the last session ID
		var lastSID string
		for _, r := range results {
			if r.sessionID != "" {
				lastSID = r.sessionID
			}
		}
		return nil, lastSID, "", "", nil, err
	}

	// Collect results
	var plans []*SwarmPlan
	var lastSessionID string
	var allSessionIDs []string
	var allRawOutputs []string
	var allRenderedPrompts []string

	for _, r := range results {
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

	if len(plans) == 0 {
		return nil, lastSessionID, combinedRaw, lastPrompt, allSessionIDs, nil
	}
	if len(plans) == 1 {
		return plans[0], lastSessionID, combinedRaw, lastPrompt, allSessionIDs, nil
	}

	merged := mergeSwarmPlans(plans)
	return merged, lastSessionID, combinedRaw, lastPrompt, allSessionIDs, nil
}

// mergeSwarmPlans combines multiple SwarmPlans by deduplicating module tags,
// module IDs, extensions (by filename, last wins), and focus areas.
func mergeSwarmPlans(plans []*SwarmPlan) *SwarmPlan {
	tagSet := make(map[string]bool)
	idSet := make(map[string]bool)
	focusSet := make(map[string]bool)
	extMap := make(map[string]GeneratedExtension)
	qcMap := make(map[string]QuickCheck)
	snipMap := make(map[string]Snippet)
	var notes []string

	for batchIdx, p := range plans {
		for _, t := range p.ModuleTags {
			tagSet[t] = true
		}
		for _, id := range p.ModuleIDs {
			idSet[id] = true
		}
		for _, fa := range p.FocusAreas {
			focusSet[fa] = true
		}
		for _, ext := range p.Extensions {
			if existingExt, collision := extMap[ext.Filename]; collision && existingExt.Code != ext.Code {
				// Rename on collision with different code
				nameSet := make(map[string]bool, len(extMap))
				for k := range extMap {
					nameSet[k] = true
				}
				ext.Filename = deduplicateExtensionFilename(ext.Filename, nameSet)
				zap.L().Info("Renamed colliding batch extension",
					zap.String("new_filename", ext.Filename),
					zap.Int("batch", batchIdx+1))
			}
			extMap[ext.Filename] = ext
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
	return merged
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

func (s *SwarmRunner) runTriageLoop(ctx context.Context, cfg SwarmConfig, agentRun *database.AgentRun, result *SwarmResult, sessionDir string, extensionDir string) error {
	triageCfg := TriageLoopConfig{
		Engine:         s.engine,
		Repository:     s.repo,
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: SwarmPromptTriage,
		TargetURL:      agentRun.TargetURL,
		Hostname:       hostnameFromURL(agentRun.TargetURL),
		Instruction:    cfg.Instruction,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		MaxRounds:      cfg.MaxIterations,
		ScanFunc:       cfg.ScanFunc,
		SessionDir:     sessionDir,
		ExtensionDir:   extensionDir,
		OnRescan: func() {
			s.emitPhase(cfg, SwarmPhaseRescan)
			agentRun.CurrentPhase = SwarmPhaseRescan
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

	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: SwarmPromptSASTReview,
		TargetURL:      targetURL,
		Hostname:       hostname,
		Instruction:    cfg.Instruction,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
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

	// Save prompt and output to session dir
	writePromptToSessionDir(sessionDir, "prompt-sast-review.md", agentResult.RenderedPrompt)
	if sessionDir != "" && agentResult.RawOutput != "" {
		_ = os.WriteFile(filepath.Join(sessionDir, "sast-review-output.md"), []byte(agentResult.RawOutput), 0644)
	}

	if cfg.DryRun {
		return nil
	}

	// Parse as SourceAnalysisResult (validated routes + optional extensions)
	saResult, parseErr := ParseSourceAnalysisResult(agentResult.RawOutput)
	if parseErr != nil {
		zap.L().Warn("Failed to parse SAST review result", zap.Error(parseErr))
		return nil
	}

	zap.L().Info("SAST review completed",
		zap.Int("validated_routes", len(saResult.HTTPRecords)),
		zap.Int("extensions", len(saResult.Extensions)))

	return saResult
}
