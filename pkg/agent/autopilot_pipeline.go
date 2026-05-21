package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/audit"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/olium"
	oautopilot "github.com/vigolium/vigolium/pkg/olium/autopilot"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// Prompt formatting thresholds and limits.
const (
	findingsTierFullDetail   = 15   // ≤ this count: full detail per finding
	findingsTierSummaryTable = 40   // ≤ this count: table + critical/high detail; above: table + top N
	findingsTopNDetail       = 10   // number of findings shown in full detail for large sets
	maxBodyExcerptChars      = 500  // max chars from finding body in full-detail view
	maxTitleChars            = 47   // max title length in summary table
	maxKnowledgeBaseChars    = 4000 // max chars of knowledge base included in prompt
)

// AutopilotPipelineConfig configures the autopilot pipeline.
type AutopilotPipelineConfig struct {
	TargetURL   string
	SourcePath  string
	Files       []string
	Instruction string
	Focus       string

	// SystemPrompt, when non-empty, fully replaces the built-in autopilot
	// system prompt at the olium runtime layer. Empty falls back to
	// agent.olium.system_prompt in settings, then to the embedded persona.
	SystemPrompt string

	AgentName   string
	MaxCommands int

	DryRun     bool
	ShowPrompt bool

	// Triage, when true, runs an AI triage pass over the findings after the
	// operator loop completes — classifying each as confirmed (→ "triaged")
	// or "false_positive" and writing the verdict back, scoped to this run.
	// Pure classification: no native rescan.
	Triage bool

	SessionsDir string
	SessionDir  string

	ProjectUUID           string
	ScanUUID              string
	ParentAgenticScanUUID string

	StreamWriter     io.Writer
	ProgressCallback func(phase string, message string)

	// Audit is the audit-cfg slot — backed by either audit or piolium per
	// AuditHarness. Field name is legacy; the runtime is harness-agnostic.
	Audit *config.AuditAgentConfig

	// AuditHarness selects which harness backs the Audit cfg. Zero-valued
	// defaults to audit for backward compat.
	AuditHarness HarnessSpec

	// BrowserEnabled indicates whether agent-browser is available for the agent.
	BrowserEnabled bool
	// BrowserRequested preserves explicit user intent even when heuristics are weak.
	BrowserRequested bool
	// RequiresBrowser means auth/setup should prefer browser assistance over HTTP-only preparation.
	RequiresBrowser bool
	// Credentials carries compact credentials extracted from the prompt or flag input.
	Credentials string
	// CredentialSets carries structured role/account pairs extracted from prompt input.
	CredentialSets []agenttypes.IntentCredentialSet
	// AuthRequired means auth should be prepared before operator launch.
	AuthRequired bool
	// BrowserStartURL is an explicit login/start URL for browser-based flows.
	BrowserStartURL string
	// FocusRoutes are protected or browser-focused routes named by the user.
	FocusRoutes []string
	// SessionConfig is the prepared session config for authenticated scanning.
	SessionConfig *AgentSessionConfig
	// AuthHeaders are hydrated headers ready for immediate use.
	AuthHeaders map[string]string
	// PreparedAuth summarizes the auth preparation outcome.
	PreparedAuth *AutopilotPreparedAuth

	// DiffContext holds parsed diff information for focused scanning.
	// When set, the agent prompt includes changed file list and patch content.
	DiffContext *agenttypes.DiffContext

	ContextBundle *AutopilotContextBundle
	Plan          *AutopilotExecutionPlan
	Artifacts     AutopilotArtifactSpec
}

// AutopilotPipelineRunner orchestrates the autopilot pipeline.
type AutopilotPipelineRunner struct {
	engine *Engine
	repo   *database.Repository
}

// NewAutopilotPipelineRunner creates a new autopilot pipeline runner.
func NewAutopilotPipelineRunner(engine *Engine, repo *database.Repository) *AutopilotPipelineRunner {
	return &AutopilotPipelineRunner{engine: engine, repo: repo}
}

type auditContextStruct struct {
	Findings      []*audit.Finding
	KnowledgeBase string
}

// RunAutonomous executes the autopilot pipeline:
// 1. Run vigolium-audit first when source context is available
// 2. Freeze context into native plan + artifacts
// 3. Launch the autonomous operator agent with full tool access
func (r *AutopilotPipelineRunner) RunAutonomous(ctx context.Context, cfg AutopilotPipelineConfig) (*AutopilotPipelineResult, error) {
	start := time.Now()

	if err := r.engine.Preflight(cfg.AgentName); err != nil {
		// The olium provider drives both the audit operator and the
		// autonomous operator. When its preflight fails (offline local
		// model, bad creds, network black hole) the AI loop can't run —
		// but the native scanner needs no AI. Degrade to a deterministic
		// blackbox scan when a target is available instead of aborting.
		return r.runBlackboxFallback(ctx, cfg, start, err)
	}

	// Auto-create session directory when not provided (e.g. API path)
	if cfg.SessionDir == "" && cfg.SessionsDir != "" {
		agenticScanUUID := uuid.New().String()
		sessionDir, sdErr := EnsureSessionDir(cfg.SessionsDir, agenticScanUUID)
		if sdErr != nil {
			zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
		} else {
			cfg.SessionDir = sessionDir
		}
	}

	// Seed on-disk SKILL.md files so the operator agent can read them via
	// filesystem tools. Mirrors the swarm pipeline. Browser SKILL is only
	// dropped when the browser is actually available to the agent.
	if cfg.SessionDir != "" {
		CopySkillsToSessionDir(cfg.SessionDir, cfg.BrowserEnabled || cfg.BrowserRequested)
	}

	result := &AutopilotPipelineResult{
		SessionDir: cfg.SessionDir,
	}

	spec, artifactErr := prepareAutopilotArtifacts(cfg.SessionDir)
	if artifactErr != nil {
		zap.L().Warn("Failed to prepare autopilot artifact directories", zap.Error(artifactErr))
		result.Warnings = append(result.Warnings, "failed to prepare some artifact directories")
	}
	cfg.Artifacts = spec
	result.ArtifactsDir = filepath.Dir(spec.BriefPath)

	// Mock mode: write sample audit-state.json and return immediately.
	// No subprocess is launched, no main agent runs.
	if cfg.Audit != nil && cfg.Audit.EffectiveMode() == "mock" {
		return r.runMockMode(cfg, result, start)
	}

	// Step 1: Run audit first and freeze its output before starting the operator agent.
	auditStatus := "skipped"
	if cfg.Audit != nil && cfg.Audit.IsEnabled() && cfg.SourcePath != "" {
		printPhaseHeader(agenttypes.AutopilotPhaseAudit, "comprehensive security audits on repository and focusing on uncovering exploitable vulnerabilities with high accuracy")
	}
	auditLogFn := func(msg string) { printPhaseLine(agenttypes.AutopilotPhaseAudit, msg) }
	auditRunner, auditWait, auditErr := startAuditAgentBackground(ctx, cfg.Audit, cfg.AuditHarness, cfg.SourcePath, cfg.SessionDir, cfg.ProjectUUID, cfg.ScanUUID, cfg.ParentAgenticScanUUID, r.repo, cfg.StreamWriter, auditLogFn)
	var auditCtx *auditContextStruct
	if auditErr != nil {
		result.Degraded = true
		result.Warnings = append(result.Warnings, fmt.Sprintf("audit failed to start, continuing without source audit context: %v", auditErr))
		auditStatus = "failed_to_start"
	}
	if auditRunner != nil {
		auditStatus = "completed"
		auditLogFn("running audit before operator startup")
		emitProgress(&cfg, "audit", "running audit before autonomous execution")
		if auditWait != nil {
			auditWait()
		}
		auditCtx = loadAuditDriverContext(cfg.SessionDir, cfg.AuditHarness)
		if auditCtx != nil && len(auditCtx.Findings) > 0 {
			result.FindingsCount = len(auditCtx.Findings)
			auditLogFn(fmt.Sprintf("loaded %d frozen findings", len(auditCtx.Findings)))
		}
	}

	if auditRunner != nil && cfg.SessionDir != "" {
		var stats FindingStats
		stats = auditRunner.FindingStats()
		if r.repo != nil {
			fallback := r.importFindings(cfg.SessionDir, cfg.ProjectUUID, cfg.ScanUUID, cfg.AuditHarness)
			stats = mergeFindingStats(stats, fallback)
		}
		if stats.Parsed > 0 {
			result.FindingsCount = stats.Parsed
			result.FindingsSaved = stats.Saved
			result.FindingsBySeverity = stats.BySeverity
		}
	}

	preparedAuth, authWarnings := r.prepareAutopilotAuth(ctx, &cfg)
	if preparedAuth != nil {
		cfg.PreparedAuth = preparedAuth
	}
	if len(authWarnings) > 0 {
		result.Warnings = append(result.Warnings, authWarnings...)
	}

	bundle := buildAutopilotContextBundle(cfg, auditCtx, auditStatus, result.Warnings)
	cfg.ContextBundle = &bundle
	if cfg.BrowserEnabled {
		if cfg.BrowserRequested || cfg.RequiresBrowser {
			cfg.BrowserEnabled = true
		} else {
			cfg.BrowserEnabled = bundle.BrowserDecision == "browser_required" || bundle.BrowserDecision == "browser_recommended"
		}
	}
	plan := buildAutopilotPlan(cfg, bundle, spec)
	cfg.Plan = &plan
	result.BrowserDecision = bundle.BrowserDecision
	writePreparedAuthArtifacts(spec, bundle, plan, cfg.PreparedAuth, cfg.AuthHeaders, cfg.SessionConfig)

	// Step 2: Build prompt from frozen context and plan.
	prompt := buildAutonomousPrompt(cfg, auditCtx, false)
	if err := writeAutopilotArtifacts(spec, bundle, plan, prompt); err != nil {
		zap.L().Warn("Failed to write autopilot context artifacts", zap.Error(err))
		result.Warnings = append(result.Warnings, "failed to write some autopilot context artifacts")
	}

	// Dry-run short-circuit: artifacts have been written, no agent dispatch.
	if cfg.DryRun {
		result.Duration = time.Since(start)
		return result, nil
	}

	printPhaseHeader(agenttypes.AutopilotPhaseAutopilot, "autonomous agent that executes against the prepared whitebox context and native plan")
	printPhaseLine(agenttypes.AutopilotPhaseAutopilot, "starting autonomous agent session")
	emitProgress(&cfg, "autopilot", "starting autonomous agent session")

	// Wrap stream writer with progress tracking
	streamWriter := cfg.StreamWriter
	if cfg.ProgressCallback != nil && streamWriter != nil {
		streamWriter = &progressWriter{
			inner:    streamWriter,
			callback: cfg.ProgressCallback,
			phase:    "autopilot",
			interval: 10 * 1024, // emit progress every 10KB
		}
	}

	// Resolve the olium provider from config so the autonomous operator
	// runs the same in-process agent loop the CLI uses. The pipeline's
	// pre-assembled prompt (audit findings + attack plan + auth notes)
	// becomes the agent's first user turn via InitialPrompt.
	var oliumCfg config.OliumConfig
	if r.engine != nil && r.engine.settings != nil {
		oliumCfg = r.engine.settings.Agent.Olium
	}
	prov, _, model, provErr := olium.ResolveProvider(olium.Options{
		Provider:            oliumCfg.Provider,
		OAuthCredPath:       oliumCfg.OAuthCredPath,
		OAuthToken:          oliumCfg.OAuthToken,
		LLMAPIKey:           oliumCfg.LLMAPIKey,
		GoogleCloudProject:  oliumCfg.GoogleCloudProject,
		GoogleCloudLocation: oliumCfg.GoogleCloudLocation,
		Model:               oliumCfg.Model,
		ReasoningEffort:     oliumCfg.ReasoningEffort,
		CustomBaseURL:       oliumCfg.CustomProvider.BaseURL,
		CustomModelID:       oliumCfg.CustomProvider.ModelID,
		CustomAPIKey:        firstNonEmpty(oliumCfg.CustomProvider.APIKey, oliumCfg.LLMAPIKey),
		CustomExtraHeaders:  oliumCfg.CustomProvider.ExtraHeaders,
	})
	if provErr != nil {
		return nil, fmt.Errorf("autonomous agent: resolve olium provider: %w", provErr)
	}
	// Same gate as the CLI path — autopilot bypasses runOliumOnEngine so
	// we wrap the provider explicitly here.
	prov = WrapProviderWithSemaphore(&oliumCfg, prov)

	autopilotResult, err := oautopilot.Run(ctx, oautopilot.Options{
		Provider:         prov,
		Model:            model,
		Target:           cfg.TargetURL,
		SourcePath:       cfg.SourcePath,
		Focus:            cfg.Focus,
		Instruction:      cfg.Instruction,
		ProjectUUID:      cfg.ProjectUUID,
		ScanUUID:         cfg.ScanUUID,
		AgenticScanUUID:  cfg.ParentAgenticScanUUID,
		Repo:             r.repo,
		SessionDir:       cfg.SessionDir,
		MaxTurns:         cfg.MaxCommands,
		Out:              streamWriter,
		ToolLog:          streamWriter,
		SystemPrompt:     firstNonEmpty(cfg.SystemPrompt, oliumCfg.SystemPrompt),
		InitialPrompt:    prompt,
		BrowserAvailable: cfg.BrowserEnabled,
	})
	if err != nil {
		return nil, fmt.Errorf("autonomous agent failed: %w", err)
	}
	if autopilotResult != nil {
		result.OperatorFindingsCount = int(autopilotResult.FindingCount)
	}

	if auditRunner != nil {
		if status := auditRunner.Status(); status != nil {
			auditLogFn(fmt.Sprintf("%d/%d phases completed (status: %s)",
				status.CompletedPhases, status.TotalPhases, status.Status))
		}
	}

	verification := verifyAutopilotArtifacts(spec)
	result.VerifiedFindingCount = verification.ConfirmedCount
	result.Warnings = append(result.Warnings, verification.Warnings...)
	if len(result.Warnings) > 0 {
		result.Degraded = true
	}

	// Optional post-scan triage: classify findings as confirmed vs false
	// positive and write the verdict back. Non-fatal — a triage failure
	// must not fail an otherwise-completed scan.
	if cfg.Triage {
		emitProgress(&cfg, "triage", "triaging findings")
		if _, terr := RunAutopilotTriage(ctx, r.engine, r.repo, AutopilotTriageParams{
			TargetURL:       cfg.TargetURL,
			SourcePath:      cfg.SourcePath,
			ScanUUID:        cfg.ScanUUID,
			ProjectUUID:     cfg.ProjectUUID,
			AgenticScanUUID: cfg.ParentAgenticScanUUID,
			SessionDir:      cfg.SessionDir,
			StreamWriter:    cfg.StreamWriter,
		}); terr != nil {
			zap.L().Warn("Autopilot triage pass failed (scan results unaffected)", zap.Error(terr))
			result.Warnings = append(result.Warnings, "triage pass failed: "+terr.Error())
		}
	}

	emitProgress(&cfg, "autopilot", "autonomous session completed")
	result.Duration = time.Since(start)
	return result, nil
}

// runBlackboxFallback degrades a failed-preflight autopilot run to a
// deterministic native scan. The audit step (audit/piolium) and the
// autonomous operator both need the olium provider; when its preflight
// fails there is no AI loop to run, but the native scanner doesn't need
// AI — so a target-bearing run can still produce findings. Source-only
// runs have nothing to scan and surface the original preflight error so
// the operator knows credentials/connectivity must be fixed.
func (r *AutopilotPipelineRunner) runBlackboxFallback(
	ctx context.Context,
	cfg AutopilotPipelineConfig,
	start time.Time,
	preflightErr error,
) (*AutopilotPipelineResult, error) {
	target := strings.TrimSpace(cfg.TargetURL)
	if target == "" {
		return nil, fmt.Errorf("autopilot preflight failed and no target is available for a native fallback scan: %w", preflightErr)
	}

	warn := fmt.Sprintf("AI provider preflight failed (%v) — running a native blackbox scan instead (no AI audit or operator)", preflightErr)
	zap.L().Warn("Autopilot preflight failed; degrading to native blackbox scan",
		zap.String("target", target), zap.Error(preflightErr))
	printPhaseHeader(agenttypes.AutopilotPhaseAutopilot, "AI provider unreachable — native blackbox fallback scan")
	printPhaseLine(agenttypes.AutopilotPhaseAutopilot, warn)
	if cfg.StreamWriter != nil {
		_, _ = fmt.Fprintf(cfg.StreamWriter, "[autopilot] %s\n", warn)
	}
	emitProgress(&cfg, "autopilot", "preflight failed — running native blackbox scan")

	result := &AutopilotPipelineResult{
		SessionDir: cfg.SessionDir,
		Degraded:   true,
		Warnings:   []string{warn},
	}

	res, scanErr := runner.LaunchScan(ctx, runner.LaunchParams{
		Targets:          []string{target},
		ProjectUUID:      cfg.ProjectUUID,
		Repository:       r.repo,
		ScanningStrategy: agenttypes.ScanStrategyBalanced,
		EnableDiscovery:  true,
		EnableSpidering:  true,
	})
	result.Duration = time.Since(start)
	if scanErr != nil {
		result.Warnings = append(result.Warnings, "native fallback scan failed: "+scanErr.Error())
		return result, fmt.Errorf("autopilot preflight failed and the native fallback scan also failed (%v): %w", preflightErr, scanErr)
	}
	if res != nil {
		result.OperatorFindingsCount = int(res.FindingCount)
		printPhaseLine(agenttypes.AutopilotPhaseAutopilot, fmt.Sprintf(
			"native blackbox scan complete  scan=%s requests=%d findings=%d",
			res.ScanUUID, res.TotalRequests, res.FindingCount))
	}
	return result, nil
}

// importFindings parses audit output from the session directory's
// harness subdir and saves findings to the database. Uses context.Background()
// to avoid issues with parent context cancellation. The harness drives both
// the source folder and the finding-source tagging (audit vs piolium).
func (r *AutopilotPipelineRunner) importFindings(sessionDir, projectUUID, scanUUID string, harness HarnessSpec) FindingStats {
	if harness.Name == "" {
		harness = DefaultAuditHarness()
	}
	auditDir := filepath.Join(sessionDir, harness.SessionSubdir)

	result, err := audit.ParseFolder(auditDir)
	if err != nil {
		zap.L().Debug("Audit import: no findings to import", zap.String("harness", harness.Name), zap.Error(err))
		return FindingStats{}
	}

	auditID := ""
	if len(result.State.Audits) > 0 {
		auditID = result.State.Audits[0].AuditID
	}

	findings := audit.BuildFindingsWithSource(result.RawFindings, auditID, "", projectUUID, result.RepoName, harnessFindingSource(harness))

	stats := FindingStats{
		Parsed:     len(findings),
		BySeverity: make(map[string]int, len(findings)),
	}
	for _, f := range findings {
		stats.BySeverity[f.Severity]++
	}

	// Detached from the parent ctx so a user Ctrl+C between audit
	// completion and finding persistence doesn't drop already-extracted
	// findings. Bounded by a soft deadline so a hung DB can't outlive the
	// rest of the run; 30s is generous for a few dozen inserts on SQLite
	// and PostgreSQL alike.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, f := range findings {
		f.ScanUUID = scanUUID
		if err := r.repo.SaveFindingDirect(ctx, f); err != nil {
			zap.L().Debug("Audit import: failed to save finding",
				zap.String("module_id", f.ModuleID), zap.Error(err))
			continue
		}
		if f.ID > 0 {
			stats.Saved++
		}
	}

	if stats.Saved > 0 {
		zap.L().Info("Imported audit findings",
			zap.Int("parsed", stats.Parsed),
			zap.Int("saved", stats.Saved))
	}

	return stats
}

// mergeFindingStats combines two FindingStats sources, picking the larger
// Parsed/Saved counts and unioning BySeverity (max per bucket). Used when the
// autopilot runner's in-monitor import and the pipeline's fallback re-import
// each see a partial view of the findings set.
func mergeFindingStats(a, b FindingStats) FindingStats {
	out := FindingStats{
		Parsed:     a.Parsed,
		Saved:      a.Saved,
		BySeverity: map[string]int{},
	}
	for k, v := range a.BySeverity {
		out.BySeverity[k] = v
	}
	if b.Parsed > out.Parsed {
		out.Parsed = b.Parsed
	}
	if b.Saved > out.Saved {
		out.Saved = b.Saved
	}
	for k, v := range b.BySeverity {
		if v > out.BySeverity[k] {
			out.BySeverity[k] = v
		}
	}
	return out
}

// runMockMode writes a sample audit-state.json with a mock finding and returns
// immediately. No subprocess is launched and no main agent runs.
func (r *AutopilotPipelineRunner) runMockMode(cfg AutopilotPipelineConfig, result *AutopilotPipelineResult, start time.Time) (*AutopilotPipelineResult, error) {
	printPhaseLine("mock", "writing sample audit-state.json (no agent launched)")

	auditDirLocal := filepath.Join(cfg.SessionDir, "vigolium-results")
	if err := os.MkdirAll(auditDirLocal, 0o755); err != nil {
		return nil, fmt.Errorf("mock: failed to create vigolium-audit dir: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Resolve git metadata from source path (best-effort)
	commit, branch, repository := resolveGitMeta(cfg.SourcePath)

	mockState := map[string]interface{}{
		"audits": []map[string]interface{}{
			{
				"audit_id":     now,
				"commit":       commit,
				"branch":       branch,
				"repository":   repository,
				"mode":         "mock",
				"model":        "none",
				"agent_sdk":    "none",
				"started_at":   now,
				"completed_at": now,
				"status":       "complete",
				"phases": map[string]interface{}{
					"mock": map[string]interface{}{
						"status":       "complete",
						"completed_at": now,
						"summary":      "Mock mode — sample output, no agent executed",
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(mockState, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("mock: failed to marshal audit-state: %w", err)
	}

	statePath := filepath.Join(auditDirLocal, "audit-state.json")
	if err := os.WriteFile(statePath, data, 0o644); err != nil {
		return nil, fmt.Errorf("mock: failed to write audit-state.json: %w", err)
	}

	printPhaseLine("mock", "sample audit-state.json written to "+statePath)
	result.Duration = time.Since(start)
	return result, nil
}

// resolveGitMeta extracts commit SHA, branch, and repository name from a source
// directory. Returns empty strings on failure (best-effort).
func resolveGitMeta(sourceDir string) (commit, branch, repository string) {
	if sourceDir == "" {
		return "", "", ""
	}
	run := func(args ...string) string {
		cmd := exec.CommandContext(context.Background(), "git", args...)
		cmd.Dir = sourceDir
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	commit = run("rev-parse", "HEAD")
	branch = run("branch", "--show-current")

	remote := run("remote", "get-url", "origin")
	if remote != "" {
		// Extract org/repo from URL: strip scheme+host or git@ prefix, drop .git suffix
		repo := remote
		if idx := strings.Index(repo, "://"); idx >= 0 {
			repo = repo[idx+3:]
			if si := strings.Index(repo, "/"); si >= 0 {
				repo = repo[si+1:]
			}
		} else if idx := strings.Index(repo, ":"); idx >= 0 {
			repo = repo[idx+1:]
		}
		repo = strings.TrimSuffix(repo, ".git")
		repository = repo
	} else {
		repository = filepath.Base(sourceDir)
	}
	return
}

// loadAuditDriverContext loads audit findings and knowledge base from the session
// directory's harness subdir. The schema is shared across audit and piolium
// (knowledge-base-report.md filename is the same).
func loadAuditDriverContext(sessionDir string, harness HarnessSpec) *auditContextStruct {
	if sessionDir == "" {
		return nil
	}
	if harness.Name == "" {
		harness = DefaultAuditHarness()
	}
	auditDir := filepath.Join(sessionDir, harness.SessionSubdir)

	auditImport, err := audit.ParseFolder(auditDir)
	if err != nil {
		zap.L().Debug("No audit findings to load", zap.String("harness", harness.Name), zap.Error(err))
		return nil
	}

	ac := &auditContextStruct{
		Findings: auditImport.RawFindings,
	}

	kbPath := filepath.Join(auditDir, "knowledge-base-report.md")
	if kbData, readErr := os.ReadFile(kbPath); readErr == nil {
		ac.KnowledgeBase = string(kbData)
	}

	return ac
}

// buildAutonomousPrompt constructs the mission brief for an autonomous autopilot session.
// Handles source-only, target-only, source+target, and prepared source context.
func buildAutonomousPrompt(cfg AutopilotPipelineConfig, ac *auditContextStruct, auditRunning bool) string {
	sourceOnly := cfg.TargetURL == "" && cfg.SourcePath != ""
	if sourceOnly {
		return buildSourceOnlyPrompt(cfg, ac, auditRunning)
	}
	return buildTargetPrompt(cfg, ac, auditRunning)
}

// buildSourceOnlyPrompt constructs a code-review-focused mission brief when no target is available.
func buildSourceOnlyPrompt(cfg AutopilotPipelineConfig, ac *auditContextStruct, auditRunning bool) string {
	var b strings.Builder
	hasFindings := ac != nil && len(ac.Findings) > 0

	b.WriteString("# Autonomous Security Code Review\n\n")
	b.WriteString("## Mission\n\n")

	if hasFindings {
		fmt.Fprintf(&b, "An automated security audit (vigolium-audit) has been performed on the source code at **%s**.\n", cfg.SourcePath)
		b.WriteString("Your job is to review the audit findings, investigate the source code, and provide a comprehensive security analysis.\n\n")
		b.WriteString("- **Validate findings** — Read the relevant source code to confirm or disprove each finding\n")
		b.WriteString("- **Assess exploitability** — Determine real-world impact and attack scenarios\n")
		b.WriteString("- **Find additional issues** — The audit may have missed vulnerabilities\n")
		b.WriteString("- **Provide remediation** — Suggest specific code fixes for confirmed vulnerabilities\n\n")
	} else {
		fmt.Fprintf(&b, "Perform a comprehensive security code review of the application at **%s**.\n\n", cfg.SourcePath)
		b.WriteString("No live target is available — this is a **static analysis / code review** session.\n\n")
	}

	// Source section
	b.WriteString("## Source Code\n\n")
	fmt.Fprintf(&b, "- **Path:** %s\n", cfg.SourcePath)
	if len(cfg.Files) > 0 {
		fmt.Fprintf(&b, "- **Focus files:** %s\n", strings.Join(cfg.Files, ", "))
	}
	b.WriteString("\n")

	writeCommonSections(&b, cfg, ac, auditRunning)

	// Source-only recommended approach
	b.WriteString("## Recommended Approach\n\n")
	if auditRunning && !hasFindings {
		b.WriteString("A source audit has completed and the prepared context is ready. Start your own analysis from that prepared context:\n\n")
	}
	if hasFindings {
		b.WriteString("1. **Review audit findings** — Prioritize by severity, read the cited source locations\n")
		b.WriteString("2. **Validate each finding** — Trace data flow through the code to confirm exploitability\n")
		b.WriteString("3. **Search for variants** — If a pattern is vulnerable, grep for similar patterns\n")
		b.WriteString("4. **Check for missed issues** — Review auth, input validation, crypto, secrets, config\n")
		b.WriteString("5. **Report** — Summarize with severity, evidence (code snippets), and remediation\n\n")
	} else {
		b.WriteString("1. **Map the application** — Read entry points, routes, middleware, auth configuration\n")
		b.WriteString("2. **Identify sinks** — Find SQL queries, shell commands, file operations, HTTP clients, template rendering\n")
		b.WriteString("3. **Trace data flow** — Follow user input from entry points to sinks\n")
		b.WriteString("4. **Check security controls** — Authentication, authorization, CSRF, rate limiting, input validation\n")
		b.WriteString("5. **Check secrets and config** — Hardcoded credentials, insecure defaults, debug flags\n")
		b.WriteString("6. **Report** — Summarize findings with code locations, severity, and remediation\n\n")
	}

	b.WriteString("## Guidelines\n\n")
	b.WriteString("- Use Grep, Glob, and Read tools to navigate the codebase efficiently\n")
	b.WriteString("- Trace complete data flows — don't stop at the first function boundary\n")
	b.WriteString("- Check both the happy path and error handling paths\n")
	b.WriteString("- When you find a vulnerability, search for similar patterns elsewhere in the code\n")
	b.WriteString("- No live target is available — do not attempt HTTP requests or scanning commands\n")

	return b.String()
}

// buildTargetPrompt constructs a mission brief for target-based scanning (with or without source).
func buildTargetPrompt(cfg AutopilotPipelineConfig, ac *auditContextStruct, auditRunning bool) string {
	var b strings.Builder
	hasFindings := ac != nil && len(ac.Findings) > 0

	b.WriteString("# Autonomous Security Assessment\n\n")

	if hasFindings {
		b.WriteString("## Mission\n\n")
		fmt.Fprintf(&b, "An automated security audit (vigolium-audit) has been performed on the source code targeting **%s**.\n", cfg.TargetURL)
		b.WriteString("Your job is to review the audit findings and take action:\n\n")
		b.WriteString("- **Write PoCs/exploits** for confirmed or high-confidence findings against the live target\n")
		b.WriteString("- **Run native scans** (`vigolium scan-url`, `vigolium scan-request`) on discovered routes and endpoints\n")
		b.WriteString("- **Investigate** findings that need more evidence or validation\n")
		b.WriteString("- **Skip** low-confidence or already-disproved findings\n")
		b.WriteString("- **Discover gaps** — run discovery on the target to find endpoints the audit may have missed\n\n")
	} else {
		b.WriteString("## Mission\n\n")
		fmt.Fprintf(&b, "Perform a comprehensive security assessment of **%s**.\n\n", cfg.TargetURL)
		b.WriteString("You have full autonomy to decide your approach. Use any combination of vigolium CLI commands, ")
		b.WriteString("curl, jq, and standard Unix tools. There are no fixed phases — you decide what to do, ")
		b.WriteString("in what order, and when you're done.\n\n")
	}

	// Target section
	b.WriteString("## Target\n\n")
	fmt.Fprintf(&b, "- **URL:** %s\n", cfg.TargetURL)

	if cfg.SourcePath != "" {
		fmt.Fprintf(&b, "- **Source code:** %s\n", cfg.SourcePath)
		if !hasFindings {
			b.WriteString("  - Read the source code to understand routes, auth flows, and vulnerability sinks\n")
			b.WriteString("  - Use this knowledge to guide your scanning strategy\n")
		}
	}
	if len(cfg.Files) > 0 {
		fmt.Fprintf(&b, "- **Focus files:** %s\n", strings.Join(cfg.Files, ", "))
	}
	b.WriteString("\n")

	writeCommonSections(&b, cfg, ac, auditRunning)

	// Recommended approach
	b.WriteString("## Recommended Approach\n\n")
	if hasFindings {
		b.WriteString("The frozen Audit audit has already mapped the codebase. Focus on validation and exploitation:\n\n")
		b.WriteString("1. **Review audit findings** — Prioritize by severity and confidence\n")
		if cfg.BrowserEnabled {
			b.WriteString("2. **Authenticate if needed** — If findings require authenticated access, use `agent-browser` to log in and capture session credentials\n")
			b.WriteString("3. **Exploit confirmed findings** — Write PoCs using curl, custom scripts, or vigolium extensions\n")
		} else {
			b.WriteString("2. **Exploit confirmed findings** — Write PoCs using curl, custom scripts, or vigolium extensions\n")
		}
		b.WriteString("   - Use `printf '<raw-request>' | vigolium scan-request --json` for targeted scanning\n")
		b.WriteString("   - Use `vigolium scan-url <url> --json --module-tag <tag>` for route-level scanning\n")
		stepN := 3
		if cfg.BrowserEnabled {
			stepN = 4
		}
		fmt.Fprintf(&b, "%d. **Run targeted native scans** — Scan routes identified in findings\n", stepN)
		fmt.Fprintf(&b, "%d. **Investigate uncertain findings** — Use source code analysis and probing\n", stepN+1)
		fmt.Fprintf(&b, "%d. **Discover gaps** — Run `vigolium scan --only discovery -t <target> --json` to find missed endpoints\n", stepN+2)
		fmt.Fprintf(&b, "%d. **Report** — Summarize confirmed vulnerabilities with evidence and remediation\n\n", stepN+3)
	} else {
		stepN := 1
		if cfg.PreparedAuth != nil && cfg.PreparedAuth.Hydrated {
			fmt.Fprintf(&b, "%d. **Use Prepared Authentication** — Start with the preflight auth artifacts that were already prepared:\n", stepN)
			if cfg.Artifacts.SessionConfigPath != "" {
				fmt.Fprintf(&b, "   - Session config: `%s`\n", cfg.Artifacts.SessionConfigPath)
			}
			if cfg.Artifacts.AuthHeadersPath != "" {
				fmt.Fprintf(&b, "   - Hydrated headers/cookies: `%s`\n", cfg.Artifacts.AuthHeadersPath)
			}
			b.WriteString("   - Reuse this state before attempting any manual login flow\n")
			b.WriteString("   - Only fall back to browser/manual auth if the prepared state is rejected by protected routes\n\n")
			stepN++
		} else if cfg.BrowserEnabled {
			fmt.Fprintf(&b, "%d. **Authenticate** — If the target has a login page, use `agent-browser` to authenticate:\n", stepN)
			if cfg.BrowserStartURL != "" {
				fmt.Fprintf(&b, "   - Start at `%s`\n", cfg.BrowserStartURL)
			}
			b.WriteString("   - `agent-browser open <login-url> --session-name scan` to open the page\n")
			b.WriteString("   - `agent-browser snapshot --json --session-name scan` to find form elements\n")
			b.WriteString("   - Fill credentials, submit, then `agent-browser cookies --json --session-name scan`\n")
			b.WriteString("   - Use captured cookies/tokens with vigolium scan commands via `--header`\n\n")
			stepN++
		}
		fmt.Fprintf(&b, "%d. **Reconnaissance** — Discover the attack surface:\n", stepN)
		b.WriteString("   - Run `vigolium scan --only discovery -t <target> --json` for content discovery\n")
		b.WriteString("   - Run `vigolium scan --only spidering -t <target> --json --spider` for crawling\n")
		b.WriteString("   - Use `curl -s -i` to probe interesting endpoints manually\n")
		if cfg.SourcePath != "" {
			b.WriteString("   - Read application source code to find routes, auth mechanisms, and sinks\n")
		}
		b.WriteString("   - Review discovered endpoints: `vigolium traffic --json`\n\n")

		fmt.Fprintf(&b, "%d. **Analysis & Scanning** — Test for vulnerabilities:\n", stepN+1)
		b.WriteString("   - Scan high-value endpoints: `vigolium scan-url <url> --json`\n")
		b.WriteString("   - Use targeted module tags: `--module-tag injection,xss,auth,ssrf,ssti`\n")
		b.WriteString("   - Pipe raw requests: `printf '...' | vigolium scan-request --json`\n")
		b.WriteString("   - Write custom JS extensions for edge cases: `vigolium ext eval --ext-file script.js`\n\n")

		fmt.Fprintf(&b, "%d. **Verification & Iteration** — Confirm and expand:\n", stepN+2)
		b.WriteString("   - Review findings: `vigolium finding --json --severity critical,high`\n")
		b.WriteString("   - Manually verify with curl to confirm exploitability\n")
		b.WriteString("   - Test related endpoints for similar vulnerabilities\n")
		b.WriteString("   - Import confirmed findings: `echo '{...}' | vigolium finding load`\n\n")

		fmt.Fprintf(&b, "%d. **Reporting** — Summarize your work:\n", stepN+3)
		b.WriteString("   - Provide a clear summary of all confirmed vulnerabilities\n")
		b.WriteString("   - Include severity, evidence, and remediation guidance\n")
		b.WriteString("   - Note any false positives you identified and dismissed\n\n")
	}

	b.WriteString("## Guidelines\n\n")
	b.WriteString("- Always use `--json` for structured output you can analyze\n")
	b.WriteString("- Don't scan static assets (CSS, JS bundles, images, fonts)\n")
	b.WriteString("- After finding a vulnerability type, test similar endpoints for the same class\n")
	b.WriteString("- Pay attention to error messages — they reveal technology and paths\n")
	b.WriteString("- If a scan returns no findings, move on — don't retry the same thing\n")
	b.WriteString("- Use `vigolium db stats --json` to check overall progress\n")
	b.WriteString("- You have full shell access — be creative and thorough\n")

	return b.String()
}

// writeCommonSections writes focus, instruction, context, plan, findings, knowledge base,
// and artifact instructions shared between source-only and target prompts.
func writeCommonSections(b *strings.Builder, cfg AutopilotPipelineConfig, ac *auditContextStruct, auditRunning bool) {
	hasFindings := ac != nil && len(ac.Findings) > 0

	if cfg.Focus != "" {
		b.WriteString("## Focus Area\n\n")
		b.WriteString(cfg.Focus)
		b.WriteString("\n\n")
	}

	if cfg.Instruction != "" {
		b.WriteString("## Custom Instructions\n\n")
		b.WriteString(cfg.Instruction)
		b.WriteString("\n\n")
	}

	if cfg.ContextBundle != nil {
		b.WriteString("## Whitebox Context\n\n")
		for _, p := range cfg.ContextBundle.Priorities {
			fmt.Fprintf(b, "- %s\n", p)
		}
		if cfg.ContextBundle.BrowserDecision != "" {
			fmt.Fprintf(b, "\n- Browser policy: `%s`", cfg.ContextBundle.BrowserDecision)
			if cfg.ContextBundle.BrowserReason != "" {
				fmt.Fprintf(b, " — %s", cfg.ContextBundle.BrowserReason)
			}
			b.WriteString("\n")
		}
		if len(cfg.ContextBundle.Warnings) > 0 {
			b.WriteString("\n### Warnings\n\n")
			for _, w := range cfg.ContextBundle.Warnings {
				fmt.Fprintf(b, "- %s\n", w)
			}
		}
		if cfg.ContextBundle.PreparedAuth != nil {
			b.WriteString("\n### Prepared Authentication\n\n")
			fmt.Fprintf(b, "- Requested: %t\n", cfg.ContextBundle.PreparedAuth.Requested)
			fmt.Fprintf(b, "- Source: %s\n", firstNonEmpty(cfg.ContextBundle.PreparedAuth.Source, "none"))
			fmt.Fprintf(b, "- Hydrated: %t\n", cfg.ContextBundle.PreparedAuth.Hydrated)
			if cfg.ContextBundle.PreparedAuth.SessionConfig != "" {
				fmt.Fprintf(b, "- Session config artifact: `%s`\n", cfg.ContextBundle.PreparedAuth.SessionConfig)
			}
			if len(cfg.ContextBundle.PreparedAuth.FocusRoutes) > 0 {
				fmt.Fprintf(b, "- Focus routes: %s\n", strings.Join(cfg.ContextBundle.PreparedAuth.FocusRoutes, ", "))
			}
		}
		b.WriteString("\n")
	}

	if cfg.Plan != nil {
		b.WriteString("## Native Plan\n\n")
		for _, task := range cfg.Plan.Tasks {
			fmt.Fprintf(b, "%d. **%s** — %s\n", task.Priority, task.Type, task.Reason)
		}
		b.WriteString("\n### Budgets\n\n")
		for _, key := range []string{"auth", "recon", "validate", "extension", "report"} {
			if v, ok := cfg.Plan.Budgets[key]; ok {
				fmt.Fprintf(b, "- `%s`: %d\n", key, v)
			}
		}
		b.WriteString("\n### Stop Criteria\n\n")
		for _, c := range cfg.Plan.StopCriteria {
			fmt.Fprintf(b, "- %s\n", c)
		}
		b.WriteString("\n")
	}

	// Diff context section
	if cfg.DiffContext != nil && len(cfg.DiffContext.ChangedFiles) > 0 {
		b.WriteString("## Diff Context (Changed Files)\n\n")
		fmt.Fprintf(b, "This scan is focused on changes from: **%s**\n\n", cfg.DiffContext.DiffRef)
		b.WriteString("### Changed Files\n\n")
		for _, f := range cfg.DiffContext.ChangedFiles {
			fmt.Fprintf(b, "- `%s`\n", f)
		}
		b.WriteString("\n")
		if cfg.DiffContext.PatchContent != "" {
			patch := cfg.DiffContext.PatchContent
			const maxPatchChars = 8000
			if len(patch) > maxPatchChars {
				patch = patch[:maxPatchChars] + "\n\n... (patch truncated — full diff available via git)\n"
			}
			b.WriteString("### Patch\n\n```diff\n")
			b.WriteString(patch)
			b.WriteString("\n```\n\n")
		}
		b.WriteString("**Priority:** Focus your analysis on the changed code paths. ")
		b.WriteString("Vulnerabilities in unchanged code are lower priority unless directly related to the changes.\n\n")
	}

	// Audit findings section
	if hasFindings {
		b.WriteString("## Security Audit Findings\n\n")
		fmt.Fprintf(b, "The vigolium-audit produced **%d findings**. ", len(ac.Findings))
		b.WriteString("Review them and decide what action to take for each.\n\n")

		if cfg.SessionDir != "" {
			fmt.Fprintf(b, "> Full finding details: `%s/audit/`\n\n", cfg.SessionDir)
		}

		b.WriteString(formatFindings(ac.Findings))
		b.WriteString("\n")
	}

	// Knowledge base section (truncated)
	if ac != nil && ac.KnowledgeBase != "" {
		b.WriteString("## Application Knowledge Base\n\n")
		kb := ac.KnowledgeBase
		if len(kb) > maxKnowledgeBaseChars {
			kb = kb[:maxKnowledgeBaseChars] + "\n\n... (truncated — see full report in session dir)\n"
		}
		b.WriteString(kb)
		b.WriteString("\n\n")
	}

	if cfg.Artifacts.BriefPath != "" {
		b.WriteString("## Required Artifacts\n\n")
		b.WriteString("You must keep the operator artifacts up to date while you work.\n\n")
		fmt.Fprintf(b, "- Confirmed findings: `%s`\n", cfg.Artifacts.FindingsPath)
		fmt.Fprintf(b, "- Dismissed findings: `%s`\n", cfg.Artifacts.DismissedPath)
		fmt.Fprintf(b, "- Visited endpoints: `%s`\n", cfg.Artifacts.VisitedEndpointsPath)
		fmt.Fprintf(b, "- Session config: `%s`\n", cfg.Artifacts.SessionConfigPath)
		fmt.Fprintf(b, "- Auth state: `%s`\n", cfg.Artifacts.AuthStatePath)
		fmt.Fprintf(b, "- Auth headers/cookies: `%s`\n", cfg.Artifacts.AuthHeadersPath)
		fmt.Fprintf(b, "- Browser session state: `%s`\n", cfg.Artifacts.BrowserSessionPath)
		fmt.Fprintf(b, "- Evidence directory: `%s`\n\n", cfg.Artifacts.EvidenceDir)
		b.WriteString("Every retained finding must include reproducible evidence. If you cannot support a finding with evidence, move it to the dismissed artifact.\n\n")
	}
}

// formatFindings formats audit findings for inclusion in the agent prompt.
// Uses tiered formatting based on finding count to manage prompt size.
func formatFindings(findings []*audit.Finding) string {
	if len(findings) == 0 {
		return ""
	}

	// Sort by severity first, then exploitability as a tiebreaker so a
	// confirmed-PoC high beats a theoretical high. Pre-compute both keys
	// once per finding — sort.SliceStable calls the comparator O(N log N)
	// times, and exploitabilityScore re-normalizes three strings per call,
	// so doing it inline turned each finding's keys into 5-7× redundant work.
	type ranked struct {
		f         *audit.Finding
		sevRank   int
		exploitBy int
	}
	ranks := make([]ranked, len(findings))
	for i, f := range findings {
		ranks[i] = ranked{f: f, sevRank: severityRank(f.Severity), exploitBy: exploitabilityScore(f)}
	}
	sort.SliceStable(ranks, func(i, j int) bool {
		if ranks[i].sevRank != ranks[j].sevRank {
			return ranks[i].sevRank < ranks[j].sevRank
		}
		return ranks[i].exploitBy < ranks[j].exploitBy
	})
	sorted := make([]*audit.Finding, len(ranks))
	for i, r := range ranks {
		sorted[i] = r.f
	}

	var b strings.Builder

	// Tier 1: full detail per finding
	if len(sorted) <= findingsTierFullDetail {
		for _, f := range sorted {
			writeFullFinding(&b, f)
		}
		return b.String()
	}

	// Tier 2: summary table + detail for critical/high only
	if len(sorted) <= findingsTierSummaryTable {
		writeFindingSummaryTable(&b, sorted)
		b.WriteString("\n### Critical and High Severity Details\n\n")
		for _, f := range sorted {
			if isCriticalOrHigh(f.Severity) {
				writeFullFinding(&b, f)
			}
		}
		return b.String()
	}

	// Tier 3: summary table + top N detail
	writeFindingSummaryTable(&b, sorted)
	fmt.Fprintf(&b, "\n### Top %d Findings (Details)\n\n", findingsTopNDetail)
	count := findingsTopNDetail
	if count > len(sorted) {
		count = len(sorted)
	}
	for i := 0; i < count; i++ {
		writeFullFinding(&b, sorted[i])
	}
	fmt.Fprintf(&b, "\n> %d additional findings available. Read the persisted Audit finding files in the session artifacts.\n", len(sorted)-count)
	return b.String()
}

// writeFullFinding writes a detailed finding entry to the builder.
func writeFullFinding(b *strings.Builder, f *audit.Finding) {
	title := f.Title
	if title == "" {
		title = f.Slug
	}

	fmt.Fprintf(b, "### [%s] %s (%s)\n", f.FindingID, title, f.Severity)

	// Metadata line
	fmt.Fprintf(b, "- **Verdict:** %s", f.Verdict)
	if f.PoCStatus != "" {
		fmt.Fprintf(b, " | **PoC Status:** %s", f.PoCStatus)
	}
	if f.CWE != "" {
		fmt.Fprintf(b, " | **CWE:** %s", f.CWE)
	}
	b.WriteString("\n")

	// Locations
	if len(f.Locations) > 0 {
		fmt.Fprintf(b, "- **Locations:** `%s`\n", strings.Join(f.Locations, "`, `"))
	}

	if f.Body != "" {
		b.WriteString("\n")
		b.WriteString(modkit.Truncate(f.Body, maxBodyExcerptChars))
		b.WriteString("\n")
	}

	b.WriteString("\n")
}

// writeFindingSummaryTable writes a markdown table summarizing all findings.
func writeFindingSummaryTable(b *strings.Builder, findings []*audit.Finding) {
	b.WriteString("| ID | Title | Severity | Verdict | PoC | Locations |\n")
	b.WriteString("|----|-------|----------|---------|-----|-----------|\n")
	for _, f := range findings {
		title := f.Title
		if title == "" {
			title = f.Slug
		}
		title = modkit.Truncate(title, maxTitleChars)
		locs := ""
		if len(f.Locations) > 0 {
			locs = f.Locations[0]
			if len(f.Locations) > 1 {
				locs += fmt.Sprintf(" (+%d)", len(f.Locations)-1)
			}
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n",
			f.FindingID, title, f.Severity, f.Verdict, f.PoCStatus, locs)
	}
}

// parseSeverity converts a severity string to the typed enum.
// Returns severity.Undefined for unrecognized values.
func parseSeverity(sev string) severity.Severity {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return severity.Critical
	case "high":
		return severity.High
	case "medium":
		return severity.Medium
	case "low":
		return severity.Low
	case "info":
		return severity.Info
	default:
		return severity.Undefined
	}
}

// severityRank returns a sort rank for severity (lower = more critical).
func severityRank(sev string) int {
	// severity.Severity int values increase with severity, so negate for descending sort.
	return -int(parseSeverity(sev))
}

func isCriticalOrHigh(sev string) bool {
	return parseSeverity(sev) >= severity.High
}

// exploitabilityScore ranks how actionable a finding is *within its severity
// bucket*. Lower = more actionable. Three signals from the audit harness:
//
//   - PoCStatus: a confirmed PoC means the harness already produced working
//     exploit evidence; pending is in-progress; theoretical is the harness's
//     best guess without proof. Confirmed > pending > theoretical.
//   - Provenance: "" (promoted/confirmed) findings sit in findings/ because
//     they survived the harness's own validation; "theoretical" and "draft"
//     are weaker signals (theoretical is VALID-but-unproven, draft is
//     pre-promotion intermediate).
//   - Confidence: when the harness reports its own confidence, prefer high
//     over medium over low — a high-confidence medium reads cleaner than a
//     low-confidence medium even though both rank the same on severity.
//
// Severity remains the primary sort key (in formatFindings); this only
// reorders findings that tie on severity.
func exploitabilityScore(f *audit.Finding) int {
	score := 0
	switch strings.ToLower(strings.TrimSpace(f.PoCStatus)) {
	case "confirmed":
		// best signal — keep at 0
	case "pending":
		score += 10
	case "theoretical", "":
		score += 20
	default:
		score += 15
	}
	switch strings.ToLower(strings.TrimSpace(f.Provenance)) {
	case "":
		// promoted/confirmed — best signal
	case "theoretical":
		score += 5
	case "draft":
		score += 8
	default:
		score += 5
	}
	switch strings.ToLower(strings.TrimSpace(f.Confidence)) {
	case "high":
		// best signal
	case "medium", "":
		score += 3
	case "low":
		score += 6
	default:
		score += 3
	}
	return score
}

func emitProgress(cfg *AutopilotPipelineConfig, phase, message string) {
	if cfg.ProgressCallback != nil {
		cfg.ProgressCallback(phase, message)
	}
}

// progressWriter wraps an io.Writer and emits progress callbacks at byte intervals.
type progressWriter struct {
	inner       io.Writer
	callback    func(phase string, message string)
	phase       string
	interval    int64 // bytes between progress emissions
	written     int64
	lastEmitted int64
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.inner.Write(p)
	pw.written += int64(n)
	if pw.written-pw.lastEmitted >= pw.interval {
		pw.callback(pw.phase, fmt.Sprintf("agent output: %dKB", pw.written/1024))
		pw.lastEmitted = pw.written
	}
	return n, err
}
