package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
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

// AutopilotPipelineConfig configures the v2 autopilot pipeline.
type AutopilotPipelineConfig struct {
	TargetURL   string
	SourcePath  string
	Files       []string
	Instruction string
	Focus       string

	Specialists          []VulnClass
	NoFilterSpecialists  bool // when true, skip smart specialist filtering based on recon
	AgentName            string
	AgentACPCmd          string
	MaxCommands          int

	DryRun     bool
	ShowPrompt bool

	SessionsDir string
	SessionDir  string
	ResumeDir   string

	ProjectUUID string
	ScanUUID    string

	StreamWriter io.Writer

	// Callbacks
	ScanFunc                ScanFunc
	SourceAnalysisCallback  func(*SourceAnalysisResult) error
	PhaseCallback           func(AutopilotPhase)
	ProgressCallback        func(phase string, message string)

	// AuditAgent enables the background vig-audit-agent when set.
	AuditAgent *config.AuditAgentConfig
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
	CompletedPhases            []AutopilotPhase          `json:"completed_phases"`
	TargetURL                  string                    `json:"target_url"`
	VulnQueues                 map[VulnClass]*VulnQueue  `json:"vuln_queues,omitempty"`
	ExtensionDir               string                    `json:"extension_dir,omitempty"`
	Timestamp                  time.Time                 `json:"timestamp"`
	CompletedSpecialists       map[VulnClass]bool        `json:"completed_specialists,omitempty"`
	CompletedExploitSpecialists map[VulnClass]bool       `json:"completed_exploit_specialists,omitempty"`
}

// LastPhase returns the last completed phase, or "" if none.
func (cp *AutopilotCheckpoint) LastPhase() AutopilotPhase {
	if cp == nil || len(cp.CompletedPhases) == 0 {
		return ""
	}
	return cp.CompletedPhases[len(cp.CompletedPhases)-1]
}

// AutopilotPipelineRunner orchestrates the autopilot multi-agent pipeline.
type AutopilotPipelineRunner struct {
	engine *Engine
	repo   *database.Repository
}

// NewAutopilotPipelineRunner creates a new autopilot pipeline runner.
func NewAutopilotPipelineRunner(engine *Engine, repo *database.Repository) *AutopilotPipelineRunner {
	return &AutopilotPipelineRunner{engine: engine, repo: repo}
}

// RunAutonomous executes a fully autonomous autopilot session using the Agent SDK.
// Instead of the rigid 5-phase pipeline, the agent gets a comprehensive mission brief
// and full tool access (Bash, Read, Grep, etc.) to decide its own workflow.
// The agent runs vigolium CLI commands, curl, jq, and any standard tools autonomously.
func (r *AutopilotPipelineRunner) RunAutonomous(ctx context.Context, cfg AutopilotPipelineConfig) (*AutopilotPipelineResult, error) {
	start := time.Now()

	if err := r.engine.Preflight(cfg.AgentName); err != nil {
		return nil, fmt.Errorf("autopilot preflight failed: %w", err)
	}

	result := &AutopilotPipelineResult{
		VulnQueues:   make(map[VulnClass]*VulnQueue),
		Evidence:     make(map[VulnClass][]ExploitationEvidence),
		PhaseTimings: make(map[AutopilotPhase]time.Duration),
		PhaseFailed:  make(map[AutopilotPhase]bool),
		SessionDir:   cfg.SessionDir,
	}

	// Start background audit agent when configured and source is available
	if cleanup := startAuditAgentBackground(ctx, cfg.AuditAgent, cfg.SourcePath, cfg.SessionDir, cfg.ProjectUUID, cfg.ScanUUID, r.repo, func(msg string) {
		printPhaseLine("audit-agent", msg)
	}); cleanup != nil {
		defer cleanup()
	}

	prompt := buildAutonomousPrompt(cfg)

	autopilotSessionID := uuid.New().String()
	opts := Options{
		AgentName:    cfg.AgentName,
		PromptInline: prompt,
		SourcePath:   cfg.SourcePath,
		Files:        cfg.Files,
		TargetURL:    cfg.TargetURL,
		Source:       "autopilot",
		Autopilot:    true,
		MaxCommands:  cfg.MaxCommands,
		StreamWriter: cfg.StreamWriter,
		ScanUUID:     cfg.ScanUUID,
		ProjectUUID:  cfg.ProjectUUID,
		SessionKey:   "autopilot-autonomous",
		SessionID:    autopilotSessionID,
		SessionDir:   cfg.SessionDir,
		DryRun:       cfg.DryRun,
		ShowPrompt:   cfg.ShowPrompt,
	}

	printPhaseLine("autopilot", "starting autonomous agent session")
	emitProgress(cfg, "autopilot", "starting autonomous agent session")

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
	opts.StreamWriter = streamWriter

	agentResult, err := r.engine.Run(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("autonomous agent failed: %w", err)
	}

	// Save raw output to session directory
	if cfg.SessionDir != "" && agentResult != nil && agentResult.RawOutput != "" {
		_ = os.WriteFile(filepath.Join(cfg.SessionDir, "output.md"), []byte(agentResult.RawOutput), 0644)
	}

	// Findings are saved to the DB by vigolium commands the agent executes
	// (scan-url, scan-request, finding load, etc.). The agent reports its own
	// summary in the output text.

	emitProgress(cfg, "autopilot", "autonomous session completed")
	result.Duration = time.Since(start)
	return result, nil
}

// buildAutonomousPrompt constructs the mission brief for a fully autonomous autopilot session.
func buildAutonomousPrompt(cfg AutopilotPipelineConfig) string {
	var b strings.Builder

	b.WriteString("# Autonomous Security Assessment\n\n")
	b.WriteString("## Mission\n\n")
	fmt.Fprintf(&b, "Perform a comprehensive security assessment of **%s**.\n\n", cfg.TargetURL)
	b.WriteString("You have full autonomy to decide your approach. Use any combination of vigolium CLI commands, ")
	b.WriteString("curl, jq, and standard Unix tools. There are no fixed phases — you decide what to do, ")
	b.WriteString("in what order, and when you're done.\n\n")

	b.WriteString("## Target\n\n")
	fmt.Fprintf(&b, "- **URL:** %s\n", cfg.TargetURL)

	if cfg.SourcePath != "" {
		fmt.Fprintf(&b, "- **Source code:** %s\n", cfg.SourcePath)
		b.WriteString("  - Read the source code to understand routes, auth flows, and vulnerability sinks\n")
		b.WriteString("  - Use this knowledge to guide your scanning strategy\n")
	}
	if len(cfg.Files) > 0 {
		fmt.Fprintf(&b, "- **Focus files:** %s\n", strings.Join(cfg.Files, ", "))
	}
	b.WriteString("\n")

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

	b.WriteString("## Recommended Approach\n\n")
	b.WriteString("1. **Reconnaissance** — Discover the attack surface:\n")
	b.WriteString("   - Run `vigolium scan --only discovery -t <target> --json` for content discovery\n")
	b.WriteString("   - Run `vigolium scan --only spidering -t <target> --json --spider` for crawling\n")
	b.WriteString("   - Use `curl -s -i` to probe interesting endpoints manually\n")
	if cfg.SourcePath != "" {
		b.WriteString("   - Read application source code to find routes, auth mechanisms, and sinks\n")
	}
	b.WriteString("   - Review discovered endpoints: `vigolium traffic --json`\n\n")

	b.WriteString("2. **Analysis & Scanning** — Test for vulnerabilities:\n")
	b.WriteString("   - Scan high-value endpoints: `vigolium scan-url <url> --json`\n")
	b.WriteString("   - Use targeted module tags: `--module-tag injection,xss,auth,ssrf,ssti`\n")
	b.WriteString("   - Pipe raw requests: `printf '...' | vigolium scan-request --json`\n")
	b.WriteString("   - Write custom JS extensions for edge cases: `vigolium ext eval --ext-file script.js`\n\n")

	b.WriteString("3. **Verification & Iteration** — Confirm and expand:\n")
	b.WriteString("   - Review findings: `vigolium finding --json --severity critical,high`\n")
	b.WriteString("   - Manually verify with curl to confirm exploitability\n")
	b.WriteString("   - Test related endpoints for similar vulnerabilities\n")
	b.WriteString("   - Import confirmed findings: `echo '{...}' | vigolium finding load`\n\n")

	b.WriteString("4. **Reporting** — Summarize your work:\n")
	b.WriteString("   - Provide a clear summary of all confirmed vulnerabilities\n")
	b.WriteString("   - Include severity, evidence, and remediation guidance\n")
	b.WriteString("   - Note any false positives you identified and dismissed\n\n")

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

// Run executes the full autopilot pipeline (legacy 5-phase mode for non-SDK backends).
func (r *AutopilotPipelineRunner) Run(ctx context.Context, cfg AutopilotPipelineConfig) (*AutopilotPipelineResult, error) {
	start := time.Now()

	// Pre-flight: verify agent backend is reachable before starting pipeline
	if err := r.engine.Preflight(cfg.AgentName); err != nil {
		return nil, fmt.Errorf("autopilot preflight failed: %w", err)
	}

	// Ensure warm sessions for multi-call mode
	r.engine.EnsureWarmSessions()

	result := &AutopilotPipelineResult{
		VulnQueues:   make(map[VulnClass]*VulnQueue),
		Evidence:     make(map[VulnClass][]ExploitationEvidence),
		PhaseTimings: make(map[AutopilotPhase]time.Duration),
		PhaseFailed:  make(map[AutopilotPhase]bool),
		SessionDir:   cfg.SessionDir,
	}

	// Start background audit agent when configured and source is available
	if cleanup := startAuditAgentBackground(ctx, cfg.AuditAgent, cfg.SourcePath, cfg.SessionDir, cfg.ProjectUUID, cfg.ScanUUID, r.repo, func(msg string) {
		printPhaseLine("audit-agent", msg)
	}); cleanup != nil {
		defer cleanup()
	}

	// Load checkpoint for resume
	var checkpoint *AutopilotCheckpoint
	if cfg.ResumeDir != "" {
		cp, err := loadAutopilotCheckpoint(cfg.ResumeDir)
		if err != nil {
			zap.L().Warn("Failed to load autopilot checkpoint, starting fresh", zap.Error(err))
		} else {
			checkpoint = cp
			if cp.VulnQueues != nil {
				result.VulnQueues = cp.VulnQueues
			}
		}
	}

	phaseCompleted := func(phase AutopilotPhase) bool {
		if checkpoint == nil {
			return false
		}
		for _, p := range checkpoint.CompletedPhases {
			if p == phase {
				return true
			}
		}
		return false
	}

	notifyPhase := func(phase AutopilotPhase) {
		if cfg.PhaseCallback != nil {
			cfg.PhaseCallback(phase)
		}
		printPhaseLine(string(phase), "starting")
	}

	// Phase 1: Recon (+ parallel source analysis when --source is provided)
	var reconResult *ReconDeliverable
	if !phaseCompleted(AutopilotPhaseRecon) {
		notifyPhase(AutopilotPhaseRecon)
		emitProgress(cfg, "recon", "starting reconnaissance")
		phaseStart := time.Now()

		var reconErr error
		var sourceResult *SourceAnalysisResult

		if cfg.SourcePath != "" {
			// Run recon and source analysis in parallel
			g, gctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				reconResult, reconErr = r.runRecon(gctx, cfg)
				return nil // don't fail the group
			})
			g.Go(func() error {
				saCfg := SourceAnalysisConfig{
					AgentName:   cfg.AgentName,
					AgentACPCmd: cfg.AgentACPCmd,
					TargetURL:   cfg.TargetURL,
					SourcePath:  cfg.SourcePath,
					Files:       cfg.Files,
					Instruction: cfg.Instruction,
					SessionKey:  "autopilot-source-analysis",
					DryRun:      cfg.DryRun,
					ShowPrompt:  cfg.ShowPrompt,
					ScanUUID:    cfg.ScanUUID,
					ProjectUUID: cfg.ProjectUUID,
					StreamWriter: cfg.StreamWriter,
					SessionDir:  cfg.SessionDir,
				}
				emitProgress(cfg, "source-analysis", "running source analysis in parallel with recon")
				var saErr error
				sourceResult, _, _, saErr = r.engine.RunSourceAnalysisParallel(gctx, saCfg)
				if saErr != nil {
					zap.L().Warn("Parallel source analysis failed", zap.Error(saErr))
				}
				return nil // don't fail the group
			})
			_ = g.Wait()
		} else {
			reconResult, reconErr = r.runRecon(ctx, cfg)
		}

		result.PhaseTimings[AutopilotPhaseRecon] = time.Since(phaseStart)
		result.PhasesRun = append(result.PhasesRun, AutopilotPhaseRecon)

		if reconErr != nil {
			zap.L().Warn("Recon phase failed, continuing with empty recon", zap.Error(reconErr))
			result.PhaseFailed[AutopilotPhaseRecon] = true
		} else if reconResult != nil {
			zap.L().Info("Recon completed",
				zap.Int("endpoints", len(reconResult.Endpoints)),
				zap.Int("tech_stack", len(reconResult.TechStack)))
			emitProgress(cfg, "recon", fmt.Sprintf("found %d endpoints", len(reconResult.Endpoints)))
		}

		// Process source analysis results
		if sourceResult != nil {
			if cfg.SourceAnalysisCallback != nil {
				if cbErr := cfg.SourceAnalysisCallback(sourceResult); cbErr != nil {
					zap.L().Warn("Source analysis callback failed", zap.Error(cbErr))
				}
			}
			emitProgress(cfg, "source-analysis", fmt.Sprintf("found %d routes, %d extensions",
				len(sourceResult.HTTPRecords), len(sourceResult.Extensions)))
		}

		r.saveCheckpoint(cfg, result)
	}

	// Smart specialist filtering: skip irrelevant specialists based on recon output
	effectiveSpecialists := cfg.Specialists
	if !cfg.NoFilterSpecialists && reconResult != nil {
		effectiveSpecialists = filterSpecialistsByRecon(reconResult, cfg.Specialists)
		if len(effectiveSpecialists) < len(cfg.Specialists) {
			zap.L().Info("Filtered specialists based on recon",
				zap.Int("original", len(cfg.Specialists)),
				zap.Int("remaining", len(effectiveSpecialists)))
		}
	}
	// Use filtered specialists for remaining phases
	filteredCfg := cfg
	filteredCfg.Specialists = effectiveSpecialists

	// Phase 2: Vuln Analysis (parallel specialists)
	if !phaseCompleted(AutopilotPhaseVulnAnalysis) {
		notifyPhase(AutopilotPhaseVulnAnalysis)
		phaseStart := time.Now()

		// Pass completed specialists from checkpoint for partial resume
		var completedSpecs map[VulnClass]bool
		if checkpoint != nil && checkpoint.CompletedSpecialists != nil {
			completedSpecs = checkpoint.CompletedSpecialists
		}
		emitProgress(filteredCfg, "vuln-analysis", fmt.Sprintf("running %d specialists", len(filteredCfg.Specialists)))
		queues, extensions, err := r.runVulnAnalysis(ctx, filteredCfg, completedSpecs)
		result.PhaseTimings[AutopilotPhaseVulnAnalysis] = time.Since(phaseStart)
		result.PhasesRun = append(result.PhasesRun, AutopilotPhaseVulnAnalysis)

		if err != nil {
			zap.L().Warn("Vuln analysis phase had errors", zap.Error(err))
		}

		// Check if vuln analysis produced any results
		hasResults := false
		for _, q := range queues {
			if q != nil && len(q.Items) > 0 {
				hasResults = true
				break
			}
		}
		if !hasResults {
			result.PhaseFailed[AutopilotPhaseVulnAnalysis] = true
		}

		for class, queue := range queues {
			result.VulnQueues[class] = queue
		}

		// Write merged extensions
		if len(extensions) > 0 && cfg.SessionDir != "" {
			extDir, writeErr := WriteExtensionsToSessionDir(extensions, cfg.SessionDir)
			if writeErr != nil {
				zap.L().Warn("Failed to write extensions", zap.Error(writeErr))
			} else {
				zap.L().Info("Merged extensions from specialists",
					zap.Int("count", len(extensions)),
					zap.String("dir", extDir))
			}
		}

		r.saveCheckpoint(cfg, result)
	}

	// Phase 3: Native Scan
	if !phaseCompleted(AutopilotPhaseNativeScan) && cfg.ScanFunc != nil {
		// Warn if all AI phases failed — scan will run with default modules, not AI-guided targeting
		if result.PhaseFailed[AutopilotPhaseRecon] && result.PhaseFailed[AutopilotPhaseVulnAnalysis] {
			zap.L().Warn("All AI phases failed — native scan will run with default modules (no AI-guided targeting). " +
				"Check agent backend configuration and ensure the agent binary is installed and accessible")
			printPhaseLine("warning", "AI phases produced no results; falling back to default scan modules")
		}

		notifyPhase(AutopilotPhaseNativeScan)
		phaseStart := time.Now()

		extDir := filepath.Join(cfg.SessionDir, "extensions")
		if _, statErr := os.Stat(extDir); os.IsNotExist(statErr) {
			extDir = ""
		}

		// Collect module tags from all vuln queues
		var tags []string
		for _, queue := range result.VulnQueues {
			if queue != nil && queue.Class != "" {
				tags = append(tags, queue.Class)
			}
		}

		scanErr := cfg.ScanFunc(ctx, ScanRequest{
			ModuleTags:   tags,
			ExtensionDir: extDir,
		})
		result.PhaseTimings[AutopilotPhaseNativeScan] = time.Since(phaseStart)
		result.PhasesRun = append(result.PhasesRun, AutopilotPhaseNativeScan)

		if scanErr != nil {
			zap.L().Warn("Native scan phase failed", zap.Error(scanErr))
		}

		r.saveCheckpoint(cfg, result)
	}

	// Phase 4: Exploit Verify (parallel specialists, conditional)
	if !phaseCompleted(AutopilotPhaseExploitVerify) {
		notifyPhase(AutopilotPhaseExploitVerify)
		phaseStart := time.Now()

		var completedExploitSpecs map[VulnClass]bool
		if checkpoint != nil && checkpoint.CompletedExploitSpecialists != nil {
			completedExploitSpecs = checkpoint.CompletedExploitSpecialists
		}
		emitProgress(filteredCfg, "exploit-verify", "verifying findings")
		evidence, err := r.runExploitVerify(ctx, filteredCfg, result.VulnQueues, completedExploitSpecs)
		result.PhaseTimings[AutopilotPhaseExploitVerify] = time.Since(phaseStart)
		result.PhasesRun = append(result.PhasesRun, AutopilotPhaseExploitVerify)

		if err != nil {
			zap.L().Warn("Exploit verification had errors", zap.Error(err))
		}

		for class, ev := range evidence {
			result.Evidence[class] = ev
			for _, e := range ev {
				switch e.Status {
				case EvidenceStatusExploited:
					result.Confirmed++
				case EvidenceStatusFalsePositive:
					result.FalsePositives++
				}
				result.TotalFindings++
			}
		}

		r.saveCheckpoint(cfg, result)
	}

	// Phase 5: Report
	if !phaseCompleted(AutopilotPhaseReport) {
		notifyPhase(AutopilotPhaseReport)
		phaseStart := time.Now()

		r.runReport(ctx, cfg, result)
		result.PhaseTimings[AutopilotPhaseReport] = time.Since(phaseStart)
		result.PhasesRun = append(result.PhasesRun, AutopilotPhaseReport)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// runRecon executes the recon phase using an autopilot agent with terminal access.
func (r *AutopilotPipelineRunner) runRecon(ctx context.Context, cfg AutopilotPipelineConfig) (*ReconDeliverable, error) {
	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: "autopilot-recon",
		SourcePath:     cfg.SourcePath,
		TargetURL:      cfg.TargetURL,
		Source:         "autopilot-v2",
		Autopilot:      true,
		MaxCommands:    cfg.MaxCommands,
		Instruction:    cfg.Instruction,
		StreamWriter:   cfg.StreamWriter,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		SessionKey:     "autopilot-recon",
	}

	if cfg.Focus != "" {
		opts.Append = fmt.Sprintf("## Focus Area\n\n%s", cfg.Focus)
	}

	result, err := r.engine.Run(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("recon agent failed: %w", err)
	}

	recon, parseErr := ParseReconDeliverable(result.RawOutput)
	if parseErr != nil {
		zap.L().Warn("Failed to parse recon deliverable", zap.Error(parseErr))
		return nil, nil
	}

	return recon, nil
}

// runVulnAnalysis runs parallel specialist agents for vuln analysis (no terminal).
// It supports resuming from a checkpoint — already-completed specialists are skipped.
func (r *AutopilotPipelineRunner) runVulnAnalysis(ctx context.Context, cfg AutopilotPipelineConfig, completedSpecialists map[VulnClass]bool) (map[VulnClass]*VulnQueue, []GeneratedExtension, error) {
	queues := make(map[VulnClass]*VulnQueue)
	var mu sync.Mutex
	var allExtensions []GeneratedExtension

	g, gctx := errgroup.WithContext(ctx)

	for _, specialist := range cfg.Specialists {
		class := specialist

		// Skip already-completed specialists on resume
		if completedSpecialists[class] {
			zap.L().Info("Skipping already-completed vuln specialist", zap.String("class", string(class)))
			continue
		}

		g.Go(func() error {
			templateID := fmt.Sprintf("autopilot-vuln-%s", class)

			opts := Options{
				AgentName:      cfg.AgentName,
				AgentACPCmd:    cfg.AgentACPCmd,
				PromptTemplate: templateID,
				SourcePath:     cfg.SourcePath,
				TargetURL:      cfg.TargetURL,
				Source:         "autopilot-v2",
				Autopilot:      false, // no terminal for vuln analysis
				Instruction:    cfg.Instruction,
				StreamWriter:   cfg.StreamWriter,
				ScanUUID:       cfg.ScanUUID,
				ProjectUUID:    cfg.ProjectUUID,
				SessionKey:     fmt.Sprintf("autopilot-vuln-%s", class),
			}

			if len(cfg.Files) > 0 {
				opts.Files = cfg.Files
			}

			result, err := r.engine.Run(gctx, opts)
			if err != nil {
				zap.L().Warn("Vuln analysis specialist failed",
					zap.String("class", string(class)), zap.Error(err))
				return nil // don't fail the group
			}

			queue, parseErr := ParseVulnQueue(result.RawOutput)
			if parseErr != nil {
				zap.L().Warn("Failed to parse vuln queue",
					zap.String("class", string(class)), zap.Error(parseErr))
				return nil
			}

			// Extract extensions: try structured JSON first, fall back to code blocks
			extensions := ParseExtensionsFromJSON(result.RawOutput)
			if len(extensions) == 0 {
				extensions = extractCodeBlockExtensions(result.RawOutput)
			}

			mu.Lock()
			queues[class] = queue
			allExtensions = append(allExtensions, extensions...)
			mu.Unlock()

			zap.L().Info("Vuln analysis specialist completed",
				zap.String("class", string(class)),
				zap.Int("items", len(queue.Items)),
				zap.Int("extensions", len(extensions)))

			return nil
		})
	}

	err := g.Wait()
	return queues, allExtensions, err
}

// runExploitVerify runs parallel specialist agents for exploit verification (with terminal).
// It supports resuming from a checkpoint — already-completed specialists are skipped.
func (r *AutopilotPipelineRunner) runExploitVerify(ctx context.Context, cfg AutopilotPipelineConfig, queues map[VulnClass]*VulnQueue, completedSpecialists map[VulnClass]bool) (map[VulnClass][]ExploitationEvidence, error) {
	evidence := make(map[VulnClass][]ExploitationEvidence)
	var mu sync.Mutex

	g, gctx := errgroup.WithContext(ctx)

	for _, specialist := range cfg.Specialists {
		class := specialist
		queue := queues[class]

		// Skip if no vuln queue items for this class
		if queue == nil || len(queue.Items) == 0 {
			continue
		}

		// Skip already-completed specialists on resume
		if completedSpecialists[class] {
			zap.L().Info("Skipping already-completed exploit specialist", zap.String("class", string(class)))
			continue
		}

		g.Go(func() error {
			templateID := fmt.Sprintf("autopilot-exploit-%s", class)

			// Serialize vuln queue as context for the exploit agent
			queueJSON, _ := json.Marshal(queue)

			opts := Options{
				AgentName:      cfg.AgentName,
				AgentACPCmd:    cfg.AgentACPCmd,
				PromptTemplate: templateID,
				SourcePath:     cfg.SourcePath,
				TargetURL:      cfg.TargetURL,
				Source:         "autopilot-v2",
				Autopilot:      true, // terminal enabled for exploitation
				MaxCommands:    cfg.MaxCommands,
				Instruction:    cfg.Instruction,
				StreamWriter:   cfg.StreamWriter,
				ScanUUID:       cfg.ScanUUID,
				ProjectUUID:    cfg.ProjectUUID,
				SessionKey:     fmt.Sprintf("autopilot-exploit-%s", class),
				Extra: map[string]string{
					"VulnQueue": string(queueJSON),
				},
			}

			result, err := r.engine.Run(gctx, opts)
			if err != nil {
				zap.L().Warn("Exploit verification specialist failed",
					zap.String("class", string(class)), zap.Error(err))
				return nil
			}

			ev, parseErr := ParseExploitationEvidence(result.RawOutput)
			if parseErr != nil {
				zap.L().Warn("Failed to parse exploitation evidence",
					zap.String("class", string(class)), zap.Error(parseErr))
				return nil
			}

			mu.Lock()
			evidence[class] = ev
			mu.Unlock()

			zap.L().Info("Exploit verification completed",
				zap.String("class", string(class)),
				zap.Int("evidence_count", len(ev)))

			return nil
		})
	}

	err := g.Wait()
	return evidence, err
}

// runReport executes the report phase.
func (r *AutopilotPipelineRunner) runReport(ctx context.Context, cfg AutopilotPipelineConfig, result *AutopilotPipelineResult) {
	// Serialize evidence for the report agent
	evidenceJSON, _ := json.MarshalIndent(result.Evidence, "", "  ")

	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: "autopilot-report",
		TargetURL:      cfg.TargetURL,
		Source:         "autopilot-v2",
		Autopilot:      false,
		StreamWriter:   cfg.StreamWriter,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		SessionKey:     "autopilot-report",
		Extra: map[string]string{
			"Evidence":       string(evidenceJSON),
			"TotalFindings":  fmt.Sprintf("%d", result.TotalFindings),
			"Confirmed":      fmt.Sprintf("%d", result.Confirmed),
			"FalsePositives": fmt.Sprintf("%d", result.FalsePositives),
		},
	}

	reportResult, err := r.engine.Run(ctx, opts)
	if err != nil {
		zap.L().Warn("Report phase failed", zap.Error(err))
		return
	}

	// Save report to session directory
	if cfg.SessionDir != "" && reportResult.RawOutput != "" {
		_ = os.WriteFile(filepath.Join(cfg.SessionDir, "report.md"), []byte(reportResult.RawOutput), 0644)
	}
}

// saveCheckpoint persists the autopilot pipeline state after a phase completes.
func (r *AutopilotPipelineRunner) saveCheckpoint(cfg AutopilotPipelineConfig, result *AutopilotPipelineResult) {
	if cfg.SessionDir == "" {
		return
	}
	cp := &AutopilotCheckpoint{
		CompletedPhases: make([]AutopilotPhase, len(result.PhasesRun)),
		TargetURL:       cfg.TargetURL,
		VulnQueues:      result.VulnQueues,
		Timestamp:       time.Now(),
	}
	copy(cp.CompletedPhases, result.PhasesRun)

	if err := writeAutopilotCheckpoint(cfg.SessionDir, cp); err != nil {
		zap.L().Warn("Failed to write autopilot checkpoint", zap.Error(err))
	}
}

// writeAutopilotCheckpoint persists an AutopilotCheckpoint to the session directory.
func writeAutopilotCheckpoint(sessionDir string, cp *AutopilotCheckpoint) error {
	if sessionDir == "" {
		return nil
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal autopilot checkpoint: %w", err)
	}
	return os.WriteFile(filepath.Join(sessionDir, "autopilot-checkpoint.json"), data, 0644)
}

// loadAutopilotCheckpoint reads an AutopilotCheckpoint from the session directory.
func loadAutopilotCheckpoint(sessionDir string) (*AutopilotCheckpoint, error) {
	data, err := os.ReadFile(filepath.Join(sessionDir, "autopilot-checkpoint.json"))
	if err != nil {
		return nil, err
	}
	var cp AutopilotCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("failed to parse autopilot checkpoint: %w", err)
	}
	return &cp, nil
}

// filterSpecialistsByRecon prunes the specialist list based on recon results.
// Returns all configured specialists if recon is nil/empty or filtering is disabled.
func filterSpecialistsByRecon(recon *ReconDeliverable, configured []VulnClass) []VulnClass {
	if recon == nil || len(recon.Endpoints) == 0 {
		return configured
	}

	// Build a set of interesting signals from the recon data
	hasAuthEndpoints := false
	hasIDParams := false
	hasSSRFPatterns := false

	authKeywords := []string{"login", "register", "password", "token", "session", "oauth", "auth", "signup", "signin"}
	ssrfKeywords := []string{"url=", "redirect", "proxy", "fetch", "callback", "next=", "return=", "dest=", "target="}
	idKeywords := []string{"id=", "user_id", "account_id", "order_id", "item_id"}

	for _, ep := range recon.Endpoints {
		if hasAuthEndpoints && hasSSRFPatterns && hasIDParams {
			break // all signals found, no need to check more endpoints
		}
		epLower := strings.ToLower(ep.URL + " " + ep.Parameter + " " + ep.Notes)
		for _, kw := range authKeywords {
			if strings.Contains(epLower, kw) {
				hasAuthEndpoints = true
				break
			}
		}
		for _, kw := range ssrfKeywords {
			if strings.Contains(epLower, kw) {
				hasSSRFPatterns = true
				break
			}
		}
		for _, kw := range idKeywords {
			if strings.Contains(epLower, kw) {
				hasIDParams = true
				break
			}
		}
	}

	// Also check auth flows from recon
	if len(recon.AuthFlows) > 0 {
		hasAuthEndpoints = true
	}

	var filtered []VulnClass
	for _, class := range configured {
		switch class {
		case VulnClassAuth:
			if !hasAuthEndpoints {
				zap.L().Info("Skipping specialist (no auth endpoints detected)", zap.String("class", string(class)))
				continue
			}
		case VulnClassAuthz:
			if !hasAuthEndpoints && !hasIDParams {
				zap.L().Info("Skipping specialist (no auth flows or ID parameters detected)", zap.String("class", string(class)))
				continue
			}
		case VulnClassSSRF:
			if !hasSSRFPatterns {
				zap.L().Info("Skipping specialist (no SSRF-related patterns detected)", zap.String("class", string(class)))
				continue
			}
		}
		filtered = append(filtered, class)
	}

	// Always run at least injection and XSS — they're universally applicable
	if len(filtered) == 0 {
		return configured
	}

	return filtered
}

// emitProgress calls the progress callback if set.
func emitProgress(cfg AutopilotPipelineConfig, phase, message string) {
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

// Write delegates to the inner writer and emits progress at intervals.
func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.inner.Write(p)
	pw.written += int64(n)
	if pw.written-pw.lastEmitted >= pw.interval {
		pw.callback(pw.phase, fmt.Sprintf("agent output: %dKB", pw.written/1024))
		pw.lastEmitted = pw.written
	}
	return n, err
}
