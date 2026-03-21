package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

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

	Specialists []VulnClass
	AgentName   string
	AgentACPCmd string
	MaxCommands int

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
	Duration       time.Duration
	SessionDir     string
}

// AutopilotCheckpoint captures autopilot pipeline state for checkpoint/resume.
type AutopilotCheckpoint struct {
	CompletedPhases []AutopilotPhase          `json:"completed_phases"`
	TargetURL       string                    `json:"target_url"`
	VulnQueues      map[VulnClass]*VulnQueue  `json:"vuln_queues,omitempty"`
	ExtensionDir    string                    `json:"extension_dir,omitempty"`
	Timestamp       time.Time                 `json:"timestamp"`
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

// Run executes the full autopilot pipeline.
func (r *AutopilotPipelineRunner) Run(ctx context.Context, cfg AutopilotPipelineConfig) (*AutopilotPipelineResult, error) {
	start := time.Now()

	// Ensure warm sessions for multi-call mode
	r.engine.EnsureWarmSessions()

	result := &AutopilotPipelineResult{
		VulnQueues:   make(map[VulnClass]*VulnQueue),
		Evidence:     make(map[VulnClass][]ExploitationEvidence),
		PhaseTimings: make(map[AutopilotPhase]time.Duration),
		SessionDir:   cfg.SessionDir,
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

	// Phase 1: Recon
	if !phaseCompleted(AutopilotPhaseRecon) {
		notifyPhase(AutopilotPhaseRecon)
		phaseStart := time.Now()

		reconResult, err := r.runRecon(ctx, cfg)
		result.PhaseTimings[AutopilotPhaseRecon] = time.Since(phaseStart)
		result.PhasesRun = append(result.PhasesRun, AutopilotPhaseRecon)

		if err != nil {
			zap.L().Warn("Recon phase failed, continuing with empty recon", zap.Error(err))
		} else if reconResult != nil {
			zap.L().Info("Recon completed",
				zap.Int("endpoints", len(reconResult.Endpoints)),
				zap.Int("tech_stack", len(reconResult.TechStack)))
		}

		r.saveCheckpoint(cfg, result)
	}

	// Phase 2: Vuln Analysis (parallel specialists)
	if !phaseCompleted(AutopilotPhaseVulnAnalysis) {
		notifyPhase(AutopilotPhaseVulnAnalysis)
		phaseStart := time.Now()

		queues, extensions, err := r.runVulnAnalysis(ctx, cfg)
		result.PhaseTimings[AutopilotPhaseVulnAnalysis] = time.Since(phaseStart)
		result.PhasesRun = append(result.PhasesRun, AutopilotPhaseVulnAnalysis)

		if err != nil {
			zap.L().Warn("Vuln analysis phase had errors", zap.Error(err))
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

		evidence, err := r.runExploitVerify(ctx, cfg, result.VulnQueues)
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
func (r *AutopilotPipelineRunner) runVulnAnalysis(ctx context.Context, cfg AutopilotPipelineConfig) (map[VulnClass]*VulnQueue, []GeneratedExtension, error) {
	queues := make(map[VulnClass]*VulnQueue)
	var mu sync.Mutex
	var allExtensions []GeneratedExtension

	g, gctx := errgroup.WithContext(ctx)

	for _, specialist := range cfg.Specialists {
		class := specialist
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

			// Extract extensions from the specialist output
			extensions := extractCodeBlockExtensions(result.RawOutput)

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
func (r *AutopilotPipelineRunner) runExploitVerify(ctx context.Context, cfg AutopilotPipelineConfig, queues map[VulnClass]*VulnQueue) (map[VulnClass][]ExploitationEvidence, error) {
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
