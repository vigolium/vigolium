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
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"

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

	// Scanning parameters
	VulnType      string   // optional: focus on specific vulnerability type
	ModuleNames   []string // optional: explicit module IDs to use
	ScanningPhase string   // default "dynamic-assessment"
	MaxIterations int      // max triage-rescan loops (default 3)

	// Agent
	AgentName string
	DryRun    bool

	// Project/scan
	ProjectUUID string
	ScanUUID    string

	// Session directory base path for agent artifacts
	SessionsDir string

	// Streaming
	StreamWriter io.Writer

	// ScanFunc runs the dynamic assessment phase with the given module filters.
	// moduleTags and moduleIDs come from the agent's swarm plan.
	// extensionDir is the path to generated JS extensions (empty if none).
	ScanFunc func(ctx context.Context, moduleTags []string, moduleIDs []string, extensionDir string) error

	// PhaseCallback is called when a swarm phase starts.
	PhaseCallback func(phase string)
}

// SwarmPhase constants for the agent swarm mode.
const (
	SwarmPhaseNormalize      = "normalize"
	SwarmPhaseSourceAnalysis = "source-analysis"
	SwarmPhasePlan           = "plan"
	SwarmPhaseExtension = "extension"
	SwarmPhaseScan      = "scan"
	SwarmPhaseTriage    = "triage"
	SwarmPhaseRescan    = "rescan"
)

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
	if cfg.ScanningPhase == "" {
		cfg.ScanningPhase = "dynamic-assessment"
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
	var err error
	err = s.runSwarmPipeline(ctx, cfg, agentRun, result)

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
	// Create session directory for artifacts
	sessionDir, sdErr := EnsureSessionDir(cfg.SessionsDir, agentRun.UUID)
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir, falling back to temp dirs", zap.Error(sdErr))
	}

	// Phase 1: Normalize inputs
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

	// Phase 1.5: Source analysis (if --source provided)
	var sourceExtensionDir string
	if cfg.SourcePath != "" {
		s.emitPhase(cfg, SwarmPhaseSourceAnalysis)
		agentRun.CurrentPhase = SwarmPhaseSourceAnalysis

		saCfg := SourceAnalysisConfig{
			AgentName:    cfg.AgentName,
			TargetURL:    targetURL,
			SourcePath:   cfg.SourcePath,
			Files:        cfg.Files,
			DryRun:       cfg.DryRun,
			ScanUUID:     cfg.ScanUUID,
			ProjectUUID:  cfg.ProjectUUID,
			StreamWriter: cfg.StreamWriter,
		}

		saResult, saErr := s.engine.RunSourceAnalysis(ctx, saCfg)
		if saErr != nil {
			zap.L().Warn("Source analysis failed, continuing with input records only", zap.Error(saErr))
		} else if saResult != nil {
			// Filter source-discovered routes by target hostname and append
			sourceRecords := filterSourceRecordsByHostname(saResult.HTTPRecords, targetURL)
			if len(sourceRecords) > 0 {
				zap.L().Info("Appending source-discovered routes",
					zap.Int("total_discovered", len(saResult.HTTPRecords)),
					zap.Int("hostname_matched", len(sourceRecords)))
				records = append(records, sourceRecords...)
				result.TotalRecords = len(records)
			}

			// Write source-analysis extensions to session dir
			if len(saResult.Extensions) > 0 {
				dir, writeErr := writeExtensionsToDir(saResult.Extensions, sessionDir)
				if writeErr != nil {
					zap.L().Warn("Failed to write source-analysis extensions", zap.Error(writeErr))
				} else {
					sourceExtensionDir = dir
				}
			}

			// Write session config to session dir
			if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
				writeSessionConfigToDir(saResult.SessionConfig, sessionDir)
			}
		}
	}

	// Phase 2: Master agent — analyze and plan (batched if > 5 records)
	s.emitPhase(cfg, SwarmPhasePlan)
	agentRun.CurrentPhase = SwarmPhasePlan

	const masterBatchSize = 5
	var plan *SwarmPlan
	var sessionID string

	if len(records) <= masterBatchSize {
		plan, sessionID, err = s.runMasterAgent(ctx, cfg, records, targetURL)
	} else {
		plan, sessionID, err = s.runMasterAgentBatched(ctx, cfg, records, targetURL, masterBatchSize)
	}
	if err != nil {
		return fmt.Errorf("master agent failed: %w", err)
	}

	result.SessionID = sessionID

	if cfg.DryRun {
		result.SwarmPlan = plan
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
	}

	// Phase 3: Write generated extensions (from master agent plan)
	var extensionDir string
	if plan != nil && len(plan.Extensions) > 0 {
		s.emitPhase(cfg, SwarmPhaseExtension)
		agentRun.CurrentPhase = SwarmPhaseExtension

		dir, writeErr := writeExtensionsToDir(plan.Extensions, sessionDir)
		if writeErr != nil {
			zap.L().Warn("Failed to write generated extensions", zap.Error(writeErr))
		} else {
			extensionDir = dir
		}
	}

	// Merge source-analysis extension dir with plan extension dir
	if sourceExtensionDir != "" && extensionDir == "" {
		extensionDir = sourceExtensionDir
	}

	// Phase 4: Execute scan
	if cfg.ScanFunc != nil {
		s.emitPhase(cfg, SwarmPhaseScan)
		agentRun.CurrentPhase = SwarmPhaseScan

		// Merge user-specified modules with agent-selected ones
		tags, ids := s.mergeModules(cfg, plan)

		if err := cfg.ScanFunc(ctx, tags, ids, extensionDir); err != nil {
			return fmt.Errorf("scan execution failed: %w", err)
		}
	}

	// Phase 5-6: Triage loop (only for extension-generated findings)
	s.emitPhase(cfg, SwarmPhaseTriage)
	agentRun.CurrentPhase = SwarmPhaseTriage

	if err := s.runTriageLoop(ctx, cfg, agentRun, result); err != nil {
		zap.L().Warn("Triage failed, continuing with scan results", zap.Error(err))
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

func (s *SwarmRunner) runMasterAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string) (*SwarmPlan, string, error) {
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
		PromptTemplate: "agent-swarm-master",
		TargetURL:      targetURL,
		Hostname:       hostname,
		DryRun:         cfg.DryRun,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
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
	var lastParseErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			zap.L().Info("retrying master agent (previous output was unparseable)",
				zap.Int("attempt", attempt),
				zap.Error(lastParseErr))
		}

		result, err := s.engine.RunWithExtra(ctx, opts, map[string]string{
			"RequestContext": requestContext,
			"VulnType":       cfg.VulnType,
		})
		if err != nil {
			return nil, "", fmt.Errorf("master agent execution failed: %w", err)
		}

		lastSessionID = result.SessionID

		if cfg.DryRun {
			return nil, result.SessionID, nil
		}

		plan, parseErr := ParseSwarmPlan(result.RawOutput)
		if parseErr != nil {
			zap.L().Debug("master agent raw output (parse failed)",
				zap.String("output", result.RawOutput),
				zap.Int("attempt", attempt))
			lastParseErr = parseErr
			continue
		}

		return plan, result.SessionID, nil
	}

	return nil, lastSessionID, fmt.Errorf("failed to parse swarm plan after %d attempts: %w", maxAttempts, lastParseErr)
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

// runMasterAgentBatched calls the master agent in batches when there are many records.
// Each batch produces a SwarmPlan; plans are merged by deduplicating tags, IDs, and extensions.
func (s *SwarmRunner) runMasterAgentBatched(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, batchSize int) (*SwarmPlan, string, error) {
	var plans []*SwarmPlan
	var lastSessionID string

	for i := 0; i < len(records); i += batchSize {
		select {
		case <-ctx.Done():
			return nil, lastSessionID, ctx.Err()
		default:
		}

		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]

		zap.L().Info("Running master agent batch",
			zap.Int("batch_start", i),
			zap.Int("batch_end", end),
			zap.Int("total_records", len(records)))

		plan, sid, err := s.runMasterAgent(ctx, cfg, batch, targetURL)
		if err != nil {
			return nil, lastSessionID, fmt.Errorf("master agent batch %d-%d failed: %w", i, end, err)
		}
		if sid != "" {
			lastSessionID = sid
		}
		if plan != nil {
			plans = append(plans, plan)
		}
	}

	if len(plans) == 0 {
		return nil, lastSessionID, nil
	}
	if len(plans) == 1 {
		return plans[0], lastSessionID, nil
	}

	merged := mergeSwarmPlans(plans)
	return merged, lastSessionID, nil
}

// mergeSwarmPlans combines multiple SwarmPlans by deduplicating module tags,
// module IDs, extensions (by filename, last wins), and focus areas.
func mergeSwarmPlans(plans []*SwarmPlan) *SwarmPlan {
	tagSet := make(map[string]bool)
	idSet := make(map[string]bool)
	focusSet := make(map[string]bool)
	extMap := make(map[string]GeneratedExtension)
	var notes []string

	for _, p := range plans {
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
			extMap[ext.Filename] = ext
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

func (s *SwarmRunner) mergeModules(cfg SwarmConfig, plan *SwarmPlan) (tags []string, ids []string) {
	if plan != nil {
		tags = plan.ModuleTags
		ids = plan.ModuleIDs
	}

	// Add user-specified modules as explicit IDs
	if len(cfg.ModuleNames) > 0 {
		ids = append(ids, cfg.ModuleNames...)
	}

	return tags, ids
}

func (s *SwarmRunner) runTriageLoop(ctx context.Context, cfg SwarmConfig, agentRun *database.AgentRun, result *SwarmResult) error {
	// Only triage extension-generated findings
	// We query findings with finding_source = 'extension' for this scan
	for round := 0; round <= cfg.MaxIterations; round++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Run triage agent
		opts := Options{
			AgentName:      cfg.AgentName,
			PromptTemplate: "pipeline-triage",
			TargetURL:      agentRun.TargetURL,
			DryRun:         cfg.DryRun,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			StreamWriter:   cfg.StreamWriter,
		}

		if round > 0 {
			opts.Append = fmt.Sprintf("## Context\n\nThis is triage round %d (after rescan). Focus on new findings from the latest scan.\nIMPORTANT: Only triage findings with finding_source='extension' (agent-generated). Built-in module findings have their own confirmation logic.", round+1)
		} else {
			opts.Append = "IMPORTANT: Only triage findings with finding_source='extension' (agent-generated). Built-in module findings have their own confirmation logic and should be reported as-is."
		}

		triageResult, err := s.engine.Run(ctx, opts)
		if err != nil {
			return fmt.Errorf("triage round %d failed: %w", round, err)
		}

		if cfg.DryRun {
			return nil
		}

		triage, err := ParseTriageResult(triageResult.RawOutput)
		if err != nil {
			zap.L().Warn("Failed to parse triage result, treating as done", zap.Error(err))
			return nil
		}

		result.TriageResults = append(result.TriageResults, triage)
		result.Confirmed += len(triage.Confirmed)
		result.FalsePositives += len(triage.FalsePositives)
		result.Iterations = round + 1

		triageJSON, _ := json.Marshal(triage)
		agentRun.TriageResult = string(triageJSON)

		if triage.Verdict != "rescan" || len(triage.FollowUps) == 0 || round >= cfg.MaxIterations {
			break
		}

		// Rescan with follow-up modules
		if cfg.ScanFunc != nil {
			s.emitPhase(cfg, SwarmPhaseRescan)
			agentRun.CurrentPhase = SwarmPhaseRescan

			var followTags, followIDs []string
			for _, fu := range triage.FollowUps {
				followTags = append(followTags, fu.ModuleTags...)
				followIDs = append(followIDs, fu.ModuleIDs...)
			}

			if err := cfg.ScanFunc(ctx, followTags, followIDs, ""); err != nil {
				zap.L().Warn("Rescan failed", zap.Int("round", round+1), zap.Error(err))
				break
			}
		}
	}

	return nil
}
