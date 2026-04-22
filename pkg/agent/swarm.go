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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/backend"
	agentinput "github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/agent/parsing"
	agentprompt "github.com/vigolium/vigolium/pkg/agent/prompt"
	"github.com/vigolium/vigolium/pkg/archon/claudecost"
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
	SourcePath  string                  // path to application source code (triggers source analysis phase)
	Files       []string                // specific files to include (relative to SourcePath)
	DiffContext *agenttypes.DiffContext // non-nil when --diff or --last-commits was provided

	// Custom instruction
	Instruction string // user-provided custom instruction appended to agent prompts

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
	Auth               bool   // run browser-based auth phase before discovery (--auth, requires Browser)
	Credentials        string // optional credentials for browser auth phase (--credentials)
	CredentialSets     []agenttypes.IntentCredentialSet
	AuthRequired       bool
	RequiresBrowser    bool
	BrowserStartURL    string
	FocusRoutes        []string

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

	// Archon enables the background archon-audit when set.
	// Requires SourcePath to be non-empty.
	Archon *config.AuditAgentConfig
}

// Prompt template constants for the agent swarm mode.
const (
	SwarmPromptPlan       = "agent-swarm-plan"
	SwarmPromptExtensions = "agent-swarm-extensions"
	SwarmPromptCodeAudit  = "swarm-code-audit"
	SwarmPromptSASTReview = "swarm-sast-review"
	SwarmPromptTriage     = "agent-swarm-triage"
	SwarmPromptAuth       = "agent-swarm-auth"
)

// SwarmPhaseDescription returns a short description of what a swarm phase does.
func SwarmPhaseDescription(phase string) string {
	switch phase {
	case SwarmPhaseNormalize:
		return "parse and normalize input targets into scannable HTTP records"
	case SwarmPhaseAuth:
		return "browser-based authentication — login to capture session cookies for authenticated scanning"
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
	case SwarmPhaseAuth:
		return SwarmPromptAuth
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

type swarmRecordStats struct {
	Initial   int
	Source    int
	SAST      int
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

	// Set up context cache for DB enrichment across phases
	if s.engine != nil {
		s.engine.SetContextCache(agentprompt.NewContextCache(30 * time.Second))
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
		protocol, model = s.engine.settings.Agent.BackendMeta(cfg.AgentName)
	}
	// Create agent run record — use pre-assigned UUID if provided (e.g. from CLI session dir)
	runUUID := cfg.RunUUID
	if runUUID == "" {
		runUUID = uuid.New().String()
	}
	agenticScan := &database.AgenticScan{
		UUID:        runUUID,
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
		if err := s.repo.CreateAgenticScan(ctx, agenticScan); err != nil {
			zap.L().Warn("Failed to create agent run record", zap.Error(err))
		}
	}

	result := &SwarmResult{AgenticScanUUID: runUUID}

	// Execute phases
	err := s.runSwarmPipeline(ctx, cfg, agenticScan, result)

	// Finalize
	result.Duration = time.Since(start)
	now := time.Now()
	agenticScan.CompletedAt = now
	agenticScan.DurationMs = result.Duration.Milliseconds()
	agenticScan.FindingCount = result.TotalFindings
	usage := claudecost.Usage{
		InputTokens:  int64(result.TokenUsage.InputTokens),
		OutputTokens: int64(result.TokenUsage.OutputTokens),
	}
	agenticScan.TotalInputTokens = usage.InputTokens
	agenticScan.TotalOutputTokens = usage.OutputTokens
	agenticScan.EstimatedCostUSD = usage.Price(agenticScan.Model)

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
		SASTRecords:      stats.SAST,
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

func (s *SwarmRunner) normalizeInputs(ctx context.Context, cfg SwarmConfig) ([]*httpmsg.HttpRequestResponse, string, error) {
	var allRecords []*httpmsg.HttpRequestResponse
	var targetURL string

	for _, input := range cfg.Inputs {
		records, err := agentinput.NormalizeInput(ctx, input, cfg.InputType, s.repo)
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

// buildRecordSummary generates a compact one-line-per-record summary of ALL records.
// This is appended to the plan agent context when records were filtered down by
// selectPlanRecords, so the agent sees the full API surface at a glance even when
// only the top-N most interesting records have full request/response details.
func buildRecordSummary(records []*httpmsg.HttpRequestResponse) string {
	if len(records) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n## All Discovered Endpoints (summary)\n\n")
	b.WriteString("| # | Method | Path | Status |\n")
	b.WriteString("|---|--------|------|--------|\n")
	for i, rr := range records {
		method := "?"
		path := "?"
		status := "?"
		if req := rr.Request(); req != nil {
			method = req.Method()
			path = req.Path()
			if qIdx := strings.Index(path, "?"); qIdx >= 0 {
				path = path[:qIdx]
			}
		}
		if rr.HasResponse() {
			status = fmt.Sprintf("%d", rr.Response().StatusCode())
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", i+1, method, path, status)
	}
	return b.String()
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
func (s *SwarmRunner) runMasterAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, extraSummary ...string) (plan *SwarmPlan, sessionID string, rawOutput string, renderedPrompt string, err error) {
	// Pre-compute request context once for both phases
	requestContext := buildSmartHTTPContext(records, cfg.MaxResponseBodyBytes)
	// Append record summary (if provided) so the agent sees the full API surface
	if len(extraSummary) > 0 && extraSummary[0] != "" {
		requestContext += extraSummary[0]
	}

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

	// Retry loop — retries on both parse failures and transient agent errors (timeouts, etc.).
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
			opts.Append = buildPlanRetryFeedback(effectiveVulnType, lastErr, lastRawOutput)
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

		parsed, parseErr := parsing.ParseSwarmPlan(result.RawOutput)
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
	parsed, parseErr := parsing.ParseSwarmExtensions(result.RawOutput)
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

	existing := make(map[string]string, len(source)) // filename -> code
	nameSet := make(map[string]bool, len(source))    // maintained for deduplicateExtensionFilename
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
		// Source-only mode: keep all records without hostname filtering.
		normalized, _ := parsing.NormalizeAgentRecords(agentRecords)
		var passthrough []*httpmsg.HttpRequestResponse
		var passthroughNotes []string
		for _, rec := range normalized {
			rr, convertErr := ToHTTPRequestResponse(rec)
			if convertErr != nil {
				continue
			}
			passthrough = append(passthrough, rr)
			passthroughNotes = append(passthroughNotes, rec.Notes)
		}
		return passthrough, passthroughNotes
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
	normalized, dropped := parsing.NormalizeAgentRecords(agentRecords)
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
func (s *SwarmRunner) runMasterAgentBatched(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, batchSize int, recordSummary string) (*SwarmPlan, string, string, string, []string, *BatchProvenance, error) {
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
		// Default to 3: agent sessions are I/O-bound (LLM API), not CPU-bound.
		// NumCPU was too aggressive — each session uses 200-500MB and hits rate limits.
		batchConcurrency = 3
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
			plan, sid, rawOutput, prompt, err := s.runMasterAgent(gCtx, cfg, batch, targetURL, recordSummary)
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
	var orderedResults []batchResult
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
		orderedResults = append(orderedResults, r)
		if r.sessionID != "" {
			lastSessionID = r.sessionID
			allSessionIDs = append(allSessionIDs, r.sessionID)
		}
	}

	sort.Slice(orderedResults, func(i, j int) bool {
		return orderedResults[i].batchNum < orderedResults[j].batchNum
	})

	var plans []*SwarmPlan
	for _, r := range orderedResults {
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

func (s *SwarmRunner) runTriageLoop(ctx context.Context, cfg SwarmConfig, agenticScan *database.AgenticScan, result *SwarmResult, sessionDir string, extensionDir string, checkpoint *SwarmCheckpoint, extensionRenames map[string]string, completedPhases []string) error {
	// Determine triage resume point from checkpoint
	triageResumeRound := 0
	triageFindingFloor := int64(0)
	if checkpoint != nil && checkpoint.TriageRound > 0 {
		triageResumeRound = checkpoint.TriageRound
		triageFindingFloor = checkpoint.LastFindingID
		zap.L().Info("Resuming triage from checkpoint",
			zap.Int("resume_round", triageResumeRound),
			zap.Int64("finding_floor", triageFindingFloor))
	}

	triageCfg := TriageLoopConfig{
		Engine:                    s.engine,
		Repository:                s.repo,
		AgentName:                 cfg.AgentName,
		PromptTemplate:            SwarmPromptTriage,
		TargetURL:                 agenticScan.TargetURL,
		Hostname:                  hostnameFromURL(agenticScan.TargetURL),
		SourcePath:                cfg.SourcePath,
		Instruction:               cfg.Instruction,
		SessionKey:                SwarmPhaseTriage,
		DryRun:                    cfg.DryRun,
		ShowPrompt:                cfg.ShowPrompt,
		ScanUUID:                  cfg.ScanUUID,
		ProjectUUID:               cfg.ProjectUUID,
		AgenticScanUUID:           agenticScan.UUID,
		StreamWriter:              cfg.StreamWriter,
		MaxRounds:                 cfg.MaxIterations,
		MaxFindingsPerTriageBatch: 25,
		ResumeFromRound:           triageResumeRound,
		ProgressCallback:          cfg.ProgressCallback,
		ScanFunc:                  cfg.ScanFunc,
		SessionDir:                sessionDir,
		ExtensionDir:              extensionDir,
		InitialFindingIDFloor:     triageFindingFloor,
		OnRescan: func() {
			s.emitPhase(cfg, SwarmPhaseRescan)
			agenticScan.CurrentPhase = SwarmPhaseRescan
			s.persistPhase(ctx, agenticScan)
			// Invalidate context cache — rescan may produce new findings
			if s.engine != nil {
				s.engine.InvalidateContextCache()
			}
		},
		OnTriageRoundComplete: func(round int) {
			if cpErr := s.writeSwarmCheckpoint(sessionDir, cfg.ProjectUUID, completedPhases, agenticScan.TargetURL, result.TotalRecords, result.SwarmPlan, extensionDir, round+1, extensionRenames, result, swarmRecordStats{}); cpErr != nil {
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
		agenticScan.TriageResult = string(triageJSON)
	}

	return nil
}

// runSASTReview spawns a sub-agent to review SAST findings and validate extracted routes.
// It queries SAST findings from the database, formats them for the agent, and parses
// the response as a SourceAnalysisResult (validated routes + optional extensions).
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
	findings, parseErr := parsing.ParseFindings(agentResult.RawOutput)
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
func (s *SwarmRunner) validateProbeAndSave(ctx context.Context, records []*httpmsg.HttpRequestResponse, notes []string, authHeaders map[string]string, source, projectUUID string, pc ProbeConfig) []string {
	if len(records) == 0 {
		return nil
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
		var savedUUIDs []string
		remarksMap := make(map[string][]string)
		for i, rr := range valid {
			savedUUID, saveErr := s.repo.SaveRecord(ctx, rr, source, projectUUID)
			if saveErr != nil {
				zap.L().Debug("Failed to save record", zap.String("source", source), zap.Error(saveErr))
			} else {
				savedCount++
				savedUUIDs = append(savedUUIDs, savedUUID)
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
		return savedUUIDs
	}
	return nil
}

// ProbeConfig holds tuning parameters for HTTP record probing.
type ProbeConfig struct {
	Concurrency int                        // max parallel probe requests; 0 = default 10
	Timeout     time.Duration              // per-request probe timeout; 0 = default 10s
	MaxBodySize int                        // max response body bytes; 0 = default 2MB
	OnProgress  func(completed, total int) // optional progress callback
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
	backend.ReprobeUnprobedRecords(ctx, s.repo, projectUUID, hostname, authHeaders, source)
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
			if backend.IsAuthHeader(h.Name) {
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
