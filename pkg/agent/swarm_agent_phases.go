package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/agent/parsing"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"

	"go.uber.org/zap"
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
	case SwarmPhaseDiscover:
		return "crawl and spider targets to discover additional endpoints"
	case SwarmPhaseRecon:
		return "lightweight tech-stack reconnaissance — probe well-known paths, OPTIONS/CORS, security headers, and API specs to enrich the planner's context"
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
	case SwarmPhasePlan:
		return SwarmPromptPlan
	case SwarmPhaseTriage:
		return SwarmPromptTriage
	default:
		return ""
	}
}

// runMasterAgent orchestrates the two-phase plan+extension agent flow.
// Phase 1 (plan) produces module tags, IDs, focus areas, and notes using a
// simple markdown-section format that is highly resistant to LLM output errors.
// Phase 2 (extensions) is conditional — it only runs when the plan indicates
// custom extensions are needed — and produces JavaScript code blocks in isolation.
// If Phase 2 fails, the plan from Phase 1 is still valid and the scan proceeds
// without custom extensions (graceful degradation).
// runMasterAgent's techStackMd parameter is the pre-rendered recon
// markdown (see pkg/agent/recon). Pass "" when no recon ran (e.g.
// --source mode or --skip recon); the prompt template handles an empty
// TechStack gracefully.
func (s *SwarmRunner) runMasterAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, techStackMd string, extraSummary ...string) (plan *SwarmPlan, rawOutput string, renderedPrompt string, err error) {
	// Pre-compute request context once for both phases
	requestContext := buildSmartHTTPContext(records, cfg.MaxResponseBodyBytes)
	// Append record summary (if provided) so the agent sees the full API surface
	if len(extraSummary) > 0 && extraSummary[0] != "" {
		requestContext += extraSummary[0]
	}

	// Phase 1: Plan agent — analyze and select modules (no code generation)
	plan, _, rawOutput, renderedPrompt, err = s.runPlanAgent(ctx, cfg, records, targetURL, requestContext, techStackMd)
	if err != nil {
		return nil, rawOutput, renderedPrompt, err
	}
	if cfg.DryRun || plan == nil {
		return plan, rawOutput, renderedPrompt, nil
	}

	// Normalize parsed plan: clean tags/IDs, strip inline commentary
	normalizePlan(plan)

	// Phase 2: Extension agent — generate custom JS extensions (conditional).
	// Runs when the plan agent flagged it OR when --with-extensions forced it.
	if cfg.ForceExtensions || planNeedsExtensions(plan) {
		extPlan, extRaw, extErr := s.runExtensionAgentWithRetry(ctx, cfg, records, targetURL, plan, requestContext, techStackMd)
		if extErr != nil {
			// Graceful degradation: log the error but proceed with the plan from Phase 1.
			// Stamp the error onto the plan so the Plan-phase summary can surface Case C.
			plan.ExtensionAgentError = extErr.Error()
			zap.L().Warn("Extension agent failed after retries — scanning without custom extensions",
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
		}
	}

	return plan, rawOutput, renderedPrompt, nil
}

// runPlanAgent executes Phase 1: analysis and module selection.
// The prompt asks for markdown sections only (no JSON, no code), making parsing robust.
func (s *SwarmRunner) runPlanAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, requestContext string, techStackMd string) (plan *SwarmPlan, sessionID string, rawOutput string, renderedPrompt string, err error) {
	hostname := ""
	if targetURL != "" {
		hostname = hostnameFromURL(targetURL)
	}

	opts := Options{
		AgentName:      cfg.AgentName,
		PromptTemplate: SwarmPromptPlan,
		TargetURL:      targetURL,
		Hostname:       hostname,
		SourcePath:     cfg.SourcePath,
		Instruction:    cfg.Instruction,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		Verbose:        cfg.Verbose,
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

		// Pass the full skill registry so the planner sees the <available_skills>
		// menu and can populate recommended_skills for the triage phase.
		result, runErr := s.engine.RunWithExtraSkills(ctx, opts, map[string]string{
			"RequestContext": extraContext,
			"VulnType":       effectiveVulnType,
			"TechStack":      techStackMd,
		}, s.skills)
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

		lastRawOutput = result.RawOutput
		lastRenderedPrompt = result.RenderedPrompt

		if cfg.DryRun {
			return nil, "", result.RawOutput, result.RenderedPrompt, nil
		}

		parsed, parseErr := parsing.ParseSwarmPlan(result.RawOutput)
		if parseErr != nil {
			zap.L().Debug("plan agent raw output (parse failed)",
				zap.String("output", result.RawOutput),
				zap.Int("attempt", attempt))
			lastErr = parseErr
			continue
		}

		return parsed, "", result.RawOutput, result.RenderedPrompt, nil
	}

	return nil, "", lastRawOutput, lastRenderedPrompt, fmt.Errorf("failed to parse plan after %d attempts: %w", maxAttempts, lastErr)
}

// runExtensionAgentWithRetry adds (a) a cache keyed by target + plan
// focus/tags/IDs so retries and batched fan-out share results, and (b)
// a 3-attempt outer retry on parse failures (runExtensionAgent's inner
// retry only handles transient LLM errors).
func (s *SwarmRunner) runExtensionAgentWithRetry(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, plan *SwarmPlan, requestContext string, techStackMd string) (extPlan *SwarmPlan, rawOutput string, err error) {
	cacheKey := extensionCacheKey(targetURL, plan)
	if cacheKey != "" {
		if v, ok := s.extensionCache.Load(cacheKey); ok {
			entry := v.(extensionCacheEntry)
			zap.L().Info("Extension agent cache hit — reusing prior result",
				zap.String("cache_key", cacheKey),
				zap.Int("extensions", len(entry.Plan.Extensions)))
			return entry.Plan, entry.RawOutput, nil
		}
	}

	const maxAttempts = 3
	var lastErr error
	var lastRaw string
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var extPlan2 *SwarmPlan
		var raw string
		extPlan2, _, raw, _, lastErr = s.runExtensionAgent(ctx, cfg, records, targetURL, plan, requestContext, techStackMd)
		lastRaw = raw
		if lastErr == nil {
			if cacheKey != "" && extPlan2 != nil && len(extPlan2.Extensions)+len(extPlan2.QuickChecks)+len(extPlan2.Snippets) > 0 {
				s.extensionCache.Store(cacheKey, extensionCacheEntry{Plan: extPlan2, RawOutput: raw})
			}
			return extPlan2, raw, nil
		}
		if attempt < maxAttempts {
			zap.L().Warn("Extension agent parse/run failed, will retry",
				zap.Int("attempt", attempt),
				zap.Error(lastErr))
		}
	}
	return nil, lastRaw, lastErr
}

// extensionCacheKey produces a stable cache key from the inputs that
// drive extension generation: target URL + the plan's focus areas +
// module tags + module IDs. Two runs of the swarm against the same site
// with the same plan deserve to share extensions; runs with different
// plans get different keys.
//
// Returns "" when there's nothing usable to key on (empty target, no
// focus signal) — callers treat that as "don't cache", which is the
// right default for inputs the LLM may interpret differently each time.
func extensionCacheKey(targetURL string, plan *SwarmPlan) string {
	if plan == nil {
		return ""
	}
	host := ""
	if targetURL != "" {
		host = hostnameFromURL(targetURL)
	}
	if host == "" && len(plan.FocusAreas) == 0 {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(host))
	h.Write([]byte{0})
	// FocusAreas / ModuleTags / ModuleIDs come from a parsed/normalized
	// SwarmPlan, but the order isn't guaranteed across calls (merging
	// from batches re-sorts). Sort defensively.
	for _, x := range sortedCopy(plan.FocusAreas) {
		h.Write([]byte(x))
		h.Write([]byte{0})
	}
	h.Write([]byte{1})
	for _, x := range sortedCopy(plan.ModuleTags) {
		h.Write([]byte(x))
		h.Write([]byte{0})
	}
	h.Write([]byte{1})
	for _, x := range sortedCopy(plan.ModuleIDs) {
		h.Write([]byte(x))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// runExtensionAgent executes Phase 2: custom extension generation.
// It receives the parsed plan as context so the agent focuses only on writing code.
// This is isolated from the plan phase — if it fails, the plan is still valid.
func (s *SwarmRunner) runExtensionAgent(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, plan *SwarmPlan, requestContext string, techStackMd string) (extPlan *SwarmPlan, sessionID string, rawOutput string, renderedPrompt string, err error) {
	hostname := ""
	if targetURL != "" {
		hostname = hostnameFromURL(targetURL)
	}

	// Build plan context summary for the extension agent
	planContext := buildPlanContext(plan)

	opts := Options{
		AgentName:      cfg.AgentName,
		PromptTemplate: SwarmPromptExtensions,
		TargetURL:      targetURL,
		Hostname:       hostname,
		SourcePath:     cfg.SourcePath,
		Instruction:    cfg.Instruction,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		Verbose:        cfg.Verbose,
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
			"TechStack":      techStackMd,
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

	if cfg.DryRun {
		return nil, "", result.RawOutput, result.RenderedPrompt, nil
	}

	// Parse extensions from the output — we only care about extensions, quick_checks, snippets
	parsed, parseErr := parsing.ParseSwarmExtensions(result.RawOutput)
	if parseErr != nil {
		return nil, "", result.RawOutput, result.RenderedPrompt,
			fmt.Errorf("extension agent output unparseable: %w", parseErr)
	}

	return parsed, "", result.RawOutput, result.RenderedPrompt, nil
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

// runMasterAgentBatched calls the master agent in parallel batches when there are many records.
// Each batch produces a SwarmPlan; plans are merged incrementally as results arrive.
// On first error, remaining in-flight batches are cancelled and the partial merged plan is returned.
func (s *SwarmRunner) runMasterAgentBatched(ctx context.Context, cfg SwarmConfig, records []*httpmsg.HttpRequestResponse, targetURL string, batchSize int, recordSummary string, techStackMd string) (*SwarmPlan, string, string, *BatchProvenance, error) {
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
			plan, rawOutput, prompt, err := s.runMasterAgent(gCtx, cfg, batch, targetURL, techStackMd, recordSummary)
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
		return mergedPlan, combinedRaw, lastPrompt, batchProv, firstErr
	}

	return mergedPlan, combinedRaw, lastPrompt, batchProv, nil
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

	var needsExt bool
	var needsExtReason string
	var extAgentErr string
	for batchIdx, p := range plans {
		batchNum := batchIdx + 1
		if p.NeedsExtensions {
			needsExt = true
			if needsExtReason == "" && p.NeedsExtensionsReason != "" {
				needsExtReason = p.NeedsExtensionsReason
			}
		}
		if extAgentErr == "" && p.ExtensionAgentError != "" {
			extAgentErr = p.ExtensionAgentError
		}
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
		ModuleTags:            sortedKeys(tagSet),
		ModuleIDs:             sortedKeys(idSet),
		FocusAreas:            sortedKeys(focusSet),
		Notes:                 strings.Join(notes, "; "),
		NeedsExtensions:       needsExt,
		NeedsExtensionsReason: needsExtReason,
		ExtensionAgentError:   extAgentErr,
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
