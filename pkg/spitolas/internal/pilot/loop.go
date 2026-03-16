package pilot

import (
	"context"
	"fmt"
	"strings"
	"time"

	acp "github.com/coder/acp-go-sdk"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
	"go.uber.org/zap"
)

// Result holds the outcome of a pilot-driven crawl.
type Result struct {
	StatesDiscovered     int
	ActionsExecuted      int
	CheckpointsCompleted int
	CheckpointsPending   int
	Duration             time.Duration
}

// Run executes the pilot-driven crawl loop.
// It starts a browser, an in-process MCP HTTP server for tool dispatch,
// and runs ACP agent sessions that connect to the MCP server.
// All crawl state is managed in Go and survives ACP session boundaries —
// each new session receives a complete briefing via buildSessionBriefing().
func (bc *PilotCrawler) Run(ctx context.Context) (*Result, error) {
	startTime := time.Now()

	zap.L().Info("starting pilot-driven crawl",
		zap.String("target", bc.config.URL.String()))

	// Step 1: Get a browser page
	browser := bc.browserPool.Get()
	if browser == nil {
		return nil, fmt.Errorf("no browser available in pool")
	}
	page, err := browser.NewPage()
	if err != nil {
		return nil, fmt.Errorf("create browser page: %w", err)
	}
	bc.currentPage = page

	// Step 2: Start network capture
	if bc.capture != nil {
		if err := bc.capture.Start(browser.RodBrowser()); err != nil {
			zap.L().Warn("failed to start network capture", zap.Error(err))
		}
	}

	// Step 3: Navigate to target
	if err := page.Navigate(bc.config.URL.String()); err != nil {
		return nil, fmt.Errorf("navigate to target: %w", err)
	}
	_ = page.WaitStable(bc.config.DOMStableTime)

	// Step 4: Capture initial state
	html, err := page.HTMLWithFramesFiltered(bc.config.CrawlFrames, bc.config.ExcludeFrames)
	if err != nil {
		return nil, fmt.Errorf("get initial HTML: %w", err)
	}
	pageURL, _ := page.URL()
	strippedDOM := state.StripDOM(html, bc.config.DOMStripTags, bc.config.DOMStripAttrs)
	indexState := state.New(pageURL, html, strippedDOM, 0)
	bc.graph.AddState(indexState)
	bc.currentState = indexState

	// Step 5: Auto-detect blacklist entries
	bc.autoDetectBlacklist(ctx)

	// Step 6: Load persisted checkpoints (crash recovery)
	if err := bc.checkpoints.Load(); err != nil {
		zap.L().Warn("failed to load checkpoints", zap.Error(err))
	}

	zap.L().Info("pilot initial state captured",
		zap.String("state", indexState.Name),
		zap.String("url", pageURL),
		zap.Int("blacklistEntries", len(bc.blacklist.All())))

	// Write trace header and system prompt
	bc.trace.WriteHeader(bc.config.URL.String(), bc.pilotConfig)
	bc.trace.WriteSystemPrompt(systemPrompt)

	// Step 7: Start in-process MCP HTTP server
	mcpServer, err := newMCPHTTPServer(ctx, bc)
	if err != nil {
		return nil, fmt.Errorf("start mcp server: %w", err)
	}
	defer mcpServer.Stop()

	// Step 8: Inject pilot system prompt into ACP session metadata
	if bc.agentDef.SessionMeta == nil {
		bc.agentDef.SessionMeta = &config.ACPSessionMeta{}
	}
	if bc.agentDef.SessionMeta.SystemPrompt == nil {
		bc.agentDef.SessionMeta.SystemPrompt = &config.ACPSystemPrompt{}
	}
	if bc.agentDef.SessionMeta.SystemPrompt.Append != "" {
		bc.agentDef.SessionMeta.SystemPrompt.Append += "\n\n" + systemPrompt
	} else {
		bc.agentDef.SessionMeta.SystemPrompt.Append = systemPrompt
	}

	// Step 9: Spawn a single ACP session — reused across all prompt turns.
	// Unlike RunACP (which spawns+kills per call), we keep the subprocess
	// alive and send follow-up prompts on the same session.
	mcpServers := []acp.McpServer{
		{Http: &acp.McpServerHttp{
			Name:    "vigolium-pilot",
			Url:     mcpServer.URL() + "/mcp",
			Headers: []acp.HttpHeader{},
		}},
	}

	sess, spawnErr := spawnPilotSession(ctx, bc.agentDef, mcpServers, bc.agentDef.SessionMeta)
	if spawnErr != nil {
		return nil, fmt.Errorf("spawn pilot ACP session: %w", spawnErr)
	}
	defer sess.Kill()

	maxAttempts := bc.pilotConfig.MaxRetries + 1

	// Stall timeout: if the agent makes no tool calls for this duration,
	// cancel the current prompt and send a follow-up. The subprocess stays
	// alive — only the Prompt call is interrupted.
	stallTimeout := bc.pilotConfig.StallTimeout
	if stallTimeout == 0 {
		stallTimeout = 7 * time.Minute
	}

	var lastACPErr error
	attempt := 0
	for attempt < maxAttempts {
		attempt++
		// Check parent context before starting a new attempt
		if ctx.Err() != nil {
			break
		}

		prompt, buildErr := bc.buildSessionBriefing(ctx, attempt, maxAttempts)
		if buildErr != nil {
			zap.L().Warn("failed to build session briefing", zap.Error(buildErr))
			break
		}

		// Trace: session start and full briefing
		bc.trace.WriteSessionStart(attempt, maxAttempts)
		bc.trace.WriteBriefing(prompt)

		// Each attempt inherits the parent deadline (no time-splitting).
		// The stall timer handles "is this session productive?" by cancelling
		// the prompt if no MCP tool call is received within stallTimeout.
		attemptCtx, attemptCancel := context.WithCancel(ctx)
		bc.setStallTimer(newStallTimer(stallTimeout, attemptCancel))

		discovered, _, completed, _ := bc.checkpoints.Stats()
		zap.L().Info("sending ACP prompt",
			zap.Int("attempt", attempt),
			zap.Int("maxAttempts", maxAttempts),
			zap.Int("checkpointsCompleted", completed),
			zap.Int("checkpointsPending", discovered),
			zap.Duration("stallTimeout", stallTimeout),
			zap.Int("promptLength", len(prompt)))

		acpResult, acpErr := sess.Prompt(attemptCtx, prompt)
		stalled := bc.stopStallTimer()
		attemptCancel()

		// Agent called terminate_crawl — clean exit
		if bc.terminated.Load() {
			zap.L().Info("pilot terminated by agent request")
			bc.trace.WriteSessionEnd("terminated by agent", nil)
			lastACPErr = nil
			break
		}

		if acpErr == nil {
			// Agent finished its turn cleanly. Check if there's more work.
			discovered, _, completed, _ := bc.checkpoints.Stats()
			activeCP := bc.checkpoints.Active()
			replayID := bc.checkpoints.ReplayingID()

			if discovered == 0 && activeCP == nil && replayID == "" {
				// All checkpoints done — clean exit
				zap.L().Info("pilot ACP prompt completed",
					zap.String("sessionID", acpResult.SessionID))
				bc.trace.WriteSessionEnd("completed", nil)
				lastACPErr = nil
				break
			}

			// Pending work remains — send follow-up prompt
			zap.L().Info("pilot turn ended with pending work, sending follow-up",
				zap.Int("pending", discovered),
				zap.Int("completed", completed))
			bc.trace.WriteSessionEnd("follow-up (pending checkpoints)", nil)
			time.Sleep(2 * time.Second)
			attempt = 0 // agent responded — reset consecutive failure counter
			continue
		}

		lastACPErr = acpErr

		// Subprocess crashed — can't continue
		if !sess.Alive() {
			zap.L().Warn("pilot ACP subprocess died", zap.Error(acpErr))
			bc.trace.WriteSessionEnd("subprocess died", acpErr)
			break
		}

		// Parent context expired — hard stop
		if ctx.Err() != nil {
			bc.trace.WriteSessionEnd("context cancelled", ctx.Err())
			break
		}

		// Stall detected — agent stopped making tool calls, send follow-up
		if stalled {
			zap.L().Warn("pilot stalled — no tool calls received, sending follow-up prompt",
				zap.Duration("stallTimeout", stallTimeout),
				zap.Int("attempt", attempt))
			bc.trace.WriteSessionEnd("stalled", acpErr)
		} else {
			// ACP error (prompt failure, etc.) — retryable via follow-up
			retryable := isACPPromptTimeout(acpErr) || isACPPromptError(acpErr)
			if !retryable {
				zap.L().Warn("pilot ACP failed with non-retryable error",
					zap.Error(acpErr),
					zap.String("output", acpResult.Stdout))
				bc.trace.WriteSessionEnd("non-retryable error", acpErr)
				break
			}
			bc.trace.WriteSessionEnd("retrying", acpErr)
		}

		if attempt < maxAttempts {
			discovered, _, completed, _ = bc.checkpoints.Stats()

			// Don't retry if all checkpoints are completed and depth phase is done
			if discovered == 0 && bc.crawlPhase == PhaseDepth && bc.checkpoints.Active() == nil && bc.checkpoints.ReplayingID() == "" && completed > 0 {
				zap.L().Info("all checkpoints completed, not retrying despite ACP error",
					zap.Int("completed", completed))
				bc.trace.WriteSessionEnd("all checkpoints completed", acpErr)
				break
			}

			zap.L().Info("pilot sending follow-up prompt",
				zap.Int("attempt", attempt),
				zap.Int("completed", completed),
				zap.Int("pending", discovered),
				zap.Int("states", bc.graph.StateCount()),
				zap.Error(acpErr))

			// Brief pause before follow-up prompt
			time.Sleep(2 * time.Second)
		} else {
			bc.trace.WriteSessionEnd("max attempts reached", acpErr)
		}
	}

	// Build result
	discovered, _, completed, _ := bc.checkpoints.Stats()
	result := &Result{
		StatesDiscovered:     bc.graph.StateCount(),
		ActionsExecuted:      bc.trace.Len(),
		CheckpointsCompleted: completed,
		CheckpointsPending:   discovered,
		Duration:             time.Since(startTime),
	}

	// Trace: final summary
	bc.trace.WriteSummary(result)

	return result, lastACPErr
}

// buildSessionBriefing constructs a complete prompt for any ACP session.
// It includes ALL Go-managed state so the agent can immediately resume work.
func (bc *PilotCrawler) buildSessionBriefing(ctx context.Context, attempt, maxAttempts int) (string, error) {
	pageState, err := bc.SerializePage(ctx, bc.currentPage, bc.currentState)
	if err != nil {
		return "", fmt.Errorf("serialize page state: %w", err)
	}

	var b strings.Builder

	// Session context
	if attempt > 1 {
		fmt.Fprintf(&b, "## SESSION %d of %d\n\n", attempt, maxAttempts)
		b.WriteString("Previous session ended. All state preserved in Go. Resume immediately.\n\n")
	}

	// Target
	b.WriteString("## Target\n")
	fmt.Fprintf(&b, "URL: %s\n\n", bc.config.URL.String())

	// Authentication
	if bc.pilotConfig.Auth.Enabled {
		bc.renderAuthConfig(&b)
	}

	// Task directive — checkpoint-aware
	bc.renderTaskDirective(&b)

	// Active checkpoint details (if any)
	bc.renderActiveCheckpoint(&b)

	// Checkpoint list is in the Checkpoint Compass (part of page state).
	// Not duplicated here to save tokens.

	// Recent actions (from active checkpoint or global)
	bc.renderRecentActions(&b, 10)

	// Blacklisted elements
	bc.renderBlacklistBriefing(&b)

	// Stored credentials
	bc.renderCredentialsBriefing(&b)

	// Created entities
	bc.renderEntitiesBriefing(&b)

	// Current page state (includes Checkpoint Compass)
	b.WriteString("## Current Page State\n\n")
	b.WriteString(pageState)

	return b.String(), nil
}

// renderAuthConfig writes the authentication configuration section.
func (bc *PilotCrawler) renderAuthConfig(b *strings.Builder) {
	b.WriteString("## Authentication\n")
	if bc.pilotConfig.Auth.Username != "" {
		fmt.Fprintf(b, "Credentials: username=%q, password=%q\n",
			bc.pilotConfig.Auth.Username, bc.pilotConfig.Auth.Password)
		b.WriteString("Try these when you reach a login page. Max 3 attempts, then move on.\n\n")
	} else if bc.pilotConfig.Auth.AutoRegister {
		b.WriteString("No credentials. Auto-register enabled — try registration if found.\n\n")
	}
}

// renderTaskDirective writes the checkpoint-aware task instruction.
// Handles all continuation states: mid-replay, active checkpoint, idle.
func (bc *PilotCrawler) renderTaskDirective(b *strings.Builder) {
	discovered, _, completed, _ := bc.checkpoints.Stats()
	total := discovered + completed

	b.WriteString("## YOUR TASK\n\n")

	// Case 1: Replay was in progress when session died
	replayID, cursor, rState, totalSteps := bc.checkpoints.GetReplayState()
	if replayID != "" {
		cp, _ := bc.checkpoints.Get(replayID)
		if cp != nil {
			if rState == replayWaitingForHelp && cursor < totalSteps {
				step := cp.NavigationSteps[cursor]
				fmt.Fprintf(b, "RESUME: You were navigating to checkpoint %q (%s).\n", cp.Name, replayID)
				fmt.Fprintf(b, "Step %d/%d failed: %s — intent: %q\n", cursor+1, totalSteps, step.Tool, step.Intent)
				b.WriteString("Look at the current page state and fix this step manually (click/type the right element).\n")
				b.WriteString("Then call resume_replay() to continue. Or call abort_replay() to skip this checkpoint.\n\n")
			} else {
				fmt.Fprintf(b, "RESUME: Navigation to checkpoint %q (%s) was interrupted.\n", cp.Name, replayID)
				fmt.Fprintf(b, "Call go_to_checkpoint(%q) to restart navigation from root.\n\n", replayID)
			}
			return
		}
	}

	// Case 2: Active checkpoint (was exploring when session died)
	activeCP := bc.checkpoints.Active()
	if activeCP != nil {
		fmt.Fprintf(b, "RESUME: Continue exploring checkpoint %q (%s).\n", activeCP.Name, activeCP.ID)
		fmt.Fprintf(b, "Test plan: %s\n", activeCP.TestPlan)
		fmt.Fprintf(b, "Actions so far: %d. Complete it with complete_checkpoint() when done.\n\n", activeCP.ActionCount)
		return
	}

	// Case 3: No checkpoints discovered yet
	if total == 0 {
		b.WriteString("Explore the application. Identify ALL features and call create_checkpoint() for each.\n")
		b.WriteString("You can create MULTIPLE checkpoints on a single page.\n\n")
		return
	}

	// Case 4: Pending checkpoints to explore
	if discovered > 0 {
		fmt.Fprintf(b, "Explore pending checkpoints. %d pending, %d completed.\n", discovered, completed)
		b.WriteString("Use get_next_checkpoint() then go_to_checkpoint(id).\n\n")
		return
	}

	// Case 5: All done
	if bc.crawlPhase == PhaseBreadth {
		b.WriteString("All breadth checkpoints completed. Call get_next_checkpoint() to enter depth phase.\n\n")
	} else {
		b.WriteString("All checkpoints completed (breadth + depth). Call terminate_crawl() to finish.\n\n")
	}
}

// renderActiveCheckpoint writes detailed context about the active or replaying checkpoint.
func (bc *PilotCrawler) renderActiveCheckpoint(b *strings.Builder) {
	// Show replay-in-progress state if navigating to a checkpoint
	replayID, cursor, rState, totalSteps := bc.checkpoints.GetReplayState()
	if replayID != "" {
		cp, _ := bc.checkpoints.Get(replayID)
		if cp != nil {
			fmt.Fprintf(b, "## Navigating to Checkpoint: %s (%s)\n", cp.Name, replayID)
			fmt.Fprintf(b, "Replay progress: step %d of %d\n", cursor+1, totalSteps)
			if rState == replayWaitingForHelp && cursor < totalSteps {
				step := cp.NavigationSteps[cursor]
				fmt.Fprintf(b, "BLOCKED at step %d: %s args=%v\n", cursor+1, step.Tool, step.Args)
				fmt.Fprintf(b, "Intent: %s\n", step.Intent)
			}
			b.WriteByte('\n')
		}
	}

	cp := bc.checkpoints.Active()
	if cp == nil {
		return
	}

	fmt.Fprintf(b, "## Active Checkpoint: %s (%s)\n", cp.Name, cp.ID)
	fmt.Fprintf(b, "Description: %s\n", cp.Description)
	fmt.Fprintf(b, "Test Plan: %s\n", cp.TestPlan)

	if len(cp.Actions) > 0 {
		n := min(len(cp.Actions), 10)
		fmt.Fprintf(b, "\nActions in this checkpoint (last %d of %d):\n", n, len(cp.Actions))
		start := len(cp.Actions) - n
		for i, e := range cp.Actions[start:] {
			fmt.Fprintf(b, "  %d. ", start+i+1)
			writeActionSummary(b, e)
		}
	}
	b.WriteByte('\n')
}

// renderRecentActions writes recent actions from the global log.
func (bc *PilotCrawler) renderRecentActions(b *strings.Builder, n int) {
	entries := bc.trace.RecentEntries(n)
	if len(entries) == 0 {
		return
	}

	fmt.Fprintf(b, "## Recent Actions (last %d of %d total)\n\n", len(entries), bc.trace.Len())

	for _, e := range entries {
		fmt.Fprintf(b, "%d. ", e.Seq)
		writeActionSummary(b, e)
	}
	b.WriteByte('\n')
}

// writeActionSummary writes a single action entry as a compact one-line summary.
func writeActionSummary(b *strings.Builder, e ActionEntry) {
	status := "OK"
	if !e.Success {
		status = "FAIL"
	}
	fmt.Fprintf(b, "[%s] %s", status, e.Tool)

	switch e.Tool {
	case "click":
		fmt.Fprintf(b, " xpath=%s", e.Args["xpath"])
	case "type_text":
		fmt.Fprintf(b, " xpath=%s value=%q", e.Args["xpath"], e.Args["value"])
	case "select_option":
		fmt.Fprintf(b, " xpath=%s value=%q", e.Args["xpath"], e.Args["value"])
	case "navigate":
		fmt.Fprintf(b, " url=%s", e.Args["url"])
	case "submit_form":
		fmt.Fprintf(b, " form_xpath=%s", e.Args["form_xpath"])
	}

	if e.AfterState.StateID != "" {
		fmt.Fprintf(b, " → %s", e.AfterState.StateID)
	}
	if !e.Success && e.Error != "" {
		fmt.Fprintf(b, " error=%q", e.Error)
	}
	b.WriteByte('\n')
}

// renderBlacklistBriefing writes blacklisted elements.
func (bc *PilotCrawler) renderBlacklistBriefing(b *strings.Builder) {
	entries := bc.blacklist.All()
	if len(entries) == 0 {
		return
	}

	fmt.Fprintf(b, "## Blacklisted Elements (%d)\n\n", len(entries))
	for _, e := range entries {
		fmt.Fprintf(b, "- xpath=%s reason=%q\n", e.XPath, e.Reason)
	}
	b.WriteByte('\n')
}

// renderCredentialsBriefing writes agent-discovered credentials.
func (bc *PilotCrawler) renderCredentialsBriefing(b *strings.Builder) {
	if bc.credentials == nil {
		return
	}
	b.WriteString("## Stored Credentials\n\n")
	fmt.Fprintf(b, "Username: %s\nPassword: %s\n\n", bc.credentials.Username, bc.credentials.Password)
}

// renderEntitiesBriefing writes created entities.
func (bc *PilotCrawler) renderEntitiesBriefing(b *strings.Builder) {
	entities := bc.entities.All()
	if len(entities) == 0 {
		return
	}

	b.WriteString("## Created Entities\n\n")
	for _, e := range entities {
		status := "active"
		if e.Deleted {
			status = "deleted"
		}
		fmt.Fprintf(b, "- [%s] %s: %s (%s)\n", status, e.Type, e.Identifier, e.ID)
	}
	b.WriteByte('\n')
}

// autoDetectBlacklist scans the current page elements for logout/signout patterns.
func (bc *PilotCrawler) autoDetectBlacklist(ctx context.Context) {
	elements, err := bc.extractor.Extract(ctx, bc.currentPage)
	if err != nil {
		return
	}

	dangerousTextPatterns := []string{
		"logout", "log out", "sign out", "signout", "end session",
		"delete my account", "close account", "deactivate account",
	}
	dangerousHrefPatterns := []string{
		"/logout", "/signout", "/sign-out", "/session/destroy",
		"/auth/logout", "/users/sign_out",
	}

	for _, elem := range elements {
		xpath := ""
		if elem.Identification != nil {
			xpath = elem.Identification.Value
		}
		if xpath == "" {
			continue
		}

		text := strings.ToLower(elem.Text)
		href := strings.ToLower(elem.Href)

		for _, pattern := range dangerousTextPatterns {
			if strings.Contains(text, pattern) {
				bc.blacklist.Add(xpath, pattern, true)
				break
			}
		}

		for _, pattern := range dangerousHrefPatterns {
			if strings.Contains(href, pattern) {
				if _, already := bc.blacklist.IsBlacklisted(xpath); !already {
					bc.blacklist.Add(xpath, "href:"+pattern, true)
				}
				break
			}
		}
	}
}
