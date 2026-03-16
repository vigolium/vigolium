package pilot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
	"go.uber.org/zap"
)

// ToolResult is the structured result returned to the ACP agent after each tool call.
type ToolResult struct {
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	Data       any    `json:"data,omitempty"`
	PageState  string `json:"page_state,omitempty"`  // full serialized page state
	Screenshot string `json:"screenshot,omitempty"` // base64 JPEG screenshot (when enabled)
}

// HandleTool dispatches a tool call to the appropriate handler.
// Every action tool returns the full page state in its result.
func (bc *PilotCrawler) HandleTool(ctx context.Context, tool string, args map[string]string) (string, error) {
	start := time.Now()
	before := bc.captureSnapshot()

	var result ToolResult

	switch tool {
	// === Action Tools (primary — each returns full page state) ===
	case "click":
		result = bc.toolClick(ctx, args)
	case "type_text":
		result = bc.toolTypeText(ctx, args)
	case "select_option":
		result = bc.toolSelectOption(ctx, args)
	case "check":
		result = bc.toolCheck(ctx, args)
	case "navigate":
		result = bc.toolNavigate(ctx, args)
	case "go_back":
		result = bc.toolGoBack(ctx)
	case "submit_form":
		result = bc.toolSubmitForm(ctx, args)
	case "scroll":
		result = bc.toolScroll(ctx, args)

	// === Investigative Tools ===
	case "get_page_text":
		result = bc.toolGetPageText()
	case "get_element_text":
		result = bc.toolGetElementText(args)
	case "screenshot":
		result = bc.toolScreenshot()
	case "execute_js":
		result = bc.toolExecuteJS(ctx, args)
	case "get_state_graph":
		result = bc.toolGetStateGraph()

	// === Checkpoint Tools ===
	case "create_checkpoint":
		result = bc.toolCreateCheckpoint(ctx, args)
	case "go_to_checkpoint":
		result = bc.toolGoToCheckpoint(ctx, args)
	case "resume_replay":
		result = bc.toolResumeReplay(ctx)
	case "abort_replay":
		result = bc.toolAbortReplay()
	case "complete_checkpoint":
		result = bc.toolCompleteCheckpoint(args)
	case "get_checkpoint_list":
		result = bc.toolGetCheckpointList()
	case "get_next_checkpoint":
		result = bc.toolGetNextCheckpoint()
	case "update_checkpoint":
		result = bc.toolUpdateCheckpoint(args)
	case "activate_checkpoint":
		result = bc.toolActivateCheckpoint(ctx, args)

	// === Entity Tracking Tools ===
	case "register_entity":
		result = bc.toolRegisterEntity(args)
	case "get_created_entities":
		result = bc.toolGetCreatedEntities()
	case "mark_entity_deleted":
		result = bc.toolMarkEntityDeleted(args)

	// === Session Tools ===
	case "store_credentials":
		result = bc.toolStoreCredentials(args)
	case "get_credentials":
		result = bc.toolGetCredentials()
	case "blacklist_element":
		result = bc.toolBlacklistElement(args)
	case "get_blacklist":
		result = bc.toolGetBlacklist()
	case "log_finding":
		result = bc.toolLogFinding(args)
	case "terminate_crawl":
		result = bc.toolTerminateCrawl(args)

	default:
		result = ToolResult{Success: false, Error: fmt.Sprintf("unknown tool: %s", tool)}
	}

	elapsed := time.Since(start)

	// Record state-changing tools to in-memory entries (for BFS) and active checkpoint
	if isActionTool(tool) {
		after := bc.captureSnapshot()
		entry := bc.trace.RecordAction(tool, args, result.Success, result.Error, before, after, elapsed)
		bc.checkpoints.RecordAction(entry)

		// Track consecutive failures for auto-abandon
		if result.Success {
			bc.consecutiveFailures = 0
		} else {
			bc.consecutiveFailures++
			if bc.consecutiveFailures >= 5 {
				if activeCP := bc.checkpoints.Active(); activeCP != nil {
					notes := fmt.Sprintf("auto-abandoned: %d consecutive action failures", bc.consecutiveFailures)
					bc.checkpoints.Abandon(activeCP.ID, notes)
					bc.consecutiveFailures = 0
					zap.L().Warn("checkpoint auto-abandoned due to consecutive failures",
						zap.String("checkpoint", activeCP.Name),
						zap.String("id", activeCP.ID))
					result.Data = map[string]any{
						"auto_abandoned": activeCP.Name,
						"reason":         notes,
						"next_action":    "call get_next_checkpoint() to continue",
					}
				}
			}
		}
	}

	// Trace ALL tool calls (action, investigative, checkpoint, session)
	bc.trace.WriteToolCall(tool, args, &result, elapsed)

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf(`{"success":false,"error":"marshal error: %s"}`, err), nil
	}
	return string(data), nil
}

// noBrowser returns an error ToolResult when no browser page is available.
func noBrowser() ToolResult {
	return ToolResult{Success: false, Error: "no browser page available"}
}

// captureSnapshot creates a StateSnapshot of the current state.
func (bc *PilotCrawler) captureSnapshot() StateSnapshot {
	snap := StateSnapshot{}
	if bc.currentState != nil {
		snap.StateID = bc.currentState.Name
		snap.URL = bc.currentState.URL
	}
	if bc.currentPage != nil {
		snap.Title, _ = bc.currentPage.Title()
	}
	return snap
}

// screenshotQuality is the JPEG quality for compact screenshots sent to AI agents.
const screenshotQuality = 60

// refreshPageState serializes the current page state and attaches it to the result.
// When screenshot mode is enabled, also captures a compact JPEG screenshot.
func (bc *PilotCrawler) refreshPageState(ctx context.Context, result *ToolResult) {
	ps, err := bc.SerializePage(ctx, bc.currentPage, bc.currentState)
	if err != nil {
		zap.L().Warn("failed to serialize page state", zap.Error(err))
		return
	}
	result.PageState = ps

	if bc.pilotConfig != nil && bc.pilotConfig.Screenshot && bc.currentPage != nil {
		data, err := bc.currentPage.ScreenshotCompact(screenshotQuality)
		if err == nil {
			result.Screenshot = base64.StdEncoding.EncodeToString(data)
		}
	}
}

// ============================================================================
// Action Tool Handlers
// ============================================================================

func (bc *PilotCrawler) toolClick(ctx context.Context, args map[string]string) ToolResult {
	xpath := args["xpath"]
	if xpath == "" {
		return ToolResult{Success: false, Error: "xpath is required"}
	}

	// Blacklist enforcement — page unchanged, skip full serialization
	if reason, blocked := bc.blacklist.IsBlacklisted(xpath); blocked {
		return ToolResult{Success: false, Error: fmt.Sprintf("BLOCKED: element is blacklisted — reason: %s", reason)}
	}
	if bc.currentPage == nil {
		return noBrowser()
	}

	elem, err := bc.currentPage.ElementX(xpath)
	if err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("element not found: %s", err)}
	}

	if err := elem.Click(); err != nil {
		r := ToolResult{Success: false, Error: fmt.Sprintf("click failed: %s", err)}
		bc.refreshPageState(ctx, &r)
		return r
	}

	_ = bc.currentPage.WaitStable(bc.config.DOMStableTime)
	bc.updateState(ctx)

	r := ToolResult{Success: true}
	bc.refreshPageState(ctx, &r)
	return r
}

func (bc *PilotCrawler) toolTypeText(ctx context.Context, args map[string]string) ToolResult {
	xpath := args["xpath"]
	value := args["value"]
	if xpath == "" {
		return ToolResult{Success: false, Error: "xpath is required"}
	}
	if bc.currentPage == nil {
		return noBrowser()
	}

	elem, err := bc.currentPage.ElementX(xpath)
	if err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("element not found: %s", err)}
	}

	// Clear existing value first
	_ = elem.SelectAllText()
	if err := elem.Input(value); err != nil {
		r := ToolResult{Success: false, Error: fmt.Sprintf("type failed: %s", err)}
		bc.refreshPageState(ctx, &r)
		return r
	}

	r := ToolResult{Success: true}
	bc.refreshPageState(ctx, &r)
	return r
}

func (bc *PilotCrawler) toolSelectOption(ctx context.Context, args map[string]string) ToolResult {
	xpath := args["xpath"]
	value := args["value"]
	if xpath == "" {
		return ToolResult{Success: false, Error: "xpath is required"}
	}
	if bc.currentPage == nil {
		return noBrowser()
	}

	elem, err := bc.currentPage.ElementX(xpath)
	if err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("element not found: %s", err)}
	}

	if err := elem.Select([]string{value}); err != nil {
		r := ToolResult{Success: false, Error: fmt.Sprintf("select failed: %s", err)}
		bc.refreshPageState(ctx, &r)
		return r
	}

	r := ToolResult{Success: true}
	bc.refreshPageState(ctx, &r)
	return r
}

func (bc *PilotCrawler) toolCheck(ctx context.Context, args map[string]string) ToolResult {
	xpath := args["xpath"]
	if xpath == "" {
		return ToolResult{Success: false, Error: "xpath is required"}
	}
	if bc.currentPage == nil {
		return noBrowser()
	}

	checked := args["checked"] != "false"
	result, err := bc.currentPage.Eval(checkScript(xpath, checked))
	if err != nil {
		r := ToolResult{Success: false, Error: fmt.Sprintf("check failed: %s", err)}
		bc.refreshPageState(ctx, &r)
		return r
	}
	if s, ok := result.(string); ok && s == "not found" {
		return ToolResult{Success: false, Error: "element not found"}
	}

	r := ToolResult{Success: true}
	bc.refreshPageState(ctx, &r)
	return r
}

func (bc *PilotCrawler) toolNavigate(ctx context.Context, args map[string]string) ToolResult {
	url := args["url"]
	if url == "" {
		return ToolResult{Success: false, Error: "url is required"}
	}
	if bc.currentPage == nil {
		return noBrowser()
	}

	if err := bc.currentPage.Navigate(url); err != nil {
		r := ToolResult{Success: false, Error: fmt.Sprintf("navigate failed: %s", err)}
		bc.refreshPageState(ctx, &r)
		return r
	}

	_ = bc.currentPage.WaitStable(bc.config.DOMStableTime)
	bc.updateState(ctx)

	r := ToolResult{Success: true}
	bc.refreshPageState(ctx, &r)
	return r
}

func (bc *PilotCrawler) toolGoBack(ctx context.Context) ToolResult {
	if bc.currentPage == nil {
		return noBrowser()
	}
	if err := bc.currentPage.NavigateBack(); err != nil {
		r := ToolResult{Success: false, Error: fmt.Sprintf("go_back failed: %s", err)}
		bc.refreshPageState(ctx, &r)
		return r
	}

	_ = bc.currentPage.WaitStable(bc.config.DOMStableTime)
	bc.updateState(ctx)

	r := ToolResult{Success: true}
	bc.refreshPageState(ctx, &r)
	return r
}

func (bc *PilotCrawler) toolSubmitForm(ctx context.Context, args map[string]string) ToolResult {
	formXPath := args["form_xpath"]
	if formXPath == "" {
		return ToolResult{Success: false, Error: "form_xpath is required"}
	}
	if bc.currentPage == nil {
		return noBrowser()
	}

	result, err := bc.currentPage.Eval(submitFormScript(formXPath))
	if err != nil {
		r := ToolResult{Success: false, Error: fmt.Sprintf("submit failed: %s", err)}
		bc.refreshPageState(ctx, &r)
		return r
	}
	if s, ok := result.(string); ok && s == "not found" {
		return ToolResult{Success: false, Error: "form not found"}
	}

	_ = bc.currentPage.WaitStable(bc.config.DOMStableTime)
	bc.updateState(ctx)

	r := ToolResult{Success: true}
	bc.refreshPageState(ctx, &r)
	return r
}

func (bc *PilotCrawler) toolScroll(ctx context.Context, args map[string]string) ToolResult {
	if bc.currentPage == nil {
		return noBrowser()
	}
	direction := args["direction"]
	amount := args["amount"]
	if amount == "" {
		amount = "500"
	}

	var script string
	switch direction {
	case "down":
		script = fmt.Sprintf("window.scrollBy(0, %s)", amount)
	case "up":
		script = fmt.Sprintf("window.scrollBy(0, -%s)", amount)
	default:
		script = fmt.Sprintf("window.scrollBy(0, %s)", amount)
	}

	_, _ = bc.currentPage.Eval(script)

	r := ToolResult{Success: true}
	bc.refreshPageState(ctx, &r)
	return r
}

// ============================================================================
// Investigative Tool Handlers
// ============================================================================

func (bc *PilotCrawler) toolGetPageText() ToolResult {
	if bc.currentPage == nil {
		return noBrowser()
	}
	result, err := bc.currentPage.Eval(`document.body.innerText.substring(0, 8192)`)
	if err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("get_page_text failed: %s", err)}
	}
	text, _ := result.(string)
	return ToolResult{Success: true, Data: text}
}

func (bc *PilotCrawler) toolGetElementText(args map[string]string) ToolResult {
	xpath := args["xpath"]
	if xpath == "" {
		return ToolResult{Success: false, Error: "xpath is required"}
	}
	if bc.currentPage == nil {
		return noBrowser()
	}

	script := fmt.Sprintf(`(() => {
		const el = document.evaluate(%q, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
		if (!el) return null;
		return el.textContent.substring(0, 4096);
	})()`, xpath)

	result, err := bc.currentPage.Eval(script)
	if err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("get_element_text failed: %s", err)}
	}
	if result == nil {
		return ToolResult{Success: false, Error: "element not found"}
	}
	text, _ := result.(string)
	return ToolResult{Success: true, Data: text}
}

func (bc *PilotCrawler) toolScreenshot() ToolResult {
	if bc.currentPage == nil {
		return noBrowser()
	}
	data, err := bc.currentPage.ScreenshotCompact(screenshotQuality)
	if err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("screenshot failed: %s", err)}
	}
	return ToolResult{Success: true, Screenshot: base64.StdEncoding.EncodeToString(data)}
}

func (bc *PilotCrawler) toolExecuteJS(ctx context.Context, args map[string]string) ToolResult {
	code := args["code"]
	if code == "" {
		return ToolResult{Success: false, Error: "code is required"}
	}
	if bc.currentPage == nil {
		return noBrowser()
	}

	result, err := bc.currentPage.Eval(code)
	if err != nil {
		return ToolResult{Success: false, Error: fmt.Sprintf("execute_js failed: %s", err)}
	}

	// After JS execution, page state may have changed
	bc.updateState(ctx)

	return ToolResult{Success: true, Data: result}
}

func (bc *PilotCrawler) toolGetStateGraph() ToolResult {
	if bc.graph == nil {
		return ToolResult{Success: false, Error: "no state graph available"}
	}

	states := bc.graph.AllStates()
	type stateInfo struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		URL   string `json:"url"`
		Depth int    `json:"depth"`
	}
	stateInfos := make([]stateInfo, 0, len(states))
	for _, s := range states {
		stateInfos = append(stateInfos, stateInfo{
			ID:    s.ID,
			Name:  s.Name,
			URL:   s.URL,
			Depth: s.Depth,
		})
	}

	allEdges := bc.graph.AllEdges()
	type edgeInfo struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Action string `json:"action"`
	}
	edgeInfos := make([]edgeInfo, 0, len(allEdges))
	for _, e := range allEdges {
		xpath := ""
		if e.Identification != nil {
			xpath = e.Identification.Value
		}
		edgeInfos = append(edgeInfos, edgeInfo{
			Source: e.SourceStateID,
			Target: e.TargetStateID,
			Action: xpath,
		})
	}

	currentName := ""
	if bc.currentState != nil {
		currentName = bc.currentState.Name
	}

	return ToolResult{
		Success: true,
		Data: map[string]any{
			"states":        stateInfos,
			"edges":         edgeInfos,
			"state_count":   len(stateInfos),
			"edge_count":    len(edgeInfos),
			"current_state": currentName,
		},
	}
}

// ============================================================================
// Checkpoint Tool Handlers
// ============================================================================

func (bc *PilotCrawler) toolCreateCheckpoint(ctx context.Context, args map[string]string) ToolResult {
	name := args["name"]
	if name == "" {
		return ToolResult{Success: false, Error: "name is required"}
	}
	description := args["description"]
	testPlan := args["test_plan"]

	// Parse priority (default 500, clamp 1-1000)
	priority := 500
	if p := args["priority"]; p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			priority = v
		}
	}
	if priority < 1 {
		priority = 1
	} else if priority > 1000 {
		priority = 1000
	}

	// Derive navigation steps from root to current state via BFS on action log
	steps := bc.deriveNavigationSteps()

	// If entry_xpath is provided, append a final click step to enter the feature
	if entryXPath := args["entry_xpath"]; entryXPath != "" {
		intent := bc.getElementIntent(entryXPath)
		if intent == "" {
			intent = fmt.Sprintf("Click element at %s", entryXPath)
		}
		steps = append(steps, NavigationStep{
			Tool:   "click",
			Args:   map[string]string{"xpath": entryXPath},
			Intent: intent,
		})
	}

	// Capture page info
	pageURL := ""
	if bc.currentPage != nil {
		pageURL, _ = bc.currentPage.URL()
	}
	domFingerprint := bc.computeDOMFingerprint()

	// Parent = currently active checkpoint (if any)
	parentID := bc.checkpoints.ActiveID()

	cp := bc.checkpoints.Create(name, description, testPlan, steps, pageURL, domFingerprint, parentID, bc.crawlPhase, priority)

	return ToolResult{
		Success: true,
		Data: map[string]any{
			"checkpoint_id": cp.ID,
			"parent_id":     parentID,
			"priority":      cp.Priority,
			"steps_count":   len(steps),
			"pending_count": bc.checkpoints.PendingCount(),
		},
	}
}

// replayFastWait is the reduced wait time between steps during mechanical replay.
const replayFastWait = 500 * time.Millisecond

func (bc *PilotCrawler) toolGoToCheckpoint(ctx context.Context, args map[string]string) ToolResult {
	cpID := args["checkpoint_id"]
	if cpID == "" {
		return ToolResult{Success: false, Error: "checkpoint_id is required"}
	}

	cp, ok := bc.checkpoints.Get(cpID)
	if !ok {
		return ToolResult{Success: false, Error: fmt.Sprintf("checkpoint %q not found", cpID)}
	}

	bc.checkpoints.StartReplay(cpID)

	if bc.currentPage == nil {
		return noBrowser()
	}

	// No navigation steps — checkpoint is the root page itself
	if len(cp.NavigationSteps) == 0 {
		if err := bc.currentPage.Navigate(bc.config.URL.String()); err != nil {
			r := ToolResult{Success: false, Error: fmt.Sprintf("navigate to root failed: %s", err)}
			bc.refreshPageState(ctx, &r)
			return r
		}
		_ = bc.currentPage.WaitStable(bc.config.DOMStableTime)
		bc.updateState(ctx)

		bc.checkpoints.Activate(cpID)
		r := ToolResult{
			Success: true,
			Data: map[string]any{
				"status":    "checkpoint_reached",
				"name":      cp.Name,
				"test_plan": cp.TestPlan,
			},
		}
		bc.refreshPageState(ctx, &r)
		return r
	}

	// Try direct URL navigation first (faster, avoids root round-trip).
	// Only for checkpoints with a stored page_url — skip for SPAs where
	// URL doesn't reflect state.
	if cp.PageURL != "" && cp.PageURL != bc.config.URL.String() {
		if err := bc.currentPage.Navigate(cp.PageURL); err == nil {
			_ = bc.currentPage.WaitStable(bc.config.DOMStableTime)
			bc.updateState(ctx)

			// Verify we reached the right page via DOM fingerprint
			if cp.DOMFingerprint == "" || bc.computeDOMFingerprint() == cp.DOMFingerprint {
				bc.checkpoints.Activate(cpID)
				r := ToolResult{
					Success: true,
					Data: map[string]any{
						"status":    "checkpoint_reached",
						"name":      cp.Name,
						"test_plan": cp.TestPlan,
					},
				}
				bc.refreshPageState(ctx, &r)
				return r
			}
			// DOM fingerprint mismatch — fall through to replay from root
		}
	}

	// Fallback: navigate to root URL and replay steps sequentially
	if err := bc.currentPage.Navigate(bc.config.URL.String()); err != nil {
		r := ToolResult{Success: false, Error: fmt.Sprintf("navigate to root failed: %s", err)}
		bc.refreshPageState(ctx, &r)
		return r
	}
	_ = bc.currentPage.WaitStable(bc.config.DOMStableTime)
	bc.updateState(ctx)

	return bc.replaySteps(ctx, cpID, 0)
}

func (bc *PilotCrawler) toolResumeReplay(ctx context.Context) ToolResult {
	id, _, rState, _ := bc.checkpoints.GetReplayState()
	if id == "" {
		return ToolResult{Success: false, Error: "no checkpoint replay in progress"}
	}
	if rState != replayWaitingForHelp {
		return ToolResult{Success: false, Error: "replay is not waiting for help"}
	}

	// Advance past the failed step (LLM has handled it)
	newCursor, total := bc.checkpoints.AdvanceReplayCursor()
	if newCursor >= total {
		// All steps done — activate checkpoint
		cp, _ := bc.checkpoints.Get(id)
		bc.checkpoints.Activate(id)
		r := ToolResult{
			Success: true,
			Data: map[string]any{
				"status":    "checkpoint_reached",
				"name":      cp.Name,
				"test_plan": cp.TestPlan,
			},
		}
		bc.refreshPageState(ctx, &r)
		return r
	}

	// Continue replaying from the new cursor position
	return bc.replaySteps(ctx, id, newCursor)
}

func (bc *PilotCrawler) toolAbortReplay() ToolResult {
	id := bc.checkpoints.AbortReplay()
	if id == "" {
		return ToolResult{Success: false, Error: "no checkpoint replay in progress"}
	}
	return ToolResult{
		Success: true,
		Data: map[string]any{
			"aborted_checkpoint": id,
			"message":            "Replay aborted. Checkpoint remains discovered. Navigate manually or try another checkpoint.",
		},
	}
}

func (bc *PilotCrawler) toolCompleteCheckpoint(args map[string]string) ToolResult {
	cpID := args["checkpoint_id"]
	notes := args["notes"]
	if cpID == "" {
		return ToolResult{Success: false, Error: "checkpoint_id is required"}
	}

	cp, ok := bc.checkpoints.Get(cpID)
	if !ok {
		return ToolResult{Success: false, Error: fmt.Sprintf("checkpoint %q not found", cpID)}
	}

	// Block completion of checkpoints that were never visited.
	// Agent must use go_to_checkpoint() or activate_checkpoint() first.
	if cp.Status == CheckpointDiscovered {
		return ToolResult{
			Success: false,
			Error: fmt.Sprintf(
				"checkpoint %q has not been visited. Use go_to_checkpoint(%q) first, interact with its features, then complete.",
				cpID, cpID,
			),
		}
	}

	cp, ok = bc.checkpoints.Complete(cpID, notes)
	if !ok {
		return ToolResult{Success: false, Error: fmt.Sprintf("checkpoint %q not found", cpID)}
	}

	discovered, _, completed, _ := bc.checkpoints.Stats()

	return ToolResult{
		Success: true,
		Data: map[string]any{
			"completed":     cp.Name,
			"action_count":  cp.ActionCount,
			"pending_count": discovered,
			"total_done":    completed,
		},
	}
}

// toolActivateCheckpoint marks a checkpoint as active for exploration.
// Use when the agent arrived at a checkpoint's page via natural navigation
// (without go_to_checkpoint). Required before complete_checkpoint.
func (bc *PilotCrawler) toolActivateCheckpoint(_ context.Context, args map[string]string) ToolResult {
	cpID := args["checkpoint_id"]
	if cpID == "" {
		return ToolResult{Success: false, Error: "checkpoint_id is required"}
	}

	cp, ok := bc.checkpoints.Activate(cpID)
	if !ok {
		return ToolResult{Success: false, Error: fmt.Sprintf("checkpoint %q not found", cpID)}
	}

	return ToolResult{
		Success: true,
		Data: map[string]any{
			"activated": cp.Name,
			"test_plan": cp.TestPlan,
		},
	}
}

func (bc *PilotCrawler) toolGetCheckpointList() ToolResult {
	checkpoints := bc.checkpoints.All()
	type cpInfo struct {
		ID          string           `json:"id"`
		Name        string           `json:"name"`
		Status      CheckpointStatus `json:"status"`
		Priority    int              `json:"priority"`
		Description string           `json:"description"`
		TestPlan    string           `json:"test_plan"`
		StepCount   int              `json:"step_count"`
		ActionCount int              `json:"action_count"`
		ParentID    string           `json:"parent_id,omitempty"`
		Children    []string         `json:"children,omitempty"`
		Notes       string           `json:"notes,omitempty"`
	}

	infos := make([]cpInfo, 0, len(checkpoints))
	for _, cp := range checkpoints {
		infos = append(infos, cpInfo{
			ID:          cp.ID,
			Name:        cp.Name,
			Status:      cp.Status,
			Priority:    cp.Priority,
			Description: cp.Description,
			TestPlan:    cp.TestPlan,
			StepCount:   len(cp.NavigationSteps),
			ActionCount: cp.ActionCount,
			ParentID:    cp.ParentID,
			Children:    cp.Children,
			Notes:       cp.Notes,
		})
	}

	return ToolResult{Success: true, Data: infos}
}

func (bc *PilotCrawler) toolGetNextCheckpoint() ToolResult {
	cp := bc.checkpoints.NextPending()
	if cp == nil {
		// No pending checkpoints — check if we should enter depth phase
		if bc.crawlPhase == PhaseBreadth {
			bc.crawlPhase = PhaseDepth
			return ToolResult{
				Success: true,
				Data: map[string]any{
					"message": "All breadth checkpoints done. Entering DEPTH PHASE. " +
						"Use execute_js to discover hidden features, event listeners, API endpoints. " +
						"Re-explore needs_revisit checkpoints for auth-gated features. " +
						"Create new checkpoints for anything found. " +
						"Call terminate_crawl() only when depth exploration is complete.",
					"phase": string(PhaseDepth),
				},
			}
		}
		return ToolResult{Success: true, Data: map[string]any{
			"message": "no pending checkpoints",
			"phase":   string(bc.crawlPhase),
		}}
	}

	return ToolResult{
		Success: true,
		Data: map[string]any{
			"checkpoint_id": cp.ID,
			"name":          cp.Name,
			"description":   cp.Description,
			"test_plan":     cp.TestPlan,
			"priority":      cp.Priority,
			"step_count":    len(cp.NavigationSteps),
			"status":        string(cp.Status),
			"phase":         string(bc.crawlPhase),
		},
	}
}

func (bc *PilotCrawler) toolUpdateCheckpoint(args map[string]string) ToolResult {
	cpID := args["checkpoint_id"]
	if cpID == "" {
		return ToolResult{Success: false, Error: "checkpoint_id is required"}
	}

	ok := bc.checkpoints.Update(cpID, func(cp *Checkpoint) {
		if name := args["name"]; name != "" {
			cp.Name = name
		}
		if desc := args["description"]; desc != "" {
			cp.Description = desc
		}
		if tp := args["test_plan"]; tp != "" {
			cp.TestPlan = tp
		}
		if p := args["priority"]; p != "" {
			if v, err := strconv.Atoi(p); err == nil {
				if v < 1 {
					v = 1
				} else if v > 1000 {
					v = 1000
				}
				cp.Priority = v
			}
		}
	})

	if !ok {
		return ToolResult{Success: false, Error: fmt.Sprintf("checkpoint %q not found", cpID)}
	}
	return ToolResult{Success: true}
}

// ============================================================================
// Entity Tracking Tool Handlers
// ============================================================================

func (bc *PilotCrawler) toolRegisterEntity(args map[string]string) ToolResult {
	entityType := args["type"]
	identifier := args["identifier"]
	if entityType == "" || identifier == "" {
		return ToolResult{Success: false, Error: "type and identifier are required"}
	}

	stateID := ""
	if bc.currentState != nil {
		stateID = bc.currentState.Name
	}

	id := bc.entities.Register(entityType, identifier, stateID)
	return ToolResult{Success: true, Data: map[string]any{"entity_id": id}}
}

func (bc *PilotCrawler) toolGetCreatedEntities() ToolResult {
	return ToolResult{Success: true, Data: bc.entities.All()}
}

func (bc *PilotCrawler) toolMarkEntityDeleted(args map[string]string) ToolResult {
	entityID := args["entity_id"]
	if entityID == "" {
		return ToolResult{Success: false, Error: "entity_id is required"}
	}

	if !bc.entities.MarkDeleted(entityID) {
		return ToolResult{Success: false, Error: fmt.Sprintf("entity %q not found", entityID)}
	}
	return ToolResult{Success: true}
}

// ============================================================================
// Session Tool Handlers
// ============================================================================

func (bc *PilotCrawler) toolStoreCredentials(args map[string]string) ToolResult {
	bc.credentials = &Credentials{
		Username: args["username"],
		Password: args["password"],
	}

	return ToolResult{Success: true, Data: map[string]any{"stored": true}}
}

func (bc *PilotCrawler) toolGetCredentials() ToolResult {
	if bc.credentials == nil {
		return ToolResult{Success: false, Error: "no credentials stored"}
	}
	return ToolResult{
		Success: true,
		Data: map[string]any{
			"username": bc.credentials.Username,
			"password": bc.credentials.Password,
		},
	}
}

func (bc *PilotCrawler) toolBlacklistElement(args map[string]string) ToolResult {
	xpath := args["xpath"]
	reason := args["reason"]
	if xpath == "" {
		return ToolResult{Success: false, Error: "xpath is required"}
	}
	bc.blacklist.Add(xpath, reason, false)
	return ToolResult{Success: true}
}

func (bc *PilotCrawler) toolGetBlacklist() ToolResult {
	return ToolResult{Success: true, Data: bc.blacklist.All()}
}

func (bc *PilotCrawler) toolLogFinding(args map[string]string) ToolResult {
	zap.L().Info("pilot finding",
		zap.String("description", args["description"]),
		zap.String("severity", args["severity"]),
		zap.String("url", args["url"]),
		zap.String("evidence", args["evidence"]))
	return ToolResult{Success: true}
}

func (bc *PilotCrawler) toolTerminateCrawl(args map[string]string) ToolResult {
	reason := args["reason"]

	// Termination guard — reject premature termination
	warnings := bc.checkTerminationReadiness()
	if len(warnings) > 0 {
		return ToolResult{
			Success: false,
			Error:   "Cannot terminate yet:\n- " + strings.Join(warnings, "\n- "),
			Data:    map[string]any{"warnings": warnings},
		}
	}

	zap.L().Info("pilot requesting crawl termination", zap.String("reason", reason))
	bc.terminated.Store(true)
	return ToolResult{Success: true, Data: map[string]any{"terminating": true, "reason": reason}}
}

// checkTerminationReadiness returns warnings if the crawl shouldn't terminate yet.
func (bc *PilotCrawler) checkTerminationReadiness() []string {
	var warnings []string

	if bc.crawlPhase == PhaseBreadth {
		warnings = append(warnings, "Still in breadth phase — complete all discovered checkpoints first, then enter depth phase")
	}

	discovered, _, _, _ := bc.checkpoints.Stats()
	if discovered > 0 {
		warnings = append(warnings, fmt.Sprintf("%d checkpoints still pending exploration", discovered))
	}

	return warnings
}

// ============================================================================
// Replay Helpers — hybrid replay with LLM handoff
// ============================================================================

// replaySteps executes navigation steps mechanically starting at fromCursor.
// On step failure, stops and returns needs_help for LLM intervention.
// On success, activates the checkpoint and returns checkpoint_reached.
func (bc *PilotCrawler) replaySteps(ctx context.Context, cpID string, fromCursor int) ToolResult {
	cp, ok := bc.checkpoints.Get(cpID)
	if !ok {
		return ToolResult{Success: false, Error: fmt.Sprintf("checkpoint %q not found", cpID)}
	}

	for i := fromCursor; i < len(cp.NavigationSteps); i++ {
		select {
		case <-ctx.Done():
			return ToolResult{Success: false, Error: "context cancelled during replay"}
		default:
		}

		bc.reportProgress() // reset stall timer — each step proves we're alive

		step := cp.NavigationSteps[i]
		before := bc.captureSnapshot()
		stepStart := time.Now()

		err := bc.executeReplayStep(ctx, step)
		if err != nil {
			// Retry once — DOM may have shifted during page load
			_ = bc.currentPage.WaitStable(replayFastWait)
			before = bc.captureSnapshot()
			stepStart = time.Now()
			err = bc.executeReplayStep(ctx, step)
		}
		if err != nil {
			// Step failed twice — hand off to LLM
			bc.checkpoints.SetWaitingForHelp(i)

			r := ToolResult{
				Success: false,
				Data: map[string]any{
					"status":      "needs_help",
					"checkpoint":  cp.Name,
					"failed_step": i,
					"total_steps": len(cp.NavigationSteps),
					"step_tool":   step.Tool,
					"step_args":   step.Args,
					"step_intent": step.Intent,
					"error":       err.Error(),
					"message":     "Step failed. Fix it manually (click/type the right element), then call resume_replay().",
				},
			}
			bc.refreshPageState(ctx, &r)
			return r
		}

		// Wait for DOM to settle before capturing state — prevents recording
		// transitional DOM states that would produce incorrect BFS edges.
		_ = bc.currentPage.WaitStable(replayFastWait)

		// Record replay step in action log so BFS can build full paths
		// across replay boundaries. Marked IsReplay so RecentEntries filters them out.
		bc.updateState(ctx)
		after := bc.captureSnapshot()
		e := bc.trace.RecordAction(step.Tool, step.Args, true, "", before, after, time.Since(stepStart))
		bc.trace.MarkReplay(e.Seq)
	}

	// All steps passed — activate checkpoint
	bc.checkpoints.Activate(cpID)

	// Verify DOM fingerprint (warn if mismatch, don't fail)
	var warning string
	if cp.DOMFingerprint != "" {
		actual := bc.computeDOMFingerprint()
		if actual != cp.DOMFingerprint {
			warning = "Page content differs from creation time (dynamic content may differ)"
		}
	}

	bc.updateState(ctx)

	data := map[string]any{
		"status":    "checkpoint_reached",
		"name":      cp.Name,
		"test_plan": cp.TestPlan,
	}
	if warning != "" {
		data["warning"] = warning
	}

	r := ToolResult{Success: true, Data: data}
	bc.refreshPageState(ctx, &r)
	return r
}

// executeReplayStep executes a single navigation step mechanically.
// This bypasses HandleTool — actions are NOT recorded in the action log.
func (bc *PilotCrawler) executeReplayStep(ctx context.Context, step NavigationStep) error {
	if bc.currentPage == nil {
		return fmt.Errorf("no browser page")
	}

	switch step.Tool {
	case "click":
		xpath := step.Args["xpath"]
		if xpath == "" {
			return fmt.Errorf("click: xpath is empty")
		}
		elem, err := bc.currentPage.ElementX(xpath)
		if err != nil {
			return fmt.Errorf("click: element not found at %s: %w", xpath, err)
		}
		if err := elem.Click(); err != nil {
			return fmt.Errorf("click failed: %w", err)
		}

	case "type_text":
		xpath := step.Args["xpath"]
		if xpath == "" {
			return fmt.Errorf("type_text: xpath is empty")
		}
		elem, err := bc.currentPage.ElementX(xpath)
		if err != nil {
			return fmt.Errorf("type_text: element not found: %w", err)
		}
		_ = elem.SelectAllText()
		if err := elem.Input(step.Args["value"]); err != nil {
			return fmt.Errorf("type_text failed: %w", err)
		}

	case "select_option":
		xpath := step.Args["xpath"]
		if xpath == "" {
			return fmt.Errorf("select_option: xpath is empty")
		}
		elem, err := bc.currentPage.ElementX(xpath)
		if err != nil {
			return fmt.Errorf("select_option: element not found: %w", err)
		}
		if err := elem.Select([]string{step.Args["value"]}); err != nil {
			return fmt.Errorf("select_option failed: %w", err)
		}

	case "check":
		xpath := step.Args["xpath"]
		checked := step.Args["checked"] != "false"
		result, err := bc.currentPage.Eval(checkScript(xpath, checked))
		if err != nil {
			return fmt.Errorf("check failed: %w", err)
		}
		if s, ok := result.(string); ok && s == "not found" {
			return fmt.Errorf("check: element not found")
		}

	case "submit_form":
		result, err := bc.currentPage.Eval(submitFormScript(step.Args["form_xpath"]))
		if err != nil {
			return fmt.Errorf("submit_form failed: %w", err)
		}
		if s, ok := result.(string); ok && s == "not found" {
			return fmt.Errorf("submit_form: form not found")
		}

	case "navigate":
		if err := bc.currentPage.Navigate(step.Args["url"]); err != nil {
			return fmt.Errorf("navigate failed: %w", err)
		}

	case "go_back":
		if err := bc.currentPage.NavigateBack(); err != nil {
			return fmt.Errorf("go_back failed: %w", err)
		}

	case "execute_js":
		if _, err := bc.currentPage.Eval(step.Args["code"]); err != nil {
			return fmt.Errorf("execute_js failed: %w", err)
		}

	case "scroll":
		amount := step.Args["amount"]
		if amount == "" {
			amount = "500"
		}
		dir := step.Args["direction"]
		if dir == "up" {
			amount = "-" + amount
		}
		_, _ = bc.currentPage.Eval(fmt.Sprintf("window.scrollBy(0, %s)", amount))

	default:
		return fmt.Errorf("unsupported replay tool: %s", step.Tool)
	}

	return nil
}

// ============================================================================
// Shared JS Helpers — used by both tool handlers and replay
// ============================================================================

// checkScript returns the JavaScript to set a checkbox/radio state.
func checkScript(xpath string, checked bool) string {
	return fmt.Sprintf(`(() => {
		const el = document.evaluate(%q, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
		if (!el) return 'not found';
		el.checked = %t;
		el.dispatchEvent(new Event('change', {bubbles: true}));
		return 'ok';
	})()`, xpath, checked)
}

// submitFormScript returns the JavaScript to submit a form.
// Dispatches the submit event first for frameworks that intercept it.
func submitFormScript(formXPath string) string {
	return fmt.Sprintf(`(() => {
		const form = document.evaluate(%q, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
		if (!form) return 'not found';
		form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
		if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); }
		return 'ok';
	})()`, formXPath)
}

// ============================================================================
// Navigation Helpers
// ============================================================================

// deriveNavigationSteps finds the shortest path from root to the current state
// by performing BFS on the action log's state transitions.
//
// Actions that don't change state (type_text, select_option, check) are grouped
// with the subsequent state-changing action into compound edges. This ensures
// form fills (e.g., typing a username before submitting a login form) are
// included in the navigation path and replayed correctly.
func (bc *PilotCrawler) deriveNavigationSteps() []NavigationStep {
	if bc.currentState == nil || bc.graph == nil {
		return nil
	}

	indexState := bc.graph.GetIndexState()
	if indexState == nil {
		return nil
	}

	indexName := indexState.Name
	targetName := bc.currentState.Name
	if indexName == targetName {
		return nil // already at root
	}

	entries := bc.trace.Entries(0)
	if len(entries) == 0 {
		return nil
	}

	// Build compound edges: group same-state preparatory actions (type_text,
	// select_option, etc.) with the subsequent state-changing action.
	// Example: [type_text "carlos", submit_form] → single edge from login to next state.
	type compoundEdge struct {
		entries []*ActionEntry // preparatory actions + final state-changing action
	}
	adj := make(map[string][]compoundEdge)

	var pending []*ActionEntry
	var pendingState string

	for i := range entries {
		e := &entries[i]
		if !e.Success || e.BeforeState.StateID == "" {
			continue
		}

		// If the action starts at a different state than our pending buffer,
		// the pending actions are orphaned (no transition followed them).
		if pendingState != "" && e.BeforeState.StateID != pendingState {
			pending = nil
		}
		pendingState = e.BeforeState.StateID

		// Same-state action → accumulate as preparatory step
		if e.AfterState.StateID == "" || e.BeforeState.StateID == e.AfterState.StateID {
			pending = append(pending, e)
			continue
		}

		// State-changing action → create compound edge with all accumulated prep steps
		all := make([]*ActionEntry, len(pending)+1)
		copy(all, pending)
		all[len(pending)] = e

		adj[e.BeforeState.StateID] = append(adj[e.BeforeState.StateID], compoundEdge{entries: all})

		pendingState = e.AfterState.StateID
		pending = nil
	}

	// BFS from index to target — finds shortest path in state transitions.
	// Each edge carries all actions needed to traverse it (including form fills).
	type node struct {
		stateID string
		path    []*ActionEntry
	}
	visited := map[string]bool{indexName: true}
	queue := []node{{stateID: indexName, path: nil}}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for _, ce := range adj[curr.stateID] {
			lastEntry := ce.entries[len(ce.entries)-1]
			nextState := lastEntry.AfterState.StateID
			if visited[nextState] {
				continue
			}

			newPath := make([]*ActionEntry, len(curr.path)+len(ce.entries))
			copy(newPath, curr.path)
			copy(newPath[len(curr.path):], ce.entries)

			if nextState == targetName {
				return bc.entriesToSteps(newPath)
			}
			visited[nextState] = true
			queue = append(queue, node{stateID: nextState, path: newPath})
		}
	}

	return nil // no path found
}

// entriesToSteps converts ActionEntry pointers to NavigationSteps.
func (bc *PilotCrawler) entriesToSteps(entries []*ActionEntry) []NavigationStep {
	steps := make([]NavigationStep, 0, len(entries))
	for _, e := range entries {
		step := NavigationStep{
			Tool:   e.Tool,
			Args:   maps.Clone(e.Args),
			Intent: deriveIntentFromAction(e.Tool, e.Args),
		}
		if e.AfterState.Title != "" {
			step.ExpectedDOMHint = e.AfterState.Title
		}
		steps = append(steps, step)
	}
	return steps
}

// computeDOMFingerprint captures a human-readable fingerprint of the current page.
func (bc *PilotCrawler) computeDOMFingerprint() string {
	if bc.currentPage == nil {
		return ""
	}
	result, err := bc.currentPage.Eval(`(() => {
		const title = document.title || '';
		const h1 = document.querySelector('h1')?.textContent?.trim() || '';
		const formCount = document.forms.length;
		return JSON.stringify({title, h1, formCount});
	})()`)
	if err != nil {
		return ""
	}
	s, _ := result.(string)
	return s
}

// getElementIntent extracts a human-readable description of what an element is.
func (bc *PilotCrawler) getElementIntent(xpath string) string {
	if bc.currentPage == nil {
		return ""
	}
	script := fmt.Sprintf(`(() => {
		const el = document.evaluate(%q, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
		if (!el) return '';
		const text = el.textContent.trim();
		const tag = el.tagName.toLowerCase();
		if (text.length > 50) return tag + ':' + text.substring(0, 50);
		return tag + ':' + text;
	})()`, xpath)

	result, err := bc.currentPage.Eval(script)
	if err != nil {
		return ""
	}
	if s, ok := result.(string); ok && s != "" {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) == 2 && parts[1] != "" {
			return fmt.Sprintf("Click '%s' (%s)", parts[1], parts[0])
		}
	}
	return ""
}

// deriveIntentFromAction generates a human-readable intent from a tool call.
func deriveIntentFromAction(tool string, args map[string]string) string {
	switch tool {
	case "click":
		return fmt.Sprintf("Click element at %s", args["xpath"])
	case "navigate":
		return fmt.Sprintf("Navigate to %s", args["url"])
	case "type_text":
		return fmt.Sprintf("Type %q into %s", args["value"], args["xpath"])
	case "select_option":
		return fmt.Sprintf("Select %q in %s", args["value"], args["xpath"])
	case "submit_form":
		return fmt.Sprintf("Submit form at %s", args["form_xpath"])
	case "check":
		return fmt.Sprintf("Check element at %s", args["xpath"])
	case "go_back":
		return "Go back"
	case "scroll":
		return fmt.Sprintf("Scroll %s %s", args["direction"], args["amount"])
	case "execute_js":
		code := args["code"]
		if len(code) > 60 {
			code = code[:60] + "..."
		}
		return fmt.Sprintf("Execute JS: %s", code)
	default:
		return tool
	}
}


// ============================================================================
// State Management Helpers
// ============================================================================

// updateState captures the current page DOM, compares with known states,
// and updates bc.currentState. This is called after every navigation/click.
func (bc *PilotCrawler) updateState(ctx context.Context) {
	if bc.currentPage == nil || bc.graph == nil {
		return
	}

	html, err := bc.currentPage.HTMLWithFramesFiltered(bc.config.CrawlFrames, bc.config.ExcludeFrames)
	if err != nil {
		zap.L().Warn("failed to get page HTML for state update", zap.Error(err))
		return
	}

	pageURL, _ := bc.currentPage.URL()
	strippedDOM := state.StripDOM(html, bc.config.DOMStripTags, bc.config.DOMStripAttrs)
	existing := bc.graph.FindStateByDOM(strippedDOM)

	if existing != nil {
		bc.currentState = existing
	} else {
		depth := 0
		if bc.currentState != nil {
			depth = bc.currentState.Depth + 1
		}
		newState := state.New(pageURL, html, strippedDOM, depth)
		bc.graph.AddState(newState)
		bc.currentState = newState

		zap.L().Debug("pilot discovered new state",
			zap.String("state", newState.Name),
			zap.String("url", pageURL))
	}
}

// isActionTool returns true for tools that modify browser/application state.
// Read-only investigative, checkpoint management, and session tools return false.
func isActionTool(tool string) bool {
	switch tool {
	case "click", "type_text", "select_option", "check",
		"navigate", "go_back", "submit_form", "scroll",
		"execute_js":
		return true
	}
	return false
}
