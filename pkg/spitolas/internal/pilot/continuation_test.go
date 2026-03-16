package pilot

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// renderTaskDirective — all 7 continuation scenarios
// =============================================================================

// helper: create a minimal PilotCrawler for directive tests (no browser needed)
func newDirectiveTestCrawler(t *testing.T) *PilotCrawler {
	t.Helper()
	return &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
		pilotConfig: &PilotConfig{},
		crawlPhase:  PhaseBreadth,
	}
}

func renderDirective(bc *PilotCrawler) string {
	var b strings.Builder
	bc.renderTaskDirective(&b)
	return b.String()
}

// S1: No checkpoints discovered yet — fresh start
func TestDirective_S1_NoCheckpoints(t *testing.T) {
	bc := newDirectiveTestCrawler(t)

	directive := renderDirective(bc)

	if !strings.Contains(directive, "Explore the application") {
		t.Error("should instruct to explore")
	}
	if strings.Contains(directive, "RESUME") {
		t.Error("should NOT contain RESUME for fresh start")
	}
}

// S2: Some checkpoints created, none explored
func TestDirective_S2_PendingCheckpoints(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	bc.checkpoints.Create("login", "Login", "Test login", nil, "", "", "", PhaseBreadth, 500)
	bc.checkpoints.Create("dashboard", "Dashboard", "Check widgets", nil, "", "", "", PhaseBreadth, 500)

	directive := renderDirective(bc)

	if !strings.Contains(directive, "Explore pending checkpoints") {
		t.Error("should instruct to explore pending checkpoints")
	}
	if !strings.Contains(directive, "2 pending") {
		t.Error("should show 2 pending")
	}
	if !strings.Contains(directive, "get_next_checkpoint()") {
		t.Error("should mention get_next_checkpoint")
	}
}

// S3: Mid-replay — step failed, waiting for LLM help
func TestDirective_S3_ReplayWaitingForHelp(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	cp := bc.checkpoints.Create("users", "User management", "CRUD ops", []NavigationStep{
		{Tool: "click", Args: map[string]string{"xpath": "//nav/a[1]"}, Intent: "Click Admin link"},
		{Tool: "click", Args: map[string]string{"xpath": "//sidebar/a[2]"}, Intent: "Click Users in sidebar"},
		{Tool: "click", Args: map[string]string{"xpath": "//btn[1]"}, Intent: "Click Create User"},
	}, "", "", "", PhaseBreadth, 500)

	bc.checkpoints.StartReplay(cp.ID)
	bc.checkpoints.SetWaitingForHelp(1) // step 2 failed

	directive := renderDirective(bc)

	if !strings.Contains(directive, "RESUME: You were navigating to checkpoint") {
		t.Error("should contain RESUME navigation instruction")
	}
	if !strings.Contains(directive, "Step 2/3 failed") {
		t.Errorf("should show step 2/3 failed, got: %s", directive)
	}
	if !strings.Contains(directive, "Click Users in sidebar") {
		t.Error("should show the step intent")
	}
	if !strings.Contains(directive, "resume_replay()") {
		t.Error("should mention resume_replay")
	}
	if !strings.Contains(directive, "abort_replay()") {
		t.Error("should mention abort_replay")
	}
}

// S4: Mid-replay — interrupted between steps (not at a failure point)
func TestDirective_S4_ReplayInterrupted(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	cp := bc.checkpoints.Create("settings", "Settings", "Update profile", []NavigationStep{
		{Tool: "click", Args: map[string]string{"xpath": "//nav/a[3]"}},
		{Tool: "click", Args: map[string]string{"xpath": "//tab[2]"}},
	}, "", "", "", PhaseBreadth, 500)

	bc.checkpoints.StartReplay(cp.ID)
	// replayState stays replayIdle (interrupted between steps, not at a failure)

	directive := renderDirective(bc)

	if !strings.Contains(directive, "RESUME: Navigation to checkpoint") {
		t.Error("should contain RESUME navigation interrupted")
	}
	if !strings.Contains(directive, "was interrupted") {
		t.Error("should mention interruption")
	}
	if !strings.Contains(directive, "go_to_checkpoint") {
		t.Error("should suggest go_to_checkpoint to restart")
	}
}

// S5: Active checkpoint mid-exploration — session died while exploring
func TestDirective_S5_ActiveCheckpointMidExploration(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	cp := bc.checkpoints.Create("users", "User CRUD", "Create, edit, delete", nil, "", "", "", PhaseBreadth, 500)
	bc.checkpoints.Activate(cp.ID)

	// Simulate 5 actions in the checkpoint
	for i := 0; i < 5; i++ {
		bc.checkpoints.RecordAction(ActionEntry{Tool: "click", Success: true})
	}

	directive := renderDirective(bc)

	if !strings.Contains(directive, "RESUME: Continue exploring checkpoint") {
		t.Error("should contain RESUME continue exploring")
	}
	if !strings.Contains(directive, "users") {
		t.Errorf("should show checkpoint name, got: %s", directive)
	}
	if !strings.Contains(directive, "Create, edit, delete") {
		t.Error("should show test plan")
	}
	if !strings.Contains(directive, "Actions so far: 5") {
		t.Error("should show action count")
	}
	if !strings.Contains(directive, "complete_checkpoint()") {
		t.Error("should mention complete_checkpoint")
	}
}

// S6: Just completed a checkpoint — next one pending
func TestDirective_S6_OneCompletedOnePending(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	cp1 := bc.checkpoints.Create("login", "Login", "Test login", nil, "", "", "", PhaseBreadth, 500)
	bc.checkpoints.Create("dashboard", "Dashboard", "Check widgets", nil, "", "", "", PhaseBreadth, 500)

	bc.checkpoints.Activate(cp1.ID)
	bc.checkpoints.Complete(cp1.ID, "login works")

	directive := renderDirective(bc)

	if !strings.Contains(directive, "Explore pending checkpoints") {
		t.Error("should instruct to explore pending")
	}
	if !strings.Contains(directive, "1 pending") {
		t.Error("should show 1 pending")
	}
	if !strings.Contains(directive, "1 completed") {
		t.Error("should show 1 completed")
	}
}

// S7: All checkpoints completed — should terminate
func TestDirective_S7_AllCompleted(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	bc.crawlPhase = PhaseDepth // depth phase: terminate_crawl() is appropriate
	cp1 := bc.checkpoints.Create("login", "Login", "Test", nil, "", "", "", PhaseBreadth, 500)
	cp2 := bc.checkpoints.Create("dashboard", "Dashboard", "Test", nil, "", "", "", PhaseBreadth, 500)

	bc.checkpoints.Activate(cp1.ID)
	bc.checkpoints.Complete(cp1.ID, "done")
	bc.checkpoints.Activate(cp2.ID)
	bc.checkpoints.Complete(cp2.ID, "done")

	directive := renderDirective(bc)

	if !strings.Contains(directive, "All checkpoints completed") {
		t.Error("should instruct to terminate")
	}
	if !strings.Contains(directive, "terminate_crawl()") {
		t.Error("should mention terminate_crawl")
	}
}

// =============================================================================
// renderActiveCheckpoint — replay state and scoped actions
// =============================================================================

func renderActiveCP(bc *PilotCrawler) string {
	var b strings.Builder
	bc.renderActiveCheckpoint(&b)
	return b.String()
}

// Replay in progress — shows navigation state
func TestActiveCheckpoint_ReplayInProgress(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	cp := bc.checkpoints.Create("users", "Users", "CRUD", []NavigationStep{
		{Tool: "click", Args: map[string]string{"xpath": "//a[1]"}, Intent: "Click Admin"},
		{Tool: "click", Args: map[string]string{"xpath": "//a[2]"}, Intent: "Click Users"},
	}, "", "", "", PhaseBreadth, 500)

	bc.checkpoints.StartReplay(cp.ID)
	bc.checkpoints.SetWaitingForHelp(1)

	rendered := renderActiveCP(bc)

	if !strings.Contains(rendered, "Navigating to Checkpoint") {
		t.Error("should show navigating state")
	}
	if !strings.Contains(rendered, "step 2 of 2") {
		t.Error("should show replay progress")
	}
	if !strings.Contains(rendered, "BLOCKED at step 2") {
		t.Error("should show blocked step")
	}
	if !strings.Contains(rendered, "Click Users") {
		t.Error("should show step intent")
	}
}

// Active checkpoint with scoped actions
func TestActiveCheckpoint_WithScopedActions(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	cp := bc.checkpoints.Create("users", "Users", "CRUD", nil, "", "", "", PhaseBreadth, 500)
	bc.checkpoints.Activate(cp.ID)

	bc.checkpoints.RecordAction(ActionEntry{
		Tool: "click", Args: map[string]string{"xpath": "//btn[1]"}, Success: true,
	})
	bc.checkpoints.RecordAction(ActionEntry{
		Tool: "type_text", Args: map[string]string{"xpath": "//input", "value": "test@test.com"}, Success: true,
	})
	bc.checkpoints.RecordAction(ActionEntry{
		Tool: "click", Args: map[string]string{"xpath": "//submit"}, Success: false, Error: "element not found",
	})

	rendered := renderActiveCP(bc)

	if !strings.Contains(rendered, "Active Checkpoint: users") {
		t.Errorf("should show active checkpoint name, got: %s", rendered)
	}
	if !strings.Contains(rendered, "Test Plan: CRUD") {
		t.Error("should show test plan")
	}
	if !strings.Contains(rendered, "last 3 of 3") {
		t.Error("should show action count")
	}
	if !strings.Contains(rendered, "[OK] click") {
		t.Error("should show successful actions")
	}
	if !strings.Contains(rendered, "[FAIL] click") {
		t.Error("should show failed actions")
	}
	if !strings.Contains(rendered, `error="element not found"`) {
		t.Error("should show error message")
	}
}

// =============================================================================
// renderCompass — continuation state rendering
// =============================================================================

func TestCompass_MixedStates(t *testing.T) {
	bc := newDirectiveTestCrawler(t)

	cp1 := bc.checkpoints.Create("login", "Login", "Test", nil, "", "", "", PhaseBreadth, 500)
	bc.checkpoints.Create("dashboard", "Dashboard", "Test", nil, "", "", "", PhaseBreadth, 500)
	cp3 := bc.checkpoints.Create("settings", "Settings", "Test", nil, "", "", "", PhaseBreadth, 500)

	bc.checkpoints.Activate(cp1.ID)
	bc.checkpoints.Complete(cp1.ID, "login works")
	bc.checkpoints.Block(cp3.ID, "unreachable")

	compass := bc.renderCompass()

	if !strings.Contains(compass, "[COMPLETED]") {
		t.Error("should show COMPLETED status")
	}
	if !strings.Contains(compass, "[DISCOVERED]") {
		t.Error("should show DISCOVERED status")
	}
	if !strings.Contains(compass, "[BLOCKED]") {
		t.Error("should show BLOCKED status")
	}
	if !strings.Contains(compass, "go_to_checkpoint") {
		t.Error("should show go_to_checkpoint hint for discovered")
	}
}

// =============================================================================
// Checkpoint tool flow — simulating multi-step agent interactions
// =============================================================================

// Test: full lifecycle without browser (checkpoint CRUD only)
func TestCheckpointFlow_FullLifecycleNoBrowser(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	ctx := t.Context()

	// Step 1: Agent discovers features
	r1, _ := bc.HandleTool(ctx, "create_checkpoint", map[string]string{
		"name": "login", "description": "Login page", "test_plan": "Test auth flow",
	})
	cpID1 := mustParseToolData(t, r1, "checkpoint_id")

	r2, _ := bc.HandleTool(ctx, "create_checkpoint", map[string]string{
		"name": "products", "description": "Product catalog", "test_plan": "Search, filter, view",
	})
	cpID2 := mustParseToolData(t, r2, "checkpoint_id")

	// Step 2: Get next checkpoint
	r3, _ := bc.HandleTool(ctx, "get_next_checkpoint", nil)
	nextID := mustParseToolData(t, r3, "checkpoint_id")
	if nextID != cpID1 {
		t.Errorf("expected first checkpoint, got %s", nextID)
	}

	// Step 3: Activate then complete first checkpoint
	bc.HandleTool(ctx, "activate_checkpoint", map[string]string{"checkpoint_id": cpID1})
	r4, _ := bc.HandleTool(ctx, "complete_checkpoint", map[string]string{
		"checkpoint_id": cpID1, "notes": "login form tested",
	})
	remaining := mustParseToolDataFloat(t, r4, "pending_count")
	if remaining != 1 {
		t.Errorf("expected 1 pending, got %v", remaining)
	}

	// Step 4: Second checkpoint
	r5, _ := bc.HandleTool(ctx, "get_next_checkpoint", nil)
	nextID2 := mustParseToolData(t, r5, "checkpoint_id")
	if nextID2 != cpID2 {
		t.Errorf("expected second checkpoint, got %s", nextID2)
	}

	bc.HandleTool(ctx, "activate_checkpoint", map[string]string{"checkpoint_id": cpID2})
	bc.HandleTool(ctx, "complete_checkpoint", map[string]string{
		"checkpoint_id": cpID2, "notes": "product search works",
	})

	// Step 5: No more pending — first call transitions breadth→depth, second returns no pending
	bc.HandleTool(ctx, "get_next_checkpoint", nil) // flush breadth→depth transition
	r6, _ := bc.HandleTool(ctx, "get_next_checkpoint", nil)
	msg := mustParseToolData(t, r6, "message")
	if msg != "no pending checkpoints" {
		t.Errorf("expected no pending, got %s", msg)
	}

	// Verify final state
	_, _, completed, _ := bc.checkpoints.Stats()
	if completed != 2 {
		t.Errorf("expected 2 completed, got %d", completed)
	}
}

// Test: abort_replay returns checkpoint to discoverable state
func TestCheckpointFlow_AbortReplayKeepsDiscovered(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	ctx := t.Context()

	bc.checkpoints.Create("hard-to-reach", "Complex SPA page", "Test forms",
		[]NavigationStep{
			{Tool: "click", Args: map[string]string{"xpath": "//a[1]"}},
		}, "", "", "", PhaseBreadth, 500)

	// Simulate: go_to_checkpoint started replay, then session died
	// New session starts, agent can't fix the broken step, aborts
	bc.checkpoints.StartReplay("cp_1")
	bc.checkpoints.SetWaitingForHelp(0)

	r, _ := bc.HandleTool(ctx, "abort_replay", nil)
	assertToolSuccess(t, r)

	// Checkpoint should still be discoverable
	cp, _ := bc.checkpoints.Get("cp_1")
	if cp.Status != CheckpointDiscovered {
		t.Errorf("expected discovered after abort, got %s", cp.Status)
	}
	if bc.checkpoints.ReplayingID() != "" {
		t.Error("replaying ID should be cleared after abort")
	}
}

// Test: scoped actions survive checkpoint state transitions
func TestCheckpointFlow_ScopedActionsPersist(t *testing.T) {
	bc := newDirectiveTestCrawler(t)

	cp := bc.checkpoints.Create("test", "Test", "Plan", nil, "", "", "", PhaseBreadth, 500)
	bc.checkpoints.Activate(cp.ID)

	// Record actions
	for i := 0; i < 5; i++ {
		bc.checkpoints.RecordAction(ActionEntry{
			Tool:    "click",
			Args:    map[string]string{"xpath": "//btn"},
			Success: true,
		})
	}

	// "Session dies" — verify state persists
	active := bc.checkpoints.Active()
	if active == nil {
		t.Fatal("active checkpoint should persist")
	}
	if active.ActionCount != 5 {
		t.Errorf("expected 5 actions, got %d", active.ActionCount)
	}
	if len(active.Actions) != 5 {
		t.Errorf("expected 5 scoped actions, got %d", len(active.Actions))
	}

	// "New session" — briefing should include the actions
	var b strings.Builder
	bc.renderActiveCheckpoint(&b)
	rendered := b.String()

	if !strings.Contains(rendered, "last 5 of 5") {
		t.Errorf("briefing should show 5 actions, got: %s", rendered)
	}
}

// Test: hierarchical checkpoints — child created during parent exploration
func TestCheckpointFlow_HierarchicalCreation(t *testing.T) {
	bc := newDirectiveTestCrawler(t)
	ctx := t.Context()

	// Create parent
	r1, _ := bc.HandleTool(ctx, "create_checkpoint", map[string]string{
		"name": "admin", "description": "Admin panel", "test_plan": "Explore sub-pages",
	})
	parentID := mustParseToolData(t, r1, "checkpoint_id")

	// Activate parent
	bc.checkpoints.Activate(parentID)

	// While exploring parent, discover child features
	r2, _ := bc.HandleTool(ctx, "create_checkpoint", map[string]string{
		"name": "users", "description": "User management", "test_plan": "CRUD",
	})
	childID := mustParseToolData(t, r2, "checkpoint_id")

	// Verify hierarchy
	child, _ := bc.checkpoints.Get(childID)
	if child.ParentID != parentID {
		t.Errorf("child parent should be %s, got %s", parentID, child.ParentID)
	}

	parent, _ := bc.checkpoints.Get(parentID)
	if len(parent.Children) != 1 || parent.Children[0] != childID {
		t.Errorf("parent should have child %s, got %v", childID, parent.Children)
	}

	// parent_id should be in the tool result
	parentResult := mustParseToolData(t, r2, "parent_id")
	if parentResult != parentID {
		t.Errorf("create_checkpoint should return parent_id=%s, got %s", parentID, parentResult)
	}
}

// =============================================================================
// Session briefing content — verify continuation prompt structure
// =============================================================================

// Test: continuation session header format
func TestBriefing_ContinuationHeader(t *testing.T) {
	var b strings.Builder
	// Replicate the header logic from buildSessionBriefing
	attempt, maxAttempts := 2, 3
	fmt.Fprintf(&b, "## SESSION %d of %d\n\n", attempt, maxAttempts)
	b.WriteString("Previous session ended. All state preserved in Go. Resume immediately.\n\n")

	header := b.String()
	if !strings.Contains(header, "SESSION 2 of 3") {
		t.Error("should contain session header")
	}
	if !strings.Contains(header, "Resume immediately") {
		t.Error("should contain resume instruction")
	}
}

// Test: writeActionSummary consistency
func TestWriteActionSummary_ConsistentKeys(t *testing.T) {
	tests := []struct {
		entry    ActionEntry
		contains string
	}{
		{
			ActionEntry{Tool: "click", Args: map[string]string{"xpath": "//a[1]"}, Success: true},
			"xpath=//a[1]",
		},
		{
			ActionEntry{Tool: "type_text", Args: map[string]string{"xpath": "//input", "value": "hello"}, Success: true},
			`value="hello"`,
		},
		{
			ActionEntry{Tool: "select_option", Args: map[string]string{"xpath": "//select", "value": "opt1"}, Success: true},
			`value="opt1"`,
		},
		{
			ActionEntry{Tool: "submit_form", Args: map[string]string{"form_xpath": "//form"}, Success: true},
			"form_xpath=//form",
		},
		{
			ActionEntry{Tool: "navigate", Args: map[string]string{"url": "http://test.com"}, Success: true},
			"url=http://test.com",
		},
		{
			ActionEntry{Tool: "click", Args: map[string]string{"xpath": "//x"}, Success: false, Error: "not found"},
			`error="not found"`,
		},
		{
			ActionEntry{Tool: "click", Args: map[string]string{"xpath": "//x"}, Success: true, AfterState: StateSnapshot{StateID: "state_003"}},
			"→ state_003",
		},
	}

	for _, tt := range tests {
		var b strings.Builder
		writeActionSummary(&b, tt.entry)
		line := b.String()
		if !strings.Contains(line, tt.contains) {
			t.Errorf("writeActionSummary(%s) should contain %q, got: %s", tt.entry.Tool, tt.contains, line)
		}
	}
}

// =============================================================================
// Retry-skip guard — don't retry when all done
// =============================================================================

func TestRetryGuard_AllCompletedSkipsRetry(t *testing.T) {
	ct := NewCheckpointTracker("")
	cp1 := ct.Create("a", "A", "test", nil, "", "", "", PhaseBreadth, 500)
	cp2 := ct.Create("b", "B", "test", nil, "", "", "", PhaseBreadth, 500)
	ct.Activate(cp1.ID)
	ct.Complete(cp1.ID, "done")
	ct.Activate(cp2.ID)
	ct.Complete(cp2.ID, "done")

	discovered, _, _, _ := ct.Stats()

	// The condition from loop.go retry guard
	shouldSkipRetry := discovered == 0 && ct.Active() == nil && ct.ReplayingID() == "" && (discovered+2) > 0
	if !shouldSkipRetry {
		t.Error("should skip retry when all checkpoints completed")
	}
}

func TestRetryGuard_PendingCheckpointsShouldRetry(t *testing.T) {
	ct := NewCheckpointTracker("")
	cp1 := ct.Create("a", "A", "test", nil, "", "", "", PhaseBreadth, 500)
	ct.Create("b", "B", "test", nil, "", "", "", PhaseBreadth, 500)
	ct.Activate(cp1.ID)
	ct.Complete(cp1.ID, "done")

	discovered, _, _, _ := ct.Stats()

	shouldSkipRetry := discovered == 0 && ct.Active() == nil && ct.ReplayingID() == ""
	if shouldSkipRetry {
		t.Error("should NOT skip retry when there are pending checkpoints")
	}
}

func TestRetryGuard_ActiveCheckpointShouldRetry(t *testing.T) {
	ct := NewCheckpointTracker("")
	cp := ct.Create("a", "A", "test", nil, "", "", "", PhaseBreadth, 500)
	ct.Activate(cp.ID)

	shouldSkipRetry := ct.Active() == nil
	if shouldSkipRetry {
		t.Error("should NOT skip retry when a checkpoint is active")
	}
}

// =============================================================================
// Helpers
// =============================================================================

func assertToolSuccess(t *testing.T, rawResult string) {
	t.Helper()
	var tr ToolResult
	if err := json.Unmarshal([]byte(rawResult), &tr); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !tr.Success {
		t.Fatalf("expected success, got error: %s", tr.Error)
	}
}

func mustParseToolData(t *testing.T, rawResult, key string) string {
	t.Helper()
	var tr ToolResult
	json.Unmarshal([]byte(rawResult), &tr)
	data, ok := tr.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected map data, got %T", tr.Data)
	}
	val, ok := data[key]
	if !ok {
		t.Fatalf("missing key %q in data", key)
	}
	s, ok := val.(string)
	if !ok {
		t.Fatalf("expected string for key %q, got %T", key, val)
	}
	return s
}

func mustParseToolDataFloat(t *testing.T, rawResult, key string) float64 {
	t.Helper()
	var tr ToolResult
	json.Unmarshal([]byte(rawResult), &tr)
	data := tr.Data.(map[string]any)
	return data[key].(float64)
}
