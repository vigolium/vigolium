// plan_test.go — Tests for the checkpoint-based pilot system.
package pilot

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Tool dispatch + return format
// =============================================================================

func TestToolResultFormat(t *testing.T) {
	var r ToolResult
	r.Success = true
	r.PageState = "=== PAGE STATE ==="
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["success"]; !ok {
		t.Error("missing 'success' in ToolResult JSON")
	}
	if _, ok := m["page_state"]; !ok {
		t.Error("missing 'page_state' in ToolResult JSON")
	}
	if _, ok := m["error"]; ok {
		t.Error("'error' should be omitted when empty")
	}
}

func TestHandleToolDispatchesAllTools(t *testing.T) {
	allTools := []string{
		// Action tools (8)
		"click", "type_text", "select_option", "check",
		"navigate", "go_back", "submit_form", "scroll",
		// Investigative tools (5)
		"get_page_text", "get_element_text", "screenshot",
		"execute_js", "get_state_graph",
		// Checkpoint tools (8)
		"create_checkpoint", "go_to_checkpoint", "resume_replay",
		"abort_replay", "complete_checkpoint", "activate_checkpoint",
		"get_checkpoint_list", "get_next_checkpoint", "update_checkpoint",
		// Entity tools (3)
		"register_entity", "get_created_entities", "mark_entity_deleted",
		// Session tools (6)
		"store_credentials", "get_credentials",
		"blacklist_element", "get_blacklist",
		"log_finding", "terminate_crawl",
	}

	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}

	for _, tool := range allTools {
		result, err := bc.HandleTool(context.Background(), tool, map[string]string{})
		if err != nil {
			t.Errorf("HandleTool(%q) returned error: %v", tool, err)
			continue
		}
		var tr ToolResult
		if err := json.Unmarshal([]byte(result), &tr); err != nil {
			t.Errorf("HandleTool(%q) returned invalid JSON: %v", tool, err)
			continue
		}
		if strings.Contains(tr.Error, "unknown tool") {
			t.Errorf("tool %q not dispatched — got 'unknown tool' error", tool)
		}
	}
}

func TestHandleToolUnknownTool(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}
	result, _ := bc.HandleTool(context.Background(), "nonexistent_tool", nil)
	var tr ToolResult
	_ = json.Unmarshal([]byte(result), &tr)
	if tr.Success {
		t.Error("unknown tool should return success=false")
	}
	if !strings.Contains(tr.Error, "unknown tool") {
		t.Errorf("expected 'unknown tool' error, got: %s", tr.Error)
	}
}

// =============================================================================
// Click blacklist enforcement
// =============================================================================

func TestClickBlacklistEnforcement(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}

	bc.blacklist.Add("/html/body/nav/a[5]", "logout", true)

	result, _ := bc.HandleTool(context.Background(), "click", map[string]string{
		"xpath": "/html/body/nav/a[5]",
	})
	var tr ToolResult
	_ = json.Unmarshal([]byte(result), &tr)

	if tr.Success {
		t.Error("clicking blacklisted element should fail")
	}
	if !strings.Contains(tr.Error, "BLOCKED") {
		t.Errorf("expected BLOCKED error, got: %s", tr.Error)
	}
	if !strings.Contains(tr.Error, "logout") {
		t.Errorf("expected reason 'logout' in error, got: %s", tr.Error)
	}
}

// =============================================================================
// Checkpoint tool lifecycle
// =============================================================================

func TestCheckpointToolLifecycle(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}
	ctx := context.Background()

	// Step 1: create_checkpoint
	result, _ := bc.HandleTool(ctx, "create_checkpoint", map[string]string{
		"name":        "login",
		"description": "Login page",
		"test_plan":   "Test login with valid/invalid creds",
	})
	var tr1 ToolResult
	_ = json.Unmarshal([]byte(result), &tr1)
	if !tr1.Success {
		t.Fatal("create_checkpoint should succeed")
	}
	data1 := tr1.Data.(map[string]any)
	cpID := data1["checkpoint_id"].(string)
	if cpID == "" {
		t.Fatal("checkpoint_id should not be empty")
	}
	if data1["pending_count"].(float64) != 1 {
		t.Error("pending_count should be 1")
	}

	// Step 2: get_next_checkpoint
	result2, _ := bc.HandleTool(ctx, "get_next_checkpoint", nil)
	var tr2 ToolResult
	_ = json.Unmarshal([]byte(result2), &tr2)
	data2 := tr2.Data.(map[string]any)
	if data2["name"].(string) != "login" {
		t.Error("should return login as next checkpoint")
	}

	// Step 3: activate then complete checkpoint
	_, _ = bc.HandleTool(ctx, "activate_checkpoint", map[string]string{"checkpoint_id": cpID})
	result3, _ := bc.HandleTool(ctx, "complete_checkpoint", map[string]string{
		"checkpoint_id": cpID,
		"notes":         "tested login with valid/invalid creds",
	})
	var tr3 ToolResult
	_ = json.Unmarshal([]byte(result3), &tr3)
	if !tr3.Success {
		t.Fatal("complete_checkpoint should succeed")
	}
	data3 := tr3.Data.(map[string]any)
	if data3["pending_count"].(float64) != 0 {
		t.Error("pending_count should be 0")
	}
	if data3["total_done"].(float64) != 1 {
		t.Error("total_done should be 1")
	}

	// Verify status
	cp, _ := bc.checkpoints.Get(cpID)
	if cp.Status != CheckpointCompleted {
		t.Errorf("expected completed, got %s", cp.Status)
	}
}

func TestGetNextCheckpointEmpty(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}

	result, _ := bc.HandleTool(context.Background(), "get_next_checkpoint", nil)
	var tr ToolResult
	_ = json.Unmarshal([]byte(result), &tr)
	data := tr.Data.(map[string]any)
	if _, hasMsg := data["message"]; !hasMsg {
		t.Error("should return message when no pending checkpoints")
	}
}

// =============================================================================
// Entity and credential tools
// =============================================================================

func TestEntityToolLifecycle(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}
	ctx := context.Background()

	result, _ := bc.HandleTool(ctx, "register_entity", map[string]string{
		"type": "user", "identifier": "test@example.com",
	})
	var tr ToolResult
	_ = json.Unmarshal([]byte(result), &tr)
	if !tr.Success {
		t.Fatal("register_entity should succeed")
	}
	entityID := tr.Data.(map[string]any)["entity_id"].(string)

	result2, _ := bc.HandleTool(ctx, "get_created_entities", nil)
	var tr2 ToolResult
	_ = json.Unmarshal([]byte(result2), &tr2)
	entities := tr2.Data.([]any)
	if len(entities) != 1 {
		t.Errorf("expected 1 entity, got %d", len(entities))
	}

	result3, _ := bc.HandleTool(ctx, "mark_entity_deleted", map[string]string{"entity_id": entityID})
	var tr3 ToolResult
	_ = json.Unmarshal([]byte(result3), &tr3)
	if !tr3.Success {
		t.Error("mark_entity_deleted should succeed")
	}
}

func TestCredentialsTools(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}
	ctx := context.Background()

	// No creds initially
	result, _ := bc.HandleTool(ctx, "get_credentials", nil)
	var tr ToolResult
	_ = json.Unmarshal([]byte(result), &tr)
	if tr.Success {
		t.Error("get_credentials should fail when no creds stored")
	}

	_, _ = bc.HandleTool(ctx, "store_credentials", map[string]string{"username": "admin", "password": "secret123"})

	result3, _ := bc.HandleTool(ctx, "get_credentials", nil)
	var tr3 ToolResult
	_ = json.Unmarshal([]byte(result3), &tr3)
	if !tr3.Success {
		t.Error("get_credentials should succeed after store")
	}
	creds := tr3.Data.(map[string]any)
	if creds["username"].(string) != "admin" {
		t.Error("credentials not returned correctly")
	}
}

// =============================================================================
// Action log recording
// =============================================================================

func TestTraceOnlyRecordsActionTools(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}
	ctx := context.Background()

	// Read-only tools — should NOT be recorded as action entries
	_, _ = bc.HandleTool(ctx, "get_checkpoint_list", nil)
	_, _ = bc.HandleTool(ctx, "get_blacklist", nil)
	_, _ = bc.HandleTool(ctx, "get_credentials", nil)
	_, _ = bc.HandleTool(ctx, "get_created_entities", nil)
	_, _ = bc.HandleTool(ctx, "get_next_checkpoint", nil)
	_, _ = bc.HandleTool(ctx, "get_page_text", nil)
	_, _ = bc.HandleTool(ctx, "screenshot", nil)

	if bc.trace.Len() != 0 {
		t.Errorf("read-only tools should NOT be recorded as action entries, got %d", bc.trace.Len())
	}
}

func TestTraceRecordsActionTools(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}
	ctx := context.Background()

	_, _ = bc.HandleTool(ctx, "click", map[string]string{"xpath": "/a[1]"})
	_, _ = bc.HandleTool(ctx, "navigate", map[string]string{"url": "http://test.com"})

	if bc.trace.Len() != 2 {
		t.Errorf("action tools should be recorded, expected 2, got %d", bc.trace.Len())
	}
}

func TestTraceRecordActionFields(t *testing.T) {
	tr, _ := NewSessionTrace("")
	defer func() { _ = tr.Close() }()

	before := StateSnapshot{StateID: "s1", URL: "http://a.com"}
	after := StateSnapshot{StateID: "s2", URL: "http://a.com/b", IsNew: true}

	entry := tr.RecordAction("click", map[string]string{"xpath": "/a[1]"}, true, "", before, after, 150*time.Millisecond)
	if entry.Seq != 1 {
		t.Errorf("Seq should be 1, got %d", entry.Seq)
	}
	if entry.Tool != "click" {
		t.Errorf("Tool should be 'click', got %q", entry.Tool)
	}
	if !entry.Success {
		t.Error("Success should be true")
	}
	if entry.BeforeState.StateID != "s1" {
		t.Error("BeforeState.StateID wrong")
	}
	if entry.AfterState.StateID != "s2" {
		t.Error("AfterState.StateID wrong")
	}
	if entry.DurationMS != 150 {
		t.Errorf("DurationMS should be 150, got %d", entry.DurationMS)
	}
}

func TestTraceMarkdownFile(t *testing.T) {
	dir := t.TempDir()
	tracePath := filepath.Join(dir, "session_trace.md")

	tr, err := NewSessionTrace(tracePath)
	if err != nil {
		t.Fatal(err)
	}

	tr.WriteHeader("http://test.com", &PilotConfig{Screenshot: true, MaxRetries: 2})
	tr.WriteSystemPrompt("You are a test agent.")
	tr.WriteSessionStart(1, 3)
	tr.WriteBriefing("## Target\nURL: http://test.com")

	tr.WriteToolCall("click", map[string]string{"xpath": "/a[1]"}, &ToolResult{
		Success:   true,
		PageState: "=== PAGE STATE ===\nURL: http://test.com/page1",
	}, 100*time.Millisecond)

	tr.WriteToolCall("navigate", map[string]string{"url": "http://test.com/page2"}, &ToolResult{
		Success: false,
		Error:   "navigate failed: timeout",
	}, 5*time.Second)

	tr.RecordAction("click", map[string]string{"xpath": "/a[1]"}, true, "",
		StateSnapshot{StateID: "s1"}, StateSnapshot{StateID: "s2"}, 100*time.Millisecond)

	tr.WriteSessionEnd("completed", nil)
	tr.WriteSummary(&Result{StatesDiscovered: 5, CheckpointsCompleted: 3, CheckpointsPending: 1})
	_ = tr.Close()

	data, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	checks := []string{
		"# Pilot Session Trace",
		"**Target**: http://test.com",
		"## System Prompt",
		"You are a test agent.",
		"## ACP Session (Attempt 1/3)",
		"### Briefing Prompt",
		"#### #1 click ✓",
		"#### #2 navigate ✗",
		"navigate failed: timeout",
		"### Session End",
		"## Summary",
		"Tool Distribution",
	}
	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("trace file missing expected content: %q", check)
		}
	}
}

// =============================================================================
// Stall detection
// =============================================================================

func TestStallDetectionThreshold(t *testing.T) {
	ct := NewCheckpointTracker("")
	cp := ct.Create("x", "desc", "plan", nil, "", "", "", PhaseBreadth, 500)
	ct.Activate(cp.ID)

	for range StallThreshold {
		ct.RecordAction(ActionEntry{Tool: "click"})
	}
	if len(ct.StalledCheckpoints()) != 0 {
		t.Error("at exactly StallThreshold, should NOT be stalled")
	}

	ct.RecordAction(ActionEntry{Tool: "click"})
	if len(ct.StalledCheckpoints()) != 1 {
		t.Error("above StallThreshold, should be stalled")
	}
}

// =============================================================================
// Checkpoint compass
// =============================================================================

func TestCheckpointCompass(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}

	bc.checkpoints.Create("login", "Login", "Test login", nil, "", "", "", PhaseBreadth, 500)
	cp2 := bc.checkpoints.Create("dashboard", "Dashboard", "Check widgets", nil, "", "", "", PhaseBreadth, 500)
	bc.checkpoints.Create("settings", "Settings", "Update profile", nil, "", "", "", PhaseBreadth, 500)

	bc.checkpoints.Activate(cp2.ID)
	bc.checkpoints.RecordAction(ActionEntry{Tool: "click"})
	bc.checkpoints.RecordAction(ActionEntry{Tool: "click"})

	compass := bc.renderCompass()

	if !strings.Contains(compass, "=== CHECKPOINT COMPASS ===") {
		t.Error("missing compass header")
	}
	if !strings.Contains(compass, "[DISCOVERED]") {
		t.Error("missing DISCOVERED status")
	}
	if !strings.Contains(compass, "[ACTIVE]") {
		t.Error("missing ACTIVE status")
	}
	if !strings.Contains(compass, "PROGRESS:") {
		t.Error("missing progress line")
	}
	if !strings.Contains(compass, "login") {
		t.Error("missing login checkpoint")
	}
	if !strings.Contains(compass, "dashboard") {
		t.Error("missing dashboard checkpoint")
	}
	if !strings.Contains(compass, "(2 actions)") {
		t.Error("missing action count for active checkpoint")
	}
}

// =============================================================================
// isActionTool
// =============================================================================

func TestIsActionToolCoversAllReplayableTools(t *testing.T) {
	replayableTools := []string{
		"click", "type_text", "select_option", "check",
		"navigate", "go_back", "submit_form", "scroll",
		"execute_js",
	}
	for _, tool := range replayableTools {
		if !isActionTool(tool) {
			t.Errorf("%q should be an action tool", tool)
		}
	}

	readOnlyTools := []string{
		"get_page_text", "get_element_text", "screenshot",
		"get_state_graph",
		"create_checkpoint", "go_to_checkpoint", "resume_replay",
		"abort_replay", "complete_checkpoint", "activate_checkpoint",
		"get_checkpoint_list", "get_next_checkpoint", "update_checkpoint",
		"register_entity", "get_created_entities", "mark_entity_deleted",
		"store_credentials", "get_credentials",
		"blacklist_element", "get_blacklist",
		"log_finding", "terminate_crawl",
	}
	for _, tool := range readOnlyTools {
		if isActionTool(tool) {
			t.Errorf("%q should NOT be an action tool", tool)
		}
	}
}

// =============================================================================
// MCP tool definitions
// =============================================================================

func TestAllToolsHaveMCPDefinitions(t *testing.T) {
	defs := allToolDefinitions()
	definedTools := make(map[string]bool)
	for _, d := range defs {
		definedTools[d.Name] = true
	}

	allTools := []string{
		"click", "type_text", "select_option", "check",
		"navigate", "go_back", "submit_form", "scroll",
		"get_page_text", "get_element_text", "screenshot",
		"execute_js", "get_state_graph",
		"create_checkpoint", "go_to_checkpoint", "resume_replay",
		"abort_replay", "complete_checkpoint", "activate_checkpoint",
		"get_checkpoint_list", "get_next_checkpoint", "update_checkpoint",
		"register_entity", "get_created_entities", "mark_entity_deleted",
		"store_credentials", "get_credentials",
		"blacklist_element", "get_blacklist",
		"log_finding", "terminate_crawl",
	}

	for _, tool := range allTools {
		if !definedTools[tool] {
			t.Errorf("tool %q has no MCP definition", tool)
		}
	}
}

func TestMCPDefinitionsHaveSchemas(t *testing.T) {
	defs := allToolDefinitions()
	for _, d := range defs {
		if d.InputSchema.Type != "object" {
			t.Errorf("tool %q: inputSchema.type should be 'object'", d.Name)
		}
		if d.Description == "" {
			t.Errorf("tool %q: missing description", d.Name)
		}
	}
}

// =============================================================================
// Required parameters
// =============================================================================

func TestToolRequiredParameters(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}
	ctx := context.Background()

	tests := []struct {
		tool string
		args map[string]string
	}{
		{"click", map[string]string{}},
		{"type_text", map[string]string{}},
		{"select_option", map[string]string{}},
		{"check", map[string]string{}},
		{"navigate", map[string]string{}},
		{"submit_form", map[string]string{}},
		{"execute_js", map[string]string{}},
		{"get_element_text", map[string]string{}},
		{"create_checkpoint", map[string]string{}},
		{"go_to_checkpoint", map[string]string{}},
		{"complete_checkpoint", map[string]string{}},
		{"update_checkpoint", map[string]string{}},
		{"mark_entity_deleted", map[string]string{}},
		{"register_entity", map[string]string{"type": "user"}},
		{"blacklist_element", map[string]string{}},
	}

	for _, tt := range tests {
		result, _ := bc.HandleTool(ctx, tt.tool, tt.args)
		var tr ToolResult
		_ = json.Unmarshal([]byte(result), &tr)
		if tr.Success {
			t.Errorf("%s with empty required args should fail", tt.tool)
		}
		if tr.Error == "" {
			t.Errorf("%s should return an error message", tt.tool)
		}
	}
}

// =============================================================================
// Session tools
// =============================================================================

func TestTerminateCrawlTool(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
		crawlPhase:  PhaseDepth,
	}

	result, _ := bc.HandleTool(context.Background(), "terminate_crawl", map[string]string{
		"reason": "all checkpoints completed",
	})
	var tr ToolResult
	_ = json.Unmarshal([]byte(result), &tr)
	if !tr.Success {
		t.Error("terminate_crawl should succeed")
	}
	data := tr.Data.(map[string]any)
	if data["terminating"] != true {
		t.Error("should indicate terminating=true")
	}
}

func TestLogFindingTool(t *testing.T) {
	bc := &PilotCrawler{
		checkpoints: NewCheckpointTracker(""),
		entities:    NewEntityTracker(),
		blacklist:   NewBlacklist(),
		trace:       mustNewTrace(t),
	}

	result, _ := bc.HandleTool(context.Background(), "log_finding", map[string]string{
		"description": "XSS in search field",
		"severity":    "high",
	})
	var tr ToolResult
	_ = json.Unmarshal([]byte(result), &tr)
	if !tr.Success {
		t.Error("log_finding should succeed")
	}
}

// =============================================================================
// Checkpoint persistence
// =============================================================================

func TestCheckpointPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoints.json")

	// Create and persist
	ct1 := NewCheckpointTracker(path)
	ct1.Create("login", "Login", "Test login", nil, "", "", "", PhaseBreadth, 500)
	ct1.Create("dashboard", "Dashboard", "Check widgets", nil, "", "", "", PhaseBreadth, 500)

	// Load in a new tracker
	ct2 := NewCheckpointTracker(path)
	if err := ct2.Load(); err != nil {
		t.Fatal(err)
	}

	all := ct2.All()
	if len(all) != 2 {
		t.Errorf("expected 2 checkpoints after load, got %d", len(all))
	}
	if all[0].Name != "login" || all[1].Name != "dashboard" {
		t.Error("checkpoint names don't match after load")
	}

	// Next ID should continue from where it left off
	cp3 := ct2.Create("settings", "Settings", "Update profile", nil, "", "", "", PhaseBreadth, 500)
	if cp3.ID != "cp_3" {
		t.Errorf("expected cp_3, got %s", cp3.ID)
	}
}

// =============================================================================
// Helpers
// =============================================================================

func mustNewTrace(t *testing.T) *SessionTrace {
	t.Helper()
	tr, err := NewSessionTrace("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}
