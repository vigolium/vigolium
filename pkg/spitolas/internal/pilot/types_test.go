package pilot

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

func TestCheckpointTrackerLifecycle(t *testing.T) {
	ct := NewCheckpointTracker("")

	// Create checkpoints
	cp1 := ct.Create("login", "Login page", "Test login form", nil, "http://app.com/login", "", "", PhaseBreadth, 500)
	cp2 := ct.Create("dashboard", "Main dashboard", "Check widgets", []NavigationStep{
		{Tool: "click", Args: map[string]string{"xpath": "/html/body/nav/a[1]"}, Intent: "Click Dashboard"},
	}, "http://app.com/dashboard", "", "", PhaseBreadth, 500)

	// Check stats
	discovered, active, completed, blocked := ct.Stats()
	if discovered != 2 || active != 0 || completed != 0 || blocked != 0 {
		t.Errorf("expected 2/0/0/0, got %d/%d/%d/%d", discovered, active, completed, blocked)
	}

	// Activate
	f, ok := ct.Activate(cp1.ID)
	if !ok || f.Name != "login" {
		t.Error("Activate failed")
	}
	if ct.ActiveID() != cp1.ID {
		t.Error("ActiveID should be cp1")
	}

	// Complete
	_, ok = ct.Complete(cp1.ID, "tested login form")
	if !ok {
		t.Error("Complete failed")
	}
	if ct.ActiveID() != "" {
		t.Error("ActiveID should be empty after complete")
	}

	// NextPending should return dashboard
	next := ct.NextPending()
	if next == nil || next.ID != cp2.ID {
		t.Error("NextPending should return dashboard")
	}

	// Stats
	discovered, _, completed, _ = ct.Stats()
	if discovered != 1 || completed != 1 {
		t.Errorf("expected 1/1, got %d/%d", discovered, completed)
	}
}

func TestCheckpointStallDetection(t *testing.T) {
	ct := NewCheckpointTracker("")
	cp := ct.Create("slow", "Takes many actions", "...", nil, "", "", "", PhaseBreadth, 500)
	ct.Activate(cp.ID)

	// Record actions past threshold
	for i := 0; i < StallThreshold+5; i++ {
		ct.RecordAction(ActionEntry{Tool: "click"})
	}

	stalled := ct.StalledCheckpoints()
	if len(stalled) != 1 || stalled[0].ID != cp.ID {
		t.Error("expected one stalled checkpoint")
	}
}

func TestCheckpointHierarchy(t *testing.T) {
	ct := NewCheckpointTracker("")

	parent := ct.Create("users", "User management", "CRUD", nil, "", "", "", PhaseBreadth, 500)
	child1 := ct.Create("roles", "Role management", "Assign roles", nil, "", "", parent.ID, PhaseBreadth, 500)
	child2 := ct.Create("groups", "Group management", "Create groups", nil, "", "", parent.ID, PhaseBreadth, 500)

	// Parent should have children
	p, _ := ct.Get(parent.ID)
	if len(p.Children) != 2 {
		t.Errorf("expected 2 children, got %d", len(p.Children))
	}
	if p.Children[0] != child1.ID || p.Children[1] != child2.ID {
		t.Error("children IDs don't match")
	}

	// Children should have parent
	c1, _ := ct.Get(child1.ID)
	if c1.ParentID != parent.ID {
		t.Error("child1 parent should be users")
	}
}

func TestCheckpointBlock(t *testing.T) {
	ct := NewCheckpointTracker("")
	cp := ct.Create("broken", "Unreachable", "...", nil, "", "", "", PhaseBreadth, 500)

	_, ok := ct.Block(cp.ID, "cannot navigate to this page")
	if !ok {
		t.Error("Block should succeed")
	}

	blocked, _ := ct.Get(cp.ID)
	if blocked.Status != CheckpointBlocked {
		t.Errorf("expected blocked, got %s", blocked.Status)
	}
	if blocked.Notes != "cannot navigate to this page" {
		t.Error("notes not saved")
	}
}

func TestCheckpointReplayState(t *testing.T) {
	ct := NewCheckpointTracker("")
	cp := ct.Create("test", "Test", "...", []NavigationStep{
		{Tool: "click", Args: map[string]string{"xpath": "/a[1]"}},
		{Tool: "click", Args: map[string]string{"xpath": "/a[2]"}},
		{Tool: "click", Args: map[string]string{"xpath": "/a[3]"}},
	}, "", "", "", PhaseBreadth, 500)

	// Start replay
	_, ok := ct.StartReplay(cp.ID)
	if !ok {
		t.Fatal("StartReplay failed")
	}
	if ct.ReplayingID() != cp.ID {
		t.Error("ReplayingID should be set")
	}

	// Simulate step failure at step 1
	ct.SetWaitingForHelp(1)
	id, cursor, state, total := ct.GetReplayState()
	if id != cp.ID || cursor != 1 || state != replayWaitingForHelp || total != 3 {
		t.Errorf("unexpected replay state: id=%s cursor=%d state=%d total=%d", id, cursor, state, total)
	}

	// Advance past failed step
	newCursor, newTotal := ct.AdvanceReplayCursor()
	if newCursor != 2 || newTotal != 3 {
		t.Errorf("expected cursor=2 total=3, got %d/%d", newCursor, newTotal)
	}

	// Abort replay
	abortedID := ct.AbortReplay()
	if abortedID != cp.ID {
		t.Error("AbortReplay should return the checkpoint ID")
	}
	if ct.ReplayingID() != "" {
		t.Error("ReplayingID should be empty after abort")
	}
}

func TestCheckpointScopedActions(t *testing.T) {
	ct := NewCheckpointTracker("")
	cp := ct.Create("test", "Test", "...", nil, "", "", "", PhaseBreadth, 500)
	ct.Activate(cp.ID)

	// Record scoped actions
	ct.RecordAction(ActionEntry{Tool: "click", Args: map[string]string{"xpath": "/a[1]"}, Success: true})
	ct.RecordAction(ActionEntry{Tool: "type_text", Args: map[string]string{"xpath": "/input"}, Success: true})

	active := ct.Active()
	if active.ActionCount != 2 {
		t.Errorf("expected 2 actions, got %d", active.ActionCount)
	}

	recent := ct.RecentActions(1)
	if len(recent) != 1 || recent[0].Tool != "type_text" {
		t.Error("RecentActions(1) should return last action")
	}

	all := ct.RecentActions(0)
	if len(all) != 2 {
		t.Error("RecentActions(0) should return all actions")
	}
}

func TestEntityTracker(t *testing.T) {
	et := NewEntityTracker()

	id1 := et.Register("user", "test@example.com", "state_001")
	id2 := et.Register("post", "Hello World", "state_002")

	all := et.All()
	if len(all) != 2 {
		t.Errorf("expected 2 entities, got %d", len(all))
	}

	if !et.MarkDeleted(id1) {
		t.Error("MarkDeleted should succeed")
	}
	if et.MarkDeleted("nonexistent") {
		t.Error("MarkDeleted should fail for nonexistent")
	}
	_ = id2
}

func TestBlacklist(t *testing.T) {
	bl := NewBlacklist()

	bl.Add("/html/body/nav/a[5]", "logout", true)
	bl.Add("/html/body/footer/a[1]", "dangerous", false)

	reason, blocked := bl.IsBlacklisted("/html/body/nav/a[5]")
	if !blocked || reason != "logout" {
		t.Error("should be blacklisted")
	}

	_, blocked = bl.IsBlacklisted("/html/body/nav/a[1]")
	if blocked {
		t.Error("should not be blacklisted")
	}

	all := bl.All()
	if len(all) != 2 {
		t.Errorf("expected 2 entries, got %d", len(all))
	}
}

// =============================================================================
// deriveNavigationSteps — compound edge BFS
// =============================================================================

// newBFSTestCrawler creates a PilotCrawler with a state graph and trace for BFS tests.
// States are created fresh (counter is reset).
func newBFSTestCrawler(t *testing.T) (*PilotCrawler, *state.Graph, *SessionTrace) {
	t.Helper()
	state.ResetCounter()
	graph := state.NewGraph()
	trace, err := NewSessionTrace("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { trace.Close() })
	bc := &PilotCrawler{
		graph:       graph,
		trace:       trace,
		checkpoints: NewCheckpointTracker(""),
	}
	return bc, graph, trace
}

// TestDeriveNavSteps_LoginFormFill verifies that type_text + submit_form sequences
// are included in navigation steps. This is the exact scenario from the ginandjuice
// login flow: click login → type username → submit → type password → submit.
func TestDeriveNavSteps_LoginFormFill(t *testing.T) {
	bc, graph, trace := newBFSTestCrawler(t)

	// Create 4 states: root → login(username) → login(password) → my-account
	sRoot := state.New("http://app.com/", "", "root-dom", 0)
	sLoginUser := state.New("http://app.com/login", "", "login-user-dom", 1)
	sLoginPass := state.New("http://app.com/login", "", "login-pass-dom", 2)
	sAccount := state.New("http://app.com/my-account", "", "account-dom", 3)
	graph.AddState(sRoot)
	graph.AddState(sLoginUser)
	graph.AddState(sLoginPass)
	graph.AddState(sAccount)

	// Simulate the login action sequence:
	// 1. click "Log in" link: root → login(username form)
	trace.RecordAction("click", map[string]string{"xpath": "//nav/a[5]"},
		true, "", snap(sRoot), snap(sLoginUser), 100*time.Millisecond)
	// 2. type username: stays on same state (no DOM change)
	trace.RecordAction("type_text", map[string]string{"xpath": "//input[1]", "value": "carlos"},
		true, "", snap(sLoginUser), snap(sLoginUser), 50*time.Millisecond)
	// 3. submit username form: transitions to password form
	trace.RecordAction("submit_form", map[string]string{"form_xpath": "//form[1]"},
		true, "", snap(sLoginUser), snap(sLoginPass), 200*time.Millisecond)
	// 4. type password: stays on same state
	trace.RecordAction("type_text", map[string]string{"xpath": "//input[2]", "value": "hunter2"},
		true, "", snap(sLoginPass), snap(sLoginPass), 50*time.Millisecond)
	// 5. submit password form: transitions to my-account
	trace.RecordAction("submit_form", map[string]string{"form_xpath": "//form[1]"},
		true, "", snap(sLoginPass), snap(sAccount), 200*time.Millisecond)

	// Target: derive steps from root to my-account
	bc.currentState = sAccount
	steps := bc.deriveNavigationSteps()

	// All 5 steps must be present (including the 2 type_text steps)
	if len(steps) != 5 {
		t.Fatalf("expected 5 navigation steps, got %d: %v", len(steps), toolNames(steps))
	}

	wantTools := []string{"click", "type_text", "submit_form", "type_text", "submit_form"}
	for i, want := range wantTools {
		if steps[i].Tool != want {
			t.Errorf("step %d: expected tool %q, got %q", i, want, steps[i].Tool)
		}
	}

	// Verify credential values are preserved
	if steps[1].Args["value"] != "carlos" {
		t.Errorf("step 1 (username): expected value \"carlos\", got %q", steps[1].Args["value"])
	}
	if steps[3].Args["value"] != "hunter2" {
		t.Errorf("step 3 (password): expected value \"hunter2\", got %q", steps[3].Args["value"])
	}
}

// TestDeriveNavSteps_ChildCheckpointIncludesAuth verifies that navigation steps for
// a checkpoint created AFTER login include the full auth path from root.
// This tests the scenario: root → login → my-account → click "Order details".
func TestDeriveNavSteps_ChildCheckpointIncludesAuth(t *testing.T) {
	bc, graph, trace := newBFSTestCrawler(t)

	sRoot := state.New("http://app.com/", "", "root-dom", 0)
	sLogin := state.New("http://app.com/login", "", "login-dom", 1)
	sAccount := state.New("http://app.com/my-account", "", "account-dom", 2)
	sOrderDetail := state.New("http://app.com/order/1", "", "order-dom", 3)
	graph.AddState(sRoot)
	graph.AddState(sLogin)
	graph.AddState(sAccount)
	graph.AddState(sOrderDetail)

	// Login flow: click → type → submit
	trace.RecordAction("click", map[string]string{"xpath": "//nav/a[5]"},
		true, "", snap(sRoot), snap(sLogin), 100*time.Millisecond)
	trace.RecordAction("type_text", map[string]string{"xpath": "//input[1]", "value": "admin"},
		true, "", snap(sLogin), snap(sLogin), 50*time.Millisecond)
	trace.RecordAction("type_text", map[string]string{"xpath": "//input[2]", "value": "secret"},
		true, "", snap(sLogin), snap(sLogin), 50*time.Millisecond)
	trace.RecordAction("submit_form", map[string]string{"form_xpath": "//form[1]"},
		true, "", snap(sLogin), snap(sAccount), 200*time.Millisecond)
	// Navigate to order detail
	trace.RecordAction("click", map[string]string{"xpath": "//table/tr[1]/a"},
		true, "", snap(sAccount), snap(sOrderDetail), 100*time.Millisecond)

	// Derive steps from root to order detail (child of authenticated area)
	bc.currentState = sOrderDetail
	steps := bc.deriveNavigationSteps()

	// Should include: click login, type user, type pass, submit, click order
	if len(steps) != 5 {
		t.Fatalf("expected 5 steps (including auth), got %d: %v", len(steps), toolNames(steps))
	}

	wantTools := []string{"click", "type_text", "type_text", "submit_form", "click"}
	for i, want := range wantTools {
		if steps[i].Tool != want {
			t.Errorf("step %d: expected %q, got %q", i, want, steps[i].Tool)
		}
	}
}

// TestDeriveNavSteps_SimpleClickPath verifies BFS still works for simple
// click-only navigation (no form fills).
func TestDeriveNavSteps_SimpleClickPath(t *testing.T) {
	bc, graph, trace := newBFSTestCrawler(t)

	s1 := state.New("http://app.com/", "", "root", 0)
	s2 := state.New("http://app.com/catalog", "", "catalog", 1)
	s3 := state.New("http://app.com/product", "", "product", 2)
	graph.AddState(s1)
	graph.AddState(s2)
	graph.AddState(s3)

	trace.RecordAction("click", map[string]string{"xpath": "//nav/a[1]"},
		true, "", snap(s1), snap(s2), 100*time.Millisecond)
	trace.RecordAction("click", map[string]string{"xpath": "//product/a[1]"},
		true, "", snap(s2), snap(s3), 100*time.Millisecond)

	bc.currentState = s3
	steps := bc.deriveNavigationSteps()

	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}
	if steps[0].Tool != "click" || steps[1].Tool != "click" {
		t.Error("both steps should be clicks")
	}
}

// TestDeriveNavSteps_AtRoot returns nil when already at root.
func TestDeriveNavSteps_AtRoot(t *testing.T) {
	bc, graph, _ := newBFSTestCrawler(t)

	s := state.New("http://app.com/", "", "root", 0)
	graph.AddState(s)
	bc.currentState = s

	steps := bc.deriveNavigationSteps()
	if steps != nil {
		t.Errorf("expected nil steps at root, got %d steps", len(steps))
	}
}

// TestDeriveNavSteps_OrphanedFormFills verifies that form fills NOT followed by
// a state transition are correctly discarded (not leaked into the next edge).
func TestDeriveNavSteps_OrphanedFormFills(t *testing.T) {
	bc, graph, trace := newBFSTestCrawler(t)

	s1 := state.New("http://app.com/", "", "root", 0)
	s2 := state.New("http://app.com/page", "", "page", 1)
	s3 := state.New("http://app.com/other", "", "other", 2)
	graph.AddState(s1)
	graph.AddState(s2)
	graph.AddState(s3)

	// Navigate to page
	trace.RecordAction("click", map[string]string{"xpath": "//a[1]"},
		true, "", snap(s1), snap(s2), 100*time.Millisecond)
	// Type something on page (same state — no submit follows)
	trace.RecordAction("type_text", map[string]string{"xpath": "//input", "value": "orphan"},
		true, "", snap(s2), snap(s2), 50*time.Millisecond)
	// Navigate away (different action, the type_text is orphaned)
	trace.RecordAction("click", map[string]string{"xpath": "//a[2]"},
		true, "", snap(s2), snap(s3), 100*time.Millisecond)

	bc.currentState = s3
	steps := bc.deriveNavigationSteps()

	// The orphaned type_text should be grouped with the click that follows
	// (both actions happen on s2 and the click transitions to s3)
	if len(steps) != 3 {
		t.Fatalf("expected 3 steps (click + type_text + click), got %d: %v", len(steps), toolNames(steps))
	}
	wantTools := []string{"click", "type_text", "click"}
	for i, want := range wantTools {
		if steps[i].Tool != want {
			t.Errorf("step %d: expected %q, got %q", i, want, steps[i].Tool)
		}
	}
}

// TestDeriveNavSteps_SelectOptionIncluded verifies select_option (dropdown) is
// included in navigation steps just like type_text.
func TestDeriveNavSteps_SelectOptionIncluded(t *testing.T) {
	bc, graph, trace := newBFSTestCrawler(t)

	s1 := state.New("http://app.com/", "", "root", 0)
	s2 := state.New("http://app.com/form", "", "form", 1)
	s3 := state.New("http://app.com/result", "", "result", 2)
	graph.AddState(s1)
	graph.AddState(s2)
	graph.AddState(s3)

	trace.RecordAction("click", map[string]string{"xpath": "//a[1]"},
		true, "", snap(s1), snap(s2), 100*time.Millisecond)
	trace.RecordAction("select_option", map[string]string{"xpath": "//select", "value": "store_123"},
		true, "", snap(s2), snap(s2), 50*time.Millisecond)
	trace.RecordAction("submit_form", map[string]string{"form_xpath": "//form"},
		true, "", snap(s2), snap(s3), 200*time.Millisecond)

	bc.currentState = s3
	steps := bc.deriveNavigationSteps()

	if len(steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(steps))
	}
	if steps[1].Tool != "select_option" {
		t.Errorf("step 1: expected select_option, got %q", steps[1].Tool)
	}
	if steps[1].Args["value"] != "store_123" {
		t.Errorf("step 1: expected value \"store_123\", got %q", steps[1].Args["value"])
	}
}

// snap creates a StateSnapshot from a state for use in RecordAction.
func snap(s *state.State) StateSnapshot {
	return StateSnapshot{StateID: s.Name, URL: s.URL}
}

// toolNames extracts tool names from a NavigationStep slice for diagnostic output.
func toolNames(steps []NavigationStep) []string {
	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.Tool
	}
	return names
}

func TestSessionTrace(t *testing.T) {
	tr, err := NewSessionTrace("")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	before := StateSnapshot{StateID: "state_001", URL: "http://test.com"}
	after := StateSnapshot{StateID: "state_002", URL: "http://test.com/page2", IsNew: true}

	entry := tr.RecordAction("click", map[string]string{"xpath": "/html/body/a[1]"}, true, "", before, after, 100)
	if entry.Tool != "click" {
		t.Error("RecordAction should return the entry")
	}
	tr.RecordAction("type_text", map[string]string{"xpath": "/html/body/input", "value": "test"}, true, "", after, after, 50)

	if tr.Len() != 2 {
		t.Errorf("expected 2 entries, got %d", tr.Len())
	}

	entries := tr.Entries(1)
	if len(entries) != 1 || entries[0].Tool != "click" {
		t.Error("Entries(1) should return first entry only")
	}

	allEntries := tr.Entries(0)
	if len(allEntries) != 2 {
		t.Error("Entries(0) should return all entries")
	}
}
