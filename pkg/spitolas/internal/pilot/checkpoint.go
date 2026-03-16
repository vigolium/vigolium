package pilot

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

// CheckpointStatus represents the lifecycle state of a checkpoint.
type CheckpointStatus string

const (
	CheckpointDiscovered CheckpointStatus = "discovered"
	CheckpointActive     CheckpointStatus = "active"
	CheckpointCompleted  CheckpointStatus = "completed"
	CheckpointBlocked    CheckpointStatus = "blocked"
	CheckpointAbandoned  CheckpointStatus = "abandoned"
)

// CrawlPhase distinguishes breadth-first discovery from depth exploration.
type CrawlPhase string

const (
	PhaseBreadth CrawlPhase = "breadth"
	PhaseDepth   CrawlPhase = "depth"
)

// replayState tracks the internal state of navigating to a checkpoint.
type replayState int

const (
	replayIdle           replayState = iota // not navigating
	replayWaitingForHelp                    // step failed, LLM intervening
	replayReached                           // successfully arrived at checkpoint
)

// NavigationStep records one action in the sequential path from root URL to a checkpoint.
// For SPAs where URLs don't change, this sequential replay is the ONLY reliable way
// to reach a checkpoint.
type NavigationStep struct {
	Tool            string            `json:"tool"`
	Args            map[string]string `json:"args"`
	Intent          string            `json:"intent"`                      // human-readable: "Click 'Users' in sidebar"
	ElementText     string            `json:"element_text,omitempty"`      // visible text of the target element
	ExpectedDOMHint string            `json:"expected_dom_hint,omitempty"` // expected page title after this step
}

// StallThreshold is the number of actions after which a checkpoint is considered stalled.
const StallThreshold = 30

// Checkpoint is a resumable waypoint in the pilot-driven crawl.
// Each checkpoint represents a discovered feature/area with:
//   - NavigationSteps: sequential actions from root URL to reach it
//   - TestPlan: what the LLM should do when exploring it
//   - Actions: scoped recording of what was done during exploration
type Checkpoint struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	TestPlan    string           `json:"test_plan"`
	Status      CheckpointStatus `json:"status"`
	Priority    int              `json:"priority"` // 1-1000, higher = processed first
	Notes       string           `json:"notes,omitempty"`

	// Navigation: full sequential steps from ROOT URL to this checkpoint.
	// Always starts at root. For SPAs, this is the ONLY reliable way to get here.
	NavigationSteps []NavigationStep `json:"navigation_steps"`

	// DOM fingerprint at creation time — used to verify arrival after replay.
	// Human-readable JSON: {title, h1, nav, formCount}.
	DOMFingerprint string `json:"dom_fingerprint"`

	// URL at creation time (informational — NOT used for navigation in SPAs).
	PageURL string `json:"page_url"`

	// Scoped action recording (only actions taken while exploring THIS checkpoint).
	Actions     []ActionEntry `json:"actions,omitempty"`
	ActionCount int           `json:"action_count"`

	// Hierarchy: checkpoints discovered while exploring another checkpoint.
	ParentID string   `json:"parent_id,omitempty"`
	Children []string `json:"children,omitempty"`

	// Phase tracking: which crawl phase created/completed this checkpoint.
	Phase CrawlPhase `json:"phase"`

	// Timestamps.
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Internal replay state (transient, not persisted to disk).
	replayCursor int
	replayState  replayState
}

// CheckpointTracker manages all checkpoints and their lifecycle.
// It is the Go-managed ground truth that survives ACP session boundaries.
type CheckpointTracker struct {
	mu          sync.RWMutex
	checkpoints map[string]*Checkpoint
	order       []string // discovery order
	activeID    string   // currently active (exploring) checkpoint
	replayingID string   // checkpoint being navigated to via go_to_checkpoint
	nextID      int
	persistPath string // path to checkpoints.json for crash recovery
}

// NewCheckpointTracker creates a new tracker. If persistPath is non-empty,
// checkpoints are saved to disk after every mutation for crash recovery.
func NewCheckpointTracker(persistPath string) *CheckpointTracker {
	return &CheckpointTracker{
		checkpoints: make(map[string]*Checkpoint),
		order:       make([]string, 0),
		persistPath: persistPath,
	}
}

// === CRUD ===

// Create registers a new checkpoint in discovered status.
func (ct *CheckpointTracker) Create(name, description, testPlan string, steps []NavigationStep, pageURL, domFingerprint, parentID string, phase CrawlPhase, priority int) *Checkpoint {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.nextID++
	id := "cp_" + strconv.Itoa(ct.nextID)

	cp := &Checkpoint{
		ID:              id,
		Name:            name,
		Description:     description,
		TestPlan:        testPlan,
		Status:          CheckpointDiscovered,
		Priority:        priority,
		NavigationSteps: steps,
		DOMFingerprint:  domFingerprint,
		PageURL:         pageURL,
		ParentID:        parentID,
		Phase:           phase,
		CreatedAt:       time.Now(),
	}
	ct.checkpoints[id] = cp
	ct.order = append(ct.order, id)

	if parentID != "" {
		if parent, ok := ct.checkpoints[parentID]; ok {
			parent.Children = append(parent.Children, id)
		}
	}

	ct.persist()
	return cp
}

// Get returns a checkpoint by ID.
func (ct *CheckpointTracker) Get(id string) (*Checkpoint, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	cp, ok := ct.checkpoints[id]
	return cp, ok
}

// All returns all checkpoints in discovery order.
func (ct *CheckpointTracker) All() []*Checkpoint {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	result := make([]*Checkpoint, 0, len(ct.order))
	for _, id := range ct.order {
		if cp, ok := ct.checkpoints[id]; ok {
			result = append(result, cp)
		}
	}
	return result
}

// Update modifies mutable fields of a checkpoint.
func (ct *CheckpointTracker) Update(id string, fn func(*Checkpoint)) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	cp, ok := ct.checkpoints[id]
	if !ok {
		return false
	}
	fn(cp)
	ct.persist()
	return true
}

// === Lifecycle ===

// Activate marks a checkpoint as active and starts scoped action recording.
// On first activation, clears actions. On re-activation (e.g., returning to a
// checkpoint after exploring another), preserves existing actions.
func (ct *CheckpointTracker) Activate(id string) (*Checkpoint, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	cp, ok := ct.checkpoints[id]
	if !ok {
		return nil, false
	}

	// Only reset actions on first activation (discovered → active).
	// Re-activation preserves existing action history.
	if cp.Status == CheckpointDiscovered {
		cp.ActionCount = 0
		cp.Actions = nil
	}

	cp.Status = CheckpointActive
	cp.replayState = replayReached
	ct.activeID = id
	ct.replayingID = ""
	ct.persist()
	return cp, true
}

// Complete marks a checkpoint as completed and stops scoped recording.
func (ct *CheckpointTracker) Complete(id, notes string) (*Checkpoint, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	cp, ok := ct.checkpoints[id]
	if !ok {
		return nil, false
	}
	cp.Status = CheckpointCompleted
	cp.Notes = notes
	now := time.Now()
	cp.CompletedAt = &now

	if ct.activeID == id {
		ct.activeID = ""
	}
	ct.persist()
	return cp, true
}

// Abandon marks a checkpoint as abandoned (gave up after repeated failures).
func (ct *CheckpointTracker) Abandon(id, notes string) (*Checkpoint, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	cp, ok := ct.checkpoints[id]
	if !ok {
		return nil, false
	}
	cp.Status = CheckpointAbandoned
	cp.Notes = notes
	now := time.Now()
	cp.CompletedAt = &now

	if ct.activeID == id {
		ct.activeID = ""
	}
	if ct.replayingID == id {
		ct.replayingID = ""
	}
	ct.persist()
	return cp, true
}

// Block marks a checkpoint as blocked (unreachable or broken).
func (ct *CheckpointTracker) Block(id, reason string) (*Checkpoint, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	cp, ok := ct.checkpoints[id]
	if !ok {
		return nil, false
	}
	cp.Status = CheckpointBlocked
	cp.Notes = reason

	if ct.activeID == id {
		ct.activeID = ""
	}
	if ct.replayingID == id {
		ct.replayingID = ""
	}
	ct.persist()
	return cp, true
}

// === Query ===

// ActiveID returns the ID of the currently active checkpoint, or "".
func (ct *CheckpointTracker) ActiveID() string {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.activeID
}

// Active returns the currently active checkpoint, or nil.
func (ct *CheckpointTracker) Active() *Checkpoint {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	if ct.activeID == "" {
		return nil
	}
	return ct.checkpoints[ct.activeID]
}

// ReplayingID returns the ID of the checkpoint being navigated to, or "".
func (ct *CheckpointTracker) ReplayingID() string {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.replayingID
}

// NextPending returns the highest-priority discovered (unexplored) checkpoint.
func (ct *CheckpointTracker) NextPending() *Checkpoint {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var best *Checkpoint
	for _, id := range ct.order {
		cp := ct.checkpoints[id]
		if cp != nil && cp.Status == CheckpointDiscovered {
			if best == nil || cp.Priority > best.Priority {
				best = cp
			}
		}
	}
	return best
}

// Stats returns counts by status.
func (ct *CheckpointTracker) Stats() (discovered, active, completed, blocked int) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	for _, cp := range ct.checkpoints {
		switch cp.Status {
		case CheckpointDiscovered:
			discovered++
		case CheckpointActive:
			active++
		case CheckpointCompleted:
			completed++
		case CheckpointBlocked:
			blocked++
		case CheckpointAbandoned:
			// Abandoned checkpoints don't count as pending — they won't block termination
		}
	}
	return
}

// PendingCount returns the number of discovered (not yet explored) checkpoints.
func (ct *CheckpointTracker) PendingCount() int {
	d, _, _, _ := ct.Stats()
	return d
}

// StalledCheckpoints returns checkpoints that have been active for too many actions.
func (ct *CheckpointTracker) StalledCheckpoints() []*Checkpoint {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var stalled []*Checkpoint
	for _, cp := range ct.checkpoints {
		if cp.Status == CheckpointActive && cp.ActionCount > StallThreshold {
			stalled = append(stalled, cp)
		}
	}
	return stalled
}

// === Scoped Action Recording ===

// maxCheckpointActions is the maximum number of actions kept in a checkpoint's rolling window.
// ActionCount tracks the true total; Actions is capped to avoid unbounded memory growth.
const maxCheckpointActions = 50

// RecordAction appends an action to the active checkpoint's scoped action list.
// Only records when a checkpoint is active (being explored, not during replay navigation).
// Actions are capped at a rolling window; ActionCount tracks the true total.
func (ct *CheckpointTracker) RecordAction(entry ActionEntry) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.activeID == "" {
		return
	}
	cp, ok := ct.checkpoints[ct.activeID]
	if !ok || cp.Status != CheckpointActive {
		return
	}
	cp.ActionCount++
	cp.Actions = append(cp.Actions, entry)
	if len(cp.Actions) > maxCheckpointActions {
		cp.Actions = cp.Actions[len(cp.Actions)-maxCheckpointActions:]
	}
}

// RecentActions returns the last n actions from the active checkpoint.
func (ct *CheckpointTracker) RecentActions(n int) []ActionEntry {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if ct.activeID == "" {
		return nil
	}
	cp, ok := ct.checkpoints[ct.activeID]
	if !ok {
		return nil
	}
	if n <= 0 || n >= len(cp.Actions) {
		result := make([]ActionEntry, len(cp.Actions))
		copy(result, cp.Actions)
		return result
	}
	start := len(cp.Actions) - n
	result := make([]ActionEntry, n)
	copy(result, cp.Actions[start:])
	return result
}

// === Replay State Management ===

// StartReplay marks a checkpoint as being navigated to.
func (ct *CheckpointTracker) StartReplay(id string) (*Checkpoint, bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	cp, ok := ct.checkpoints[id]
	if !ok {
		return nil, false
	}
	cp.replayCursor = 0
	cp.replayState = replayIdle
	ct.replayingID = id
	return cp, true
}

// SetWaitingForHelp marks the replaying checkpoint as needing LLM intervention at the given step.
func (ct *CheckpointTracker) SetWaitingForHelp(cursor int) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.replayingID == "" {
		return
	}
	if cp, ok := ct.checkpoints[ct.replayingID]; ok {
		cp.replayCursor = cursor
		cp.replayState = replayWaitingForHelp
	}
}

// AdvanceReplayCursor moves past the current failed step (LLM handled it or chose to skip).
// Returns the new cursor position and total steps.
func (ct *CheckpointTracker) AdvanceReplayCursor() (cursor, total int) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.replayingID == "" {
		return -1, 0
	}
	cp, ok := ct.checkpoints[ct.replayingID]
	if !ok {
		return -1, 0
	}
	cp.replayCursor++
	cp.replayState = replayIdle
	return cp.replayCursor, len(cp.NavigationSteps)
}

// GetReplayState returns the replay state of the checkpoint being navigated to.
func (ct *CheckpointTracker) GetReplayState() (id string, cursor int, state replayState, total int) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	if ct.replayingID == "" {
		return "", -1, replayIdle, 0
	}
	cp, ok := ct.checkpoints[ct.replayingID]
	if !ok {
		return "", -1, replayIdle, 0
	}
	return ct.replayingID, cp.replayCursor, cp.replayState, len(cp.NavigationSteps)
}

// AbortReplay cancels the current navigation attempt. Checkpoint stays in its current status.
func (ct *CheckpointTracker) AbortReplay() string {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	id := ct.replayingID
	if id != "" {
		if cp, ok := ct.checkpoints[id]; ok {
			cp.replayCursor = 0
			cp.replayState = replayIdle
		}
		ct.replayingID = ""
	}
	return id
}

// === Persistence ===

type checkpointExport struct {
	Checkpoints []*Checkpoint `json:"checkpoints"`
	NextID      int           `json:"next_id"`
	ActiveID    string        `json:"active_id"`
}

// persist saves checkpoints to disk. Must be called with lock held.
func (ct *CheckpointTracker) persist() {
	if ct.persistPath == "" {
		return
	}
	exp := checkpointExport{
		NextID:   ct.nextID,
		ActiveID: ct.activeID,
	}
	for _, id := range ct.order {
		if cp, ok := ct.checkpoints[id]; ok {
			exp.Checkpoints = append(exp.Checkpoints, cp)
		}
	}
	data, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(ct.persistPath, data, 0644)
}

// Load loads checkpoints from disk for crash recovery.
func (ct *CheckpointTracker) Load() error {
	if ct.persistPath == "" {
		return nil
	}
	data, err := os.ReadFile(ct.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var exp checkpointExport
	if err := json.Unmarshal(data, &exp); err != nil {
		return fmt.Errorf("parse checkpoints: %w", err)
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.checkpoints = make(map[string]*Checkpoint, len(exp.Checkpoints))
	ct.order = make([]string, 0, len(exp.Checkpoints))
	for _, cp := range exp.Checkpoints {
		ct.checkpoints[cp.ID] = cp
		ct.order = append(ct.order, cp.ID)
	}
	ct.nextID = exp.NextID
	ct.activeID = exp.ActiveID
	return nil
}
