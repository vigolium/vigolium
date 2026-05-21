package autopilot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// The autopilot engine keeps the full conversation in memory and re-sends it
// every turn — there is no summarisation, so a 200-turn run drifts toward the
// provider's context ceiling and early observations get buried or evicted.
// The scratchpad gives the agent a working memory that is (a) persisted to the
// session dir so it survives process restarts / `vigolium log` replay, and
// (b) echoed back in full on every tool call so the freshest copy always lands
// at the conversation tail where attention is strongest and eviction can't
// reach it. It mirrors the ReportFindingContext pattern: one context per run,
// shared by both tools, guarded by a single mutex.

const (
	// scratchpadNoteSoftCap bounds stored notes. Keyed notes are never
	// evicted (they're deliberate facts the agent chose to pin); once the
	// total exceeds the cap the oldest *unkeyed* notes are dropped first so
	// the freeform log can't grow without bound over a long run.
	scratchpadNoteSoftCap = 200

	// scratchpadFile is the agent-owned state file. Distinct from the
	// pipeline's plan.json (which is read-only seed input) so a resumed run
	// restores agent edits rather than re-seeding from the frozen plan.
	scratchpadFile = "scratchpad.json"

	// pipelinePlanFile is the AutopilotExecutionPlan the agent pipeline
	// freezes before the operator loop starts. We seed from it when the
	// agent hasn't written its own scratchpad yet. Decoded via a local
	// subset struct to avoid an import cycle with pkg/agent.
	pipelinePlanFile = "plan.json"
)

// planStatus is the lifecycle of a single plan item.
const (
	planPending    = "pending"
	planInProgress = "in_progress"
	planDone       = "done"
	planDropped    = "dropped"
)

func validPlanStatus(s string) bool {
	switch s {
	case planPending, planInProgress, planDone, planDropped:
		return true
	}
	return false
}

// PlanItem is one tracked task. ID is stable across update_plan calls so the
// agent can re-state the list without losing identity; Status drives the
// rendered checkbox.
type PlanItem struct {
	ID     string `json:"id"`
	Task   string `json:"task"`
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// Note is one durable observation. Key, when set, makes the note an
// upsert slot ("auth-scheme", "idor-export") so the agent can refine a fact
// without piling up stale copies.
type Note struct {
	Key  string   `json:"key,omitempty"`
	Text string   `json:"text"`
	Tags []string `json:"tags,omitempty"`
	At   string   `json:"at"`
}

// ScratchpadContext is the per-run working memory shared by update_plan and
// remember. SessionDir == "" degrades to in-memory only (still useful within
// the run, just not replayable).
type ScratchpadContext struct {
	SessionDir string

	mu           sync.Mutex
	plan         []PlanItem
	notes        []Note
	stopCriteria []string // seeded from pipeline plan.json; surfaced, not editable
}

// scratchpadState is the on-disk shape (our own file, full round-trip).
type scratchpadState struct {
	Plan         []PlanItem `json:"plan"`
	Notes        []Note     `json:"notes"`
	StopCriteria []string   `json:"stop_criteria,omitempty"`
}

// NewScratchpadContext builds the run-scoped working memory and restores any
// prior state (resume) or, failing that, seeds the plan from the pipeline's
// frozen execution plan so the operator starts against a real task list rather
// than a blank page.
func NewScratchpadContext(sessionDir string) *ScratchpadContext {
	c := &ScratchpadContext{SessionDir: sessionDir}
	c.loadOrSeed()
	return c
}

func (c *ScratchpadContext) autopilotDir() string {
	if c.SessionDir == "" {
		return ""
	}
	return filepath.Join(c.SessionDir, "autopilot")
}

// loadOrSeed restores scratchpad.json if present (resumed run), else seeds the
// plan from the pipeline's plan.json. Both are best-effort: any decode failure
// just leaves an empty scratchpad the agent fills in itself.
func (c *ScratchpadContext) loadOrSeed() {
	dir := c.autopilotDir()
	if dir == "" {
		return
	}

	if raw, err := os.ReadFile(filepath.Join(dir, scratchpadFile)); err == nil {
		var st scratchpadState
		if json.Unmarshal(raw, &st) == nil {
			c.plan = st.Plan
			c.notes = st.Notes
			c.stopCriteria = st.StopCriteria
			return
		}
	}

	// Seed from the pipeline's frozen AutopilotExecutionPlan. Decode only the
	// subset we need so pkg/olium/autopilot doesn't import pkg/agent.
	raw, err := os.ReadFile(filepath.Join(dir, pipelinePlanFile))
	if err != nil {
		return
	}
	var seed struct {
		Tasks []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Priority int    `json:"priority"`
			Reason   string `json:"reason"`
		} `json:"tasks"`
		StopCriteria []string `json:"stop_criteria"`
	}
	if json.Unmarshal(raw, &seed) != nil {
		return
	}
	sort.SliceStable(seed.Tasks, func(i, j int) bool {
		return seed.Tasks[i].Priority < seed.Tasks[j].Priority
	})
	for i, t := range seed.Tasks {
		id := t.ID
		if id == "" {
			id = fmt.Sprintf("t%d", i+1)
		}
		task := t.Type
		if t.Reason != "" {
			task = fmt.Sprintf("%s — %s", t.Type, t.Reason)
		}
		if strings.TrimSpace(task) == "" {
			continue
		}
		c.plan = append(c.plan, PlanItem{ID: id, Task: task, Status: planPending})
	}
	c.stopCriteria = seed.StopCriteria
}

// persist writes the current state atomically. Caller holds c.mu. Best-effort:
// a write failure is non-fatal (the in-memory copy is still authoritative for
// the rest of the run) but is surfaced to the model so it knows replay/resume
// won't have this state.
func (c *ScratchpadContext) persist() error {
	dir := c.autopilotDir()
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	st := scratchpadState{Plan: c.plan, Notes: c.notes, StopCriteria: c.stopCriteria}
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, scratchpadFile+".tmp")
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, scratchpadFile))
}

// render produces the markdown snapshot echoed back to the model on every
// call. Deterministic ordering so prompt-cache churn is minimal and the agent
// sees a stable view turn to turn.
func (c *ScratchpadContext) render() string {
	var b strings.Builder
	b.WriteString("## Working memory (survives context loss — the transcript does not)\n\n")

	b.WriteString("### Plan\n")
	if len(c.plan) == 0 {
		b.WriteString("_(empty — call update_plan to lay out your tasks before investigating)_\n")
	} else {
		for _, p := range c.plan {
			box := "[ ]"
			switch p.Status {
			case planInProgress:
				box = "[~]"
			case planDone:
				box = "[x]"
			case planDropped:
				box = "[-]"
			}
			line := fmt.Sprintf("- %s %s: %s", box, p.ID, p.Task)
			if p.Note != "" {
				line += "  — " + p.Note
			}
			b.WriteString(line + "\n")
		}
	}

	if len(c.stopCriteria) > 0 {
		b.WriteString("\n### Stop criteria (halt_scan when these are met)\n")
		for _, s := range c.stopCriteria {
			b.WriteString("- " + s + "\n")
		}
	}

	b.WriteString(fmt.Sprintf("\n### Notes (%d)\n", len(c.notes)))
	if len(c.notes) == 0 {
		b.WriteString("_(none — call remember to pin durable facts: auth schemes, role boundaries, confirmed/refuted hypotheses)_\n")
	} else {
		for _, n := range c.notes {
			prefix := "- "
			if n.Key != "" {
				prefix = "- [" + n.Key + "] "
			}
			line := prefix + n.Text
			if len(n.Tags) > 0 {
				line += "  (" + strings.Join(n.Tags, ", ") + ")"
			}
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

// Digest returns a compact plan-state snapshot the engine pins to every tool
// result tail. The full render() (~1 KiB markdown) is echoed only when
// update_plan or remember are called; on every other tool call this short
// form keeps the latest plan checkboxes (and the in-progress task's full
// text, since that's what the agent is actively working on) at the
// conversation tail so it survives the long stretches between scratchpad
// touches. Returns empty string when there's nothing tracked yet so the
// hook doesn't add noise to tool results during an unplanned warm-up.
func (c *ScratchpadContext) Digest() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.plan) == 0 && len(c.notes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n--- working memory (pinned by engine) ---\n")
	if len(c.plan) > 0 {
		for _, p := range c.plan {
			box := "[ ]"
			switch p.Status {
			case planInProgress:
				box = "[~]"
			case planDone:
				box = "[x]"
			case planDropped:
				box = "[-]"
			}
			line := fmt.Sprintf("%s %s", box, p.ID)
			// Only inline the task text for in-progress items — that's
			// what the agent's currently working on. Pending/done items
			// can be re-read via update_plan recall if needed.
			if p.Status == planInProgress && p.Task != "" {
				line += ": " + p.Task
			}
			b.WriteString(line + "\n")
		}
	}
	if len(c.notes) > 0 {
		b.WriteString(fmt.Sprintf("notes=%d (call `remember` with recall=true to read)\n", len(c.notes)))
	}
	return b.String()
}

// ---- update_plan tool ----

// NewUpdatePlanTool returns the update_plan tool. Replace-semantics: the
// supplied array becomes the plan in full (mirrors the model's mental model
// of "here is my current todo list"). Called with no plan it just echoes the
// current state — a cheap recall the agent can do whenever it's unsure what
// it has already covered.
func NewUpdatePlanTool(sp *ScratchpadContext) tool.Tool { return &updatePlanTool{sp: sp} }

type updatePlanTool struct{ sp *ScratchpadContext }

func (*updatePlanTool) Name() string     { return "update_plan" }
func (*updatePlanTool) Label() string    { return "Update plan" }
func (*updatePlanTool) Category() string { return tool.CategoryVigolium }
func (*updatePlanTool) IsReadOnly() bool { return false }
func (*updatePlanTool) Description() string {
	return "Maintain your audit plan as a task list that survives context loss. " +
		"Call with `plan` (the full ordered list — replace-semantics) to set/update tasks; " +
		"call with no arguments to recall the current plan when you're unsure what you've covered. " +
		"Lay out a plan before your first investigative action and mark items in_progress/done as you go. " +
		"The plan is persisted to the session dir and echoed back on every call."
}

func (*updatePlanTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"plan": map[string]any{
				"type":        "array",
				"description": "Full ordered task list (replaces the current plan). Omit to just recall the current state.",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":     map[string]any{"type": "string", "description": "Stable short id (e.g. 'auth', 'idor'). Auto-assigned if omitted."},
						"task":   map[string]any{"type": "string", "description": "What this step accomplishes. Required."},
						"status": map[string]any{"type": "string", "enum": []string{planPending, planInProgress, planDone, planDropped}, "description": "Default 'pending'."},
						"note":   map[string]any{"type": "string", "description": "Optional short progress note (e.g. 'verifier in api/auth.go:88')."},
					},
					"required": []string{"task"},
				},
			},
		},
	}
}

func (t *updatePlanTool) Execute(_ context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	t.sp.mu.Lock()
	defer t.sp.mu.Unlock()

	raw, hasPlan := args["plan"]
	if !hasPlan || raw == nil {
		// Recall-only.
		return tool.Result{Content: t.sp.render()}, nil
	}

	arr, ok := raw.([]any)
	if !ok {
		return tool.Result{Content: "update_plan: 'plan' must be an array of {task, status?, id?, note?} objects", IsError: true}, nil
	}

	next := make([]PlanItem, 0, len(arr))
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return tool.Result{Content: fmt.Sprintf("update_plan: plan[%d] must be an object", i), IsError: true}, nil
		}
		task, _ := obj["task"].(string)
		task = strings.TrimSpace(task)
		if task == "" {
			return tool.Result{Content: fmt.Sprintf("update_plan: plan[%d].task is required", i), IsError: true}, nil
		}
		status, _ := obj["status"].(string)
		status = strings.TrimSpace(status)
		if status == "" {
			status = planPending
		}
		if !validPlanStatus(status) {
			return tool.Result{Content: fmt.Sprintf("update_plan: plan[%d].status %q invalid (use pending|in_progress|done|dropped)", i, status), IsError: true}, nil
		}
		id, _ := obj["id"].(string)
		id = strings.TrimSpace(id)
		if id == "" {
			id = fmt.Sprintf("t%d", i+1)
		}
		note, _ := obj["note"].(string)
		next = append(next, PlanItem{ID: id, Task: task, Status: status, Note: strings.TrimSpace(note)})
	}

	t.sp.plan = next
	out := t.sp.render()
	if err := t.sp.persist(); err != nil {
		out += fmt.Sprintf("\n\n[warning] plan not persisted to disk: %v (in-memory only; resume/replay won't have it)", err)
	}
	return tool.Result{
		Content: out,
		Details: map[string]any{"plan_items": len(next)},
	}, nil
}

// ---- remember tool ----

// NewRememberTool returns the remember tool — an append/upsert log of durable
// facts the agent must not lose to context eviction.
func NewRememberTool(sp *ScratchpadContext) tool.Tool { return &rememberTool{sp: sp} }

type rememberTool struct{ sp *ScratchpadContext }

func (*rememberTool) Name() string     { return "remember" }
func (*rememberTool) Label() string    { return "Remember fact" }
func (*rememberTool) Category() string { return tool.CategoryVigolium }
func (*rememberTool) IsReadOnly() bool { return false }
func (*rememberTool) Description() string {
	return "Pin a durable fact to working memory so it survives context loss (auth scheme, a role/tenant " +
		"boundary, a confirmed or refuted hypothesis, a payload that worked). Pass `key` to upsert a named " +
		"slot instead of appending (prevents stale duplicates). Call with `recall: true` (optionally filtered " +
		"by `tags`) to read notes back when the transcript may have dropped them. Do this immediately when " +
		"you learn something — do not rely on the conversation surviving."
}

func (*rememberTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"note":   map[string]any{"type": "string", "description": "The fact to record. Required unless recall=true."},
			"key":    map[string]any{"type": "string", "description": "Optional slot name — upserts (replaces) the prior note with this key instead of appending."},
			"tags":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional classification tags (e.g. ['auth','idor'])."},
			"recall": map[string]any{"type": "boolean", "description": "When true, return stored notes (optionally filtered by `tags`) instead of writing."},
		},
	}
}

func (t *rememberTool) Execute(_ context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	t.sp.mu.Lock()
	defer t.sp.mu.Unlock()

	tags := stringSlice(args["tags"])

	if b, _ := args["recall"].(bool); b {
		return tool.Result{Content: t.sp.recall(tags)}, nil
	}

	note, _ := args["note"].(string)
	note = strings.TrimSpace(note)
	if note == "" {
		return tool.Result{Content: "remember: 'note' is required (or pass recall=true to read)", IsError: true}, nil
	}
	key, _ := args["key"].(string)
	key = strings.TrimSpace(key)

	n := Note{Key: key, Text: note, Tags: tags, At: time.Now().UTC().Format(time.RFC3339)}
	if key != "" {
		replaced := false
		for i := range t.sp.notes {
			if t.sp.notes[i].Key == key {
				t.sp.notes[i] = n
				replaced = true
				break
			}
		}
		if !replaced {
			t.sp.notes = append(t.sp.notes, n)
		}
	} else {
		t.sp.notes = append(t.sp.notes, n)
	}
	t.sp.evictIfNeeded()

	out := fmt.Sprintf("Recorded (%d notes total).\n\n%s", len(t.sp.notes), t.sp.render())
	if err := t.sp.persist(); err != nil {
		out += fmt.Sprintf("\n\n[warning] note not persisted to disk: %v (in-memory only)", err)
	}
	return tool.Result{
		Content: out,
		Details: map[string]any{"notes_total": len(t.sp.notes)},
	}, nil
}

// recall returns notes, optionally filtered to those carrying every tag in
// filter. Caller holds c.mu.
func (c *ScratchpadContext) recall(filter []string) string {
	if len(filter) == 0 {
		return c.render()
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("## Notes matching tags [%s]\n\n", strings.Join(filter, ", ")))
	count := 0
	for _, n := range c.notes {
		if !hasAllTags(n.Tags, filter) {
			continue
		}
		count++
		prefix := "- "
		if n.Key != "" {
			prefix = "- [" + n.Key + "] "
		}
		b.WriteString(prefix + n.Text + "\n")
	}
	if count == 0 {
		b.WriteString("_(no notes match those tags)_\n")
	}
	return b.String()
}

// evictIfNeeded enforces scratchpadNoteSoftCap by dropping the oldest unkeyed
// notes first. Keyed notes are deliberate pins and are never auto-evicted.
// Caller holds c.mu.
func (c *ScratchpadContext) evictIfNeeded() {
	if len(c.notes) <= scratchpadNoteSoftCap {
		return
	}
	over := len(c.notes) - scratchpadNoteSoftCap
	kept := make([]Note, 0, len(c.notes))
	for _, n := range c.notes {
		if over > 0 && n.Key == "" {
			over--
			continue
		}
		kept = append(kept, n)
	}
	c.notes = kept
}

func stringSlice(v any) []string {
	switch raw := v.(type) {
	case []string:
		return raw
	case []any:
		out := make([]string, 0, len(raw))
		for _, x := range raw {
			if s, ok := x.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}

func hasAllTags(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if strings.EqualFold(h, w) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
