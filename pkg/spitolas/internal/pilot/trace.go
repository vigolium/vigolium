package pilot

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ActionEntry records a single agent action for replay/reproduce.
type ActionEntry struct {
	Seq         int               `json:"seq"`
	Timestamp   time.Time         `json:"timestamp"`
	Tool        string            `json:"tool"`
	Args        map[string]string `json:"args"`
	Success     bool              `json:"success"`
	Error       string            `json:"error,omitempty"`
	BeforeState StateSnapshot     `json:"before_state"`
	AfterState  StateSnapshot     `json:"after_state"`
	DurationMS  int64             `json:"duration_ms"`
	IsReplay    bool              `json:"is_replay,omitempty"` // true for mechanically replayed steps (not LLM-driven)
}

// SessionTrace captures the entire pilot crawl session into a single LLM-readable
// Markdown file. It replaces ActionLog with a comprehensive trace that includes
// briefing prompts, every tool call with page states, checkpoint lifecycle events,
// and session summaries — everything needed to debug and improve the pilot's
// prompt design and decision-making flow.
//
// The trace file is designed to be read by an LLM reviewer who can analyze:
//   - Whether the system prompt gives the right directives
//   - Whether the briefing prompt provides adequate context
//   - Whether the agent makes good tool call decisions given the page state
//   - Whether SerializePage() exposes enough information
//   - Where the agent gets stuck, loops, or wastes actions
//   - Error patterns and their root causes
type SessionTrace struct {
	mu        sync.Mutex
	file      *os.File
	entries   []ActionEntry  // in-memory action entries for BFS path derivation and briefing
	seq       int            // global tool call counter (all tools)
	startTime time.Time

	// Stats
	toolCalls map[string][2]int // tool → [success, fail]
	errors    map[string]int    // error message → count
}

// NewSessionTrace creates a new trace. If path is non-empty, the full session
// trace is written to a Markdown file at that path.
func NewSessionTrace(path string) (*SessionTrace, error) {
	t := &SessionTrace{
		entries:   make([]ActionEntry, 0, 256),
		startTime: time.Now(),
		toolCalls: make(map[string][2]int),
		errors:    make(map[string]int),
	}
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("create trace file: %w", err)
		}
		t.file = f
	}
	return t, nil
}

// WriteHeader writes the session header to the trace file.
func (t *SessionTrace) WriteHeader(target string, pilotCfg *PilotConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b strings.Builder
	b.WriteString("# Pilot Session Trace\n\n")
	fmt.Fprintf(&b, "- **Target**: %s\n", target)
	fmt.Fprintf(&b, "- **Started**: %s\n", t.startTime.Format(time.RFC3339))
	if pilotCfg != nil {
		fmt.Fprintf(&b, "- **Screenshot**: %t\n", pilotCfg.Screenshot)
		fmt.Fprintf(&b, "- **Max Retries**: %d\n", pilotCfg.MaxRetries)
		if pilotCfg.Auth.Enabled {
			if pilotCfg.Auth.Username != "" {
				fmt.Fprintf(&b, "- **Auth**: username=%s\n", pilotCfg.Auth.Username)
			} else if pilotCfg.Auth.AutoRegister {
				b.WriteString("- **Auth**: auto-register\n")
			}
		}
	}
	b.WriteString("\n")

	t.write(b.String())
}

// WriteSystemPrompt writes the full system prompt section.
func (t *SessionTrace) WriteSystemPrompt(prompt string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b strings.Builder
	b.WriteString("## System Prompt\n\n```\n")
	b.WriteString(prompt)
	b.WriteString("\n```\n\n---\n\n")

	t.write(b.String())
}

// WriteSessionStart writes the ACP session attempt marker.
func (t *SessionTrace) WriteSessionStart(attempt, maxAttempts int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "## ACP Session (Attempt %d/%d)\n\n", attempt, maxAttempts)

	t.write(b.String())
}

// WriteBriefing writes the full briefing prompt sent to the agent.
func (t *SessionTrace) WriteBriefing(prompt string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b strings.Builder
	b.WriteString("### Briefing Prompt\n\n```\n")
	b.WriteString(prompt)
	b.WriteString("\n```\n\n### Tool Calls\n\n")

	t.write(b.String())
}

// WriteToolCall writes a single tool call entry to the trace file.
// Called for ALL tools — action, investigative, checkpoint, and session.
func (t *SessionTrace) WriteToolCall(tool string, args map[string]string, result *ToolResult, duration time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.seq++
	seq := t.seq

	// Update stats
	counts := t.toolCalls[tool]
	if result.Success {
		counts[0]++
	} else {
		counts[1]++
	}
	t.toolCalls[tool] = counts
	if !result.Success && result.Error != "" {
		t.errors[result.Error]++
	}

	var b strings.Builder
	status := "✓"
	if !result.Success {
		status = "✗"
	}

	fmt.Fprintf(&b, "#### #%d %s %s (%dms)\n\n", seq, tool, status, duration.Milliseconds())

	// Args
	if len(args) > 0 {
		b.WriteString("**Args**:")
		for k, v := range args {
			if k == "code" && len(v) > 200 {
				v = v[:200] + "..."
			}
			fmt.Fprintf(&b, " %s=%q", k, v)
		}
		b.WriteString("\n\n")
	}

	// Error
	if !result.Success && result.Error != "" {
		fmt.Fprintf(&b, "**Error**: %s\n\n", result.Error)
	}

	// Result data (for non-action tools: checkpoint, entity, session tools)
	if result.Data != nil && !isActionTool(tool) {
		fmt.Fprintf(&b, "**Result**: %v\n\n", result.Data)
	}

	// Screenshot indicator (don't embed base64, just note it)
	if result.Screenshot != "" {
		b.WriteString("**Screenshot**: attached\n\n")
	}

	// Page state (populated by action tools and some checkpoint tools like go_to_checkpoint)
	if result.PageState != "" {
		b.WriteString("**Page State**:\n```\n")
		b.WriteString(result.PageState)
		b.WriteString("\n```\n\n")
	}

	t.write(b.String())
}

// WriteSessionEnd writes the session end marker.
func (t *SessionTrace) WriteSessionEnd(reason string, acpErr error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b strings.Builder
	b.WriteString("### Session End\n\n")
	fmt.Fprintf(&b, "- **Reason**: %s\n", reason)
	if acpErr != nil {
		fmt.Fprintf(&b, "- **Error**: %s\n", acpErr)
	}
	b.WriteString("\n---\n\n")

	t.write(b.String())
}

// WriteSummary writes the final session summary with tool distribution and error patterns.
func (t *SessionTrace) WriteSummary(result *Result) {
	t.mu.Lock()
	defer t.mu.Unlock()

	duration := time.Since(t.startTime)

	var b strings.Builder
	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- **Duration**: %s\n", duration.Round(time.Second))
	fmt.Fprintf(&b, "- **Total tool calls**: %d\n", t.seq)
	fmt.Fprintf(&b, "- **Action entries**: %d\n", len(t.entries))

	if result != nil {
		fmt.Fprintf(&b, "- **States discovered**: %d\n", result.StatesDiscovered)
		fmt.Fprintf(&b, "- **Checkpoints**: %d completed, %d pending\n",
			result.CheckpointsCompleted, result.CheckpointsPending)
	}

	// Tool distribution table sorted by total calls
	type toolStat struct {
		name    string
		success int
		fail    int
	}
	stats := make([]toolStat, 0, len(t.toolCalls))
	totalSuccess, totalFail := 0, 0
	for tool, counts := range t.toolCalls {
		stats = append(stats, toolStat{tool, counts[0], counts[1]})
		totalSuccess += counts[0]
		totalFail += counts[1]
	}
	sort.Slice(stats, func(i, j int) bool {
		return (stats[i].success + stats[i].fail) > (stats[j].success + stats[j].fail)
	})

	b.WriteString("\n### Tool Distribution\n\n")
	b.WriteString("| Tool | Success | Fail | Total |\n")
	b.WriteString("|------|---------|------|-------|\n")
	for _, s := range stats {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", s.name, s.success, s.fail, s.success+s.fail)
	}
	fmt.Fprintf(&b, "| **TOTAL** | **%d** | **%d** | **%d** |\n\n", totalSuccess, totalFail, totalSuccess+totalFail)

	// Error patterns
	if len(t.errors) > 0 {
		b.WriteString("### Error Patterns\n\n")
		for errMsg, count := range t.errors {
			msg := errMsg
			if len(msg) > 120 {
				msg = msg[:120] + "..."
			}
			fmt.Fprintf(&b, "- `%s` — %d occurrence(s)\n", msg, count)
		}
		b.WriteString("\n")
	}

	t.write(b.String())
}

// ============================================================================
// In-memory action entry management (used by BFS, briefing, checkpoint)
// ============================================================================

// RecordAction appends an action entry to in-memory storage for BFS path
// derivation and briefing rendering. Returns the entry for checkpoint scoped recording.
func (t *SessionTrace) RecordAction(tool string, args map[string]string, success bool, errMsg string, before, after StateSnapshot, duration time.Duration) ActionEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry := ActionEntry{
		Seq:         len(t.entries) + 1,
		Timestamp:   time.Now(),
		Tool:        tool,
		Args:        args,
		Success:     success,
		Error:       errMsg,
		BeforeState: before,
		AfterState:  after,
		DurationMS:  duration.Milliseconds(),
	}
	t.entries = append(t.entries, entry)
	return entry
}

// MarkReplay sets the IsReplay flag on an entry by sequence number.
func (t *SessionTrace) MarkReplay(seq int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx := seq - 1
	if idx >= 0 && idx < len(t.entries) {
		t.entries[idx].IsReplay = true
	}
}

// Entries returns all recorded action entries up to the given sequence number.
// If seq <= 0, returns all entries.
func (t *SessionTrace) Entries(seq int) []ActionEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	if seq <= 0 || seq > len(t.entries) {
		result := make([]ActionEntry, len(t.entries))
		copy(result, t.entries)
		return result
	}
	result := make([]ActionEntry, seq)
	copy(result, t.entries[:seq])
	return result
}

// Len returns the number of recorded action entries.
func (t *SessionTrace) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// RecentEntries returns the last n non-replay action entries.
// Replay entries (mechanical go_to_checkpoint steps) are filtered out
// to avoid polluting the LLM briefing with replay noise.
func (t *SessionTrace) RecentEntries(n int) []ActionEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Collect non-replay entries
	var filtered []ActionEntry
	for i := range t.entries {
		if !t.entries[i].IsReplay {
			filtered = append(filtered, t.entries[i])
		}
	}

	if n <= 0 || n >= len(filtered) {
		return filtered
	}
	return filtered[len(filtered)-n:]
}

// Close flushes and closes the trace file.
func (t *SessionTrace) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file != nil {
		return t.file.Close()
	}
	return nil
}

// write appends text to the trace file. Must be called with lock held.
func (t *SessionTrace) write(s string) {
	if t.file != nil {
		_, _ = t.file.WriteString(s)
	}
}
