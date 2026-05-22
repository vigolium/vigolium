package engine

import "github.com/vigolium/vigolium/pkg/olium/stream"

// EventType is the union of engine-emitted event kinds. These are a
// superset of the provider's stream events: the engine forwards text /
// thinking / tool-call events from the provider and adds its own
// tool-execution and turn-lifecycle events.
type EventType string

const (
	// Forwarded from the provider.
	EventTextDelta     EventType = "text_delta"
	EventThinkingDelta EventType = "thinking_delta"
	EventToolCallStart EventType = "toolcall_start" // model began a tool call (unexecuted)

	// Emitted by the engine.
	EventToolExecStart    EventType = "tool_exec_start"    // engine about to run a tool
	EventToolExecProgress EventType = "tool_exec_progress" // tool streaming partial output
	EventToolExecEnd      EventType = "tool_exec_end"      // tool finished
	EventTurnDone         EventType = "turn_done"          // assistant turn complete (model finished this request)
	EventRunDone          EventType = "run_done"           // full run complete (no more tool calls pending)
	EventError            EventType = "error"
	// EventInfo carries a non-fatal engine-level notice (e.g. "transient
	// upstream stream error; retrying"). Message lives in Delta. Consumers
	// that don't recognize this type silently drop it — backward compatible.
	EventInfo EventType = "info"
)

// Event is the single value type emitted on the engine event channel.
type Event struct {
	Type EventType `json:"type"`

	// Text / thinking payloads.
	Delta string `json:"delta,omitempty"`

	// Tool events.
	ToolCallID   string         `json:"tool_call_id,omitempty"`
	ToolName     string         `json:"tool_name,omitempty"`
	ToolCategory string         `json:"tool_category,omitempty"` // tool.CategoryBuiltin / tool.CategoryVigolium
	ToolArgs     map[string]any `json:"tool_args,omitempty"`
	ToolResult   string         `json:"tool_result,omitempty"`
	ToolIsErr    bool           `json:"tool_is_error,omitempty"`

	// Turn / run lifecycle.
	StopReason stream.StopReason `json:"stop_reason,omitempty"`
	Usage      *stream.Usage     `json:"usage,omitempty"`

	// Error payload.
	Err string `json:"error,omitempty"`
}
