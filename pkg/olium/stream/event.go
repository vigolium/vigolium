// Package stream defines the unified event protocol that every olium provider
// translates to. Consumers (TUI, headless runner, subprocess adapter) speak
// only this protocol, so swapping Codex for Anthropic or Gemini is a
// provider-layer change that doesn't ripple upward.
package stream

type EventType string

const (
	EventTextStart     EventType = "text_start"
	EventTextDelta     EventType = "text_delta"
	EventTextEnd       EventType = "text_end"
	EventThinkingStart EventType = "thinking_start"
	EventThinkingDelta EventType = "thinking_delta"
	EventThinkingEnd   EventType = "thinking_end"
	EventToolCallStart EventType = "toolcall_start"
	EventToolCallDelta EventType = "toolcall_delta"
	EventToolCallEnd   EventType = "toolcall_end"
	EventDone          EventType = "done"
	EventError         EventType = "error"
)

type StopReason string

const (
	StopReasonStop    StopReason = "stop"
	StopReasonLength  StopReason = "length"
	StopReasonToolUse StopReason = "toolUse"
	StopReasonError   StopReason = "error"
)

type Usage struct {
	Input       int     `json:"input"`
	Output      int     `json:"output"`
	CacheRead   int     `json:"cacheRead"`
	CacheWrite  int     `json:"cacheWrite"`
	TotalTokens int     `json:"totalTokens"`
	Cost        float64 `json:"cost"`
}

type ToolCall struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// Event is the single value type emitted on a provider stream. Fields are
// populated based on Type; consumers should switch on Type first.
type Event struct {
	Type       EventType  `json:"type"`
	Delta      string     `json:"delta,omitempty"`
	Content    string     `json:"content,omitempty"`
	ToolCall   *ToolCall  `json:"toolCall,omitempty"`
	StopReason StopReason `json:"stopReason,omitempty"`
	Usage      *Usage     `json:"usage,omitempty"`
	Err        string     `json:"error,omitempty"`
}
