// Package engine owns olium's multi-turn agent loop: it orchestrates the
// provider, tool registry, conversation history, and event fan-out. TUI
// and headless runners are thin consumers.
package engine

// Role enumerates conversation roles.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// ToolCall is a model-requested tool invocation.
type ToolCall struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// Message is a single entry in the conversation history.
//
// Assistant messages may carry Text, ToolCalls, or both. Tool messages
// reference the ToolCallID they answer and carry the rendered Content.
type Message struct {
	Role      Role       `json:"role"`
	Text      string     `json:"text,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`

	ToolCallID string `json:"tool_call_id,omitempty"`
	Content    string `json:"content,omitempty"`
	IsError    bool   `json:"is_error,omitempty"`
}
