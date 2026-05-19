// Package provider defines the Provider interface every LLM backend
// implements. The engine speaks to providers purely through this interface;
// swapping Codex for Anthropic is a provider-layer change.
package provider

import (
	"context"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// Role is the author of a chat message.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

// ToolCall is a model-requested tool invocation carried inside an assistant
// message. Providers emit these during streaming and reconsume them when
// building follow-up requests.
type ToolCall struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// Message is a single entry in a conversation.
//
// Assistant messages may carry Text, ToolCalls, or both. Tool messages
// reference ToolCallID and carry the rendered Content.
type Message struct {
	Role       Role       `json:"role"`
	Text       string     `json:"text,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Content    string     `json:"content,omitempty"`
	IsError    bool       `json:"is_error,omitempty"`
}

// ToolDef describes a tool to the model. Providers wrap this in their
// own declaration envelope.
type ToolDef struct {
	Name        string
	Description string
	Schema      map[string]any
}

// Request is what the runner passes to Provider.Stream.
type Request struct {
	Model        string
	System       string
	Messages     []Message
	Tools        []ToolDef
	SessionID    string
	ReasoningEff string
	// CacheControl, when true, asks the provider to emit cache-hint
	// markers (Anthropic: cache_control:{type:"ephemeral"}) on the
	// stable prefix of the request so repeat turns can reuse the
	// cached prompt. Providers that don't support caching ignore this.
	CacheControl bool
}

// Provider streams model output as stream.Event values on the returned
// channel. The channel is closed when the stream ends; on error, the final
// event has Type == stream.EventError and Err set before the channel closes.
type Provider interface {
	Name() string
	Stream(ctx context.Context, req Request) (<-chan stream.Event, error)
}
