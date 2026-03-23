package codexsdk

import (
	"encoding/json"
	"fmt"
)

// jsonRPCRequest is a JSON-RPC 2.0 request sent from client to server.
type jsonRPCRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params"`
}

// jsonRPCNotification is a JSON-RPC 2.0 notification (no id, no response expected).
type jsonRPCNotification struct {
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type jsonRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// rawMessage is used to classify incoming JSONL messages from the server.
type rawMessage struct {
	ID     *string         `json:"id,omitempty"`
	Method *string         `json:"method,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *jsonRPCError   `json:"error,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
}

// messageKind classifies what kind of JSON-RPC message this is.
func (m *rawMessage) messageKind() string {
	if m.Method != nil && m.ID != nil {
		return "server_request" // server-initiated request (approval)
	}
	if m.Method != nil && m.ID == nil {
		return "notification"
	}
	if m.ID != nil && m.Error != nil {
		return "error_response"
	}
	if m.ID != nil {
		return "response"
	}
	return "unknown"
}

// Notification is a parsed server notification with method and typed/raw payload.
type Notification struct {
	Method  string
	Payload json.RawMessage
}

// NotificationRegistry maps method names to their Go types for deserialization.
var NotificationRegistry = map[string]func() any{
	"thread/started":                      func() any { return &ThreadStartedNotification{} },
	"turn/started":                        func() any { return &TurnStartedNotification{} },
	"turn/completed":                      func() any { return &TurnCompletedNotification{} },
	"item/agentMessage/delta":             func() any { return &AgentMessageDeltaNotification{} },
	"item/started":                        func() any { return &ItemStartedNotification{} },
	"item/completed":                      func() any { return &ItemCompletedNotification{} },
	"item/commandExecution/outputDelta":   func() any { return &CommandExecutionOutputDeltaNotification{} },
	"item/fileChange/outputDelta":         func() any { return &FileChangeOutputDeltaNotification{} },
	"item/reasoning/textDelta":            func() any { return &ReasoningTextDeltaNotification{} },
	"thread/tokenUsage/updated":           func() any { return &ThreadTokenUsageUpdatedNotification{} },
	"error":                               func() any { return &ErrorNotification{} },
}

// RPCError represents a JSON-RPC error returned by the server.
type RPCError struct {
	Code    int
	Message string
	Data    json.RawMessage
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("codex RPC error %d: %s", e.Code, e.Message)
}

// IsServerBusy returns true if this is a server overload error.
func (e *RPCError) IsServerBusy() bool {
	return e.Code >= -32099 && e.Code <= -32000
}
