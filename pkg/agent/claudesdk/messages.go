package claudesdk

import (
	"encoding/json"
	"fmt"
)

// Message is the interface all parsed Claude CLI messages implement.
type Message interface {
	msgType() string
	GetSessionID() string
}

// AssistantMessage is a complete response from Claude.
type AssistantMessage struct {
	SessionIDField string         `json:"-"`
	Content        []ContentBlock `json:"-"` // extracted from message.content
	Model          string         `json:"-"`
}

func (m *AssistantMessage) msgType() string        { return "assistant" }
func (m *AssistantMessage) GetSessionID() string    { return m.SessionIDField }

// ResultMessage is the final message with cost/usage statistics.
type ResultMessage struct {
	SessionIDField string  `json:"-"`
	Subtype        string  `json:"subtype"`
	IsError        bool    `json:"is_error"`
	NumTurns       int     `json:"num_turns"`
	TotalCostUSD   float64 `json:"total_cost_usd"`
	DurationMS     int     `json:"duration_ms"`
	Usage          Usage   `json:"usage"`
}

func (m *ResultMessage) msgType() string        { return "result" }
func (m *ResultMessage) GetSessionID() string    { return m.SessionIDField }

// StreamEvent is an incremental streaming update.
type StreamEvent struct {
	SessionIDField string
	EventType      string       // e.g., "content_block_delta", "message_start"
	Delta          *ContentDelta // non-nil for content_block_delta events
}

func (m *StreamEvent) msgType() string        { return "stream_event" }
func (m *StreamEvent) GetSessionID() string    { return m.SessionIDField }

// SystemMessage is a system-level notification.
type SystemMessage struct {
	SessionIDField string
	Subtype        string
}

func (m *SystemMessage) msgType() string        { return "system" }
func (m *SystemMessage) GetSessionID() string    { return m.SessionIDField }

// ContentBlock represents a content block in an assistant message.
type ContentBlock struct {
	Type string // "text", "tool_use", "thinking", etc.
	Text string // populated for text/thinking blocks
}

// ContentDelta represents a streaming text delta.
type ContentDelta struct {
	Text string
}

// Usage tracks token consumption.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// --- JSON parsing helpers ---

// messageEnvelope is the top-level JSON structure for all messages.
type messageEnvelope struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id"`
	Message   json.RawMessage `json:"message,omitempty"` // for assistant
	Event     json.RawMessage `json:"event,omitempty"`   // for stream_event
	Subtype   string          `json:"subtype,omitempty"` // for system/result
}

// parseMessage parses a JSON-lines message into a typed Message.
// Returns (nil, nil) for unknown/control message types (forward-compatible).
func parseMessage(data []byte) (Message, error) {
	var env messageEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("failed to parse message envelope: %w", err)
	}

	switch env.Type {
	case "assistant":
		return parseAssistantMessage(data, env.SessionID)
	case "result":
		return parseResultMessage(data, env.SessionID)
	case "stream_event":
		return parseStreamEvent(data, env.SessionID)
	case "system":
		return &SystemMessage{
			SessionIDField: env.SessionID,
			Subtype:        env.Subtype,
		}, nil
	default:
		// Unknown types (control_request, control_response, user, etc.)
		// silently ignored for forward compatibility.
		return nil, nil
	}
}

// parseAssistantMessage extracts text content blocks from an assistant message.
func parseAssistantMessage(data []byte, sessionID string) (*AssistantMessage, error) {
	var raw struct {
		Message struct {
			Model   string `json:"model"`
			Content []struct {
				Type     string `json:"type"`
				Text     string `json:"text,omitempty"`
				Thinking string `json:"thinking,omitempty"`
			} `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse assistant message: %w", err)
	}

	blocks := make([]ContentBlock, 0, len(raw.Message.Content))
	for _, c := range raw.Message.Content {
		text := c.Text
		if c.Type == "thinking" {
			text = c.Thinking
		}
		blocks = append(blocks, ContentBlock{
			Type: c.Type,
			Text: text,
		})
	}

	return &AssistantMessage{
		SessionIDField: sessionID,
		Content:        blocks,
		Model:          raw.Message.Model,
	}, nil
}

// parseResultMessage extracts result statistics.
func parseResultMessage(data []byte, sessionID string) (*ResultMessage, error) {
	var raw struct {
		Subtype      string  `json:"subtype"`
		IsError      bool    `json:"is_error"`
		NumTurns     int     `json:"num_turns"`
		TotalCostUSD float64 `json:"total_cost_usd"`
		DurationMS   int     `json:"duration_ms"`
		Usage        Usage   `json:"usage"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse result message: %w", err)
	}

	return &ResultMessage{
		SessionIDField: sessionID,
		Subtype:        raw.Subtype,
		IsError:        raw.IsError,
		NumTurns:       raw.NumTurns,
		TotalCostUSD:   raw.TotalCostUSD,
		DurationMS:     raw.DurationMS,
		Usage:          raw.Usage,
	}, nil
}

// parseStreamEvent extracts streaming delta data.
func parseStreamEvent(data []byte, sessionID string) (*StreamEvent, error) {
	var raw struct {
		Event struct {
			Type  string `json:"type"`
			Delta *struct {
				Type string  `json:"type"`
				Text *string `json:"text,omitempty"`
			} `json:"delta,omitempty"`
		} `json:"event"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse stream event: %w", err)
	}

	evt := &StreamEvent{
		SessionIDField: sessionID,
		EventType:      raw.Event.Type,
	}

	// Extract text delta for content_block_delta events
	if raw.Event.Type == "content_block_delta" && raw.Event.Delta != nil && raw.Event.Delta.Text != nil {
		evt.Delta = &ContentDelta{Text: *raw.Event.Delta.Text}
	}

	return evt, nil
}
