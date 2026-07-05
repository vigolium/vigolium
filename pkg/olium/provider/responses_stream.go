package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// Shared OpenAI Responses-API wire format.
//
// Two drivers speak the Responses API: Codex (ChatGPT backend
// /codex/responses, subscription OAuth) and OpenAIResponses (public
// api.openai.com/v1/responses, API key). The request `input` array, the
// `tools`/`reasoning` shapes, and the response.* SSE stream are identical
// between them — only the endpoint, auth, and a handful of request fields
// differ. This file holds the shared half so the two drivers can't drift.

type responsesReasoning struct {
	Effort  string `json:"effort,omitempty"`
	Summary string `json:"summary,omitempty"`
}

type responsesTool struct {
	Type        string         `json:"type"` // "function"
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
	Strict      bool           `json:"strict"`
}

// responsesRequest is the Responses API request body shared by Codex and
// OpenAIResponses. It's a superset: each driver's builder sets the fields it
// needs and leaves the rest at their omitempty zero value.
type responsesRequest struct {
	Model             string              `json:"model"`
	Store             bool                `json:"store"`
	Stream            bool                `json:"stream"`
	Instructions      string              `json:"instructions,omitempty"`
	Input             []any               `json:"input"`
	Tools             []responsesTool     `json:"tools,omitempty"`
	Text              map[string]string   `json:"text,omitempty"`
	Include           []string            `json:"include,omitempty"`
	PromptCacheKey    string              `json:"prompt_cache_key,omitempty"`
	ToolChoice        string              `json:"tool_choice,omitempty"`
	ParallelToolCalls bool                `json:"parallel_tool_calls"`
	Reasoning         *responsesReasoning `json:"reasoning,omitempty"`
}

// buildResponsesInput converts the provider-neutral message list into the
// Responses API `input` array. User/assistant messages, function_call items
// (the assistant's tool requests), and function_call_output items (tool
// results) all sit side-by-side in one flat array.
func buildResponsesInput(msgs []Message) []any {
	input := make([]any, 0, len(msgs)*2)
	msgIdx := 0
	for _, m := range msgs {
		switch m.Role {
		case RoleUser:
			input = append(input, map[string]any{
				"role": "user",
				"content": []map[string]any{
					{"type": "input_text", "text": m.Text},
				},
			})
		case RoleAssistant:
			if m.Text != "" {
				input = append(input, map[string]any{
					"type":   "message",
					"role":   "assistant",
					"status": "completed",
					"id":     fmt.Sprintf("msg_%d", msgIdx),
					"content": []map[string]any{
						{"type": "output_text", "text": m.Text, "annotations": []any{}},
					},
				})
				msgIdx++
			}
			for _, tc := range m.ToolCalls {
				argsJSON, _ := json.Marshal(tc.Args)
				input = append(input, map[string]any{
					"type":      "function_call",
					"call_id":   tc.ID,
					"name":      tc.Name,
					"arguments": string(argsJSON),
				})
			}
		case RoleTool:
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": m.ToolCallID,
				"output":  m.Content,
			})
		}
	}
	return input
}

// buildResponsesTools converts provider-neutral tool defs into the Responses
// API `tools` array — all function tools, non-strict. Returns nil for an
// empty list so the omitempty tag drops the field entirely.
func buildResponsesTools(tools []ToolDef) []responsesTool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]responsesTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, responsesTool{
			Type:        "function",
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Schema,
			Strict:      false,
		})
	}
	return out
}

// clampReasoning mirrors pi-ai's model-specific effort clamping. gpt-5.2+
// doesn't accept "minimal"; bump to "low". Shared by both Responses drivers.
func clampReasoning(modelID, effort string) string {
	if effort == "minimal" {
		switch {
		case strings.HasPrefix(modelID, "gpt-5.2"),
			strings.HasPrefix(modelID, "gpt-5.3"),
			strings.HasPrefix(modelID, "gpt-5.4"),
			strings.HasPrefix(modelID, "gpt-5.5"):
			return "low"
		}
	}
	return effort
}

// --- SSE consumption ---

// consumeResponsesSSE drains a Responses-API SSE stream into the unified
// event channel. label names the provider for debug traces and the
// content-less error-frame fallback strings (so a blank upstream error still
// classifies as transient and the engine retries).
func consumeResponsesSSE(ctx context.Context, body io.ReadCloser, out chan<- stream.Event, label string) {
	defer func() { _ = body.Close() }()
	defer close(out)

	reader := stream.NewSSEReader(body)
	state := &responsesStreamState{label: label}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		evt, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			out <- stream.Event{Type: stream.EventError, Err: err.Error()}
			return
		}
		if evt.Data == "" || evt.Data == "[DONE]" {
			continue
		}

		var parsed map[string]any
		if err := json.Unmarshal([]byte(evt.Data), &parsed); err != nil {
			continue
		}
		t, _ := parsed["type"].(string)
		if DebugEnabled() {
			extra := ""
			if item, ok := parsed["item"].(map[string]any); ok {
				if itype, _ := item["type"].(string); itype != "" {
					extra = " item.type=" + itype
				}
			}
			debugFprintf(os.Stderr, "[%s-sse] %s%s", label, t, extra)
		}
		state.handle(t, parsed, out)
	}
}

// responsesStreamState tracks the current output item (message / reasoning /
// function_call) so delta events can be attributed correctly. label is the
// owning provider's name, used for debug output and error fallbacks.
type responsesStreamState struct {
	label    string
	itemType string // "message" | "reasoning" | "function_call"
	toolID   string
	toolName string
	toolJSON string
}

func (s *responsesStreamState) handle(t string, ev map[string]any, out chan<- stream.Event) {
	switch t {
	case "response.output_item.added":
		item, _ := ev["item"].(map[string]any)
		if item == nil {
			return
		}
		s.itemType, _ = item["type"].(string)
		switch s.itemType {
		case "message":
			out <- stream.Event{Type: stream.EventTextStart}
		case "reasoning":
			out <- stream.Event{Type: stream.EventThinkingStart}
		case "function_call":
			s.toolID, _ = item["call_id"].(string)
			s.toolName, _ = item["name"].(string)
			s.toolJSON, _ = item["arguments"].(string)
			out <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: s.toolID, Name: s.toolName}}
		}

	case "response.output_text.delta":
		delta, _ := ev["delta"].(string)
		if delta != "" {
			out <- stream.Event{Type: stream.EventTextDelta, Delta: delta}
		}

	case "response.reasoning_summary_text.delta":
		delta, _ := ev["delta"].(string)
		if delta != "" {
			out <- stream.Event{Type: stream.EventThinkingDelta, Delta: delta}
		}

	case "response.function_call_arguments.delta":
		delta, _ := ev["delta"].(string)
		if delta != "" {
			s.toolJSON += delta
			out <- stream.Event{Type: stream.EventToolCallDelta, Delta: delta}
		}

	case "response.output_item.done":
		item, _ := ev["item"].(map[string]any)
		switch s.itemType {
		case "message":
			var full string
			if item != nil {
				if content, ok := item["content"].([]any); ok {
					for _, c := range content {
						if cm, ok := c.(map[string]any); ok {
							if text, _ := cm["text"].(string); text != "" {
								full += text
							}
						}
					}
				}
			}
			out <- stream.Event{Type: stream.EventTextEnd, Content: full}
		case "reasoning":
			out <- stream.Event{Type: stream.EventThinkingEnd}
		case "function_call":
			args := map[string]any{}
			if s.toolJSON != "" {
				debugToolArgErr(s.label, json.Unmarshal([]byte(s.toolJSON), &args))
			}
			out <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{
				ID:        s.toolID,
				Name:      s.toolName,
				Arguments: args,
			}}
			s.toolID, s.toolName, s.toolJSON = "", "", ""
		}
		s.itemType = ""

	case "response.completed":
		usage := extractUsage(ev)
		stop := stream.StopReasonStop
		if resp, ok := ev["response"].(map[string]any); ok {
			if status, _ := resp["status"].(string); status == "incomplete" {
				stop = stream.StopReasonLength
			}
		}
		out <- stream.Event{Type: stream.EventDone, StopReason: stop, Usage: usage}

	case "response.failed":
		msg := s.label + " response failed"
		if resp, ok := ev["response"].(map[string]any); ok {
			if errObj, ok := resp["error"].(map[string]any); ok {
				if m, _ := errObj["message"].(string); m != "" {
					msg = m
				}
			}
		}
		out <- stream.Event{Type: stream.EventError, Err: msg}

	case "error":
		msg, _ := ev["message"].(string)
		if msg == "" {
			msg = s.label + " stream error"
		}
		out <- stream.Event{Type: stream.EventError, Err: msg}
	}
}

// extractUsage pulls the token counts off a response.completed event's
// nested response.usage object. Shared by every Responses-API driver.
func extractUsage(ev map[string]any) *stream.Usage {
	resp, ok := ev["response"].(map[string]any)
	if !ok {
		return nil
	}
	u, ok := resp["usage"].(map[string]any)
	if !ok {
		return nil
	}
	input := intField(u, "input_tokens")
	output := intField(u, "output_tokens")
	total := intField(u, "total_tokens")
	cached := 0
	if details, ok := u["input_tokens_details"].(map[string]any); ok {
		cached = intField(details, "cached_tokens")
	}
	return &stream.Usage{
		Input:       input - cached,
		Output:      output,
		CacheRead:   cached,
		TotalTokens: total,
	}
}

// intField reads a numeric field off a decoded JSON object (JSON numbers
// decode to float64). A generic helper reused across the SSE parsers in this
// package (Responses usage, Anthropic/Vertex token counts).
func intField(m map[string]any, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}

// responsesErrorFrom returns a friendlier error for common 4xx/5xx responses
// from a Responses-API endpoint. label prefixes the message with the owning
// provider's name.
func responsesErrorFrom(label string, status int, raw []byte) error {
	var parsed struct {
		Error struct {
			Code     string  `json:"code"`
			Type     string  `json:"type"`
			Message  string  `json:"message"`
			PlanType string  `json:"plan_type"`
			ResetsAt float64 `json:"resets_at"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &parsed)
	if parsed.Error.Message != "" {
		return fmt.Errorf("%s %d: %s", label, status, parsed.Error.Message)
	}
	if len(raw) > 0 {
		return fmt.Errorf("%s %d: %s", label, status, string(raw))
	}
	return fmt.Errorf("%s %d", label, status)
}
