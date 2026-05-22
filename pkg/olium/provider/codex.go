package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/olium/auth"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// codexDebug dumps every SSE event type to stderr when VIGOLIUM_OLIUM_DEBUG=1.
// Kept as a quiet operator knob for tracking down stream-shape regressions.
var codexDebug = os.Getenv("VIGOLIUM_OLIUM_DEBUG") != ""

// debugToolArgErr surfaces a tool-call argument unmarshal failure under the
// VIGOLIUM_OLIUM_DEBUG knob. A failure here is consequential: the tool is
// invoked with empty arguments because the streamed JSON could not be
// assembled. It is kept non-fatal (the call still proceeds) but observable.
// Shared by the codex, anthropic, and openai stream parsers in this package.
func debugToolArgErr(provider string, err error) {
	if err != nil && codexDebug {
		fmt.Fprintf(os.Stderr, "[olium %s] tool-call argument unmarshal failed: %v\n", provider, err)
	}
}

const (
	codexDefaultBaseURL = "https://chatgpt.com/backend-api"
	codexResponsesPath  = "/codex/responses"
	codexOriginator     = "olium"
)

// Codex speaks to the ChatGPT backend /codex/responses endpoint using a
// ChatGPT subscription token (not an OpenAI API key). Stream format is SSE
// with response.* events matching the Responses API.
type Codex struct {
	auth    *auth.CodexAuth
	baseURL string
	http    *http.Client
}

// NewCodex constructs a Codex provider with the given auth handle.
func NewCodex(a *auth.CodexAuth) *Codex {
	return &Codex{
		auth:    a,
		baseURL: codexDefaultBaseURL,
		http:    newHTTPClient(),
	}
}

func (c *Codex) Name() string { return "codex" }

// CloseIdleConnections drops idle HTTP/2 conns on this provider's transport.
// See provider.ConnectionResetter.
func (c *Codex) CloseIdleConnections() {
	c.http.CloseIdleConnections()
}

// --- Request body types ---
//
// The Codex Responses API accepts a heterogeneous `input` array: user
// messages, assistant messages, function_call items (assistant's tool
// requests), and function_call_output items (tool responses) all sit
// side-by-side. We model it as []any with per-message struct shapes.

type codexReasoning struct {
	Effort  string `json:"effort,omitempty"`
	Summary string `json:"summary,omitempty"`
}

type codexTool struct {
	Type        string         `json:"type"` // "function"
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
	Strict      bool           `json:"strict"`
}

type codexRequest struct {
	Model             string            `json:"model"`
	Store             bool              `json:"store"`
	Stream            bool              `json:"stream"`
	Instructions      string            `json:"instructions,omitempty"`
	Input             []any             `json:"input"`
	Tools             []codexTool       `json:"tools,omitempty"`
	Text              map[string]string `json:"text,omitempty"`
	Include           []string          `json:"include,omitempty"`
	PromptCacheKey    string            `json:"prompt_cache_key,omitempty"`
	ToolChoice        string            `json:"tool_choice,omitempty"`
	ParallelToolCalls bool              `json:"parallel_tool_calls"`
	Reasoning         *codexReasoning   `json:"reasoning,omitempty"`
}

func (c *Codex) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	accountID, err := c.auth.AccountID()
	if err != nil {
		return nil, fmt.Errorf("codex: %w", err)
	}
	token, err := c.auth.AccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("codex: %w", err)
	}

	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = uuid.NewString()
	}

	body := buildCodexRequest(req, sessionID)
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	resp, err := c.doStreamRequest(ctx, payload, sessionID, token, accountID)
	if err != nil {
		return nil, err
	}
	// On 401 the access token is bad even though the JWT exp said it was
	// fine — clock skew, manual revocation, or server-side invalidation.
	// Force a refresh and retry the request once. We only retry once to
	// avoid a tight loop if the refresh itself is broken.
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		newToken, refreshErr := c.auth.ForceRefresh(ctx, token)
		if refreshErr != nil {
			return nil, fmt.Errorf("codex 401 retry: %w", refreshErr)
		}
		resp, err = c.doStreamRequest(ctx, payload, sessionID, newToken, accountID)
		if err != nil {
			return nil, err
		}
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, codexErrorFrom(resp.StatusCode, raw)
	}

	out := make(chan stream.Event, 32)
	go c.consumeSSE(ctx, resp.Body, out)
	return out, nil
}

func (c *Codex) doStreamRequest(ctx context.Context, payload []byte, sessionID, token, accountID string) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+codexResponsesPath, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("chatgpt-account-id", accountID)
	httpReq.Header.Set("originator", codexOriginator)
	httpReq.Header.Set("OpenAI-Beta", "responses=experimental")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("session_id", sessionID)
	httpReq.Header.Set("x-client-request-id", sessionID)
	httpReq.Header.Set("User-Agent", fmt.Sprintf("olium (%s %s)", runtime.GOOS, runtime.GOARCH))

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("codex request: %w", err)
	}
	return resp, nil
}

func buildCodexRequest(req Request, sessionID string) codexRequest {
	input := make([]any, 0, len(req.Messages)*2)
	msgIdx := 0
	for _, m := range req.Messages {
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

	body := codexRequest{
		Model:             req.Model,
		Store:             false,
		Stream:            true,
		Instructions:      req.System,
		Input:             input,
		Text:              map[string]string{"verbosity": "medium"},
		Include:           []string{"reasoning.encrypted_content"},
		PromptCacheKey:    sessionID,
		ToolChoice:        "auto",
		ParallelToolCalls: true,
	}
	if len(req.Tools) > 0 {
		body.Tools = make([]codexTool, 0, len(req.Tools))
		for _, t := range req.Tools {
			body.Tools = append(body.Tools, codexTool{
				Type:        "function",
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Schema,
				Strict:      false,
			})
		}
	}
	// Always request reasoning summaries so the TUI can show "thinking"
	// before each answer. Default effort is "medium" unless the caller
	// overrides via Request.ReasoningEff.
	effort := req.ReasoningEff
	if effort == "" {
		effort = "medium"
	}
	body.Reasoning = &codexReasoning{
		Effort:  clampReasoning(req.Model, effort),
		Summary: "auto",
	}
	return body
}

// clampReasoning mirrors pi-ai's model-specific effort clamping. gpt-5.2+
// doesn't accept "minimal"; bump to "low".
func clampReasoning(modelID, effort string) string {
	if effort == "minimal" {
		switch {
		case hasPrefix(modelID, "gpt-5.2"), hasPrefix(modelID, "gpt-5.3"), hasPrefix(modelID, "gpt-5.4"), hasPrefix(modelID, "gpt-5.5"):
			return "low"
		}
	}
	return effort
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// --- SSE consumption ---

func (c *Codex) consumeSSE(ctx context.Context, body io.ReadCloser, out chan<- stream.Event) {
	defer func() { _ = body.Close() }()
	defer close(out)

	reader := stream.NewSSEReader(body)
	state := &codexStreamState{}

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
		if codexDebug {
			extra := ""
			if item, ok := parsed["item"].(map[string]any); ok {
				if itype, _ := item["type"].(string); itype != "" {
					extra = " item.type=" + itype
				}
			}
			debugFprintf(os.Stderr, "[codex-sse] %s%s", t, extra)
		}
		state.handle(t, parsed, out)
	}
}

// codexStreamState tracks the current output item (message / reasoning /
// function_call) so delta events can be attributed correctly.
type codexStreamState struct {
	itemType string // "message" | "reasoning" | "function_call"
	toolID   string
	toolName string
	toolJSON string
}

func (s *codexStreamState) handle(t string, ev map[string]any, out chan<- stream.Event) {
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
				debugToolArgErr("codex", json.Unmarshal([]byte(s.toolJSON), &args))
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
		msg := "codex response failed"
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
			msg = "codex stream error"
		}
		out <- stream.Event{Type: stream.EventError, Err: msg}
	}
}

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

func intField(m map[string]any, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}

// codexErrorFrom returns a friendlier error for common 4xx/5xx responses.
func codexErrorFrom(status int, raw []byte) error {
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
		return fmt.Errorf("codex %d: %s", status, parsed.Error.Message)
	}
	if len(raw) > 0 {
		return fmt.Errorf("codex %d: %s", status, string(raw))
	}
	return fmt.Errorf("codex %d", status)
}
