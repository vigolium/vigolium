package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

const openAIChatCompletionsURL = "https://api.openai.com/v1/chat/completions"

// OpenAI is the Chat Completions API provider. It streams Server-Sent Events,
// reassembles tool-call argument deltas, and emits unified stream.Event
// values. Modeled after the Anthropic provider so the engine doesn't need to
// know which backend is running.
//
// The same struct also backs the openai-compatible provider (Ollama,
// OpenRouter, LM Studio, vLLM, etc.) — the only differences are baseURL,
// optional extra headers, and that an empty apiKey suppresses the
// Authorization header so unauthenticated local servers work.
type OpenAI struct {
	apiKey       secret
	baseURL      string // full chat-completions URL
	extraHeaders map[string]string
	name         string
	client       *http.Client
}

// NewOpenAI constructs the canonical OpenAI provider pointed at
// api.openai.com. The key is wrapped in a formatter-safe secret so a stray
// `%v` on the provider can't leak it.
func NewOpenAI(apiKey string) *OpenAI {
	return &OpenAI{
		apiKey:  secret(apiKey),
		baseURL: openAIChatCompletionsURL,
		name:    "openai",
		client:  newHTTPClient(),
	}
}

// NewOpenAICompatible constructs a provider that speaks the OpenAI Chat
// Completions wire format against an arbitrary endpoint (Ollama, OpenRouter,
// LM Studio, vLLM, Together, Groq, LocalAI, custom proxies).
//
// baseURL accepts either a full chat-completions URL
// (http://host/v1/chat/completions) or the v1 root (http://host/v1), in
// which case /chat/completions is appended. An empty apiKey suppresses the
// Authorization header — required for unauthenticated local servers like
// Ollama. extraHeaders are applied after standard headers so callers can
// override Authorization for backends with non-Bearer schemes.
func NewOpenAICompatible(baseURL, apiKey string, extraHeaders map[string]string) *OpenAI {
	return &OpenAI{
		apiKey:       secret(apiKey),
		baseURL:      normalizeOpenAIBaseURL(baseURL),
		extraHeaders: extraHeaders,
		name:         "openai-compatible",
		client:       newHTTPClient(),
	}
}

// normalizeOpenAIBaseURL tolerates either a full chat-completions URL or a
// v1 root by appending /chat/completions when the path doesn't already end
// in it. Trailing slashes are trimmed so we don't end up with `/v1//chat/...`.
func normalizeOpenAIBaseURL(raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	if u == "" {
		return ""
	}
	if strings.HasSuffix(u, "/chat/completions") {
		return u
	}
	return u + "/chat/completions"
}

func (o *OpenAI) Name() string {
	if o.name != "" {
		return o.name
	}
	return "openai"
}

// CloseIdleConnections drops idle HTTP/2 conns on this provider's transport.
// See provider.ConnectionResetter.
func (o *OpenAI) CloseIdleConnections() {
	o.client.CloseIdleConnections()
}

// --- Request body types ---

type oaiToolDef struct {
	Type     string         `json:"type"` // always "function"
	Function oaiFunctionDef `json:"function"`
}

type oaiFunctionDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
}

type oaiToolCall struct {
	ID       string          `json:"id,omitempty"`
	Type     string          `json:"type,omitempty"` // "function"
	Function oaiFunctionCall `json:"function"`
}

type oaiFunctionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments"` // JSON-encoded as a string
}

type oaiMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content,omitempty"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
	Name       string        `json:"name,omitempty"`
}

type oaiRequest struct {
	Model    string       `json:"model"`
	Messages []oaiMessage `json:"messages"`
	Tools    []oaiToolDef `json:"tools,omitempty"`
	Stream   bool         `json:"stream"`
	// StreamOptions.IncludeUsage requests the final chunk to carry token
	// counts in `usage` — Anthropic gives them by default; OpenAI requires
	// the opt-in.
	StreamOptions *oaiStreamOptions `json:"stream_options,omitempty"`
}

type oaiStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// Stream issues a streaming Chat Completions request and returns a channel
// of unified events. Same protocol contract as Provider.Stream on every
// other backend in this package.
func (a *OpenAI) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	body := buildOpenAIRequest(req)
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := a.baseURL
	if url == "" {
		url = openAIChatCompletionsURL
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	// Skip Authorization when no key is configured — unauthenticated local
	// servers (Ollama, LM Studio with no token, vLLM behind a trust boundary)
	// reject the bogus `Bearer ` value, and the standard OpenAI path always
	// has a key, so the conditional only kicks in for openai-compatible.
	if key := a.apiKey.Reveal(); key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+key)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	for k, v := range a.extraHeaders {
		httpReq.Header.Set(k, v)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.Name(), err)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s %d: %s", a.Name(), resp.StatusCode, string(raw))
	}

	out := make(chan stream.Event, 32)
	go a.consumeSSE(ctx, resp.Body, out)
	return out, nil
}

func buildOpenAIRequest(req Request) oaiRequest {
	messages := make([]oaiMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		messages = append(messages, oaiMessage{Role: "system", Content: req.System})
	}

	for _, m := range req.Messages {
		switch m.Role {
		case RoleUser:
			messages = append(messages, oaiMessage{Role: "user", Content: m.Text})

		case RoleAssistant:
			msg := oaiMessage{Role: "assistant", Content: m.Text}
			if len(m.ToolCalls) > 0 {
				msg.ToolCalls = make([]oaiToolCall, 0, len(m.ToolCalls))
				for _, tc := range m.ToolCalls {
					argsJSON, _ := json.Marshal(tc.Args)
					msg.ToolCalls = append(msg.ToolCalls, oaiToolCall{
						ID:   tc.ID,
						Type: "function",
						Function: oaiFunctionCall{
							Name:      tc.Name,
							Arguments: string(argsJSON),
						},
					})
				}
			}
			messages = append(messages, msg)

		case RoleTool:
			messages = append(messages, oaiMessage{
				Role:       "tool",
				ToolCallID: m.ToolCallID,
				Content:    m.Content,
			})
		}
	}

	body := oaiRequest{
		Model:         req.Model,
		Messages:      messages,
		Stream:        true,
		StreamOptions: &oaiStreamOptions{IncludeUsage: true},
	}
	if len(req.Tools) > 0 {
		body.Tools = make([]oaiToolDef, 0, len(req.Tools))
		for _, t := range req.Tools {
			body.Tools = append(body.Tools, oaiToolDef{
				Type: "function",
				Function: oaiFunctionDef{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  t.Schema,
				},
			})
		}
	}
	return body
}

// --- SSE consumption ---

// consumeSSE walks the OpenAI streaming response and emits unified events.
// The protocol differs from Anthropic in three notable ways: (1) the
// terminating sentinel is the literal string `[DONE]`, not a JSON event;
// (2) tool calls are streamed as a list keyed by `index`, with name/id
// arriving once and `function.arguments` arriving as JSON string fragments
// that must be concatenated before parsing; (3) usage stats are only
// included when StreamOptions.IncludeUsage is set, and arrive in a final
// chunk that has an empty `choices` array.
func (a *OpenAI) consumeSSE(ctx context.Context, body io.ReadCloser, out chan<- stream.Event) {
	defer func() { _ = body.Close() }()
	defer close(out)

	reader := stream.NewSSEReader(body)
	state := &openaiState{tools: map[int]*openaiToolBuf{}}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		evt, err := reader.Next()
		if errors.Is(err, io.EOF) {
			state.flushFinal(out)
			return
		}
		if err != nil {
			out <- stream.Event{Type: stream.EventError, Err: err.Error()}
			return
		}
		data := strings.TrimSpace(evt.Data)
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			state.flushFinal(out)
			return
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(data), &parsed); err != nil {
			continue
		}
		state.handle(parsed, out)
	}
}

type openaiToolBuf struct {
	id        string
	name      string
	arguments strings.Builder
	emitted   bool // true once we've sent EventToolCallStart
}

type openaiState struct {
	textOpen   bool
	tools      map[int]*openaiToolBuf
	stopReason stream.StopReason
	usage      stream.Usage
	finalSent  bool
}

func (s *openaiState) handle(ev map[string]any, out chan<- stream.Event) {
	choices, _ := ev["choices"].([]any)
	if u, ok := ev["usage"].(map[string]any); ok {
		s.usage.Input = intField(u, "prompt_tokens")
		s.usage.Output = intField(u, "completion_tokens")
		// Cached prompt tokens live under prompt_tokens_details.cached_tokens.
		if d, ok := u["prompt_tokens_details"].(map[string]any); ok {
			s.usage.CacheRead = intField(d, "cached_tokens")
		}
	}

	for _, c := range choices {
		choice, _ := c.(map[string]any)
		if choice == nil {
			continue
		}
		if delta, ok := choice["delta"].(map[string]any); ok {
			s.applyDelta(delta, out)
		}
		if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
			s.setStop(fr)
		}
	}
}

func (s *openaiState) applyDelta(delta map[string]any, out chan<- stream.Event) {
	if content, ok := delta["content"].(string); ok && content != "" {
		if !s.textOpen {
			out <- stream.Event{Type: stream.EventTextStart}
			s.textOpen = true
		}
		out <- stream.Event{Type: stream.EventTextDelta, Delta: content}
	}

	tcs, _ := delta["tool_calls"].([]any)
	for _, raw := range tcs {
		tc, _ := raw.(map[string]any)
		if tc == nil {
			continue
		}
		idx := intField(tc, "index")
		buf, ok := s.tools[idx]
		if !ok {
			buf = &openaiToolBuf{}
			s.tools[idx] = buf
		}
		if id, _ := tc["id"].(string); id != "" {
			buf.id = id
		}
		if fn, ok := tc["function"].(map[string]any); ok {
			if name, _ := fn["name"].(string); name != "" {
				buf.name = name
			}
			if args, _ := fn["arguments"].(string); args != "" {
				buf.arguments.WriteString(args)
				if buf.emitted {
					out <- stream.Event{Type: stream.EventToolCallDelta, Delta: args}
				}
			}
		}
		// Emit start once we have at least the function name.
		if !buf.emitted && buf.name != "" {
			out <- stream.Event{
				Type:     stream.EventToolCallStart,
				ToolCall: &stream.ToolCall{ID: buf.id, Name: buf.name},
			}
			buf.emitted = true
			// Backfill any arguments that arrived alongside the name in the
			// same delta — emit them now so the consumer's running buffer
			// stays in sync with the final accumulated string.
			if buf.arguments.Len() > 0 {
				out <- stream.Event{Type: stream.EventToolCallDelta, Delta: buf.arguments.String()}
			}
		}
	}
}

func (s *openaiState) setStop(reason string) {
	switch reason {
	case "stop":
		s.stopReason = stream.StopReasonStop
	case "length":
		s.stopReason = stream.StopReasonLength
	case "tool_calls", "function_call":
		s.stopReason = stream.StopReasonToolUse
	default:
		s.stopReason = stream.StopReasonStop
	}
}

// flushFinal emits the closing events: text_end (if a text block was open),
// one tool_call_end per buffered tool call (with arguments parsed from the
// accumulated JSON string), and a single done event with the usage tally.
// Idempotent — safe to call from both the [DONE] sentinel and the EOF path.
func (s *openaiState) flushFinal(out chan<- stream.Event) {
	if s.finalSent {
		return
	}
	s.finalSent = true

	if s.textOpen {
		out <- stream.Event{Type: stream.EventTextEnd}
		s.textOpen = false
	}
	// Iterate by index order so multi-tool turns commit deterministically.
	max := -1
	for i := range s.tools {
		if i > max {
			max = i
		}
	}
	for i := 0; i <= max; i++ {
		buf, ok := s.tools[i]
		if !ok || !buf.emitted {
			continue
		}
		args := map[string]any{}
		if buf.arguments.Len() > 0 {
			debugToolArgErr("openai", json.Unmarshal([]byte(buf.arguments.String()), &args))
		}
		out <- stream.Event{
			Type: stream.EventToolCallEnd,
			ToolCall: &stream.ToolCall{
				ID:        buf.id,
				Name:      buf.name,
				Arguments: args,
			},
		}
	}
	usage := s.usage
	usage.TotalTokens = usage.Input + usage.Output
	out <- stream.Event{Type: stream.EventDone, StopReason: s.stopReason, Usage: &usage}
}
