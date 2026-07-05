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

const (
	anthropicMessagesURL = "https://api.anthropic.com/v1/messages"
	anthropicVersion     = "2023-06-01"
	// claudeCodeOAuthBeta is required when authenticating with a Claude Code
	// OAuth token (`sk-ant-oat01-…` minted by `claude setup-token`).
	claudeCodeOAuthBeta = "oauth-2025-04-20"
	// claudeCodeOAuthPreamble is the system-prompt prefix the Anthropic API
	// expects when an OAuth-token request goes out. Without it the OAuth
	// session is rejected as "not Claude Code". We prepend it transparently
	// so user-supplied system prompts continue to work.
	claudeCodeOAuthPreamble = "You are Claude Code, Anthropic's official CLI for Claude."
)

// Anthropic is the native Messages API provider. It streams Server-Sent
// Events, accumulates content blocks, and emits unified stream.Event values.
//
// Two auth modes are supported:
//   - apiKey   : standard `x-api-key` header (`sk-ant-api…` keys).
//   - oauthToken: `Authorization: Bearer …` plus the OAuth beta header,
//     used for Claude Code OAuth tokens (`sk-ant-oat01-…`).
//
// Both credential fields are wrapped in a formatter-safe secret so a stray
// `%v` on the provider value can't leak the raw credential. baseURL and
// extraHeaders back the anthropic-compatible variant — a gateway or proxy that
// mirrors POST /v1/messages — and default to the canonical Anthropic endpoint
// with no extra headers for the api-key / oauth providers.
type Anthropic struct {
	apiKey       secret
	oauthToken   secret
	baseURL      string
	extraHeaders map[string]string
	name         string
	client       *http.Client
}

// NewAnthropic constructs an Anthropic provider authenticated with an API key.
func NewAnthropic(apiKey string) *Anthropic {
	return &Anthropic{apiKey: secret(apiKey), baseURL: anthropicMessagesURL, name: "anthropic", client: newHTTPClient()}
}

// NewAnthropicOAuth constructs an Anthropic provider authenticated with a
// Claude Code OAuth token (produced by `claude setup-token`). Requests sent
// through this provider include the `oauth-2025-04-20` beta header and the
// Claude Code system-prompt preamble required by the OAuth grant.
func NewAnthropicOAuth(token string) *Anthropic {
	return &Anthropic{oauthToken: secret(token), baseURL: anthropicMessagesURL, name: "anthropic", client: newHTTPClient()}
}

// NewAnthropicCompatible speaks the Anthropic Messages wire format against an
// arbitrary base URL — a self-hosted gateway, a LiteLLM-style proxy, or any
// endpoint that mirrors POST /v1/messages. baseURL accepts a full messages URL
// (http://host/v1/messages), a /v1 root (http://host/v1 — /messages is
// appended), or a bare host (http://host — /v1/messages is appended). An empty
// apiKey suppresses the x-api-key header for unauthenticated local proxies;
// extraHeaders are applied last so callers can switch to a Bearer scheme or
// pin a specific anthropic-version.
func NewAnthropicCompatible(baseURL, apiKey string, extraHeaders map[string]string) *Anthropic {
	return &Anthropic{
		apiKey:       secret(apiKey),
		baseURL:      normalizeAnthropicBaseURL(baseURL),
		extraHeaders: extraHeaders,
		name:         "anthropic-compatible",
		client:       newHTTPClient(),
	}
}

func (a *Anthropic) Name() string { return a.name }

// normalizeAnthropicBaseURL tolerates a full /v1/messages URL, a /v1 root, or
// a bare host, resolving each to a complete messages endpoint. Trailing
// slashes are trimmed so we never emit /v1//messages.
func normalizeAnthropicBaseURL(raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	switch {
	case u == "":
		return ""
	case strings.HasSuffix(u, "/messages"):
		return u
	case strings.HasSuffix(u, "/v1"):
		return u + "/messages"
	default:
		return u + "/v1/messages"
	}
}

// CloseIdleConnections drops idle HTTP/2 conns on this provider's transport
// so the next request opens a fresh one. Engine calls this between retry
// attempts after a transient stream error.
func (a *Anthropic) CloseIdleConnections() {
	a.client.CloseIdleConnections()
}

// --- Request body types ---

type anthContentText struct {
	Type string `json:"type"` // "text"
	Text string `json:"text"`
}

type anthContentToolUse struct {
	Type  string         `json:"type"` // "tool_use"
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	Input map[string]any `json:"input"`
}

type anthContentToolResult struct {
	Type      string `json:"type"` // "tool_result"
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

type anthMessage struct {
	Role    string `json:"role"`
	Content []any  `json:"content"`
}

// anthCacheControl marks a content block as a prompt-cache breakpoint.
// Only "ephemeral" is supported today; callers should emit at most 4
// breakpoints per request (Anthropic API limit).
type anthCacheControl struct {
	Type string `json:"type"` // "ephemeral"
}

// anthSystemBlock is the structured form of the system field — we only
// switch to it when prompt caching is enabled, since "system as string"
// and "system as []block" are both accepted and the string form is
// lighter on the wire.
type anthSystemBlock struct {
	Type         string            `json:"type"` // "text"
	Text         string            `json:"text"`
	CacheControl *anthCacheControl `json:"cache_control,omitempty"`
}

type anthTool struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	InputSchema  map[string]any    `json:"input_schema"`
	CacheControl *anthCacheControl `json:"cache_control,omitempty"`
}

type anthRequest struct {
	Model     string        `json:"model"`
	System    any           `json:"system,omitempty"` // string or []anthSystemBlock
	MaxTokens int           `json:"max_tokens"`
	Messages  []anthMessage `json:"messages"`
	Tools     []anthTool    `json:"tools,omitempty"`
	Stream    bool          `json:"stream"`
}

func (a *Anthropic) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	if !a.oauthToken.IsZero() {
		req.System = applyClaudeCodeOAuthPreamble(req.System)
	}
	body := buildAnthropicRequest(req)
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	if !a.oauthToken.IsZero() {
		httpReq.Header.Set("authorization", "Bearer "+a.oauthToken.Reveal())
		httpReq.Header.Set("anthropic-beta", claudeCodeOAuthBeta)
	} else if !a.apiKey.IsZero() {
		// Empty api key (anthropic-compatible against an unauthenticated local
		// proxy) suppresses the header entirely, mirroring openai-compatible.
		httpReq.Header.Set("x-api-key", a.apiKey.Reveal())
	}
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("accept", "text/event-stream")
	// extraHeaders are applied last so a compatible gateway can override the
	// auth scheme (e.g. Authorization: Bearer) or pin its own anthropic-version.
	for k, v := range a.extraHeaders {
		httpReq.Header.Set(k, v)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		// Auth failures (401/403) are the most common transient operator
		// issue with this provider, especially for anthropic-oauth where
		// the token from `claude setup-token` rotates every 90 days. Surface
		// a structured hint so the operator knows what to do — without it,
		// the raw upstream "authentication_error" can read as a transient
		// network blip and trigger a retry loop.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			hint := " — anthropic API key is invalid or expired; rotate via the Anthropic console"
			if !a.oauthToken.IsZero() {
				hint = " — Claude Code OAuth token expired or revoked; refresh with `claude setup-token` and update agent.olium.oauth_token (or $ANTHROPIC_API_KEY)"
			}
			return nil, fmt.Errorf("anthropic %d: %s%s", resp.StatusCode, string(raw), hint)
		}
		return nil, fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(raw))
	}

	out := make(chan stream.Event, 32)
	go consumeAnthropicSSE(ctx, resp.Body, out)
	return out, nil
}

func buildAnthropicRequest(req Request) anthRequest {
	body := anthRequest{
		Model:     req.Model,
		MaxTokens: 8192,
		Messages:  buildAnthropicMessages(req.Messages),
		Stream:    true,
	}
	applyAnthropicSystemAndTools(&body, req)
	return body
}

// buildAnthropicMessages converts the provider-neutral message list into
// Anthropic's `messages` array, folding consecutive tool_result blocks into
// a single user message as the API requires. Exposed (un-exported but
// package-visible) so the Vertex Anthropic path can reuse it.
func buildAnthropicMessages(msgs []Message) []anthMessage {
	messages := make([]anthMessage, 0, len(msgs))

	// Anthropic requires alternating roles. Consecutive tool results from
	// a single assistant turn must be merged into one user message with
	// multiple tool_result content blocks. We build up a pending message
	// and flush it when the role flips.
	var pending *anthMessage
	flush := func() {
		if pending != nil && len(pending.Content) > 0 {
			messages = append(messages, *pending)
		}
		pending = nil
	}

	for _, m := range msgs {
		switch m.Role {
		case RoleUser:
			if pending == nil || pending.Role != "user" {
				flush()
				pending = &anthMessage{Role: "user"}
			}
			pending.Content = append(pending.Content, anthContentText{Type: "text", Text: m.Text})

		case RoleAssistant:
			flush()
			pending = &anthMessage{Role: "assistant"}
			if m.Text != "" {
				pending.Content = append(pending.Content, anthContentText{Type: "text", Text: m.Text})
			}
			for _, tc := range m.ToolCalls {
				pending.Content = append(pending.Content, anthContentToolUse{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Name,
					Input: tc.Args,
				})
			}

		case RoleTool:
			// Tool results belong to a "user" message per Anthropic spec.
			if pending == nil || pending.Role != "user" {
				flush()
				pending = &anthMessage{Role: "user"}
			}
			pending.Content = append(pending.Content, anthContentToolResult{
				Type:      "tool_result",
				ToolUseID: m.ToolCallID,
				Content:   m.Content,
				IsError:   m.IsError,
			})
		}
	}
	flush()
	return messages
}

// applyAnthropicSystemAndTools fills system + tools onto an existing
// request body, applying optional cache-control breakpoints. Shared between
// the native Anthropic provider and the Vertex Anthropic path.
func applyAnthropicSystemAndTools(body *anthRequest, req Request) {
	// System: emit as a string by default, or as a cache-tagged content
	// block when caching is on. The block form is slightly heavier on the
	// wire but lets Anthropic reuse the cached prefix on follow-up turns.
	if req.CacheControl && strings.TrimSpace(req.System) != "" {
		body.System = []anthSystemBlock{{
			Type:         "text",
			Text:         req.System,
			CacheControl: &anthCacheControl{Type: "ephemeral"},
		}}
	} else if req.System != "" {
		body.System = req.System
	}

	if len(req.Tools) > 0 {
		body.Tools = make([]anthTool, 0, len(req.Tools))
		for _, t := range req.Tools {
			body.Tools = append(body.Tools, anthTool{
				Name:        t.Name,
				Description: t.Description,
				InputSchema: t.Schema,
			})
		}
		// Place one cache breakpoint on the final tool — Anthropic
		// caches up to and including the marked block, so tagging the
		// last tool effectively caches the entire tool list (which is
		// stable across an autopilot run).
		if req.CacheControl {
			body.Tools[len(body.Tools)-1].CacheControl = &anthCacheControl{Type: "ephemeral"}
		}
	}
}

// --- SSE consumption ---

// consumeAnthropicSSE drains an Anthropic-style Messages SSE stream into the
// unified event channel. Shared between the direct Anthropic provider and
// the Vertex Anthropic path (which uses the same SSE shape).
func consumeAnthropicSSE(ctx context.Context, body io.ReadCloser, out chan<- stream.Event) {
	defer func() { _ = body.Close() }()
	defer close(out)

	reader := stream.NewSSEReader(body)
	state := &anthropicState{}

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
		if evt.Data == "" {
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(evt.Data), &parsed); err != nil {
			continue
		}
		state.handle(evt.Event, parsed, out)
	}
}

type anthropicState struct {
	currentKind string // "text" | "tool_use" | "thinking"
	toolID      string
	toolName    string
	toolJSON    string
	stopReason  stream.StopReason

	usage stream.Usage
}

func (s *anthropicState) handle(evtName string, ev map[string]any, out chan<- stream.Event) {
	t, _ := ev["type"].(string)
	if t == "" {
		t = evtName
	}

	switch t {
	case "message_start":
		if msg, ok := ev["message"].(map[string]any); ok {
			if u, ok := msg["usage"].(map[string]any); ok {
				s.usage.Input = intField(u, "input_tokens")
				s.usage.CacheRead = intField(u, "cache_read_input_tokens")
				s.usage.CacheWrite = intField(u, "cache_creation_input_tokens")
			}
		}

	case "content_block_start":
		block, _ := ev["content_block"].(map[string]any)
		if block == nil {
			return
		}
		kind, _ := block["type"].(string)
		s.currentKind = kind
		switch kind {
		case "text":
			out <- stream.Event{Type: stream.EventTextStart}
		case "tool_use":
			s.toolID, _ = block["id"].(string)
			s.toolName, _ = block["name"].(string)
			s.toolJSON = ""
			out <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: s.toolID, Name: s.toolName}}
		case "thinking":
			out <- stream.Event{Type: stream.EventThinkingStart}
		}

	case "content_block_delta":
		delta, _ := ev["delta"].(map[string]any)
		if delta == nil {
			return
		}
		dtype, _ := delta["type"].(string)
		switch dtype {
		case "text_delta":
			if text, _ := delta["text"].(string); text != "" {
				out <- stream.Event{Type: stream.EventTextDelta, Delta: text}
			}
		case "input_json_delta":
			if partial, _ := delta["partial_json"].(string); partial != "" {
				s.toolJSON += partial
				out <- stream.Event{Type: stream.EventToolCallDelta, Delta: partial}
			}
		case "thinking_delta":
			if text, _ := delta["thinking"].(string); text != "" {
				out <- stream.Event{Type: stream.EventThinkingDelta, Delta: text}
			}
		}

	case "content_block_stop":
		switch s.currentKind {
		case "text":
			out <- stream.Event{Type: stream.EventTextEnd}
		case "tool_use":
			args := map[string]any{}
			if s.toolJSON != "" {
				debugToolArgErr("anthropic", json.Unmarshal([]byte(s.toolJSON), &args))
			}
			out <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{
				ID:        s.toolID,
				Name:      s.toolName,
				Arguments: args,
			}}
			s.toolID, s.toolName, s.toolJSON = "", "", ""
		case "thinking":
			out <- stream.Event{Type: stream.EventThinkingEnd}
		}
		s.currentKind = ""

	case "message_delta":
		if delta, ok := ev["delta"].(map[string]any); ok {
			if stop, ok := delta["stop_reason"].(string); ok {
				s.setStop(stop)
			}
		}
		if u, ok := ev["usage"].(map[string]any); ok {
			s.usage.Output = intField(u, "output_tokens")
		}

	case "message_stop":
		u := s.usage
		u.TotalTokens = u.Input + u.Output
		out <- stream.Event{Type: stream.EventDone, StopReason: s.stopReason, Usage: &u}

	case "error":
		msg := "anthropic error"
		if e, ok := ev["error"].(map[string]any); ok {
			if m, _ := e["message"].(string); m != "" {
				msg = m
			}
		}
		out <- stream.Event{Type: stream.EventError, Err: msg}
	}
}

// applyClaudeCodeOAuthPreamble prepends the Claude Code identity preamble
// required by OAuth-token requests. If the user-supplied system prompt
// already contains the preamble (e.g. from a custom override), it is
// returned untouched so we don't double-prepend.
func applyClaudeCodeOAuthPreamble(system string) string {
	if system == "" {
		return claudeCodeOAuthPreamble
	}
	if strings.HasPrefix(system, claudeCodeOAuthPreamble) {
		return system
	}
	return claudeCodeOAuthPreamble + "\n\n" + system
}

// stopReason lives on the state so message_stop has something to emit
// even if message_delta arrived earlier.
func (s *anthropicState) setStop(stop string) {
	switch stop {
	case "end_turn", "stop_sequence":
		s.stopReason = stream.StopReasonStop
	case "max_tokens":
		s.stopReason = stream.StopReasonLength
	case "tool_use":
		s.stopReason = stream.StopReasonToolUse
	default:
		s.stopReason = stream.StopReasonStop
	}
}
