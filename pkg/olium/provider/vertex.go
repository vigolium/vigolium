package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/auth"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// vertexDebug dumps Vertex request bodies + raw SSE event types to stderr
// when VIGOLIUM_OLIUM_DEBUG=1. Useful for tracking down 4xx schema errors
// (Gemini's functionDeclarations validator is the strictest of the three).
var vertexDebug = os.Getenv("VIGOLIUM_OLIUM_DEBUG") != ""

const (
	// vertexAnthropicVersion is the magic body field every
	// publishers/anthropic request must carry. Distinct from the
	// `anthropic-version` HTTP header used by api.anthropic.com.
	vertexAnthropicVersion = "vertex-2023-10-16"
	// vertexHostTpl is the regional Vertex AI host. Filled with location.
	vertexHostTpl = "%s-aiplatform.googleapis.com"
)

// vertexTransport is the shared transport for both Vertex provider variants
// (anthropic-vertex and google-vertex). One service-account credential
// authorizes both paths; the only thing the wrapper providers add is model-
// prefix validation and the user-facing Name().
type vertexTransport struct {
	auth     *auth.VertexAuth
	project  string
	location string
	client   *http.Client
}

// newVertexTransport constructs the shared Vertex transport. Project/location
// must be resolved by the caller (env > YAML > SA-file fallback for project,
// env > YAML > "us-central1" default for location).
func newVertexTransport(a *auth.VertexAuth, project, location string) *vertexTransport {
	return &vertexTransport{
		auth:     a,
		project:  project,
		location: location,
		client:   &http.Client{},
	}
}

// requireProjectAndLocation returns an error if either is missing. Callers
// are the wrapper providers, which prefix their own provider name.
func (v *vertexTransport) requireProjectAndLocation(providerName string) error {
	if v.project == "" {
		return fmt.Errorf("%s: project not set (set agent.olium.google_cloud_project, $GOOGLE_CLOUD_PROJECT, --gcp-project, or include project_id in the SA JSON)", providerName)
	}
	if v.location == "" {
		return fmt.Errorf("%s: location not set (set agent.olium.google_cloud_location, $GOOGLE_CLOUD_LOCATION, or --gcp-location; default us-central1)", providerName)
	}
	return nil
}

// requireModelPrefix asserts the requested model id starts with prefix.
// otherProviderName is mentioned in the error so users hopping vendors get a
// pointer to the right provider key (e.g. anthropic-vertex → google-vertex).
func (v *vertexTransport) requireModelPrefix(providerName, prefix, model, otherProviderName string) error {
	if strings.HasPrefix(model, prefix) {
		return nil
	}
	return fmt.Errorf("%s: unsupported model %q (expected %s*; use %s for the other vendor)", providerName, model, prefix, otherProviderName)
}

// --- Anthropic-on-Vertex ---

// vertexAnthRequest mirrors anthRequest but drops the `model` field (it's in
// the URL on Vertex) and adds the required `anthropic_version` body field.
type vertexAnthRequest struct {
	AnthropicVersion string        `json:"anthropic_version"`
	System           any           `json:"system,omitempty"`
	MaxTokens        int           `json:"max_tokens"`
	Messages         []anthMessage `json:"messages"`
	Tools            []anthTool    `json:"tools,omitempty"`
	Stream           bool          `json:"stream"`
}

func (v *vertexTransport) streamAnthropic(ctx context.Context, providerName string, req Request) (<-chan stream.Event, error) {
	body := vertexAnthRequest{
		AnthropicVersion: vertexAnthropicVersion,
		MaxTokens:        8192,
		Messages:         buildAnthropicMessages(req.Messages),
		Stream:           true,
	}
	// Reuse the system/tools/cache-control logic by piping through a
	// synthetic anthRequest: the helper only mutates System and Tools.
	tmp := anthRequest{}
	applyAnthropicSystemAndTools(&tmp, req)
	body.System = tmp.System
	body.Tools = tmp.Tools

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if vertexDebug {
		debugFprintf(os.Stderr, "[vertex-anthropic] %s", string(payload))
	}

	url := fmt.Sprintf(
		"https://"+vertexHostTpl+"/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:streamRawPredict",
		v.location, v.project, v.location, req.Model,
	)

	token, err := v.auth.AccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", providerName, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := v.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", providerName, err)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s %d: %s", providerName, resp.StatusCode, string(raw))
	}

	out := make(chan stream.Event, 32)
	go consumeAnthropicSSE(ctx, resp.Body, out)
	return out, nil
}

// --- Gemini-on-Vertex ---

// gemPart models a single content piece in a Gemini message. Exactly one of
// the optional fields should be set per part.
type gemPart struct {
	Text             string               `json:"text,omitempty"`
	FunctionCall     *gemFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *gemFunctionResponse `json:"functionResponse,omitempty"`
}

// gemFunctionCall mirrors Gemini's tool invocation. The Vertex v1 API does
// not accept an `id` field here — the function `name` is the sole call
// identifier in the wire format. We track our own internal IDs in the SSE
// consumer to satisfy the unified engine event protocol.
type gemFunctionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args,omitempty"`
}

type gemFunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type gemContent struct {
	Role  string    `json:"role,omitempty"` // "user" | "model"
	Parts []gemPart `json:"parts"`
}

type gemFunctionDecl struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type gemTool struct {
	FunctionDeclarations []gemFunctionDecl `json:"functionDeclarations,omitempty"`
}

type gemRequest struct {
	Contents          []gemContent `json:"contents"`
	SystemInstruction *gemContent  `json:"systemInstruction,omitempty"`
	Tools             []gemTool    `json:"tools,omitempty"`
}

func (v *vertexTransport) streamGemini(ctx context.Context, providerName string, req Request) (<-chan stream.Event, error) {
	body := buildGeminiRequest(req)
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if vertexDebug {
		debugFprintf(os.Stderr, "[vertex-gemini] %s", string(payload))
	}

	url := fmt.Sprintf(
		"https://"+vertexHostTpl+"/v1/projects/%s/locations/%s/publishers/google/models/%s:streamGenerateContent?alt=sse",
		v.location, v.project, v.location, req.Model,
	)

	token, err := v.auth.AccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", providerName, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := v.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", providerName, err)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%s %d: %s", providerName, resp.StatusCode, string(raw))
	}

	out := make(chan stream.Event, 32)
	go consumeGeminiSSE(ctx, resp.Body, out)
	return out, nil
}

// buildGeminiRequest translates the provider-neutral Request into Gemini's
// native shape. Tool calls and tool results are flattened into part-level
// functionCall/functionResponse blocks; system prompt becomes
// systemInstruction.
func buildGeminiRequest(req Request) gemRequest {
	// Build a call-id → name map by walking assistant messages so tool
	// results (which only carry the ID) can be re-tagged with the
	// original function name on the way back to Gemini.
	idToName := map[string]string{}
	for _, m := range req.Messages {
		if m.Role != RoleAssistant {
			continue
		}
		for _, tc := range m.ToolCalls {
			if tc.ID != "" && tc.Name != "" {
				idToName[tc.ID] = tc.Name
			}
		}
	}

	contents := make([]gemContent, 0, len(req.Messages))
	for _, m := range req.Messages {
		switch m.Role {
		case RoleUser:
			contents = append(contents, gemContent{
				Role:  "user",
				Parts: []gemPart{{Text: m.Text}},
			})
		case RoleAssistant:
			parts := make([]gemPart, 0, 1+len(m.ToolCalls))
			if strings.TrimSpace(m.Text) != "" {
				parts = append(parts, gemPart{Text: m.Text})
			}
			for _, tc := range m.ToolCalls {
				args := tc.Args
				if args == nil {
					args = map[string]any{}
				}
				parts = append(parts, gemPart{
					FunctionCall: &gemFunctionCall{
						Name: tc.Name,
						Args: args,
					},
				})
			}
			if len(parts) == 0 {
				continue
			}
			contents = append(contents, gemContent{Role: "model", Parts: parts})
		case RoleTool:
			name := idToName[m.ToolCallID]
			if name == "" {
				name = "tool" // last-resort fallback; Gemini requires a name
			}
			// Gemini wants `response` as an object. We try to parse the
			// tool output as JSON first (so structured results travel
			// through cleanly); on failure we wrap as {"output": "..."}.
			var respObj map[string]any
			if err := json.Unmarshal([]byte(m.Content), &respObj); err != nil || respObj == nil {
				respObj = map[string]any{"output": m.Content}
			}
			if m.IsError {
				respObj["error"] = true
			}
			contents = append(contents, gemContent{
				Role: "user", // tool replies are surfaced as user-role per Gemini convention
				Parts: []gemPart{{
					FunctionResponse: &gemFunctionResponse{
						Name:     name,
						Response: respObj,
					},
				}},
			})
		}
	}

	body := gemRequest{Contents: contents}
	if strings.TrimSpace(req.System) != "" {
		body.SystemInstruction = &gemContent{
			Parts: []gemPart{{Text: req.System}},
		}
	}
	if len(req.Tools) > 0 {
		decls := make([]gemFunctionDecl, 0, len(req.Tools))
		for _, t := range req.Tools {
			decls = append(decls, gemFunctionDecl{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  sanitizeGeminiSchema(t.Schema),
			})
		}
		body.Tools = []gemTool{{FunctionDeclarations: decls}}
	}
	return body
}

// sanitizeGeminiSchema rewrites a JSON-Schema-flavored map into the subset
// Gemini's OpenAPI-3.0 schema validator accepts:
//   - lowercase `type` strings get uppercased to STRING/OBJECT/etc.
//   - keys Gemini rejects (`additionalProperties`, `$schema`, `$id`, `$ref`,
//     `definitions`) get stripped.
//   - recursion into properties/items/anyOf/oneOf/allOf preserves nested
//     schemas.
//
// The original map is not mutated; returns nil when input is nil.
func sanitizeGeminiSchema(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch k {
		case "additionalProperties", "$schema", "$id", "$ref", "definitions":
			continue
		case "type":
			if s, ok := v.(string); ok {
				out[k] = strings.ToUpper(s)
			} else {
				out[k] = v
			}
		case "properties":
			if m, ok := v.(map[string]any); ok {
				clean := make(map[string]any, len(m))
				for pk, pv := range m {
					if pm, ok := pv.(map[string]any); ok {
						clean[pk] = sanitizeGeminiSchema(pm)
					} else {
						clean[pk] = pv
					}
				}
				out[k] = clean
			} else {
				out[k] = v
			}
		case "items":
			if m, ok := v.(map[string]any); ok {
				out[k] = sanitizeGeminiSchema(m)
			} else {
				out[k] = v
			}
		case "anyOf", "oneOf", "allOf":
			if arr, ok := v.([]any); ok {
				cleaned := make([]any, 0, len(arr))
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						cleaned = append(cleaned, sanitizeGeminiSchema(m))
					} else {
						cleaned = append(cleaned, item)
					}
				}
				out[k] = cleaned
			} else {
				out[k] = v
			}
		default:
			out[k] = v
		}
	}
	return out
}

// consumeGeminiSSE drains Vertex's `:streamGenerateContent?alt=sse` stream.
// Each `data:` payload is a complete chunk with `candidates[].content.parts[]`;
// parts can be text deltas, complete functionCalls, or completion-signaling
// chunks with finishReason set. Usage metadata arrives in the final chunk.
func consumeGeminiSSE(ctx context.Context, body io.ReadCloser, out chan<- stream.Event) {
	defer func() { _ = body.Close() }()
	defer close(out)

	reader := stream.NewSSEReader(body)
	state := &geminiState{}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		evt, err := reader.Next()
		if err == io.EOF {
			state.flushFinal(out)
			return
		}
		if err != nil {
			out <- stream.Event{Type: stream.EventError, Err: err.Error()}
			return
		}
		if strings.TrimSpace(evt.Data) == "" {
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(evt.Data), &parsed); err != nil {
			continue
		}
		if vertexDebug {
			debugFprintf(os.Stderr, "[vertex-gemini-sse] %s", evt.Data)
		}
		state.handle(parsed, out)
	}
}

type geminiState struct {
	textOpen   bool
	stopReason stream.StopReason
	usage      stream.Usage
	finalSent  bool
}

func (s *geminiState) handle(ev map[string]any, out chan<- stream.Event) {
	if u, ok := ev["usageMetadata"].(map[string]any); ok {
		s.usage.Input = intField(u, "promptTokenCount")
		s.usage.Output = intField(u, "candidatesTokenCount")
		s.usage.CacheRead = intField(u, "cachedContentTokenCount")
		// totalTokenCount is the authoritative sum; fall back to input+output.
		if total := intField(u, "totalTokenCount"); total > 0 {
			s.usage.TotalTokens = total
		}
	}

	candidates, _ := ev["candidates"].([]any)
	for _, c := range candidates {
		cand, _ := c.(map[string]any)
		if cand == nil {
			continue
		}
		if content, ok := cand["content"].(map[string]any); ok {
			parts, _ := content["parts"].([]any)
			for _, p := range parts {
				pm, _ := p.(map[string]any)
				if pm == nil {
					continue
				}
				s.applyPart(pm, out)
			}
		}
		if fr, _ := cand["finishReason"].(string); fr != "" {
			s.setStop(fr)
		}
	}
}

func (s *geminiState) applyPart(p map[string]any, out chan<- stream.Event) {
	if text, ok := p["text"].(string); ok && text != "" {
		if !s.textOpen {
			out <- stream.Event{Type: stream.EventTextStart}
			s.textOpen = true
		}
		out <- stream.Event{Type: stream.EventTextDelta, Delta: text}
		return
	}
	if fc, ok := p["functionCall"].(map[string]any); ok {
		// Gemini delivers a complete functionCall in one chunk; we synthesize
		// matching start/delta/end events so consumers see the same lifecycle
		// as on Anthropic/OpenAI.
		id, _ := fc["id"].(string)
		name, _ := fc["name"].(string)
		args, _ := fc["args"].(map[string]any)
		if id == "" {
			// Some Gemini revisions omit `id`; synthesize a stable one from
			// the name so our engine can still pair the response back.
			id = "fn-" + name
		}
		out <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: id, Name: name}}
		argsJSON, _ := json.Marshal(args)
		if len(argsJSON) > 0 && string(argsJSON) != "null" {
			out <- stream.Event{Type: stream.EventToolCallDelta, Delta: string(argsJSON)}
		}
		out <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{
			ID:        id,
			Name:      name,
			Arguments: args,
		}}
	}
}

func (s *geminiState) setStop(reason string) {
	switch reason {
	case "STOP", "FINISH_REASON_STOP":
		s.stopReason = stream.StopReasonStop
	case "MAX_TOKENS":
		s.stopReason = stream.StopReasonLength
	case "TOOL_USE", "FUNCTION_CALL":
		s.stopReason = stream.StopReasonToolUse
	default:
		// SAFETY / RECITATION / BLOCKLIST etc. — surface as generic stop
		// rather than an error so the engine can still finalize the turn.
		s.stopReason = stream.StopReasonStop
	}
}

func (s *geminiState) flushFinal(out chan<- stream.Event) {
	if s.finalSent {
		return
	}
	s.finalSent = true
	if s.textOpen {
		out <- stream.Event{Type: stream.EventTextEnd}
		s.textOpen = false
	}
	usage := s.usage
	if usage.TotalTokens == 0 {
		usage.TotalTokens = usage.Input + usage.Output
	}
	out <- stream.Event{Type: stream.EventDone, StopReason: s.stopReason, Usage: &usage}
}
