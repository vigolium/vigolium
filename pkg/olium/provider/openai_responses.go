package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

const openAIResponsesURL = "https://api.openai.com/v1/responses"

// OpenAIResponses is the public OpenAI Responses API provider
// (POST https://api.openai.com/v1/responses). It speaks the same Responses
// wire format as Codex — shared via responses_stream.go — but authenticates
// with a standard OpenAI API key (Authorization: Bearer) instead of a ChatGPT
// subscription OAuth token, and targets api.openai.com rather than the ChatGPT
// backend. Point baseURL at an Azure OpenAI deployment or a compatible proxy
// to reuse the Responses wire format elsewhere.
type OpenAIResponses struct {
	apiKey  secret
	baseURL string // full /responses URL
	client  *http.Client
}

// NewOpenAIResponses constructs the canonical provider pointed at
// api.openai.com/v1/responses. The key is wrapped in a formatter-safe secret
// so a stray `%v` on the provider can't leak it.
func NewOpenAIResponses(apiKey string) *OpenAIResponses {
	return &OpenAIResponses{
		apiKey:  secret(apiKey),
		baseURL: openAIResponsesURL,
		client:  newHTTPClient(),
	}
}

func (o *OpenAIResponses) Name() string { return "openai-responses" }

// CloseIdleConnections drops idle HTTP/2 conns on this provider's transport.
// See provider.ConnectionResetter.
func (o *OpenAIResponses) CloseIdleConnections() {
	o.client.CloseIdleConnections()
}

func (o *OpenAIResponses) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	body := buildOpenAIResponsesRequest(req)
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	if !o.apiKey.IsZero() {
		httpReq.Header.Set("Authorization", "Bearer "+o.apiKey.Reveal())
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai-responses request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		// 401/403 is the most common operator issue — a stale or wrong key, or
		// a key on an org without Responses API access. Surface a hint so it
		// doesn't read as a transient network blip and trigger a retry loop.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			hint := " — OpenAI API key is invalid, expired, or the org lacks Responses API access"
			return nil, fmt.Errorf("openai-responses %d: %s%s", resp.StatusCode, strings.TrimSpace(string(raw)), hint)
		}
		return nil, responsesErrorFrom("openai-responses", resp.StatusCode, raw)
	}

	out := make(chan stream.Event, 32)
	go consumeResponsesSSE(ctx, resp.Body, out, "openai-responses")
	return out, nil
}

// buildOpenAIResponsesRequest assembles a standard public-API Responses
// request. Unlike the Codex flavor it gates the reasoning and verbosity
// controls on the model family (sending them to a gpt-4o-class model is a 400)
// and only sets a prompt cache key when the engine threads a stable session
// id, so OpenAI's automatic prefix caching isn't defeated by a per-turn key.
func buildOpenAIResponsesRequest(req Request) responsesRequest {
	body := responsesRequest{
		Model:             req.Model,
		Store:             false,
		Stream:            true,
		Instructions:      req.System,
		Input:             buildResponsesInput(req.Messages),
		Tools:             buildResponsesTools(req.Tools),
		ToolChoice:        "auto",
		ParallelToolCalls: true,
	}
	if req.SessionID != "" {
		body.PromptCacheKey = req.SessionID
	}
	if isResponsesReasoningModel(req.Model) {
		effort := req.ReasoningEff
		if effort == "" {
			effort = "medium"
		}
		body.Reasoning = &responsesReasoning{
			Effort:  clampReasoning(req.Model, effort),
			Summary: "auto",
		}
		// store:false means the server retains nothing between turns; ask for
		// the encrypted reasoning blob so multi-turn tool loops keep context.
		body.Include = []string{"reasoning.encrypted_content"}
	}
	if supportsResponsesVerbosity(req.Model) {
		body.Text = map[string]string{"verbosity": "medium"}
	}
	return body
}

// responsesReasoningPrefixes are the model-family prefixes that accept the
// `reasoning` request param: the gpt-5 line and the o-series.
var responsesReasoningPrefixes = []string{"gpt-5", "o1", "o3", "o4", "o5"}

// isResponsesReasoningModel reports whether a model accepts the `reasoning`
// request param. The reasoning families are the gpt-5 line and the o-series
// (o1/o3/o4/o5); gpt-4o and older reject the param outright.
func isResponsesReasoningModel(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	for _, p := range responsesReasoningPrefixes {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

// supportsResponsesVerbosity reports whether a model accepts the text
// verbosity control — a gpt-5-family feature.
func supportsResponsesVerbosity(model string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), "gpt-5")
}
