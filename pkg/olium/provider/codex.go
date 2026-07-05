package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/olium/auth"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// debugToolArgErr surfaces a tool-call argument unmarshal failure when provider
// tracing is on (DebugEnabled / VIGOLIUM_OLIUM_DEBUG / --debug). A failure here
// is consequential: the tool is invoked with empty arguments because the
// streamed JSON could not be assembled. It is kept non-fatal (the call still
// proceeds) but observable. Shared by the codex, anthropic, and openai stream
// parsers in this package.
func debugToolArgErr(provider string, err error) {
	if err != nil && DebugEnabled() {
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
// with response.* events matching the Responses API. The Responses wire
// format (request input, tools, and the SSE state machine) is shared with the
// OpenAIResponses provider via responses_stream.go — Codex layers on the
// ChatGPT-specific base URL, auth headers, and 401 token-refresh retry.
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
		return nil, responsesErrorFrom("codex", resp.StatusCode, raw)
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

// buildCodexRequest assembles the ChatGPT-backend flavor of the Responses
// request: store disabled, encrypted reasoning carry-over, the session id as
// the prompt cache key, and a reasoning summary so the TUI can render
// "thinking". The input/tools shapes come from the shared Responses builders.
func buildCodexRequest(req Request, sessionID string) responsesRequest {
	body := responsesRequest{
		Model:             req.Model,
		Store:             false,
		Stream:            true,
		Instructions:      req.System,
		Input:             buildResponsesInput(req.Messages),
		Tools:             buildResponsesTools(req.Tools),
		Text:              map[string]string{"verbosity": "medium"},
		Include:           []string{"reasoning.encrypted_content"},
		PromptCacheKey:    sessionID,
		ToolChoice:        "auto",
		ParallelToolCalls: true,
	}
	// Always request reasoning summaries so the TUI can show "thinking"
	// before each answer. Default effort is "medium" unless the caller
	// overrides via Request.ReasoningEff.
	effort := req.ReasoningEff
	if effort == "" {
		effort = "medium"
	}
	body.Reasoning = &responsesReasoning{
		Effort:  clampReasoning(req.Model, effort),
		Summary: "auto",
	}
	return body
}

// consumeSSE drains the ChatGPT-backend Responses stream. The parsing is the
// shared Responses SSE machine, labeled "codex" for debug traces and the
// content-less error fallback ("codex stream error", which the engine's
// transient-error classifier keys on).
func (c *Codex) consumeSSE(ctx context.Context, body io.ReadCloser, out chan<- stream.Event) {
	consumeResponsesSSE(ctx, body, out, "codex")
}
