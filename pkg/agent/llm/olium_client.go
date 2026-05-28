package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/olium"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
)

// oliumClient adapts the in-process olium engine to the Client interface, so a
// JS extension's vigolium.agent.* calls run through the same provider stack the
// agent modes use. It is the only Client implementation after the standalone
// HTTP backends (anthropic/openai) were retired in favour of olium.
//
// Each Complete is a fresh, single-turn, tool-less engine run: conversation
// history is supplied per-call via CompletionRequest.Messages, so the adapter
// holds no mutable state and is safe to share across concurrent extension runs
// (the resolved provider is a stateless HTTP caller).
type oliumClient struct {
	cfg   *config.OliumConfig
	prov  provider.Provider
	model string
}

// NewOliumClient builds a Client backed by the olium engine resolved from cfg.
// The provider is resolved eagerly so misconfiguration (missing/invalid
// credentials, unknown provider) surfaces at wiring time rather than on the
// first extension call. A nil cfg is rejected.
func NewOliumClient(cfg *config.OliumConfig) (Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("olium config is nil")
	}
	opts, err := oliumOptions(cfg)
	if err != nil {
		return nil, err
	}
	prov, _, model, err := olium.ResolveProvider(opts)
	if err != nil {
		return nil, fmt.Errorf("olium provider: %w", err)
	}
	return &oliumClient{cfg: cfg, prov: prov, model: model}, nil
}

func oliumOptions(cfg *config.OliumConfig) (olium.Options, error) {
	effectiveExtraBody, err := cfg.CustomProvider.EffectiveExtraBody()
	if err != nil {
		return olium.Options{}, fmt.Errorf("olium custom_provider: %w", err)
	}
	return olium.Options{
		Provider:            cfg.Provider,
		OAuthCredPath:       cfg.OAuthCredPath,
		OAuthToken:          cfg.OAuthToken,
		LLMAPIKey:           cfg.LLMAPIKey,
		GoogleCloudProject:  cfg.GoogleCloudProject,
		GoogleCloudLocation: cfg.GoogleCloudLocation,
		Model:               cfg.Model,
		ReasoningEffort:     cfg.ReasoningEffort,
		CustomBaseURL:       cfg.CustomProvider.BaseURL,
		CustomModelID:       cfg.CustomProvider.ModelID,
		CustomAPIKey:        firstNonEmpty(cfg.CustomProvider.APIKey, cfg.LLMAPIKey),
		CustomExtraHeaders:  cfg.CustomProvider.ExtraHeadersMap(),
		CustomExtraBody:     effectiveExtraBody,
	}, nil
}

// Complete runs one tool-less olium turn and returns the model's text. The
// per-call timeout from olium config (call_timeout_sec) bounds a hung stream.
func (c *oliumClient) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if c.cfg != nil {
		if to := c.cfg.EffectiveCallTimeout(); to > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, to)
			defer cancel()
		}
	}

	system, prompt := splitMessages(req)
	if req.JSONSchema != "" {
		system = appendJSONInstruction(system, req.JSONSchema)
	}

	eng := oengine.New(oengine.Config{
		Provider: c.prov,
		Model:    c.model,
		System:   system,
		// No tools registered → the model answers in a single assistant turn;
		// MaxTurns is left at the engine default since the loop terminates as
		// soon as there are no pending tool calls.
	})

	var out strings.Builder
	var tokensIn, tokensOut int
	for ev := range eng.Run(ctx, prompt) {
		switch ev.Type {
		case oengine.EventTextDelta:
			out.WriteString(ev.Delta)
		case oengine.EventTurnDone:
			if ev.Usage != nil {
				tokensIn += ev.Usage.Input
				tokensOut += ev.Usage.Output
			}
		case oengine.EventError:
			return nil, fmt.Errorf("olium completion: %s", ev.Err)
		}
	}

	return &CompletionResponse{
		Content:   out.String(),
		Model:     c.model,
		TokensIn:  tokensIn,
		TokensOut: tokensOut,
	}, nil
}

// splitMessages separates system messages (joined into the engine system
// prompt) from the conversation, which olium consumes as a single user prompt.
// When more than one non-system message is present, turns are labelled so the
// model can follow the exchange; a lone user message is passed through verbatim.
func splitMessages(req CompletionRequest) (system, prompt string) {
	var sys, conv []string
	nonSystem := 0
	for _, m := range req.Messages {
		if !strings.EqualFold(m.Role, "system") {
			nonSystem++
		}
	}
	multi := nonSystem > 1
	for _, m := range req.Messages {
		switch strings.ToLower(m.Role) {
		case "system":
			sys = append(sys, m.Content)
		case "assistant":
			conv = append(conv, label(multi, "Assistant", m.Content))
		default: // "user" and any unknown role
			conv = append(conv, label(multi, "User", m.Content))
		}
	}
	return strings.Join(sys, "\n\n"), strings.Join(conv, "\n\n")
}

func label(multi bool, role, content string) string {
	if !multi {
		return content
	}
	return role + ": " + content
}

// appendJSONInstruction folds a requested JSON schema into the system prompt.
// olium has no provider-native structured-output hook here, so this is a
// best-effort instruction — the same contract the JS API documents.
func appendJSONInstruction(system, schema string) string {
	instr := "Respond ONLY with a single JSON value conforming to this JSON schema. " +
		"Do not wrap it in markdown fences or add any prose:\n" + schema
	if system == "" {
		return instr
	}
	return system + "\n\n" + instr
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
