package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
)

// errNoByokOverride signals that the request carried no BYOK fields and
// the caller should reuse the server-wide engine.
var errNoByokOverride = errors.New("no byok override")

// oliumConfigForRequest derives a per-request OliumConfig by overlaying
// the request's BYOK fields onto the server-wide agent.olium defaults.
//
// Provider auto-detection (the operator does NOT have to pass `provider`):
//   - oauth_cred_file / oauth_cred_json → openai-codex-oauth (Codex
//     credentials are the only shape that lands in OAuthCredPath).
//   - oauth_token                       → anthropic-oauth (Claude Code
//     OAuth bearer).
//   - api_key starting with sk-ant-     → anthropic-api-key.
//   - api_key starting with anything    → openai-api-key (covers
//     OpenRouter / proxy keys; validateKeyShape downstream rejects the
//     obvious cross-wires).
//
// Returns errNoByokOverride when the request carries no BYOK, so callers
// can fall back to the server-wide cached engine without an allocation.
//
// The returned cleanup tears down any per-request staged cred file
// produced from oauth_cred_json. Always non-nil; safe to defer.
func (h *Handlers) oliumConfigForRequest(byok AgentBYOK) (config.OliumConfig, func(), error) {
	if byok.IsZero() {
		return config.OliumConfig{}, func() {}, errNoByokOverride
	}

	out := h.settings.Agent.Olium

	credFile := strings.TrimSpace(byok.OAuthCredFile)
	credJSON := strings.TrimSpace(byok.OAuthCredJSON)
	apiKey := strings.TrimSpace(byok.APIKey)
	oauthToken := strings.TrimSpace(byok.OAuthToken)

	// Mutual exclusion mirrors agent.ValidateAuthOverride's rule for the
	// subprocess path. Single source of truth would be nice — see
	// resolveBYOKForAudit — but the in-process path needs to map the
	// fields into provider/key fields, which the AuthOverride validator
	// doesn't expose, so we re-validate here.
	set := 0
	for _, v := range []string{apiKey, oauthToken, credFile, credJSON} {
		if v != "" {
			set++
		}
	}
	if set > 1 {
		return config.OliumConfig{}, func() {},
			fmt.Errorf("auth override: at most one of api_key / oauth_token / oauth_cred_file / oauth_cred_json may be set")
	}

	cleanup := func() {}

	switch {
	case credJSON != "":
		path, c, err := stageInlineCredJSON(h.settings.Agent.EffectiveSessionsDir(), credJSON)
		if err != nil {
			return config.OliumConfig{}, cleanup, err
		}
		cleanup = c
		out.Provider = "openai-codex-oauth"
		out.OAuthCredPath = path
		// Clear the conflicting fields so a server-wide LLMAPIKey doesn't
		// confuse the codex provider construction.
		out.LLMAPIKey = ""
		out.OAuthToken = ""
	case credFile != "":
		out.Provider = "openai-codex-oauth"
		out.OAuthCredPath = credFile
		out.LLMAPIKey = ""
		out.OAuthToken = ""
	case oauthToken != "":
		out.Provider = "anthropic-oauth"
		out.OAuthToken = oauthToken
		out.LLMAPIKey = ""
	case apiKey != "":
		out.LLMAPIKey = apiKey
		if strings.HasPrefix(apiKey, "sk-ant-") {
			out.Provider = "anthropic-api-key"
		} else {
			out.Provider = "openai-api-key"
		}
		out.OAuthToken = ""
		out.OAuthCredPath = ""
	}

	return out, cleanup, nil
}

// engineForRequest constructs a per-request agent.Engine when the request
// carries BYOK fields, or returns the server-wide cached engine otherwise.
// The cleanup tears down any per-request staged cred file; safe to defer
// unconditionally.
func (h *Handlers) engineForRequest(byok AgentBYOK) (*agent.Engine, func(), error) {
	overlay, cleanup, err := h.oliumConfigForRequest(byok)
	if errors.Is(err, errNoByokOverride) {
		return h.agentEngine, func() {}, nil
	}
	if err != nil {
		return nil, cleanup, err
	}
	// Shallow-copy settings then overlay olium so we don't mutate the
	// shared server config. config.Settings is a value type with embedded
	// structs, so the copy isolates per-request mutations.
	scoped := *h.settings
	scoped.Agent = h.settings.Agent
	scoped.Agent.Olium = overlay
	return agent.NewEngine(&scoped, h.repo), cleanup, nil
}
