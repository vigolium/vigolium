package cli

import (
	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
)

// oliumOverrides holds per-command olium provider override flag values.
// Each subcommand instantiates its own struct so flag state doesn't leak
// across commands in tests, and registers the flags on its own flag set.
type oliumOverrides struct {
	Provider    string
	Model       string
	OAuthCred   string
	OAuthToken  string
	LLMAPIKey   string
	GCPProject  string
	GCPLocation string
	BaseURL     string
}

func registerOliumOverrideFlags(cmd *cobra.Command, o *oliumOverrides) {
	f := cmd.Flags()
	f.StringVar(&o.Provider, "provider", "", "Olium provider override: openai-codex-oauth | openai-api-key | anthropic-api-key | anthropic-oauth | anthropic-cli | anthropic-vertex | google-vertex | openai-compatible (falls back to agent.olium.provider)")
	f.StringVar(&o.Model, "model", "", "Olium model id override (falls back to agent.olium.model)")
	f.StringVar(&o.OAuthCred, "oauth-cred", "", "Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS)")
	f.StringVar(&o.OAuthToken, "oauth-token", "", "Olium Anthropic OAuth bearer token (anthropic-oauth; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY)")
	f.StringVar(&o.LLMAPIKey, "llm-api-key", "", "Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var)")
	f.StringVar(&o.GCPProject, "gcp-project", "", "GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id)")
	f.StringVar(&o.GCPLocation, "gcp-location", "", "GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1)")
	f.StringVar(&o.BaseURL, "base-url", "", "Endpoint URL for openai-compatible provider (e.g. http://localhost:11434/v1); falls back to agent.olium.custom_provider.base_url")
}

// applyOliumOverrides mutates settings.Agent.Olium with any non-empty fields
// from o. Engine.Run reads settings.Agent.Olium directly, so mutating it is
// the simplest way to plumb a per-run override through without restructuring
// the engine entry point.
func applyOliumOverrides(settings *config.Settings, o *oliumOverrides) {
	if o.Provider != "" {
		settings.Agent.Olium.Provider = o.Provider
	}
	if o.Model != "" {
		settings.Agent.Olium.Model = o.Model
	}
	if o.OAuthCred != "" {
		settings.Agent.Olium.OAuthCredPath = o.OAuthCred
	}
	if o.OAuthToken != "" {
		settings.Agent.Olium.OAuthToken = o.OAuthToken
	}
	if o.LLMAPIKey != "" {
		settings.Agent.Olium.LLMAPIKey = o.LLMAPIKey
	}
	if o.GCPProject != "" {
		settings.Agent.Olium.GoogleCloudProject = o.GCPProject
	}
	if o.GCPLocation != "" {
		settings.Agent.Olium.GoogleCloudLocation = o.GCPLocation
	}
	if o.BaseURL != "" {
		settings.Agent.Olium.CustomProvider.BaseURL = o.BaseURL
	}
}
