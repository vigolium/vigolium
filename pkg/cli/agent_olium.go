package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/olium"
)

var (
	oliumModel         string
	oliumOAuthCredPath string
	oliumOAuthToken    string
	oliumSystem        string
	oliumPrompt        string
	oliumStdin         bool
	oliumVerbose       bool
	oliumProvider      string
	oliumLLMAPIKey     string
	oliumClaudeBin     string
	oliumGCPProject    string
	oliumGCPLocation   string
	oliumBaseURL       string
)

var agentOliumCmd = &cobra.Command{
	Use:   "olium [prompt...]",
	Short: "Launch vigolium — interactive TUI agent (olium engine)",
	Long: `Launch the vigolium agent (powered by the olium engine).

Providers (vendor-first; the prefix tells you which credentials to provide):
  openai-codex-oauth — uses --oauth-cred / agent.olium.oauth_cred_path (~/.codex/auth.json from "codex login")
  openai-api-key     — uses --llm-api-key / agent.olium.llm_api_key (or $OPENAI_API_KEY)
  anthropic-api-key  — uses --llm-api-key / agent.olium.llm_api_key (or $ANTHROPIC_API_KEY)
  anthropic-oauth    — uses --oauth-token / agent.olium.oauth_token (or $ANTHROPIC_API_KEY); for tokens minted by "claude setup-token"
  anthropic-cli      — shells out to the local "claude" binary (no key needed here)
  anthropic-vertex   — uses --oauth-cred (GCP service-account JSON, or $GOOGLE_APPLICATION_CREDENTIALS) + --gcp-project / --gcp-location;
                       routes claude-* model ids to publishers/anthropic on Vertex AI. Default model: claude-opus-4-6.
  google-vertex      — same GCP creds as anthropic-vertex; routes gemini-* model ids to publishers/google on Vertex AI.
                       Default model: gemini-2.5-pro.
  openai-compatible  — any OpenAI Chat Completions-compatible endpoint (Ollama, OpenRouter, LM Studio, vLLM,
                       Together, Groq, LocalAI, custom proxies). Uses --base-url / agent.olium.custom_provider.base_url,
                       --llm-api-key / custom_provider.api_key (optional), and --model / custom_provider.model_id.`,
	DisableFlagsInUseLine: true,
	RunE:                  runAgentOlium,
}

// oliumCmd mirrors agentOliumCmd at the top level so users can invoke the agent
// with `vigolium olium` (or the shorter `vigolium ol` alias) without having to
// type the `agent` parent.
var oliumCmd = &cobra.Command{
	Use:                   "olium [prompt...]",
	Aliases:               []string{"ol"},
	Short:                 "Launch vigolium — interactive TUI agent (alias for `vigolium agent olium`)",
	Long:                  agentOliumCmd.Long,
	DisableFlagsInUseLine: true,
	RunE:                  runAgentOlium,
}

func runAgentOlium(cmd *cobra.Command, args []string) error {
	// Load settings so yaml-level olium defaults (agent.olium.*) can back
	// the CLI flags. A load failure is non-fatal: flags alone still work,
	// matching the pre-config behavior.
	var oliumCfg config.OliumConfig
	if settings, err := config.LoadSettings(globalConfig); err == nil {
		oliumCfg = settings.Agent.Olium
	}

	opts := olium.Options{
		Provider:            firstNonEmptyString(oliumProvider, oliumCfg.Provider),
		OAuthCredPath:       firstNonEmptyString(oliumOAuthCredPath, oliumCfg.OAuthCredPath),
		OAuthToken:          firstNonEmptyString(oliumOAuthToken, oliumCfg.OAuthToken),
		LLMAPIKey:           firstNonEmptyString(oliumLLMAPIKey, oliumCfg.LLMAPIKey),
		GoogleCloudProject:  firstNonEmptyString(oliumGCPProject, oliumCfg.GoogleCloudProject),
		GoogleCloudLocation: firstNonEmptyString(oliumGCPLocation, oliumCfg.GoogleCloudLocation),
		ClaudeBinary:        oliumClaudeBin,
		Model:               firstNonEmptyString(oliumModel, oliumCfg.Model),
		SystemPrompt:        firstNonEmptyString(oliumSystem, oliumCfg.SystemPrompt),
		ReasoningEffort:     oliumCfg.ReasoningEffort,
		Version:             getVersion(),
		// openai-compatible — --base-url / --llm-api-key / --model fall back
		// to custom_provider.* in YAML. ExtraHeaders has no CLI flag (map is
		// awkward to flag-plumb; set it in YAML).
		CustomBaseURL:      firstNonEmptyString(oliumBaseURL, oliumCfg.CustomProvider.BaseURL),
		CustomModelID:      oliumCfg.CustomProvider.ModelID,
		CustomAPIKey:       firstNonEmptyString(oliumLLMAPIKey, oliumCfg.CustomProvider.APIKey, oliumCfg.LLMAPIKey),
		CustomExtraHeaders: oliumCfg.CustomProvider.ExtraHeaders,
	}

	fmt.Fprint(os.Stderr, GetOliumBanner())

	// -p / --prompt runs one prompt non-interactively and streams to stdout.
	// Why: a single-shot prompt has no use for the TUI, so -p doubles as the
	// headless trigger. `-p -` is the conventional "read from stdin" sentinel.
	// Positional args (with no -p) still seed an interactive session.
	if prompt := strings.TrimSpace(oliumPrompt); prompt != "" {
		if prompt == "-" {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("read stdin: %w", err)
			}
			prompt = strings.TrimSpace(string(raw))
			if prompt == "" {
				return fmt.Errorf("olium: -p - requires a non-empty prompt on stdin")
			}
		}
		return olium.RunHeadless(context.Background(), olium.HeadlessOptions{
			Options: opts,
			Prompt:  prompt,
			Verbose: oliumVerbose,
		})
	}

	// Collect an initial prompt for the TUI from: positional args > stdin.
	// Stdin is auto-detected when piped (not a tty).
	initial := strings.TrimSpace(strings.Join(args, " "))
	if initial == "" && (oliumStdin || isStdinPiped()) {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		initial = strings.TrimSpace(string(raw))
	}

	// Interactive TUI — may be seeded with an initial prompt that
	// gets auto-submitted on startup.
	opts.InitialPrompt = initial
	return olium.RunTUI(opts)
}

// registerOliumFlags wires the shared olium flag set onto a cobra command. The
// underlying variables are package-level, so both agentOliumCmd and oliumCmd
// read from the same state regardless of which entry point is invoked.
func registerOliumFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&oliumProvider, "provider", "", "Provider: openai-codex-oauth | openai-api-key | anthropic-api-key | anthropic-oauth | anthropic-cli | anthropic-vertex | google-vertex | openai-compatible (default: openai-codex-oauth)")
	f.StringVar(&oliumModel, "model", "", "Model id (provider-specific default if empty)")
	f.StringVar(&oliumOAuthCredPath, "oauth-cred", "", "Path to OAuth/SA credential file (openai-codex-oauth: ~/.codex/auth.json; anthropic-vertex/google-vertex: SA JSON or $GOOGLE_APPLICATION_CREDENTIALS)")
	f.StringVar(&oliumOAuthToken, "oauth-token", "", "Anthropic OAuth bearer token (anthropic-oauth; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY)")
	f.StringVar(&oliumLLMAPIKey, "llm-api-key", "", "API key for key-based providers (anthropic-api-key, openai-api-key); else uses ANTHROPIC_API_KEY / OPENAI_API_KEY env")
	f.StringVar(&oliumClaudeBin, "claude-bin", "", "Path to the `claude` binary (anthropic-cli provider)")
	f.StringVar(&oliumGCPProject, "gcp-project", "", "GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id)")
	f.StringVar(&oliumGCPLocation, "gcp-location", "", "GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1)")
	f.StringVar(&oliumBaseURL, "base-url", "", "Endpoint URL for openai-compatible provider (e.g. http://localhost:11434/v1 for Ollama); falls back to agent.olium.custom_provider.base_url")
	f.StringVar(&oliumSystem, "system", "", "Override system prompt")
	f.StringVarP(&oliumPrompt, "prompt", "p", "", "Run one prompt non-interactively and stream to stdout (skips the TUI). Pass '-' to read the prompt from stdin")
	f.BoolVar(&oliumStdin, "stdin", false, "Force reading prompt from stdin")
	f.BoolVarP(&oliumVerbose, "verbose", "v", false, "In headless mode, surface a per-tool head/tail preview of each tool result alongside the standard one-liner")
}

func init() {
	agentCmd.AddCommand(agentOliumCmd)
	rootCmd.AddCommand(oliumCmd)

	registerOliumFlags(agentOliumCmd)
	registerOliumFlags(oliumCmd)
}

// isStdinPiped reports whether stdin has data piped in (not a tty).
// Used to auto-detect `echo ... | vigolium agent olium` without requiring
// an explicit --stdin flag.
func isStdinPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}
