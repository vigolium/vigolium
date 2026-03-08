package config

import (
	"fmt"
	"time"
)

// SourceAwareConfig holds configuration for source code awareness features.
type SourceAwareConfig struct {
	StoragePath           string                      `yaml:"storage_path"`  // base directory for cloned repos
	CloneDepth            int                         `yaml:"clone_depth"`   // git clone --depth value
	ThirdPartyIntegration ThirdPartyIntegrationConfig `yaml:"third_party_integration"`
	AstGrep               AstGrepConfig               `yaml:"ast_grep"`
	AgentSAST             AgentSASTConfig             `yaml:"agent_sast"`
}

// AgentSASTConfig controls AI agent-powered SAST analysis that runs after
// ast-grep and third-party tools complete.
type AgentSASTConfig struct {
	Enabled         bool     `yaml:"enabled"`          // default: false
	PromptTemplates []string `yaml:"prompt_templates"` // template IDs to run (default: ["security-code-review"])
	CustomPrompts   []string `yaml:"custom_prompts"`   // inline prompt strings to run after templates
	Agent           string   `yaml:"agent"`            // agent backend override (empty = use default_agent)
	Timeout         string   `yaml:"timeout"`          // per-template timeout (default: "15m")
}

// TimeoutDuration returns the parsed timeout, defaulting to 15 minutes.
func (c *AgentSASTConfig) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 15 * time.Minute
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 15 * time.Minute
	}
	return d
}

// EffectiveTemplates returns the prompt templates to run, defaulting to ["security-code-review"].
func (c *AgentSASTConfig) EffectiveTemplates() []string {
	if len(c.PromptTemplates) == 0 {
		return []string{"security-code-review"}
	}
	return c.PromptTemplates
}

// AstGrepConfig controls ast-grep source code analysis for route/parameter extraction.
type AstGrepConfig struct {
	Enabled  bool   `yaml:"enabled"`
	RulesDir string `yaml:"rules_dir"` // default "~/.vigolium/sast-rules/astgrep/"
	Timeout  string `yaml:"timeout"`   // default "5m"
}

// Validate checks that AstGrepConfig fields are valid.
func (c *AstGrepConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Timeout != "" {
		if _, err := time.ParseDuration(c.Timeout); err != nil {
			return fmt.Errorf("invalid ast_grep timeout %q: %w", c.Timeout, err)
		}
	}
	return nil
}

// TimeoutDuration returns the parsed timeout duration, defaulting to 5 minutes.
func (c *AstGrepConfig) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// ThirdPartyIntegrationConfig controls external security tool integration for source repos.
type ThirdPartyIntegrationConfig struct {
	Enabled bool                  `yaml:"enabled"`
	Tools   map[string]ToolConfig `yaml:"tools"`
	Timeout string                `yaml:"timeout"` // e.g. "10m"
}

// ToolConfig defines an external CLI security tool to run against source repos.
type ToolConfig struct {
	Enabled    bool       `yaml:"enabled"`
	Command    string     `yaml:"command"`              // binary name or path
	Args       []string   `yaml:"args,omitempty"`        // extra args appended before the target path
	OutputFile string     `yaml:"output_file,omitempty"` // placeholder for the output file (e.g. "{{output}}")
	Steps      []ToolStep `yaml:"steps,omitempty"`       // multi-step execution (e.g. CodeQL)
	Language   string     `yaml:"language,omitempty"`    // language hint for tools like CodeQL
}

// ToolStep defines a single step in a multi-step tool execution pipeline.
type ToolStep struct {
	Args       []string `yaml:"args"`
	OutputFile string   `yaml:"output_file,omitempty"` // placeholder for the step's output file
}

// Validate checks that ThirdPartyIntegrationConfig fields are valid.
func (c *ThirdPartyIntegrationConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Timeout != "" {
		if _, err := time.ParseDuration(c.Timeout); err != nil {
			return fmt.Errorf("invalid third_party_integration timeout %q: %w", c.Timeout, err)
		}
	}
	for name, t := range c.Tools {
		if t.Command == "" {
			return fmt.Errorf("third_party_integration.tools[%s].command must not be empty", name)
		}
	}
	return nil
}

// TimeoutDuration returns the parsed timeout duration, defaulting to 10 minutes.
func (c *ThirdPartyIntegrationConfig) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 10 * time.Minute
	}
	return d
}

// DefaultThirdPartyIntegrationConfig returns sensible defaults with semgrep and trivy.
func DefaultThirdPartyIntegrationConfig() *ThirdPartyIntegrationConfig {
	return &ThirdPartyIntegrationConfig{
		Enabled: true,
		Timeout: "10m",
		Tools: map[string]ToolConfig{
			"semgrep": {
				Enabled:    true,
				Command:    "semgrep",
				Args:       []string{"scan", "--sarif", "--quiet", "--sarif-output={{output}}"},
				OutputFile: "{{output}}",
			},
			"trivy": {
				Enabled:    true,
				Command:    "trivy",
				Args:       []string{"fs", "--format", "sarif", "--quiet", "--output={{output}}"},
				OutputFile: "{{output}}",
			},
			"codeql": {
				Enabled:  false,
				Command:  "codeql",
				Language: "auto",
				Steps: []ToolStep{
					{Args: []string{"database", "create", "{{db}}", "--language={{language}}", "--source-root={{repo}}", "--overwrite"}},
					{Args: []string{"pack", "download", "codeql/{{language}}-queries"}},
					{Args: []string{"database", "analyze", "{{db}}", "codeql/{{language}}-queries", "--format=sarif-latest", "--output={{output}}", "--threads=0"}, OutputFile: "{{output}}"},
				},
			},
		},
	}
}

// DefaultSourceAwareConfig returns default source-aware configuration.
func DefaultSourceAwareConfig() *SourceAwareConfig {
	return &SourceAwareConfig{
		StoragePath:           "~/.vigolium/source-aware/",
		CloneDepth:            1,
		ThirdPartyIntegration: *DefaultThirdPartyIntegrationConfig(),
		AstGrep: AstGrepConfig{
			Enabled:  true,
			RulesDir: "~/.vigolium/sast-rules/astgrep/",
			Timeout:  "5m",
		},
	}
}
