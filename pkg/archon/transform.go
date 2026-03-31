package archon

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// HarnessConfig represents a platform's frontmatter.yaml configuration.
type HarnessConfig struct {
	Format          string                    `yaml:"format"`
	AgentNamePrefix string                    `yaml:"agent_name_prefix,omitempty"`
	Defaults        map[string]any            `yaml:"defaults"`
	Overrides       map[string]map[string]any `yaml:"overrides,omitempty"`
	Exclude         []string                  `yaml:"exclude,omitempty"`
}

// CanonicalAgent holds a parsed canonical agent .md file.
type CanonicalAgent struct {
	Filename    string
	Basename    string // filename without .md
	Description string
	Body        string // everything after the frontmatter
}

// replacements maps old strings to new, applied in order (longest-match-first).
var replacements = []struct{ Old, New string }{
	{"~/.vig-audit-agent/", "~/.config/archon-audit/"},
	{"vig-audit-agent", "archon-audit"},
	{"vig-auditor", "archon-audit"},
	{"vig-run:", "archon:"},
	{"vig-run", "archon"},
	{"vig-audit", "archon-audit"},
}

// RenameStrings applies the global vig→archon string replacements.
func RenameStrings(content string) string {
	for _, r := range replacements {
		content = strings.ReplaceAll(content, r.Old, r.New)
	}
	return content
}

// ParseCanonicalAgent parses a canonical agent .md file with YAML frontmatter.
func ParseCanonicalAgent(filename string, content []byte) (*CanonicalAgent, error) {
	s := string(content)

	if !strings.HasPrefix(s, "---\n") {
		return nil, fmt.Errorf("%s: missing frontmatter", filename)
	}

	end := strings.Index(s[4:], "\n---")
	if end < 0 {
		return nil, fmt.Errorf("%s: unclosed frontmatter", filename)
	}

	fmRaw := s[4 : 4+end]
	body := s[4+end+4:] // skip the closing ---\n

	var fm struct {
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(fmRaw), &fm); err != nil {
		return nil, fmt.Errorf("%s: bad frontmatter: %w", filename, err)
	}

	basename := strings.TrimSuffix(filename, ".md")

	return &CanonicalAgent{
		Filename:    filename,
		Basename:    basename,
		Description: fm.Description,
		Body:        body,
	}, nil
}

// IsExcluded checks if an agent is in the harness exclusion list.
func IsExcluded(basename string, cfg *HarnessConfig) bool {
	for _, name := range cfg.Exclude {
		if name == basename {
			return true
		}
	}
	if ov, ok := cfg.Overrides[basename]; ok {
		if exc, ok := ov["exclude"]; ok {
			if b, ok := exc.(bool); ok && b {
				return true
			}
		}
	}
	return false
}

// BuildPlatformAgent generates the platform-native .md file for an agent
// by merging harness defaults with per-agent overrides.
func BuildPlatformAgent(agent *CanonicalAgent, cfg *HarnessConfig) ([]byte, error) {
	merged := make(map[string]any)
	for k, v := range cfg.Defaults {
		merged[k] = v
	}
	if ov, ok := cfg.Overrides[agent.Basename]; ok {
		for k, v := range ov {
			if k == "exclude" {
				continue
			}
			merged[k] = v
		}
	}

	merged["name"] = agent.Basename
	merged["description"] = agent.Description

	fmBytes, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshal frontmatter for %s: %w", agent.Basename, err)
	}

	var buf bytes.Buffer
	buf.WriteString("---\n")
	buf.Write(fmBytes)
	buf.WriteString("---\n")
	buf.WriteString(RenameStrings(agent.Body))

	return buf.Bytes(), nil
}

// AgentExtension returns the file extension for the harness format.
func (c *HarnessConfig) AgentExtension() string {
	if c.Format == "toml" {
		return ".toml"
	}
	return ".md"
}

// BuildCodexAgent generates a .toml agent file for the Codex platform.
// Codex uses TOML frontmatter with model and sandbox_mode fields.
func BuildCodexAgent(agent *CanonicalAgent, cfg *HarnessConfig) ([]byte, error) {
	merged := make(map[string]any)
	for k, v := range cfg.Defaults {
		merged[k] = v
	}
	if ov, ok := cfg.Overrides[agent.Basename]; ok {
		for k, v := range ov {
			if k == "exclude" {
				continue
			}
			merged[k] = v
		}
	}

	// Build TOML output
	var buf bytes.Buffer

	// Write known keys in stable order, then body as system prompt
	prefix := cfg.AgentNamePrefix
	if prefix == "" {
		prefix = "archon:"
	}

	buf.WriteString(fmt.Sprintf("name = %q\n", prefix+agent.Basename))
	buf.WriteString(fmt.Sprintf("description = %q\n", agent.Description))

	// Write remaining config keys in sorted order
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := merged[k]
		switch val := v.(type) {
		case string:
			buf.WriteString(fmt.Sprintf("%s = %q\n", k, val))
		case bool:
			buf.WriteString(fmt.Sprintf("%s = %v\n", k, val))
		case int:
			buf.WriteString(fmt.Sprintf("%s = %d\n", k, val))
		case float64:
			buf.WriteString(fmt.Sprintf("%s = %v\n", k, val))
		}
	}

	buf.WriteString("\nsystem_prompt = \"\"\"\n")
	buf.WriteString(RenameStrings(agent.Body))
	if !strings.HasSuffix(agent.Body, "\n") {
		buf.WriteString("\n")
	}
	buf.WriteString("\"\"\"\n")

	return buf.Bytes(), nil
}

// LoadHarnessConfig reads and parses a frontmatter.yaml.
func LoadHarnessConfig(data []byte) (*HarnessConfig, error) {
	var cfg HarnessConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
