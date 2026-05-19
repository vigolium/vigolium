// Package skill implements a passive, LLM-guided skill system for olium,
// matching the agentskills.io convention used by Claude Code and pi-mono.
//
// A "skill" is a Markdown file (SKILL.md) with YAML frontmatter sitting
// inside a directory. The frontmatter declares the skill's name and a
// one-line description. The body is prose that guides the LLM's tool
// usage for a specific task ("how to audit JWT auth", "how to triage a
// SQLi finding", …).
//
// Skills are NOT executable code. They are instructional assets: the
// agent loads the description into its system prompt, and when the task
// matches, it uses the read_file tool to pull the full body and follow
// the instructions. This is "progressive disclosure" — tokens only
// spent on skills the model chooses to load.
//
// Two invocation modes:
//   - Automatic: description in system prompt, model reads on demand.
//   - Explicit: user types `/skill:name <args>` in the TUI; we expand
//     the skill body inline into the prompt before sending.
package skill

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Source identifies where a skill was loaded from, for display and for
// conflict-resolution when the same name exists in multiple scopes.
type Source string

const (
	SourceProjectAgent  Source = "project-agent"  // ./.agent/skills/…
	SourceProjectClaude Source = "project-claude" // ./.claude/skills/…
	SourceUserVigolium  Source = "user-vigolium"  // ~/.vigolium/skills/
	SourceEmbedded      Source = "embedded"       // public/presets/skills/
)

// Skill is a parsed SKILL.md. Body excludes the frontmatter.
type Skill struct {
	Name         string   // must be [a-z0-9-]+, ≤64 chars
	Description  string   // one-line hook for the system prompt
	License      string   // optional
	AllowedTools []string // optional restriction (frontmatter: allowed-tools)

	Path    string // absolute path to SKILL.md (empty for embedded)
	BaseDir string // directory containing SKILL.md (for relative refs)
	Body    string // markdown body, frontmatter stripped
	Source  Source // scope this skill was loaded from
}

// frontmatterRe captures the YAML block at the very top of a file. We
// normalize CRLF to LF before applying it.
var frontmatterRe = regexp.MustCompile(`(?s)\A---\s*\n(.*?)\n---\s*(?:\n|$)`)

// nameValidRe enforces the agentskills.io name rules.
var nameValidRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

type frontmatter struct {
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	License      string   `yaml:"license"`
	AllowedTools []string `yaml:"allowed-tools"`
}

// Parse decodes a SKILL.md byte blob into a Skill. path/baseDir/source
// are attached to the result; they're not parsed from the content.
// Returns a descriptive error if frontmatter is missing or the name is
// invalid — callers should skip the skill but keep loading others.
func Parse(raw []byte, path, baseDir string, source Source) (*Skill, error) {
	content := strings.ReplaceAll(string(raw), "\r\n", "\n")

	m := frontmatterRe.FindStringSubmatchIndex(content)
	if m == nil {
		return nil, fmt.Errorf("missing YAML frontmatter (expected --- block at start of file)")
	}
	yamlBlock := content[m[2]:m[3]]
	body := strings.TrimSpace(content[m[1]:])

	var fm frontmatter
	if err := yaml.Unmarshal([]byte(yamlBlock), &fm); err != nil {
		return nil, fmt.Errorf("parse frontmatter: %w", err)
	}

	if fm.Name == "" {
		return nil, fmt.Errorf("frontmatter.name is required")
	}
	if !nameValidRe.MatchString(fm.Name) || len(fm.Name) > 64 {
		return nil, fmt.Errorf("frontmatter.name %q: must be lowercase a-z0-9 with single hyphens, ≤64 chars", fm.Name)
	}
	if fm.Description == "" {
		return nil, fmt.Errorf("frontmatter.description is required")
	}
	if len(fm.Description) > 1024 {
		return nil, fmt.Errorf("frontmatter.description too long (%d chars, max 1024)", len(fm.Description))
	}

	return &Skill{
		Name:         fm.Name,
		Description:  fm.Description,
		License:      fm.License,
		AllowedTools: fm.AllowedTools,
		Path:         path,
		BaseDir:      baseDir,
		Body:         body,
		Source:       source,
	}, nil
}
