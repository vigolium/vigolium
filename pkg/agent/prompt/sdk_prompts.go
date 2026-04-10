package prompt

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
	"go.uber.org/zap"
)

const sdkSystemPromptFile = "autopilot-system-prompt.md"

// LoadSDKAutopilotSystemPrompt loads the SDK autopilot system prompt from the
// first available source:
//  1. ~/.vigolium/prompts/autopilot-system-prompt.md (user override)
//  2. Embedded public/presets/prompts/autopilot/autopilot-system-prompt.md
//
// Returns the content and a human-readable source description.
func LoadSDKAutopilotSystemPrompt() (content string, source string) {
	// 1. User override: ~/.vigolium/prompts/autopilot-system-prompt.md
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".vigolium", "prompts", sdkSystemPromptFile)
		if data, err := os.ReadFile(path); err == nil {
			zap.L().Debug("loaded SDK autopilot system prompt from user file", zap.String("path", path))
			return string(data), path
		}
	}

	// 2. Embedded
	embeddedPath := "presets/prompts/autopilot/" + sdkSystemPromptFile
	if data, err := public.StaticFS.ReadFile(embeddedPath); err == nil {
		return string(data), "embedded:" + embeddedPath
	}

	// Should never happen — the file is embedded in the binary.
	zap.L().Warn("SDK autopilot system prompt file not found, using minimal fallback")
	return "You have access to the vigolium CLI scanner via the Bash tool. " +
		"Run 'vigolium --help' to discover available commands. " +
		"Use curl, jq, and standard Unix tools freely.", "fallback"
}

const browserPromptSectionFile = "autopilot-browser-section.md"

// LoadBrowserPromptSection loads the optional browser instructions section that
// gets appended to the autopilot system prompt when agent-browser is enabled.
// Returns empty string when the file is not found (non-fatal).
func LoadBrowserPromptSection() string {
	// 1. User override: ~/.vigolium/prompts/autopilot-browser-section.md
	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".vigolium", "prompts", browserPromptSectionFile)
		if data, err := os.ReadFile(path); err == nil {
			zap.L().Debug("loaded browser prompt section from user file", zap.String("path", path))
			return string(data)
		}
	}

	// 2. Embedded
	embeddedPath := "presets/prompts/autopilot/" + browserPromptSectionFile
	if data, err := public.StaticFS.ReadFile(embeddedPath); err == nil {
		return string(data)
	}

	return ""
}

// IsClaudeAgent returns true if the agent command appears to be Claude Code CLI.
func IsClaudeAgent(command string) bool {
	if command == "" || command == "claude" {
		return true
	}
	// Check basename for paths like /opt/homebrew/bin/claude
	return filepath.Base(command) == "claude"
}

// SystemPromptFilename returns the appropriate filename for the system prompt
// based on the agent type. Claude Code auto-discovers CLAUDE.md; other agents
// get AGENTS.md (for reference only — prompt is still passed inline).
func SystemPromptFilename(agentCommand string) string {
	if IsClaudeAgent(agentCommand) {
		return "CLAUDE.md"
	}
	return "AGENTS.md"
}

// PrintSystemPromptInfo prints where the system prompt was loaded from and
// where it was written. A non-empty phase groups the lines under a multi-phase
// pipeline (e.g. autopilot); empty phase keeps the default unprefixed format
// used by single-phase commands like `agent query`.
func PrintSystemPromptInfo(loadedFrom, writtenTo, phase string) {
	if phase != "" {
		prefix := terminal.PhasePrefix(phase)
		fmt.Fprintf(os.Stderr, "%s %s %s\n",
			prefix, terminal.Bold("system prompt:"), terminal.Gray(loadedFrom))
		if writtenTo != "" {
			fmt.Fprintf(os.Stderr, "%s %s %s\n",
				prefix, terminal.Bold("written to:"), terminal.Gray(terminal.ShortenHome(writtenTo)))
		}
		return
	}

	fmt.Fprintf(os.Stderr, "%s System prompt: %s\n",
		terminal.InfoSymbol(), terminal.Gray(loadedFrom))
	if writtenTo != "" {
		fmt.Fprintf(os.Stderr, "%s Written to: %s\n",
			terminal.InfoSymbol(), terminal.Gray(terminal.ShortenHome(writtenTo)))
	}
}
