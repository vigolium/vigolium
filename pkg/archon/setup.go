package archon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	archonres "github.com/vigolium/vigolium/internal/resources/archon"
	"go.uber.org/zap"
)

// Supported archon platforms.
const (
	PlatformClaude   = "claude"
	PlatformCodex    = "codex"
	PlatformOpenCode = "opencode"
	PlatformByteSec  = "bytesec"
	PlatformTraeCLI  = "traecli"
)

// ExtractArchonHarness extracts the embedded archon-audit content (agents, commands,
// skills, extras) to the given base directory for the default Claude platform.
// Kept for backward compatibility — calls ExtractArchonHarnessForPlatform with "claude".
func ExtractArchonHarness(baseDir string) (string, error) {
	return ExtractArchonHarnessForPlatform(baseDir, PlatformClaude)
}

// ExtractArchonHarnessForPlatform extracts the embedded archon-audit content for the
// specified platform ("claude", "codex", or "opencode").
// Uses a version-aware marker (per-platform) so that binary upgrades trigger re-extraction.
// Returns the path to the extracted plugin directory.
func ExtractArchonHarnessForPlatform(baseDir, platform string) (string, error) {
	if baseDir == "" {
		return "", fmt.Errorf("empty base directory for archon harness extraction")
	}
	if platform == "" {
		platform = PlatformClaude
	}

	// Per-platform marker so different platforms don't clobber each other.
	marker := filepath.Join(baseDir, ".extracted-"+platform)
	currentHash := embeddedArchonHash()
	if existing, err := os.ReadFile(marker); err == nil && string(existing) == currentHash {
		return baseDir, nil // already extracted and up-to-date
	}

	_ = os.MkdirAll(baseDir, 0o755)

	harnessPath := "harnesses/" + platform + "/frontmatter.yaml"
	harnessData, err := archonres.HarnessesFS.ReadFile(harnessPath)
	if err != nil {
		return "", fmt.Errorf("read %s harness config: %w", platform, err)
	}
	cfg, err := LoadHarnessConfig(harnessData)
	if err != nil {
		return "", fmt.Errorf("parse %s harness config: %w", platform, err)
	}

	if err := installAgents(baseDir, platform, cfg); err != nil {
		return "", fmt.Errorf("install agents: %w", err)
	}
	if err := installCommands(baseDir); err != nil {
		return "", fmt.Errorf("install commands: %w", err)
	}
	if err := installSkills(baseDir); err != nil {
		return "", fmt.Errorf("install skills: %w", err)
	}
	if err := installExtras(baseDir, platform); err != nil {
		return "", fmt.Errorf("install extras: %w", err)
	}

	_ = os.WriteFile(marker, []byte(currentHash), 0o644)

	zap.L().Info("Extracted embedded archon-audit harness",
		zap.String("platform", platform),
		zap.String("base_dir", baseDir))

	return baseDir, nil
}

// installAgents extracts agent-defs with harness config transforms applied.
// Supports nested subdirectories (e.g. agent-defs/vigolium/) via WalkDir.
func installAgents(baseDir, platform string, cfg *HarnessConfig) error {
	destDir := filepath.Join(baseDir, "agents")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	return fs.WalkDir(archonres.AgentsFS, "agent-defs", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors silently
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}

		data, err := archonres.AgentsFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		// Derive basename from relative path: "agent-defs/vigolium/audit.md" → "vigolium-audit"
		relPath := strings.TrimPrefix(path, "agent-defs/")
		basename := strings.TrimSuffix(relPath, ".md")
		basename = strings.ReplaceAll(basename, "/", "-")

		agent, err := ParseCanonicalAgent(basename+".md", data)
		if err != nil {
			return err
		}
		agent.Basename = basename

		if IsExcluded(agent.Basename, cfg) {
			return nil
		}

		var output []byte
		switch platform {
		case PlatformCodex:
			output, err = BuildCodexAgent(agent, cfg)
		default:
			// Claude and OpenCode both use .md with YAML frontmatter
			output, err = BuildPlatformAgent(agent, cfg)
		}
		if err != nil {
			return fmt.Errorf("build agent %s: %w", agent.Basename, err)
		}

		ext := cfg.AgentExtension()
		destFile := filepath.Join(destDir, agent.Basename+ext)
		if err := os.WriteFile(destFile, output, 0o644); err != nil {
			return err
		}

		return nil
	})
}

// installCommands extracts command-defs as agent commands.
func installCommands(baseDir string) error {
	destDir := filepath.Join(baseDir, "commands", "archon")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	entries, err := fs.ReadDir(archonres.CommandsFS, "command-defs")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}

		data, err := archonres.CommandsFS.ReadFile("command-defs/" + entry.Name())
		if err != nil {
			return err
		}

		content := RenameStrings(string(data))
		destFile := filepath.Join(destDir, entry.Name())
		if err := os.WriteFile(destFile, []byte(content), 0o644); err != nil {
			return err
		}
	}

	return nil
}

// installSkills extracts shared skills.
func installSkills(baseDir string) error {
	destDir := filepath.Join(baseDir, "skills")

	return fs.WalkDir(archonres.SkillsFS, "skills", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors silently
		}

		relPath := strings.TrimPrefix(path, "skills/")
		if relPath == "" {
			return nil
		}
		dest := filepath.Join(destDir, relPath)

		if d.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}

		data, err := archonres.SkillsFS.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}

		content := RenameStrings(string(data))
		_ = os.MkdirAll(filepath.Dir(dest), 0o755)
		return os.WriteFile(dest, []byte(content), 0o644)
	})
}

// installExtras writes platform-specific extras.
func installExtras(baseDir, platform string) error {
	switch platform {
	case PlatformClaude:
		return installClaudeExtras(baseDir)
	case PlatformCodex:
		return installCodexExtras(baseDir)
	case PlatformOpenCode, PlatformByteSec, PlatformTraeCLI:
		// These platforms have no special extras beyond agents/commands/skills.
		return nil
	default:
		return installClaudeExtras(baseDir)
	}
}

// installClaudeExtras writes plugin.json for the Claude platform.
func installClaudeExtras(baseDir string) error {
	pluginDir := filepath.Join(baseDir, ".claude-plugin")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return err
	}

	pluginJSON, err := archonres.HarnessesFS.ReadFile("harnesses/claude/plugin.json")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(pluginDir, "plugin.json"), pluginJSON, 0o644)
}

// installCodexExtras writes the AGENTS.md dispatch block and subagent preamble
// for the Codex platform. Codex uses a central AGENTS.md file to route audit
// phases to typed subagents, and a subagent-preamble.md for output chunking rules.
func installCodexExtras(baseDir string) error {
	dispatchData, err := archonres.HarnessesFS.ReadFile("harnesses/codex/agents-dispatch.md")
	if err != nil {
		return fmt.Errorf("read codex agents-dispatch.md: %w", err)
	}

	content := RenameStrings(string(dispatchData))
	destFile := filepath.Join(baseDir, "AGENTS.md")
	if err := os.WriteFile(destFile, []byte(content), 0o644); err != nil {
		return err
	}

	// Extract subagent preamble if present (used for output chunking instructions).
	preambleData, err := archonres.HarnessesFS.ReadFile("harnesses/codex/subagent-preamble.md")
	if err == nil {
		preambleDest := filepath.Join(baseDir, "subagent-preamble.md")
		if err := os.WriteFile(preambleDest, preambleData, 0o644); err != nil {
			return err
		}
	}

	return nil
}

// embeddedArchonHash computes a hash of a representative embedded file
// to detect when the binary's bundled archon content has been updated.
func embeddedArchonHash() string {
	// Use the deep command as representative since it's the most comprehensive
	data, err := archonres.CommandsFS.ReadFile("command-defs/deep.md")
	if err != nil {
		return "unknown"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:8])
}
