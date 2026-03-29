package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/public"
	"go.uber.org/zap"
)

// CopySkillsToSessionDir copies embedded skill files to the session directory
// so the agent can discover them from its working directory.
// Always copies vigolium-scanner. Conditionally copies agent-browser when browserEnabled is true.
func CopySkillsToSessionDir(sessionDir string, browserEnabled bool) {
	if sessionDir == "" {
		return
	}

	skills := []string{"skills/vigolium-scanner"}
	if browserEnabled {
		skills = append(skills, "skills/agent-browser")
	}

	for _, skillPath := range skills {
		destDir := filepath.Join(sessionDir, skillPath)
		copyEmbeddedDir(skillPath, destDir)
	}
}

// DefaultAuditAgentDir returns the default directory for the embedded audit agent: ~/.vigolium/vig-audit-agent/.
func DefaultAuditAgentDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vigolium", "vig-audit-agent")
}

// ExtractAuditAgentPlugin extracts the embedded vig-audit-agent to ~/.vigolium/vig-audit-agent/.
// It writes the plugin (commands + agents) and bundled security skills so that Claude Code
// can load them via --plugin-dir. Returns the path to the extracted plugin directory.
// If the plugin was already extracted, it returns the existing path without re-extracting.
func ExtractAuditAgentPlugin() (string, error) {
	baseDir := DefaultAuditAgentDir()
	if baseDir == "" {
		return "", fmt.Errorf("cannot determine home directory for audit agent extraction")
	}
	return extractAuditAgentTo(baseDir)
}

// extractAuditAgentTo extracts the embedded audit agent to the given base directory.
// Uses a version-aware marker so that binary upgrades trigger re-extraction.
func extractAuditAgentTo(baseDir string) (string, error) {
	if baseDir == "" {
		return "", nil
	}

	pluginDir := filepath.Join(baseDir, "plugin")
	skillsDir := filepath.Join(baseDir, "skills")

	// Version-aware marker: compare hash of embedded content to detect upgrades
	marker := filepath.Join(baseDir, ".extracted")
	currentHash := embeddedAuditAgentHash()
	if existing, err := os.ReadFile(marker); err == nil && string(existing) == currentHash {
		return pluginDir, nil // already extracted and up-to-date
	}

	_ = os.MkdirAll(baseDir, 0o755)

	copyEmbeddedDir("vig-audit-agent/plugin", pluginDir)
	copyEmbeddedDir("vig-audit-agent/skills", skillsDir)

	_ = os.WriteFile(marker, []byte(currentHash), 0o644)

	zap.L().Info("Extracted embedded audit agent",
		zap.String("base_dir", baseDir),
		zap.String("plugin_dir", pluginDir))

	return pluginDir, nil
}

// embeddedAuditAgentHash computes a hash of a representative embedded file
// to detect when the binary's bundled audit agent has been updated.
func embeddedAuditAgentHash() string {
	data, err := public.StaticFS.ReadFile("vig-audit-agent/skills/audit/SKILL.md")
	if err != nil {
		return "unknown"
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:8]) // 16 hex chars is plenty for change detection
}

// copyEmbeddedDir recursively copies an embedded FS directory to the local filesystem.
func copyEmbeddedDir(embeddedRoot string, destRoot string) {
	err := fs.WalkDir(public.StaticFS, embeddedRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors silently
		}
		rel, relErr := filepath.Rel(embeddedRoot, path)
		if relErr != nil {
			return nil
		}
		dest := filepath.Join(destRoot, rel)

		if d.IsDir() {
			_ = os.MkdirAll(dest, 0o755)
			return nil
		}
		data, readErr := public.StaticFS.ReadFile(path)
		if readErr != nil {
			zap.L().Debug("failed to read embedded skill file", zap.String("path", path), zap.Error(readErr))
			return nil
		}
		_ = os.MkdirAll(filepath.Dir(dest), 0o755)
		if writeErr := os.WriteFile(dest, data, 0o644); writeErr != nil {
			zap.L().Debug("failed to write skill file", zap.String("dest", dest), zap.Error(writeErr))
		}
		return nil
	})
	if err != nil {
		zap.L().Debug("failed to walk embedded skill directory", zap.String("root", embeddedRoot), zap.Error(err))
	}
}
