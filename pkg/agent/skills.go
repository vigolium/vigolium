package agent

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/pkg/archon"
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

// DefaultArchonDir returns the default directory for the embedded archon-audit harness: ~/.vigolium/archon-audit/.
func DefaultArchonDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vigolium", "archon-audit")
}

// ExtractArchonPlugin extracts the embedded archon-audit harness to ~/.vigolium/archon-audit/
// for the default Claude platform.
// It writes agents, commands, skills, and plugin.json so that Claude Code can load them
// via --plugin-dir. Returns the path to the extracted plugin directory.
// If the harness was already extracted and up-to-date, returns the existing path.
func ExtractArchonPlugin() (string, error) {
	return ExtractArchonPluginForPlatform(archon.PlatformClaude)
}

// ExtractArchonPluginForPlatform extracts the embedded archon-audit harness for the
// specified platform ("claude", "codex", or "opencode").
func ExtractArchonPluginForPlatform(platform string) (string, error) {
	baseDir := DefaultArchonDir()
	if baseDir == "" {
		return "", fmt.Errorf("cannot determine home directory for archon harness extraction")
	}
	return archon.ExtractArchonHarnessForPlatform(baseDir, platform)
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
