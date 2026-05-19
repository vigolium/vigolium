package agent

import (
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
		// Skip the embed.FS walk when SKILL.md is already on disk. Resume
		// paths and the pipeline/CLI both call this helper for the same
		// run, so the second call would otherwise re-walk and re-write
		// the same bytes.
		if _, err := os.Stat(filepath.Join(destDir, "SKILL.md")); err == nil {
			continue
		}
		copyEmbeddedDir(skillPath, destDir)
	}
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
