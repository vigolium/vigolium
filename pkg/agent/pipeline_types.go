package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/paths"
	"github.com/vigolium/vigolium/pkg/modules"
	"go.uber.org/zap"
)

// sanitizeExtensionFilename ensures a filename is safe for writing to disk.
// It strips path components to prevent traversal, converts to a URL-friendly
// slug (lowercase, alphanumeric + hyphens), and falls back to a numbered
// default for empty or dot-only names.
func sanitizeExtensionFilename(name string, index int) string {
	name = filepath.Base(name)
	if name == "" || name == "." || name == ".." {
		return fmt.Sprintf("extension-%d.js", index)
	}

	// Strip .js extension for slug processing, re-add after
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if ext == "" {
		ext = ".js"
	}

	// Slugify: lowercase, replace non-alphanumeric with hyphens, collapse, trim
	slug := strings.ToLower(base)
	var sb strings.Builder
	prevHyphen := false
	for _, r := range slug {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
			prevHyphen = false
		} else if !prevHyphen {
			sb.WriteRune('-')
			prevHyphen = true
		}
	}
	slug = strings.Trim(sb.String(), "-")

	if slug == "" {
		return fmt.Sprintf("extension-%d.js", index)
	}
	return slug + ext
}

// WriteCheckpointToDir persists a SwarmCheckpoint to the session directory (exported for CLI use).
func WriteCheckpointToDir(sessionDir string, cp *SwarmCheckpoint) error {
	return writeCheckpoint(sessionDir, cp)
}

// writeCheckpoint persists a SwarmCheckpoint to the session directory.
func writeCheckpoint(sessionDir string, cp *SwarmCheckpoint) error {
	if sessionDir == "" {
		return nil
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}
	// Atomic write: write to temp file then rename, so a crash mid-write
	// never leaves a corrupt checkpoint that breaks resume.
	target := filepath.Join(sessionDir, "checkpoint.json")
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint temp file: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("failed to rename checkpoint temp file: %w", err)
	}
	return nil
}

// loadCheckpoint reads a SwarmCheckpoint from the session directory.
func loadCheckpoint(sessionDir string) (*SwarmCheckpoint, error) {
	data, err := os.ReadFile(filepath.Join(sessionDir, "checkpoint.json"))
	if err != nil {
		return nil, err
	}
	var cp SwarmCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	return &cp, nil
}

// EnsureSessionDir creates the session directory for a given run ID under the specified base directory.
// If baseDir is empty, defaults to ~/.vigolium/agent-sessions/.
// Returns the absolute path to the created directory.
func EnsureSessionDir(baseDir, agenticScanUUID string) (string, error) {
	if baseDir == "" {
		baseDir = paths.VigoliumPath("agent-sessions")
		if baseDir == "" {
			return "", fmt.Errorf("failed to resolve the state directory: no home directory and no %s", paths.StateDirEnv)
		}
	}
	dir := filepath.Join(baseDir, agenticScanUUID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create session dir: %w", err)
	}
	return dir, nil
}

// writeSessionArtifact best-effort writes a session artifact (per-phase agent
// output, plans, recon reports) for post-hoc inspection. A write failure is
// logged but never aborts the run — these files are diagnostic, not control
// flow. Centralizes the justification for the dropped write errors at the call
// sites across the agent pipeline.
func writeSessionArtifact(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		zap.L().Debug("failed to write session artifact", zap.String("path", path), zap.Error(err))
	}
}

// WriteExtensionsToSessionDir writes generated JavaScript extensions to <sessionDir>/extensions/
// and returns the extensions subdirectory path.
func WriteExtensionsToSessionDir(extensions []GeneratedExtension, sessionDir string) (string, error) {
	extDir := filepath.Join(sessionDir, "extensions")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create extensions dir: %w", err)
	}
	for i, ext := range extensions {
		filename := sanitizeExtensionFilename(ext.Filename, i)
		path := filepath.Join(extDir, filename)
		if writeErr := os.WriteFile(path, []byte(ext.Code), 0644); writeErr != nil {
			zap.L().Warn("Failed to write extension",
				zap.String("filename", ext.Filename), zap.Error(writeErr))
			continue
		}
		zap.L().Info("Generated extension",
			zap.String("filename", ext.Filename),
			zap.String("reason", ext.Reason),
			zap.String("path", path))
	}
	return extDir, nil
}

// ResolveModulesFromPlan converts agent-suggested tags and IDs into a deduplicated
// module ID list. Falls back to ["all"] when no modules are resolved.
func ResolveModulesFromPlan(tags []string, ids []string) []string {
	moduleSet := make(map[string]bool)

	if len(tags) > 0 {
		resolved := modules.ResolveModuleTags(tags)
		for _, id := range resolved {
			moduleSet[id] = true
		}
	}

	for _, id := range ids {
		moduleSet[id] = true
	}

	if len(moduleSet) == 0 {
		return []string{"all"}
	}

	result := make([]string, 0, len(moduleSet))
	for id := range moduleSet {
		result = append(result, id)
	}
	return result
}

// WriteExtensionsToTempDir writes generated JavaScript extensions to a temporary
// directory and returns the directory path. Caller is responsible for cleanup.
func WriteExtensionsToTempDir(extensions []GeneratedExtension, prefix string) (string, error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	for i, ext := range extensions {
		filename := sanitizeExtensionFilename(ext.Filename, i)
		path := filepath.Join(dir, filename)
		if writeErr := os.WriteFile(path, []byte(ext.Code), 0644); writeErr != nil {
			zap.L().Warn("Failed to write extension",
				zap.String("filename", ext.Filename),
				zap.Error(writeErr))
			continue
		}
		zap.L().Info("Generated extension",
			zap.String("filename", ext.Filename),
			zap.String("reason", ext.Reason))
	}

	return dir, nil
}
