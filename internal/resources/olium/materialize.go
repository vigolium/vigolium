package olium

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// EnsureOnDisk materializes the embedded built-in skills into dir (created if
// absent), preserving the `<name>/SKILL.md` layout, and returns how many files
// were newly written.
//
// Semantics are deliberately "write-if-missing": an existing file is left
// untouched so operator edits to a materialized skill are never clobbered, yet
// a skill newly shipped in a binary upgrade still lands on disk on the next
// call (its file is missing). Writes are atomic (temp + rename) so a concurrent
// skill loader never observes a partial SKILL.md. Errors on individual files
// are returned; callers treat materialization as best-effort since the embedded
// copies remain available as a loader fallback regardless.
func EnsureOnDisk(dir string) (written int, err error) {
	if dir == "" {
		return 0, fmt.Errorf("skills dir is empty")
	}
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		return 0, fmt.Errorf("create skills dir %s: %w", dir, mkErr)
	}

	walkErr := fs.WalkDir(SkillsFS, SkillsPrefix, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(SkillsPrefix, path)
		if relErr != nil {
			return nil // skip a file we can't place
		}
		dst := filepath.Join(dir, rel)
		if _, statErr := os.Stat(dst); statErr == nil {
			return nil // already present — preserve any edits
		}

		data, readErr := SkillsFS.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read embedded skill %s: %w", path, readErr)
		}
		if mkErr := os.MkdirAll(filepath.Dir(dst), 0o755); mkErr != nil {
			return fmt.Errorf("create skill dir for %s: %w", rel, mkErr)
		}
		tmp := dst + ".tmp"
		if writeErr := os.WriteFile(tmp, data, 0o644); writeErr != nil {
			return fmt.Errorf("write skill %s: %w", rel, writeErr)
		}
		if renErr := os.Rename(tmp, dst); renErr != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("install skill %s: %w", rel, renErr)
		}
		written++
		return nil
	})
	return written, walkErr
}
