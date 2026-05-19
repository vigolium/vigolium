package skill

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Registry holds skills loaded for a single olium session. First-found-by-name
// wins across scopes, following the precedence declared at Load time.
type Registry struct {
	skills map[string]*Skill
	order  []string // insertion order (project → user → embedded) for stable listing
}

// Get returns a skill by name, or nil if not found.
func (r *Registry) Get(name string) *Skill {
	if r == nil {
		return nil
	}
	return r.skills[name]
}

// List returns skills in a stable order suitable for prompt injection.
// Project-scope skills come first (user-authored, highest signal), then
// user-global, then embedded. Within a scope, alphabetical by name.
func (r *Registry) List() []*Skill {
	if r == nil {
		return nil
	}
	out := make([]*Skill, 0, len(r.skills))
	for _, n := range r.order {
		if s, ok := r.skills[n]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Len reports the number of registered skills.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.skills)
}

// LoadOptions configures Registry construction.
type LoadOptions struct {
	// WorkingDir is the starting point for project-scope skill discovery.
	// Defaults to os.Getwd(). Ancestor directories are searched too, so
	// running olium from a subfolder still picks up repo-root .agent/skills/.
	WorkingDir string

	// IncludeUserSkills enables ~/.vigolium/skills/ discovery. Enabled
	// for autopilot and swarm modes; disabled for generic `vigolium
	// agent olium` chat so scan-specific skills don't pollute casual use.
	IncludeUserSkills bool

	// Embedded, if non-nil, is scanned for built-in skills shipped with
	// the binary. Typically `public/presets/skills/` via go:embed.
	Embedded       fs.FS
	EmbeddedPrefix string // path inside Embedded to scan; e.g. "public/presets/skills"

	// Warnings, if non-nil, is appended to with non-fatal load issues
	// (malformed SKILL.md, duplicate names, etc.). Never nil on exit.
	Warnings *[]string
}

// Load discovers and parses skills per the options. Malformed skills
// are skipped with a warning; the function only returns an error on
// something catastrophic (like a broken embed FS).
func Load(opts LoadOptions) (*Registry, error) {
	reg := &Registry{skills: map[string]*Skill{}}
	var warnings []string
	if opts.Warnings == nil {
		opts.Warnings = &warnings
	}

	cwd := opts.WorkingDir
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	// Walk: project-scope (.agent/skills/, .claude/skills/) across cwd
	// and ancestors. Closer to cwd wins on conflict.
	for _, dir := range ancestorDirs(cwd) {
		loadDiskDir(reg, filepath.Join(dir, ".agent", "skills"), SourceProjectAgent, opts.Warnings)
		loadDiskDir(reg, filepath.Join(dir, ".claude", "skills"), SourceProjectClaude, opts.Warnings)
	}

	// User scope (autopilot/swarm only).
	if opts.IncludeUserSkills {
		if home, err := os.UserHomeDir(); err == nil {
			loadDiskDir(reg, filepath.Join(home, ".vigolium", "skills"), SourceUserVigolium, opts.Warnings)
		}
	}

	// Embedded fallback.
	if opts.Embedded != nil && opts.EmbeddedPrefix != "" {
		loadEmbeddedDir(reg, opts.Embedded, opts.EmbeddedPrefix, opts.Warnings)
	}

	return reg, nil
}

// LoadFromEmbed is a convenience wrapper for the common case:
// an embed.FS compiled into the binary.
func LoadFromEmbed(fsys embed.FS, prefix string, includeUser bool) (*Registry, []string, error) {
	var warnings []string
	reg, err := Load(LoadOptions{
		IncludeUserSkills: includeUser,
		Embedded:          fsys,
		EmbeddedPrefix:    prefix,
		Warnings:          &warnings,
	})
	return reg, warnings, err
}

// ancestorDirs returns start and every parent up to the filesystem root,
// in order of closest-first. Duplicates and non-absolute input are
// handled defensively.
func ancestorDirs(start string) []string {
	if start == "" {
		return nil
	}
	abs, err := filepath.Abs(start)
	if err != nil {
		return []string{start}
	}
	var out []string
	seen := map[string]struct{}{}
	for {
		if _, dup := seen[abs]; !dup {
			out = append(out, abs)
			seen[abs] = struct{}{}
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	return out
}

// loadDiskDir scans one scope directory on disk.
//
// Two shapes are accepted under `root`:
//   - `root/<name>/SKILL.md` — standard agentskills.io layout (directory skill)
//   - `root/<name>.md`       — single-file shorthand, frontmatter.name must match filename stem
func loadDiskDir(reg *Registry, root string, source Source, warnings *[]string) {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("skill: read %s: %v", root, err))
		return
	}
	// Sort for determinism.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		path := filepath.Join(root, e.Name())
		if e.IsDir() {
			skillFile := filepath.Join(path, "SKILL.md")
			if st, err := os.Stat(skillFile); err == nil && !st.IsDir() {
				readAndRegister(reg, skillFile, path, source, warnings)
			}
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			readAndRegister(reg, path, root, source, warnings)
		}
	}
}

// loadEmbeddedDir walks an embed.FS with the same layout rules.
func loadEmbeddedDir(reg *Registry, fsys fs.FS, prefix string, warnings *[]string) {
	sub, err := fs.Sub(fsys, prefix)
	if err != nil {
		return
	}
	_ = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.EqualFold(d.Name(), "SKILL.md") && !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		raw, err := fs.ReadFile(sub, path)
		if err != nil {
			return nil
		}
		// Embedded "path" is relative; record it as a synthetic marker so
		// the model can still tell where it came from.
		fullPath := filepath.Join("<embedded>", prefix, path)
		baseDir := filepath.Join("<embedded>", prefix, filepath.Dir(path))
		register(reg, raw, fullPath, baseDir, SourceEmbedded, warnings)
		return nil
	})
}

func readAndRegister(reg *Registry, path, baseDir string, source Source, warnings *[]string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("skill: read %s: %v", path, err))
		return
	}
	register(reg, raw, path, baseDir, source, warnings)
}

func register(reg *Registry, raw []byte, path, baseDir string, source Source, warnings *[]string) {
	s, err := Parse(raw, path, baseDir, source)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("skill: %s: %v", path, err))
		return
	}
	if _, exists := reg.skills[s.Name]; exists {
		// Higher-precedence scope was loaded first; keep it.
		return
	}
	reg.skills[s.Name] = s
	reg.order = append(reg.order, s.Name)
}
