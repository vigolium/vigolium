package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var skillsUninstallDryRun bool

// Subcommand: vigolium skills uninstall [name]...
var skillsUninstallCmd = &cobra.Command{
	Use:   "uninstall [name...]",
	Short: "Remove an installed skill bundle from a coding agent's skills directory",
	Long: `Remove what 'vigolium skills install' wrote, from the directory --agent and
--scope (or --dir) name. With no name, removes the '` + defaultInstallSkill + `' skill; --all
removes every bundled skill found there.

Only files the install manifest (.vigolium-skill.json) lists, and only while
their sha256 still matches it, are removed; files you added beside them are
kept, and the directory is removed only when it ends up empty. An install with
local edits (status modified) is left whole unless --force, which removes the
edited files too. An install without a manifest (written by hand or by an old
binary) is removed only with --force, and only when its SKILL.md declares the
skill being removed.

--dry-run lists what would be removed without touching anything.`,
	Example: `  # Remove the project-scope Claude Code install
  vigolium skills uninstall
  # See what would go from the global Codex/agents install
  vigolium skills uninstall --agent codex --scope global --dry-run -j`,
	Args: cobra.ArbitraryArgs,
	RunE: runSkillsUninstall,
}

func init() {
	skillsCmd.AddCommand(skillsUninstallCmd)
	f := skillsUninstallCmd.Flags()
	f.StringVar(&skillsOpts.Agent, "agent", "claude", "Coding agent the skill was installed for: claude, codex, or agents")
	f.StringVar(&skillsOpts.Scope, "scope", "project", "Install scope: project (current folder) or global (home dir)")
	f.BoolVar(&skillsOpts.All, "all", false, "Remove every bundled skill installed there")
	f.StringVar(&skillsOpts.Dir, "dir", "", "Directory the skill was installed into (--agent/--scope are still validated, but do not pick the path)")
	f.BoolVar(&skillsUninstallDryRun, "dry-run", false, "Show what would be removed, without deleting anything")

	registerCommandSchema(contract.Command{Name: "skills uninstall", Item: skillUninstallView{}, Extras: skillUninstallExtras{},
		Description: "One item per skill bundle: what was (or, with --dry-run, would be) removed, what was kept and why."})
}

// skillUninstallView is one bundle in `skills uninstall -j`.
//
// status is the install state found (missing, current, stale, modified);
// status_after the state left behind (missing once removed). reason says why a
// bundle was left alone: not_installed, modified (local edits; --force) or
// unstamped (no manifest; --force). files_removed lists the bundle files
// deleted, modified the edited ones, kept the files that were never the
// bundle's (they stay, and so does the directory).
type skillUninstallView struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Removed      bool     `json:"removed"`
	Status       string   `json:"status"`
	StatusAfter  string   `json:"status_after"`
	Reason       string   `json:"reason,omitempty"`
	FilesRemoved []string `json:"files_removed"`
	Modified     []string `json:"modified,omitempty"`
	Kept         []string `json:"kept,omitempty"`
}

// skillUninstallExtras are the top-level counters of `skills uninstall -j`.
type skillUninstallExtras struct {
	Removed int    `json:"removed"`
	Skipped int    `json:"skipped"`
	Dir     string `json:"dir"`
}

func runSkillsUninstall(cmd *cobra.Command, names []string) error {
	skills, err := loadBundledSkills()
	if err != nil {
		return err
	}
	var targets []bundledSkill
	switch {
	case skillsOpts.All:
		targets = skills
	case len(names) == 0:
		b, ok := findBundle(skills, defaultInstallSkill)
		if !ok {
			return fmt.Errorf("default skill %q is not bundled (available: %s)", defaultInstallSkill, bundleNames(skills))
		}
		targets = []bundledSkill{b}
	default:
		if targets, err = resolveNamedTargets(skills, names); err != nil {
			return err
		}
	}
	baseDir, err := resolveSkillsBaseDir()
	if err != nil {
		return err
	}

	out := humanOut()
	removed, skipped := 0, 0
	items := make([]skillUninstallView, 0, len(targets))
	for _, b := range targets {
		view, uerr := uninstallSkillBundle(b, filepath.Join(baseDir, b.Name), globalForce, skillsUninstallDryRun)
		if uerr != nil {
			return fmt.Errorf("uninstall %s: %w", b.Name, uerr)
		}
		items = append(items, view)
		if view.Removed {
			removed++
		} else {
			skipped++
		}
		printSkillUninstall(out, view)
	}

	if globalJSON {
		action := "uninstall"
		if removed == 0 {
			action = "noop"
		}
		return emitMutation(cmd, "", mutationResult{
			Changed: removed > 0 && !skillsUninstallDryRun,
			Action:  action,
			DryRun:  skillsUninstallDryRun,
			Items:   items,
			Extra:   map[string]any{"removed": removed, "skipped": skipped, "dir": baseDir},
		})
	}
	fmt.Printf("\n%s %d removed, %d skipped.\n", terminal.InfoSymbol(), removed, skipped)
	return nil
}

func printSkillUninstall(out io.Writer, v skillUninstallView) {
	verb := "Removed"
	if skillsUninstallDryRun {
		verb = "Dry run: would remove"
	}
	switch {
	case v.Removed:
		_, _ = fmt.Fprintf(out, "%s %s %s (%d file(s)) from %s\n", terminal.SuccessSymbol(), verb,
			terminal.Cyan(v.Name), len(v.FilesRemoved), terminal.Gray(v.Path))
		if len(v.Kept) > 0 {
			_, _ = fmt.Fprintf(out, "%s Kept %d file(s) the bundle never shipped: %s\n", terminal.InfoSymbol(),
				len(v.Kept), terminal.Gray(strings.Join(v.Kept, ", ")))
		}
	case v.Reason == "not_installed":
		_, _ = fmt.Fprintf(out, "%s %s is not installed at %s\n", terminal.InfoSymbol(), terminal.Cyan(v.Name), terminal.Gray(v.Path))
	case v.Reason == skillStatusModified:
		_, _ = fmt.Fprintf(out, "%s %s at %s has local edits (%s): left in place; --force removes them too\n",
			terminal.WarningSymbol(), terminal.Cyan(v.Name), terminal.Gray(v.Path), strings.Join(v.Modified, ", "))
	case v.Reason == "unstamped":
		_, _ = fmt.Fprintf(out, "%s %s at %s has no %s, so its files cannot be told from yours: left in place; --force removes the directory\n",
			terminal.WarningSymbol(), terminal.Cyan(v.Name), terminal.Gray(v.Path), skillManifestName)
	}
}

// uninstallSkillBundle removes bundle b's install at dest. Without force, an
// install with any edited or missing manifest file is left whole, and so is an
// install with no manifest. Files the manifest does not list are never
// removed. dryRun reports the same decision without deleting.
func uninstallSkillBundle(b bundledSkill, dest string, force, dryRun bool) (skillUninstallView, error) {
	_, digest, err := bundleContents(b)
	if err != nil {
		return skillUninstallView{}, err
	}
	st := inspectSkillInstall(dest, digest)
	view := skillUninstallView{Name: b.Name, Path: dest, Status: st.Status, StatusAfter: st.Status, FilesRemoved: []string{}}
	if st.Status == skillStatusMissing {
		view.Reason = "not_installed"
		return view, nil
	}
	if st.Manifest == nil {
		return uninstallUnstampedSkill(b.Name, dest, force, dryRun, view)
	}

	var remove []string
	for _, f := range st.Manifest.Files {
		rel := filepath.FromSlash(f.Path)
		if !filepath.IsLocal(rel) {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(dest, rel))
		switch {
		case errors.Is(readErr, fs.ErrNotExist):
			view.Modified = append(view.Modified, f.Path)
		case readErr != nil:
			return view, readErr
		default:
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != f.SHA256 {
				view.Modified = append(view.Modified, f.Path)
			}
			remove = append(remove, f.Path)
		}
	}
	if len(view.Modified) > 0 && !force {
		view.Reason = skillStatusModified
		return view, nil
	}
	remove = append(remove, skillManifestName)
	listed := map[string]bool{}
	for _, p := range remove {
		listed[p] = true
	}
	view.Kept = unlistedSkillFiles(dest, listed)
	view.Removed = true
	view.StatusAfter = skillStatusMissing
	for _, p := range remove {
		if p != skillManifestName {
			view.FilesRemoved = append(view.FilesRemoved, p)
		}
	}
	if dryRun {
		return view, nil
	}
	for _, p := range remove {
		if err := os.Remove(filepath.Join(dest, filepath.FromSlash(p))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return view, fmt.Errorf("remove %s: %w", p, err)
		}
	}
	removeEmptySkillDirs(dest, remove)
	return view, nil
}

// uninstallUnstampedSkill handles an install with no manifest: nothing tells
// its files from the user's, so it goes only under --force, and only when its
// SKILL.md declares the skill being removed.
func uninstallUnstampedSkill(name, dest string, force, dryRun bool, view skillUninstallView) (skillUninstallView, error) {
	if !force {
		view.Reason = "unstamped"
		return view, nil
	}
	skillMd := filepath.Join(dest, "SKILL.md")
	raw, err := os.ReadFile(skillMd)
	if err != nil {
		return view, err
	}
	parsed, perr := skill.Parse(raw, skillMd, dest, skill.SourceProjectClaude)
	if perr != nil || !strings.EqualFold(parsed.Name, name) {
		return view, fmt.Errorf("refusing to remove %s: it has no %s and its SKILL.md does not declare %q", dest, skillManifestName, name)
	}
	view.Kept = nil
	_ = filepath.WalkDir(dest, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr == nil && !d.IsDir() {
			if rel, relErr := filepath.Rel(dest, p); relErr == nil {
				view.FilesRemoved = append(view.FilesRemoved, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	view.Removed = true
	view.StatusAfter = skillStatusMissing
	if dryRun {
		return view, nil
	}
	return view, os.RemoveAll(dest)
}

// unlistedSkillFiles lists the files under dest that listed does not name,
// relative and slash-separated.
func unlistedSkillFiles(dest string, listed map[string]bool) []string {
	var out []string
	_ = filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dest, p)
		if relErr == nil && !listed[filepath.ToSlash(rel)] {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

// removeEmptySkillDirs removes the directories the removed files left empty,
// deepest first, then dest itself when nothing is left in it.
func removeEmptySkillDirs(dest string, removed []string) {
	dirs := map[string]bool{}
	for _, p := range removed {
		for dir := path.Dir(p); dir != "." && dir != "/"; dir = path.Dir(dir) {
			dirs[dir] = true
		}
	}
	ordered := make([]string, 0, len(dirs))
	for d := range dirs {
		ordered = append(ordered, d)
	}
	// Deeper paths have more separators; remove them before their parents.
	sort.Slice(ordered, func(i, j int) bool { return strings.Count(ordered[i], "/") > strings.Count(ordered[j], "/") })
	for _, d := range ordered {
		_ = os.Remove(filepath.Join(dest, filepath.FromSlash(d))) // fails when not empty
	}
	_ = os.Remove(dest)
}
