package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/public"
)

// skillManifestName is the sidecar `skills install` writes next to SKILL.md.
// It is a dotfile so agent skill loaders, which read SKILL.md and the files it
// references, never pick it up; SKILL.md itself is left byte-identical to the
// bundle (agent loaders parse its frontmatter, so no stamp goes there).
const skillManifestName = ".vigolium-skill.json"

// Install states reported by `skills ls -j` (installed[].status), the install
// receipt and the doctor skill check.
const (
	skillStatusCurrent  = "current"  // matches the bundle this binary ships
	skillStatusStale    = "stale"    // another bundle, or a legacy install with no manifest
	skillStatusModified = "modified" // a file the manifest lists was edited or removed
	skillStatusMissing  = "missing"  // no SKILL.md at the path
)

// skillManifest records what one `skills install` wrote. files lists every
// bundle file with its sha256 so a later run can tell local edits (modified)
// from an older bundle (stale), and so --force can prune files a newer bundle
// no longer ships.
type skillManifest struct {
	Name          string              `json:"name"`
	BinaryVersion string              `json:"binary_version"`
	Commit        string              `json:"commit,omitempty"`
	BundleSHA256  string              `json:"bundle_sha256"`
	Files         []skillManifestFile `json:"files"`
	InstalledAt   string              `json:"installed_at"`
}

// skillManifestFile is one installed file, relative to the skill directory
// with forward slashes.
type skillManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// bundleHash is one embedded bundle's hashed contents.
type bundleHash struct {
	files  []skillManifestFile
	digest string
	err    error
}

// bundleHashes memoizes bundleContents by embed directory: the embedded
// bundle cannot change while the process runs, and status, doctor and skills
// ls would otherwise hash all of it on every call.
var bundleHashes sync.Map

// bundleContents hashes every file of an embedded bundle and returns them
// sorted by path, plus the bundle digest: sha256 over "path\x00sha256\n" for
// each file in that order, so it depends on content and layout only. The
// returned slice is shared; callers must not modify it.
func bundleContents(b bundledSkill) ([]skillManifestFile, string, error) {
	if v, ok := bundleHashes.Load(b.EmbedDir); ok {
		h := v.(bundleHash)
		return h.files, h.digest, h.err
	}
	files, digest, err := hashBundle(b)
	bundleHashes.Store(b.EmbedDir, bundleHash{files: files, digest: digest, err: err})
	return files, digest, err
}

func hashBundle(b bundledSkill) ([]skillManifestFile, string, error) {
	var files []skillManifestFile
	err := fs.WalkDir(public.StaticFS, b.EmbedDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		data, err := public.StaticFS.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files = append(files, skillManifestFile{
			Path:   strings.TrimPrefix(p, b.EmbedDir+"/"),
			SHA256: hex.EncodeToString(sum[:]),
		})
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("hash bundle %s: %w", b.Name, err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	h := sha256.New()
	for _, f := range files {
		_, _ = fmt.Fprintf(h, "%s\x00%s\n", f.Path, f.SHA256)
	}
	return files, hex.EncodeToString(h.Sum(nil)), nil
}

// readSkillManifest loads <dest>/.vigolium-skill.json. A missing file is
// (nil, nil): a legacy install, or no install at all.
func readSkillManifest(dest string) (*skillManifest, error) {
	raw, err := os.ReadFile(filepath.Join(dest, skillManifestName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m skillManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", skillManifestName, err)
	}
	return &m, nil
}

func writeSkillManifest(dest string, m *skillManifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dest, skillManifestName), append(raw, '\n'), 0o644)
}

// skillInstallState is what is on disk at one skill directory.
type skillInstallState struct {
	Status   string
	Version  string         // the manifest's binary_version; "" for a legacy install
	Manifest *skillManifest // nil for a legacy (or unreadable-manifest) install
}

// inspectSkillInstall classifies the install at dest against the bundle digest
// this binary ships. Local edits win over staleness: a modified install is
// reported as modified even when it is also old, so nothing that reinstalls
// stale copies unattended (doctor --fix) discards a user's changes.
func inspectSkillInstall(dest, bundleDigest string) skillInstallState {
	if _, err := os.Stat(filepath.Join(dest, "SKILL.md")); err != nil {
		return skillInstallState{Status: skillStatusMissing}
	}
	m, err := readSkillManifest(dest)
	if err != nil || m == nil {
		// No manifest: written by a binary that predates stamping (or by
		// hand), so it cannot be the current bundle's install.
		return skillInstallState{Status: skillStatusStale}
	}
	st := skillInstallState{Status: skillStatusCurrent, Version: m.BinaryVersion, Manifest: m}
	if modified, _, err := manifestDrift(dest, m); err != nil || len(modified) > 0 {
		st.Status = skillStatusModified
	} else if m.BundleSHA256 != bundleDigest {
		st.Status = skillStatusStale
	}
	return st
}

// manifestDrift reads every file manifest m lists under dest. modified names
// the ones that are missing or whose content no longer matches; present names
// the ones still on disk (edited or not). Paths that escape dest are skipped.
// A read error other than a missing file is returned.
func manifestDrift(dest string, m *skillManifest) (modified, present []string, err error) {
	for _, f := range m.Files {
		rel := filepath.FromSlash(f.Path)
		if !filepath.IsLocal(rel) {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(dest, rel))
		switch {
		case errors.Is(readErr, fs.ErrNotExist):
			modified = append(modified, f.Path)
			continue
		case readErr != nil:
			return modified, present, readErr
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != f.SHA256 {
			modified = append(modified, f.Path)
		}
		present = append(present, f.Path)
	}
	return modified, present, nil
}

// skillInstallOutcome is what installSkillBundle did at one destination.
type skillInstallOutcome struct {
	Installed bool
	Status    string   // the state before this run (missing on a fresh install)
	Version   string   // the previous install's binary_version, if stamped
	Backup    string   // where a legacy install was moved under --force
	Pruned    []string // files the previous manifest listed that the bundle dropped
}

// installSkillBundle installs bundle b at dest. Without force an existing
// install is left alone and its state reported. With force:
//   - a stamped install is overwritten in place, after deleting the files its
//     manifest lists that this bundle no longer ships (files the user added are
//     never in the manifest, so they survive);
//   - a legacy install (SKILL.md, no manifest) whose frontmatter names the same
//     skill is moved to <dest>.bak-<UTC timestamp> (its SKILL.md renamed to
//     SKILL.md.bak so agents do not load it as a second copy) and a fresh copy
//     written, so nothing is deleted silently; any other SKILL.md is refused.
func installSkillBundle(b bundledSkill, dest string, force bool, version, commit string, now time.Time) (skillInstallOutcome, error) {
	files, digest, err := bundleContents(b)
	if err != nil {
		return skillInstallOutcome{}, err
	}
	prev := inspectSkillInstall(dest, digest)
	out := skillInstallOutcome{Status: prev.Status, Version: prev.Version}
	if prev.Status != skillStatusMissing && !force {
		return out, nil
	}

	if prev.Status != skillStatusMissing {
		if prev.Manifest != nil {
			out.Pruned, err = pruneDroppedSkillFiles(dest, prev.Manifest, files)
			if err != nil {
				return out, err
			}
		} else {
			if out.Backup, err = backupLegacySkill(b.Name, dest, now); err != nil {
				return out, err
			}
		}
	}

	if err := copyEmbeddedSkillBundle(b.EmbedDir, dest); err != nil {
		return out, err
	}
	if err := writeSkillManifest(dest, &skillManifest{
		Name:          b.Name,
		BinaryVersion: version,
		Commit:        commit,
		BundleSHA256:  digest,
		Files:         files,
		InstalledAt:   now.UTC().Format(time.RFC3339),
	}); err != nil {
		return out, fmt.Errorf("write %s: %w", skillManifestName, err)
	}
	out.Installed = true
	return out, nil
}

// pruneDroppedSkillFiles deletes the files the old manifest lists that the new
// bundle does not ship, then any directory that left empty. Paths that escape
// dest are ignored rather than trusted.
func pruneDroppedSkillFiles(dest string, old *skillManifest, next []skillManifestFile) ([]string, error) {
	keep := make(map[string]bool, len(next))
	for _, f := range next {
		keep[f.Path] = true
	}
	var pruned []string
	for _, f := range old.Files {
		rel := filepath.FromSlash(f.Path)
		if keep[f.Path] || !filepath.IsLocal(rel) {
			continue
		}
		target := filepath.Join(dest, rel)
		if err := os.Remove(target); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return pruned, fmt.Errorf("prune %s: %w", f.Path, err)
		}
		pruned = append(pruned, f.Path)
		removeEmptyParents(dest, f.Path)
	}
	return pruned, nil
}

// removeEmptyParents removes the directories above the removed file rel
// (slash-separated, relative to dest) that it left empty, up to but not
// including dest.
func removeEmptyParents(dest, rel string) {
	for dir := path.Dir(rel); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if os.Remove(filepath.Join(dest, filepath.FromSlash(dir))) != nil {
			return // not empty (or already gone)
		}
	}
}

// backupLegacySkill moves a pre-manifest install aside so --force can write a
// clean copy. It refuses when SKILL.md names a different skill: that directory
// is not ours to move.
func backupLegacySkill(name, dest string, now time.Time) (string, error) {
	if ok, got, err := legacySkillDeclares(name, dest); err != nil {
		return "", err
	} else if !ok {
		return "", fmt.Errorf("refusing to replace %s: it has no %s and its SKILL.md declares %s, not %q; move it aside or pick another --dir",
			dest, skillManifestName, got, name)
	}
	base := dest + ".bak-" + now.UTC().Format("20060102T150405Z")
	backup := base
	for i := 1; ; i++ {
		if _, statErr := os.Lstat(backup); errors.Is(statErr, fs.ErrNotExist) {
			break
		}
		backup = fmt.Sprintf("%s-%d", base, i)
	}
	if err := os.Rename(dest, backup); err != nil {
		return "", fmt.Errorf("back up legacy install: %w", err)
	}
	// The backup sits next to the fresh copy in the agent's skills directory,
	// and agent loaders take any subdirectory holding a SKILL.md as a skill: a
	// second "vigolium-scanner" with the old content. Renaming its entry file
	// keeps every byte while taking it out of the loader's view.
	if err := os.Rename(filepath.Join(backup, "SKILL.md"), filepath.Join(backup, legacyBackupSkillMd)); err != nil {
		return backup, fmt.Errorf("disable backed-up SKILL.md: %w", err)
	}
	return backup, nil
}

// legacySkillDeclares reports whether the SKILL.md of the unstamped install at
// dest declares the skill name, the one check that makes the directory ours to
// move or remove. got describes what it declares instead, for the refusal.
func legacySkillDeclares(name, dest string) (ok bool, got string, err error) {
	skillMd := filepath.Join(dest, "SKILL.md")
	raw, err := os.ReadFile(skillMd)
	if err != nil {
		return false, "", err
	}
	parsed, perr := skill.Parse(raw, skillMd, dest, skill.SourceProjectClaude)
	if perr != nil {
		return false, "unparseable frontmatter", nil
	}
	return strings.EqualFold(parsed.Name, name), fmt.Sprintf("skill %q", parsed.Name), nil
}

// legacyBackupSkillMd is what SKILL.md is renamed to inside a legacy backup.
const legacyBackupSkillMd = "SKILL.md.bak"

// skillInstallLocation is one directory skills are looked for in.
type skillInstallLocation struct {
	Agent string // claude | agents
	Scope string // project | global
	Dir   string
}

// skillInstallLocations lists the four directories `skills install` can
// target, in the order an agent would search them: ./.claude/skills,
// ~/.claude/skills, ./.agents/skills, ~/.agents/skills. When the working
// directory is $HOME the project and global paths coincide; each path is
// listed once (as project).
func skillInstallLocations() []skillInstallLocation {
	var out []skillInstallLocation
	seen := map[string]bool{}
	for _, agent := range []string{"claude", "agents"} {
		for _, scope := range []string{"project", "global"} {
			dir, err := skillsInstallBaseDir(agent, scope)
			if err != nil || seen[dir] {
				continue
			}
			seen[dir] = true
			out = append(out, skillInstallLocation{Agent: agent, Scope: scope, Dir: dir})
		}
	}
	return out
}

// skillInstalledView is one row of `skills ls -j` installed[]: a bundled
// skill at one install location.
type skillInstalledView struct {
	Name    string `json:"name"`
	Agent   string `json:"agent"`
	Scope   string `json:"scope"`
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Status  string `json:"status"`
}

// scanInstalledSkills reports every bundled skill at every install location,
// missing ones included.
func scanInstalledSkills(skills []bundledSkill) []skillInstalledView {
	out := []skillInstalledView{}
	digests := make(map[string]string, len(skills))
	for _, b := range skills {
		if _, d, err := bundleContents(b); err == nil {
			digests[b.Name] = d
		}
	}
	for _, loc := range skillInstallLocations() {
		for _, b := range skills {
			dest := filepath.Join(loc.Dir, b.Name)
			st := inspectSkillInstall(dest, digests[b.Name])
			out = append(out, skillInstalledView{
				Name: b.Name, Agent: loc.Agent, Scope: loc.Scope, Path: dest,
				Version: st.Version, Status: st.Status,
			})
		}
	}
	return out
}
