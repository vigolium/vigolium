package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/public"
)

// skillTestEnv points HOME and the working directory at fresh temp dirs so the
// four install locations are empty and private to the test.
func skillTestEnv(t *testing.T) (home, project string) {
	t.Helper()
	home, project = t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(project)
	return home, project
}

func scannerBundle(t *testing.T) bundledSkill {
	t.Helper()
	skills, err := loadBundledSkills()
	require.NoError(t, err)
	b, ok := findBundle(skills, defaultInstallSkill)
	require.True(t, ok)
	return b
}

var skillTestNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// ageSkillInstall makes a stamped install look like an older bundle's: a
// different bundle digest and version, plus one reference the old bundle
// shipped and this one dropped.
func ageSkillInstall(t *testing.T, dest string) {
	t.Helper()
	m, err := readSkillManifest(dest)
	require.NoError(t, err)
	require.NotNil(t, m)
	m.BinaryVersion = "v0.0.1"
	m.BundleSHA256 = "0000"
	require.NoError(t, os.WriteFile(filepath.Join(dest, "references", "dropped.md"), []byte("old"), 0o644))
	// Hashed for real so the install reads as stale, not modified.
	sum := sha256.Sum256([]byte("old"))
	m.Files = append(m.Files, skillManifestFile{Path: "references/dropped.md", SHA256: hex.EncodeToString(sum[:])})
	require.NoError(t, writeSkillManifest(dest, m))
}

func TestSkillInstallWritesManifest(t *testing.T) {
	b := scannerBundle(t)
	dest := filepath.Join(t.TempDir(), b.Name)

	res, err := installSkillBundle(b, dest, false, "v9.9.9", "abc123", skillTestNow)
	require.NoError(t, err)
	require.True(t, res.Installed)
	require.Equal(t, skillStatusMissing, res.Status)

	m, err := readSkillManifest(dest)
	require.NoError(t, err)
	require.NotNil(t, m)
	files, digest, err := bundleContents(b)
	require.NoError(t, err)
	require.Equal(t, b.Name, m.Name)
	require.Equal(t, "v9.9.9", m.BinaryVersion)
	require.Equal(t, "abc123", m.Commit)
	require.Equal(t, digest, m.BundleSHA256)
	require.Equal(t, files, m.Files)
	require.Equal(t, "2026-10-10T12:00:00Z", m.InstalledAt)
	for _, f := range m.Files {
		require.NotEqual(t, skillManifestName, f.Path, "the manifest does not list itself")
	}

	// SKILL.md is byte-identical to the bundle: no stamp in the frontmatter.
	want, err := public.StaticFS.ReadFile(b.EmbedDir + "/SKILL.md")
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(dest, "SKILL.md"))
	require.NoError(t, err)
	require.Equal(t, want, got)

	st := inspectSkillInstall(dest, digest)
	require.Equal(t, skillStatusCurrent, st.Status)
	require.Equal(t, "v9.9.9", st.Version)

	// A second run without --force leaves a current install alone.
	res, err = installSkillBundle(b, dest, false, "v9.9.9", "", skillTestNow)
	require.NoError(t, err)
	require.False(t, res.Installed)
	require.Equal(t, skillStatusCurrent, res.Status)
}

func TestSkillInstallModifiedDetected(t *testing.T) {
	b := scannerBundle(t)
	dest := filepath.Join(t.TempDir(), b.Name)
	_, err := installSkillBundle(b, dest, false, "v1", "", skillTestNow)
	require.NoError(t, err)
	_, digest, err := bundleContents(b)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte("---\nname: x\n---\nedited\n"), 0o644))
	require.Equal(t, skillStatusModified, inspectSkillInstall(dest, digest).Status)

	// Modified wins over stale, so unattended reinstalls never discard edits.
	require.Equal(t, skillStatusModified, inspectSkillInstall(dest, "other-digest").Status)

	// A file the user adds is not a modification.
	dest2 := filepath.Join(t.TempDir(), b.Name)
	_, err = installSkillBundle(b, dest2, false, "v1", "", skillTestNow)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dest2, "notes.md"), []byte("mine"), 0o644))
	require.Equal(t, skillStatusCurrent, inspectSkillInstall(dest2, digest).Status)
}

func TestSkillReinstallForcePrunesDroppedFiles(t *testing.T) {
	b := scannerBundle(t)
	dest := filepath.Join(t.TempDir(), b.Name)
	_, err := installSkillBundle(b, dest, false, "v0.0.1", "", skillTestNow)
	require.NoError(t, err)
	ageSkillInstall(t, dest)
	require.NoError(t, os.WriteFile(filepath.Join(dest, "notes.md"), []byte("mine"), 0o644))

	// Without --force a stale install is reported, not touched.
	res, err := installSkillBundle(b, dest, false, "v9", "", skillTestNow)
	require.NoError(t, err)
	require.False(t, res.Installed)
	require.Equal(t, skillStatusStale, res.Status)
	require.Equal(t, "v0.0.1", res.Version)
	require.FileExists(t, filepath.Join(dest, "references", "dropped.md"))

	res, err = installSkillBundle(b, dest, true, "v9", "", skillTestNow)
	require.NoError(t, err)
	require.True(t, res.Installed)
	require.Equal(t, []string{"references/dropped.md"}, res.Pruned)
	require.NoFileExists(t, filepath.Join(dest, "references", "dropped.md"))
	require.FileExists(t, filepath.Join(dest, "notes.md"), "files the manifest never listed survive --force")
	require.Empty(t, res.Backup)

	_, digest, err := bundleContents(b)
	require.NoError(t, err)
	st := inspectSkillInstall(dest, digest)
	require.Equal(t, skillStatusCurrent, st.Status)
	require.Equal(t, "v9", st.Version)
}

func TestSkillLegacyInstallForceBacksUp(t *testing.T) {
	b := scannerBundle(t)
	base := t.TempDir()
	dest := filepath.Join(base, b.Name)
	require.NoError(t, copyEmbeddedSkillBundle(b.EmbedDir, dest)) // a pre-manifest install
	require.NoError(t, os.WriteFile(filepath.Join(dest, "notes.md"), []byte("mine"), 0o644))
	_, digest, err := bundleContents(b)
	require.NoError(t, err)
	require.Equal(t, skillStatusStale, inspectSkillInstall(dest, digest).Status, "no manifest reads as stale")

	res, err := installSkillBundle(b, dest, true, "v9", "", skillTestNow)
	require.NoError(t, err)
	require.True(t, res.Installed)
	require.Equal(t, dest+".bak-20261010T120000Z", res.Backup)
	require.FileExists(t, filepath.Join(res.Backup, "notes.md"), "the legacy copy is moved aside, not deleted")
	require.FileExists(t, filepath.Join(res.Backup, legacyBackupSkillMd))
	require.NoFileExists(t, filepath.Join(res.Backup, "SKILL.md"), "agents must not load the backup as a second skill")
	require.NoFileExists(t, filepath.Join(dest, "notes.md"))
	require.Equal(t, skillStatusCurrent, inspectSkillInstall(dest, digest).Status)

	// A second legacy backup in the same second gets its own name.
	require.NoError(t, os.Remove(filepath.Join(dest, skillManifestName)))
	res, err = installSkillBundle(b, dest, true, "v9", "", skillTestNow)
	require.NoError(t, err)
	require.Equal(t, dest+".bak-20261010T120000Z-1", res.Backup)
}

func TestSkillLegacyInstallOtherNameRefused(t *testing.T) {
	b := scannerBundle(t)
	dest := filepath.Join(t.TempDir(), b.Name)
	require.NoError(t, os.MkdirAll(dest, 0o755))
	foreign := "---\nname: someone-else\ndescription: not ours\n---\nbody\n"
	require.NoError(t, os.WriteFile(filepath.Join(dest, "SKILL.md"), []byte(foreign), 0o644))

	_, err := installSkillBundle(b, dest, true, "v9", "", skillTestNow)
	require.ErrorContains(t, err, "refusing to replace")
	got, readErr := os.ReadFile(filepath.Join(dest, "SKILL.md"))
	require.NoError(t, readErr)
	require.Equal(t, foreign, string(got), "a foreign SKILL.md is left untouched")
}

func TestSkillsListJSONReportsInstalls(t *testing.T) {
	home, project := skillTestEnv(t)
	b := scannerBundle(t)
	globalClaude := filepath.Join(home, ".claude", "skills", b.Name)
	projectAgents := filepath.Join(project, ".agents", "skills", b.Name)
	_, err := installSkillBundle(b, globalClaude, false, "v9", "", skillTestNow)
	require.NoError(t, err)
	require.NoError(t, copyEmbeddedSkillBundle(b.EmbedDir, projectAgents)) // legacy

	doc := emitCaptured(t, func() error { return runSkillsList(skillsListCmd) })
	requireEnvelope(t, doc, "skills list", "read")
	raw, err := json.Marshal(doc["installed"])
	require.NoError(t, err)
	var installed []skillInstalledView
	require.NoError(t, json.Unmarshal(raw, &installed))

	byPath := map[string]skillInstalledView{}
	for _, v := range installed {
		byPath[v.Path] = v
	}
	require.Len(t, byPath, 4, "one row per location for the one bundled skill: %v", installed)
	require.Equal(t, skillInstalledView{Name: b.Name, Agent: "claude", Scope: "global", Path: globalClaude, Version: "v9", Status: skillStatusCurrent},
		byPath[globalClaude])
	require.Equal(t, skillInstalledView{Name: b.Name, Agent: "agents", Scope: "project", Path: projectAgents, Status: skillStatusStale},
		byPath[projectAgents])
	require.Equal(t, skillStatusMissing, byPath[filepath.Join(project, ".claude", "skills", b.Name)].Status)
	require.Equal(t, skillStatusMissing, byPath[filepath.Join(home, ".agents", "skills", b.Name)].Status)
}

func TestSkillsInstallJSONReportsStale(t *testing.T) {
	skillTestEnv(t)
	dir := filepath.Join(t.TempDir(), "dest")
	b := scannerBundle(t)
	require.NoError(t, copyEmbeddedSkillBundle(b.EmbedDir, filepath.Join(dir, b.Name)))
	swapGlobal(t, &skillsOpts.Dir, dir)
	swapGlobal(t, &skillsOpts.All, false)
	swapGlobal(t, &globalForce, false)

	doc := emitCaptured(t, func() error { return runSkillsInstall(skillsInstallCmd, nil) })
	items := requireEnvelope(t, doc, "skills install", "mutation")
	require.Equal(t, false, doc["changed"])
	require.Len(t, items, 1)
	item := items[0].(map[string]any)
	require.Equal(t, skillStatusStale, item["status"])
	require.Equal(t, skillStatusStale, item["reason"])
	require.Equal(t, false, item["installed"])

	swapGlobal(t, &globalForce, true)
	doc = emitCaptured(t, func() error { return runSkillsInstall(skillsInstallCmd, nil) })
	items = requireEnvelope(t, doc, "skills install", "mutation")
	require.Equal(t, true, doc["changed"])
	item = items[0].(map[string]any)
	require.Equal(t, true, item["installed"])
	require.NotEmpty(t, item["backup"])
	require.FileExists(t, filepath.Join(dir, b.Name, skillManifestName))
}

func TestDoctorSkillCheckStatuses(t *testing.T) {
	missing := doctorSkillCheck([]skillInstalledView{{Status: skillStatusMissing}}, "v9")
	require.Equal(t, diagnostics.StatusOK, missing.Status)
	require.Contains(t, missing.Message, "not installed")

	current := doctorSkillCheck([]skillInstalledView{{Path: "/a", Status: skillStatusCurrent, Version: "v9"}}, "v9")
	require.Equal(t, diagnostics.StatusOK, current.Status)
	require.Empty(t, current.Tip)

	stale := doctorSkillCheck([]skillInstalledView{{Path: "/a", Status: skillStatusStale}, {Path: "/b", Status: skillStatusCurrent}}, "v9")
	require.Equal(t, diagnostics.StatusWarning, stale.Status)
	require.Contains(t, stale.Message, "stale=1")
	require.Contains(t, stale.Tip, "doctor --fix --only skill")

	modified := doctorSkillCheck([]skillInstalledView{{Path: "/a", Status: skillStatusModified}}, "v9")
	require.Equal(t, diagnostics.StatusWarning, modified.Status)
	require.Contains(t, modified.Tip, "--force")
}

// doctor -j carries the skill check in the report, and --fix --only skill
// reinstalls stale copies (and only those) without touching the verdict.
func TestDoctorSkillCheckAndFix(t *testing.T) {
	home, project := skillTestEnv(t)
	b := scannerBundle(t)
	staleDest := filepath.Join(home, ".claude", "skills", b.Name)
	modifiedDest := filepath.Join(project, ".claude", "skills", b.Name)
	_, err := installSkillBundle(b, staleDest, false, "v0.0.1", "", skillTestNow)
	require.NoError(t, err)
	ageSkillInstall(t, staleDest)
	_, err = installSkillBundle(b, modifiedDest, false, "v0.0.1", "", skillTestNow)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(modifiedDest, "SKILL.md"), []byte("edited"), 0o644))

	swapGlobal(t, &globalConfig, "")
	swapGlobal(t, &globalDB, filepath.Join(home, "doctor.sqlite"))
	swapGlobal(t, &doctorStrict, false)
	swapGlobal(t, &doctorRunDiagnostics, func(diagnostics.Deps) *diagnostics.Report {
		return &diagnostics.Report{Status: "ready", Database: &diagnostics.CheckResult{Status: diagnostics.StatusOK}}
	})

	swapGlobal(t, &doctorFix, false)
	swapGlobal(t, &doctorOnly, nil)
	doc := emitCaptured(t, func() error { return runDoctorCmd(doctorCmd, nil) })
	require.Equal(t, "ready", doc["status"], "a stale skill does not move the verdict")
	var skillCheck map[string]any
	for _, it := range doc["items"].([]any) {
		if c := it.(map[string]any); c["id"] == "skill" {
			skillCheck = c
		}
	}
	require.NotNil(t, skillCheck, "the skill check is one of the flat checks")
	require.Equal(t, "warning", skillCheck["status"])
	require.Contains(t, skillCheck["message"], "stale=1")
	require.Contains(t, skillCheck["message"], "modified=1")

	swapGlobal(t, &doctorFix, true)
	swapGlobal(t, &doctorOnly, []string{"skill"})
	doc = emitCaptured(t, func() error { return runDoctorCmd(doctorCmd, nil) })
	fixes := doc["fixes"].([]any)
	require.Len(t, fixes, 1, "only the stale install is reinstalled: %v", fixes)
	fix := fixes[0].(map[string]any)
	require.Equal(t, "skill", fix["key"])
	require.Equal(t, true, fix["success"])
	require.NoFileExists(t, filepath.Join(staleDest, "references", "dropped.md"))

	_, digest, err := bundleContents(b)
	require.NoError(t, err)
	require.Equal(t, skillStatusCurrent, inspectSkillInstall(staleDest, digest).Status)
	require.Equal(t, skillStatusModified, inspectSkillInstall(modifiedDest, digest).Status, "local edits are kept")
	items := doc["items"].([]any)
	require.Len(t, items, 1, "--only skill shows the skill check alone")
	require.Contains(t, items[0].(map[string]any)["message"], "stale=0", "items are the re-checked state")
}
