package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// An --agent or --scope typo next to --dir used to be accepted and ignored.
func TestSkillsInstallValidatesAgentAndScopeWithDir(t *testing.T) {
	skillTestEnv(t)
	dir := filepath.Join(t.TempDir(), "dest")
	swapGlobal(t, &skillsOpts.Dir, dir)
	swapGlobal(t, &skillsOpts.All, false)
	for _, c := range []struct{ agent, scope string }{{"cluade", "project"}, {"claude", "globl"}} {
		swapGlobal(t, &skillsOpts.Agent, c.agent)
		swapGlobal(t, &skillsOpts.Scope, c.scope)
		for name, run := range map[string]func() error{
			"install":   func() error { return runSkillsInstall(skillsInstallCmd, nil) },
			"uninstall": func() error { return runSkillsUninstall(skillsUninstallCmd, nil) },
		} {
			err := run()
			require.Errorf(t, err, "%s --agent %s --scope %s --dir", name, c.agent, c.scope)
			var ue usageError
			require.Truef(t, errors.As(err, &ue), "%s: want a usage error, got %v", name, err)
		}
		_, statErr := os.Stat(dir)
		require.True(t, os.IsNotExist(statErr), "nothing is written when a flag is refused")
	}
}

// A fresh install reported status "missing" and nothing else: the state before
// the run. status_after is the state the run left.
func TestSkillsInstallReportsStatusAfter(t *testing.T) {
	skillTestEnv(t)
	dir := filepath.Join(t.TempDir(), "dest")
	swapGlobal(t, &skillsOpts.Dir, dir)
	swapGlobal(t, &skillsOpts.All, false)
	swapGlobal(t, &skillsOpts.Agent, "claude")
	swapGlobal(t, &skillsOpts.Scope, "project")
	swapGlobal(t, &globalForce, false)

	swapGlobal(t, &skillsInstallDryRun, true)
	doc := emitCaptured(t, func() error { return runSkillsInstall(skillsInstallCmd, nil) })
	item := requireEnvelope(t, doc, "skills install", "mutation")[0].(map[string]any)
	require.Equal(t, skillStatusMissing, item["status"])
	require.Equal(t, skillStatusCurrent, item["status_after"], "a dry run predicts the state it would leave")
	_, statErr := os.Stat(dir)
	require.True(t, os.IsNotExist(statErr))

	swapGlobal(t, &skillsInstallDryRun, false)
	doc = emitCaptured(t, func() error { return runSkillsInstall(skillsInstallCmd, nil) })
	item = requireEnvelope(t, doc, "skills install", "mutation")[0].(map[string]any)
	require.Equal(t, skillStatusMissing, item["status"])
	require.Equal(t, skillStatusCurrent, item["status_after"])
}

func TestSkillUninstallRemovesOnlyUnmodifiedManifestFiles(t *testing.T) {
	b := scannerBundle(t)
	dest := filepath.Join(t.TempDir(), b.Name)
	_, err := installSkillBundle(b, dest, false, "v1", "", skillTestNow)
	require.NoError(t, err)
	mine := filepath.Join(dest, "notes.md")
	require.NoError(t, os.WriteFile(mine, []byte("mine"), 0o644))

	v, err := uninstallSkillBundle(b, dest, false, false)
	require.NoError(t, err)
	require.True(t, v.Removed)
	require.Equal(t, skillStatusCurrent, v.Status)
	require.Equal(t, skillStatusMissing, v.StatusAfter)
	require.Contains(t, v.FilesRemoved, "SKILL.md")
	require.Equal(t, []string{"notes.md"}, v.Kept)
	require.FileExists(t, mine, "a file the bundle never shipped is kept")
	require.NoFileExists(t, filepath.Join(dest, "SKILL.md"))
	require.NoFileExists(t, filepath.Join(dest, skillManifestName))
	require.NoDirExists(t, filepath.Join(dest, "references"), "a directory the removal emptied goes too")

	// Nothing of ours left: a clean install's directory disappears entirely.
	dest2 := filepath.Join(t.TempDir(), b.Name)
	_, err = installSkillBundle(b, dest2, false, "v1", "", skillTestNow)
	require.NoError(t, err)
	_, err = uninstallSkillBundle(b, dest2, false, false)
	require.NoError(t, err)
	require.NoDirExists(t, dest2)
}

func TestSkillUninstallModifiedNeedsForce(t *testing.T) {
	b := scannerBundle(t)
	dest := filepath.Join(t.TempDir(), b.Name)
	_, err := installSkillBundle(b, dest, false, "v1", "", skillTestNow)
	require.NoError(t, err)
	edited := filepath.Join(dest, "SKILL.md")
	require.NoError(t, os.WriteFile(edited, []byte("---\nname: vigolium-scanner\n---\nmy notes\n"), 0o644))

	v, err := uninstallSkillBundle(b, dest, false, false)
	require.NoError(t, err)
	require.False(t, v.Removed)
	require.Equal(t, skillStatusModified, v.Reason)
	require.Equal(t, []string{"SKILL.md"}, v.Modified)
	require.Empty(t, v.FilesRemoved)
	require.FileExists(t, edited)
	require.FileExists(t, filepath.Join(dest, "references", "invariants.md"), "a modified install is left whole")

	// --dry-run --force reports and deletes nothing.
	v, err = uninstallSkillBundle(b, dest, true, true)
	require.NoError(t, err)
	require.True(t, v.Removed)
	require.Contains(t, v.FilesRemoved, "SKILL.md")
	require.FileExists(t, edited)

	v, err = uninstallSkillBundle(b, dest, true, false)
	require.NoError(t, err)
	require.True(t, v.Removed)
	require.NoDirExists(t, dest)
}

func TestSkillUninstallUnstampedNeedsForce(t *testing.T) {
	b := scannerBundle(t)
	dest := filepath.Join(t.TempDir(), b.Name)
	require.NoError(t, copyEmbeddedSkillBundle(b.EmbedDir, dest))

	v, err := uninstallSkillBundle(b, dest, false, false)
	require.NoError(t, err)
	require.False(t, v.Removed)
	require.Equal(t, "unstamped", v.Reason)
	require.FileExists(t, filepath.Join(dest, "SKILL.md"))

	v, err = uninstallSkillBundle(b, dest, true, false)
	require.NoError(t, err)
	require.True(t, v.Removed)
	require.NoDirExists(t, dest)

	// Another skill's directory under the same name is never removed.
	other := filepath.Join(t.TempDir(), b.Name)
	require.NoError(t, os.MkdirAll(other, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(other, "SKILL.md"), []byte("---\nname: someone-else\ndescription: x\n---\n"), 0o644))
	_, err = uninstallSkillBundle(b, other, true, false)
	require.Error(t, err)
	require.FileExists(t, filepath.Join(other, "SKILL.md"))
}

func TestSkillsUninstallJSON(t *testing.T) {
	skillTestEnv(t)
	dir := filepath.Join(t.TempDir(), "dest")
	b := scannerBundle(t)
	_, err := installSkillBundle(b, filepath.Join(dir, b.Name), false, "v1", "", skillTestNow)
	require.NoError(t, err)
	swapGlobal(t, &skillsOpts.Dir, dir)
	swapGlobal(t, &skillsOpts.All, false)
	swapGlobal(t, &skillsOpts.Agent, "claude")
	swapGlobal(t, &skillsOpts.Scope, "project")
	swapGlobal(t, &globalForce, false)

	swapGlobal(t, &skillsUninstallDryRun, true)
	doc := emitCaptured(t, func() error { return runSkillsUninstall(skillsUninstallCmd, nil) })
	items := requireEnvelope(t, doc, "skills uninstall", "mutation")
	require.Equal(t, false, doc["changed"])
	require.Equal(t, true, doc["dry_run"])
	require.Equal(t, true, items[0].(map[string]any)["removed"])
	require.FileExists(t, filepath.Join(dir, b.Name, "SKILL.md"))

	swapGlobal(t, &skillsUninstallDryRun, false)
	doc = emitCaptured(t, func() error { return runSkillsUninstall(skillsUninstallCmd, nil) })
	items = requireEnvelope(t, doc, "skills uninstall", "mutation")
	require.Equal(t, true, doc["changed"])
	require.Equal(t, skillStatusMissing, items[0].(map[string]any)["status_after"])
	require.NoDirExists(t, filepath.Join(dir, b.Name))

	doc = emitCaptured(t, func() error { return runSkillsUninstall(skillsUninstallCmd, nil) })
	items = requireEnvelope(t, doc, "skills uninstall", "mutation")
	require.Equal(t, false, doc["changed"])
	require.Equal(t, "noop", doc["action"])
	require.Equal(t, "not_installed", items[0].(map[string]any)["reason"])
}
