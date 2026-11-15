package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/public"
)

func resetSkillsGet(t *testing.T) {
	t.Helper()
	swapGlobal(t, &skillsOpts.Full, false)
	swapGlobal(t, &skillsOpts.All, false)
	swapGlobal(t, &skillsOpts.Refs, nil)
	swapGlobal(t, &skillsOpts.ListRefs, false)
	swapGlobal(t, &globalJSON, false)
}

// An agent without the skill on disk could fetch SKILL.md (16 KB) or the
// whole bundle (735 KB), nothing in between, so it could not follow the router.
func TestSkillsGetOneReference(t *testing.T) {
	want, err := public.StaticFS.ReadFile(skillBundleDir + "/references/recipes.md")
	require.NoError(t, err)

	for _, spelling := range []string{"recipes", "recipes.md", "references/recipes.md", "RECIPES"} {
		resetSkillsGet(t)
		swapGlobal(t, &skillsOpts.Refs, []string{spelling})
		out := captureStdout(t, func() { require.NoError(t, runSkillsGet(skillsGetCmd, []string{"vigolium-scanner"})) })
		require.Equalf(t, string(want), out, "--ref %s prints exactly that file", spelling)
	}

	// The path form names the same file.
	resetSkillsGet(t)
	out := captureStdout(t, func() {
		require.NoError(t, runSkillsGet(skillsGetCmd, []string{"vigolium-scanner/references/recipes.md"}))
	})
	require.Equal(t, string(want), out)

	// -j: one item per reference.
	resetSkillsGet(t)
	swapGlobal(t, &globalJSON, true)
	swapGlobal(t, &skillsOpts.Refs, []string{"recipes", "invariants"})
	doc := emitCaptured(t, func() error { return runSkillsGet(skillsGetCmd, []string{"vigolium-scanner"}) })
	items := requireEnvelope(t, doc, "skills get", "read")
	require.Len(t, items, 2)
	first := items[0].(map[string]any)
	require.Equal(t, "references/recipes.md", first["path"])
	require.Equal(t, string(want), first["content"])
	require.Equal(t, "references/invariants.md", items[1].(map[string]any)["path"])
}

func TestSkillsGetUnknownReference(t *testing.T) {
	resetSkillsGet(t)
	swapGlobal(t, &skillsOpts.Refs, []string{"recipies"})
	err := runSkillsGet(skillsGetCmd, []string{"vigolium-scanner"})
	require.Error(t, err)
	var ce clicommon.CLIError
	require.ErrorAs(t, err, &ce)
	require.Equal(t, "recipes", ce.DidYouMean)
	require.Contains(t, ce.Hint, "--list-refs")
}

func TestSkillsGetListRefs(t *testing.T) {
	resetSkillsGet(t)
	swapGlobal(t, &globalJSON, true)
	swapGlobal(t, &skillsOpts.ListRefs, true)
	doc := emitCaptured(t, func() error { return runSkillsGet(skillsGetCmd, []string{"vigolium-scanner"}) })
	items := requireEnvelope(t, doc, "skills get", "read")
	require.Greater(t, len(items), 3)
	first := items[0].(map[string]any)
	require.Equal(t, "SKILL.md", first["path"])
	require.Greater(t, first["bytes"].(float64), float64(1000))
	require.Greater(t, first["lines"].(float64), float64(50))
	var paths []string
	for _, it := range items {
		paths = append(paths, it.(map[string]any)["path"].(string))
		require.NotContains(t, it.(map[string]any), "content", "--list-refs lists, it does not print")
	}
	require.Contains(t, strings.Join(paths, " "), "references/invariants.md")
}

// --full keeps its meaning; combining it with a narrower mode is ambiguous.
func TestSkillsGetModesExclusive(t *testing.T) {
	resetSkillsGet(t)
	swapGlobal(t, &skillsOpts.Full, true)
	swapGlobal(t, &skillsOpts.Refs, []string{"recipes"})
	err := runSkillsGet(skillsGetCmd, []string{"vigolium-scanner"})
	var ue usageError
	require.ErrorAs(t, err, &ue)

	resetSkillsGet(t)
	swapGlobal(t, &skillsOpts.Full, true)
	out := captureStdout(t, func() { require.NoError(t, runSkillsGet(skillsGetCmd, []string{"vigolium-scanner"})) })
	require.Contains(t, out, "----- vigolium-scanner/references/recipes.md -----")
}
