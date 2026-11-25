package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/public"
)

// pinnedEnvFor is the pinned session runWithEnv hands a child.
func pinnedEnvFor(t *testing.T) (string, []string) {
	t.Helper()
	home, cfg := pinnedHome(t)
	return home, []string{"VIGOLIUM_PINNED=1", "VIGOLIUM_CONFIG=" + cfg,
		"VIGOLIUM_DB_PATH=" + filepath.Join(t.TempDir(), "pinned.sqlite")}
}

// Under the pin, --help shows neither the refused flags nor `scan stop`, and
// ends with the pin's line; without it, both are listed.
func TestPinnedHelpHidesRefusedSurface(t *testing.T) {
	home, env := pinnedEnvFor(t)

	code, out, stderr := runWithEnv(t, home, env, "scan-url", "--help")
	require.Equal(t, 0, code, stderr)
	assert.NotContains(t, out, "--ignore-scope")
	assert.NotContains(t, out, "--config")
	assert.NotContains(t, out, "--allow-risky-payloads")
	assert.Contains(t, out, pinnedHelpNote)

	code, out, stderr = runWithEnv(t, home, env, "scan", "--help")
	require.Equal(t, 0, code, stderr)
	assert.NotRegexp(t, `(?m)^\s+stop\s`, out, "scan stop must be hidden")
	assert.NotContains(t, out, "--allow-risky-payloads")
	assert.Contains(t, out, pinnedHelpNote)

	code, out, stderr = runWithEnv(t, home, env, "--help")
	require.Equal(t, 0, code, stderr)
	assert.NotContains(t, out, "--config")
	assert.Contains(t, out, pinnedHelpNote)

	code, out, _ = runWithEnv(t, home, nil, "scan-url", "--help")
	require.Equal(t, 0, code)
	assert.Contains(t, out, "--ignore-scope")
	assert.NotContains(t, out, pinnedHelpNote)
	code, out, _ = runWithEnv(t, home, nil, "scan", "--help")
	require.Equal(t, 0, code)
	assert.Regexp(t, `(?m)^\s+stop\s`, out)
}

// --usage and --usage -j drop the refused flags; -j names the pin in policy.
func TestPinnedUsageHidesRefusedFlags(t *testing.T) {
	home, env := pinnedEnvFor(t)

	code, out, stderr := runWithEnv(t, home, env, "scan-url", "--usage")
	require.Equal(t, 0, code, stderr)
	assert.NotContains(t, out, "--ignore-scope")
	assert.NotContains(t, out, "--config")
	assert.Contains(t, out, pinnedHelpNote)

	code, out, stderr = runWithEnv(t, home, env, "scan", "--usage")
	require.Equal(t, 0, code, stderr)
	assert.NotRegexp(t, `subcommands:[^\n]*\bstop\b`, out, "scan stop must be hidden")

	code, out, stderr = runWithEnv(t, home, env, "scan-url", "--usage", "-j")
	require.Equal(t, 0, code, stderr)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1, out)
	raw, _ := json.Marshal(docs[0])
	var doc struct {
		Policy string `json:"policy"`
		Items  []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, pinnedHelpNote, doc.Policy)
	require.NotEmpty(t, doc.Items)
	for _, it := range doc.Items {
		assert.NotContains(t, pinnedHiddenFlags(), it.Name, "--usage -j lists a refused flag")
	}

	// A hidden flag still refuses with its hint: hiding is display only.
	code, out, _ = runWithEnv(t, home, env, "traffic", "--no-redact", "-j")
	assert.Equal(t, ExitUsageError, code, out)
	assert.Equal(t, "vigolium traffic -j", errorHint(t, out))
}

// skills get under the pin drops every line naming a refused flag or command
// and ends with the pin's line.
func TestPinnedSkillsGet(t *testing.T) {
	home, env := pinnedEnvFor(t)
	code, out, stderr := runWithEnv(t, home, env, "skills", "get", "vigolium-scanner", "--full")
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, out, pinnedHelpNote)
	assert.False(t, pinnedRefusedText.MatchString(out), "pinned skill output names a refused flag or command")

	full, err := public.StaticFS.ReadFile("skills/vigolium-scanner/references/flags.generated.md")
	require.NoError(t, err)
	require.True(t, pinnedRefusedText.Match(full), "fixture: the flag reference names refused flags")
}

func TestPinnedSkillViewDropsWholeContinuedCommands(t *testing.T) {
	md := "intro --config-dir stays\n" +
		"use --ignore-scope here\n" +
		"```bash\n" +
		"vigolium replay -i x \\\n" +
		"  --ignore-scope -j\n" +
		"vigolium traffic -j\n" +
		"vigolium scan stop abc\n" +
		"```\n"
	got := pinnedSkillView(md)
	assert.Contains(t, got, "--config-dir stays")
	assert.NotContains(t, got, "--ignore-scope")
	assert.NotContains(t, got, "replay -i x")
	assert.NotContains(t, got, "scan stop")
	assert.Contains(t, got, "vigolium traffic -j")
	assert.Equal(t, 2, strings.Count(got, "```"), got)
	assert.True(t, strings.HasSuffix(strings.TrimSpace(got), pinnedHelpNote))
}

// The embedded profile names this build, stays under its bound, teaches the
// verbs it promises and, under the pin, hides what the pin refuses.
func TestEmbeddedProfile(t *testing.T) {
	prev, prevCommit := Version, Commit
	Version, Commit = "v0.0.0-test", "abc1234"
	t.Cleanup(func() { Version, Commit = prev, prevCommit })

	got := embeddedSkillProfile(rootCmd)
	assert.Contains(t, got, "commit abc1234")
	assert.Contains(t, got, "v0.0.0-test")
	assert.Less(t, len(got), embeddedProfileMaxBytes, "embedded profile is %d bytes", len(got))
	for _, verb := range []string{"scan-url", "scan", "fuzz", "replay", "traffic", "finding", "kit param-mine",
		"kit unlock-walk", "ingest", "schema", "auth lint"} {
		assert.Contains(t, got, "### `vigolium "+verb+"`", verb)
	}
	assert.Contains(t, got, "vigolium schema error")
	assert.Regexp(t, "vigolium scan [^\n]*--only", got, "scan is taught through --only")
	assert.NotContains(t, got, pinnedHelpNote)

	t.Setenv(pinnedEnvVar, "1")
	restore := applyPinnedHelpView(rootCmd)
	defer restore()
	pinned := embeddedSkillProfile(rootCmd)
	assert.Contains(t, pinned, pinnedHelpNote)
	assert.False(t, pinnedRefusedText.MatchString(pinned), "pinned profile names a refused flag")
	assert.NotContains(t, pinned, "vigolium scan stop")
}

func TestEmbeddedProfileThroughTheBinary(t *testing.T) {
	home, _ := pinnedHome(t)
	code, out, stderr := runWithEnv(t, home, nil, "skills", "get", "vigolium-scanner", "--profile", "embedded")
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, out, "# vigolium (embedded profile)")

	code, _, _ = runWithEnv(t, home, nil, "skills", "get", "vigolium-scanner", "--profile", "tiny")
	assert.Equal(t, ExitUsageError, code)
	code, _, _ = runWithEnv(t, home, nil, "skills", "get", "vigolium-scanner", "--profile", "embedded", "--full")
	assert.Equal(t, ExitUsageError, code)
}

// applyPinnedHelpView's restore puts every flag and command back.
func TestPinnedHelpViewRestores(t *testing.T) {
	restore := applyPinnedHelpView(rootCmd)
	f := scanURLCmd.Flags().Lookup("ignore-scope")
	require.NotNil(t, f)
	assert.True(t, f.Hidden)
	assert.True(t, rootCmd.PersistentFlags().Lookup("config").Hidden)
	restore()
	assert.False(t, f.Hidden)
	assert.False(t, rootCmd.PersistentFlags().Lookup("config").Hidden)
	stop, _, err := rootCmd.Find([]string{"scan", "stop"})
	require.NoError(t, err)
	assert.False(t, stop.Hidden)
}
