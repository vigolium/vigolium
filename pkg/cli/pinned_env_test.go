package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// pinnedHome is a throwaway HOME whose config pins a moderate tier ceiling and
// turns OAST off; it returns the home and that config's path.
func pinnedHome(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".vigolium")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, initMarkerFileName), []byte("ok"), 0o600))
	cfg := filepath.Join(dir, "vigolium-configs.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte(noOASTConfig+"dynamic-assessment:\n  max_module_tier: moderate\n"), 0o600))
	return home, cfg
}

// runWithEnv is runA3 (the real Execute in a child) with extra VIGOLIUM_*
// variables; every ambient VIGOLIUM_* is dropped first.
func runWithEnv(t *testing.T, home string, extra []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScopeAdmissionChild$", "-test.v=false")
	env := []string{a3ChildEnv + "=" + strings.Join(args, "\x1f"), "HOME=" + home, "NO_COLOR=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "VIGOLIUM_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env, extra...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	}
	t.Fatalf("run child: %v", err)
	return -1, "", ""
}

// errorHint is the error envelope's error.hint.
func errorHint(t *testing.T, stdout string) string {
	t.Helper()
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1, stdout)
	raw, _ := json.Marshal(docs[0])
	var doc struct {
		Error struct {
			Hint string `json:"hint"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	return doc.Error.Hint
}

// Under VIGOLIUM_PINNED=1 every flag that widens the env pins exits 2
// refused_by_policy before anything runs, and error.hint is the same command
// line without the refused part.
func TestPinnedEnvRefusesWidening(t *testing.T) {
	home, cfg := pinnedHome(t)
	pinnedDB := filepath.Join(t.TempDir(), "pinned.sqlite")
	env := []string{"VIGOLIUM_PINNED=1", "VIGOLIUM_CONFIG=" + cfg, "VIGOLIUM_DB_PATH=" + pinnedDB}
	const tgt = "http://127.0.0.1:9"

	cases := []struct {
		name string
		args []string
		hint string
	}{
		{"--config other", []string{"traffic", "--config", "/tmp/other.yaml", "-j"}, "vigolium traffic -j"},
		{"--db other on a write", []string{"import", "--db=/tmp/other.sqlite", "x.har", "-j"}, "vigolium import x.har -j"},
		{"--ignore-scope", []string{"replay", "-i", "curl " + tgt + "/x", "--ignore-scope", "-j"}, "vigolium replay -i 'curl " + tgt + "/x' -j"},
		{"--redirect-mode any", []string{"scan", "-t", tgt, "--redirect-mode", "any", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"--no-redact", []string{"traffic", "--no-redact", "-j"}, "vigolium traffic -j"},
		{"--all-records", []string{"agent", "swarm", "--all-records", "-j"}, "vigolium agent swarm -j"},
		{"--browser-insecure", []string{"scan", "-t", tgt, "--browser-insecure", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"--upload-results", []string{"scan", "-t", tgt, "--upload-results", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"--allow-risky-payloads", []string{"scan", "-t", tgt, "--allow-risky-payloads", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"--intensity deep", []string{"scan", "-t", tgt, "--intensity=deep", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"--max-module-tier above the config's", []string{"scan", "-t", tgt, "--max-module-tier", "heavy", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"--set scope.*", []string{"scan", "-t", tgt, "--set", "scope.host.include=[evil.example]", "--set", "spidering.max_depth=2", "-j"},
			"vigolium scan -t " + tgt + " --set spidering.max_depth=2 -j"},
		{"--set oast.*", []string{"scan", "-t", tgt, "--set", "oast.enabled=true", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"--set raises the tier", []string{"scan", "-t", tgt, "--set", "dynamic-assessment.max_module_tier=intrusive", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"--set allows risky payloads", []string{"scan", "-t", tgt, "--set", "dynamic-assessment.allow_risky_payloads=true", "-j"}, "vigolium scan -t " + tgt + " -j"},
		{"scan stop", []string{"scan", "stop", "abcdef12", "-j"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runWithEnv(t, home, env, c.args...)
			require.Equal(t, ExitUsageError, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			assert.Equal(t, string(apicontract.CodeRefusedByPolicy), errorCode(t, stdout))
			hint := errorHint(t, stdout)
			if c.hint != "" {
				assert.Equal(t, c.hint, hint)
			} else {
				assert.Contains(t, hint, "cannot stop another scan")
			}
		})
	}
}

// Narrowing flags, and the pinned files named again, pass under the pin; with
// the variable unset nothing is refused.
func TestPinnedEnvLetsNarrowingPass(t *testing.T) {
	home, cfg := pinnedHome(t)
	pinnedDB := filepath.Join(t.TempDir(), "pinned.sqlite")
	env := []string{"VIGOLIUM_PINNED=1", "VIGOLIUM_CONFIG=" + cfg, "VIGOLIUM_DB_PATH=" + pinnedDB}
	const tgt = "http://127.0.0.1:9"
	for name, args := range map[string][]string{
		"lower tier":               {"--max-module-tier", "light"},
		"same tier":                {"--max-module-tier", "moderate"},
		"redirects off":            {"--redirect-mode", "off"},
		"quick intensity":          {"--intensity", "quick"},
		"risky payloads off":       {"--allow-risky-payloads=false"},
		"pinned config named":      {"--config", cfg},
		"pinned db named":          {"--db", pinnedDB},
		"--set a crawl key":        {"--set", "spidering.max_depth=2"},
		"--set the tier lower":     {"--set", "dynamic-assessment.max_module_tier=light"},
		"browser-insecure off":     {"--browser-insecure=false"},
		"lower rate than ceiling":  {"--rate-limit", "3"},
		"rate above ceiling holds": {"--rate-limit", "500"},
	} {
		t.Run(name, func(t *testing.T) {
			argv := append([]string{"scan", "--dry-run", "-t", tgt, "-j"}, args...)
			code, stdout, stderr := runWithEnv(t, home, append(env, "VIGOLIUM_RATE_CEILING=5"), argv...)
			require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
			assert.NotContains(t, stdout, string(apicontract.CodeRefusedByPolicy))
		})
	}

	// The ceiling is not overridable under the pin: --rate-limit 500 runs at 5.
	code, stdout, stderr := runWithEnv(t, home, append(env, "VIGOLIUM_RATE_CEILING=5"),
		"scan", "--dry-run", "-t", tgt, "-j", "--rate-limit", "500")
	require.Equal(t, 0, code, stderr)
	assert.Regexp(t, `"rate_limit":5[,}]`, stdout, "the dry-run plan runs at the ceiling")
	assert.NotContains(t, stdout, `"rate_limit":500`)

	// A pure read of another store passes: it sends nothing and writes nothing.
	other := filepath.Join(t.TempDir(), "other.sqlite")
	_, stdout, stderr = runWithEnv(t, home, env, "traffic", "--db", other, "-j")
	assert.NotContains(t, stdout, string(apicontract.CodeRefusedByPolicy), stderr)

	// Unset, the same widening flag is not refused.
	code, stdout, stderr = runWithEnv(t, home, nil, "traffic", "--no-redact", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.NotContains(t, stdout, string(apicontract.CodeRefusedByPolicy))
}

// dropFlag removes every spelling of a flag and keeps everything else; with a
// matcher only the matching occurrences go.
func TestPinnedDropFlagAndShellJoin(t *testing.T) {
	db := rootCmd.PersistentFlags().Lookup("db")
	set := rootCmd.PersistentFlags().Lookup("set")
	noRedact := rootCmd.PersistentFlags().Lookup("no-redact")
	require.NotNil(t, db)
	require.NotNil(t, set)
	require.NotNil(t, noRedact)

	argv := []string{"traffic", "--db", "a.sqlite", "--db=b.sqlite", "--no-redact", "-j", "--", "--db"}
	assert.Equal(t, []string{"traffic", "--no-redact", "-j", "--", "--db"}, dropFlag(db, nil)(argv))
	assert.Equal(t, []string{"traffic", "--db", "a.sqlite", "--db=b.sqlite", "-j", "--", "--db"}, dropFlag(noRedact, nil)(argv))

	sets := []string{"scan", "--set", "scope.x=1", "--set=spidering.max_depth=2", "--set", "oast.enabled=false"}
	assert.Equal(t, []string{"scan", "--set=spidering.max_depth=2", "--set", "oast.enabled=false"},
		dropFlag(set, func(v string) bool { return v == "scope.x=1" })(sets))

	assert.Equal(t, `scan -t http://a.example 'curl http://x' 'it'\''s'`, quoteArgv([]string{"scan", "-t", "http://a.example", "curl http://x", "it's"}))
}
