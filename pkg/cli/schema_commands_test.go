package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/runner"
)

// `schema commands -j` publishes every declared command with its traits, so a
// driver can build its reach and deny tables from it.
func TestSchemaCommandsPublishesTraits(t *testing.T) {
	preparedMachineTree(t)
	doc := emitCaptured(t, func() error { return runSchemaCommands(schemaCommandsCmd, nil) })
	items := doc["items"].([]any)
	rows := map[string]map[string]any{}
	for _, it := range items {
		r := it.(map[string]any)
		rows[r["command"].(string)] = r
	}
	for path := range commandTraits {
		if path == "" {
			continue
		}
		_, ok := rows[path]
		assert.True(t, ok, "%q is published", path)
	}

	stop := rows["scan stop"]
	require.NotNil(t, stop)
	assert.Equal(t, true, stop["writes_global"], "scan stop drops a sentinel in the shared sessions dir")
	assert.Equal(t, true, stop["mutates"])
	assert.Equal(t, false, stop["sends_traffic"])

	fuzz := rows["fuzz"]
	assert.Equal(t, true, fuzz["sends_traffic"])
	assert.Equal(t, "write", fuzz["db"])
	assert.Equal(t, true, fuzz["reads_store"])

	traffic := rows["traffic"]
	assert.Equal(t, false, traffic["mutates"], "a store read changes nothing")
	assert.Equal(t, false, traffic["writes_global"])
	assert.Equal(t, "read", traffic["db"])

	for _, path := range []string{"config set", "scope add", "skills install", "update", "agent cancel"} {
		assert.Equal(t, true, rows[path]["writes_global"], path)
	}
	assert.Equal(t, false, rows["version"]["writes_global"])

	// Value flags: -n/--limit take a value (the drift §0 of the 0.5.7 sync
	// found), a bool such as --ignore-scope does not.
	mine := rows["kit param-mine"]["value_flags"].([]any)
	assert.Contains(t, mine, "--limit")
	assert.Contains(t, mine, "-n")
	assert.NotContains(t, mine, "--ignore-scope")
	assert.NotContains(t, mine, "--require-scope")
	assert.NotContains(t, mine, "--config", "root flags are listed once, globally")

	global := doc["global_value_flags"].([]any)
	assert.Contains(t, global, "--config")
	assert.Contains(t, global, "--db")
	assert.NotContains(t, global, "--json")
}

func TestSchemaCommandsOneRow(t *testing.T) {
	preparedMachineTree(t)
	doc := emitCaptured(t, func() error { return runSchemaCommands(schemaCommandsCmd, []string{"scan", "stop"}) })
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	assert.Equal(t, "scan stop", items[0].(map[string]any)["command"])

	err := runSchemaCommands(schemaCommandsCmd, []string{"no-such-command"})
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
}

// `schema commands -j` names the scan pipeline a command runs from the flags
// its registrar annotates, and the native lines a shim or phase front door
// runs as: a guard derives "runs the phase pipeline", "scans one request" and
// "runs this phase whatever the line says" from them instead of naming the
// commands itself.
func TestSchemaCommandsPublishesPipelineAndTranslations(t *testing.T) {
	preparedMachineTree(t)
	doc := emitCaptured(t, func() error { return runSchemaCommands(schemaCommandsCmd, nil) })
	pipelines := map[string]any{}
	translations := map[string][]any{}
	for _, it := range doc["items"].([]any) {
		r := it.(map[string]any)
		if p, ok := r["pipeline"]; ok {
			pipelines[r["command"].(string)] = p
		}
		if tr, ok := r["translates_to"]; ok {
			translations[r["command"].(string)] = tr.([]any)
		}
	}
	assert.Equal(t, map[string]any{
		"scan": "full", "run": "full", "fingerprint": "full",
		"scan-url": "single-request", "scan-request": "single-request",
	}, pipelines)
	assert.Equal(t, []any{"run known-issue-scan"}, translations["nuclei"])
	assert.Equal(t, []any{"fuzz", "run discovery"}, translations["ffuf"])
	assert.Equal(t, []any{"run fingerprint"}, translations["fingerprint"])
	assert.Equal(t, []any{"dns"}, translations["dig"])
	for _, s := range shimSpecs {
		assert.NotEmpty(t, translations[s.name], "shim %s publishes no translates_to", s.name)
	}
	assert.Len(t, translations, len(shimSpecs)+len(phaseFrontDoors))
}

// Every line a shim's translate produces resolves to one of the shim's
// translatesTo entries, and every entry is a command path or `run` with a
// canonical phase.
func TestShimTranslatesToCoversExamples(t *testing.T) {
	root := preparedMachineTree(t)
	t.Setenv(pinnedEnvVar, "")
	examples := map[string][][]string{
		"ffuf": {{"-u", "https://t.test/FUZZ", "-w", "words.txt"}, {"-u", "https://t.test/FUZZ"}},
	}
	for _, s := range shimSpecs {
		argv := strings.Fields(strings.TrimPrefix(s.example, "vigolium "))
		lines := append([][]string{argv}, examples[s.name]...)
		for _, l := range lines {
			if l[0] != s.name {
				l = append([]string{s.name}, l...)
			}
			v := explainArgv(root, l)
			require.True(t, v.Parses, "%v: %s", l, v.Error)
			got := strings.TrimSpace(v.Command + " " + v.Phase)
			assert.Contains(t, s.translatesTo, got, "%v translates to %q", l, got)
		}
		for _, line := range s.translatesTo {
			words := strings.Fields(line)
			c, rest, err := root.Find(words)
			require.NoError(t, err, line)
			if commandPathWithoutRoot(c) == "run" {
				require.Len(t, rest, 1, line)
				canonical := slices.ContainsFunc(runner.PhaseVocabulary(), func(p runner.PhaseSpelling) bool {
					return p.OnlyAccepted && p.Canonical == rest[0]
				})
				assert.True(t, canonical, "%s: a translation names a canonical phase run accepts", line)
				continue
			}
			assert.Empty(t, rest, line)
			assert.Equal(t, line, commandPathWithoutRoot(c))
		}
	}
}

// `fingerprint` runs the fingerprint phase whatever --only the line passes,
// which is what its translates_to (`run fingerprint`) states: every record the
// run stores is the fingerprint phase's.
func TestFingerprintRunsItsPhaseOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")
	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "light", "--only", "dynamic-assessment", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, "fingerprint", oneDoc(t, stdout, stderr)["command"])
	total := func(args ...string) float64 {
		code, stdout, stderr := runA3(t, home, append([]string{"traffic", "-j", "--compact", "--all", "--fields", "uuid"}, args...)...)
		require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
		return oneDoc(t, stdout, stderr)["total"].(float64)
	}
	stored := total()
	assert.Positive(t, stored)
	assert.Equal(t, stored, total("--source", fingerprintPhase), "only the fingerprint phase sent")
}
