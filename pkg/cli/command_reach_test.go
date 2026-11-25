package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/waf"
)

// Every traffic-sending command declares its reach, every reach row names a
// declared command, and every flag a row names exists on that command.
func TestCommandReachCoversTraffic(t *testing.T) {
	root := preparedMachineTree(t)
	for path, tr := range commandTraits {
		if tr.SendsTraffic {
			_, ok := commandReach[path]
			assert.True(t, ok, "%q sends traffic and declares no reach", path)
		}
	}
	for path, r := range commandReach {
		_, ok := commandTraits[path]
		require.True(t, ok, "%q has a reach row but no trait", path)
		c, _, err := root.Find(strings.Fields(path))
		require.NoError(t, err, path)
		require.Equal(t, path, commandPathWithoutRoot(c))
		assert.Contains(t, []string{reachNone, reachLine, reachStore, reachUnbounded}, r.Reach, path)
		for _, s := range r.Targets {
			assert.True(t, (s.Flag == "") != (s.Positional == ""), "%s: a target is a flag or a positional", path)
			if s.Flag != "" {
				assert.NotNil(t, c.Flags().Lookup(s.Flag), "%s: no --%s", path, s.Flag)
			}
			assert.Contains(t, []string{targetURL, targetHost, targetFile, targetInput, targetRecordUUID, targetScanUUID, targetFindingID}, s.Kind, path)
			if s.Pins {
				assert.True(t, s.Flag != "" && s.Kind == targetURL, "%s: only a url flag pins the destination", path)
			}
		}
		for _, f := range r.ReachFlags {
			assert.NotNil(t, c.Flags().Lookup(f.Flag), "%s: no --%s", path, f.Flag)
			if f.With != "" {
				assert.NotNil(t, c.Flags().Lookup(f.With), "%s: no --%s", path, f.With)
			}
		}
	}
}

// `schema commands -j` names targets, reach and aliases for the commands a
// guard has to read.
func TestSchemaCommandsPublishesReach(t *testing.T) {
	preparedMachineTree(t)
	doc := emitCaptured(t, func() error { return runSchemaCommands(schemaCommandsCmd, nil) })
	rows := map[string]map[string]any{}
	for _, it := range doc["items"].([]any) {
		r := it.(map[string]any)
		rows[r["command"].(string)] = r
	}
	target := func(path string) []map[string]any {
		var out []map[string]any
		for _, x := range rows[path]["targets"].([]any) {
			out = append(out, x.(map[string]any))
		}
		return out
	}
	reachFlags := func(path string) map[string]string {
		out := map[string]string{}
		for _, x := range rows[path]["reach_flags"].([]any) {
			m := x.(map[string]any)
			out[m["flag"].(string)] = m["reach"].(string)
		}
		return out
	}

	assert.Equal(t, "line", rows["scan-url"]["reach"])
	assert.Equal(t, "store", reachFlags("scan-url")["--include-stored"])
	assert.Contains(t, target("scan-url"), map[string]any{"positional": "first", "kind": "url"})
	assert.Contains(t, target("scan-url"), map[string]any{"flag": "--target", "short": "-t", "kind": "url"})

	assert.Equal(t, "line", rows["fuzz"]["reach"])
	assert.Contains(t, target("fuzz"), map[string]any{"flag": "--record-uuid", "short": "-u", "kind": "record_uuid"})
	assert.Equal(t, "store", reachFlags("fuzz")["--record-uuid"])

	assert.Equal(t, "store", rows["replay"]["reach"])
	assert.Contains(t, target("replay"), map[string]any{"flag": "--record-uuid", "short": "-u", "kind": "record_uuid"})
	assert.Equal(t, "unbounded", reachFlags("replay")["--all"])

	assert.Equal(t, "line", rows["fingerprint"]["reach"])
	assert.Contains(t, target("fingerprint"), map[string]any{"positional": "each", "kind": "url"})
	assert.Contains(t, target("fingerprint"), map[string]any{"flag": "--target-file", "short": "-T", "kind": "file"})

	assert.Equal(t, "line", rows["kit param-mine"]["reach"])
	assert.Contains(t, target("kit param-mine"), map[string]any{"positional": "first", "kind": "url"})

	assert.Equal(t, "line", rows["kit unlock-walk"]["reach"])
	assert.Contains(t, target("kit unlock-walk"), map[string]any{"flag": "--origin", "kind": "url", "pins": true})
	assert.Contains(t, target("kit unlock-walk"), map[string]any{"flag": "--profile", "kind": "file"})

	assert.Equal(t, "store", rows["scan"]["reach"], "scan -t also tests the stored records of the origin")
	assert.Equal(t, "line", reachFlags("scan")["--input-only"])
	assert.Equal(t, "unbounded", reachFlags("scan")["--all-records"])

	assert.Equal(t, "none", rows["hosts"]["reach"])
	assert.Equal(t, "none", rows["dns"]["reach"])
	assert.NotEmpty(t, rows["dns"]["reach_note"])
	assert.Equal(t, "store", reachFlags("traffic")["--replay"])

	runAliases := rows["run"]["aliases"].([]any)
	for _, a := range []string{"r", "run dast", "run dynamic-assessment", "r spider", "run cve"} {
		assert.Contains(t, runAliases, a)
	}
	assert.NotContains(t, runAliases, "run seed", "an internal step is not a phase run accepts")
	assert.Contains(t, rows["module ls"]["aliases"].([]any), "mo list")

	global := doc["global_reach_flags"].([]any)
	assert.Contains(t, global, map[string]any{"flag": "--dry-run", "reach": "none"})
	assert.Contains(t, global, map[string]any{"flag": "--help", "short": "-h", "reach": "none"})

	// A pinning target fixes the destination of every request the command
	// sends; the request file or stored record only supplies the shape.
	pins := func(path string) []string {
		var out []string
		for _, s := range target(path) {
			if s["pins"] == true {
				out = append(out, s["flag"].(string))
			}
		}
		return out
	}
	assert.Equal(t, []string{"--target"}, pins("fuzz"))
	assert.Equal(t, []string{"--target"}, pins("replay"))
	assert.Equal(t, []string{"--target"}, pins("scan-request"))
	assert.Equal(t, []string{"--origin"}, pins("kit unlock-walk"))

	// A reach flag carries its shorthand, so `replay -a` reads as `--all`.
	assert.Contains(t, rows["replay"]["reach_flags"], map[string]any{"flag": "--all", "short": "-a", "reach": "unbounded"})
	assert.Contains(t, rows["fuzz"]["reach_flags"], map[string]any{"flag": "--record-uuid", "short": "-u", "reach": "store"})
	assert.Empty(t, pins("scan"), "scan -t adds a target; it does not pin the others")
}

// explain-argv resolves one line: command, targets, reach and the flag that
// set it, without running it.
func TestExplainArgvResolvesLines(t *testing.T) {
	root := preparedMachineTree(t)
	t.Setenv(pinnedEnvVar, "")
	cases := []struct {
		name    string
		argv    []string
		command string
		phase   string
		reach   string
		reachBy string
		targets []explainedTarget
	}{
		{"scan-url positional", []string{"scan-url", "https://app.test/login"}, "scan-url", "", "line", "",
			[]explainedTarget{{"https://app.test/login", "url", "positional"}}},
		{"scan-url include-stored", []string{"scan-url", "-t", "https://app.test/a", "--include-stored"}, "scan-url", "", "store", "--include-stored",
			[]explainedTarget{{"https://app.test/a", "url", "--target"}}},
		{"root flag first", []string{"--db", "/tmp/x.sqlite", "scan-url", "https://app.test/"}, "scan-url", "", "line", "",
			[]explainedTarget{{"https://app.test/", "url", "positional"}}},
		{"fuzz record", []string{"fuzz", "-u", "abcdef12", "-t", "https://staging.test"}, "fuzz", "", "store", "--record-uuid",
			[]explainedTarget{{"https://staging.test", "url", "--target"}, {"abcdef12", "record_uuid", "--record-uuid"}}},
		{"replay all", []string{"replay", "--host", "app.test", "--all"}, "replay", "", "unbounded", "--all",
			[]explainedTarget{{"app.test", "host", "--host"}}},
		{"fingerprint each", []string{"fingerprint", "https://a.test", "https://b.test"}, "fingerprint", "", "line", "",
			[]explainedTarget{{"https://a.test", "url", "positional"}, {"https://b.test", "url", "positional"}}},
		{"param-mine positional", []string{"kit", "param-mine", "https://app.test/api"}, "kit param-mine", "", "line", "",
			[]explainedTarget{{"https://app.test/api", "url", "positional"}}},
		{"unlock-walk origin", []string{"kit", "unlock-walk", "--profile", "p.json", "--origin", "https://app.test"}, "kit unlock-walk", "", "line", "",
			[]explainedTarget{{"p.json", "file", "--profile"}, {"https://app.test", "url", "--origin"}}},
		{"run alias and phase alias", []string{"r", "dast", "-t", "https://app.test"}, "run", "dynamic-assessment", "line", "",
			[]explainedTarget{{"https://app.test", "url", "--target"}}},
		{"scan all-records", []string{"scan", "--all-records"}, "scan", "", "unbounded", "--all-records", []explainedTarget{}},
		{"dry run", []string{"scan", "-t", "https://app.test", "--dry-run"}, "scan", "", "none", "--dry-run",
			[]explainedTarget{{"https://app.test", "url", "--target"}}},
		{"help", []string{"scan-url", "--help"}, "scan-url", "", "none", "--help", []explainedTarget{}},
		{"traffic replay", []string{"traffic", "--host", "app.test", "--replay"}, "traffic", "", "store", "--replay",
			[]explainedTarget{{"app.test", "host", "--host"}}},
		{"store read", []string{"hosts", "app.test"}, "hosts", "", "none", "", []explainedTarget{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := explainArgv(root, c.argv)
			require.True(t, v.Parses, v.Error)
			assert.Equal(t, c.command, v.Command)
			assert.Equal(t, c.phase, v.Phase)
			assert.Equal(t, c.reach, v.Reach)
			assert.Equal(t, c.reachBy, v.ReachBy)
			assert.Equal(t, c.targets, v.Targets)
			assert.False(t, v.Pinned)
			assert.Empty(t, v.Refusals)
		})
	}
}

// A line explained leaves the tree as it found it: a flag set on one line is
// not set on the next.
func TestExplainArgvRestoresFlags(t *testing.T) {
	root := preparedMachineTree(t)
	require.Equal(t, "store", explainArgv(root, []string{"scan-url", "https://a.test", "--include-stored"}).Reach)
	v := explainArgv(root, []string{"scan-url", "https://a.test"})
	assert.Equal(t, "line", v.Reach)
	assert.Equal(t, []explainedTarget{{"https://a.test", "url", "positional"}}, v.Targets)
}

// A line that does not parse sends nothing.
func TestExplainArgvUnparsedLine(t *testing.T) {
	root := preparedMachineTree(t)
	for _, argv := range [][]string{
		{"scan-url", "--no-such-flag"},
		{"run", "not-a-phase"},
		{"run", "seed"},
		{"scan-url", "a", "b"},
	} {
		v := explainArgv(root, argv)
		assert.False(t, v.Parses, "%v", argv)
		assert.NotEmpty(t, v.Error)
		assert.Equal(t, "none", v.Reach)
	}
}

// A tool shim's line is explained as the native line it translates to.
func TestExplainArgvShim(t *testing.T) {
	root := preparedMachineTree(t)
	v := explainArgv(root, []string{"nuclei", "-u", "https://app.test"})
	require.True(t, v.Parses, v.Error)
	assert.Equal(t, "nuclei", v.TranslatedFrom)
	assert.Equal(t, "run", v.Command)
	assert.Equal(t, "known-issue-scan", v.Phase)
	assert.Equal(t, "line", v.Reach)
	assert.Contains(t, v.Targets, explainedTarget{"https://app.test", "url", "--target"})
}

// Under VIGOLIUM_PINNED=1 explain-argv reports what the pin refuses on the
// line, with the corrected line, through the same check the pin runs.
func TestExplainArgvPinnedRefusal(t *testing.T) {
	root := preparedMachineTree(t)
	_, cfg := pinnedHome(t)
	t.Setenv(pinnedEnvVar, "1")
	t.Setenv(configEnvVar, cfg)
	t.Setenv(dbPathEnvVar, filepath.Join(t.TempDir(), "pinned.sqlite"))

	v := explainArgv(root, []string{"scan-url", "https://app.test", "--ignore-scope", "--max-module-tier", "heavy"})
	require.True(t, v.Parses, v.Error)
	assert.True(t, v.Pinned)
	require.Len(t, v.Refusals, 2)
	assert.Contains(t, v.Refusals[0], "--ignore-scope widens the pinned session")
	assert.Contains(t, v.Refusals[1], "--max-module-tier heavy")
	assert.Equal(t, "vigolium scan-url https://app.test", v.Hint)

	ok := explainArgv(root, []string{"scan-url", "https://app.test"})
	assert.True(t, ok.Pinned)
	assert.Empty(t, ok.Refusals)

	stop := explainArgv(root, []string{"scan", "stop", "abcdef12"})
	require.Len(t, stop.Refusals, 1)
	assert.Contains(t, stop.Hint, "cannot stop another scan")
}

// The real binary: `explain-argv -j -- <line>` exits 0 with the object, even
// for a line the pin refuses, and sends nothing.
func TestExplainArgvEndToEnd(t *testing.T) {
	home, cfg := pinnedHome(t)
	env := []string{"VIGOLIUM_PINNED=1", "VIGOLIUM_CONFIG=" + cfg, "VIGOLIUM_DB_PATH=" + filepath.Join(t.TempDir(), "p.sqlite")}
	code, stdout, stderr := runWithEnv(t, home, env, "explain-argv", "-j", "--", "scan-url", "http://127.0.0.1:9/x", "--ignore-scope")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1)
	raw, _ := json.Marshal(docs[0]["items"].([]any)[0])
	var v explainArgvView
	require.NoError(t, json.Unmarshal(raw, &v))
	assert.Equal(t, "scan-url", v.Command)
	assert.Equal(t, "line", v.Reach)
	assert.True(t, v.Pinned)
	require.Len(t, v.Refusals, 1)
	assert.Equal(t, "vigolium scan-url http://127.0.0.1:9/x", v.Hint)
}

// `schema block-signatures -j` rows are the classifier's table, round-trip.
func TestSchemaBlockSignaturesRoundTrip(t *testing.T) {
	preparedMachineTree(t)
	doc := emitCaptured(t, func() error { return runSchemaBlockSignatures(schemaBlockSignaturesCmd, nil) })
	raw, err := json.Marshal(doc["items"])
	require.NoError(t, err)
	var rows []waf.Signature
	require.NoError(t, json.Unmarshal(raw, &rows))
	assert.Equal(t, waf.Signatures, rows)
	ids := map[string]bool{}
	for _, r := range rows {
		assert.False(t, ids[r.ID], "duplicate id %s", r.ID)
		ids[r.ID] = true
	}
	assert.True(t, ids["imperva.block.incapsula-resource"])
	assert.True(t, ids["cloudflare.challenge.cf-mitigated"])
}
