package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/diagnostics"
)

// The read commands migrated from RAW JSON to the envelope (plan B4). Each test
// runs the command's own -j path and pins the contract every document now
// shares — one document, schema_version, the cobra command path, ok, kind, and
// items as an array — plus the scalar keys each command kept at the top level.

// requireEnvelope asserts the shared contract and returns items.
func requireEnvelope(t *testing.T, doc map[string]any, command, kind string) []any {
	t.Helper()
	require.EqualValues(t, AgentSchemaVersion, doc["schema_version"], "schema_version")
	require.Equal(t, command, doc["command"], "command must be the cobra path")
	require.Equal(t, true, doc["ok"], "ok")
	require.Equal(t, kind, doc["kind"], "kind")
	items, ok := doc["items"].([]any)
	require.True(t, ok, "items must be an array, got %T: %v", doc["items"], doc["items"])
	if kind == string(kindMutation) {
		require.Contains(t, doc, "changed", "a mutation document always says whether it changed state")
		require.NotEmpty(t, doc["action"], "a mutation document names its action")
	}
	validateRegisteredMap(t, doc)
	return items
}

// legacyKeys turns --json-legacy-keys on for one test.
func legacyKeys(t *testing.T) {
	t.Helper()
	swapGlobal(t, &globalJSONLegacyKeys, true)
}

func TestModuleLsJSONEnvelope(t *testing.T) {
	opts := &moduleOptions{ModuleType: "all"}
	doc := emitCaptured(t, func() error { return printModuleJSON(moduleLsCmd, opts, "") })
	items := requireEnvelope(t, doc, "module ls", "read")
	require.NotEmpty(t, items)
	require.EqualValues(t, len(items), doc["total"])
	active, passive := doc["active_count"].(float64), doc["passive_count"].(float64)
	require.EqualValues(t, len(items), active+passive, "the per-type counts stay at the top level")
	require.NotContains(t, doc, "modules", "the legacy row alias is off by default")

	legacyKeys(t)
	doc = emitCaptured(t, func() error { return printModuleJSON(moduleLsCmd, opts, "") })
	require.Len(t, doc["modules"], len(items), "--json-legacy-keys renders the old `modules` array")
}

func TestVersionJSONEnvelope(t *testing.T) {
	doc := emitCaptured(t, func() error { return printVersionJSON(versionCmd) })
	items := requireEnvelope(t, doc, "version", "read")
	require.Len(t, items, 1)
	info := items[0].(map[string]any)
	require.NotEmpty(t, info["version"])
	require.Contains(t, info, "db_schema_version")

	legacyKeys(t)
	doc = emitCaptured(t, func() error { return printVersionJSON(versionCmd) })
	require.Equal(t, info["version"], doc["version"], "\".\" flattens the bare object back to the top level")
}

func TestSkillsListAndGetJSONEnvelope(t *testing.T) {
	doc := emitCaptured(t, func() error { return runSkillsList(skillsListCmd) })
	items := requireEnvelope(t, doc, "skills list", "read")
	require.NotEmpty(t, items)
	first := items[0].(map[string]any)
	require.NotEmpty(t, first["name"])

	swapGlobal(t, &skillsOpts.Full, true)
	swapGlobal(t, &skillsOpts.All, false)
	name := first["name"].(string)
	doc = emitCaptured(t, func() error { return runSkillsGet(skillsGetCmd, []string{name}) })
	items = requireEnvelope(t, doc, "skills get", "read")
	require.Len(t, items, 1)
	skill := items[0].(map[string]any)
	require.Equal(t, name, skill["name"])
	require.NotEmpty(t, skill["content"], "-j carries the SKILL.md markdown as content")
	refs, ok := skill["references"].([]any)
	require.True(t, ok, "--full includes references: %v", skill)
	for _, r := range refs {
		ref := r.(map[string]any)
		require.NotEmpty(t, ref["path"])
		require.NotEmpty(t, ref["content"])
	}
}

func TestKitPayloadJSONEnvelope(t *testing.T) {
	swapGlobal(t, &kitPayloadList, false)
	swapGlobal(t, &kitPayloadClasses, []string{"sqli"})
	doc := emitCaptured(t, func() error { return runKitPayload(kitPayloadCmd, nil) })
	items := requireEnvelope(t, doc, "kit payload", "read")
	require.NotEmpty(t, items)
	require.EqualValues(t, len(items), doc["count"], "count stays at the top level")
	require.Equal(t, []any{"sqli"}, doc["classes"])

	swapGlobal(t, &kitPayloadList, true)
	doc = emitCaptured(t, func() error { return runKitPayload(kitPayloadCmd, nil) })
	require.NotEmpty(t, requireEnvelope(t, doc, "kit payload", "read"), "--list rows are the class names")
}

func TestKitWordlistJSONEnvelope(t *testing.T) {
	doc := emitCaptured(t, func() error { return runKitWordlist(kitWordlistCmd, nil) })
	items := requireEnvelope(t, doc, "kit wordlist", "read")
	require.NotEmpty(t, items)
	require.Contains(t, items[0], "entries")

	doc = emitCaptured(t, func() error { return runKitWordlist(kitWordlistCmd, []string{"jwt"}) })
	items = requireEnvelope(t, doc, "kit wordlist", "read")
	require.NotEmpty(t, items)
	require.Equal(t, "jwt.secrets.list", doc["name"])
	require.EqualValues(t, len(items), doc["count"])
}

func TestKitSecretScanJSONEnvelope(t *testing.T) {
	token := "ghp_R8vKq2" + "LmZ7xTn4Wp" + "C9sYb3HjD6" + "fGa1QeUo5N"
	file := filepath.Join(t.TempDir(), "leak.js")
	require.NoError(t, os.WriteFile(file, []byte(`const gh = "`+token+`";`+"\n"), 0o600))
	swapGlobal(t, &kitSecretFailOnMatch, false)

	doc := emitCaptured(t, func() error { return runKitSecretScan(kitSecretScanCmd, []string{file}) })
	items := requireEnvelope(t, doc, "kit secret-scan", "read")
	require.NotEmpty(t, items, "the matches are the rows")
	require.EqualValues(t, len(items), doc["count"])
	require.EqualValues(t, 1, doc["files_scanned"])
}

func TestKitJWTCrackJSONEnvelope(t *testing.T) {
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString([]byte(`{"sub":"1"}`))
	mac := hmac.New(sha256.New, []byte("b4-inline-secret"))
	mac.Write([]byte(signing))
	token := signing + "." + enc.EncodeToString(mac.Sum(nil))

	swapGlobal(t, &kitJWTSecrets, []string{"b4-inline-secret"})
	swapGlobal(t, &kitJWTWordlist, "")
	swapGlobal(t, &kitJWTFailOnCrack, false)
	doc := emitCaptured(t, func() error { return runKitJWTCrack(kitJWTCrackCmd, []string{token}) })
	items := requireEnvelope(t, doc, "kit jwt-crack", "read")
	require.Len(t, items, 1)
	res := items[0].(map[string]any)
	require.Equal(t, true, res["cracked"])
	require.Equal(t, "b4-inline-secret", res["secret"])
}

func TestKitHarvestEnvelopeCarriesStatsAndLimits(t *testing.T) {
	env, err := envelopeFromStruct(kitHarvestCmd, kitHarvestResult{
		Domains: []string{"a.test"},
		Sources: []string{"wayback"},
		Count:   1,
		URLs:    []string{"http://a.test/x"},
		Stats:   kitHarvestStats{Raw: 3, Kept: 1, Duplicate: 2},
		Limits:  []string{"cdx_max_rows"},
	}, "urls")
	require.NoError(t, err)
	doc := emitCaptured(t, func() error { return writeAgentJSON(env) })
	items := requireEnvelope(t, doc, "kit harvest", "read")
	require.Equal(t, []any{"http://a.test/x"}, items)
	stats, ok := doc["stats"].(map[string]any)
	require.True(t, ok, "stats object: %v", doc)
	require.EqualValues(t, 3, stats["raw"])
	require.EqualValues(t, 2, stats["duplicate"])
	require.Equal(t, []any{"cdx_max_rows"}, doc["limits"])
	require.EqualValues(t, 1, doc["count"])
}

// A producer that never closes stdin must not hang `kit harvest -`: the shared
// bounded reader gives up at --input-read-timeout.
func TestKitHarvestStdinBounded(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	_, err = w.WriteString("a.test\n") // some data, then silence: the pipe stays open
	require.NoError(t, err)
	swapGlobal(t, &os.Stdin, r)
	swapGlobal(t, &globalInputReadTimeout, 200*time.Millisecond)

	done := make(chan error, 1)
	go func() {
		_, err := kitCollectDomains([]string{"-"})
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err, "an unterminated stdin must fail at the read deadline")
	case <-time.After(10 * time.Second):
		t.Fatal("kit harvest stdin read did not honour --input-read-timeout")
	}
}

func TestDoctorJSONEnvelope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	swapGlobal(t, &globalConfig, "")
	swapGlobal(t, &globalDB, filepath.Join(home, "doctor.sqlite"))
	swapGlobal(t, &doctorFix, false)
	swapGlobal(t, &doctorOnly, nil)
	swapGlobal(t, &doctorStrict, false)
	swapGlobal(t, &doctorRunDiagnostics, func(diagnostics.Deps) *diagnostics.Report {
		return &diagnostics.Report{Status: "degraded", Timestamp: "t"}
	})
	t.Cleanup(resetDBCacheForTest)

	doc := emitCaptured(t, func() error { return runDoctorCmd(doctorCmd, nil) })
	items := requireEnvelope(t, doc, "doctor", "read")
	require.NotEmpty(t, items, "items are the flat checks")
	for _, it := range items {
		require.Contains(t, it, "id")
		require.Contains(t, it, "status")
	}
	require.Equal(t, "degraded", doc["status"], "the verdict is copied up for a branch without indexing")
	require.Contains(t, doc, "capabilities")

	legacyKeys(t)
	doc = emitCaptured(t, func() error { return runDoctorCmd(doctorCmd, nil) })
	require.Equal(t, "t", doc["timestamp"], "\".\" flattens the bare report back to the top level")
}

func TestJSEvalJSONEnvelope(t *testing.T) {
	doc := emitCaptured(t, func() error { return emitJSEvalResult(jsCmd, `{"a":1}`) })
	items := requireEnvelope(t, doc, "js", "read")
	require.Len(t, items, 1)
	require.Equal(t, map[string]any{"a": float64(1)}, items[0].(map[string]any)["value"],
		"the return value is embedded as JSON, not as a string")

	doc = emitCaptured(t, func() error { return emitJSEvalResult(jsCmd, "") })
	items = requireEnvelope(t, doc, "js", "read")
	require.Contains(t, items[0], "value")
	require.Nil(t, items[0].(map[string]any)["value"], "undefined/null returns value:null")
}

func TestIngestJSONIsMutation(t *testing.T) {
	doc := emitCaptured(t, func() error {
		return reportIngest(ingestOutcome{Submitted: 3, Errors: 1}, true, 0, 1, time.Second)
	})
	requireEnvelope(t, doc, "ingest", "mutation")
	require.Equal(t, true, doc["changed"])
	require.Equal(t, "submit", doc["action"])
	require.EqualValues(t, 3, doc["records_submitted"], "remote counters stay at the top level")
	require.EqualValues(t, 1, doc["errors"])

	doc = emitCaptured(t, func() error {
		return reportIngest(ingestOutcome{Stored: 2}, false, 0, 1, time.Second)
	})
	requireEnvelope(t, doc, "ingest", "mutation")
	require.Equal(t, "ingest", doc["action"])
	require.EqualValues(t, 2, doc["records_ingested"])
}

func TestFindingLoadJSONIsMutation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	swapGlobal(t, &globalDB, filepath.Join(dir, "load.sqlite"))
	resetDBCacheForTest()
	t.Cleanup(resetDBCacheForTest)
	src := filepath.Join(dir, "finding.json")
	require.NoError(t, os.WriteFile(src,
		[]byte(`{"title":"B4 test finding","severity":"high","url":"http://a.test/"}`), 0o600))

	doc := emitCaptured(t, func() error { return runFindingLoad(findingLoadCmd, []string{src}) })
	items := requireEnvelope(t, doc, "finding load", "mutation")
	require.Equal(t, true, doc["changed"])
	require.Len(t, items, 1, "items are the stored finding ids")
	require.EqualValues(t, 1, doc["parsed"])
	require.EqualValues(t, 1, doc["saved"])
	require.EqualValues(t, 0, doc["skipped"])
}

func TestProjectListJSONEnvelope(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	swapGlobal(t, &globalDB, filepath.Join(dir, "projects.sqlite"))
	resetDBCacheForTest()
	t.Cleanup(resetDBCacheForTest)
	require.Nil(t, projectListCmd.LocalNonPersistentFlags().Lookup("json"),
		"the local --json shadowed the global -j; it must stay deleted")

	doc := emitCaptured(t, func() error { return projectListCmd.RunE(projectListCmd, nil) })
	items := requireEnvelope(t, doc, "project list", "read")
	require.EqualValues(t, len(items), doc["total"])
}

func TestStorageCommandsHaveNoLocalJSONFlag(t *testing.T) {
	require.Nil(t, storageLsCmd.LocalNonPersistentFlags().Lookup("json"))
	require.Nil(t, storagePresignCmd.LocalNonPersistentFlags().Lookup("json"))
}
