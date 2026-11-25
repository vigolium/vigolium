package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/work"
)

// stdoutItems decodes the one -j document on stdout and returns its items.
func stdoutItems(t *testing.T, stdout string) ([]map[string]any, map[string]any) {
	t.Helper()
	docs := decodeStdoutDocuments(t, stdout)
	require.Len(t, docs, 1, stdout)
	raw, _ := json.Marshal(docs[0]["items"])
	var items []map[string]any
	require.NoError(t, json.Unmarshal(raw, &items))
	return items, docs[0]
}

// A phase-qualified pace flag or --set naming a pair the phase does not
// enforce is refused with pace_unsupported naming the pairs that bind; an
// enforced pair passes.
func TestRefuseUnboundPaceFlags(t *testing.T) {
	require.NoError(t, refuseUnboundPaceFlags())

	withPaceKnob(t, rateLimitKnob, "known-issue-scan", 20)
	withPaceKnob(t, maxPerHostKnob, "probe", 3)
	require.NoError(t, refuseUnboundPaceFlags(), "enforced pairs bind")

	withPaceKnob(t, rateLimitKnob, "spidering", 5)
	err := refuseUnboundPaceFlags()
	var ce clicommon.CLIError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, apicontract.CodePaceUnsupported, ce.ErrorCode())
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
	assert.Contains(t, ce.Fact(), "--rate-limit spidering=5")
	assert.NotContains(t, ce.Fact(), "known-issue-scan", "only the refused pair is named as refused")
	assert.Contains(t, ce.Hint, "known-issue-scan=rate_limit")
	assert.Contains(t, ce.Hint, "schema pace")
}

func TestRefuseUnboundPaceSetOverlay(t *testing.T) {
	withSetOverlay(t, "scanning_pace.probe.max_per_host=3", "spidering.max_depth=2")
	require.NoError(t, refuseUnboundPaceFlags(), "an enforced pair and a non-pace key pass")

	withSetOverlay(t, "scanning_pace.dynamic-assessment.rate_limit=9")
	err := refuseUnboundPaceFlags()
	var ce clicommon.CLIError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, apicontract.CodePaceUnsupported, ce.ErrorCode())
	assert.Contains(t, ce.Fact(), "dynamic-assessment.rate_limit")
}

// withSetOverlay installs raw as this invocation's --set overlay, as the root
// command's installConfigOverlay does before refuseUnboundPaceFlags runs.
func withSetOverlay(t *testing.T, raw ...string) {
	t.Helper()
	swapGlobal(t, &globalSetOverlay, raw)
	entries, err := config.ParseOverlay(raw)
	require.NoError(t, err)
	config.SetProcessOverlay(entries)
	t.Cleanup(func() { config.SetProcessOverlay(nil) })
}

// End to end: the refusal is the -j error envelope, exit 2, before any scan.
func TestPaceUnsupportedExitsTwo(t *testing.T) {
	home, _ := pinnedHome(t)
	code, stdout, stderr := runWithEnv(t, home, nil, "scan", "--dry-run", "-t", "http://127.0.0.1:9", "-j", "--max-per-host", "spidering=4")
	require.Equal(t, ExitUsageError, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodePaceUnsupported), errorCode(t, stdout))

	code, stdout, stderr = runWithEnv(t, home, nil, "scan", "--dry-run", "-t", "http://127.0.0.1:9", "-j", "--rate-limit", "known-issue-scan=20")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
}

// `schema pace -j` lists every (phase, dial) pair with the flag and whether it
// binds, from the same table the refusal reads.
func TestSchemaPaceRows(t *testing.T) {
	home, _ := pinnedHome(t)
	code, stdout, stderr := runWithEnv(t, home, nil, "schema", "pace", "-j")
	require.Equal(t, 0, code, stderr)
	items, _ := stdoutItems(t, stdout)
	require.Len(t, items, len(config.PhaseSectionNames())*len(config.PaceFields))
	got := map[string]bool{}
	for _, it := range items {
		got[it["phase"].(string)+"/"+it["flag"].(string)] = it["enforced"].(bool)
	}
	assert.False(t, got["spidering/--rate-limit"])
	assert.True(t, got["probe/--max-per-host"])
	assert.True(t, got["known-issue-scan/--rate-limit"])
	assert.False(t, got["dynamic-assessment/--max-per-host"])
}

// `schema storage --ddl` prints the store's DDL one ;-terminated statement per
// line without opening a store; -j carries {schema_version, statements}.
func TestSchemaStorageDDL(t *testing.T) {
	home, _ := pinnedHome(t)
	code, stdout, stderr := runWithEnv(t, home, nil, "schema", "storage", "--ddl")
	require.Equal(t, 0, code, stderr)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	want := database.FreshSchemaDDL()
	require.Len(t, lines, len(want)+1, "a version comment, then one line per statement")
	for i, s := range want {
		assert.Equal(t, s+";", lines[i+1])
	}
	_, err := os.Stat(filepath.Join(home, ".vigolium", "database-vgnm.sqlite"))
	assert.True(t, os.IsNotExist(err), "--ddl opens no store")

	code, stdout, stderr = runWithEnv(t, home, nil, "schema", "storage", "--ddl", "-j")
	require.Equal(t, 0, code, stderr)
	items, _ := stdoutItems(t, stdout)
	require.Len(t, items, 1)
	assert.EqualValues(t, database.CurrentSchemaVersion(), items[0]["schema_version"])
	stmts, _ := items[0]["statements"].([]any)
	assert.Len(t, stmts, len(want))

	code, _, _ = runWithEnv(t, home, nil, "schema", "storage", "--ddl", "http_records")
	assert.Equal(t, ExitUsageError, code, "--ddl takes no table")
}

// --set overlays one key for the invocation (config get reports it with
// source "set"), leaves the file alone, and an unknown key is a usage error
// naming it.
func TestConfigOverlayFlag(t *testing.T) {
	home, cfg := pinnedHome(t)
	before, err := os.ReadFile(cfg)
	require.NoError(t, err)

	code, stdout, stderr := runWithEnv(t, home, nil, "config", "get", "scanning_pace.rate_limit", "--set", "scanning_pace.rate_limit=7", "-j")
	require.Equal(t, 0, code, stderr)
	items, _ := stdoutItems(t, stdout)
	require.Len(t, items, 1)
	assert.EqualValues(t, 7, items[0]["value"])
	assert.Equal(t, config.SourceSet, items[0]["source"])

	after, err := os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "--set never writes the file")

	// A command that writes the config takes no overlay: it would persist it.
	code, stdout, _ = runWithEnv(t, home, nil, "config", "set", "scanning_pace.concurrency", "3", "--set", "scope.host.include=[a.example]", "-j")
	require.Equal(t, ExitUsageError, code)
	assert.Equal(t, string(apicontract.CodeUsageError), errorCode(t, stdout))
	after, err = os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))

	code, stdout, _ = runWithEnv(t, home, nil, "config", "ls", "--set", "nope.not_a_key=1", "-j")
	require.Equal(t, ExitUsageError, code)
	assert.Equal(t, string(apicontract.CodeUsageError), errorCode(t, stdout))
	assert.Contains(t, stdout, "nope.not_a_key")
}

// seedCoverageStore writes one scan with a two-module coverage ledger over two
// records and a module ledger, and returns the store path and scan uuid.
func seedCoverageStore(t *testing.T) (string, string) {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "cov.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, db.EnsureSchemaReady(ctx))
	repo := database.NewRepository(db)
	const scan = "5c0e1b2a-3d4e-4f50-8a61-72b3c4d5e6f7"
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: scan, ProjectUUID: database.DefaultProjectUUID, Status: "completed"}))
	require.NoError(t, repo.SetScanCoverageModules(ctx, scan, []string{"xss", "sqli"}))
	require.NoError(t, repo.UpdateScanPartial(ctx, &database.Scan{UUID: scan, ModuleStats: map[string]database.ModuleStat{
		"xss": {Invocations: 2, Requests: 5, Findings: 1, Skips: map[string]int64{database.SkipTechFilter: 1}},
	}}))
	w := database.NewProgressWriter(repo)
	r1, r2 := work.Coverage{}, work.Coverage{}
	r1.SetModuleDone(0)
	r2.SetModuleDone(1)
	w.Write(database.ScanRecordProgress{ScanUUID: scan, RecordUUID: "rec-1", ProjectUUID: database.DefaultProjectUUID, DoneBits: r1.DoneBits})
	w.Write(database.ScanRecordProgress{ScanUUID: scan, RecordUUID: "rec-2", ProjectUUID: database.DefaultProjectUUID, DoneBits: r2.DoneBits})
	w.Close()
	require.NoError(t, db.Close())
	return cfg.SQLite.Path, scan
}

// `scan coverage <uuid> -j` decodes done_bits into (record, module) cells,
// paged by -n/--offset; `scan status -j` carries module_stats.
func TestScanCoverageAndModuleStatsReads(t *testing.T) {
	home, _ := pinnedHome(t)
	dbPath, scan := seedCoverageStore(t)

	code, stdout, stderr := runWithEnv(t, home, nil, "scan", "coverage", scan, "-j", "--db", dbPath)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	items, doc := stdoutItems(t, stdout)
	assert.EqualValues(t, 4, doc["total"])
	cells := make([]string, 0, len(items))
	for _, it := range items {
		cells = append(cells, it["record_uuid"].(string)+"/"+it["module_id"].(string)+"/"+map[bool]string{true: "done", false: "open"}[it["done"].(bool)])
	}
	assert.Equal(t, []string{"rec-1/xss/done", "rec-1/sqli/open", "rec-2/xss/open", "rec-2/sqli/done"}, cells)

	code, stdout, stderr = runWithEnv(t, home, nil, "scan", "coverage", scan[:8], "-j", "-n", "1", "--offset", "1", "--db", dbPath)
	require.Equal(t, 0, code, stderr)
	items, doc = stdoutItems(t, stdout)
	require.Len(t, items, 1)
	assert.Equal(t, "rec-1", items[0]["record_uuid"])
	assert.Equal(t, "sqli", items[0]["module_id"])
	assert.EqualValues(t, 4, doc["total"])

	code, stdout, _ = runWithEnv(t, home, nil, "scan", "coverage", "0badc0de-0000-4000-8000-000000000000", "-j", "--db", dbPath)
	assert.Equal(t, ExitError, code)
	assert.Equal(t, string(apicontract.CodeScanNotFound), errorCode(t, stdout))

	code, stdout, stderr = runWithEnv(t, home, nil, "scan", "status", scan, "-j", "--db", dbPath)
	require.Equal(t, 0, code, stderr)
	items, _ = stdoutItems(t, stdout)
	require.Len(t, items, 1)
	stats, ok := items[0]["module_stats"].(map[string]any)
	require.True(t, ok, "scan status carries module_stats: %s", stdout)
	xss := stats["xss"].(map[string]any)
	assert.EqualValues(t, 5, xss["requests"])
	assert.EqualValues(t, 1, xss["skips"].(map[string]any)["tech_filter"])

	tr, ok := commandTraits["scan coverage"]
	require.True(t, ok)
	assert.False(t, tr.SendsTraffic)
}

// scan.finished carries the stored module ledger as module_stats.
func TestScanFinishedCarriesModuleStats(t *testing.T) {
	ev := &scanevents.Event{Type: scanevents.TypeScanFinished, Status: scanevents.StatusCompleted}
	applyScanCompletion(ev, &database.Scan{ModuleStats: map[string]database.ModuleStat{
		"sqli": {Invocations: 3, Requests: 7, Errors: 1, Skips: map[string]int64{database.SkipTimeout: 2}},
	}})
	require.Contains(t, ev.ModuleStats, "sqli")
	assert.Equal(t, scanevents.ModuleStat{Invocations: 3, Requests: 7, Errors: 1, Skips: map[string]int64{"timeout": 2}}, ev.ModuleStats["sqli"])

	ev = &scanevents.Event{Type: scanevents.TypeScanFinished, Status: scanevents.StatusCompleted}
	applyScanCompletion(ev, &database.Scan{})
	assert.Nil(t, ev.ModuleStats, "no ledger, no key")
}
