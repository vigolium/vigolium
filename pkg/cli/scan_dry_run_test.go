package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/contract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanplan"
)

// scan --dry-run resolves and prints the plan with no side effect beyond
// reading an existing database. Each case re-execs the test binary as the real
// CLI (runA3) in a throwaway HOME against a counting local server.

// dryRunDoc is the -j document of a dry run.
type dryRunDoc struct {
	Command string           `json:"command"`
	Kind    string           `json:"kind"`
	OK      bool             `json:"ok"`
	DryRun  bool             `json:"dry_run"`
	Total   int              `json:"total"`
	Items   []scanplan.Phase `json:"items"`
	Plan    *scanplan.Plan   `json:"plan"`
	DBPath  string           `json:"db_path"`
}

func decodeDryRunDoc(t *testing.T, stdout string) dryRunDoc {
	t.Helper()
	var doc dryRunDoc
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc), "stdout must be one JSON document:\n%s", stdout)
	return doc
}

// seedDryRunDB creates a schema-ready store at path and returns its mtime and
// size once closed.
func seedDryRunDB(t *testing.T, path string) (time.Time, int64) {
	t.Helper()
	cfg := config.DefaultSettings().Database
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = path
	db, err := database.NewDB(&cfg)
	require.NoError(t, err)
	require.NoError(t, db.EnsureSchemaReady(context.Background()))
	require.NoError(t, db.Close())
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.ModTime(), info.Size()
}

func countScanRows(t *testing.T, path string) int {
	t.Helper()
	n, err := a3Repo(t, path).DB().NewSelect().Model((*database.Scan)(nil)).Count(context.Background())
	require.NoError(t, err)
	return int(n)
}

// TestScanDryRunHasNoSideEffects: a dry run with discovery fuzzing on, the
// large wordlist tier and an output file requested sends nothing, writes no output
// file, materializes no wordlist, creates no scan row and leaves the database
// file untouched — and prints the plan as one -j document.
func TestScanDryRunHasNoSideEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := countingServer(t)
	home := a3Home(t, "*")
	// The large tier and (via --only discovery) fuzzing: every embedded list a
	// real run would materialize.
	cfgPath := filepath.Join(home, ".vigolium", "vigolium-configs.yaml")
	cfg, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, append(cfg, []byte("discovery:\n  wordlists:\n    tier: large\n")...), 0o600))
	dbPath := filepath.Join(home, "plan.sqlite")
	mtime, size := seedDryRunDB(t, dbPath)
	time.Sleep(20 * time.Millisecond) // an mtime change must be visible
	out := filepath.Join(home, "out", "x.jsonl")

	code, stdout, stderr := runA3(t, home, "scan", "-t", srv.URL+"/", "--dry-run", "-j",
		"--db", dbPath, "-o", out, "--format", "jsonl", "--only", "discovery,dast")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	assert.Zero(t, hits.Load(), "a dry run must not contact the target")
	_, err = os.Stat(out)
	assert.True(t, os.IsNotExist(err), "dry run wrote the output file")
	_, err = os.Stat(filepath.Join(home, ".vigolium", "wordlists"))
	assert.True(t, os.IsNotExist(err), "dry run materialized the wordlists")
	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, mtime, info.ModTime(), "dry run modified the database file")
	assert.Equal(t, size, info.Size(), "dry run modified the database file")
	assert.Zero(t, countScanRows(t, dbPath), "dry run created a scan row")

	doc := decodeDryRunDoc(t, stdout)
	// Every key the document carries is in its published schema mirror.
	var keys map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &keys))
	published := map[string]bool{}
	for _, k := range append(contract.JSONFieldNames(scanDryRunDocSchema{}), contract.JSONFieldNames(contract.EnvelopeCommon{})...) {
		published[k] = true
	}
	for k := range keys {
		assert.True(t, published[k], "dry-run key %q missing from scanDryRunDocSchema", k)
	}
	assert.Equal(t, "scan", doc.Command)
	assert.Equal(t, "scan", doc.Kind)
	assert.True(t, doc.OK)
	assert.True(t, doc.DryRun)
	require.NotNil(t, doc.Plan)
	assert.Empty(t, doc.Plan.ScanUUID, "no scan uuid is minted")
	assert.True(t, doc.Plan.DryRun)
	assert.Equal(t, len(doc.Plan.Phases), doc.Total)
	assert.Equal(t, doc.Plan.Phases, doc.Items, "items are the plan's phases")
	assert.Equal(t, dbPath, doc.DBPath)
	require.NotNil(t, doc.Plan.Discovery)
	assert.True(t, doc.Plan.Discovery.Fuzzing)
	assert.Equal(t, config.WordlistTierLarge, doc.Plan.Discovery.WordlistTier)
	assert.Equal(t, 1, doc.Plan.Targets.Admitted)
	require.NotNil(t, doc.Plan.Targets.DBRecordsInScope)
	assert.Positive(t, doc.Plan.Estimate.High)
	assert.Equal(t, scanplan.ConfidenceRough, doc.Plan.Estimate.Confidence)
}

// TestRunPhaseDryRun: `run <phase> --dry-run` plans the one phase.
func TestRunPhaseDryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, hits := countingServer(t)
	home := a3Home(t, "*")

	code, stdout, stderr := runA3(t, home, "run", "discovery", "-t", srv.URL+"/", "--dry-run", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Zero(t, hits.Load())
	doc := decodeDryRunDoc(t, stdout)
	require.NotNil(t, doc.Plan)
	assert.Equal(t, "run", doc.Command)
	assert.True(t, doc.Plan.Phase("discovery").Enabled)
	da := doc.Plan.Phase("dynamic-assessment")
	assert.False(t, da.Enabled)
	assert.Equal(t, "only", da.DisabledBy)
}

// TestStoredScanPlan: the scan document's plan is the row's scans.plan.
func TestStoredScanPlan(t *testing.T) {
	assert.Nil(t, storedScanPlan(nil))
	assert.Nil(t, storedScanPlan(&database.Scan{}))
	raw, err := json.Marshal(&scanplan.Plan{SchemaVersion: scanplan.SchemaVersion, Strategy: "lite"})
	require.NoError(t, err)
	p := storedScanPlan(&database.Scan{Plan: raw})
	require.NotNil(t, p)
	assert.Equal(t, "lite", p.Strategy)
}

// TestRenderPlanHuman: the table names every phase and why each disabled one
// is off.
func TestRenderPlanHuman(t *testing.T) {
	ten := int64(10)
	p := &scanplan.Plan{
		DryRun: true, Strategy: "balanced", Heuristics: "basic",
		Phases: []scanplan.Phase{
			{ID: "discovery", Enabled: true, SendsTarget: true, Budget: &scanplan.PhaseBudget{PerTargetMS: 60000, Semantics: scanplan.SemanticsPerTarget, Source: scanplan.SourceFactor, DurationFactor: 0.5}},
			{ID: "spidering", DisabledBy: "skip", SendsTarget: true},
		},
		Targets:  scanplan.Targets{Seeded: 1, Admitted: 1, DBRecordsInScope: &ten},
		Estimate: scanplan.Estimate{Low: 5, High: 50, Confidence: scanplan.ConfidenceRough, ByPhase: map[string]scanplan.PhaseEstimate{"discovery": {Low: 5, High: 50}}},
		Warnings: []scanplan.Warning{{Code: "unbounded_discovery", Message: "x"}},
	}
	var b strings.Builder
	renderPlan(&b, p)
	out := b.String()
	for _, want := range []string{"dry run", "discovery", "1m0s/target [factor x0.5]", "5-50", "off: skip", "10 stored records", "unbounded_discovery"} {
		assert.Contains(t, out, want)
	}
}

// TestScanEventsPlanSecond: on a real (local) scan the stream opens with
// scan.started then scan.plan, and the row stores the same plan.
func TestScanEventsPlanSecond(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	srv, _ := countingServer(t)
	home := a3Home(t, "*")
	dbPath := filepath.Join(home, "events.sqlite")

	code, stdout, stderr := runA3(t, home, "scan", "-t", srv.URL+"/", "--only", "probe", "--events", "ndjson", "--db", dbPath)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.GreaterOrEqual(t, len(lines), 2, stdout)
	var first, second struct {
		Type     string         `json:"type"`
		ScanUUID string         `json:"scan_uuid"`
		Plan     *scanplan.Plan `json:"plan"`
	}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
	assert.Equal(t, "scan.started", first.Type)
	require.Equal(t, "scan.plan", second.Type, stdout)
	require.NotNil(t, second.Plan)
	assert.Equal(t, first.ScanUUID, second.Plan.ScanUUID)
	assert.True(t, second.Plan.Phase("probe").Enabled)

	row, err := a3Repo(t, dbPath).GetScanByUUID(context.Background(), first.ScanUUID)
	require.NoError(t, err)
	stored := storedScanPlan(row)
	require.NotNil(t, stored, "scans.plan not written")
	assert.Equal(t, second.Plan.EnabledPhaseIDs(), stored.EnabledPhaseIDs())
}
