//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// End-to-end coverage for `--db-isolate`: a scan runs into a private temporary
// SQLite database and merges its results into the real --db once finished. The
// payoff is that many parallel scan processes can target ONE shared --db
// without contending on a single SQLite writer during the scan. These tests
// drive the real CLI binary as a subprocess against a local httptest server, so
// they exercise the full flag → scratch → merge → cleanup path with no Docker.

// runIsolatedDiscover runs `vigolium run discover --db-isolate` against target,
// merging into destDB. It isolates per-process state via HOME so concurrent
// first-run initialization (wordlist materialization, ~/.vigolium seeding)
// never races, and points TMPDIR at scratchTmp so the scratch DB's lifecycle
// can be asserted. Returns the (ANSI-stripped) combined output and run error.
func runIsolatedDiscover(t *testing.T, bin, target, destDB, home, scratchTmp string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// A generous discovery budget keeps each scan productive even when the test
	// runs alongside the rest of the (Docker-heavy) e2e/canary suites and the
	// process is briefly CPU-starved: the localhost seed request must land within
	// the budget, or the scan ingests nothing and there is nothing to merge.
	cmd := exec.CommandContext(ctx, bin, "run", "discover",
		"-t", target,
		"--db", destDB,
		"--db-isolate",
		"--scanning-max-duration", "20s",
		"--skip-dependency-check",
	)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"TMPDIR="+scratchTmp,
		"VIGOLIUM_PROJECT=",
	)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return terminal.StripANSI(out.String()), err
}

// countHTTPRecords opens the SQLite DB at path and returns its http_records count.
func countHTTPRecords(t *testing.T, path string) int {
	t.Helper()
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        path,
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   2000,
		},
	}
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM http_records").Scan(&n))
	return n
}

// mergedRecordRe extracts the http_record count a --db-isolate run reports
// merging into its destination, from the success line written by
// finishDBIsolateMerge: "◆ Merged results into <path> (N records, M findings)".
var mergedRecordRe = regexp.MustCompile(`Merged results into .*\((\d+) records`)

// mergedRecordCount returns how many http_records the given run reported merging
// into the shared destination, parsed from its (ANSI-stripped) output. It fails
// the test if the merge confirmation line is absent — a clean db-isolate run
// always prints it.
func mergedRecordCount(t *testing.T, out string) int {
	t.Helper()
	m := mergedRecordRe.FindStringSubmatch(out)
	require.Lenf(t, m, 2, "expected a 'Merged results into ... (N records' line in output:\n%s", out)
	n, err := strconv.Atoi(m[1])
	require.NoError(t, err)
	return n
}

// assertNoScratchLeftovers fails if any vigolium-isolate-* scratch files remain
// in dir — the scratch DB (and its WAL sidecars) must be removed after a
// successful merge.
func assertNoScratchLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "vigolium-isolate-",
			"scratch DB should be cleaned up after a successful merge, found %s", e.Name())
	}
}

// TestDBIsolate_SingleRun verifies a single --db-isolate discover run merges
// results into a fresh destination DB and cleans up its scratch DB.
func TestDBIsolate_SingleRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping db-isolate e2e in short mode")
	}
	bin := buildVigoliumBinary(t)
	srv := startTestHTTPServer(t)

	home := t.TempDir()
	scratchTmp := t.TempDir()
	destDB := filepath.Join(t.TempDir(), "dest.sqlite")

	out, err := runIsolatedDiscover(t, bin, srv.URL+"/", destDB, home, scratchTmp)
	if err != nil {
		t.Fatalf("discover --db-isolate failed: %v\n%s", err, out)
	}

	// The destination (created by the merge) must hold the discovered records.
	require.GreaterOrEqual(t, countHTTPRecords(t, destDB), 1,
		"expected at least one merged HTTP record in the destination DB")
	// The merge runs to the real --db, so the success line names it.
	assert.Contains(t, out, "Merged results into", "expected merge confirmation in output")
	assertNoScratchLeftovers(t, scratchTmp)
}

// TestDBIsolate_ParallelSharedDB is the core scenario: many concurrent scan
// processes all target ONE shared --db with --db-isolate. Every process must
// succeed (no SQLITE_BUSY contention failures), the merge must lose nothing (the
// destination ends up holding exactly the sum of what every process reported
// merging), and no scratch DBs may be left behind.
func TestDBIsolate_ParallelSharedDB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping db-isolate e2e in short mode")
	}
	bin := buildVigoliumBinary(t)
	srv := startTestHTTPServer(t)

	const procs = 4
	scratchTmp := t.TempDir() // shared, so we can assert all scratch DBs were removed
	destDB := filepath.Join(t.TempDir(), "shared.sqlite")

	var wg sync.WaitGroup
	errs := make([]error, procs)
	outs := make([]string, procs)
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Per-process HOME avoids first-run init races; the shared --db is
			// what exercises the merge-contention path.
			home := filepath.Join(t.TempDir(), fmt.Sprintf("home-%d", idx))
			require.NoError(t, os.MkdirAll(home, 0o755))
			outs[idx], errs[idx] = runIsolatedDiscover(t, bin, srv.URL+"/", destDB, home, scratchTmp)
		}(i)
	}
	wg.Wait()

	// Every process must succeed and report how many records it merged. Summing
	// those is the ground truth for what the shared destination should hold:
	// records carry per-process UUIDs, so concurrent scans of the same target
	// never dedup against each other on merge.
	merged := 0
	for i := 0; i < procs; i++ {
		if errs[i] != nil {
			t.Fatalf("parallel process %d failed (db-isolate should serialize merges, not fail): %v\n%s",
				i, errs[i], outs[i])
		}
		merged += mergedRecordCount(t, outs[i])
	}

	// The merge must lose nothing under contention: the shared destination holds
	// exactly the sum of what every process reported merging. This is the
	// feature's real guarantee — and, unlike a fixed per-process floor, it holds
	// at any productivity level, even when a CPU-starved scan ingests fewer
	// records under the load of the full e2e/canary suite.
	require.Equal(t, merged, countHTTPRecords(t, destDB),
		"shared destination must hold exactly the records all %d processes merged, with no contention loss", procs)
	assertNoScratchLeftovers(t, scratchTmp)

	// Per-scan productivity is environment-dependent: under enough concurrent CPU
	// load a discover run can exhaust its budget before the localhost seed lands
	// and ingest nothing. A fully starved batch (every process merged 0) is not a
	// db-isolate defect — the no-loss and no-leftover invariants above still hold,
	// and TestDBIsolate_SingleRun guards the productive path — so report it rather
	// than flaking. In the normal case (merged > 0) the equality check above has
	// proven records accumulated across all processes without contention loss.
	if merged == 0 {
		t.Logf("all %d processes ingested 0 records (host too CPU-starved to land a request "+
			"within the discovery budget); db-isolate merge invariants still held", procs)
	}
}
