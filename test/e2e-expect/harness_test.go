//go:build e2e

package e2eexpect

import (
	"context"
	"flag"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/test/e2e-expect/lab"
)

var (
	updateExpect    = flag.Bool("update-expect", false, "rewrite testdata/expect.json from this run")
	intersectExpect = flag.Bool("intersect-expect", false, "narrow live entries in testdata/expect.json to what this run also saw (record a live golden over several runs)")
)

// newLab starts an empty lab torn down with the test.
func newLab(t *testing.T) *lab.Lab {
	t.Helper()
	l := lab.New()
	t.Cleanup(l.Close)
	return l
}

// scanOptions is the in-process baseline: everything off except what a
// scenario turns on, a deterministic module set, no tech gate.
func scanOptions(targets ...string) *types.Options {
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Targets = targets
	opts.Concurrency = 8
	opts.MaxPerHost = 4
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	opts.NoTechFilter = true
	opts.PassiveModules = []string{}
	opts.DiscoverEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.SpideringEnabled = false
	opts.FingerprintEnabled = false
	opts.SkipPortSweep = true
	opts.HeuristicsCheck = "none"
	opts.SkipDynamicAssessment = false
	return opts
}

// scanRun is one finished in-process scan.
type scanRun struct {
	runner   *runner.Runner
	db       *database.DB
	repo     *database.Repository
	err      error
	elapsed  time.Duration
	findings []*database.Finding
}

// runScan runs a native scan in-process against a fresh in-memory database
// and fails the test if it does not return within deadline.
func runScan(t *testing.T, opts *types.Options, deadline time.Duration) *scanRun {
	t.Helper()
	sr := startScan(t, opts)
	return sr.wait(t, deadline)
}

// pendingScan is a scan running in the background.
type pendingScan struct {
	*scanRun
	start time.Time
	done  chan struct{}
}

func startScan(t *testing.T, opts *types.Options) *pendingScan {
	t.Helper()
	db, repo := memDB(t)
	r, err := runner.New(opts)
	require.NoError(t, err)
	r.SetSettings(config.DefaultSettings())
	r.SetRepository(repo)
	t.Cleanup(r.Close)

	ps := &pendingScan{scanRun: &scanRun{runner: r, db: db, repo: repo}, start: time.Now(), done: make(chan struct{})}
	go func() {
		defer close(ps.done)
		ps.err = r.RunNativeScan()
	}()
	return ps
}

func (ps *pendingScan) wait(t *testing.T, deadline time.Duration) *scanRun {
	t.Helper()
	select {
	case <-ps.done:
	case <-time.After(deadline):
		ps.runner.Close()
		t.Fatalf("scan did not finish within %s (still running after deadline; runner closed)", deadline)
	}
	ps.elapsed = time.Since(ps.start)
	ps.findings = allFindings(t, ps.db)
	return ps.scanRun
}

// openDB opens a SQLite store at path (":memory:" for a scratch one) with the
// production defaults, closed with the test.
func openDB(t *testing.T, path string) *database.DB {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	require.NoErrorf(t, err, "open %s", path)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func memDB(t *testing.T) (*database.DB, *database.Repository) {
	t.Helper()
	db := openDB(t, ":memory:")
	require.NoError(t, db.CreateSchema(context.Background()))
	return db, database.NewRepository(db)
}

// allFindings returns findings and candidates alike.
func allFindings(t *testing.T, db *database.DB) []*database.Finding {
	t.Helper()
	fs, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{
		Limit:       10000,
		RecordKinds: []string{database.RecordKindFinding, database.RecordKindCandidate},
	}).Execute(context.Background())
	require.NoError(t, err)
	return fs
}

// urlPath is a URL's path, "/" when it has none.
func urlPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

// findingPath is the URL path a finding was raised on.
func findingPath(f *database.Finding) string { return urlPath(f.URL) }

// sortedSet returns the distinct values of key over xs, sorted.
func sortedSet[T any](xs []T, key func(T) string) []string {
	seen := map[string]bool{}
	for _, x := range xs {
		if k := key(x); k != "" {
			seen[k] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

// findingKeys renders findings as sorted "module@path" keys.
func findingKeys(fs []*database.Finding) []string {
	return sortedSet(fs, func(f *database.Finding) string { return f.ModuleID + "@" + findingPath(f) })
}

// writeLines writes lines to a file in a temp dir and returns its path (a
// wordlist, a -T target list).
func writeLines(t *testing.T, lines []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lines.txt")
	require.NoError(t, os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
	return p
}

func logFindings(t *testing.T, fs []*database.Finding) {
	t.Helper()
	for _, f := range fs {
		t.Logf("  [%s/%s] %s %s", f.Severity, f.RecordKind, f.ModuleID, f.URL)
	}
}
