package cli

import (
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// newParallelTestCmd builds a cobra command whose flag set mirrors the subset of
// scan flags childScanArgs has to reason about: the rewritten flags
// (-t/-T/-o/-P/--split-by-host) plus a representative mix of inherited scalar,
// bool, slice, and map flags.
func newParallelTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scan"}
	fs := cmd.Flags()
	fs.StringSliceP("target", "t", nil, "")
	fs.StringP("target-file", "T", "", "")
	fs.StringP("output", "o", "", "")
	fs.IntP("parallel", "P", 1, "")
	fs.Bool("split-by-host", false, "")
	fs.BoolP("stateless", "S", false, "")
	fs.String("format", "console", "")
	fs.IntP("concurrency", "c", 50, "")
	fs.StringSliceP("header", "H", nil, "")
	fs.StringToStringP("advanced-options", "a", nil, "")
	fs.String("intensity", "", "")
	fs.Bool("headless", true, "")
	return cmd
}

// childScanArgs must drop every flag the parent rewrites per child and keep the
// rest so children inherit the operator's other flags unchanged.
func TestChildScanArgsStripsRewrittenFlags(t *testing.T) {
	cmd := newParallelTestCmd()
	require.NoError(t, cmd.ParseFlags([]string{
		"-S", "-T", "targets.txt", "-P", "4", "--split-by-host",
		"-o", "acme-vig", "--format", "jsonl,html", "-c", "30",
	}))

	got := childScanArgs(cmd)

	// Inherited flags survive.
	assert.Contains(t, got, "--stateless")
	assertFlagPair(t, got, "--concurrency", "30")
	assertFlagPair(t, got, "--format", "jsonl,html")

	// Rewritten/multi-target flags are stripped — the parent re-adds -t/-o.
	for _, banned := range []string{
		"--target-file", "--target", "--output", "--parallel", "--split-by-host",
		"-t", "-T", "-o", "-P",
	} {
		assert.NotContains(t, got, banned, "child args must not carry %s", banned)
	}
}

// The reconstructed args must re-parse into the same flag values (slices, maps,
// bools, scalars), which is the real contract: childScanArgs round-trips the
// inherited flags so the child sees what the parent saw.
func TestChildScanArgsRoundTrip(t *testing.T) {
	cmd := newParallelTestCmd()
	require.NoError(t, cmd.ParseFlags([]string{
		"-S", "-T", "targets.txt", "-P", "3", "--split-by-host", "-o", "out",
		"--format", "jsonl",
		"-H", "Authorization: Bearer x",
		"-H", "X-Env: staging",
		"-a", "xss.dom=true",
		"-a", "sqli.time=false",
		"--intensity", "deep",
		"--headless=false",
	}))

	childArgs := childScanArgs(cmd)

	// Re-parse the reconstructed args into a fresh, identical flag set.
	fresh := newParallelTestCmd()
	require.NoError(t, fresh.ParseFlags(childArgs))

	gotFormat, _ := fresh.Flags().GetString("format")
	assert.Equal(t, "jsonl", gotFormat)

	gotStateless, _ := fresh.Flags().GetBool("stateless")
	assert.True(t, gotStateless)

	gotHeadless, _ := fresh.Flags().GetBool("headless")
	assert.False(t, gotHeadless, "--headless=false must round-trip")

	gotIntensity, _ := fresh.Flags().GetString("intensity")
	assert.Equal(t, "deep", gotIntensity)

	gotHeaders, _ := fresh.Flags().GetStringSlice("header")
	assert.Equal(t, []string{"Authorization: Bearer x", "X-Env: staging"}, gotHeaders)

	gotAdv, _ := fresh.Flags().GetStringToString("advanced-options")
	assert.Equal(t, map[string]string{"xss.dom": "true", "sqli.time": "false"}, gotAdv)

	// And none of the rewritten flags leaked through.
	assert.Empty(t, fresh.Flags().Lookup("target-file").Value.String())
	gotParallel, _ := fresh.Flags().GetInt("parallel")
	assert.Equal(t, 1, gotParallel, "parallel must not be inherited (default 1 in child)")
	gotSplit, _ := fresh.Flags().GetBool("split-by-host")
	assert.False(t, gotSplit)
}

// validateParallelScan gates -P > 1 to the fully-isolated stateless path.
func TestValidateParallelScan(t *testing.T) {
	tests := []struct {
		name    string
		opts    *types.Options
		wantErr bool
	}{
		{"default parallel 1 always ok", &types.Options{Parallel: 1}, false},
		{"zero parallel rejected", &types.Options{Parallel: 0}, true},
		{"negative parallel rejected", &types.Options{Parallel: -2}, true},
		{
			"parallel>1 with full stateless combo ok",
			&types.Options{Parallel: 4, Stateless: true, TargetsFilePaths: []string{"t.txt"}, SplitByHost: true},
			false,
		},
		{
			"parallel>1 with db-isolate + target file ok (no split-by-host needed)",
			&types.Options{Parallel: 4, DBIsolate: true, TargetsFilePaths: []string{"t.txt"}},
			false,
		},
		{
			// db-isolate with no -T file is also a single target — nothing to fan
			// out, so -P degrades to a normal scan rather than erroring.
			"parallel>1 db-isolate single target degrades (no target file)",
			&types.Options{Parallel: 4, DBIsolate: true},
			false,
		},
		{
			"parallel>1 with neither stateless nor db-isolate rejected",
			&types.Options{Parallel: 4, TargetsFilePaths: []string{"t.txt"}, SplitByHost: true},
			true,
		},
		{
			// A single target (no -T file) can't fan out, so -P/--split-by-host
			// degrade to a normal scan instead of erroring.
			"parallel>1 single target degrades (no target file)",
			&types.Options{Parallel: 4, Stateless: true, SplitByHost: true},
			false,
		},
		{
			"parallel>1 stateless missing split-by-host rejected",
			&types.Options{Parallel: 4, Stateless: true, TargetsFilePaths: []string{"t.txt"}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateParallelScan(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// With a single target (no -T target file), -P/--split-by-host can't fan out, so
// validateParallelScan degrades the options to a plain one-target scan rather
// than erroring (the dispatch then falls through to the single-pass path).
func TestValidateParallelScanSingleTargetDegrades(t *testing.T) {
	opts := &types.Options{Parallel: 4, Stateless: true, SplitByHost: true, Silent: true}
	require.NoError(t, validateParallelScan(opts))
	assert.Equal(t, 1, opts.Parallel, "parallel should degrade to 1 for a single target")
	assert.False(t, opts.SplitByHost, "split-by-host should be cleared for a single target")
}

// parallelBatchError: every target failing (or a stop before any success) is
// an error (1); a partial failure or partial interrupt is incomplete (5), so 99
// failed targets out of 100 no longer exit 0 (RES-4).
func TestParallelBatchError(t *testing.T) {
	assert.NoError(t, parallelBatchError(0, 0, 0, 0), "empty batch is not a failure")
	assert.NoError(t, parallelBatchError(0, 0, 0, 5), "all succeeded")
	assert.Equal(t, ExitIncomplete, classifyExitCode(parallelBatchError(4, 0, 0, 5)), "partial failure is incomplete")
	assert.Equal(t, ExitIncomplete, classifyExitCode(parallelBatchError(99, 0, 0, 100)), "99 of 100 failed is incomplete")
	assert.Equal(t, ExitError, classifyExitCode(parallelBatchError(5, 0, 0, 5)), "all failed exits 1")
	assert.Error(t, parallelBatchError(1, 0, 0, 1), "single failed target exits non-zero")

	// Interrupt handling: a full stop (nothing finished) is an error, a
	// partial interrupt — some targets completed before Ctrl-C — is incomplete.
	assert.Equal(t, ExitError, classifyExitCode(parallelBatchError(0, 5, 0, 5)), "full interrupt before any success")
	assert.Equal(t, ExitError, classifyExitCode(parallelBatchError(2, 3, 0, 5)), "all targets failed or interrupted")
	assert.Equal(t, ExitIncomplete, classifyExitCode(parallelBatchError(0, 3, 0, 5)), "partial interrupt is incomplete")
	assert.Equal(t, ExitIncomplete, classifyExitCode(parallelBatchError(1, 2, 0, 5)), "some succeeded despite interrupt")
}

// TestResumeManifestPersistsDoneIndices: a target that finished out of order
// (after a failed one) is recorded in done_indices and skipped on resume.
func TestResumeManifestPersistsDoneIndices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.progress.json")
	m := newResumeManifest(path, "out.jsonl", []string{"jsonl"}, []string{"t.txt"}, "fp")
	assert.True(t, m.markDone(0, "a", childStats{records: 1}))
	// index 1 failed; 2 and 3 finished.
	assert.True(t, m.markDone(2, "c", childStats{records: 2, findings: 1}))
	assert.True(t, m.markDone(3, "d", childStats{records: 3}))
	assert.NoError(t, m.save())

	loaded, ok := loadResumeManifest(path)
	assert.True(t, ok)
	assert.Equal(t, 0, loaded.CompletedThrough)
	assert.False(t, loaded.doneAhead(1), "the failed target is rescanned")
	assert.True(t, loaded.doneAhead(2))
	assert.True(t, loaded.doneAhead(3))
	carry := loaded.carryover()
	assert.Equal(t, 3, carry.count)
	assert.Equal(t, 6, carry.stats.records)
	// Filling the gap advances the cursor over the persisted completions.
	assert.True(t, loaded.markDone(1, "b", childStats{}))
	assert.Equal(t, 3, loaded.CompletedThrough)
	assert.Equal(t, 6, loaded.Records)
}

// TestPreserveFailedConsoles: --db-isolate -P removes its staging directory, so
// a failed child's console is copied out and the result repointed at it.
func TestPreserveFailedConsoles(t *testing.T) {
	staging := t.TempDir()
	failedLog := filepath.Join(staging, "t001.console.log")
	okLog := filepath.Join(staging, "t000.console.log")
	assert.NoError(t, os.WriteFile(failedLog, []byte("boom"), 0o644))
	assert.NoError(t, os.WriteFile(okLog, []byte("fine"), 0o644))
	results := []targetResult{
		{target: "https://ok.test", console: okLog},
		{target: "https://bad.test/x", console: failedLog, err: errors.New("exit 1")},
	}
	dir := failedConsoleDir(filepath.Join(t.TempDir(), "report.jsonl"))
	preserveFailedConsoles(results, dir)
	assert.Equal(t, okLog, results[0].console)
	assert.NotEqual(t, failedLog, results[1].console)
	assert.True(t, strings.HasPrefix(results[1].console, dir))
	data, err := os.ReadFile(results[1].console)
	assert.NoError(t, err)
	assert.Equal(t, "boom", string(data))
}

// A gated child scanned fine and tripped --fail-on. The batch must report that
// with exit 4 — a `-P --fail-on high` run used to exit 0 unless every child
// tripped, so the gate the operator asked for did not stop their CI job.
func TestParallelBatchErrorGate(t *testing.T) {
	assert.Equal(t, ExitFailOnGate, classifyExitCode(parallelBatchError(0, 0, 2, 5)),
		"some targets tripped the gate")
	assert.Equal(t, ExitFailOnGate, classifyExitCode(parallelBatchError(0, 0, 5, 5)),
		"every target tripped the gate")

	// A real failure outranks the gate: a batch that both broke and found
	// something should report the break, which is the actionable half.
	assert.Equal(t, ExitError, classifyExitCode(parallelBatchError(5, 0, 0, 5)),
		"all failed is still a failure")
	assert.Equal(t, ExitFailOnGate, classifyExitCode(parallelBatchError(4, 0, 1, 5)),
		"the gate outranks incomplete")

	// An interrupt that stopped everything outranks the gate too: the batch did
	// not finish, so its verdict is incomplete.
	assert.Equal(t, ExitError, classifyExitCode(parallelBatchError(0, 5, 0, 5)),
		"full interrupt reports the interrupt")
}

// childTrippedGate must read the child's exit status, not its message: the
// severity gate and a genuine crash both surface as a non-nil error from
// exec.Cmd.Run, and only the code tells them apart.
func TestChildTrippedGate(t *testing.T) {
	assert.False(t, childTrippedGate(nil), "a clean child did not trip the gate")
	assert.False(t, childTrippedGate(errors.New("exit status 4")),
		"message text must not be enough — a coincidence would mislabel a failure")

	run := func(code string) error {
		cmd := exec.Command(os.Args[0], "-test.run=TestChildExitHelper")
		cmd.Env = append(os.Environ(), childExitHelperEnv+"="+code)
		return cmd.Run()
	}
	assert.True(t, childTrippedGate(run("4")), "exit 4 is the severity gate")
	assert.False(t, childTrippedGate(run("1")), "exit 1 is a failure, not the gate")
	assert.False(t, childTrippedGate(run("0")), "exit 0 is a clean child")
}

// childExitHelperEnv names the exit code TestChildExitHelper should produce.
const childExitHelperEnv = "VIGOLIUM_TEST_CHILD_EXIT"

// TestChildExitHelper is the helper process TestChildTrippedGate re-executes.
// It is a no-op unless the env var above asks it for an exit code.
func TestChildExitHelper(t *testing.T) {
	code, ok := os.LookupEnv(childExitHelperEnv)
	if !ok {
		t.Skip("helper process only")
	}
	n, err := strconv.Atoi(code)
	if err != nil {
		t.Fatalf("bad %s=%q", childExitHelperEnv, code)
	}
	os.Exit(n)
}

// withIndexSuffix disambiguates two targets that resolve to the same per-host
// output path by inserting the 1-based index before the format extension.
func TestWithIndexSuffix(t *testing.T) {
	tests := []struct {
		name string
		path string
		idx  int
		want string
	}{
		{"with extension", "acme-vig-x.com.jsonl", 1, "acme-vig-x.com-002.jsonl"},
		{"no extension", "acme-vig-x.com", 0, "acme-vig-x.com-001"},
		{"html extension", "out-app.html", 4, "out-app-005.html"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, withIndexSuffix(tt.path, tt.idx))
		})
	}
}

// perHostOutputPattern shows --output as the per-host pattern with the format
// extension preserved.
func TestPerHostOutputPattern(t *testing.T) {
	assert.Equal(t, "acme-vig-<host>", perHostOutputPattern("acme-vig"))
	assert.Equal(t, "out-<host>.jsonl", perHostOutputPattern("out.jsonl"))
	assert.Equal(t, "scan-<host>.html", perHostOutputPattern("scan.html"))
	// No base (--split-by-host without -o): the banner shows the bare host
	// placeholder, so per-format paths read "<host>.jsonl" not just an extension.
	assert.Equal(t, "<host>", perHostOutputPattern(""))
}

// perTargetConsolePath derives a sibling .console.log from a resolved output
// path, stripping any known format extension first.
func TestPerTargetConsolePath(t *testing.T) {
	assert.Equal(t, "acme-vig-app.example.com.console.log", perTargetConsolePath("acme-vig-app.example.com.jsonl"))
	assert.Equal(t, "out.console.log", perTargetConsolePath("out.html"))
	assert.Equal(t, "noext.console.log", perTargetConsolePath("noext"))
}

// hasDeferredOutputFormat is the gate for writing a sequential per-target
// .console.log: any non-console (file-based) format makes the captured log
// worthwhile; a plain console format does not (the console already IS output).
func TestHasDeferredOutputFormat(t *testing.T) {
	assert.False(t, hasDeferredOutputFormat(nil))
	assert.False(t, hasDeferredOutputFormat([]string{"console"}))
	assert.True(t, hasDeferredOutputFormat([]string{"sqlite", "html"}))
	assert.True(t, hasDeferredOutputFormat([]string{"console", "html"}))
	assert.True(t, hasDeferredOutputFormat([]string{"jsonl"}))
	assert.True(t, hasDeferredOutputFormat([]string{"fs"}))
}

// parseMapFlagValue turns pflag's "[k=v,k2=v2]" String() form back into
// individual tokens; an empty map yields no tokens.
func TestParseMapFlagValue(t *testing.T) {
	assert.Equal(t, []string{"a=1", "b=2"}, parseMapFlagValue("[a=1,b=2]"))
	assert.Nil(t, parseMapFlagValue("[]"))
	assert.Nil(t, parseMapFlagValue(""))
}

// summarizeTargetList collapses a long target list into a "(+N more)" tail.
func TestSummarizeTargetList(t *testing.T) {
	assert.Equal(t, "", summarizeTargetList(nil, 3))
	assert.Equal(t, "a, b", summarizeTargetList([]string{"a", "b"}, 3))
	assert.Equal(t, "a, b, c", summarizeTargetList([]string{"a", "b", "c"}, 3))
	assert.Equal(t, "a, b, c (+2 more)", summarizeTargetList([]string{"a", "b", "c", "d", "e"}, 3))
}

// readChildStats counts http_record/finding envelopes (by severity) from a
// child's JSONL output, falling back to the standalone .sqlite export when jsonl
// was not requested.
func TestReadChildStats(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "scan-out-host")
	jsonl := base + ".jsonl"
	content := `{"type":"scan","data":{}}
{"type":"http_record","data":{}}
{"type":"http_record","data":{}}
{"type":"finding","data":{"severity":"High"}}
{"type":"finding","data":{"severity":"medium"}}
{"type":"finding","data":{"severity":"High"}}
`
	require.NoError(t, os.WriteFile(jsonl, []byte(content), 0o644))

	t.Run("counts records and findings by severity", func(t *testing.T) {
		st, ok := readChildStats(base, []string{"jsonl", "html"})
		require.True(t, ok)
		assert.Equal(t, 2, st.records)
		assert.Equal(t, 3, st.findings)
		assert.Equal(t, 2, st.sev["high"])
		assert.Equal(t, 1, st.sev["medium"])
	})

	t.Run("resolves jsonl path even when given an extension", func(t *testing.T) {
		st, ok := readChildStats(jsonl, []string{"jsonl"})
		require.True(t, ok)
		assert.Equal(t, 3, st.findings)
	})

	t.Run("not ok when no readable format requested", func(t *testing.T) {
		_, ok := readChildStats(base, []string{"html"})
		assert.False(t, ok)
	})

	t.Run("not ok when file missing", func(t *testing.T) {
		_, ok := readChildStats(filepath.Join(dir, "nope"), []string{"jsonl"})
		assert.False(t, ok)
	})
}

// readChildStats falls back to the standalone .sqlite export so the per-target
// stats and Totals roll-up render under formats like --format sqlite,html that
// never produce a jsonl the parent could tally.
func TestReadChildStatsSQLiteFallback(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "scan-out-host")
	writeStatsSQLite(t, base+".sqlite", 4, map[string]int{"high": 2, "medium": 1, "info": 3})

	t.Run("counts from sqlite when jsonl absent", func(t *testing.T) {
		st, ok := readChildStats(base, []string{"sqlite", "html"})
		require.True(t, ok)
		assert.Equal(t, 4, st.records)
		assert.Equal(t, 6, st.findings)
		assert.Equal(t, 2, st.sev["high"])
		assert.Equal(t, 1, st.sev["medium"])
		assert.Equal(t, 3, st.sev["info"])
	})

	t.Run("prefers jsonl when both present", func(t *testing.T) {
		require.NoError(t, os.WriteFile(base+".jsonl",
			[]byte(`{"type":"http_record","data":{}}`+"\n"+`{"type":"finding","data":{"severity":"low"}}`+"\n"), 0o644))
		st, ok := readChildStats(base, []string{"jsonl", "sqlite"})
		require.True(t, ok)
		assert.Equal(t, 1, st.records) // jsonl values, not the sqlite ones
		assert.Equal(t, 1, st.findings)
		assert.Equal(t, 1, st.sev["low"])
	})

	t.Run("not ok when sqlite missing", func(t *testing.T) {
		_, ok := readChildStats(filepath.Join(dir, "nope"), []string{"sqlite"})
		assert.False(t, ok)
	})
}

// writeStatsSQLite creates a minimal standalone .sqlite with the http_records
// and findings tables readChildStatsSQLite queries, populated with recordCount
// records and the given per-severity finding counts.
func writeStatsSQLite(t *testing.T, path string, recordCount int, sevCounts map[string]int) {
	t.Helper()
	db, err := sql.Open(sqliteshim.ShimName, path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	_, err = db.Exec(`CREATE TABLE http_records (id INTEGER PRIMARY KEY);
CREATE TABLE findings (id INTEGER PRIMARY KEY, severity TEXT NOT NULL);`)
	require.NoError(t, err)

	for i := 0; i < recordCount; i++ {
		_, err = db.Exec("INSERT INTO http_records DEFAULT VALUES")
		require.NoError(t, err)
	}
	for sev, n := range sevCounts {
		for i := 0; i < n; i++ {
			_, err = db.Exec("INSERT INTO findings (severity) VALUES (?)", sev)
			require.NoError(t, err)
		}
	}
}

// severityBreakdown lists present severities in descending order and is empty
// when there are none.
func TestSeverityBreakdown(t *testing.T) {
	assert.Equal(t, "", severityBreakdown(map[string]int{}))
	got := terminal.StripANSI(severityBreakdown(map[string]int{"high": 2, "medium": 1, "critical": 1}))
	assert.Equal(t, "(1 crit, 2 high, 1 med)", got)
}

// statsSegment is empty when stats are unavailable and otherwise carries records
// + findings with a trailing separator.
func TestStatsSegment(t *testing.T) {
	assert.Equal(t, "", statsSegment(childStats{}, false))

	zero := terminal.StripANSI(statsSegment(childStats{records: 5, findings: 0, sev: map[string]int{}}, true))
	assert.Equal(t, "5 records · 0 findings · ", zero)

	some := terminal.StripANSI(statsSegment(childStats{records: 12, findings: 3, sev: map[string]int{"high": 1, "medium": 2}}, true))
	assert.Equal(t, "12 records · 3 findings (1 high, 2 med) · ", some)
}

// childScanArgs reconstructs only the operator's *changed* flags. --captured-console
// is internal and never set by the operator, so it must not appear here — the
// parallel parent appends it to each child's argv explicitly. This guards against
// it being re-emitted (and thus duplicated, or leaking into a non-captured run).
func TestChildScanArgsExcludesCapturedConsole(t *testing.T) {
	cmd := newParallelTestCmd()
	require.NoError(t, cmd.ParseFlags([]string{
		"-S", "-T", "targets.txt", "-P", "4", "--split-by-host",
		"-o", "acme-vig", "--format", "jsonl,html",
	}))

	got := childScanArgs(cmd)
	assert.NotContains(t, got, "--captured-console",
		"childScanArgs must not emit the internal --captured-console; the parent adds it explicitly")
}

// assertFlagPair asserts that args contains flag immediately followed by value.
func assertFlagPair(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return
		}
	}
	assert.Failf(t, "flag pair not found", "expected %q %q in %v", flag, value, args)
}
