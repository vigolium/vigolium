package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		"-o", "roche-vig", "--format", "jsonl,html", "-c", "30",
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
			&types.Options{Parallel: 4, Stateless: true, TargetsFilePath: "t.txt", SplitByHost: true},
			false,
		},
		{
			"parallel>1 with db-isolate + target file ok (no split-by-host needed)",
			&types.Options{Parallel: 4, DBIsolate: true, TargetsFilePath: "t.txt"},
			false,
		},
		{
			"parallel>1 db-isolate missing target file rejected",
			&types.Options{Parallel: 4, DBIsolate: true},
			true,
		},
		{
			"parallel>1 with neither stateless nor db-isolate rejected",
			&types.Options{Parallel: 4, TargetsFilePath: "t.txt", SplitByHost: true},
			true,
		},
		{
			"parallel>1 stateless missing target file rejected",
			&types.Options{Parallel: 4, Stateless: true, SplitByHost: true},
			true,
		},
		{
			"parallel>1 stateless missing split-by-host rejected",
			&types.Options{Parallel: 4, Stateless: true, TargetsFilePath: "t.txt"},
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

// parallelBatchError returns an error only when every target failed; partial
// success and an empty batch are both clean exits.
func TestParallelBatchError(t *testing.T) {
	assert.NoError(t, parallelBatchError(0, 0), "empty batch is not a failure")
	assert.NoError(t, parallelBatchError(0, 5), "all succeeded")
	assert.NoError(t, parallelBatchError(4, 5), "partial success exits clean")
	assert.Error(t, parallelBatchError(5, 5), "all failed exits non-zero")
	assert.Error(t, parallelBatchError(1, 1), "single failed target exits non-zero")
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
		{"with extension", "roche-vig-x.com.jsonl", 1, "roche-vig-x.com-002.jsonl"},
		{"no extension", "roche-vig-x.com", 0, "roche-vig-x.com-001"},
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
	assert.Equal(t, "roche-vig-<host>", perHostOutputPattern("roche-vig"))
	assert.Equal(t, "out-<host>.jsonl", perHostOutputPattern("out.jsonl"))
	assert.Equal(t, "scan-<host>.html", perHostOutputPattern("scan.html"))
	assert.Equal(t, "", perHostOutputPattern(""))
}

// perTargetConsolePath derives a sibling .console.log from a resolved output
// path, stripping any known format extension first.
func TestPerTargetConsolePath(t *testing.T) {
	assert.Equal(t, "roche-vig-app.example.com.console.log", perTargetConsolePath("roche-vig-app.example.com.jsonl"))
	assert.Equal(t, "out.console.log", perTargetConsolePath("out.html"))
	assert.Equal(t, "noext.console.log", perTargetConsolePath("noext"))
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
// child's JSONL output, and only when jsonl is among the formats.
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

	t.Run("not ok when jsonl not requested", func(t *testing.T) {
		_, ok := readChildStats(base, []string{"html"})
		assert.False(t, ok)
	})

	t.Run("not ok when file missing", func(t *testing.T) {
		_, ok := readChildStats(filepath.Join(dir, "nope"), []string{"jsonl"})
		assert.False(t, ok)
	})
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
