package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

func withExportFlags(t *testing.T, only, exclude []string) {
	t.Helper()
	prevO, prevX := topExportOnly, topExportExclude
	topExportOnly, topExportExclude = only, exclude
	t.Cleanup(func() { topExportOnly, topExportExclude = prevO, prevX })
}

func envelopeTypes(out string) map[string]int {
	got := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if i := strings.Index(line, `"type":"`); i >= 0 {
			rest := line[i+len(`"type":"`):]
			got[rest[:strings.Index(rest, `"`)]]++
		}
	}
	return got
}

// The single-format jsonl path honours --only and --exclude, aliases resolve,
// and a user --exclude does not bring the module registry back.
func TestExportJSONLHonoursOnlyAndExclude(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedRecordWithBodies(t, db, "alpha")

	run := func(only, exclude []string) map[string]int {
		withExportFlags(t, only, exclude)
		require.NoError(t, validateExportOnly())
		var buf bytes.Buffer
		_, err := streamJSONLExport(ctx, db, &buf, false, "")
		require.NoError(t, err)
		return envelopeTypes(buf.String())
	}

	got := run([]string{"findings"}, nil)
	require.Zero(t, got["http_record"], "--only findings exported records: %v", got)

	got = run(nil, []string{"http"})
	require.Zero(t, got["http_record"], "--exclude http excluded nothing: %v", got)
	require.Zero(t, got["module"], "--exclude replaced the implicit module exclusion: %v", got)

	got = run([]string{"http_records"}, nil)
	require.Positive(t, got["http_record"])

	got = run([]string{"modules"}, nil)
	require.Positive(t, got["module"])
}

func TestExportTypeValidation(t *testing.T) {
	for _, c := range []struct{ only, exclude []string }{
		{[]string{"bogus"}, nil},
		{nil, []string{"bogus"}},
		{[]string{"http"}, []string{"http_record"}},
	} {
		withExportFlags(t, c.only, c.exclude)
		var usage clicommon.UsageError
		require.True(t, errors.As(validateExportOnly(), &usage), "only=%v exclude=%v", c.only, c.exclude)
	}

	withExportFlags(t, []string{"http"}, nil)
	for _, f := range []string{"csv", "sarif"} {
		var usage clicommon.UsageError
		err := validateExportFormatsScope([]exportFormatSpec{{format: f, raw: f}})
		require.True(t, errors.As(err, &usage), "%s with --only http: %v", f, err)
	}
	require.NoError(t, validateExportFormatsScope([]exportFormatSpec{{format: "jsonl", raw: "jsonl"}}))
}

// Every format refuses a scope it renders nothing of, from the format-support
// column rather than a hard-coded findings-only list.
func TestExportFormatSupportColumn(t *testing.T) {
	require.Equal(t, []string{"findings"}, exportTypesForFormat("csv"))
	require.Contains(t, exportTypesForFormat("fs"), "http")
	require.NotContains(t, exportTypesForFormat("fs"), "scans")
	require.ElementsMatch(t, exportTypeNames(), exportTypesForFormat("jsonl"))

	for _, c := range []struct {
		only   []string
		format string
		ok     bool
	}{
		{[]string{"scans"}, "csv", false},
		{[]string{"oast"}, "markdown", false},
		{[]string{"scans"}, "fs", false},
		{[]string{"oast"}, "html", true},
		{[]string{"scans", "findings"}, "sarif", true},
	} {
		withExportFlags(t, c.only, nil)
		err := validateExportFormatsScope([]exportFormatSpec{{format: c.format, raw: c.format}})
		if c.ok {
			require.NoError(t, err, "%s --only %v", c.format, c.only)
			continue
		}
		var usage clicommon.UsageError
		require.True(t, errors.As(err, &usage), "%s --only %v: %v", c.format, c.only, err)
	}
}

// The export query is the only input of streamExportData: the export
// command's flag globals do not leak into a post-scan report's rows.
func TestExportQueryIgnoresCommandGlobals(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedRecordWithBodies(t, db, "alpha")
	seedRecordWithBodies(t, db, "beta")

	prevSearch, prevLimit := topExportSearch, topExportLimit
	topExportSearch, topExportLimit = "alpha", 1
	t.Cleanup(func() { topExportSearch, topExportLimit = prevSearch, prevLimit })

	items, err := queryExportData(ctx, db, scanReportQuery(false, "", ""))
	require.NoError(t, err)
	require.Equal(t, 2, countExportItems(items).byType["http_record"])

	items, err = queryExportData(ctx, db, topExportQuery(""))
	require.NoError(t, err)
	require.Equal(t, 1, countExportItems(items).byType["http_record"])
}
