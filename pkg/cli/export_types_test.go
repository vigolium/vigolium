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
