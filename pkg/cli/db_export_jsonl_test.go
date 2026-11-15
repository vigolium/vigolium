package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
)

func withDBExportTable(t *testing.T, format, table string) {
	t.Helper()
	prevF, prevT := exportFormat, globalTable
	exportFormat, globalTable = format, table
	t.Cleanup(func() { exportFormat, globalTable = prevF, prevT })
}

// db export jsonl writes the {type,data} dialect `export` writes and `import`
// reads; the nuclei dialect moved to --format nuclei.
func TestDBExportJSONLWritesEnvelopes(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "projA", "a")
	filters := database.QueryFilters{ProjectUUID: "projA"}
	records, err := database.NewQueryBuilder(db, filters).Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 1)

	withDBExportTable(t, "jsonl", "")
	var buf bytes.Buffer
	require.NoError(t, exportDBEnvelopes(ctx, db, filters, records, &buf))
	got := countEnvelopeTypes(t, buf.Bytes())
	require.Equal(t, map[string]int{"http_record": 1, "finding": 1}, got)

	dst := newDBAtPath(t, filepath.Join(t.TempDir(), "dst.sqlite"))
	res, err := dbimport.ImportJSONL(ctx, database.NewRepository(dst), bytes.NewReader(buf.Bytes()), "projA", dbimport.Options{})
	require.NoError(t, err)
	require.Equal(t, 1, res.RecordsImported)
	require.Equal(t, 1, res.FindingsSaved)

	withDBExportTable(t, "jsonl", "findings")
	require.NoError(t, validateDBExportTable())
	buf.Reset()
	require.NoError(t, exportDBEnvelopes(ctx, db, filters, records, &buf))
	require.Equal(t, map[string]int{"finding": 1}, countEnvelopeTypes(t, buf.Bytes()))

	buf.Reset()
	require.NoError(t, exportJSONL(ctx, db, records, &buf))
	require.Contains(t, buf.String(), `"template-id"`)
}

func TestDBExportTableMapping(t *testing.T) {
	for _, c := range []struct {
		format, table string
		ok            bool
	}{
		{"jsonl", "http_records", true},
		{"jsonl", "findings", true},
		{"csv", "http_records", true},
		{"csv", "findings", false},
		{"jsonl", "scans", false},
		{"jsonl", "bogus", false},
	} {
		withDBExportTable(t, c.format, c.table)
		err := validateDBExportTable()
		if c.ok {
			require.NoError(t, err, "%s --table %s", c.format, c.table)
			continue
		}
		var usage clicommon.UsageError
		require.ErrorAs(t, err, &usage, "%s --table %s", c.format, c.table)
	}
}
