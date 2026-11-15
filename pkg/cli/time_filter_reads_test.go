package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

// The traffic view carries sent_at in UTC, the help says how zone-less times
// are read, and --from/--to exist on every read that has a time.
func TestTimeFilterReads(t *testing.T) {
	sent := time.Date(2026, 3, 4, 5, 6, 7, 0, time.FixedZone("x", 3600))
	v := compactRecordView(&database.HTTPRecord{UUID: "u", SentAt: sent}, agentViewOptions{})
	require.Equal(t, "2026-03-04T04:06:07Z", v["sent_at"])

	require.Contains(t, clicommon.TimeFilterSyntax, "local")
	require.Contains(t, clicommon.TimeFilterSyntax, "UTC")

	for _, c := range []*struct{ name string }{{"hosts"}, {"log ls"}, {"db stats"}, {"export"}} {
		cmd, _, err := rootCmd.Find(strings.Fields(c.name))
		require.NoError(t, err, c.name)
		require.NotNil(t, cmd.Flags().Lookup("from"), "%s has no --from", c.name)
		require.NotNil(t, cmd.Flags().Lookup("to"), "%s has no --to", c.name)
	}
	cleanCmd, _, err := rootCmd.Find([]string{"db", "clean"})
	require.NoError(t, err)
	require.Nil(t, cleanCmd.Flags().Lookup("to"), "db clean --before must not gain a --to alias (it widens a DELETE)")
}

func TestLogLsTimeFilter(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 1, d, 12, 0, 0, 0, time.UTC) }
	rows := []sessionRow{{uuid: "a", createdAt: day(1)}, {uuid: "b", createdAt: day(5)}, {uuid: "c", createdAt: day(9)}}
	from, to := day(2), day(8)
	got := filterSessionRowsByTime(rows, &from, &to)
	require.Len(t, got, 1)
	require.Equal(t, "b", got[0].uuid)
}

func TestExportQueryTimeRange(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)
	seedRecordWithBodies(t, db, "old")
	seedRecordWithBodies(t, db, "new")
	_, err := db.NewUpdate().Model((*database.HTTPRecord)(nil)).Set("sent_at = ?", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)).
		Where("uuid = ?", "rec-old").Exec(ctx)
	require.NoError(t, err)
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	items, err := queryExportData(ctx, db, exportQuery{scope: fullExportScope, from: &from})
	require.NoError(t, err)
	require.Equal(t, 1, countExportItems(items).byType["http_record"])
}
