package database

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveUUIDPrefix(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	for _, s := range []struct{ uuid, project string }{
		{"aaaa1111-0000-0000-0000-000000000001", "p1"},
		{"aaaa1111-0000-0000-0000-000000000002", "p1"},
		{"bbbb2222-0000-0000-0000-000000000003", "p1"},
		{"cccc3333-0000-0000-0000-000000000004", "p2"},
	} {
		_, err := db.NewInsert().Model(&Scan{UUID: s.uuid, ProjectUUID: s.project, Status: "completed"}).Exec(ctx)
		require.NoError(t, err)
	}

	full, cands, err := repo.ResolveUUIDPrefix(ctx, "scans", "p1", "bbbb2222")
	require.NoError(t, err)
	require.Nil(t, cands)
	require.Equal(t, "bbbb2222-0000-0000-0000-000000000003", full)

	full, cands, err = repo.ResolveUUIDPrefix(ctx, "scans", "p1", "aaaa1111")
	require.NoError(t, err)
	require.Empty(t, full)
	require.Len(t, cands, 2)

	_, _, err = repo.ResolveUUIDPrefix(ctx, "scans", "p1", "cccc3333")
	require.ErrorIs(t, err, sql.ErrNoRows, "another project's scan reads as missing")

	full, _, err = repo.ResolveUUIDPrefix(ctx, "scans", "", "cccc3333")
	require.NoError(t, err)
	require.Equal(t, "cccc3333-0000-0000-0000-000000000004", full)

	_, _, err = repo.ResolveUUIDPrefix(ctx, "findings", "", "x")
	require.Error(t, err)
}
