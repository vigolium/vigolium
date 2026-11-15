package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
)

// An exported authenticated exchange imports back authenticated.
func TestExportImportRoundTripKeepsIsAuthenticated(t *testing.T) {
	ctx := context.Background()
	src := newExportTestDB(t)
	_, err := src.NewInsert().Model(&database.HTTPRecord{
		UUID: "rec-auth", Scheme: "http", Hostname: "auth.example", Port: 80,
		Method: "GET", Path: "/me", URL: "http://auth.example/me", HTTPVersion: "HTTP/1.1",
		RequestHash: "rhash-auth", IsAuthenticated: true,
		ProjectUUID: database.DefaultProjectUUID,
	}).Exec(ctx)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = streamJSONLWithQuery(ctx, src, &buf, exportQuery{scope: fullExportScope})
	require.NoError(t, err)
	require.Contains(t, buf.String(), `"is_authenticated":true`)

	dst := newDBAtPath(t, filepath.Join(t.TempDir(), "dst.sqlite"))
	_, err = dbimport.ImportJSONL(ctx, database.NewRepository(dst), &buf, database.DefaultProjectUUID, dbimport.Options{})
	require.NoError(t, err)

	var got database.HTTPRecord
	require.NoError(t, dst.NewSelect().Model(&got).Where("uuid = ?", "rec-auth").Scan(ctx))
	require.True(t, got.IsAuthenticated, "is_authenticated lost on import")
}

// A JSONL export imports back its scans and OAST interactions, re-homed into
// the target project; scope rows load only when asked for, and every type is
// counted.
func TestExportImportRoundTripSideTables(t *testing.T) {
	ctx := context.Background()
	src := newExportTestDB(t)
	_, err := src.NewInsert().Model(&database.Scan{UUID: "scan-1", ProjectUUID: "projA", Status: "completed"}).Exec(ctx)
	require.NoError(t, err)
	_, err = src.NewInsert().Model(&database.OASTInteraction{
		ProjectUUID: "projA", UniqueID: "u1", FullID: "u1.oast.example", Protocol: "dns", FindingID: 42,
	}).Exec(ctx)
	require.NoError(t, err)
	_, err = src.NewInsert().Model(&database.Scope{
		ProjectUUID: "projA", Name: "only-a", RuleType: "include", HostPattern: "a.example", Enabled: true,
	}).Exec(ctx)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = streamJSONLWithQuery(ctx, src, &buf, exportQuery{scope: fullExportScope})
	require.NoError(t, err)
	data := buf.Bytes()

	dst := newDBAtPath(t, filepath.Join(t.TempDir(), "dst.sqlite"))
	repo := database.NewRepository(dst)
	res, err := dbimport.ImportJSONL(ctx, repo, bytes.NewReader(data), "projB", dbimport.Options{})
	require.NoError(t, err)
	require.Equal(t, 1, res.ImportedByType["scan"])
	require.Equal(t, 1, res.ImportedByType["oast_interaction"])
	require.Equal(t, 1, res.SkippedTypes["scope"], "scope rows must not load into a live store by default")
	require.Zero(t, res.ImportedByType["scope"])

	var scan database.Scan
	require.NoError(t, dst.NewSelect().Model(&scan).Where("uuid = ?", "scan-1").Scan(ctx))
	require.Equal(t, "projB", scan.ProjectUUID)
	var oi database.OASTInteraction
	require.NoError(t, dst.NewSelect().Model(&oi).Where("full_id = ?", "u1.oast.example").Scan(ctx))
	require.Equal(t, "projB", oi.ProjectUUID)
	require.Zero(t, oi.FindingID, "a finding id from another store must not dangle")

	// Re-importing is a no-op counted as duplicates; scopes load on request.
	res, err = dbimport.ImportJSONL(ctx, repo, bytes.NewReader(data), "projB", dbimport.Options{ImportScopes: true})
	require.NoError(t, err)
	require.Equal(t, 1, res.DuplicatesByType["scan"])
	require.Equal(t, 1, res.DuplicatesByType["oast_interaction"])
	require.Equal(t, 1, res.ImportedByType["scope"])

	out := importResultJSON("x.jsonl", res)
	require.Contains(t, out, "imported_by_type")
	require.Contains(t, out, "skipped_types")
}
