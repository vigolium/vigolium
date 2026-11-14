package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// v1SchemaStore builds a store one schema version behind (schema_meta in its v1
// shape), the state `vigolium db migrate` exists to upgrade.
func v1SchemaStore(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v1.sqlite")
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, db.EnsureSchemaReady(ctx))
	for _, stmt := range []string{
		"DROP TABLE schema_meta",
		"CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, version INTEGER NOT NULL DEFAULT 0)",
		"INSERT INTO schema_meta (id, version) VALUES (1, 1)",
	} {
		_, err := db.ExecContext(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	require.NoError(t, db.Close())
	return path
}

func TestDBMigrateJSONContract(t *testing.T) {
	withMachineDocumentState(t)
	t.Setenv("HOME", t.TempDir())
	globalDB = v1SchemaStore(t)
	globalJSON = true

	var runErr error
	out := captureStdout(t, func() { runErr = runDBMigrate(dbMigrateCmd, nil) })
	require.NoError(t, runErr)
	docs := decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1)
	doc := docs[0]
	require.Equal(t, "db migrate", doc["command"])
	require.Equal(t, "mutation", doc["kind"])
	require.Equal(t, true, doc["changed"])
	require.Equal(t, "migrate", doc["action"])
	items, ok := doc["items"].([]any)
	require.True(t, ok && len(items) == 1, "items: %v", doc)
	res := items[0].(map[string]any)
	require.EqualValues(t, 1, res["from_version"])
	require.EqualValues(t, database.CurrentSchemaVersion(), res["to_version"])
	require.EqualValues(t, database.MinReaderVersion(), res["min_reader_version"])
	require.NotEmpty(t, res["applied"])

	// Second run: nothing to do.
	jsonResultEmitted = false
	out = captureStdout(t, func() { runErr = runDBMigrate(dbMigrateCmd, nil) })
	require.NoError(t, runErr)
	docs = decodeStdoutDocuments(t, out)
	require.Len(t, docs, 1)
	require.Equal(t, false, docs[0]["changed"])
	require.Equal(t, "noop", docs[0]["action"])
}

func TestDBMigrateRefusesMissingAndTooNew(t *testing.T) {
	withMachineDocumentState(t)
	t.Setenv("HOME", t.TempDir())

	globalDB = filepath.Join(t.TempDir(), "typo.sqlite")
	err := runDBMigrate(dbMigrateCmd, nil)
	require.Error(t, err)
	require.Equal(t, apicontract.CodeSourceMissing, classifyErrorCode(err, classifyExitCode(err)))

	path := v1SchemaStore(t)
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	_, err = db.Migrate(context.Background())
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(), "UPDATE schema_meta SET version = 99 WHERE id = 1")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	globalDB = path
	err = runDBMigrate(dbMigrateCmd, nil)
	require.True(t, errors.Is(err, database.ErrSchemaTooNew), "err = %v", err)
	require.Equal(t, apicontract.CodeSchemaTooNew, classifyErrorCode(err, classifyExitCode(err)))
}
