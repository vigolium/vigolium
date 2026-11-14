package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/uptrace/bun/driver/sqliteshim"
)

// TestOASTSessions_RedactedInGenericAPIAndExports is MISS-37: a kept OAST
// session's key material never leaves the store — not through the generic
// table API and not in an exported SQLite copy — and closing drops it.
func TestOASTSessions_RedactedInGenericAPIAndExports(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	if err := repo.SaveOASTSession(ctx, &OASTSession{
		ProjectUUID: DefaultProjectUUID, ScanUUID: "s1", ServerURL: "https://oast.example",
		CorrelationID: "corr1", SecretKey: "SECRET", PrivateKey: "PRIV", PublicKey: "PUB", Token: "TOK",
	}); err != nil {
		t.Fatal(err)
	}
	open, err := repo.ListOpenOASTSessions(ctx, DefaultProjectUUID, "s1")
	if err != nil || len(open) != 1 || open[0].SecretKey != "SECRET" {
		t.Fatalf("open = %+v, %v", open, err)
	}

	rows, _, _, err := QueryGenericTable(ctx, db, "oast_sessions", 10, 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("generic rows = %v, %v", rows, err)
	}
	for _, col := range RedactedOASTSessionColumns {
		if rows[0][col] != "<redacted>" {
			t.Errorf("generic API %s = %v, want <redacted>", col, rows[0][col])
		}
	}

	out := filepath.Join(t.TempDir(), "export.sqlite")
	if _, err := db.ExecContext(ctx, "VACUUM INTO '"+out+"'"); err != nil {
		t.Fatal(err)
	}
	if err := RedactOASTSessionKeysInFile(ctx, out); err != nil {
		t.Fatal(err)
	}
	exported, err := sql.Open(sqliteshim.ShimName, out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exported.Close() }()
	var secret *string
	if err := exported.QueryRowContext(ctx, "SELECT secret_key FROM oast_sessions").Scan(&secret); err != nil || secret != nil {
		t.Fatalf("exported secret_key = %v (err %v), want NULL", secret, err)
	}

	if err := repo.CloseOASTSession(ctx, open[0].ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if open, _ := repo.ListOpenOASTSessions(ctx, "", ""); len(open) != 0 {
		t.Fatalf("still open after close: %d", len(open))
	}
}
