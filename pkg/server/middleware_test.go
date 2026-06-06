package server

import (
	"context"
	"database/sql"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/pkg/database"
)

// newTestRepo creates an in-memory SQLite DB with schema, returns a Repository.
//
// A bare ":memory:" DSN gives every pooled connection its OWN independent
// in-memory database, so once the connection pool opens more than one
// connection (which happens as soon as a handler goroutine touches the DB
// concurrently with the test goroutine) reads and writes can land on different
// databases — a write would silently affect zero rows. Pinning the pool to a
// single connection makes all access share one in-memory database, which is
// the consistency a real file/Postgres DB provides in production.
func newTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqldb.SetMaxOpenConns(1)
	bunDB := bun.NewDB(sqldb, sqlitedialect.New())
	db := database.NewDBFromBun(bunDB, "sqlite")
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}
