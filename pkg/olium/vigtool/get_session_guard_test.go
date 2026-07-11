package vigtool

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"

	"github.com/vigolium/vigolium/pkg/database"
)

func newVigtoolTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)
	db := database.NewDBFromBun(bun.NewDB(sqldb, sqlitedialect.New()), "sqlite")
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return database.NewRepository(db)
}

// TestGetSessionProjectGuard locks in the tenant-isolation fix: get_session
// looks a run up by UUID alone, so it must refuse to return a session that
// belongs to a different project than the one scoping the tool.
func TestGetSessionProjectGuard(t *testing.T) {
	repo := newVigtoolTestRepo(t)
	ctx := context.Background()

	projA := uuid.NewString()
	projB := uuid.NewString()
	runUUID := uuid.NewString()

	if err := repo.CreateAgenticScan(ctx, &database.AgenticScan{
		UUID:        runUUID,
		ProjectUUID: projB, // owned by project B
		Mode:        "autopilot",
		AgentName:   "olium",
		Status:      "completed",
		CompletedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}

	// Tool scoped to project A must NOT see project B's run.
	toolA := NewGetSessionTool(&SessionsContext{Repo: repo, ProjectUUID: projA})
	res, err := toolA.Execute(ctx, map[string]any{"uuid": runUUID}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.IsError {
		t.Fatalf("cross-project get_session should error, got success: %s", res.Content)
	}
	if !strings.Contains(res.Content, "does not belong to the current project") {
		t.Errorf("unexpected error content: %s", res.Content)
	}

	// Tool scoped to project B sees it.
	toolB := NewGetSessionTool(&SessionsContext{Repo: repo, ProjectUUID: projB})
	res, err = toolB.Execute(ctx, map[string]any{"uuid": runUUID}, nil)
	if err != nil {
		t.Fatalf("Execute (in-project): %v", err)
	}
	if res.IsError {
		t.Fatalf("in-project get_session should succeed, got error: %s", res.Content)
	}
	if !strings.Contains(res.Content, runUUID) {
		t.Errorf("expected run UUID in result, got: %s", res.Content)
	}
}
