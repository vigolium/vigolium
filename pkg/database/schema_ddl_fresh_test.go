package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/uptrace/bun/driver/sqliteshim"
)

// sqliteCatalog reads every table's columns and every index name from a
// SQLite handle, skipping SQLite's own objects.
func sqliteCatalog(t *testing.T, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string][]string, []string) {
	t.Helper()
	ctx := context.Background()
	rows, err := q.QueryContext(ctx, "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var tables, indexes []string
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			t.Fatal(err)
		}
		switch typ {
		case "table":
			tables = append(tables, name)
		case "index":
			indexes = append(indexes, name)
		}
	}
	_ = rows.Close()
	cols := map[string][]string{}
	for _, table := range tables {
		r, err := q.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", table)
		if err != nil {
			t.Fatal(err)
		}
		for r.Next() {
			var c string
			if err := r.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols[table] = append(cols[table], c)
		}
		_ = r.Close()
		sort.Strings(cols[table])
	}
	return cols, indexes
}

// The printed DDL, executed in order on an empty file, builds the same tables,
// columns and indexes CreateSchema does, and every statement is one line.
func TestFreshSchemaDDLBuildsTheRealSchema(t *testing.T) {
	stmts := FreshSchemaDDL()
	if len(stmts) == 0 {
		t.Fatal("no statements")
	}
	raw, err := sql.Open(sqliteshim.ShimName, filepath.Join(t.TempDir(), "fresh.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	for _, s := range stmts {
		if strings.Contains(s, "\n") {
			t.Errorf("statement spans lines: %q", s)
		}
		if _, err := raw.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}

	want := newTestDB(t)
	wantCols, wantIdx := sqliteCatalog(t, want.DB)
	gotCols, gotIdx := sqliteCatalog(t, raw)
	if len(gotCols) != len(wantCols) {
		t.Errorf("tables: got %d, CreateSchema made %d", len(gotCols), len(wantCols))
	}
	for table, cols := range wantCols {
		if strings.Join(gotCols[table], ",") != strings.Join(cols, ",") {
			t.Errorf("%s columns:\n got  %v\n want %v", table, gotCols[table], cols)
		}
	}
	if strings.Join(gotIdx, ",") != strings.Join(wantIdx, ",") {
		t.Errorf("indexes:\n got  %v\n want %v", gotIdx, wantIdx)
	}
}

// A column a CREATE TABLE already declares gets no ALTER; one it does not
// declare keeps its migration.
func TestDeclaresColumn(t *testing.T) {
	body := "CREATE TABLE IF NOT EXISTS t (\n\t\tid INTEGER,\n\t\tmodule_stats {{JSON}},\n\t\tmodule_statsx TEXT\n\t)"
	if !declaresColumn(body, "module_stats") || !declaresColumn(body, "id") {
		t.Error("declared columns not found")
	}
	if declaresColumn(body, "module") || declaresColumn(body, "stats") {
		t.Error("a prefix of a declared column is not a declaration")
	}
}
