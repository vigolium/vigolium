package database

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// ddlCatalog is what a list of rendered DDL statements creates: each table's
// columns (name → declared type, constraints included) and each index's
// definition. Built from the statements alone, so both dialects can be
// compared without a server.
type ddlCatalog struct {
	tables  map[string]map[string]string
	indexes map[string]string
	order   []string // object names in creation order
}

var (
	ddlAddColumn = regexp.MustCompile(`(?is)^ALTER TABLE ([A-Za-z0-9_]+) ADD COLUMN ([A-Za-z0-9_]+) (.+)$`)
	ddlIndexBody = regexp.MustCompile(`(?is)\bON\s+(.+)$`)
)

func parseDDLCatalog(t *testing.T, stmts []string) ddlCatalog {
	t.Helper()
	cat := ddlCatalog{tables: map[string]map[string]string{}, indexes: map[string]string{}}
	object := regexp.MustCompile(ddlObjectPattern)
	for _, s := range stmts {
		s = strings.TrimSpace(s)
		if m := ddlAddColumn.FindStringSubmatch(s); m != nil {
			cols := cat.tables[m[1]]
			if cols == nil {
				t.Fatalf("column migration on undeclared table: %s", s)
			}
			// A migration re-declaring a CREATE TABLE column must agree with it
			// on the type, or a fresh store and an upgraded one end up with
			// different types. Constraints may differ: adding a NOT NULL column
			// to existing rows needs a DEFAULT the CREATE TABLE can omit.
			if prev, ok := cols[m[2]]; ok {
				if ddlTypeHead(prev) != ddlTypeHead(m[3]) {
					t.Errorf("%s.%s: CREATE TABLE declares %q, column migration %q", m[1], m[2], prev, m[3])
				}
				continue
			}
			cols[m[2]] = m[3]
			continue
		}
		m := object.FindStringSubmatch(s)
		if m == nil {
			t.Fatalf("unparsed DDL statement: %s", s)
		}
		name := m[1]
		cat.order = append(cat.order, name)
		if regexp.MustCompile(`(?i)^CREATE\s+(UNIQUE\s+)?INDEX`).MatchString(s) {
			body := ddlIndexBody.FindStringSubmatch(s)
			if body == nil {
				t.Fatalf("index without ON clause: %s", s)
			}
			unique := strings.HasPrefix(strings.ToUpper(s), "CREATE UNIQUE")
			cat.indexes[name] = strings.Join(strings.Fields(body[1]), " ") + map[bool]string{true: " UNIQUE"}[unique]
			continue
		}
		open, closeIdx := strings.Index(s, "("), strings.LastIndex(s, ")")
		cols := map[string]string{}
		for _, line := range strings.Split(s[open+1:closeIdx], "\n") {
			line = strings.TrimSuffix(strings.TrimSpace(line), ",")
			if line == "" {
				continue
			}
			first, rest, _ := strings.Cut(line, " ")
			switch strings.ToUpper(strings.TrimRight(first, "(")) {
			case "PRIMARY", "UNIQUE", "CONSTRAINT", "FOREIGN", "CHECK":
				continue
			}
			cols[first] = rest
		}
		cat.tables[name] = cols
	}
	return cat
}

// sqliteOnlyDDLTokens must never reach Postgres.
var sqliteOnlyDDLTokens = []string{"AUTOINCREMENT", "BLOB", "INSERT OR", "OR IGNORE", "PRAGMA", "WITHOUT ROWID"}

// TestSchemaDDL_PostgresRender renders every statement CreateSchema issues for
// Postgres, with no live server: no SQLite-only token and no unrendered
// template token survives, and every {{BOOL}} column is BOOLEAN.
func TestSchemaDDL_PostgresRender(t *testing.T) {
	pg := schemaDDLStatements(driverPostgres)
	all := strings.Join(pg, "\n")
	upper := strings.ToUpper(all)
	for _, tok := range sqliteOnlyDDLTokens {
		if strings.Contains(upper, tok) {
			t.Errorf("Postgres DDL contains SQLite-only token %q", tok)
		}
	}
	for _, driver := range []string{driverSQLite, driverPostgres} {
		for _, s := range schemaDDLStatements(driver) {
			if strings.Contains(s, "{{") || strings.Contains(s, "}}") {
				t.Errorf("%s render left a template token: %s", driver, s)
			}
		}
	}
	if !strings.Contains(all, "SERIAL PRIMARY KEY") || !strings.Contains(all, "BYTEA") {
		t.Error("Postgres spellings did not apply")
	}

	cat := parseDDLCatalog(t, pg)
	bools := schemaBoolColumns()
	if len(bools) == 0 {
		t.Fatal("no {{BOOL}} columns parsed from the templates")
	}
	for _, b := range bools {
		got := cat.tables[b.Table][b.Column]
		want := "BOOLEAN NOT NULL DEFAULT FALSE"
		if b.Default {
			want = "BOOLEAN NOT NULL DEFAULT TRUE"
		}
		if got != want {
			t.Errorf("Postgres %s.%s = %q, want %q", b.Table, b.Column, got, want)
		}
	}
	// No bool-shaped INTEGER 0/1 column at all: a bool declared with a literal
	// type instead of {{BOOL}} would slip past the list above.
	for table, cols := range cat.tables {
		for col, typ := range cols {
			if regexp.MustCompile(`^INTEGER NOT NULL DEFAULT [01]$`).MatchString(typ) && !isCounterColumn(col) {
				t.Errorf("Postgres %s.%s is INTEGER 0/1 (%q): declare it {{BOOL}} if it is a flag", table, col, typ)
			}
		}
	}
	for _, tbl := range v3Tables {
		if _, ok := cat.tables[tbl]; !ok {
			t.Errorf("Postgres DDL does not create %s", tbl)
		}
	}
}

// isCounterColumn names the INTEGER NOT NULL DEFAULT 0 columns that are counts,
// not flags, so the bool-shape check above can tell them apart.
func isCounterColumn(col string) bool {
	return col == "port" || col == "seq" || col == "promoted_finding_id" || col == "timed_out" || strings.HasSuffix(col, "version") ||
		strings.HasSuffix(col, "_count") || strings.HasSuffix(col, "_tokens")
}

// TestSchemaDDL_SQLiteRenderUnchanged pins the SQLite spellings: SQLite stores
// the CREATE text in sqlite_master, and the templates must render exactly the
// DDL every existing store was created with.
func TestSchemaDDL_SQLiteRenderUnchanged(t *testing.T) {
	cat := parseDDLCatalog(t, schemaDDLStatements(driverSQLite))
	for _, b := range schemaBoolColumns() {
		want := "INTEGER NOT NULL DEFAULT 0"
		if b.Default {
			want = "INTEGER NOT NULL DEFAULT 1"
		}
		if got := cat.tables[b.Table][b.Column]; got != want {
			t.Errorf("SQLite %s.%s = %q, want %q", b.Table, b.Column, got, want)
		}
	}
	if got := cat.tables["findings"]["id"]; got != "INTEGER PRIMARY KEY AUTOINCREMENT" {
		t.Errorf("SQLite findings.id = %q", got)
	}
	if got := cat.tables["http_records"]["raw_request"]; got != "BLOB" {
		t.Errorf("SQLite http_records.raw_request = %q", got)
	}
	if got := cat.tables["findings"]["cvss_score"]; got != "REAL DEFAULT 0" {
		t.Errorf("SQLite findings.cvss_score = %q", got)
	}
}

// dialectSpellings are the concrete type names a template must NOT spell
// directly: each has a token, and a literal one renders the same for both
// dialects — which is how a column ends up wrong on one of them.
var dialectSpellings = regexp.MustCompile(`\b(AUTOINCREMENT|SERIAL|BLOB|BYTEA|BOOLEAN|REAL|DOUBLE PRECISION|JSONB?)\b|(?:^|[^_])\bTIMESTAMP\b`)

// TestSchemaDDL_TemplatesUseTokens keeps dialect-sensitive types out of the
// templates as literals.
func TestSchemaDDL_TemplatesUseTokens(t *testing.T) {
	var tmpls []string
	tmpls = append(tmpls, schemaTables...)
	for _, m := range columnMigrations {
		tmpls = append(tmpls, columnMigrationDDL(m))
	}
	tmpls = append(tmpls, schemaIndexes...)
	tmpls = append(tmpls, recordSecondaryIndexes...)
	known := map[string]bool{}
	for _, tok := range ddlTokens {
		known[tok.token] = true
	}
	tokenRef := regexp.MustCompile(`\{\{[A-Z_]+\}\}`)
	for _, s := range tmpls {
		bare := tokenRef.ReplaceAllStringFunc(s, func(tok string) string {
			if !known[tok] {
				t.Errorf("unknown template token %s in: %s", tok, s)
			}
			return ""
		})
		if m := dialectSpellings.FindString(bare); m != "" {
			t.Errorf("template spells %q literally (use its token): %s", strings.TrimSpace(m), s)
		}
	}
}

// TestSchemaDDL_ModelTypesMatchTokens cross-checks the templates against the
// bun models: every bool field is a {{BOOL}} column, every type:jsonb field a
// {{JSON}} column and every float field a {{FLOAT}} column, on its own table.
func TestSchemaDDL_ModelTypesMatchTokens(t *testing.T) {
	// The templates rendered with token names kept, so the declared token is
	// readable per column.
	var stmts []string
	stmts = append(stmts, schemaTables...)
	for _, m := range columnMigrations {
		stmts = append(stmts, columnMigrationDDL(m))
	}
	cat := parseDDLCatalog(t, stmts)

	models := []any{User{}, Project{}, Scan{}, HTTPRecord{}, AnalysisArtifact{}, HostObservation{}, Finding{},
		FindingObservation{}, FindingStatusEvent{}, OASTPayload{}, AuthenticationHostname{}, OASTInteraction{},
		ScanLog{}, AgenticScan{}, AgentSection{}, AgentFindingCandidate{}, Scope{}}
	for _, m := range models {
		rt := reflect.TypeOf(m)
		base, _ := rt.Field(0).Tag.Lookup("bun")
		table, _, _ := strings.Cut(strings.TrimPrefix(base, "table:"), ",")
		cols, ok := cat.tables[table]
		if !ok {
			t.Errorf("%s: table %q not in the schema templates", rt.Name(), table)
			continue
		}
		for i := 1; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag, ok := f.Tag.Lookup("bun")
			if !ok || tag == "-" || f.Anonymous || strings.Contains(tag, "scanonly") {
				continue
			}
			col, opts, _ := strings.Cut(tag, ",")
			decl, declared := cols[col]
			var want string
			switch {
			case f.Type.Kind() == reflect.Bool:
				want = "{{BOOL}}"
			case strings.Contains(opts, "type:json"):
				want = "{{JSON}}"
			case f.Type.Kind() == reflect.Float64 || f.Type.Kind() == reflect.Float32:
				want = "{{FLOAT}}"
			default:
				continue
			}
			if !declared {
				t.Errorf("%s.%s: column %s.%s is not declared in the templates", rt.Name(), f.Name, table, col)
				continue
			}
			if !strings.HasPrefix(decl, want) {
				t.Errorf("%s.%s: %s.%s declared %q, want %s", rt.Name(), f.Name, table, col, decl, want)
			}
		}
	}
}

// TestSchemaDDL_CatalogParity: both dialect renders create the same tables
// with the same columns, and the same indexes over the same columns, in the
// same order.
func TestSchemaDDL_CatalogParity(t *testing.T) {
	lite := parseDDLCatalog(t, schemaDDLStatements(driverSQLite))
	pg := parseDDLCatalog(t, schemaDDLStatements(driverPostgres))

	if !slices.Equal(lite.order, pg.order) {
		t.Errorf("creation order differs:\nsqlite   %v\npostgres %v", lite.order, pg.order)
	}
	if len(lite.tables) != len(pg.tables) || len(lite.tables) != len(schemaTables) {
		t.Errorf("table count: sqlite %d, postgres %d, templates %d", len(lite.tables), len(pg.tables), len(schemaTables))
	}
	for table, cols := range lite.tables {
		pgCols, ok := pg.tables[table]
		if !ok {
			t.Errorf("table %s only in the SQLite render", table)
			continue
		}
		if a, b := sortedKeys(cols), sortedKeys(pgCols); !slices.Equal(a, b) {
			t.Errorf("%s columns differ:\nsqlite   %v\npostgres %v", table, a, b)
		}
	}
	if len(lite.indexes) != len(schemaIndexes)+len(recordSecondaryIndexes) {
		t.Errorf("index count %d, templates %d", len(lite.indexes), len(schemaIndexes)+len(recordSecondaryIndexes))
	}
	for name, def := range lite.indexes {
		if pg.indexes[name] != def {
			t.Errorf("index %s: sqlite %q, postgres %q", name, def, pg.indexes[name])
		}
		table, _, _ := strings.Cut(def, "(")
		if _, ok := lite.tables[strings.TrimSpace(table)]; !ok {
			t.Errorf("index %s is on undeclared table %q", name, table)
		}
	}
}

// ddlTypeHead is the type part of a column declaration: everything before its
// first constraint keyword.
func ddlTypeHead(decl string) string {
	head, _, _ := strings.Cut(decl+" ", " NOT NULL")
	head, _, _ = strings.Cut(head+" ", " DEFAULT")
	head, _, _ = strings.Cut(head+" ", " PRIMARY")
	return strings.TrimSpace(head)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
