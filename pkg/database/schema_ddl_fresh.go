package database

import (
	"regexp"
	"strings"
)

// FreshSchemaDDL is the SQLite DDL that creates an empty store at
// CurrentSchemaVersion, one statement per entry, each on a single line: the
// tables, the column migrations a table's CREATE TABLE does not already
// declare (those exist for stores created before the column, and an ALTER that
// adds a declared column fails on a fresh file), then every index. Executed in
// order on an empty SQLite file it yields the tables, columns and indexes
// CreateSchema creates; schema_meta is created but holds no version row.
// `vigolium schema storage --ddl` prints it, so a caller's test fixtures use
// the real schema instead of a hand-written copy.
func FreshSchemaDDL() []string {
	declared := map[string]string{} // table → its CREATE TABLE body
	for _, ddl := range schemaTables {
		if m := ddlObjectRe.FindStringSubmatch(ddl); m != nil {
			declared[strings.ToLower(m[1])] = ddl
		}
	}
	// schemaDDLStatements is tables, then one statement per column migration
	// (index-aligned with columnMigrations), then indexes: drop the migrations
	// a CREATE TABLE already declares.
	stmts := schemaDDLStatements(driverSQLite)
	migStart := len(schemaTables)
	out := make([]string, 0, len(stmts))
	for i, ddl := range stmts {
		if j := i - migStart; j >= 0 && j < len(columnMigrations) {
			m := columnMigrations[j]
			if body, ok := declared[strings.ToLower(m.Table)]; ok && declaresColumn(body, m.Column) {
				continue
			}
		}
		out = append(out, oneLineDDL(ddl))
	}
	return out
}

var (
	ddlObjectRe  = regexp.MustCompile(ddlObjectPattern)
	ddlLineBreak = regexp.MustCompile(`\s*\n\s*`)
)

// declaresColumn reports whether a CREATE TABLE template declares column (a
// line that starts with its name followed by whitespace).
func declaresColumn(createTable, column string) bool {
	lines := strings.Split(createTable, "\n")
	for i, line := range lines {
		t := strings.TrimLeft(line, " \t\r\f\v")
		if !strings.HasPrefix(t, column) {
			continue
		}
		if rest := t[len(column):]; rest == "" {
			if i < len(lines)-1 { // followed by the newline
				return true
			}
		} else if strings.ContainsRune(" \t\r\f\v", rune(rest[0])) {
			return true
		}
	}
	return false
}

// oneLineDDL folds a statement's line breaks and indentation into single
// spaces, keeping "(" and ")" tight.
func oneLineDDL(ddl string) string {
	s := ddlLineBreak.ReplaceAllString(strings.TrimSpace(ddl), " ")
	s = strings.ReplaceAll(s, "( ", "(")
	return strings.ReplaceAll(s, " )", ")")
}
