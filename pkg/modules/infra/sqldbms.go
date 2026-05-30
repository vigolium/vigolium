package infra

import "strings"

// DBMSTechTag is the per-host TechRegistry tag under which a detected backend
// DBMS is recorded, so one SQLi module (e.g. error-based) can hint the backend
// to another (e.g. time-based) and let it prioritize matching payloads.
func DBMSTechTag(dbType string) string {
	return "dbms:" + dbType
}

// NormalizeDBMS maps a human DBMS name (as produced by error-signature
// matching) to the canonical dbType used by the time-based payloads
// ("mysql", "postgres", "mssql", "oracle", "sqlite"). Compatible engines are
// folded onto the dialect whose sleep primitive they share. Returns "" when the
// engine has no time-based dialect this scanner models.
func NormalizeDBMS(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "mysql"), strings.Contains(n, "mariadb"), strings.Contains(n, "tidb"):
		return "mysql"
	case strings.Contains(n, "postgre"), strings.Contains(n, "cockroach"), strings.Contains(n, "yugabyte"):
		return "postgres"
	case strings.Contains(n, "microsoft sql"), strings.Contains(n, "sql server"), strings.Contains(n, "mssql"):
		return "mssql"
	case strings.Contains(n, "oracle"):
		return "oracle"
	case strings.Contains(n, "sqlite"):
		return "sqlite"
	default:
		return ""
	}
}
