package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ColumnInfo describes a single column in a database table.
type ColumnInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable string `json:"nullable"`
	Default  string `json:"default,omitempty"`
}

// ListTables returns the names of all user tables in the database.
func ListTables(ctx context.Context, db *DB) ([]string, error) {
	var query string
	switch db.Driver() {
	case "sqlite":
		query = `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`
	case "postgres":
		query = `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public' ORDER BY tablename`
	default:
		return nil, fmt.Errorf("unsupported driver: %s", db.Driver())
	}

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

// ListColumns returns column metadata for the given table.
func ListColumns(ctx context.Context, db *DB, tableName string) ([]ColumnInfo, error) {
	switch db.Driver() {
	case "sqlite":
		return listColumnsSQLite(ctx, db, tableName)
	case "postgres":
		return listColumnsPostgres(ctx, db, tableName)
	default:
		return nil, fmt.Errorf("unsupported driver: %s", db.Driver())
	}
}

func listColumnsSQLite(ctx context.Context, db *DB, tableName string) ([]ColumnInfo, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var columns []ColumnInfo
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}

		nullable := "yes"
		if notNull == 1 {
			nullable = "no"
		}
		def := ""
		if dflt.Valid {
			def = dflt.String
		}

		columns = append(columns, ColumnInfo{
			Name:     name,
			Type:     colType,
			Nullable: nullable,
			Default:  def,
		})
	}
	return columns, rows.Err()
}

func listColumnsPostgres(ctx context.Context, db *DB, tableName string) ([]ColumnInfo, error) {
	query := `SELECT column_name, data_type, is_nullable, COALESCE(column_default, '')
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
		ORDER BY ordinal_position`

	rows, err := db.QueryContext(ctx, query, tableName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var columns []ColumnInfo
	for rows.Next() {
		var col ColumnInfo
		if err := rows.Scan(&col.Name, &col.Type, &col.Nullable, &col.Default); err != nil {
			return nil, err
		}
		columns = append(columns, col)
	}
	return columns, rows.Err()
}

// QueryGenericTable runs a paginated SELECT * on the given table.
// Returns rows as ordered maps, column names, and total row count.
// The tableName must be validated against ListTables before calling.
func QueryGenericTable(ctx context.Context, db *DB, tableName string, limit, offset int) ([]map[string]interface{}, []string, int64, error) {
	// Count total rows
	var total int64
	countRow := db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", quoteIdent(db.Driver(), tableName)))
	if err := countRow.Scan(&total); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to count rows: %w", err)
	}

	// Query rows with pagination
	query := fmt.Sprintf("SELECT * FROM %s LIMIT %d OFFSET %d", quoteIdent(db.Driver(), tableName), limit, offset)
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	colNames, err := rows.Columns()
	if err != nil {
		return nil, nil, 0, err
	}

	var result []map[string]interface{}
	for rows.Next() {
		// Create a slice of interface{} pointers for Scan
		values := make([]interface{}, len(colNames))
		ptrs := make([]interface{}, len(colNames))
		for i := range values {
			ptrs[i] = &values[i]
		}

		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, 0, err
		}

		row := make(map[string]interface{}, len(colNames))
		for i, col := range colNames {
			val := values[i]
			// Convert []byte to string for display
			if b, ok := val.([]byte); ok {
				s := string(b)
				if len(s) > 200 {
					s = s[:197] + "..."
				}
				row[col] = s
			} else {
				row[col] = val
			}
		}
		result = append(result, row)
	}

	return result, colNames, total, rows.Err()
}

// quoteIdent quotes an identifier (table name) for the given driver.
func quoteIdent(driver, name string) string {
	// Sanitize: only allow alphanumeric and underscores
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
		}
	}
	switch driver {
	case "postgres":
		return `"` + name + `"`
	default:
		return `"` + name + `"`
	}
}
