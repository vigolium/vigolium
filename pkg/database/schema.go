package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// GenericQueryOptions holds options for filtered, sorted, paginated generic queries.
type GenericQueryOptions struct {
	Limit      int
	Offset     int
	SortBy     string // Column to sort by
	SortAsc    bool
	Columns    []string // Column whitelist (empty = all)
	SearchTerm string   // Fuzzy search across text columns
	Truncate   int      // Truncate []byte fields to this length (0 = no truncation)
	Filters    []GenericFilter
}

// GenericFilter represents a single column filter.
type GenericFilter struct {
	Column   string
	Operator string // "eq", "like", "gt", "lt", "gte", "lte", "in", "neq"
	Value    string
}

// TableInfo describes a table with its row count.
type TableInfo struct {
	Name     string `json:"name"`
	RowCount int64  `json:"row_count"`
}

// PrimaryKeyInfo describes the primary key column(s) of a table.
type PrimaryKeyInfo struct {
	Columns []string `json:"columns"`
}

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
	// bun's QueryContext inlines `?` placeholders before sending to the driver
	// — it does NOT recognize `$1`/`$N`, so use `?` here regardless of dialect.
	query := `SELECT column_name, data_type, is_nullable, COALESCE(column_default, '')
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = ?
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

// ListTablesWithCounts returns all user tables with their row counts.
func ListTablesWithCounts(ctx context.Context, db *DB) ([]TableInfo, error) {
	tables, err := ListTables(ctx, db)
	if err != nil {
		return nil, err
	}

	result := make([]TableInfo, 0, len(tables))
	for _, t := range tables {
		var count int64
		row := db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", quoteIdent(db.Driver(), t)))
		if err := row.Scan(&count); err != nil {
			count = -1 // signal error but don't fail entirely
		}
		result = append(result, TableInfo{Name: t, RowCount: count})
	}
	return result, nil
}

// DetectPrimaryKey returns the primary key column(s) for the given table.
func DetectPrimaryKey(ctx context.Context, db *DB, tableName string) (PrimaryKeyInfo, error) {
	switch db.Driver() {
	case "sqlite":
		return detectPKSQLite(ctx, db, tableName)
	case "postgres":
		return detectPKPostgres(ctx, db, tableName)
	default:
		return PrimaryKeyInfo{}, fmt.Errorf("unsupported driver: %s", db.Driver())
	}
}

func detectPKSQLite(ctx context.Context, db *DB, tableName string) (PrimaryKeyInfo, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return PrimaryKeyInfo{}, err
	}
	defer func() { _ = rows.Close() }()

	var pkCols []string
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return PrimaryKeyInfo{}, err
		}
		if pk > 0 {
			pkCols = append(pkCols, name)
		}
	}
	if len(pkCols) == 0 {
		pkCols = []string{"rowid"}
	}
	return PrimaryKeyInfo{Columns: pkCols}, rows.Err()
}

func detectPKPostgres(ctx context.Context, db *DB, tableName string) (PrimaryKeyInfo, error) {
	query := `SELECT a.attname
		FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		WHERE i.indrelid = ?::regclass AND i.indisprimary
		ORDER BY array_position(i.indkey, a.attnum)`

	rows, err := db.QueryContext(ctx, query, tableName)
	if err != nil {
		return PrimaryKeyInfo{}, err
	}
	defer func() { _ = rows.Close() }()

	var pkCols []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return PrimaryKeyInfo{}, err
		}
		pkCols = append(pkCols, col)
	}
	if len(pkCols) == 0 {
		return PrimaryKeyInfo{Columns: []string{"id"}}, rows.Err()
	}
	return PrimaryKeyInfo{Columns: pkCols}, rows.Err()
}

// ValidateTableName checks that the given name is in the list of real tables.
func ValidateTableName(ctx context.Context, db *DB, tableName string) error {
	tables, err := ListTables(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to list tables: %w", err)
	}
	for _, t := range tables {
		if t == tableName {
			return nil
		}
	}
	return fmt.Errorf("table %q not found", tableName)
}

// isValidColumn checks that a column name exists in the given column list.
func isValidColumn(name string, columns []ColumnInfo) bool {
	for _, c := range columns {
		if c.Name == name {
			return true
		}
	}
	return false
}

// QueryGenericTableFiltered runs a filtered, sorted, paginated SELECT on the given table.
// The tableName and all column references are validated before use.
func QueryGenericTableFiltered(ctx context.Context, db *DB, tableName string, opts GenericQueryOptions) ([]map[string]interface{}, []string, int64, error) {
	if err := ValidateTableName(ctx, db, tableName); err != nil {
		return nil, nil, 0, err
	}

	allColumns, err := ListColumns(ctx, db, tableName)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get columns: %w", err)
	}

	driver := db.Driver()
	tbl := quoteIdent(driver, tableName)

	// Build WHERE clause
	where, args, err := buildWhereClause(driver, allColumns, opts)
	if err != nil {
		return nil, nil, 0, err
	}

	// Count total matching rows
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM %s%s", tbl, where)
	var total int64
	if err := db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to count rows: %w", err)
	}

	// Build SELECT columns
	selectCols := "*"
	if len(opts.Columns) > 0 {
		var validCols []string
		for _, c := range opts.Columns {
			if isValidColumn(c, allColumns) {
				validCols = append(validCols, quoteIdent(driver, c))
			}
		}
		if len(validCols) > 0 {
			selectCols = strings.Join(validCols, ", ")
		}
	}

	// Build ORDER BY
	orderClause := ""
	if opts.SortBy != "" && isValidColumn(opts.SortBy, allColumns) {
		dir := "DESC"
		if opts.SortAsc {
			dir = "ASC"
		}
		orderClause = fmt.Sprintf(" ORDER BY %s %s", quoteIdent(driver, opts.SortBy), dir)
	}

	// Apply defaults
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	querySQL := fmt.Sprintf("SELECT %s FROM %s%s%s LIMIT %d OFFSET %d",
		selectCols, tbl, where, orderClause, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	colNames, err := rows.Columns()
	if err != nil {
		return nil, nil, 0, err
	}

	result, err := scanGenericRows(rows, colNames, opts.Truncate)
	if err != nil {
		return nil, nil, 0, err
	}
	return result, colNames, total, nil
}

// GetGenericRecord fetches a single record by primary key.
func GetGenericRecord(ctx context.Context, db *DB, tableName, pkValue string) (map[string]interface{}, error) {
	if err := ValidateTableName(ctx, db, tableName); err != nil {
		return nil, err
	}

	pk, err := DetectPrimaryKey(ctx, db, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to detect primary key: %w", err)
	}
	if len(pk.Columns) != 1 {
		return nil, fmt.Errorf("single-value lookup not supported for composite PK table %q", tableName)
	}

	driver := db.Driver()
	tbl := quoteIdent(driver, tableName)
	pkCol := quoteIdent(driver, pk.Columns[0])
	placeholder := makePlaceholder(driver, 1)

	query := fmt.Sprintf("SELECT * FROM %s WHERE %s = %s LIMIT 1", tbl, pkCol, placeholder)
	rows, err := db.QueryContext(ctx, query, pkValue)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	colNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	results, err := scanGenericRows(rows, colNames, 0)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, sql.ErrNoRows
	}
	return results[0], nil
}

// InsertGenericRecord inserts a record into the given table.
// fields is a map of column_name -> value. Column names are validated.
func InsertGenericRecord(ctx context.Context, db *DB, tableName string, fields map[string]interface{}) error {
	if err := ValidateTableName(ctx, db, tableName); err != nil {
		return err
	}

	allColumns, err := ListColumns(ctx, db, tableName)
	if err != nil {
		return fmt.Errorf("failed to get columns: %w", err)
	}

	driver := db.Driver()
	var cols []string
	var placeholders []string
	var args []interface{}
	i := 1
	for col, val := range fields {
		if !isValidColumn(col, allColumns) {
			return fmt.Errorf("invalid column %q for table %q", col, tableName)
		}
		cols = append(cols, quoteIdent(driver, col))
		placeholders = append(placeholders, makePlaceholder(driver, i))
		args = append(args, val)
		i++
	}

	if len(cols) == 0 {
		return fmt.Errorf("no valid fields provided")
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		quoteIdent(driver, tableName),
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "))

	_, err = db.ExecContext(ctx, query, args...)
	return err
}

// UpdateGenericRecord updates a record by primary key.
// fields is a map of column_name -> new_value. PK columns cannot be updated.
func UpdateGenericRecord(ctx context.Context, db *DB, tableName, pkValue string, fields map[string]interface{}) error {
	if err := ValidateTableName(ctx, db, tableName); err != nil {
		return err
	}

	pk, err := DetectPrimaryKey(ctx, db, tableName)
	if err != nil {
		return fmt.Errorf("failed to detect primary key: %w", err)
	}
	if len(pk.Columns) != 1 {
		return fmt.Errorf("single-value update not supported for composite PK table %q", tableName)
	}

	allColumns, err := ListColumns(ctx, db, tableName)
	if err != nil {
		return fmt.Errorf("failed to get columns: %w", err)
	}

	driver := db.Driver()
	pkColName := pk.Columns[0]

	var setClauses []string
	var args []interface{}
	i := 1
	for col, val := range fields {
		if col == pkColName {
			return fmt.Errorf("cannot update primary key column %q", col)
		}
		if !isValidColumn(col, allColumns) {
			return fmt.Errorf("invalid column %q for table %q", col, tableName)
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = %s", quoteIdent(driver, col), makePlaceholder(driver, i)))
		args = append(args, val)
		i++
	}

	if len(setClauses) == 0 {
		return fmt.Errorf("no valid fields to update")
	}

	args = append(args, pkValue)
	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s = %s",
		quoteIdent(driver, tableName),
		strings.Join(setClauses, ", "),
		quoteIdent(driver, pkColName),
		makePlaceholder(driver, i))

	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteGenericRecord deletes a record by primary key.
func DeleteGenericRecord(ctx context.Context, db *DB, tableName, pkValue string) error {
	if err := ValidateTableName(ctx, db, tableName); err != nil {
		return err
	}

	pk, err := DetectPrimaryKey(ctx, db, tableName)
	if err != nil {
		return fmt.Errorf("failed to detect primary key: %w", err)
	}
	if len(pk.Columns) != 1 {
		return fmt.Errorf("single-value delete not supported for composite PK table %q", tableName)
	}

	driver := db.Driver()
	query := fmt.Sprintf("DELETE FROM %s WHERE %s = %s",
		quoteIdent(driver, tableName),
		quoteIdent(driver, pk.Columns[0]),
		makePlaceholder(driver, 1))

	result, err := db.ExecContext(ctx, query, pkValue)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// buildWhereClause constructs a WHERE clause from filters and search term.
func buildWhereClause(driver string, allColumns []ColumnInfo, opts GenericQueryOptions) (string, []interface{}, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	// Apply column filters
	for _, f := range opts.Filters {
		if !isValidColumn(f.Column, allColumns) {
			return "", nil, fmt.Errorf("invalid filter column %q", f.Column)
		}
		col := quoteIdent(driver, f.Column)
		ph := makePlaceholder(driver, argIdx)

		switch f.Operator {
		case "eq", "":
			conditions = append(conditions, fmt.Sprintf("%s = %s", col, ph))
			args = append(args, f.Value)
		case "neq":
			conditions = append(conditions, fmt.Sprintf("%s != %s", col, ph))
			args = append(args, f.Value)
		case "like":
			conditions = append(conditions, fmt.Sprintf("%s LIKE %s", col, ph))
			args = append(args, f.Value)
		case "gt":
			conditions = append(conditions, fmt.Sprintf("%s > %s", col, ph))
			args = append(args, f.Value)
		case "gte":
			conditions = append(conditions, fmt.Sprintf("%s >= %s", col, ph))
			args = append(args, f.Value)
		case "lt":
			conditions = append(conditions, fmt.Sprintf("%s < %s", col, ph))
			args = append(args, f.Value)
		case "lte":
			conditions = append(conditions, fmt.Sprintf("%s <= %s", col, ph))
			args = append(args, f.Value)
		case "in":
			vals := strings.Split(f.Value, ",")
			phs := make([]string, len(vals))
			for j, v := range vals {
				phs[j] = makePlaceholder(driver, argIdx+j)
				args = append(args, strings.TrimSpace(v))
			}
			conditions = append(conditions, fmt.Sprintf("%s IN (%s)", col, strings.Join(phs, ", ")))
			argIdx += len(vals) - 1 // -1 because we increment below
		default:
			return "", nil, fmt.Errorf("unsupported filter operator %q", f.Operator)
		}
		argIdx++
	}

	// Apply search term (fuzzy match across text columns)
	if opts.SearchTerm != "" {
		var searchConds []string
		for _, c := range allColumns {
			colType := strings.ToUpper(c.Type)
			if strings.Contains(colType, "TEXT") || strings.Contains(colType, "VARCHAR") ||
				strings.Contains(colType, "CHAR") || colType == "CHARACTER VARYING" ||
				colType == "UUID" {
				ph := makePlaceholder(driver, argIdx)
				searchConds = append(searchConds, fmt.Sprintf("%s LIKE %s", quoteIdent(driver, c.Name), ph))
				args = append(args, "%"+opts.SearchTerm+"%")
				argIdx++
			}
		}
		if len(searchConds) > 0 {
			conditions = append(conditions, "("+strings.Join(searchConds, " OR ")+")")
		}
	}

	if len(conditions) == 0 {
		return "", nil, nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args, nil
}

// scanGenericRows scans sql.Rows into a slice of maps.
func scanGenericRows(rows *sql.Rows, colNames []string, truncate int) ([]map[string]interface{}, error) {
	var result []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(colNames))
		ptrs := make([]interface{}, len(colNames))
		for i := range values {
			ptrs[i] = &values[i]
		}

		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{}, len(colNames))
		for i, col := range colNames {
			val := values[i]
			if b, ok := val.([]byte); ok {
				s := string(b)
				if truncate > 0 && len(s) > truncate {
					s = s[:truncate-3] + "..."
				}
				row[col] = s
			} else {
				row[col] = val
			}
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// makePlaceholder returns a parameterized placeholder for the given driver and position.
//
// Always `?` — every query in this package goes through bun.DB, which inlines
// `?` placeholders into the SQL string before handing it to the underlying
// driver. Bun does not recognize `$N`-style placeholders and silently drops
// the args, so even on postgres we must emit `?`.
func makePlaceholder(driver string, position int) string {
	_ = driver
	_ = position
	return "?"
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
