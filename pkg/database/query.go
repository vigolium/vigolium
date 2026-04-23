package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// QueryFilters holds filter criteria for database queries
type QueryFilters struct {
	// Project scoping
	ProjectUUID string // Required: filter all queries to this project

	// Host filtering
	HostPattern string // Hostname pattern (supports wildcards)

	// Request filtering
	Methods     []string // HTTP methods (GET, POST, etc.)
	PathPattern string   // Path pattern (supports wildcards)
	StatusCodes []int    // Status codes (200, 404, etc.)
	ScanUUID    string   // Scan session UUID (for findings filtering)
	Source      string   // Filter by record source (e.g. scanner, ingest-cli, ingest-server)

	// Response filtering
	ContentType string // Filter by response content type

	// Risk filtering
	MinRiskScore int      // Minimum risk score filter
	Remark       string   // Filter by remark substring (single)
	Remarks      []string // Filter by multiple remarks (AND: record must have all)

	// Finding filtering
	FindingID      int      // Filter by finding ID
	FindingIDAfter int64    // Filter findings with ID greater than this value
	Severity       []string // Finding severity (critical, high, medium, low, info)
	ModuleName     string   // Filter findings by module name
	ModuleType     string   // Filter findings by module type (active, passive, nuclei, etc.)
	FindingSource  string   // Filter findings by source (audit, spa, agent, etc.)
	RepoName       string   // Filter findings by repo name
	Status         []string // Filter findings by lifecycle status (draft, triaged, false_positive, accepted_risk, fixed)

	// Date range filtering
	DateFrom *time.Time
	DateTo   *time.Time

	// Full-text search
	SearchTerm   string // Search across URLs, paths
	FuzzyTerm    string // Broad fuzzy search across multiple fields
	HeaderSearch string // Search in headers
	BodySearch   string // Search in request/response body

	// Pagination
	Limit  int
	Offset int

	// Sorting
	SortBy  string // Field to sort by
	SortAsc bool   // Sort ascending (default: descending)
}

// QueryBuilder builds filtered database queries
type QueryBuilder struct {
	db      *DB
	filters QueryFilters
}

// NewQueryBuilder creates a new query builder
func NewQueryBuilder(db *DB, filters QueryFilters) *QueryBuilder {
	return &QueryBuilder{
		db:      db,
		filters: filters,
	}
}

// BuildRecordsQuery builds a query for http_records table
func (qb *QueryBuilder) BuildRecordsQuery() *bun.SelectQuery {
	query := qb.db.NewSelect().Model((*HTTPRecord)(nil))

	qb.applyFilters(query)
	qb.applySorting(query)

	if qb.filters.Limit > 0 {
		query = query.Limit(qb.filters.Limit)
	}
	if qb.filters.Offset > 0 {
		query = query.Offset(qb.filters.Offset)
	}

	return query
}

// Count returns total number of matching records
func (qb *QueryBuilder) Count(ctx context.Context) (int64, error) {
	query := qb.db.NewSelect().Model((*HTTPRecord)(nil))
	qb.applyFilters(query)
	count, err := query.Count(ctx)
	return int64(count), err
}

// Execute executes the query and returns results
func (qb *QueryBuilder) Execute(ctx context.Context) ([]*HTTPRecord, error) {
	records := make([]*HTTPRecord, 0)
	query := qb.BuildRecordsQuery()
	if err := query.Scan(ctx, &records); err != nil {
		return nil, err
	}
	return records, nil
}

// applyFilters applies all filter conditions to the query
func (qb *QueryBuilder) applyFilters(query *bun.SelectQuery) {
	// Project scoping (always applied when set)
	if qb.filters.ProjectUUID != "" {
		query.Where("r.project_uuid = ?", qb.filters.ProjectUUID)
	}

	// Host filtering (direct column, no join)
	if qb.filters.HostPattern != "" {
		if strings.Contains(qb.filters.HostPattern, "*") {
			pattern := strings.ReplaceAll(qb.filters.HostPattern, "*", "%")
			query.Where("r.hostname LIKE ?", pattern)
		} else {
			query.Where("r.hostname = ?", qb.filters.HostPattern)
		}
	}

	// Method filtering
	if len(qb.filters.Methods) > 0 {
		query.Where("r.method IN (?)", bun.In(qb.filters.Methods))
	}

	// Path filtering (fuzzy by default, wildcards supported)
	if qb.filters.PathPattern != "" {
		if strings.Contains(qb.filters.PathPattern, "*") {
			pattern := strings.ReplaceAll(qb.filters.PathPattern, "*", "%")
			query.Where("r.path LIKE ?", pattern)
		} else {
			query.Where("r.path LIKE ?", "%"+qb.filters.PathPattern+"%")
		}
	}

	// Status code filtering (direct column, no join)
	if len(qb.filters.StatusCodes) > 0 {
		query.Where("r.status_code IN (?)", bun.In(qb.filters.StatusCodes))
	}

	// Content type filtering
	if qb.filters.ContentType != "" {
		query.Where("r.response_content_type LIKE ?", "%"+qb.filters.ContentType+"%")
	}

	// Source filtering
	if qb.filters.Source != "" {
		query.Where("r.source = ?", qb.filters.Source)
	}

	// Risk score filtering
	if qb.filters.MinRiskScore > 0 {
		query.Where("r.risk_score >= ?", qb.filters.MinRiskScore)
	}

	// Remark filtering (single)
	if qb.filters.Remark != "" {
		if qb.db.Driver() == "postgres" {
			query.Where("EXISTS (SELECT 1 FROM jsonb_array_elements_text(r.remarks::jsonb) AS je WHERE je LIKE ?)", "%"+qb.filters.Remark+"%")
		} else {
			query.Where("EXISTS (SELECT 1 FROM json_each(r.remarks) WHERE json_each.value LIKE ?)", "%"+qb.filters.Remark+"%")
		}
	}

	// Remarks filtering (multiple, AND semantics)
	for _, remark := range qb.filters.Remarks {
		if qb.db.Driver() == "postgres" {
			query.Where("EXISTS (SELECT 1 FROM jsonb_array_elements_text(r.remarks::jsonb) AS je WHERE je LIKE ?)", "%"+remark+"%")
		} else {
			query.Where("EXISTS (SELECT 1 FROM json_each(r.remarks) WHERE json_each.value LIKE ?)", "%"+remark+"%")
		}
	}

	// Severity filtering (requires join with findings via junction table)
	if len(qb.filters.Severity) > 0 {
		query.Join("INNER JOIN finding_records AS fr ON fr.record_uuid = r.uuid")
		query.Join("INNER JOIN findings AS f ON f.id = fr.finding_id")
		query.Where("f.severity IN (?)", bun.In(qb.filters.Severity))
		query.Group("r.uuid")
	}

	// Date range filtering
	if qb.filters.DateFrom != nil {
		query.Where("r.sent_at >= ?", qb.filters.DateFrom)
	}
	if qb.filters.DateTo != nil {
		query.Where("r.sent_at <= ?", qb.filters.DateTo)
	}

	// Fuzzy search (broad, across metadata + full request/response content)
	if qb.filters.FuzzyTerm != "" {
		if qb.db.HasFTS() && qb.db.Driver() != "postgres" {
			// FTS5 MATCH is orders of magnitude faster than CAST LIKE.
			// Also check metadata columns that aren't in the FTS index.
			p := "%" + qb.filters.FuzzyTerm + "%"
			query.Where(`(r.rowid IN (SELECT rowid FROM http_records_fts WHERE http_records_fts MATCH ?)
				OR r.method LIKE ? OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?)`,
				qb.filters.FuzzyTerm+"*", p, p, p, p)
		} else if qb.db.HasFTS() && qb.db.Driver() == "postgres" {
			p := "%" + qb.filters.FuzzyTerm + "%"
			query.Where(`(r.search_vector @@ plainto_tsquery('english', ?)
				OR r.method LIKE ? OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?)`,
				qb.filters.FuzzyTerm, p, p, p, p)
		} else {
			// Fallback: original CAST approach for databases without FTS
			p := "%" + qb.filters.FuzzyTerm + "%"
			query.Where(`(r.url LIKE ? OR r.path LIKE ? OR r.hostname LIKE ? OR r.method LIKE ?
				OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?
				OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?)`,
				p, p, p, p, p, p, p, p, p)
		}
	}

	// Full-text search
	if qb.filters.SearchTerm != "" {
		searchPattern := "%" + qb.filters.SearchTerm + "%"
		query.Where("r.url LIKE ? OR r.path LIKE ?", searchPattern, searchPattern)
	}

	// Header search (scans raw request/response bytes which contain headers)
	if qb.filters.HeaderSearch != "" {
		searchPattern := "%" + qb.filters.HeaderSearch + "%"
		query.Where("(CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?)",
			searchPattern, searchPattern)
	}

	// Body search (raw request/response covers body + headers)
	if qb.filters.BodySearch != "" {
		if qb.db.HasFTS() && qb.db.Driver() != "postgres" {
			// FTS5 indexes raw_request + raw_response which include body bytes
			query.Where(`r.rowid IN (SELECT rowid FROM http_records_fts WHERE http_records_fts MATCH ?)`,
				qb.filters.BodySearch+"*")
		} else {
			searchPattern := "%" + qb.filters.BodySearch + "%"
			query.Where(`(CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?)`,
				searchPattern, searchPattern)
		}
	}
}

// applySorting applies sorting to the query
func (qb *QueryBuilder) applySorting(query *bun.SelectQuery) {
	if qb.filters.SortBy == "" {
		qb.filters.SortBy = "created_at"
	}

	sortColumn := qb.mapSortColumn(qb.filters.SortBy)

	order := "DESC"
	if qb.filters.SortAsc {
		order = "ASC"
	}

	query.Order(fmt.Sprintf("%s %s", sortColumn, order))
}

// mapSortColumn maps user-friendly sort names to actual column names
func (qb *QueryBuilder) mapSortColumn(name string) string {
	switch name {
	case "uuid":
		return "r.uuid"
	case "created_at", "created":
		return "r.created_at"
	case "sent_at", "sent":
		return "r.sent_at"
	case "method":
		return "r.method"
	case "path":
		return "r.path"
	case "status_code", "status":
		return "r.status_code"
	case "response_time", "time":
		return "r.response_time_ms"
	case "source":
		return "r.source"
	case "risk_score", "risk":
		return "r.risk_score"
	default:
		return "r.created_at"
	}
}

// DeleteBuilder builds delete queries with filters
type DeleteBuilder struct {
	db      *DB
	filters QueryFilters
}

// NewDeleteBuilder creates a new delete builder
func NewDeleteBuilder(db *DB, filters QueryFilters) *DeleteBuilder {
	return &DeleteBuilder{
		db:      db,
		filters: filters,
	}
}

// DeleteRecords deletes HTTP records matching filters
func (db *DeleteBuilder) DeleteRecords(ctx context.Context, dryRun bool) (int64, error) {
	qb := NewQueryBuilder(db.db, db.filters)
	query := qb.BuildRecordsQuery().Column("uuid")

	var uuids []string
	if err := query.Scan(ctx, &uuids); err != nil {
		return 0, fmt.Errorf("failed to get record UUIDs: %w", err)
	}

	if len(uuids) == 0 {
		return 0, nil
	}

	if dryRun {
		return int64(len(uuids)), nil
	}

	// Delete associated findings first (no FK cascade)
	_, _ = db.db.NewDelete().
		Model((*Finding)(nil)).
		Where("id IN (SELECT finding_id FROM finding_records WHERE record_uuid IN (?))", bun.In(uuids)).
		Exec(ctx)

	// Clean up junction rows for deleted records
	_, _ = db.db.NewRaw("DELETE FROM finding_records WHERE record_uuid IN (?)", bun.In(uuids)).Exec(ctx)

	// Delete records
	result, err := db.db.NewDelete().
		Model((*HTTPRecord)(nil)).
		Where("uuid IN (?)", bun.In(uuids)).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete records: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// DeleteOrphans deletes orphaned findings (findings where none of the http_record_uuids exist in http_records)
func (db *DeleteBuilder) DeleteOrphans(ctx context.Context, dryRun bool) (int64, error) {
	orphanCondition := "NOT EXISTS (SELECT 1 FROM finding_records fr INNER JOIN http_records r ON r.uuid = fr.record_uuid WHERE fr.finding_id = f.id)"

	if dryRun {
		count, err := db.db.NewSelect().
			Model((*Finding)(nil)).
			Where(orphanCondition).
			Count(ctx)
		return int64(count), err
	}

	result, err := db.db.NewDelete().
		Model((*Finding)(nil)).
		Where(orphanCondition).
		Exec(ctx)
	if err != nil {
		return 0, err
	}

	rows, _ := result.RowsAffected()

	// Clean up orphaned junction rows
	_, _ = db.db.NewRaw("DELETE FROM finding_records WHERE finding_id NOT IN (SELECT id FROM findings)").Exec(ctx)

	return rows, nil
}

// DeleteFindings deletes findings matching the configured filters.
// If dryRun is true, returns the count without deleting.
func (db *DeleteBuilder) DeleteFindings(ctx context.Context, dryRun bool) (int64, error) {
	fqb := NewFindingsQueryBuilder(db.db, db.filters)

	// Count matching findings
	query := db.db.NewSelect().Model((*Finding)(nil))
	fqb.applyFindingFilters(query)

	var ids []int64
	if err := query.Column("id").Scan(ctx, &ids); err != nil {
		return 0, fmt.Errorf("failed to get finding IDs: %w", err)
	}

	if len(ids) == 0 {
		return 0, nil
	}

	if dryRun {
		return int64(len(ids)), nil
	}

	// Delete junction rows first
	_, _ = db.db.NewRaw("DELETE FROM finding_records WHERE finding_id IN (?)", bun.In(ids)).Exec(ctx)

	// Delete findings
	result, err := db.db.NewDelete().
		Model((*Finding)(nil)).
		Where("id IN (?)", bun.In(ids)).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to delete findings: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// cleanableTable defines a table that can be cleaned via `db clean --table`.
type cleanableTable struct {
	SQLName      string
	CascadeFirst []string // tables to DELETE FROM before the main table
}

// AllowedCleanTables maps user-facing table names to their SQL table name
// and any dependent tables that must be cleaned first.
var AllowedCleanTables = map[string]cleanableTable{
	"http_records":      {SQLName: "http_records", CascadeFirst: []string{"finding_records"}},
	"findings":          {SQLName: "findings", CascadeFirst: []string{"finding_records"}},
	"finding_records":   {SQLName: "finding_records"},
	"scans":             {SQLName: "scans"},
	"agentic_scans":        {SQLName: "agentic_scans"},
	"oast_interactions": {SQLName: "oast_interactions"},
	"source_repos":      {SQLName: "source_repos"},
	"scan_logs":         {SQLName: "scan_logs"},
	"session_hostnames": {SQLName: "session_hostnames"},
	"scopes":            {SQLName: "scopes"},
}

// DeleteTable deletes all rows from a specific table.
func (db *DeleteBuilder) DeleteTable(ctx context.Context, tableName string, dryRun bool) (int64, error) {
	entry, ok := AllowedCleanTables[tableName]
	if !ok {
		return 0, fmt.Errorf("table %q is not allowed for cleaning", tableName)
	}

	var count int64
	if err := db.db.NewRaw("SELECT COUNT(*) FROM "+entry.SQLName).Scan(ctx, &count); err != nil {
		return 0, fmt.Errorf("failed to count rows in %s: %w", entry.SQLName, err)
	}

	if dryRun || count == 0 {
		return count, nil
	}

	for _, dep := range entry.CascadeFirst {
		if _, err := db.db.ExecContext(ctx, "DELETE FROM "+dep); err != nil {
			return 0, fmt.Errorf("failed to clean cascade table %s: %w", dep, err)
		}
	}

	if _, err := db.db.ExecContext(ctx, "DELETE FROM "+entry.SQLName); err != nil {
		return 0, fmt.Errorf("failed to delete from %s: %w", entry.SQLName, err)
	}

	return count, nil
}

// allTablesDeleteOrder is the deletion order respecting dependencies.
var allTablesDeleteOrder = []string{
	"finding_records",
	"findings",
	"http_records",
	"oast_interactions",
	"scan_logs",
	"session_hostnames",
	"agentic_scans",
	"source_repos",
	"scopes",
	"scans",
}

// DeleteAllTables deletes all data from every data table.
func (db *DeleteBuilder) DeleteAllTables(ctx context.Context, dryRun bool) (map[string]int64, error) {
	counts := make(map[string]int64, len(allTablesDeleteOrder))
	for _, tbl := range allTablesDeleteOrder {
		var count int64
		if err := db.db.NewRaw("SELECT COUNT(*) FROM "+tbl).Scan(ctx, &count); err != nil {
			return nil, fmt.Errorf("failed to count %s: %w", tbl, err)
		}
		counts[tbl] = count
	}

	if dryRun {
		return counts, nil
	}

	for _, tbl := range allTablesDeleteOrder {
		if counts[tbl] > 0 {
			if _, err := db.db.ExecContext(ctx, "DELETE FROM "+tbl); err != nil {
				return nil, fmt.Errorf("failed to delete from %s: %w", tbl, err)
			}
		}
	}

	return counts, nil
}

// AllTablesDeleteOrder returns the ordered list of cleanable table names.
func AllTablesDeleteOrder() []string {
	return allTablesDeleteOrder
}

// FindingsQueryBuilder builds filtered queries for the findings table
type FindingsQueryBuilder struct {
	db      *DB
	filters QueryFilters
}

// NewFindingsQueryBuilder creates a new findings query builder
func NewFindingsQueryBuilder(db *DB, filters QueryFilters) *FindingsQueryBuilder {
	return &FindingsQueryBuilder{
		db:      db,
		filters: filters,
	}
}

// Count returns total number of matching findings
func (fqb *FindingsQueryBuilder) Count(ctx context.Context) (int64, error) {
	query := fqb.db.NewSelect().Model((*Finding)(nil))
	fqb.applyFindingFilters(query)
	count, err := query.Count(ctx)
	return int64(count), err
}

// Execute executes the query and returns findings
func (fqb *FindingsQueryBuilder) Execute(ctx context.Context) ([]*Finding, error) {
	findings := make([]*Finding, 0)
	query := fqb.db.NewSelect().Model((*Finding)(nil)).
		ExcludeColumn("additional_evidence", "request", "response")
	fqb.applyFindingFilters(query)
	fqb.applyFindingSorting(query)

	if fqb.filters.Limit > 0 {
		query = query.Limit(fqb.filters.Limit)
	}
	if fqb.filters.Offset > 0 {
		query = query.Offset(fqb.filters.Offset)
	}

	if err := query.Scan(ctx, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// applyFindingFilters applies filter conditions to a findings query
func (fqb *FindingsQueryBuilder) applyFindingFilters(query *bun.SelectQuery) {
	// Project scoping
	if fqb.filters.ProjectUUID != "" {
		query.Where("f.project_uuid = ?", fqb.filters.ProjectUUID)
	}

	// Finding ID filtering
	if fqb.filters.FindingID > 0 {
		query.Where("f.id = ?", fqb.filters.FindingID)
	}
	if fqb.filters.FindingIDAfter > 0 {
		query.Where("f.id > ?", fqb.filters.FindingIDAfter)
	}

	// Scan UUID filtering
	if fqb.filters.ScanUUID != "" {
		query.Where("f.scan_uuid = ?", fqb.filters.ScanUUID)
	}

	// Severity filtering
	if len(fqb.filters.Severity) > 0 {
		query.Where("f.severity IN (?)", bun.In(fqb.filters.Severity))
	}

	// Module name filtering
	if fqb.filters.ModuleName != "" {
		query.Where("f.module_name LIKE ?", "%"+fqb.filters.ModuleName+"%")
	}

	// Module type filtering
	if fqb.filters.ModuleType != "" {
		query.Where("f.module_type = ?", fqb.filters.ModuleType)
	}

	// Finding source filtering
	if fqb.filters.FindingSource != "" {
		query.Where("f.finding_source = ?", fqb.filters.FindingSource)
	}

	// Repo name filtering
	if fqb.filters.RepoName != "" {
		query.Where("f.repo_name = ?", fqb.filters.RepoName)
	}

	// Status filtering
	if len(fqb.filters.Status) > 0 {
		query.Where("f.status IN (?)", bun.In(fqb.filters.Status))
	}

	// Domain filtering (join http_records to filter by hostname via junction table)
	if fqb.filters.HostPattern != "" {
		query.Join("INNER JOIN finding_records AS fr ON fr.finding_id = f.id")
		query.Join("INNER JOIN http_records AS r ON r.uuid = fr.record_uuid")
		if strings.Contains(fqb.filters.HostPattern, "*") {
			pattern := strings.ReplaceAll(fqb.filters.HostPattern, "*", "%")
			query.Where("r.hostname LIKE ?", pattern)
		} else {
			query.Where("r.hostname = ?", fqb.filters.HostPattern)
		}
	}

	// Search across description, module_id, matched_at
	if fqb.filters.SearchTerm != "" {
		p := "%" + fqb.filters.SearchTerm + "%"
		query.Where("(f.description LIKE ? OR f.module_id LIKE ? OR f.matched_at LIKE ?)", p, p, p)
	}

	// Fuzzy search across finding fields and associated HTTP records
	if fqb.filters.FuzzyTerm != "" {
		p := "%" + fqb.filters.FuzzyTerm + "%"
		// Search finding's own fields first
		findingMatch := "(f.description LIKE ? OR f.module_id LIKE ? OR f.module_name LIKE ? OR f.module_short LIKE ? OR f.matched_at LIKE ? OR f.request LIKE ? OR f.response LIKE ?)"
		// Also search associated HTTP records via junction table
		recordMatch := `EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND (
				r.url LIKE ? OR r.path LIKE ? OR r.hostname LIKE ?
				OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?
			))`
		query.Where("("+findingMatch+" OR "+recordMatch+")",
			p, p, p, p, p, p, p, // finding fields
			p, p, p, p, p) // record fields
	}

	// Path filtering via associated HTTP records
	if fqb.filters.PathPattern != "" {
		var pathCond string
		if strings.Contains(fqb.filters.PathPattern, "*") {
			pattern := strings.ReplaceAll(fqb.filters.PathPattern, "*", "%")
			pathCond = fmt.Sprintf("r.path LIKE '%s'", strings.ReplaceAll(pattern, "'", "''"))
		} else {
			escaped := strings.ReplaceAll(fqb.filters.PathPattern, "'", "''")
			pathCond = fmt.Sprintf("r.path LIKE '%%%s%%'", escaped)
		}
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND ` + pathCond + `)`)
	}

	// Method filtering via associated HTTP records
	if len(fqb.filters.Methods) > 0 {
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND r.method IN (?))`, bun.In(fqb.filters.Methods))
	}

	// Status code filtering via associated HTTP records
	if len(fqb.filters.StatusCodes) > 0 {
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND r.status_code IN (?))`, bun.In(fqb.filters.StatusCodes))
	}

	// Source filtering via associated HTTP records
	if fqb.filters.Source != "" {
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND r.source = ?)`, fqb.filters.Source)
	}

	// Header search via associated HTTP records (raw bytes contain headers)
	if fqb.filters.HeaderSearch != "" {
		hp := "%" + fqb.filters.HeaderSearch + "%"
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND (
				CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?
			))`, hp, hp)
	}

	// Body search via associated HTTP records (raw bytes contain body)
	if fqb.filters.BodySearch != "" {
		bp := "%" + fqb.filters.BodySearch + "%"
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND (
				CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?
			))`, bp, bp)
	}

	// Date range filtering
	if fqb.filters.DateFrom != nil {
		query.Where("f.found_at >= ?", fqb.filters.DateFrom)
	}
	if fqb.filters.DateTo != nil {
		query.Where("f.found_at <= ?", fqb.filters.DateTo)
	}
}

// applyFindingSorting applies sorting to a findings query
func (fqb *FindingsQueryBuilder) applyFindingSorting(query *bun.SelectQuery) {
	sortBy := fqb.filters.SortBy
	if sortBy == "" {
		sortBy = "found_at"
	}

	sortColumn := fqb.mapFindingSortColumn(sortBy)
	order := "DESC"
	if fqb.filters.SortAsc {
		order = "ASC"
	}
	query.Order(fmt.Sprintf("%s %s", sortColumn, order))
}

// mapFindingSortColumn maps sort names to actual finding column names
func (fqb *FindingsQueryBuilder) mapFindingSortColumn(name string) string {
	switch name {
	case "found_at", "found":
		return "f.found_at"
	case "created_at", "created":
		return "f.created_at"
	case "severity":
		return "f.severity"
	case "module_name", "module":
		return "f.module_name"
	case "module_id":
		return "f.module_id"
	case "confidence":
		return "f.confidence"
	default:
		return "f.found_at"
	}
}

// SeverityCount holds a severity label and its count.
type SeverityCount struct {
	Severity string `bun:"severity" json:"severity"`
	Count    int64  `bun:"count" json:"count"`
}

// CountFindingsBySeverity returns finding counts grouped by severity.
func CountFindingsBySeverity(ctx context.Context, db *DB, projectUUID string) (map[string]int64, error) {
	var rows []SeverityCount
	q := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("severity, COUNT(*) AS count")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.GroupExpr("severity").
		Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}

	result := make(map[string]int64)
	for _, row := range rows {
		result[row.Severity] = row.Count
	}
	return result, nil
}

// CountFindingsByConfidence returns finding counts grouped by confidence.
func CountFindingsByConfidence(ctx context.Context, db *DB, projectUUID string) (map[string]int64, error) {
	var rows []struct {
		Confidence string `bun:"confidence"`
		Count      int64  `bun:"count"`
	}
	q := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("confidence, COUNT(*) AS count")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.GroupExpr("confidence").
		Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}

	result := make(map[string]int64)
	for _, row := range rows {
		result[row.Confidence] = row.Count
	}
	return result, nil
}
