package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"go.uber.org/zap"
)

// QueryFilters holds filter criteria for database queries
type QueryFilters struct {
	// Project scoping
	ProjectUUID string // Required: filter all queries to this project

	// Host filtering
	HostPattern string // Hostname pattern (supports wildcards)

	// Request filtering
	Methods          []string // HTTP methods (GET, POST, etc.)
	PathPattern      string   // Path pattern (supports wildcards)
	StatusCodes      []int    // Status codes (200, 404, etc.)
	ScanUUID         string   // Scan session UUID (for findings filtering)
	AgenticScanUUIDs []string // Agentic-scan UUID(s) (links agent-produced findings; pass the scan tree for nested audit/swarm runs)
	Source           string   // Filter by record source (e.g. scanner, ingest-cli, ingest-server)

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
	Confidence     []string // Finding confidence (certain, firm, tentative)
	ModuleName     string   // Filter findings by module name
	ModuleType     string   // Filter findings by module type (active, passive, nuclei, etc.)
	FindingSource  string   // Filter findings by source (audit, spa, agent, etc.)
	RecordKinds    []string // finding (default), candidate, observation
	RepoName       string   // Filter findings by repo name
	Status         []string // Filter findings by lifecycle status (draft, triaged, false_positive, accepted_risk, fixed)

	// Date range filtering
	DateFrom *time.Time
	DateTo   *time.Time

	// Full-text search
	SearchTerm   string   // Search across URLs, paths
	SearchTerms  []string // Findings: repeatable search terms, AND-combined (each further narrows the match)
	FuzzyTerm    string   // Broad fuzzy search across multiple fields
	HeaderSearch string   // Search in headers
	BodySearch   string   // Search in request/response body

	// Negative / exclusion search — drop rows where the term appears in the same
	// corpus the positive counterpart scans.
	ExcludeTerms        []string // Repeatable, AND-combined: a row is dropped if ANY term matches (inverse of SearchTerms)
	ExcludeHeaderSearch string   // Drop rows whose header/raw corpus contains the term (inverse of HeaderSearch)
	ExcludeBodySearch   string   // Drop rows whose body/raw corpus contains the term (inverse of BodySearch)

	// Pagination
	Limit  int
	Offset int

	// Sorting
	SortBy  string // Field to sort by
	SortAsc bool   // Sort ascending (default: descending)
}

// EffectiveSearchTerms returns the search terms to AND-combine: the repeatable
// SearchTerms when set, otherwise the single SearchTerm. Blank terms are
// dropped, so callers can loop the result directly.
func (f QueryFilters) EffectiveSearchTerms() []string {
	terms := f.SearchTerms
	if len(terms) == 0 && f.SearchTerm != "" {
		terms = []string{f.SearchTerm}
	}
	return nonBlank(terms)
}

// EffectiveExcludeTerms returns the exclusion search terms with blanks dropped,
// so callers can loop the result directly. Each term becomes an independent
// NOT (...) conjunct — a row is dropped if ANY term matches.
func (f QueryFilters) EffectiveExcludeTerms() []string {
	return nonBlank(f.ExcludeTerms)
}

// nonBlank returns the input with empty strings dropped.
func nonBlank(in []string) []string {
	var out []string
	for _, t := range in {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Search-corpus predicates — the single source of truth for "what --search
// scans" on each table. The positive (--search/--header/--body) and negative
// (--exclude-*) forms share one predicate so they can never drift: positive
// callers pass the bare string, negative callers prefix "NOT ". COALESCE is
// used throughout so the negated form is NULL-safe (a bare NOT (NULL LIKE ?)
// evaluates to NULL and would wrongly drop the row); it is a no-op for the
// positive form because search terms are always non-blank.
const (
	// recordSearchPredicate scans http_records: URL, path, and the raw
	// request/response corpus (headers + body). Four ? placeholders.
	recordSearchPredicate = "(COALESCE(r.url, '') LIKE ? OR COALESCE(r.path, '') LIKE ? OR " +
		"COALESCE(CAST(r.raw_request AS TEXT), '') LIKE ? OR COALESCE(CAST(r.raw_response AS TEXT), '') LIKE ?)"

	// rawCorpusPredicate scans just the raw request/response corpus, backing
	// --header/--body and their inverses. Two ? placeholders.
	rawCorpusPredicate = "(COALESCE(CAST(r.raw_request AS TEXT), '') LIKE ? OR COALESCE(CAST(r.raw_response AS TEXT), '') LIKE ?)"

	// severitySortRankExpr maps f.severity to its numeric risk rank for ORDER BY,
	// so a severity sort ranks by risk instead of alphabetically. Mirrors
	// severity_gate's canonical order (info<suspect<low<medium<high<critical).
	severitySortRankExpr = "CASE f.severity" +
		" WHEN 'critical' THEN 6 WHEN 'high' THEN 5 WHEN 'medium' THEN 4" +
		" WHEN 'low' THEN 3 WHEN 'suspect' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"

	// findingSearchPredicate scans a finding's own fields plus its linked HTTP
	// records (via the finding_records junction). The record columns sit inside
	// EXISTS, which is boolean and never NULL, so they need no COALESCE. Twelve
	// ? placeholders: 7 finding fields then 5 record fields.
	findingSearchPredicate = "((COALESCE(f.module_name, '') LIKE ? OR COALESCE(f.module_short, '') LIKE ? OR COALESCE(f.description, '') LIKE ? OR " +
		"COALESCE(f.module_id, '') LIKE ? OR COALESCE(f.matched_at, '') LIKE ? OR COALESCE(f.request, '') LIKE ? OR COALESCE(f.response, '') LIKE ?)" +
		" OR EXISTS (SELECT 1 FROM finding_records fr2" +
		" INNER JOIN http_records r ON r.uuid = fr2.record_uuid" +
		" WHERE fr2.finding_id = f.id AND (" +
		" r.url LIKE ? OR r.path LIKE ? OR r.hostname LIKE ?" +
		" OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?" +
		")))"
)

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

// ExecuteWithCount runs the filtered query and returns the matching page of
// records alongside the total unfiltered count in a single round-trip via
// Bun's ScanAndCount. Use this for paginated views instead of Execute + Count,
// which issues two separate queries.
func (qb *QueryBuilder) ExecuteWithCount(ctx context.Context) ([]*HTTPRecord, int64, error) {
	records := make([]*HTTPRecord, 0)
	count, err := qb.BuildRecordsQuery().ScanAndCount(ctx, &records)
	if err != nil {
		return nil, 0, err
	}
	return records, int64(count), nil
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
		query.Where("r.method IN (?)", bun.List(qb.filters.Methods))
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
		query.Where("r.status_code IN (?)", bun.List(qb.filters.StatusCodes))
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
		query.Where("f.severity IN (?)", bun.List(qb.filters.Severity))
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
			// FTS5 MATCH (url/path/hostname tokens) is orders of magnitude faster
			// than CAST LIKE for metadata hits. The raw_request/raw_response
			// corpus is no longer in the FTS index (it was dropped to halve ingest
			// write cost — see db.go), so body matches fall back to a CAST LIKE
			// scan here, plus the metadata columns that were never in the index.
			p := "%" + qb.filters.FuzzyTerm + "%"
			query.Where(`(r.rowid IN (SELECT rowid FROM http_records_fts WHERE http_records_fts MATCH ?)
				OR r.method LIKE ? OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?
				OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?)`,
				qb.filters.FuzzyTerm+"*", p, p, p, p, p, p)
		} else if qb.db.HasFTS() && qb.db.Driver() == "postgres" {
			p := "%" + qb.filters.FuzzyTerm + "%"
			query.Where(`(r.search_vector @@ plainto_tsquery('english', ?)
				OR r.method LIKE ? OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?)`,
				qb.filters.FuzzyTerm, p, p, p, p)
		} else {
			p := "%" + qb.filters.FuzzyTerm + "%"
			query.Where(`(r.url LIKE ? OR r.path LIKE ? OR r.hostname LIKE ? OR r.method LIKE ?
				OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?
				OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?)`,
				p, p, p, p, p, p, p, p, p)
		}
	}

	// Search across URL, path, and the raw request/response corpus (headers +
	// body live in raw_request/raw_response). Multiple terms are AND-combined:
	// every term must match somewhere, so repeating --search narrows the results.
	for _, term := range qb.filters.EffectiveSearchTerms() {
		p := "%" + term + "%"
		query.Where(recordSearchPredicate, p, p, p, p)
	}

	// Exclusion search: drop records where ANY term appears anywhere --search
	// scans (the inverse predicate). Each term is an independent NOT conjunct.
	for _, term := range qb.filters.EffectiveExcludeTerms() {
		p := "%" + term + "%"
		query.Where("NOT "+recordSearchPredicate, p, p, p, p)
	}

	// Header and body searches scan raw_request/raw_response — these contain
	// both headers and body, so HeaderSearch and BodySearch hit the same corpus
	// via the same strategy (FTS5 when available, CAST LIKE fallback).
	qb.applyRawCorpusSearch(query, qb.filters.HeaderSearch)
	qb.applyRawCorpusSearch(query, qb.filters.BodySearch)

	// Exclusion counterparts: drop records whose raw corpus contains the term.
	qb.applyRawCorpusExclude(query, qb.filters.ExcludeHeaderSearch)
	qb.applyRawCorpusExclude(query, qb.filters.ExcludeBodySearch)
}

// applyRawCorpusSearch adds a substring filter over the raw_request/raw_response
// corpus via a CAST(...) LIKE scan. The SQLite FTS index intentionally no longer
// holds the raw blobs (they were dropped to halve ingest write cost, see db.go),
// so body and header searches scan the bodies directly on both drivers. A blank
// term is a no-op.
func (qb *QueryBuilder) applyRawCorpusSearch(query *bun.SelectQuery, term string) {
	if term == "" {
		return
	}
	p := "%" + term + "%"
	query.Where(rawCorpusPredicate, p, p)
}

// applyRawCorpusExclude drops rows whose raw_request/raw_response corpus contains
// the term — the inverse of applyRawCorpusSearch (same predicate, negated). A
// blank term is a no-op.
func (qb *QueryBuilder) applyRawCorpusExclude(query *bun.SelectQuery, term string) {
	if term == "" {
		return
	}
	p := "%" + term + "%"
	query.Where("NOT "+rawCorpusPredicate, p, p)
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

	// Append the unique uuid as a stable tie-breaker so rows sharing the primary
	// sort value — e.g. the default second-precision created_at — keep a
	// deterministic, page-stable order under concurrent ingestion instead of
	// shifting between requests. Skip when the sort column already IS the uuid.
	if sortColumn != "r.uuid" {
		query.Order(fmt.Sprintf("r.uuid %s", order))
	}
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

	// Delete associated findings first (no FK cascade). Best-effort: a failure
	// here leaves orphan findings but must not block deleting the records
	// themselves, so we log rather than abort (matching the junction cleanup
	// below). A silent drop here previously hid orphaned-finding bugs.
	if _, err := db.db.NewDelete().
		Model((*Finding)(nil)).
		Where("id IN (SELECT finding_id FROM finding_records WHERE record_uuid IN (?))", bun.List(uuids)).
		Exec(ctx); err != nil {
		zap.L().Warn("failed to delete findings for deleted records (orphans may remain)", zap.Error(err))
	}

	// Clean up junction rows for deleted records
	if _, err := db.db.NewRaw("DELETE FROM finding_records WHERE record_uuid IN (?)", bun.List(uuids)).Exec(ctx); err != nil {
		zap.L().Debug("failed to clean up finding_records for deleted records", zap.Error(err))
	}

	// Delete records
	result, err := db.db.NewDelete().
		Model((*HTTPRecord)(nil)).
		Where("uuid IN (?)", bun.List(uuids)).
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
	if _, err := db.db.NewRaw("DELETE FROM finding_records WHERE finding_id NOT IN (SELECT id FROM findings)").Exec(ctx); err != nil {
		zap.L().Debug("failed to clean up orphaned finding_records", zap.Error(err))
	}

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
	if _, err := db.db.NewRaw("DELETE FROM finding_records WHERE finding_id IN (?)", bun.List(ids)).Exec(ctx); err != nil {
		zap.L().Debug("failed to delete finding_records junction rows", zap.Error(err))
	}

	// Delete findings
	result, err := db.db.NewDelete().
		Model((*Finding)(nil)).
		Where("id IN (?)", bun.List(ids)).
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
	"http_records":             {SQLName: "http_records", CascadeFirst: []string{"finding_records"}},
	"findings":                 {SQLName: "findings", CascadeFirst: []string{"finding_records"}},
	"finding_records":          {SQLName: "finding_records"},
	"scans":                    {SQLName: "scans"},
	"agentic_scans":            {SQLName: "agentic_scans", CascadeFirst: []string{"agent_sections", "agent_finding_candidates"}},
	"agent_sections":           {SQLName: "agent_sections"},
	"agent_finding_candidates": {SQLName: "agent_finding_candidates"},
	"oast_interactions":        {SQLName: "oast_interactions"},
	"scan_logs":                {SQLName: "scan_logs"},
	"authentication_hostnames": {SQLName: "authentication_hostnames"},
	"scopes":                   {SQLName: "scopes"},
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
	"authentication_hostnames",
	// Durable-autopilot child tables are cleared before the parent agentic_scans
	// so a full wipe leaves no orphan sections/candidates behind.
	"agent_sections",
	"agent_finding_candidates",
	"agentic_scans",
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

// ExecuteWithCount runs the filtered query and returns matching findings
// alongside the total unfiltered count, in a single round-trip via Bun's
// ScanAndCount. Use this when callers need both the page and the total
// (paginated views) — saves one DB roundtrip vs. Execute + Count.
func (fqb *FindingsQueryBuilder) ExecuteWithCount(ctx context.Context) ([]*Finding, int64, error) {
	findings := make([]*Finding, 0)
	query := fqb.db.NewSelect().Model(&findings).
		ExcludeColumn("additional_evidence", "request", "response")
	fqb.applyFindingFilters(query)
	fqb.applyFindingSorting(query)

	if fqb.filters.Limit > 0 {
		query = query.Limit(fqb.filters.Limit)
	}
	if fqb.filters.Offset > 0 {
		query = query.Offset(fqb.filters.Offset)
	}

	count, err := query.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, err
	}
	return findings, int64(count), nil
}

// applyFindingFilters applies filter conditions to a findings query
func (fqb *FindingsQueryBuilder) applyFindingFilters(query *bun.SelectQuery) {
	// Existing callers are finding-oriented. Keep observations/candidates
	// queryable through an explicit filter without allowing them to inflate
	// vulnerability lists, reports, stats, or CI gates by default.
	if len(fqb.filters.RecordKinds) > 0 {
		query.Where("f.record_kind IN (?)", bun.List(fqb.filters.RecordKinds))
	} else {
		query.Where("(f.record_kind IS NULL OR f.record_kind = '' OR f.record_kind = ?)", RecordKindFinding)
	}

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

	// Agentic-scan UUID filtering (agent-produced findings; list covers the
	// scan tree for nested audit driver legs / swarm sub-runs)
	if len(fqb.filters.AgenticScanUUIDs) > 0 {
		query.Where("f.agentic_scan_uuid IN (?)", bun.List(fqb.filters.AgenticScanUUIDs))
	}

	// Severity filtering
	if len(fqb.filters.Severity) > 0 {
		query.Where("f.severity IN (?)", bun.List(fqb.filters.Severity))
	}

	// Confidence filtering
	if len(fqb.filters.Confidence) > 0 {
		query.Where("f.confidence IN (?)", bun.List(fqb.filters.Confidence))
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
		query.Where("f.status IN (?)", bun.List(fqb.filters.Status))
	}

	// Domain filtering via associated HTTP records. Uses EXISTS (not a JOIN) so a
	// finding linked to N records on the matching host yields ONE row, not N — a
	// JOIN here duplicated both the listed rows and the ScanAndCount total. Matches
	// the non-duplicating pattern used by the path/method/status/source filters below.
	if fqb.filters.HostPattern != "" {
		if strings.Contains(fqb.filters.HostPattern, "*") {
			pattern := strings.ReplaceAll(fqb.filters.HostPattern, "*", "%")
			query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
				INNER JOIN http_records r ON r.uuid = fr2.record_uuid
				WHERE fr2.finding_id = f.id AND r.hostname LIKE ?)`, pattern)
		} else {
			query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
				INNER JOIN http_records r ON r.uuid = fr2.record_uuid
				WHERE fr2.finding_id = f.id AND r.hostname = ?)`, fqb.filters.HostPattern)
		}
	}

	// Search across the finding's own fields (module metadata, matched location,
	// request/response snippet) AND the linked HTTP records' url/path/host and
	// raw request/response corpus. Multiple terms are AND-combined: every term
	// must match somewhere, so repeating --search progressively narrows.
	for _, term := range fqb.filters.EffectiveSearchTerms() {
		p := "%" + term + "%"
		query.Where(findingSearchPredicate,
			p, p, p, p, p, p, p, // finding fields
			p, p, p, p, p) // record fields
	}

	// Exclusion search: drop findings where ANY term matches the same corpus
	// --search scans (the inverse predicate). Each term is an independent NOT
	// conjunct; the record side uses EXISTS so a finding is dropped when a linked
	// record matches.
	for _, term := range fqb.filters.EffectiveExcludeTerms() {
		p := "%" + term + "%"
		query.Where("NOT "+findingSearchPredicate,
			p, p, p, p, p, p, p, // finding fields
			p, p, p, p, p) // record fields
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
			WHERE fr2.finding_id = f.id AND r.method IN (?))`, bun.List(fqb.filters.Methods))
	}

	// Status code filtering via associated HTTP records
	if len(fqb.filters.StatusCodes) > 0 {
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND r.status_code IN (?))`, bun.List(fqb.filters.StatusCodes))
	}

	// Source filtering via associated HTTP records
	if fqb.filters.Source != "" {
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND r.source = ?)`, fqb.filters.Source)
	}

	if fqb.filters.HeaderSearch != "" {
		hp := "%" + fqb.filters.HeaderSearch + "%"
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND (
				CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?
			))`, hp, hp)
	}

	if fqb.filters.BodySearch != "" {
		bp := "%" + fqb.filters.BodySearch + "%"
		query.Where(`EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND (
				CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?
			))`, bp, bp)
	}

	// Exclusion counterparts: drop findings that have a linked record whose raw
	// corpus contains the term (NOT EXISTS — a NULL corpus column simply doesn't
	// match, so no COALESCE guard is needed here).
	if fqb.filters.ExcludeHeaderSearch != "" {
		hp := "%" + fqb.filters.ExcludeHeaderSearch + "%"
		query.Where(`NOT EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND (
				CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?
			))`, hp, hp)
	}

	if fqb.filters.ExcludeBodySearch != "" {
		bp := "%" + fqb.filters.ExcludeBodySearch + "%"
		query.Where(`NOT EXISTS (SELECT 1 FROM finding_records fr2
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
	// Secondary key on the unique id makes the row order total (and therefore
	// list positions reproducible across runs) when the primary sort column has
	// ties — e.g. several findings sharing a found_at, common under --glob-db
	// merges. Skipped when id is already the primary sort.
	if sortColumn != "f.id" {
		query.Order("f.id " + order)
	}
}

// mapFindingSortColumn maps sort names to actual finding column names
func (fqb *FindingsQueryBuilder) mapFindingSortColumn(name string) string {
	switch name {
	case "found_at", "found":
		return "f.found_at"
	case "created_at", "created":
		return "f.created_at"
	case "severity":
		// Rank by risk, not lexically: a plain "f.severity" string sort ordered
		// "suspect" > "medium" > "low" > "info" > "high" > "critical", which is
		// nonsense for a severity view. Mirror severity_gate's canonical ranking
		// (info < suspect < low < medium < high < critical). Portable across
		// SQLite/Postgres.
		return severitySortRankExpr
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

// CountFindingsBySeverity returns finding counts grouped by severity, filtered by
// project and, when hostnames is non-empty, restricted to findings on those in-scope
// hosts. Empty hostnames means no host filter. Findings are scoped by hostname only
// (the findings table carries no scheme/port column), unlike the origin-precise record
// scoping; this lets the scan-completion summary count only findings on the hosts
// actually scanned, not leftovers from prior scans in the same project.
func CountFindingsBySeverity(ctx context.Context, db *DB, projectUUID string, hostnames ...string) (map[string]int64, error) {
	var rows []SeverityCount
	q := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("severity, COUNT(*) AS count").
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if len(hostnames) > 0 {
		q = q.Where("hostname IN (?)", bun.List(hostnames))
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

// CountRecordsByColumn returns http_record counts grouped by a single column
// (one of method, status_code, response_content_type), filtered by project
// (empty = every row, e.g. a --glob-db merge). Keys are the column values as
// text. Powers the traffic listing's status/method/content-type summary.
func CountRecordsByColumn(ctx context.Context, db *DB, projectUUID, column string) (map[string]int64, error) {
	switch column {
	case "method", "status_code", "response_content_type":
	default:
		return nil, fmt.Errorf("CountRecordsByColumn: unsupported column %q", column)
	}
	var rows []struct {
		Key   string `bun:"key"`
		Count int64  `bun:"count"`
	}
	q := db.NewSelect().
		Model((*HTTPRecord)(nil)).
		ColumnExpr("CAST(? AS TEXT) AS key, COUNT(*) AS count", bun.Ident(column))
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.GroupExpr(column).Scan(ctx, &rows); err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Key] = r.Count
	}
	return out, nil
}

// CountFindingsByAgenticScan returns finding counts grouped by severity for
// one agentic-scan run. Severity strings are lowercased/trimmed so callers
// get a canonical key set regardless of how the finding was inserted.
// Empty agenticScanUUID returns an empty map without querying.
func CountFindingsByAgenticScan(ctx context.Context, db *DB, agenticScanUUID string) (map[string]int64, error) {
	if agenticScanUUID == "" {
		return map[string]int64{}, nil
	}
	var rows []SeverityCount
	err := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("severity, COUNT(*) AS count").
		Where("agentic_scan_uuid = ?", agenticScanUUID).
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding).
		GroupExpr("severity").
		Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}
	result := make(map[string]int64, len(rows))
	for _, row := range rows {
		key := strings.ToLower(strings.TrimSpace(row.Severity))
		if key == "" {
			continue
		}
		result[key] += row.Count
	}
	return result, nil
}

// CountFindingsByAgenticScans is like CountFindingsByAgenticScan but counts
// across several agentic-scan UUIDs at once (a parent run plus its driver /
// sub-run children). Returns severity→count with lowercase, trimmed keys.
func CountFindingsByAgenticScans(ctx context.Context, db *DB, agenticScanUUIDs []string) (map[string]int64, error) {
	if len(agenticScanUUIDs) == 0 {
		return map[string]int64{}, nil
	}
	var rows []SeverityCount
	err := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("severity, COUNT(*) AS count").
		Where("agentic_scan_uuid IN (?)", bun.List(agenticScanUUIDs)).
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding).
		GroupExpr("severity").
		Scan(ctx, &rows)
	if err != nil {
		return nil, err
	}
	result := make(map[string]int64, len(rows))
	for _, row := range rows {
		key := strings.ToLower(strings.TrimSpace(row.Severity))
		if key == "" {
			continue
		}
		result[key] += row.Count
	}
	return result, nil
}

// CountFindingsByModule returns finding counts grouped by module_id.
func CountFindingsByModule(ctx context.Context, db *DB, projectUUID string) (map[string]int64, error) {
	var rows []struct {
		ModuleID string `bun:"module_id"`
		Count    int64  `bun:"count"`
	}
	q := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("module_id, COUNT(*) AS count").
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.GroupExpr("module_id").Scan(ctx, &rows); err != nil {
		return nil, err
	}
	result := make(map[string]int64, len(rows))
	for _, row := range rows {
		if row.ModuleID != "" {
			result[row.ModuleID] = row.Count
		}
	}
	return result, nil
}

// CountFindingsByURL returns finding counts grouped by URL. Findings with
// an empty URL are skipped — they aren't endpoint-attributable anyway.
func CountFindingsByURL(ctx context.Context, db *DB, projectUUID string) (map[string]int64, error) {
	var rows []struct {
		URL   string `bun:"url"`
		Count int64  `bun:"count"`
	}
	q := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("url, COUNT(*) AS count").
		Where("url IS NOT NULL AND url != ''").
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.GroupExpr("url").Scan(ctx, &rows); err != nil {
		return nil, err
	}
	result := make(map[string]int64, len(rows))
	for _, row := range rows {
		result[row.URL] = row.Count
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
		ColumnExpr("confidence, COUNT(*) AS count").
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding)
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
