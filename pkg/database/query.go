package database

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"go.uber.org/zap"
)

// QueryFilters holds filter criteria for database queries
type QueryFilters struct {
	// Project scoping
	ProjectUUID string // Required: filter all queries to this project

	// Identity filtering. RecordUUIDs selects exact stored records by UUID and is
	// applied as a SQL predicate, so it narrows BEFORE pagination — a record is
	// never reported absent merely because it fell outside the current page.
	// Without it the read surface had no identity selector at all: the only flags
	// that took a record UUID (`replay -u`, `fuzz -u`) both send traffic, and a
	// UUID passed as the fuzzy search term matched zero rows because that term
	// searches URL/path/body, not identity.
	RecordUUIDs []string

	// URLsExact selects records whose stored url matches EXACTLY — an equality
	// IN (), never a LIKE.
	//
	// It exists because `--url` was the name callers reached for and the one name
	// the read surface did not have: --host takes a hostname, --path a fuzzy
	// pattern, and a URL passed as the positional term is a substring search that
	// also matches every URL containing it. So "show me this one endpoint" had no
	// spelling, and the nearest miss was answered by the flag suggester with
	// "did you mean --all?", which lifts the result cap.
	//
	// Repeated values are OR-ed within the field and AND-ed against every other
	// filter, matching how --uuid and --method already behave. No normalization,
	// no case folding, no trailing-slash equivalence: equality is against the
	// bytes that were stored, because a comparison that quietly canonicalizes is
	// one the caller cannot predict from the value they passed.
	URLsExact []string

	// Host filtering
	HostPattern string // Hostname pattern (supports wildcards)

	// Request filtering
	Methods     []string // HTTP methods (GET, POST, etc.)
	PathPattern string   // Path pattern (supports wildcards)
	StatusCodes []int    // Status codes (200, 404, etc.)
	ScanUUID    string   // Scan UUID: findings.scan_uuid for findings, http_records.scan_uuid (first-stored-by) for records
	// ObservedInScan selects findings the scan observed: its scan_uuid is the
	// finding's, or the scan has a finding_observations row for it. A finding
	// first stored by an earlier scan and re-detected (possibly merged as a
	// dedup duplicate) by this one counts, which f.scan_uuid alone can miss.
	// Findings only; records ignore it.
	ObservedInScan   string
	AgenticScanUUIDs []string // Agentic-scan UUID(s) (links agent-produced findings; pass the scan tree for nested audit/swarm runs)
	Source           string   // Filter by record source (e.g. scanner, ingest-cli, ingest-server)

	// Response filtering
	ContentType string // Filter by response content type

	// Risk filtering
	MinRiskScore    int      // Minimum risk score filter (anomaly_ranking's batch percentile)
	MinSurfaceScore int      // Minimum attack-surface score filter (surface_scoring's 0-100 signal score)
	Remark          string   // Filter by remark substring (single)
	Remarks         []string // Filter by multiple remarks (AND: record must have all)

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
	Status         []string // Filter findings by lifecycle status (one of FindingStatuses)
	// ExcludeStatuses drops findings whose lifecycle status is listed (a NULL
	// status reads as triaged, the column default). The --fail-on gate, scan
	// diff and --new-since pass DismissedFindingStatuses here.
	ExcludeStatuses []string
	// ObservedInScans keeps findings that any of these scans observed
	// (finding_observations), not merely the scan a finding was last
	// attributed to (findings.scan_uuid).
	ObservedInScans []string
	// NewSince keeps findings first observed after a baseline scan; see
	// NewSinceBaseline. Built by Repository.ResolveNewSince.
	NewSince *NewSinceBaseline
	// CreatedAfter keeps findings first stored after this instant
	// (`finding --new-since <duration>`).
	CreatedAfter *time.Time

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

// UsesRawCorpus reports whether any active filter matches against the
// raw_request/raw_response blob columns — the FuzzyTerm branches,
// recordSearchPredicate (--search) and the region predicates behind
// --header/--body (see message_regions.go), plus all three exclude forms.
//
// A caller that would otherwise avoid materializing those blobs (a projected
// SELECT, or a merge that omits the columns) MUST check this first and keep them
// when it returns true. The failure is silent, not an error: with the blobs
// absent every LIKE matches nothing, so --search returns an empty result and the
// --exclude-* forms — which are negated — return everything.
//
// Keep in sync with applyFilters; this is the reason to add a field here rather
// than open-code the flag checks at each call site.
func (f QueryFilters) UsesRawCorpus() bool {
	return f.FuzzyTerm != "" ||
		f.HeaderSearch != "" ||
		f.BodySearch != "" ||
		f.ExcludeHeaderSearch != "" ||
		f.ExcludeBodySearch != "" ||
		len(f.EffectiveSearchTerms()) > 0 ||
		len(f.EffectiveExcludeTerms()) > 0
}

// UsesLinkedRecords reports whether any active filter reaches into http_records
// when the query is over FINDINGS. It is the findings-side counterpart to
// UsesRawCorpus and a strictly wider question: a findings query has no record
// columns of its own, so host/path/method/status/source all resolve through an
// EXISTS over the finding_records junction (see applyFindingFilters), and every
// raw-corpus filter does too.
//
// The question does not arise for traffic, whose query is over http_records
// directly — there the rows are always present by construction.
//
// A caller that would otherwise omit the table entirely (globDBSkipSet.Records,
// MergeOptions.SkipHTTPRecords) MUST check this first. The failure is silent:
// with no rows to satisfy them, every EXISTS predicate is false, so --host
// returns nothing and the NOT EXISTS exclude forms return everything.
//
// Keep in sync with applyFindingFilters.
func (f QueryFilters) UsesLinkedRecords() bool {
	return f.HostPattern != "" ||
		f.PathPattern != "" ||
		len(f.Methods) > 0 ||
		len(f.StatusCodes) > 0 ||
		f.Source != "" ||
		f.UsesRawCorpus()
}

// UsesLinkedFindings reports whether any active filter reaches into findings
// when the query is over HTTP RECORDS. It is the mirror of UsesLinkedRecords:
// records have no finding columns of their own, so --severity resolves through a
// join over the finding_records junction (see applyFilters).
//
// A caller that would otherwise omit the finding tables entirely
// (globDBSkipSet.Findings, MergeOptions.SkipFindings) MUST check this first.
// The failure is silent: with no findings to join, a --severity record listing
// returns nothing rather than erroring.
//
// Keep in sync with applyFilters.
func (f QueryFilters) UsesLinkedFindings() bool {
	return len(f.Severity) > 0
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

// ftsPrefixQuery renders term as an FTS5 prefix query, safely.
//
// The MATCH argument is an FTS5 *expression*, not a literal: bare AND/OR/NOT/NEAR
// are operators, and ", (, ), :, ^, - and * are syntax. Appending "*" to a raw
// user term therefore produced a query that could mean something other than the
// term — or, for an unbalanced quote, a syntax error that failed the whole
// listing rather than the one predicate.
//
// Wrapping in a double-quoted string (with "" escaping an embedded quote) turns
// the whole term into a phrase, so every character is data; the trailing * then
// applies prefix matching to its last token. A term that tokenizes to nothing
// simply matches nothing, which the OR-ed LIKE predicates beside it still cover.
func ftsPrefixQuery(term string) string {
	return `"` + strings.ReplaceAll(term, `"`, `""`) + `"*`
}

// Search-corpus predicates — the single source of truth for "what --search
// scans" on each table. The positive (--search/--header/--body) and negative
// (--exclude-*) forms share one predicate so they can never drift: positive
// callers pass the bare string, negative callers prefix "NOT ". COALESCE is
// used throughout so the negated form is NULL-safe (a bare NOT (NULL LIKE ?)
// evaluates to NULL and would wrongly drop the row); it is a no-op for the
// positive form because search terms are always non-blank.
//
// Every one of them is wrapped in WithLikeEscape, which appends the ESCAPE
// clause each placeholder needs for the term escaping in like.go to take effect.
// They are vars rather than consts for that reason alone — the wrapping is a
// one-time pass at package init, not per query.
const severitySortRankExpr = "CASE f.severity" +
	" WHEN 'critical' THEN 6 WHEN 'high' THEN 5 WHEN 'medium' THEN 4" +
	" WHEN 'low' THEN 3 WHEN 'suspect' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"

var (
	// recordSearchPredicate scans http_records: URL, path, and the raw
	// request/response corpus (headers + body). Four ? placeholders.
	recordSearchPredicate = WithLikeEscape(
		"(COALESCE(r.url, '') LIKE ? OR COALESCE(r.path, '') LIKE ? OR " +
			"COALESCE(CAST(r.raw_request AS TEXT), '') LIKE ? OR COALESCE(CAST(r.raw_response AS TEXT), '') LIKE ?)")

	// findingSearchPredicate scans a finding's own fields plus its linked HTTP
	// records (via the finding_records junction). The record columns sit inside
	// EXISTS, which is boolean and never NULL, so they need no COALESCE. Twelve
	// ? placeholders: 7 finding fields then 5 record fields.
	findingSearchPredicate = WithLikeEscape(
		"((COALESCE(f.module_name, '') LIKE ? OR COALESCE(f.module_short, '') LIKE ? OR COALESCE(f.description, '') LIKE ? OR " +
			"COALESCE(f.module_id, '') LIKE ? OR COALESCE(f.matched_at, '') LIKE ? OR COALESCE(f.request, '') LIKE ? OR COALESCE(f.response, '') LIKE ?)" +
			" OR EXISTS (SELECT 1 FROM finding_records fr2" +
			" INNER JOIN http_records r ON r.uuid = fr2.record_uuid" +
			" WHERE fr2.finding_id = f.id AND (" +
			" r.url LIKE ? OR r.path LIKE ? OR r.hostname LIKE ?" +
			" OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?" +
			")))")

	// The three shapes the positional fuzzy term takes, one per index situation.
	// Hoisted out of applyFilters so all three go through WithLikeEscape in one
	// place — an escape clause missing from only the no-FTS fallback would make
	// the same term behave differently depending on how the store was opened,
	// which is the bug the FTS branch comment below already warns about.
	fuzzyRecordFTSPredicate = WithLikeEscape(
		`(r.rowid IN (SELECT rowid FROM http_records_fts WHERE http_records_fts MATCH ?)
			OR r.url LIKE ? OR r.path LIKE ? OR r.hostname LIKE ?
			OR r.method LIKE ? OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?
			OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?)`)

	fuzzyRecordPostgresFTSPredicate = WithLikeEscape(
		`(r.search_vector @@ plainto_tsquery('english', ?)
			OR r.method LIKE ? OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?)`)

	fuzzyRecordPredicate = WithLikeEscape(
		`(r.url LIKE ? OR r.path LIKE ? OR r.hostname LIKE ? OR r.method LIKE ?
			OR r.request_content_type LIKE ? OR r.response_content_type LIKE ? OR r.source LIKE ?
			OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?)`)

	// fuzzyFindingPredicate backs the positional term on `finding`: the finding's
	// own fields OR any linked record's url/path/host/raw corpus. Twelve ?
	// placeholders, 7 finding then 5 record — same order as
	// findingSearchPredicate.
	fuzzyFindingPredicate = WithLikeEscape(
		`((f.description LIKE ? OR f.module_id LIKE ? OR f.module_name LIKE ? OR f.module_short LIKE ? OR f.matched_at LIKE ? OR f.request LIKE ? OR f.response LIKE ?)
		 OR EXISTS (SELECT 1 FROM finding_records fr2
			INNER JOIN http_records r ON r.uuid = fr2.record_uuid
			WHERE fr2.finding_id = f.id AND (
				r.url LIKE ? OR r.path LIKE ? OR r.hostname LIKE ?
				OR CAST(r.raw_request AS TEXT) LIKE ? OR CAST(r.raw_response AS TEXT) LIKE ?
			)))`)

	// Remark membership, one form per driver's JSON array accessor.
	remarkPredicatePostgres = WithLikeEscape(
		"EXISTS (SELECT 1 FROM jsonb_array_elements_text(r.remarks::jsonb) AS je WHERE je LIKE ?)")
	remarkPredicateSQLite = WithLikeEscape(
		"EXISTS (SELECT 1 FROM json_each(r.remarks) WHERE json_each.value LIKE ?)")
)

// QueryBuilder builds filtered database queries
type QueryBuilder struct {
	db         *DB
	filters    QueryFilters
	omitBodies bool
}

// NewQueryBuilder creates a new query builder
func NewQueryBuilder(db *DB, filters QueryFilters) *QueryBuilder {
	return &QueryBuilder{
		db:      db,
		filters: filters,
	}
}

// OmitBodies drops raw_request/raw_response from the SELECT list, for callers
// that read only metadata off the returned records. Those two columns hold the
// whole request/response corpus and dwarf every other column, so hydrating them
// for a list view costs memory proportional to the traffic scanned rather than
// to the page size.
//
// Filters are unaffected: they run in SQL against the stored columns, so this is
// safe even with --search/--header/--body active (contrast MergeOptions.
// SkipRecordBodies, which removes the columns from the destination and so cannot
// be used with those filters). The only requirement is that the caller not read
// HTTPRecord.RawRequest/RawResponse — they come back empty.
//
// This mirrors FindingsQueryBuilder.ExecuteWithCount, which always excludes its
// equivalent blob columns; records can't default to that because --raw/--burp
// and the record views legitimately need them.
func (qb *QueryBuilder) OmitBodies() *QueryBuilder {
	qb.omitBodies = true
	return qb
}

// BuildRecordsQuery builds a query for http_records table
func (qb *QueryBuilder) BuildRecordsQuery() *bun.SelectQuery {
	query := qb.db.NewSelect().Model((*HTTPRecord)(nil))
	if qb.omitBodies {
		query = query.ExcludeColumn(recordBodyColumns...)
	}

	qb.applyFilters(query)
	qb.applySorting(query)

	if qb.filters.Limit > 0 {
		query = query.Limit(int64(qb.filters.Limit))
	}
	if qb.filters.Offset > 0 {
		query = query.Offset(int64(qb.filters.Offset))
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
// records alongside the total count for the same filters.
//
// It is NOT one round trip, despite what this comment used to claim. Bun's
// ScanAndCount collapses to a single statement only when there is no limit and
// no offset; a paginated call — the only reason to use this method — takes the
// two-query path, and with no explicit conn it runs the scan and the count
// CONCURRENTLY, so it occupies two pool connections for its duration. On SQLite
// that is worth remembering when this runs alongside a busy RecordWriter.
//
// Still preferable to Execute + Count, which serializes the same two queries.
// Callers that do not need an exact total on every refresh should use Execute
// alone rather than paying the count.
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

	// Exact identity. Deliberately an equality IN (), never a LIKE: an identity
	// selector that silently widened into a prefix match would turn "this record"
	// into "records whose id starts like this".
	if len(qb.filters.RecordUUIDs) > 0 {
		query.Where("r.uuid IN (?)", bun.List(qb.filters.RecordUUIDs))
	}

	// Exact URL selection, for the same reason and in the same shape: equality,
	// applied before pagination, so a match is never missed for falling outside
	// the current page.
	if urls := nonBlank(qb.filters.URLsExact); len(urls) > 0 {
		query.Where("r.url IN (?)", bun.List(urls))
	}

	// Host filtering (direct column, no join)
	// Accepts a bare host, host:port, an origin or a bracketed IPv6 address
	// (ParseHostFilter), so the `host` a traffic row prints filters back to it.
	applyRecordHostFilter(query, qb.filters.HostPattern, "r")

	// Method filtering
	if len(qb.filters.Methods) > 0 {
		query.Where("r.method IN (?)", bun.List(qb.filters.Methods))
	}

	// Path filtering (fuzzy by default, wildcards supported)
	if qb.filters.PathPattern != "" {
		if strings.Contains(qb.filters.PathPattern, "*") {
			query.Where(WithLikeEscape("r.path LIKE ?"), LikeGlob(qb.filters.PathPattern))
		} else {
			query.Where(WithLikeEscape("r.path LIKE ?"), LikeContains(qb.filters.PathPattern))
		}
	}

	// Status code filtering (direct column, no join)
	if len(qb.filters.StatusCodes) > 0 {
		query.Where("r.status_code IN (?)", bun.List(qb.filters.StatusCodes))
	}

	// Content type filtering
	if qb.filters.ContentType != "" {
		query.Where(WithLikeEscape("r.response_content_type LIKE ?"), LikeContains(qb.filters.ContentType))
	}

	// Source filtering
	if qb.filters.Source != "" {
		query.Where("r.source = ?", qb.filters.Source)
	}

	// Scan provenance: the records this scan stored first (http_records.scan_uuid
	// is stamped on insert, never on a dedup hit). Before this predicate existed
	// the field was honored for findings only, so `db clean --scan-uuid` and
	// `db export --scan-uuid` silently selected every record in scope.
	if qb.filters.ScanUUID != "" {
		query.Where("r.scan_uuid = ?", qb.filters.ScanUUID)
	}

	// Risk score filtering
	if qb.filters.MinRiskScore > 0 {
		query.Where("r.risk_score >= ?", qb.filters.MinRiskScore)
	}

	// Attack-surface score filtering
	if qb.filters.MinSurfaceScore > 0 {
		query.Where("r.surface_score >= ?", qb.filters.MinSurfaceScore)
	}

	// Remark filtering (single)
	if qb.filters.Remark != "" {
		qb.applyRemarkFilter(query, qb.filters.Remark)
	}

	// Remarks filtering (multiple, AND semantics)
	for _, remark := range qb.filters.Remarks {
		qb.applyRemarkFilter(query, remark)
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
			// FTS5 MATCH over url/path/hostname is an ACCELERATOR here, not a
			// replacement for the LIKE predicates on those same columns — it is
			// OR-ed with them rather than standing in for them.
			//
			// The two do not match the same things. MATCH is token/prefix based,
			// so "admin" finds /admin/ but not /superadmin/ or ?x=isadmin, which a
			// substring LIKE does find. When the FTS branch omitted the metadata
			// LIKEs, the same --fuzzy term returned different rows depending on
			// whether the handle had discovered the index — a difference in how a
			// database was opened silently changed the answer.
			//
			// Keeping both is nearly free: the raw_request/raw_response LIKEs
			// below already force a scan of every candidate row (that corpus was
			// dropped from the index to halve ingest write cost — see db.go), so
			// the metadata LIKEs add comparisons to a scan that happens anyway,
			// while MATCH still short-circuits the common metadata hit.
			p := LikeContains(qb.filters.FuzzyTerm)
			query.Where(fuzzyRecordFTSPredicate,
				ftsPrefixQuery(qb.filters.FuzzyTerm), p, p, p, p, p, p, p, p, p)
		} else if qb.db.HasFTS() && qb.db.Driver() == "postgres" {
			p := LikeContains(qb.filters.FuzzyTerm)
			query.Where(fuzzyRecordPostgresFTSPredicate,
				qb.filters.FuzzyTerm, p, p, p, p)
		} else {
			p := LikeContains(qb.filters.FuzzyTerm)
			query.Where(fuzzyRecordPredicate, p, p, p, p, p, p, p, p, p)
		}
	}

	// Search across URL, path, and the raw request/response corpus (headers +
	// body live in raw_request/raw_response). Multiple terms are AND-combined:
	// every term must match somewhere, so repeating --search narrows the results.
	for _, term := range qb.filters.EffectiveSearchTerms() {
		p := LikeContains(term)
		query.Where(recordSearchPredicate, p, p, p, p)
	}

	// Exclusion search: drop records where ANY term appears anywhere --search
	// scans (the inverse predicate). Each term is an independent NOT conjunct.
	for _, term := range qb.filters.EffectiveExcludeTerms() {
		p := LikeContains(term)
		query.Where("NOT "+recordSearchPredicate, p, p, p, p)
	}

	// Header and body searches are attributed: each scans only its own region of
	// raw_request/raw_response. See message_regions.go for why the split is in
	// SQL rather than applied to the fetched rows. The excludes are the same
	// predicate negated, so the two can never disagree about what "in the
	// headers" means.
	driver := qb.db.Driver()
	whereRegion(query, headerSearchPredicate, driver, qb.filters.HeaderSearch, false)
	whereRegion(query, bodySearchPredicate, driver, qb.filters.BodySearch, false)
	whereRegion(query, headerSearchPredicate, driver, qb.filters.ExcludeHeaderSearch, true)
	whereRegion(query, bodySearchPredicate, driver, qb.filters.ExcludeBodySearch, true)
}

// whereRegion narrows to (or, when exclude is set, drops) rows whose named
// message region contains term. A blank term is a no-op — and the predicate is
// not even built for one, which matters because almost every query passes four
// blank terms through here.
//
// `build` is taken as a function rather than a finished string for that reason:
// each call assembles a ~600-character expression out of a dozen Sprintf'd
// parts, and doing that eagerly charged every listing for four searches nobody
// asked for.
func whereRegion(query *bun.SelectQuery, build func(string) string, driver, term string, exclude bool) {
	if term == "" {
		return
	}
	predicate := build(driver)
	if exclude {
		predicate = "NOT " + predicate
	}
	p := LikeContains(term)
	query.Where(predicate, p, p)
}

// applyRemarkFilter narrows to records carrying a remark containing term. A
// remark list is JSON in both stores, so the accessor differs per driver while
// the match itself does not.
func (qb *QueryBuilder) applyRemarkFilter(query *bun.SelectQuery, term string) {
	pred := remarkPredicateSQLite
	if qb.db.Driver() == "postgres" {
		pred = remarkPredicatePostgres
	}
	query.Where(pred, LikeContains(term))
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
// RecordSortKeys are the --sort values a record query accepts (mapSortColumn).
var RecordSortKeys = []string{
	"uuid", "created_at", "created", "sent_at", "sent", "method", "path",
	"status_code", "status", "response_time", "time", "source",
	"risk_score", "risk", "surface_score", "surface",
}

// FindingSortKeys are the --sort values a finding query accepts
// (mapFindingSortColumn).
var FindingSortKeys = []string{
	"found_at", "found", "created_at", "created", "severity",
	"module_name", "module", "module_id", "confidence",
}

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
	case "surface_score", "surface":
		return "r.surface_score"
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

// DeleteRecords deletes the HTTP records matching filters, along with the
// findings whose only evidence they were.
//
// The order below is the policy, and it is not the obvious one. Deleting every
// finding that merely *touches* a deleted record destroys findings that also
// cite records the caller is keeping — one module reporting the same issue
// across five endpoints would lose the whole finding because one endpoint was
// pruned. So the junction is narrowed first, and a finding is removed only once
// nothing it links to survives:
//
//  1. collect the findings linked to the doomed records (bounded by findings
//     touched, not by records deleted);
//  2. drop those records' junction rows, so the junction describes surviving
//     evidence only;
//  3. delete the records;
//  4. delete the collected findings that now link to nothing.
//
// Step 4 is scoped to the collected candidates rather than sweeping every
// evidence-less finding, because a finding with no HTTP record is normal — audit
// and source-scan findings never have one, and this is not the command that
// removes them (see DeleteOrphans).
//
// Every IN() list is chunked (see SQLChunkSize). The filters can select an
// unbounded number of records, and bun renders a list as SQL literals rather
// than bound parameters — so an unchunked delete builds one statement holding
// every uuid as text, tens of megabytes of it on a large corpus.
func (db *DeleteBuilder) DeleteRecords(ctx context.Context, dryRun bool) (int64, error) {
	counts, err := db.DeleteRecordsByTable(ctx, dryRun)
	return counts["http_records"], err
}

// DeleteRecordsByTable is DeleteRecords reporting the rows removed from every
// table it touches: the records, their evidence links, and the findings left
// without evidence (with those findings' own child rows). A dry run executes
// the same transaction and rolls it back, so its counts are exact.
func (db *DeleteBuilder) DeleteRecordsByTable(ctx context.Context, dryRun bool) (DeleteCounts, error) {
	qb := NewQueryBuilder(db.db, db.filters)
	query := qb.BuildRecordsQuery().Column("uuid")

	// The uuids are materialized rather than counted in SQL because the filters
	// carry the caller's LIMIT: a COUNT(*) would report (and a subquery delete
	// would remove) every match rather than the page the caller asked for.
	var uuids []string
	if err := query.Scan(ctx, &uuids); err != nil {
		return nil, fmt.Errorf("failed to get record UUIDs: %w", err)
	}

	counts := DeleteCounts{}
	if len(uuids) == 0 {
		return counts, nil
	}

	// One transaction: the intermediate states below are inconsistent by
	// construction (records gone, their findings not yet reconsidered), and a
	// reader or a crash must not observe one. It also collapses what would
	// otherwise be one auto-commit per chunk into a single commit.
	err := db.countedTx(ctx, counts, dryRun, func(ctx context.Context, tx bun.Tx) error {
		// (1) Findings that cite any of the doomed records, collected before the
		// junction is touched. DISTINCT is per chunk, so the same finding can be
		// reported by several chunks — sort and compact, or step (3) re-deletes it
		// once per chunk it appeared in.
		var candidateFindings []int64
		for chunk := range slices.Chunk(uuids, SQLChunkSize) {
			var ids []int64
			if err := tx.NewRaw(
				"SELECT DISTINCT finding_id FROM finding_records WHERE record_uuid IN (?)",
				bun.List(chunk)).Scan(ctx, &ids); err != nil {
				return fmt.Errorf("failed to identify findings for deleted records: %w", err)
			}
			candidateFindings = append(candidateFindings, ids...)
		}
		slices.Sort(candidateFindings)
		candidateFindings = slices.Compact(candidateFindings)

		// (2) The doomed records and their junction rows. Shared with the dedup
		// passes so "delete these records" means one thing in this package.
		if err := deleteRecordsByUUIDsTx(ctx, tx, uuids); err != nil {
			return err
		}

		// (3) Candidates left with no surviving evidence. The junction is already
		// narrowed, so NOT EXISTS asks exactly "is anything still citing this".
		// They go through deleteFindingsByIDsTx so their history rows go too.
		var doomed []int64
		for chunk := range slices.Chunk(candidateFindings, SQLChunkSize) {
			var ids []int64
			if err := tx.NewSelect().
				Model((*Finding)(nil)).
				Column("id").
				Where("id IN (?)", bun.List(chunk)).
				Where("NOT EXISTS (SELECT 1 FROM finding_records fr WHERE fr.finding_id = f.id)").
				Scan(ctx, &ids); err != nil {
				return fmt.Errorf("failed to find findings left without evidence: %w", err)
			}
			doomed = append(doomed, ids...)
		}
		if err := deleteFindingsByIDsTx(ctx, tx, doomed); err != nil {
			return fmt.Errorf("failed to delete findings left without evidence: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return counts, nil
}

// DeleteOrphans deletes orphaned findings (findings where none of the
// http_record_uuids exist in http_records).
func (db *DeleteBuilder) DeleteOrphans(ctx context.Context, dryRun bool) (int64, error) {
	counts, err := db.DeleteOrphansByTable(ctx, dryRun)
	return counts["findings"], err
}

// DeleteOrphansByTable is DeleteOrphans reporting the rows removed per table.
//
// It honors filters.ProjectUUID. Orphan cleanup reads as store maintenance, but
// the rows it removes belong to projects: an unscoped sweep run from one
// engagement deleted another engagement's findings, which is the same
// cross-project leak the scoped delete paths exist to prevent. With no project
// filter set the behavior is unchanged and the whole store is swept.
func (db *DeleteBuilder) DeleteOrphansByTable(ctx context.Context, dryRun bool) (DeleteCounts, error) {
	orphanCondition := "NOT EXISTS (SELECT 1 FROM finding_records fr INNER JOIN http_records r ON r.uuid = fr.record_uuid WHERE fr.finding_id = f.id)"

	counts := DeleteCounts{}
	err := db.countedTx(ctx, counts, dryRun, func(ctx context.Context, tx bun.Tx) error {
		del := tx.NewDelete().Model((*Finding)(nil)).Where(orphanCondition)
		if db.filters.ProjectUUID != "" {
			del = del.Where("f.project_uuid = ?", db.filters.ProjectUUID)
		}
		res, err := del.Exec(ctx)
		if err != nil {
			return err
		}
		noteDeleted(ctx, "findings", res)

		// Clean up junction rows whose finding is now gone. This is keyed on the
		// findings table rather than on the project, so it stays correct whether
		// or not the delete above was scoped.
		for _, table := range findingChildTables {
			res, err := tx.NewRaw("DELETE FROM " + table + " WHERE finding_id NOT IN (SELECT id FROM findings)").Exec(ctx)
			if err != nil {
				zap.L().Debug("failed to clean up orphaned finding child rows", zap.String("table", table), zap.Error(err))
				continue
			}
			noteDeleted(ctx, table, res)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return counts, nil
}

// DeleteFindings deletes findings matching the configured filters.
// If dryRun is true, returns the count without deleting.
func (db *DeleteBuilder) DeleteFindings(ctx context.Context, dryRun bool) (int64, error) {
	counts, err := db.DeleteFindingsByTable(ctx, dryRun)
	return counts["findings"], err
}

// DeleteFindingsByTable is DeleteFindings reporting the rows removed per table
// (the findings and their evidence links and history). HTTP records are never
// touched. A dry run executes the delete and rolls it back.
func (db *DeleteBuilder) DeleteFindingsByTable(ctx context.Context, dryRun bool) (DeleteCounts, error) {
	fqb := NewFindingsQueryBuilder(db.db, db.filters)

	query := db.db.NewSelect().Model((*Finding)(nil))
	fqb.applyFindingFilters(query)

	var ids []int64
	if err := query.Column("id").Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("failed to get finding IDs: %w", err)
	}

	counts := DeleteCounts{}
	if len(ids) == 0 {
		return counts, nil
	}

	// Shared with the finding-dedup passes: one owner for "delete these findings
	// and their evidence links", chunked, in one transaction.
	if err := db.countedTx(ctx, counts, dryRun, func(ctx context.Context, tx bun.Tx) error {
		return deleteFindingsByIDsTx(ctx, tx, ids)
	}); err != nil {
		return nil, fmt.Errorf("failed to delete findings: %w", err)
	}
	return counts, nil
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
	"findings":                 {SQLName: "findings", CascadeFirst: findingChildTables},
	"finding_records":          {SQLName: "finding_records"},
	"finding_observations":     {SQLName: "finding_observations"},
	"finding_status_events":    {SQLName: "finding_status_events"},
	"finding_hash_aliases":     {SQLName: "finding_hash_aliases"},
	"oast_payloads":            {SQLName: "oast_payloads"},
	"oast_sessions":            {SQLName: "oast_sessions"},
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
	counts, err := db.DeleteTableByTable(ctx, tableName, dryRun)
	return counts[entry.SQLName], err
}

// DeleteTableByTable is DeleteTable reporting the rows removed from the table
// and from each dependent table it clears first.
func (db *DeleteBuilder) DeleteTableByTable(ctx context.Context, tableName string, dryRun bool) (DeleteCounts, error) {
	entry, ok := AllowedCleanTables[tableName]
	if !ok {
		return nil, fmt.Errorf("table %q is not allowed for cleaning", tableName)
	}
	counts := DeleteCounts{}
	err := db.countedTx(ctx, counts, dryRun, func(ctx context.Context, tx bun.Tx) error {
		for _, dep := range entry.CascadeFirst {
			res, err := tx.ExecContext(ctx, "DELETE FROM "+dep)
			if err != nil {
				return fmt.Errorf("failed to clean cascade table %s: %w", dep, err)
			}
			noteDeleted(ctx, dep, res)
		}
		res, err := tx.ExecContext(ctx, "DELETE FROM "+entry.SQLName)
		if err != nil {
			return fmt.Errorf("failed to delete from %s: %w", entry.SQLName, err)
		}
		noteDeleted(ctx, entry.SQLName, res)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := counts[entry.SQLName]; !ok {
		counts[entry.SQLName] = 0
	}
	return counts, nil
}

// allTablesDeleteOrder is the deletion order respecting dependencies.
var allTablesDeleteOrder = []string{
	"finding_records",
	"finding_observations",
	"finding_status_events",
	"finding_hash_aliases",
	"findings",
	"http_records",
	"oast_interactions",
	"oast_payloads",
	"oast_sessions",
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
		ExcludeColumn(findingBodyColumns...)
	fqb.applyFindingFilters(query)
	fqb.applyFindingSorting(query)

	if fqb.filters.Limit > 0 {
		query = query.Limit(int64(fqb.filters.Limit))
	}
	if fqb.filters.Offset > 0 {
		query = query.Offset(int64(fqb.filters.Offset))
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
		ExcludeColumn(findingBodyColumns...)
	fqb.applyFindingFilters(query)
	fqb.applyFindingSorting(query)

	if fqb.filters.Limit > 0 {
		query = query.Limit(int64(fqb.filters.Limit))
	}
	if fqb.filters.Offset > 0 {
		query = query.Offset(int64(fqb.filters.Offset))
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
	if fqb.filters.ObservedInScan != "" {
		query.Where("(f.scan_uuid = ? OR EXISTS (SELECT 1 FROM finding_observations o WHERE o.finding_id = f.id AND o.scan_uuid = ?))",
			fqb.filters.ObservedInScan, fqb.filters.ObservedInScan)
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
		query.Where(WithLikeEscape("f.module_name LIKE ?"), LikeContains(fqb.filters.ModuleName))
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
	if len(fqb.filters.ExcludeStatuses) > 0 {
		query.Where("COALESCE(f.status, ?) NOT IN (?)", StatusTriaged, bun.List(fqb.filters.ExcludeStatuses))
	}

	// Lifecycle predicates over finding_observations. EXISTS/NOT EXISTS rather
	// than a JOIN, so a finding observed by several scans is still one row and
	// pagination and the total stay exact.
	if len(fqb.filters.ObservedInScans) > 0 {
		query.Where("EXISTS (SELECT 1 FROM finding_observations o WHERE o.finding_id = f.id AND o.scan_uuid IN (?))",
			bun.List(fqb.filters.ObservedInScans))
	}
	if ns := fqb.filters.NewSince; ns != nil {
		ns.apply(query)
	}
	if fqb.filters.CreatedAfter != nil {
		query.Where("f.created_at > ?", *fqb.filters.CreatedAfter)
	}

	// Domain filtering via associated HTTP records. Uses EXISTS (not a JOIN) so a
	// finding linked to N records on the matching host yields ONE row, not N — a
	// JOIN here duplicated both the listed rows and the ScanAndCount total. Matches
	// the non-duplicating pattern used by the path/method/status/source filters below.
	if pred, args := recordHostPredicate(fqb.filters.HostPattern, "r"); pred != "" {
		query.Where(findingRegionPredicate(pred), args...)
	}

	// Search across the finding's own fields (module metadata, matched location,
	// request/response snippet) AND the linked HTTP records' url/path/host and
	// raw request/response corpus. Multiple terms are AND-combined: every term
	// must match somewhere, so repeating --search progressively narrows.
	for _, term := range fqb.filters.EffectiveSearchTerms() {
		p := LikeContains(term)
		query.Where(findingSearchPredicate,
			p, p, p, p, p, p, p, // finding fields
			p, p, p, p, p) // record fields
	}

	// Exclusion search: drop findings where ANY term matches the same corpus
	// --search scans (the inverse predicate). Each term is an independent NOT
	// conjunct; the record side uses EXISTS so a finding is dropped when a linked
	// record matches.
	for _, term := range fqb.filters.EffectiveExcludeTerms() {
		p := LikeContains(term)
		query.Where("NOT "+findingSearchPredicate,
			p, p, p, p, p, p, p, // finding fields
			p, p, p, p, p) // record fields
	}

	// Fuzzy search across finding fields and associated HTTP records
	if fqb.filters.FuzzyTerm != "" {
		p := LikeContains(fqb.filters.FuzzyTerm)
		query.Where(fuzzyFindingPredicate,
			p, p, p, p, p, p, p, // finding fields
			p, p, p, p, p) // record fields
	}

	// Path filtering via associated HTTP records.
	//
	// Bound as a placeholder like every other filter. It used to be interpolated
	// with fmt.Sprintf and hand-doubled quotes, which survived only because the
	// doubling was correct; a bound parameter cannot be got wrong, and it is what
	// lets the pattern carry escaped metacharacters at all.
	if fqb.filters.PathPattern != "" {
		pattern := LikeContains(fqb.filters.PathPattern)
		if strings.Contains(fqb.filters.PathPattern, "*") {
			pattern = LikeGlob(fqb.filters.PathPattern)
		}
		query.Where(WithLikeEscape(findingRegionPredicate("r.path LIKE ?")), pattern)
	}

	// Method filtering via associated HTTP records
	if len(fqb.filters.Methods) > 0 {
		query.Where(findingRegionPredicate("r.method IN (?)"), bun.List(fqb.filters.Methods))
	}

	// Status code filtering via associated HTTP records
	if len(fqb.filters.StatusCodes) > 0 {
		query.Where(findingRegionPredicate("r.status_code IN (?)"), bun.List(fqb.filters.StatusCodes))
	}

	// Source filtering via associated HTTP records
	if fqb.filters.Source != "" {
		query.Where(findingRegionPredicate("r.source = ?"), fqb.filters.Source)
	}

	// Header/body searches are attributed here too, via the same region
	// predicates the record listing uses — reached through the junction, so a
	// finding matches when one of its linked records does.
	driver := fqb.db.Driver()
	viaJunction := func(build func(string) string) func(string) string {
		return func(d string) string { return findingRegionPredicate(build(d)) }
	}
	whereRegion(query, viaJunction(headerSearchPredicate), driver, fqb.filters.HeaderSearch, false)
	whereRegion(query, viaJunction(bodySearchPredicate), driver, fqb.filters.BodySearch, false)
	whereRegion(query, viaJunction(headerSearchPredicate), driver, fqb.filters.ExcludeHeaderSearch, true)
	whereRegion(query, viaJunction(bodySearchPredicate), driver, fqb.filters.ExcludeBodySearch, true)

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
	// OrderExpr, not Order: Order parses "<column> <direction>" and rejects the
	// severity rank (a CASE expression) as an unsupported direction, logging an
	// error and dropping the ordering — `--sort severity` came back unsorted.
	// The column is one of mapFindingSortColumn's fixed values, never input.
	query.OrderExpr(sortColumn + " " + order)
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
	// One aggregate implementation, one allowlist. This used to carry its own
	// copy of both — the same GROUP BY, and a private three-column switch that
	// overlapped GroupRecordsBy's eight. Two allowlists over one table is a
	// column added to one and silently missing from the other, and two
	// key-normalization rules is the same command bucketing the same column two
	// ways depending on which view asked.
	grouping, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: projectUUID}).
		GroupRecordsBy(ctx, column, 0)
	if err != nil {
		return nil, fmt.Errorf("CountRecordsByColumn: %w", err)
	}
	out := make(map[string]int64, len(grouping.Groups))
	for _, g := range grouping.Groups {
		out[g.Value] = g.Count
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

// CountFindingsByModule returns finding counts grouped by module_id, scoped to
// one agentic-scan run when agenticScanUUID is non-empty (empty = all rows).
func CountFindingsByModule(ctx context.Context, db *DB, agenticScanUUID string) (map[string]int64, error) {
	var rows []struct {
		ModuleID string `bun:"module_id"`
		Count    int64  `bun:"count"`
	}
	q := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("module_id, COUNT(*) AS count").
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding)
	if agenticScanUUID != "" {
		q = q.Where("agentic_scan_uuid = ?", agenticScanUUID)
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

// CountFindingsByURL returns finding counts grouped by URL, scoped to one
// agentic-scan run when agenticScanUUID is non-empty (empty = all rows).
// Findings with an empty URL are skipped — they aren't endpoint-attributable.
func CountFindingsByURL(ctx context.Context, db *DB, agenticScanUUID string) (map[string]int64, error) {
	var rows []struct {
		URL   string `bun:"url"`
		Count int64  `bun:"count"`
	}
	q := db.NewSelect().
		Model((*Finding)(nil)).
		ColumnExpr("url, COUNT(*) AS count").
		Where("url IS NOT NULL AND url != ''").
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding)
	if agenticScanUUID != "" {
		q = q.Where("agentic_scan_uuid = ?", agenticScanUUID)
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
