package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// insertRecord saves one HTTP record with a controllable method/host/path/status
// and returns its UUID.
func insertRecord(t *testing.T, repo *Repository, method, host, path string, status int) string {
	t.Helper()
	ctx := context.Background()
	raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, path, host)
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	resp := httpmsg.NewHttpResponse([]byte(fmt.Sprintf("HTTP/1.1 %d X\r\nContent-Type: text/html\r\n\r\nbody", status)))
	rr = rr.WithResponse(resp)
	u, err := repo.SaveRecord(ctx, rr, "test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	return u
}

func TestNewQueryBuilder(t *testing.T) {
	db := newTestDB(t)
	filters := QueryFilters{ProjectUUID: DefaultProjectUUID, Limit: 10}
	qb := NewQueryBuilder(db, filters)
	if qb == nil {
		t.Fatal("NewQueryBuilder returned nil")
	}
	if qb.db != db {
		t.Error("query builder db not wired")
	}
	if qb.filters.Limit != 10 {
		t.Errorf("filters not stored: Limit=%d", qb.filters.Limit)
	}
}

func TestQueryBuilder_HostAndMethodFilter(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecord(t, repo, "GET", "alpha.example.com", "/a", 200)
	insertRecord(t, repo, "POST", "alpha.example.com", "/b", 201)
	insertRecord(t, repo, "GET", "beta.example.com", "/c", 200)

	// Host = alpha only.
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, HostPattern: "alpha.example.com"})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("host filter: got %d records, want 2", len(recs))
	}
	for _, r := range recs {
		if r.Hostname != "alpha.example.com" {
			t.Errorf("host filter leaked %q", r.Hostname)
		}
	}

	// Host alpha + method POST.
	qb = NewQueryBuilder(db, QueryFilters{
		ProjectUUID: DefaultProjectUUID,
		HostPattern: "alpha.example.com",
		Methods:     []string{"POST"},
	})
	recs, err = qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 1 || recs[0].Method != "POST" {
		t.Fatalf("method filter: got %d records (%v), want 1 POST", len(recs), recs)
	}
}

func TestQueryBuilder_WildcardHostAndStatusFilter(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecord(t, repo, "GET", "api.shop.com", "/x", 200)
	insertRecord(t, repo, "GET", "web.shop.com", "/y", 404)
	insertRecord(t, repo, "GET", "other.net", "/z", 200)

	// Wildcard host *.shop.com.
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, HostPattern: "*.shop.com"})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("wildcard host: got %d, want 2", len(recs))
	}

	// Status code filter.
	qb = NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, StatusCodes: []int{404}})
	recs, err = qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 1 || recs[0].StatusCode != 404 {
		t.Fatalf("status filter: got %d (%v), want one 404", len(recs), recs)
	}
}

func TestQueryBuilder_PathFilter(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecord(t, repo, "GET", "h.example.com", "/admin/login", 200)
	insertRecord(t, repo, "GET", "h.example.com", "/public/home", 200)

	// Substring (fuzzy) path match.
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, PathPattern: "admin"})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "/admin/login" {
		t.Fatalf("path substring: got %d (%v), want /admin/login", len(recs), recs)
	}

	// Wildcard path match.
	qb = NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, PathPattern: "/public/*"})
	recs, err = qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "/public/home" {
		t.Fatalf("path wildcard: got %d (%v), want /public/home", len(recs), recs)
	}
}

func TestQueryBuilder_LimitOffsetAndCount(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		insertRecord(t, repo, "GET", "page.example.com", fmt.Sprintf("/p%d", i), 200)
	}

	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID})
	total, err := qb.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 5 {
		t.Fatalf("Count = %d, want 5", total)
	}

	// Limit 2, offset 1 → 2 rows.
	qb = NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, Limit: 2, Offset: 1})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("limit/offset: got %d, want 2", len(recs))
	}
}

func TestQueryBuilder_Sorting(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Distinct status codes to make ordering observable.
	insertRecord(t, repo, "GET", "sort.example.com", "/a", 200)
	insertRecord(t, repo, "GET", "sort.example.com", "/b", 500)
	insertRecord(t, repo, "GET", "sort.example.com", "/c", 301)

	// Ascending by status_code.
	qb := NewQueryBuilder(db, QueryFilters{
		ProjectUUID: DefaultProjectUUID,
		SortBy:      "status",
		SortAsc:     true,
	})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d rows, want 3", len(recs))
	}
	if recs[0].StatusCode != 200 || recs[2].StatusCode != 500 {
		t.Errorf("ascending status order wrong: %d ... %d", recs[0].StatusCode, recs[2].StatusCode)
	}

	// Descending by status_code (SortAsc=false).
	qb = NewQueryBuilder(db, QueryFilters{
		ProjectUUID: DefaultProjectUUID,
		SortBy:      "status_code",
		SortAsc:     false,
	})
	recs, err = qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if recs[0].StatusCode != 500 || recs[2].StatusCode != 200 {
		t.Errorf("descending status order wrong: %d ... %d", recs[0].StatusCode, recs[2].StatusCode)
	}
}

func TestQueryBuilder_MapSortColumn(t *testing.T) {
	qb := &QueryBuilder{}
	tests := map[string]string{
		"uuid":          "r.uuid",
		"created":       "r.created_at",
		"created_at":    "r.created_at",
		"sent":          "r.sent_at",
		"method":        "r.method",
		"path":          "r.path",
		"status":        "r.status_code",
		"status_code":   "r.status_code",
		"time":          "r.response_time_ms",
		"response_time": "r.response_time_ms",
		"source":        "r.source",
		"risk":          "r.risk_score",
		"risk_score":    "r.risk_score",
		"nonsense":      "r.created_at", // default fallback
	}
	for in, want := range tests {
		if got := qb.mapSortColumn(in); got != want {
			t.Errorf("mapSortColumn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQueryBuilder_ProjectScoping(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecord(t, repo, "GET", "scoped.example.com", "/a", 200)

	// Querying a different project must return nothing.
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: uuid.New().String()})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("cross-project query leaked %d records", len(recs))
	}
}

// --- Finding count aggregations ---

func saveFinding(t *testing.T, repo *Repository, moduleID, sev string) {
	t.Helper()
	ctx := context.Background()
	f := &Finding{
		ProjectUUID: DefaultProjectUUID,
		ModuleID:    moduleID,
		ModuleName:  moduleID,
		Severity:    sev,
		Confidence:  "firm",
		FindingHash: uuid.New().String(), // unique to avoid dedup collapse
		Status:      StatusTriaged,
	}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatalf("SaveFindingDirect: %v", err)
	}
}

func TestCountFindingsBySeverity(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	saveFinding(t, repo, "mod-a", SeverityHigh)
	saveFinding(t, repo, "mod-b", SeverityHigh)
	saveFinding(t, repo, "mod-c", SeverityLow)

	counts, err := CountFindingsBySeverity(ctx, db, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("CountFindingsBySeverity: %v", err)
	}
	if counts[SeverityHigh] != 2 {
		t.Errorf("high = %d, want 2", counts[SeverityHigh])
	}
	if counts[SeverityLow] != 1 {
		t.Errorf("low = %d, want 1", counts[SeverityLow])
	}
	if counts[SeverityCritical] != 0 {
		t.Errorf("critical = %d, want 0", counts[SeverityCritical])
	}

	// Scoping to a foreign project yields an empty (non-error) map.
	empty, err := CountFindingsBySeverity(ctx, db, uuid.New().String())
	if err != nil {
		t.Fatalf("CountFindingsBySeverity (foreign): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("foreign project should have 0 severities, got %v", empty)
	}
}

func TestCountFindingsByModule(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	saveFinding(t, repo, "sqli", SeverityHigh)
	saveFinding(t, repo, "sqli", SeverityMedium)
	saveFinding(t, repo, "xss", SeverityLow)

	counts, err := CountFindingsByModule(ctx, db, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("CountFindingsByModule: %v", err)
	}
	if counts["sqli"] != 2 {
		t.Errorf("sqli = %d, want 2", counts["sqli"])
	}
	if counts["xss"] != 1 {
		t.Errorf("xss = %d, want 1", counts["xss"])
	}
}

func TestFindingsQueryBuilder_SeverityAndModuleFilter(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	saveFinding(t, repo, "sqli", SeverityHigh)
	saveFinding(t, repo, "sqli", SeverityMedium)
	saveFinding(t, repo, "xss", SeverityHigh)

	// Severity = high.
	fqb := NewFindingsQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, Severity: []string{SeverityHigh}})
	findings, err := fqb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("severity high: got %d, want 2", len(findings))
	}

	// Module name = sqli (LIKE).
	fqb = NewFindingsQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ModuleName: "sqli"})
	findings, count, err := fqb.ExecuteWithCount(ctx)
	if err != nil {
		t.Fatalf("ExecuteWithCount: %v", err)
	}
	if count != 2 || len(findings) != 2 {
		t.Fatalf("module sqli: got count=%d len=%d, want 2/2", count, len(findings))
	}

	// Count() over project = 3.
	fqb = NewFindingsQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID})
	total, err := fqb.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 3 {
		t.Fatalf("total findings = %d, want 3", total)
	}
}

func TestFindingsQueryBuilder_MapFindingSortColumn(t *testing.T) {
	fqb := &FindingsQueryBuilder{}
	tests := map[string]string{
		"found":       "f.found_at",
		"found_at":    "f.found_at",
		"created":     "f.created_at",
		"severity":    "f.severity",
		"module":      "f.module_name",
		"module_name": "f.module_name",
		"module_id":   "f.module_id",
		"confidence":  "f.confidence",
		"bogus":       "f.found_at", // default fallback
	}
	for in, want := range tests {
		if got := fqb.mapFindingSortColumn(in); got != want {
			t.Errorf("mapFindingSortColumn(%q) = %q, want %q", in, got, want)
		}
	}
}
