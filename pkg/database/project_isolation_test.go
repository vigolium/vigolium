package database

import (
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// newFindingEvent builds a ResultEvent whose ID() (finding_hash) is stable across
// calls with identical module/description/severity/matched fields. The req/resp
// vary so we can tell which project's evidence landed where.
func newFindingEvent(req, resp string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: "sqli-scanner",
		Info: output.Info{
			Name:        "SQL Injection",
			Description: "SQL injection in id parameter",
			Severity:    severity.High,
			Confidence:  severity.Firm,
		},
		Host:     "example.com",
		URL:      "https://example.com/item?id=1",
		Matched:  "https://example.com/item?id=1",
		Request:  req,
		Response: resp,
	}
}

// TestSaveFinding_DedupIsProjectScoped verifies that two projects producing the
// same finding_hash each keep their own finding row, and that evidence is never
// merged across the project boundary.
func TestSaveFinding_DedupIsProjectScoped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const projectA = "project-aaaaaaaa"
	const projectB = "project-bbbbbbbb"

	evA := newFindingEvent("GET /item?id=1 (A)", "200 OK A")
	evB := newFindingEvent("GET /item?id=1 (B)", "200 OK B")

	if err := repo.SaveFinding(ctx, evA, nil, "scanA", projectA); err != nil {
		t.Fatalf("SaveFinding A: %v", err)
	}
	if err := repo.SaveFinding(ctx, evB, nil, "scanB", projectB); err != nil {
		t.Fatalf("SaveFinding B: %v", err)
	}

	// The same finding_hash must NOT collapse two projects into one row.
	if evA.ID() != evB.ID() {
		t.Fatalf("test precondition broken: events should share a finding_hash (%s vs %s)", evA.ID(), evB.ID())
	}

	var findings []*Finding
	if err := db.NewSelect().Model(&findings).Order("project_uuid").Scan(ctx); err != nil {
		t.Fatalf("select findings: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (one per project), got %d", len(findings))
	}

	byProject := map[string]*Finding{}
	for _, f := range findings {
		byProject[f.ProjectUUID] = f
	}
	fa, okA := byProject[projectA]
	fb, okB := byProject[projectB]
	if !okA || !okB {
		t.Fatalf("expected one finding per project, got projects %v", keysOf(byProject))
	}

	// Each project keeps its own evidence; nothing crosses over.
	if !strings.Contains(fa.Request, "(A)") {
		t.Errorf("project A finding lost its own request: %q", fa.Request)
	}
	if !strings.Contains(fb.Request, "(B)") {
		t.Errorf("project B finding lost its own request: %q", fb.Request)
	}
	for _, ev := range fa.AdditionalEvidence {
		if strings.Contains(ev, "(B)") {
			t.Errorf("project A finding contains project B evidence: %q", ev)
		}
	}
	for _, ev := range fb.AdditionalEvidence {
		if strings.Contains(ev, "(A)") {
			t.Errorf("project B finding contains project A evidence: %q", ev)
		}
	}
}

// TestSaveFinding_DedupWithinProject confirms dedup still collapses repeats inside
// a single project and appends the duplicate's evidence to the survivor.
func TestSaveFinding_DedupWithinProject(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	const project = "project-cccccccc"

	first := newFindingEvent("first req", "first resp")
	second := newFindingEvent("second req", "second resp")

	if err := repo.SaveFinding(ctx, first, nil, "scan", project); err != nil {
		t.Fatalf("SaveFinding first: %v", err)
	}
	if err := repo.SaveFinding(ctx, second, nil, "scan", project); err != nil {
		t.Fatalf("SaveFinding second: %v", err)
	}

	var findings []*Finding
	if err := db.NewSelect().Model(&findings).Scan(ctx); err != nil {
		t.Fatalf("select findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding after within-project dedup, got %d", len(findings))
	}

	// The second request/response pair should be appended as additional evidence.
	joined := strings.Join(findings[0].AdditionalEvidence, "\n")
	if !strings.Contains(joined, "second req") {
		t.Errorf("expected duplicate evidence appended, got %q", joined)
	}
}

// TestRecordWriter_DefaultProjectDedup ensures RecordWriter.Write with an empty
// project UUID dedupes the same request the same way Repository.SaveRecord does,
// rather than inserting a second row because of a project_uuid mismatch.
func TestRecordWriter_DefaultProjectDedup(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	w := NewRecordWriter(repo, RecordWriterConfig{})
	defer w.Close()

	rr := makeTestRequest(1)

	first, err := w.Write(ctx, rr, "test", "")
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	second, err := w.Write(ctx, makeTestRequest(1), "test", "")
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if first != second {
		t.Errorf("expected same UUID for duplicate request, got %q and %q", first, second)
	}

	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("count records: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 record row after dedup, got %d", count)
	}

	// The stored row must carry the defaulted project UUID, not an empty string.
	var stored HTTPRecord
	if err := db.NewSelect().Model(&stored).Limit(1).Scan(ctx); err != nil {
		t.Fatalf("select record: %v", err)
	}
	if stored.ProjectUUID != DefaultProjectUUID {
		t.Errorf("expected project_uuid %q, got %q", DefaultProjectUUID, stored.ProjectUUID)
	}
}

// TestRecordWriter_ExplicitProjectDedup repeats the dedup check with an explicit
// project UUID to confirm the defaulting change did not regress the normal path.
func TestRecordWriter_ExplicitProjectDedup(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	w := NewRecordWriter(repo, RecordWriterConfig{})
	defer w.Close()

	const project = "project-dddddddd"

	first, err := w.Write(ctx, makeTestRequest(2), "test", project)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	second, err := w.Write(ctx, makeTestRequest(2), "test", project)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if first != second {
		t.Errorf("expected same UUID for duplicate request, got %q and %q", first, second)
	}

	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Where("project_uuid = ?", project).Count(ctx)
	if err != nil {
		t.Fatalf("count records: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 record row after dedup, got %d", count)
	}
}

// TestSaveRecord_IsProjectScoped verifies the same request stored under two
// projects yields two distinct rows.
func TestSaveRecord_IsProjectScoped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	rrFor := func() *httpmsg.HttpRequestResponse { return makeTestRequest(3) }

	if _, err := repo.SaveRecord(ctx, rrFor(), "test", "project-eeeeeeee"); err != nil {
		t.Fatalf("SaveRecord A: %v", err)
	}
	if _, err := repo.SaveRecord(ctx, rrFor(), "test", "project-ffffffff"); err != nil {
		t.Fatalf("SaveRecord B: %v", err)
	}

	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("count records: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 records across two projects, got %d", count)
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
