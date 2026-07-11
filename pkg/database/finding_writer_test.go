package database

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// makeFindingEvent builds a ResultEvent whose dedup hash varies with
// (moduleID, matched, sev) — see ResultEvent.ID().
func makeFindingEvent(moduleID, matched string, sev severity.Severity) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: moduleID,
		Info: output.Info{
			Name:        moduleID,
			Description: "desc-" + moduleID,
			Severity:    sev,
			Confidence:  severity.Firm,
		},
		Host:          "t.example.com",
		URL:           "https://t.example.com" + matched,
		Matched:       "https://t.example.com" + matched,
		Request:       "GET " + matched + " HTTP/1.1\r\nHost: t.example.com\r\n\r\n",
		Response:      "HTTP/1.1 200 OK\r\n\r\n",
		ModuleType:    "active",
		FindingSource: "scanner",
	}
}

// TestSaveFindingsBatch_DedupsWithinBatch verifies a batch of findings is
// persisted in one transaction and that a duplicate finding_hash inside the
// batch merges records onto the existing finding instead of creating a new row.
func TestSaveFindingsBatch_DedupsWithinBatch(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recA := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/a", 200)
	recB := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/b", 200)

	writes := []FindingWrite{
		{Event: makeFindingEvent("m1", "/a", severity.High), HTTPRecordUUIDs: []string{recA}, ProjectUUID: DefaultProjectUUID},
		{Event: makeFindingEvent("m2", "/b", severity.Medium), HTTPRecordUUIDs: []string{recB}, ProjectUUID: DefaultProjectUUID},
		// Duplicate of m1/a, but evidenced by a different record — must merge.
		{Event: makeFindingEvent("m1", "/a", severity.High), HTTPRecordUUIDs: []string{recB}, ProjectUUID: DefaultProjectUUID},
	}
	if err := repo.SaveFindingsBatch(ctx, writes); err != nil {
		t.Fatalf("SaveFindingsBatch: %v", err)
	}

	_, total, err := repo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 {
		t.Fatalf("total findings = %d, want 2 (duplicate should merge)", total)
	}

	// recB now links to both m2 (original) and m1 (merged), proving the dedup
	// path updated the junction table.
	byRecB, err := repo.GetFindingsByRecordUUID(ctx, recB)
	if err != nil {
		t.Fatalf("GetFindingsByRecordUUID(recB): %v", err)
	}
	if len(byRecB) != 2 {
		t.Errorf("findings linked to recB = %d, want 2 (m1 merged + m2)", len(byRecB))
	}
}

// TestSaveFinding_ReSaveDoesNotDuplicateOwnEvidence reproduces the secret-scan
// report bug where the same finding (same hash, same request/response) is emitted
// across multiple scan passes: the conflict-append path used to fold the
// duplicate's request/response into AdditionalEvidence, so the report printed the
// response twice (once as primary, once under "Additional Evidence"). The append
// must drop a pair that's byte-identical to the survivor's own primary pair.
func TestSaveFinding_ReSaveDoesNotDuplicateOwnEvidence(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recA := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/app.js", 200)
	recB := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/app.js", 200)

	// Same secret, same URL → same finding_hash, same request/response.
	ev := makeFindingEvent("secret-detect", "/app.js", severity.High)
	if err := repo.SaveFinding(ctx, ev, []string{recA}, "", DefaultProjectUUID); err != nil {
		t.Fatalf("SaveFinding (first): %v", err)
	}
	// Re-detected on a second stored copy of the same response.
	if err := repo.SaveFinding(ctx, ev, []string{recB}, "", DefaultProjectUUID); err != nil {
		t.Fatalf("SaveFinding (re-save): %v", err)
	}

	// ListFindings excludes the evidence columns; read the row back in full.
	loadEvidence := func() []string {
		f := &Finding{}
		if err := db.NewSelect().Model(f).
			Where("project_uuid = ?", DefaultProjectUUID).
			Where("module_id = ?", "secret-detect").Scan(ctx); err != nil {
			t.Fatalf("select finding: %v", err)
		}
		return f.AdditionalEvidence
	}

	_, total, err := repo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 1 {
		t.Fatalf("total findings = %d, want 1 (re-save should merge)", total)
	}
	if n := len(loadEvidence()); n != 0 {
		t.Fatalf("AdditionalEvidence = %d entries, want 0 (re-save duplicates the primary pair)", n)
	}

	// A genuinely different request/response, however, is still recorded.
	ev2 := makeFindingEvent("secret-detect", "/app.js", severity.High)
	ev2.Request = "GET /app.js?v=2 HTTP/1.1\r\nHost: t.example.com\r\n\r\n"
	ev2.Response = "HTTP/1.1 200 OK\r\nETag: \"different\"\r\n\r\nvar k='AIza...'"
	if err := repo.SaveFinding(ctx, ev2, []string{recA}, "", DefaultProjectUUID); err != nil {
		t.Fatalf("SaveFinding (distinct evidence): %v", err)
	}
	if n := len(loadEvidence()); n != 1 {
		t.Fatalf("AdditionalEvidence = %d entries, want 1 (distinct pair kept)", n)
	}
}

// TestSaveFinding_ReDetectionBumpsScanUUID is the Claim-6 regression: a finding
// re-detected in a later scan is re-attributed to that scan (project-wide
// uniqueness keeps the earliest row), so it isn't silently excluded from the new
// scan's fail-on gate or scan-scoped report.
func TestSaveFinding_ReDetectionBumpsScanUUID(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	rec := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/app.js", 200)
	ev := makeFindingEvent("secret-detect", "/app.js", severity.High)

	if err := repo.SaveFinding(ctx, ev, []string{rec}, "scan-1", DefaultProjectUUID); err != nil {
		t.Fatalf("SaveFinding (scan-1): %v", err)
	}
	if err := repo.SaveFinding(ctx, ev, []string{rec}, "scan-2", DefaultProjectUUID); err != nil {
		t.Fatalf("SaveFinding (scan-2 re-detect): %v", err)
	}

	f := &Finding{}
	if err := db.NewSelect().Model(f).
		Where("project_uuid = ?", DefaultProjectUUID).
		Where("module_id = ?", "secret-detect").Scan(ctx); err != nil {
		t.Fatalf("select finding: %v", err)
	}
	if f.ScanUUID != "scan-2" {
		t.Fatalf("finding scan_uuid = %q, want %q (re-attributed to re-detecting scan)", f.ScanUUID, "scan-2")
	}

	if _, total, err := repo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID}); err != nil {
		t.Fatalf("ListFindings: %v", err)
	} else if total != 1 {
		t.Fatalf("total findings = %d, want 1 (re-detect merges)", total)
	}
}

// TestSaveFindingsBatch_MatchesSequentialSaves checks that a batched save and a
// sequence of individual SaveFinding calls produce the same finding rows.
func TestSaveFindingsBatch_MatchesSequentialSaves(t *testing.T) {
	ctx := context.Background()
	events := []*output.ResultEvent{
		makeFindingEvent("a", "/1", severity.High),
		makeFindingEvent("b", "/2", severity.Medium),
		makeFindingEvent("c", "/3", severity.Low),
	}

	// Sequential reference.
	seqDB := newTestDB(t)
	seqRepo := NewRepository(seqDB)
	for _, ev := range events {
		if err := seqRepo.SaveFinding(ctx, ev, nil, "", DefaultProjectUUID); err != nil {
			t.Fatalf("SaveFinding: %v", err)
		}
	}
	_, seqTotal, _ := seqRepo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID})

	// Batched.
	batchDB := newTestDB(t)
	batchRepo := NewRepository(batchDB)
	writes := make([]FindingWrite, len(events))
	for i, ev := range events {
		writes[i] = FindingWrite{Event: ev, ProjectUUID: DefaultProjectUUID}
	}
	if err := batchRepo.SaveFindingsBatch(ctx, writes); err != nil {
		t.Fatalf("SaveFindingsBatch: %v", err)
	}
	_, batchTotal, _ := batchRepo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID})

	if seqTotal != batchTotal {
		t.Errorf("batched total = %d, sequential total = %d, want equal", batchTotal, seqTotal)
	}
	if batchTotal != int64(len(events)) {
		t.Errorf("batched total = %d, want %d", batchTotal, len(events))
	}
}

// TestFindingWriter_PersistsAllFindings verifies the async writer drains every
// enqueued finding by Close, across many concurrent producers.
func TestFindingWriter_PersistsAllFindings(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	rec := insertRecordP(t, repo, DefaultProjectUUID, "GET", "t.example.com", "/x", 200)

	w := NewFindingWriter(repo, FindingWriterConfig{
		BufferSize:    128,
		BatchSize:     8,
		FlushInterval: 5 * time.Millisecond,
	})

	const n = 60
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := makeFindingEvent("mod", fmt.Sprintf("/x/%d", i), severity.Low)
			if err := w.Save(ctx, ev, []string{rec}, "", DefaultProjectUUID); err != nil {
				t.Errorf("Save(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	w.Close() // drains buffered findings

	_, total, err := repo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != n {
		t.Fatalf("persisted %d findings, want %d", total, n)
	}

	m := w.Metrics()
	if m.Written+m.Inline != n {
		t.Errorf("metrics written(%d)+inline(%d) = %d, want %d", m.Written, m.Inline, m.Written+m.Inline, n)
	}
	if m.Errors != 0 {
		t.Errorf("metrics errors = %d, want 0", m.Errors)
	}
}

// TestFindingWriter_SaveAfterCloseIsSynchronous verifies findings submitted
// after Close are persisted inline rather than dropped.
func TestFindingWriter_SaveAfterCloseIsSynchronous(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	w := NewFindingWriter(repo, FindingWriterConfig{})
	w.Close()

	ev := makeFindingEvent("mod", "/late", severity.Low)
	if err := w.Save(ctx, ev, nil, "", DefaultProjectUUID); err != nil {
		t.Fatalf("Save after Close: %v", err)
	}

	_, total, err := repo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 1 {
		t.Fatalf("post-close finding not persisted: total = %d, want 1", total)
	}
	if m := w.Metrics(); m.Inline != 1 {
		t.Errorf("metrics inline = %d, want 1", m.Inline)
	}
}

// TestFindingWriter_DoubleCloseSafe ensures Close is idempotent.
func TestFindingWriter_DoubleCloseSafe(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	w := NewFindingWriter(repo, FindingWriterConfig{})
	w.Close()
	w.Close() // must not panic or hang
}
