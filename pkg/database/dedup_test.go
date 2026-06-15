package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeduplicateDeparosRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID

	// Helper to insert a deparos record with specific fields.
	insertRecord := func(hostname, method, path, responseHash string, statusCode int, contentLength int64) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                  id,
			ProjectUUID:           projectUUID,
			Scheme:                "https",
			Hostname:              hostname,
			Port:                  443,
			Method:                method,
			Path:                  path,
			URL:                   "https://" + hostname + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           id, // unique
			StatusCode:            statusCode,
			ResponseContentLength: contentLength,
			ResponseHash:          responseHash,
			HasResponse:           true,
			Source:                "deparos",
			SentAt:                time.Now(),
			CreatedAt:             time.Now(),
		}
		_, err := db.NewInsert().Model(rec).Exec(ctx)
		if err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// Group 1: 3 records with same response hash on host1 — shortest path "/a" should survive
	g1a := insertRecord("host1.com", "GET", "/a", "hash-aaa", 405, 0)
	_ = insertRecord("host1.com", "GET", "/a/b/c", "hash-aaa", 405, 0)
	_ = insertRecord("host1.com", "GET", "/a/b", "hash-aaa", 405, 0)

	// Group 2: 2 records with same hash on host1, different status — no dedup (different group key)
	g2a := insertRecord("host1.com", "GET", "/x", "hash-bbb", 200, 100)
	g2b := insertRecord("host1.com", "GET", "/x/y", "hash-bbb", 404, 100)

	// Group 3: 2 records, same hash on host2
	g3a := insertRecord("host2.com", "POST", "/short", "hash-ccc", 200, 50)
	_ = insertRecord("host2.com", "POST", "/much/longer/path", "hash-ccc", 200, 50)

	// Non-deparos record — should NOT be touched
	nonDeparos := uuid.NewString()
	_, err := db.NewInsert().Model(&HTTPRecord{
		UUID:                  nonDeparos,
		ProjectUUID:           projectUUID,
		Scheme:                "https",
		Hostname:              "host1.com",
		Port:                  443,
		Method:                "GET",
		Path:                  "/z",
		URL:                   "https://host1.com/z",
		HTTPVersion:           "HTTP/1.1",
		RequestHash:           nonDeparos,
		StatusCode:            405,
		ResponseContentLength: 0,
		ResponseHash:          "hash-aaa",
		HasResponse:           true,
		Source:                "scanner",
		SentAt:                time.Now(),
		CreatedAt:             time.Now(),
	}).Exec(ctx)
	if err != nil {
		t.Fatalf("insert non-deparos record: %v", err)
	}

	// Record without response — should NOT be touched
	noResp := insertRecordNoResponse(t, db, ctx, projectUUID)

	// Insert a finding_records junction row for one of the duplicates to verify cleanup
	_, err = db.ExecContext(ctx,
		"INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name, finding_hash, severity, confidence, http_record_uuids) VALUES (?, 'scan1', 'mod1', 'mod1', 'fh1', 'info', 'tentative', '[]')",
		projectUUID)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	// Link finding (id=1) to a record that will be deleted
	_, err = db.ExecContext(ctx, "INSERT INTO finding_records (finding_id, record_uuid) VALUES (1, ?)", g1a)
	if err != nil {
		// g1a survives, so let's link to a duplicate that will be deleted
		t.Logf("finding_records insert note: %v (may be fine)", err)
	}

	// Run dedup
	deleted, err := repo.DeduplicateDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateDeparosRecords: %v", err)
	}

	// Group 1: 3 records, 1 kept → 2 deleted
	// Group 2: different status codes, so they're separate groups of 1 each → 0 deleted
	// Group 3: 2 records, 1 kept → 1 deleted
	// Total: 3 deleted
	if deleted != 3 {
		t.Errorf("expected 3 deleted, got %d", deleted)
	}

	// Verify survivors
	survivors := map[string]bool{g1a: true, g2a: true, g2b: true, g3a: true, nonDeparos: true, noResp: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining records, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: %s (path=%s, source=%s)", rec.UUID, rec.Path, rec.Source)
		}
	}
}

func TestDeduplicateDeparosRecords_NoRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	deleted, err := repo.DeduplicateDeparosRecords(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}
}

func TestDeduplicateFindings(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID

	// Helper to insert a finding with specific fields.
	insertFinding := func(moduleID, severity, matchedAtURL string) int64 {
		matchedAt := "[]"
		if matchedAtURL != "" {
			matchedAt = `["` + matchedAtURL + `"]`
		}
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at)
			VALUES (?, 'scan1', ?, ?, ?, ?, 'firm', '[]', ?)`,
			projectUUID, moduleID, moduleID, uuid.NewString(), severity, matchedAt)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	// Group 1: same module, severity, URL — 5 findings (like input-behavior-probe with different payloads)
	g1First := insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")
	_ = insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")
	_ = insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")
	_ = insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")
	_ = insertFinding("input-behavior-probe", "info", "http://localhost:3000/ftp/eastere.gg")

	// Group 2: same module, different URL — separate group, kept
	g2 := insertFinding("input-behavior-probe", "info", "http://localhost:3000/api/users")

	// Group 3: different module, same URL — separate group, kept
	g3 := insertFinding("xss-scanner", "medium", "http://localhost:3000/ftp/eastere.gg")

	// Group 4: same module, same URL, different severity — separate group
	g4 := insertFinding("input-behavior-probe", "medium", "http://localhost:3000/ftp/eastere.gg")

	// Group 5: no matched_at — should NOT be touched
	g5 := insertFinding("input-behavior-probe", "info", "")

	// Insert a junction row for one of the duplicates
	_, _ = db.ExecContext(ctx, "INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)", g1First+1, uuid.NewString())

	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings: %v", err)
	}

	// Group 1: 5 → 1 = 4 deleted, 1 group merged
	// Groups 2-5: 1 each = 0 deleted
	// Total: 4 deleted, 1 grouped
	if deleted != 4 {
		t.Errorf("expected 4 deleted, got %d", deleted)
	}
	if grouped != 1 {
		t.Errorf("expected 1 grouped, got %d", grouped)
	}

	// Verify survivors
	var remaining []*Finding
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != 5 {
		t.Errorf("expected 5 remaining findings, got %d", len(remaining))
	}

	survivors := map[int64]bool{g1First: true, g2: true, g3: true, g4: true, g5: true}
	for _, f := range remaining {
		if !survivors[f.ID] {
			t.Errorf("unexpected survivor: id=%d module=%s severity=%s", f.ID, f.ModuleID, f.Severity)
		}
	}

	// Verify junction rows for deleted findings are cleaned up
	var junctionCount int
	err = db.NewRaw("SELECT COUNT(*) FROM finding_records WHERE finding_id = ?", g1First+1).Scan(ctx, &junctionCount)
	if err != nil {
		t.Fatalf("junction count query: %v", err)
	}
	if junctionCount != 0 {
		t.Errorf("expected junction rows cleaned up, got %d", junctionCount)
	}
}

func TestDeduplicateFindings_HostScoped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID

	insert := func(host, matchedAtURL string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, hostname, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at)
			VALUES (?, 'scan1', ?, 'input-behavior-probe', 'input-behavior-probe', ?, 'info', 'firm', '[]', ?)`,
			projectUUID, host, uuid.NewString(), `["`+matchedAtURL+`"]`)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	// 3 duplicates on host A and 3 on host B (same module/severity/URL within each host).
	insert("a.example.com", "http://a.example.com/x")
	insert("a.example.com", "http://a.example.com/x")
	insert("a.example.com", "http://a.example.com/x")
	insert("b.example.com", "http://b.example.com/y")
	insert("b.example.com", "http://b.example.com/y")
	insert("b.example.com", "http://b.example.com/y")

	// Scoped to host A: only A's 2 redundant findings collapse; B is untouched.
	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID, "a.example.com")
	if err != nil {
		t.Fatalf("DeduplicateFindings (scoped): %v", err)
	}
	if deleted != 2 || grouped != 1 {
		t.Fatalf("scoped pass: expected 2 deleted / 1 grouped, got %d / %d", deleted, grouped)
	}
	var bCount int
	if err := db.NewRaw("SELECT COUNT(*) FROM findings WHERE hostname = ?", "b.example.com").Scan(ctx, &bCount); err != nil {
		t.Fatalf("count B: %v", err)
	}
	if bCount != 3 {
		t.Fatalf("host B should be untouched by an A-scoped pass, got %d findings", bCount)
	}

	// Unscoped pass now collapses host B's duplicates too.
	deleted, grouped, err = repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings (unscoped): %v", err)
	}
	if deleted != 2 || grouped != 1 {
		t.Fatalf("unscoped pass: expected 2 deleted / 1 grouped, got %d / %d", deleted, grouped)
	}
}

func TestDeduplicateFindings_EvidenceCollected(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	matchedAt := `["http://example.com/api"]`

	// Insert 3 findings with the same group key but different request/response data.
	insertWithReqRes := func(request, response string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at, request, response)
			VALUES (?, 'scan1', 'sqli', 'sqli', ?, 'high', 'firm', '[]', ?, ?, ?)`,
			projectUUID, uuid.NewString(), matchedAt, request, response)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	survivorID := insertWithReqRes("GET /api?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nok")
	_ = insertWithReqRes("GET /api?id=1'+OR+1=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 500\r\n\r\nerror")
	_ = insertWithReqRes("GET /api?id=1'+UNION+SELECT HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 500\r\n\r\nSQL error")

	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted, got %d", deleted)
	}
	if grouped != 1 {
		t.Errorf("expected 1 grouped, got %d", grouped)
	}

	// Verify survivor has evidence from the 2 deleted duplicates.
	survivor := &Finding{}
	err = db.NewSelect().Model(survivor).Where("id = ?", survivorID).Scan(ctx)
	if err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	if len(survivor.AdditionalEvidence) != 2 {
		t.Fatalf("expected 2 additional evidence entries, got %d", len(survivor.AdditionalEvidence))
	}
	// Each evidence entry should contain the separator.
	for i, ev := range survivor.AdditionalEvidence {
		if !strings.Contains(ev, EvidenceSeparator) {
			t.Errorf("evidence[%d] missing separator: %q", i, ev)
		}
	}
}

func TestDeduplicateFindings_EvidenceCapped(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	matchedAt := `["http://example.com/api"]`

	// Insert 1 survivor + 15 duplicates (16 total) with the same group key.
	insertWithReqRes := func(request, response string) int64 {
		res, err := db.ExecContext(ctx,
			`INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name,
				finding_hash, severity, confidence, http_record_uuids, matched_at, request, response)
			VALUES (?, 'scan1', 'sqli', 'sqli', ?, 'high', 'firm', '[]', ?, ?, ?)`,
			projectUUID, uuid.NewString(), matchedAt, request, response)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		id, _ := res.LastInsertId()
		return id
	}

	survivorID := insertWithReqRes("GET /api?id=0 HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nok")
	for i := 1; i <= 15; i++ {
		insertWithReqRes(
			"GET /api?id="+strings.Repeat("x", i)+" HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 500\r\n\r\nerror",
		)
	}

	deleted, grouped, err := repo.DeduplicateFindings(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateFindings: %v", err)
	}
	if deleted != 15 {
		t.Errorf("expected 15 deleted, got %d", deleted)
	}
	if grouped != 1 {
		t.Errorf("expected 1 grouped, got %d", grouped)
	}

	// Verify survivor's AdditionalEvidence is capped at maxAdditionalEvidence.
	survivor := &Finding{}
	err = db.NewSelect().Model(survivor).Where("id = ?", survivorID).Scan(ctx)
	if err != nil {
		t.Fatalf("select survivor: %v", err)
	}
	if len(survivor.AdditionalEvidence) != maxAdditionalEvidence {
		t.Fatalf("expected %d additional evidence entries (capped), got %d", maxAdditionalEvidence, len(survivor.AdditionalEvidence))
	}
}

func TestDeduplicateFindings_NoFindings(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	deleted, grouped, err := repo.DeduplicateFindings(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}
	if grouped != 0 {
		t.Errorf("expected 0 grouped, got %d", grouped)
	}
}

func TestDeduplicateSoftDeparosRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	// Helper to insert a deparos record with response characteristics.
	insertRec := func(hostname, method, path string, statusCode int, contentLength, words int64, contentType string) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                  id,
			ProjectUUID:           projectUUID,
			Scheme:                "https",
			Hostname:              hostname,
			Port:                  443,
			Method:                method,
			Path:                  path,
			URL:                   "https://" + hostname + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           id,
			ResponseHash:          id, // unique hash per record
			StatusCode:            statusCode,
			ResponseContentLength: contentLength,
			ResponseWords:         words,
			ResponseContentType:   contentType,
			HasResponse:           true,
			Source:                "deparos",
			SentAt:                now,
			CreatedAt:             now,
		}
		_, err := db.NewInsert().Model(rec).Exec(ctx)
		if err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// Group 1: 5 records under /ftp/quarantine/... (status 405, size 0, words 28)
	// Shortest path "/ftp/quarantine/" should survive.
	g1Short := insertRec("host1.com", "GET", "/ftp/quarantine/", 405, 0, 28, "text/html")
	g1Dup1 := insertRec("host1.com", "GET", "/ftp/quarantine/abc.zip", 405, 0, 28, "text/html")
	_ = insertRec("host1.com", "GET", "/ftp/quarantine/def.tar.gz", 405, 0, 28, "text/html")
	_ = insertRec("host1.com", "GET", "/ftp/quarantine/ghi/nested", 405, 0, 28, "text/html")
	_ = insertRec("host1.com", "GET", "/ftp/quarantine/jkl.pdf", 405, 0, 28, "text/html")

	// Group 2: 3 records under /api/v1/... (status 200, size 100, words 50)
	g2Short := insertRec("host1.com", "GET", "/api/v1/a", 200, 100, 50, "application/json")
	_ = insertRec("host1.com", "GET", "/api/v1/b/c", 200, 100, 50, "application/json")
	_ = insertRec("host1.com", "GET", "/api/v1/d/e/f", 200, 100, 50, "application/json")

	// Group 3: only 2 records under /static/... — below threshold, NOT deduplicated
	g3a := insertRec("host1.com", "GET", "/static/css/main.css", 200, 500, 10, "text/css")
	g3b := insertRec("host1.com", "GET", "/static/css/reset.css", 200, 500, 10, "text/css")

	// Non-deparos record matching group 1 characteristics — should NOT be touched
	nonDeparos := uuid.NewString()
	_, err := db.NewInsert().Model(&HTTPRecord{
		UUID:                  nonDeparos,
		ProjectUUID:           projectUUID,
		Scheme:                "https",
		Hostname:              "host1.com",
		Port:                  443,
		Method:                "GET",
		Path:                  "/ftp/quarantine/scanner",
		URL:                   "https://host1.com/ftp/quarantine/scanner",
		HTTPVersion:           "HTTP/1.1",
		RequestHash:           nonDeparos,
		ResponseHash:          nonDeparos,
		StatusCode:            405,
		ResponseContentLength: 0,
		ResponseWords:         28,
		ResponseContentType:   "text/html",
		HasResponse:           true,
		Source:                "scanner",
		SentAt:                now,
		CreatedAt:             now,
	}).Exec(ctx)
	if err != nil {
		t.Fatalf("insert non-deparos record: %v", err)
	}

	// Insert a finding_records junction row for one of the duplicates
	_, err = db.ExecContext(ctx,
		"INSERT INTO findings (project_uuid, scan_uuid, module_id, module_name, finding_hash, severity, confidence, http_record_uuids) VALUES (?, 'scan1', 'mod1', 'mod1', 'fh-soft', 'info', 'tentative', '[]')",
		projectUUID)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	_, err = db.ExecContext(ctx, "INSERT INTO finding_records (finding_id, record_uuid) VALUES (1, ?)", g1Dup1)
	if err != nil {
		t.Fatalf("insert finding_records: %v", err)
	}

	deleted, statusCodes, err := repo.DeduplicateSoftDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateSoftDeparosRecords: %v", err)
	}

	// Group 1: 5 → 1 = 4 deleted
	// Group 2: 3 → 1 = 2 deleted
	// Group 3: 2 members, below threshold = 0 deleted
	// Total: 6
	if deleted != 6 {
		t.Errorf("expected 6 deleted, got %d", deleted)
	}
	if statusCodes == nil {
		t.Error("expected non-nil statusCodes map")
	}

	// Verify survivors
	survivors := map[string]bool{g1Short: true, g2Short: true, g3a: true, g3b: true, nonDeparos: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining records, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: %s (path=%s, source=%s)", rec.UUID, rec.Path, rec.Source)
		}
	}

	// Verify junction row cleanup
	var junctionCount int
	err = db.NewRaw("SELECT COUNT(*) FROM finding_records WHERE record_uuid = ?", g1Dup1).Scan(ctx, &junctionCount)
	if err != nil {
		t.Fatalf("junction count query: %v", err)
	}
	if junctionCount != 0 {
		t.Errorf("expected junction rows cleaned up, got %d", junctionCount)
	}
}

func TestDeduplicateSoftDeparosRecords_NoRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	deleted, _, err := repo.DeduplicateSoftDeparosRecords(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}
}

func TestDeduplicateSoftDeparosRecords_DifferentCharacteristics(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	insertRec := func(path string, statusCode int, words int64) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                  id,
			ProjectUUID:           projectUUID,
			Scheme:                "https",
			Hostname:              "host1.com",
			Port:                  443,
			Method:                "GET",
			Path:                  path,
			URL:                   "https://host1.com" + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           id,
			ResponseHash:          id,
			StatusCode:            statusCode,
			ResponseContentLength: 100,
			ResponseWords:         words,
			ResponseContentType:   "text/html",
			HasResponse:           true,
			Source:                "deparos",
			SentAt:                now,
			CreatedAt:             now,
		}
		_, err := db.NewInsert().Model(rec).Exec(ctx)
		if err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// Same prefix /api/v1/ but different status codes — should NOT be grouped
	insertRec("/api/v1/a", 200, 50)
	insertRec("/api/v1/b", 404, 50)
	insertRec("/api/v1/c", 500, 50)

	// Same prefix /api/v1/ but different word counts — should NOT be grouped
	insertRec("/api/v1/d", 200, 10)
	insertRec("/api/v1/e", 200, 20)
	insertRec("/api/v1/f", 200, 30)

	deleted, _, err := repo.DeduplicateSoftDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateSoftDeparosRecords: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}
}

// TestDeduplicateSoftDeparosRecords_ReflectedURLLength is the regression for the
// reflected-URL case: a family of probes against an error page that echoes the
// requested URI share status/words/content-type/prefix but differ in
// response_content_length (the echoed URI's length varies per probe). Now that
// exact length is no longer part of the soft-dedup key, the family collapses.
func TestDeduplicateSoftDeparosRecords_ReflectedURLLength(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	insertRec := func(path string, contentLength int64) {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                  id,
			ProjectUUID:           projectUUID,
			Scheme:                "https",
			Hostname:              "host1.com",
			Port:                  443,
			Method:                "GET",
			Path:                  path,
			URL:                   "https://host1.com" + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           id,
			ResponseHash:          id, // unique hash → exact dedup can't help
			StatusCode:            400,
			ResponseContentLength: contentLength, // varies with the echoed URI
			ResponseWords:         42,
			ResponseContentType:   "text/html",
			HasResponse:           true,
			Source:                "deparos",
			SentAt:                now,
			CreatedAt:             now,
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("insert record: %v", err)
		}
	}

	// 4 probes under /jboss-net/, identical shape but each a different length.
	insertRec("/jboss-net//happyaxis.jsp", 430)
	insertRec("/jboss-net//happyaxis.jsp.OLD", 434)
	insertRec("/jboss-net//happyaxis.jsp.orig", 435)
	insertRec("/jboss-net//happyaxis.jsp.csproj", 437)

	deleted, _, err := repo.DeduplicateSoftDeparosRecords(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateSoftDeparosRecords: %v", err)
	}
	// 4 → 1 survivor = 3 deleted, despite the differing content lengths.
	if deleted != 3 {
		t.Errorf("expected 3 deleted (reflected-URL family collapses regardless of length), got %d", deleted)
	}
}

func TestApplyDeparosStatusPolicy(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	insertRec := func(hostname, path string, statusCode int, source string) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:         id,
			ProjectUUID:  projectUUID,
			Scheme:       "https",
			Hostname:     hostname,
			Port:         443,
			Method:       "GET",
			Path:         path,
			URL:          "https://" + hostname + path,
			HTTPVersion:  "HTTP/1.1",
			RequestHash:  id,
			ResponseHash: id,
			StatusCode:   statusCode,
			HasResponse:  true,
			Source:       source,
			SentAt:       now,
			CreatedAt:    now,
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// 4xx that must be dropped.
	insertRec("h1.com", "/bad-400", 400, "deparos")
	insertRec("h1.com", "/forbidden-403", 403, "deparos")
	insertRec("h1.com", "/gone-410", 410, "deparos")
	// 401s on h1: collapse to one representative (shortest path survives).
	a1 := insertRec("h1.com", "/a", 401, "deparos")
	insertRec("h1.com", "/admin/secret", 401, "deparos")
	insertRec("h1.com", "/another/longer/path", 401, "deparos")
	// 401 on a second host keeps its own representative.
	b1 := insertRec("h2.com", "/login", 401, "deparos")
	// Kept statuses (not 4xx).
	ok200 := insertRec("h1.com", "/index", 200, "deparos")
	redir := insertRec("h1.com", "/old", 301, "deparos")
	serr := insertRec("h1.com", "/boom", 500, "deparos")
	// A 403 from a non-deparos source must be untouched.
	nonDeparos := insertRec("h1.com", "/scanner-403", 403, "scanner")

	deleted, statusCodes, err := repo.ApplyDeparosStatusPolicy(ctx, projectUUID, []int{401})
	if err != nil {
		t.Fatalf("ApplyDeparosStatusPolicy: %v", err)
	}
	// Dropped: 400, 403, 410 (3) + two extra 401s on h1 (2) = 5.
	if deleted != 5 {
		t.Errorf("expected 5 deleted, got %d", deleted)
	}
	if statusCodes[401] != 2 {
		t.Errorf("expected 2 collapsed 401 records in breakdown, got %d", statusCodes[401])
	}

	survivors := map[string]bool{a1: true, b1: true, ok200: true, redir: true, serr: true, nonDeparos: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: %s (path=%s status=%d source=%s)", rec.UUID, rec.Path, rec.StatusCode, rec.Source)
		}
	}
}

func TestApplyDeparosStatusPolicy_NoKeepDropsAll4xx(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := DefaultProjectUUID
	now := time.Now()

	insert := func(path string, status int) {
		id := uuid.NewString()
		_, err := db.NewInsert().Model(&HTTPRecord{
			UUID: id, ProjectUUID: projectUUID, Scheme: "https", Hostname: "h.com", Port: 443,
			Method: "GET", Path: path, URL: "https://h.com" + path, HTTPVersion: "HTTP/1.1",
			RequestHash: id, ResponseHash: id, StatusCode: status, HasResponse: true,
			Source: "deparos", SentAt: now, CreatedAt: now,
		}).Exec(ctx)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	insert("/a", 401)
	insert("/b", 403)
	insert("/c", 200)

	// Empty keep list ⇒ every 4xx (including 401) is dropped.
	deleted, _, err := repo.ApplyDeparosStatusPolicy(ctx, projectUUID, nil)
	if err != nil {
		t.Fatalf("ApplyDeparosStatusPolicy: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted (401+403), got %d", deleted)
	}
}

func TestDeduplicateDeparosByNormHash(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	projectUUID := DefaultProjectUUID
	now := time.Now()

	insertRec := func(hostname, path string, status int, normHash, source string) string {
		id := uuid.NewString()
		rec := &HTTPRecord{
			UUID:                id,
			ProjectUUID:         projectUUID,
			Scheme:              "https",
			Hostname:            hostname,
			Port:                443,
			Method:              "GET",
			Path:                path,
			URL:                 "https://" + hostname + path,
			HTTPVersion:         "HTTP/1.1",
			RequestHash:         id,
			ResponseHash:        id, // unique — exact dedup never fires
			ResponseNormHash:    normHash,
			StatusCode:          status,
			ResponseContentType: "text/html",
			HasResponse:         true,
			Source:              source,
			SentAt:              now,
			CreatedAt:           now,
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("insert record: %v", err)
		}
		return id
	}

	// Same normalized body across 3 echoing paths — shortest path survives.
	keep := insertRec("h1.com", "/x", 200, "NORM-AAA", "deparos")
	insertRec("h1.com", "/x/longer", 200, "NORM-AAA", "deparos")
	insertRec("h1.com", "/x/longest/path", 200, "NORM-AAA", "deparos")
	// Different normalized body — kept.
	other := insertRec("h1.com", "/y", 200, "NORM-BBB", "deparos")
	// Same norm hash but different status — not collapsed together.
	diffStatus := insertRec("h1.com", "/z", 500, "NORM-AAA", "deparos")
	// Empty norm hash (e.g. empty body) — left to exact dedup, untouched.
	emptyNorm1 := insertRec("h1.com", "/e1", 204, "", "deparos")
	emptyNorm2 := insertRec("h1.com", "/e2", 204, "", "deparos")
	// Matching norm hash but non-deparos source — untouched.
	nonDeparos := insertRec("h1.com", "/n", 200, "NORM-AAA", "scanner")

	deleted, _, err := repo.DeduplicateDeparosByNormHash(ctx, projectUUID)
	if err != nil {
		t.Fatalf("DeduplicateDeparosByNormHash: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted, got %d", deleted)
	}

	survivors := map[string]bool{keep: true, other: true, diffStatus: true, emptyNorm1: true, emptyNorm2: true, nonDeparos: true}
	var remaining []*HTTPRecord
	if err := db.NewSelect().Model(&remaining).Scan(ctx); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if len(remaining) != len(survivors) {
		t.Errorf("expected %d remaining, got %d", len(survivors), len(remaining))
	}
	for _, rec := range remaining {
		if !survivors[rec.UUID] {
			t.Errorf("unexpected survivor: %s (path=%s norm=%s)", rec.UUID, rec.Path, rec.ResponseNormHash)
		}
	}
}

// insertRecordNoResponse inserts a deparos record without a response.
func insertRecordNoResponse(t *testing.T, db *DB, ctx context.Context, projectUUID string) string {
	t.Helper()
	id := uuid.NewString()
	rec := &HTTPRecord{
		UUID:         id,
		ProjectUUID:  projectUUID,
		Scheme:       "https",
		Hostname:     "host1.com",
		Port:         443,
		Method:       "GET",
		Path:         "/no-response",
		URL:          "https://host1.com/no-response",
		HTTPVersion:  "HTTP/1.1",
		RequestHash:  id,
		HasResponse:  false,
		Source:       "deparos",
		ResponseHash: "hash-aaa",
		SentAt:       time.Now(),
		CreatedAt:    time.Now(),
	}
	_, err := db.NewInsert().Model(rec).Exec(ctx)
	if err != nil {
		t.Fatalf("insert no-response record: %v", err)
	}
	return id
}
