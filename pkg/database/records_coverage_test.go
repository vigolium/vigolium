package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestSaveRecordBatchAndGetByUUIDs(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	var rrs []*httpmsg.HttpRequestResponse
	for i := 0; i < 4; i++ {
		rrs = append(rrs, makeTestRequest(100+i))
	}

	uuids, err := repo.SaveRecordBatch(ctx, rrs, "batch", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecordBatch: %v", err)
	}
	if len(uuids) != 4 {
		t.Fatalf("SaveRecordBatch returned %d uuids, want 4", len(uuids))
	}

	got, err := repo.GetRecordsByUUIDs(ctx, uuids)
	if err != nil {
		t.Fatalf("GetRecordsByUUIDs: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("GetRecordsByUUIDs = %d, want 4", len(got))
	}

	// Empty inputs are no-ops.
	if u, err := repo.SaveRecordBatch(ctx, nil, "batch", DefaultProjectUUID); err != nil || u != nil {
		t.Errorf("SaveRecordBatch(nil) = %v, %v", u, err)
	}
	if g, err := repo.GetRecordsByUUIDs(ctx, nil); err != nil || g != nil {
		t.Errorf("GetRecordsByUUIDs(nil) = %v, %v", g, err)
	}
}

func TestRecordWriterSaveRecordAndBatch(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	w := NewRecordWriter(repo, RecordWriterConfig{})
	defer w.Close()

	// SaveRecord delegates to Write.
	u, err := w.SaveRecord(ctx, makeTestRequest(900), "writer", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("RecordWriter.SaveRecord: %v", err)
	}
	if u == "" {
		t.Error("RecordWriter.SaveRecord returned empty UUID")
	}

	// SaveRecordBatch writes each record.
	var batch []*httpmsg.HttpRequestResponse
	for i := 0; i < 3; i++ {
		batch = append(batch, makeTestRequest(910+i))
	}
	uuids, err := w.SaveRecordBatch(ctx, batch, "writer", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("RecordWriter.SaveRecordBatch: %v", err)
	}
	if len(uuids) != 3 {
		t.Errorf("RecordWriter.SaveRecordBatch returned %d uuids, want 3", len(uuids))
	}
}

func TestGetRecordsByHostnameAndUnprobed(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordP(t, repo, DefaultProjectUUID, "GET", "host.example.com", "/a", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "host.example.com", "/b", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "other.example.com", "/c", 200)

	byHost, err := repo.GetRecordsByHostname(ctx, DefaultProjectUUID, "host.example.com", 10)
	if err != nil {
		t.Fatalf("GetRecordsByHostname: %v", err)
	}
	if len(byHost) != 2 {
		t.Errorf("GetRecordsByHostname = %d, want 2", len(byHost))
	}

	// Insert an unprobed record (no response).
	rr, _ := httpmsg.ParseRawRequest("GET /noresp HTTP/1.1\r\nHost: probe.example.com\r\n\r\n")
	if _, err := repo.SaveRecord(ctx, rr, "probe-src", DefaultProjectUUID); err != nil {
		t.Fatalf("SaveRecord unprobed: %v", err)
	}
	unprobed, err := repo.GetUnprobedRecordsBySource(ctx, DefaultProjectUUID, "probe-src", "probe.example.com", 10)
	if err != nil {
		t.Fatalf("GetUnprobedRecordsBySource: %v", err)
	}
	if len(unprobed) != 1 {
		t.Errorf("GetUnprobedRecordsBySource = %d, want 1", len(unprobed))
	}
}

func TestGetRelatedRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Source record /users/123 → template /users/*.
	srcUUID := insertRecordP(t, repo, DefaultProjectUUID, "GET", "api.example.com", "/users/123", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "api.example.com", "/users/456", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "api.example.com", "/users/789", 200)
	// Different depth — should be excluded.
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "api.example.com", "/users/123/posts", 200)

	related, err := repo.GetRelatedRecords(ctx, srcUUID, 10)
	if err != nil {
		t.Fatalf("GetRelatedRecords: %v", err)
	}
	if len(related) != 2 {
		t.Errorf("GetRelatedRecords = %d, want 2 (same-depth siblings, excluding source)", len(related))
	}
	for _, r := range related {
		if r.UUID == srcUUID {
			t.Error("GetRelatedRecords returned the source record itself")
		}
	}
}

func TestUpdateRecordAnnotationsAndRemarks(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	u := insertRecordP(t, repo, DefaultProjectUUID, "GET", "annot.example.com", "/x", 200)

	score := 42
	if err := repo.UpdateRecordAnnotations(ctx, u, &score, []string{"interesting"}); err != nil {
		t.Fatalf("UpdateRecordAnnotations: %v", err)
	}
	rec, _ := repo.GetRecordByUUID(ctx, u)
	if rec.RiskScore != 42 {
		t.Errorf("risk score = %d, want 42", rec.RiskScore)
	}
	if len(rec.Remarks) != 1 || rec.Remarks[0] != "interesting" {
		t.Errorf("remarks = %v, want [interesting]", rec.Remarks)
	}

	// No fields set is a no-op (no error).
	if err := repo.UpdateRecordAnnotations(ctx, u, nil, nil); err != nil {
		t.Errorf("UpdateRecordAnnotations(no-op): %v", err)
	}

	// Missing record errors when there are fields to set.
	if err := repo.UpdateRecordAnnotations(ctx, "no-such-uuid", &score, nil); err == nil {
		t.Error("UpdateRecordAnnotations on missing record should error")
	}

	// AppendRemarks merges and dedupes.
	if err := repo.AppendRemarks(ctx, map[string][]string{u: {"interesting", "new-remark"}}); err != nil {
		t.Fatalf("AppendRemarks: %v", err)
	}
	rec, _ = repo.GetRecordByUUID(ctx, u)
	if len(rec.Remarks) != 2 {
		t.Errorf("after AppendRemarks remarks = %v, want 2 unique", rec.Remarks)
	}

	// Empty map no-op.
	if err := repo.AppendRemarks(ctx, nil); err != nil {
		t.Errorf("AppendRemarks(nil): %v", err)
	}
}

func TestGetRecordsWithResponseBody(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		insertRecordP(t, repo, DefaultProjectUUID, "GET", "body.example.com", fmt.Sprintf("/p%d", i), 200)
	}

	recs, err := repo.GetRecordsWithResponseBody(ctx, DefaultProjectUUID, "", 10)
	if err != nil {
		t.Fatalf("GetRecordsWithResponseBody: %v", err)
	}
	if len(recs) != 3 {
		t.Errorf("GetRecordsWithResponseBody = %d, want 3", len(recs))
	}

	// Cursor pagination: afterUUID skips earlier records.
	page, err := repo.GetRecordsWithResponseBody(ctx, DefaultProjectUUID, recs[0].UUID, 10)
	if err != nil {
		t.Fatalf("GetRecordsWithResponseBody (cursor): %v", err)
	}
	if len(page) != 2 {
		t.Errorf("cursor page = %d, want 2", len(page))
	}
}

func TestDeleteRecord(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	u := insertRecordP(t, repo, DefaultProjectUUID, "GET", "del.example.com", "/x", 200)
	if err := repo.DeleteRecord(ctx, u); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if _, err := repo.GetRecordByUUID(ctx, u); err == nil {
		t.Error("GetRecordByUUID should fail after delete")
	}
}

func TestGetDistinctHostsAndPaths(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordP(t, repo, DefaultProjectUUID, "GET", "h1.example.com", "/a", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "h1.example.com", "/b", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "h2.example.com", "/a", 200)

	hosts, err := repo.GetDistinctHosts(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("GetDistinctHosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("GetDistinctHosts = %d, want 2", len(hosts))
	}

	paths, err := repo.GetDistinctPaths(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("GetDistinctPaths: %v", err)
	}
	if len(paths) != 3 {
		t.Errorf("GetDistinctPaths = %d, want 3", len(paths))
	}
}

func TestUpdateRecordResponse(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Insert an unprobed record.
	rr, _ := httpmsg.ParseRawRequest("GET /replace HTTP/1.1\r\nHost: replace.example.com\r\n\r\n")
	u, err := repo.SaveRecord(ctx, rr, "ingest", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}

	update := &RecordResponseUpdate{
		StatusCode:            201,
		StatusPhrase:          "Created",
		ResponseContentType:   "application/json",
		ResponseContentLength: 12,
		RawResponse:           []byte("HTTP/1.1 201 Created\r\n\r\n{\"ok\":true}"),
		ResponseHash:          "abc123",
		ResponseTimeMs:        15,
	}
	if err := repo.UpdateRecordResponse(ctx, u, update); err != nil {
		t.Fatalf("UpdateRecordResponse: %v", err)
	}

	rec, _ := repo.GetRecordByUUID(ctx, u)
	if rec.StatusCode != 201 || !rec.HasResponse {
		t.Errorf("UpdateRecordResponse did not apply: status=%d hasResp=%v", rec.StatusCode, rec.HasResponse)
	}

	// Missing record errors.
	if err := repo.UpdateRecordResponse(ctx, "no-such", update); err == nil {
		t.Error("UpdateRecordResponse on missing record should error")
	}
}

func TestDeduplicateRecordsBySource(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Two records sharing identical (hostname, method, status, content-length, hash)
	// but different paths. Build directly so the response_hash collides.
	makeDup := func(path string) *HTTPRecord {
		return &HTTPRecord{
			UUID:                  path + "-uuid",
			ProjectUUID:           DefaultProjectUUID,
			Scheme:                "https",
			Hostname:              "dup.example.com",
			Port:                  443,
			Method:                "GET",
			Path:                  path,
			URL:                   "https://dup.example.com" + path,
			HTTPVersion:           "HTTP/1.1",
			RequestHash:           "reqhash-" + path,
			StatusCode:            200,
			ResponseContentLength: 100,
			ResponseHash:          "same-response-hash",
			HasResponse:           true,
			Source:                "deparos",
		}
	}
	if _, err := repo.SaveRecordsBatch(ctx, []*HTTPRecord{
		makeDup("/short"),
		makeDup("/longer/path"),
	}); err != nil {
		t.Fatalf("SaveRecordsBatch: %v", err)
	}

	deleted, err := repo.DeduplicateRecordsBySource(ctx, DefaultProjectUUID, "deparos")
	if err != nil {
		t.Fatalf("DeduplicateRecordsBySource: %v", err)
	}
	if deleted != 1 {
		t.Errorf("DeduplicateRecordsBySource deleted %d, want 1", deleted)
	}

	// The shortest path survives.
	remaining, _ := db.NewSelect().Model((*HTTPRecord)(nil)).Where("hostname = ?", "dup.example.com").Count(ctx)
	if remaining != 1 {
		t.Errorf("remaining records = %d, want 1", remaining)
	}

	// DeduplicateDeparosRecords delegates to the same path; no more dups.
	again, err := repo.DeduplicateDeparosRecords(ctx, DefaultProjectUUID)
	if err != nil {
		t.Fatalf("DeduplicateDeparosRecords: %v", err)
	}
	if again != 0 {
		t.Errorf("second dedup deleted %d, want 0", again)
	}
}
