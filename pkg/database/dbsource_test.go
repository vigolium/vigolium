package database

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func insertTestRecordsWithHost(t *testing.T, repo *Repository, host string, n int) []string {
	t.Helper()
	ctx := context.Background()
	uuids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := fmt.Sprintf("GET /endpoint/%d HTTP/1.1\r\nHost: %s\r\n\r\n", i, host)
		rr, err := httpmsg.ParseRawRequest(raw)
		if err != nil {
			t.Fatalf("ParseRawRequest: %v", err)
		}
		resp := httpmsg.NewHttpResponse([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":%d}", i)))
		rr = rr.WithResponse(resp)
		recordUUID, err := repo.SaveRecord(ctx, rr, "test", DefaultProjectUUID)
		if err != nil {
			t.Fatalf("SaveRecord[%d]: %v", i, err)
		}
		uuids = append(uuids, recordUUID)
	}
	return uuids
}

func createTestScan(t *testing.T, repo *Repository) string {
	t.Helper()
	ctx := context.Background()
	scanUUID := uuid.New().String()
	err := repo.CreateScan(ctx, &Scan{UUID: scanUUID, ProjectUUID: DefaultProjectUUID, Status: "running"})
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	return scanUUID
}

// TestOneShotDBInputSource_ReturnsAllRecords verifies the cursor-based source
// returns every record without skipping any.
func TestOneShotDBInputSource_ReturnsAllRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "cursor.example.com"
	n := 10
	inserted := insertTestRecordsWithHost(t, repo, host, n)

	source := NewOneShotDBInputSource(db, repo, scanUUID).WithHostnames([]string{host})
	var got []string
	for {
		item, err := source.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next(): %v", err)
		}
		got = append(got, item.RecordUUID)
		item.Complete()
	}

	if len(got) != len(inserted) {
		t.Errorf("returned %d records, want %d", len(got), len(inserted))
	}

	// No duplicates
	seen := make(map[string]bool)
	for _, u := range got {
		if seen[u] {
			t.Errorf("duplicate: %s", u)
		}
		seen[u] = true
	}
}

// TestOneShotDBInputSource_TimestampCollision stress-tests cursor when many
// records share the same created_at (second-level precision).
func TestOneShotDBInputSource_TimestampCollision(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "ts.example.com"
	n := 50
	insertTestRecordsWithHost(t, repo, host, n)

	// Verify timestamp collision exists
	var distinct int
	_ = db.NewSelect().TableExpr("http_records").ColumnExpr("COUNT(DISTINCT created_at)").Scan(ctx, &distinct)
	t.Logf("%d records, %d distinct timestamps", n, distinct)

	source := NewOneShotDBInputSource(db, repo, scanUUID).WithHostnames([]string{host})
	count := 0
	for {
		item, err := source.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next()[%d]: %v", count, err)
		}
		item.Complete()
		count++
	}

	if count != n {
		t.Errorf("got %d, want %d", count, n)
	}
}

// TestAuditPhasePattern_SeedThenAudit is the critical regression test.
// Simulates: seed phase advances cursor past all records, then audit phase
// resets cursor and reads all records again.
func TestAuditPhasePattern_SeedThenAudit(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "audit.example.com"
	n := 10
	inserted := insertTestRecordsWithHost(t, repo, host, n)

	// Simulate seed phase: read all records (advances cursor to end)
	seed := NewOneShotDBInputSource(db, repo, scanUUID).WithHostnames([]string{host})
	for {
		item, err := seed.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("seed Next(): %v", err)
		}
		item.Complete()
	}
	_ = seed.Close()

	// Verify cursor is at the end
	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if scan.CursorAt.IsZero() {
		t.Fatal("cursor should be non-zero after seed")
	}

	// THE FIX: reset cursor before audit phase
	if err := repo.ResetScanCursor(ctx, scanUUID); err != nil {
		t.Fatalf("ResetScanCursor: %v", err)
	}

	// Audit phase should get all records
	audit := NewOneShotDBInputSource(db, repo, scanUUID).WithHostnames([]string{host})
	var auditUUIDs []string
	for {
		item, err := audit.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("audit Next(): %v", err)
		}
		auditUUIDs = append(auditUUIDs, item.RecordUUID)
		item.Complete()
	}

	if len(auditUUIDs) != n {
		t.Errorf("audit got %d records, want %d", len(auditUUIDs), n)
	}

	// Verify every record present
	set := make(map[string]bool)
	for _, u := range auditUUIDs {
		set[u] = true
	}
	for _, u := range inserted {
		if !set[u] {
			t.Errorf("audit missing %s", u)
		}
	}
}

// TestResetScanCursor verifies the cursor reset method.
func TestResetScanCursor(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	_ = repo.AdvanceScanCursor(ctx, scanUUID, time.Now(), "some-uuid")
	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if scan.CursorAt.IsZero() {
		t.Fatal("cursor should be non-zero after advance")
	}

	_ = repo.ResetScanCursor(ctx, scanUUID)
	scan, _ = repo.GetScanByUUID(ctx, scanUUID)
	if !scan.CursorAt.IsZero() {
		t.Errorf("cursor_at should be zero after reset, got %v", scan.CursorAt)
	}
}

// TestConcurrentWritesDuringCursorRead verifies cursor-based reading works
// while concurrent writes are happening (the SQLITE_BUSY scenario).
func TestConcurrentWritesDuringCursorRead(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "concurrent.example.com"
	n := 20
	insertTestRecordsWithHost(t, repo, host, n)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			raw := fmt.Sprintf("GET /writer/%d HTTP/1.1\r\nHost: writer.example.com\r\n\r\n", i)
			rr, _ := httpmsg.ParseRawRequest(raw)
			_, _ = repo.SaveRecord(ctx, rr, "writer", DefaultProjectUUID)
			time.Sleep(time.Millisecond)
		}
	}()

	source := NewOneShotDBInputSource(db, repo, scanUUID).WithHostnames([]string{host})
	count := 0
	for {
		item, err := source.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next()[%d]: %v", count, err)
		}
		item.Complete()
		count++
	}

	wg.Wait()

	if count != n {
		t.Errorf("concurrent: got %d, want %d", count, n)
	}
}

func TestOneShotDBInputSource_CursorAdvancesOnlyOnComplete(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "ack.example.com"
	insertTestRecordsWithHost(t, repo, host, 2)

	source := NewOneShotDBInputSource(db, repo, scanUUID).WithHostnames([]string{host})
	item, err := source.Next(ctx)
	if err != nil {
		t.Fatalf("Next(): %v", err)
	}

	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if !scan.CursorAt.IsZero() {
		t.Fatalf("cursor advanced before Complete(): %v", scan.CursorAt)
	}

	item.Complete()

	scan, _ = repo.GetScanByUUID(ctx, scanUUID)
	if scan.CursorAt.IsZero() {
		t.Fatal("cursor should advance after Complete()")
	}
}

func TestRiskPrioritizedDBInputSource_DoesNotSkipNonRiskRecords(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	scanUUID := createTestScan(t, repo)

	host := "priority.example.com"
	inserted := insertTestRecordsWithHost(t, repo, host, 5)

	// Make the newest record high risk to force out-of-order processing.
	if err := repo.UpdateRiskScores(ctx, map[string]int{inserted[len(inserted)-1]: 10}); err != nil {
		t.Fatalf("UpdateRiskScores: %v", err)
	}

	source := NewRiskPrioritizedDBInputSource(db, repo, scanUUID).WithHostnames([]string{host})
	var got []string
	for {
		item, err := source.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next(): %v", err)
		}
		got = append(got, item.RecordUUID)
		item.Complete()
	}

	if len(got) != len(inserted) {
		t.Fatalf("got %d records, want %d", len(got), len(inserted))
	}

	seen := make(map[string]bool, len(got))
	for _, uuid := range got {
		seen[uuid] = true
	}
	for _, uuid := range inserted {
		if !seen[uuid] {
			t.Fatalf("missing UUID %s", uuid)
		}
	}

	scan, _ := repo.GetScanByUUID(ctx, scanUUID)
	if scan.ProcessedCount != int64(len(inserted)) {
		t.Fatalf("processed_count=%d, want %d", scan.ProcessedCount, len(inserted))
	}
	remaining, err := repo.CountRecordsAfterCursor(ctx, scan.CursorAt, scan.CursorUUID, host)
	if err != nil {
		t.Fatalf("CountRecordsAfterCursor: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining=%d, want 0", remaining)
	}
}

// TestRecordToHttpRequestResponse_PreservesScheme guards against the bug where
// scan-on-receive re-parsed raw HTTP bytes and defaulted the scheme to http,
// causing https targets to be probed over plain http and producing false
// positives.
func TestRecordToHttpRequestResponse_PreservesScheme(t *testing.T) {
	// Origin-form raw request carries no scheme on the wire.
	raw := []byte("GET /catalog?searchTerm=book HTTP/1.1\r\nHost: ginandjuice.shop\r\n\r\n")

	tests := []struct {
		name     string
		record   *HTTPRecord
		wantProt string
		wantPort int
	}{
		{
			name: "https url preserved",
			record: &HTTPRecord{
				URL:        "https://ginandjuice.shop/catalog?searchTerm=book",
				Scheme:     "https",
				Port:       443,
				RawRequest: raw,
			},
			wantProt: "https",
			wantPort: 443,
		},
		{
			name: "http url preserved",
			record: &HTTPRecord{
				URL:        "http://ginandjuice.shop/catalog?searchTerm=book",
				Scheme:     "http",
				Port:       80,
				RawRequest: raw,
			},
			wantProt: "http",
			wantPort: 80,
		},
		{
			name: "non-standard port preserved from url",
			record: &HTTPRecord{
				URL:        "https://ginandjuice.shop:8443/catalog?searchTerm=book",
				Scheme:     "https",
				Port:       8443,
				RawRequest: raw,
			},
			wantProt: "https",
			wantPort: 8443,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := recordToHttpRequestResponse(tt.record)
			if err != nil {
				t.Fatalf("recordToHttpRequestResponse: %v", err)
			}
			if got := rr.Service().Protocol(); got != tt.wantProt {
				t.Errorf("Protocol = %q, want %q", got, tt.wantProt)
			}
			if got := rr.Service().Port(); got != tt.wantPort {
				t.Errorf("Port = %d, want %d", got, tt.wantPort)
			}
		})
	}
}
