package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// newTestDB creates an in-memory SQLite database with schema for testing.
func newTestDB(t *testing.T) *DB {
	t.Helper()

	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqldb.SetMaxOpenConns(4)
	sqldb.SetMaxIdleConns(4)

	bunDB := bun.NewDB(sqldb, sqlitedialect.New())
	db := &DB{DB: bunDB, driver: "sqlite"}

	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	t.Cleanup(func() { _ = db.Close() })
	return db
}

// makeTestRequest builds a minimal HttpRequestResponse for testing.
func makeTestRequest(i int) *httpmsg.HttpRequestResponse {
	raw := fmt.Sprintf("GET /path/%d HTTP/1.1\r\nHost: example.com\r\n\r\n", i)
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		panic(fmt.Sprintf("makeTestRequest(%d): %v", i, err))
	}
	return rr
}

func TestRecordWriter_10000ConcurrentWrites(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	writer := NewRecordWriter(repo, RecordWriterConfig{
		BufferSize:    8192,
		BatchSize:     200,
		FlushInterval: 25 * time.Millisecond,
		Shards:        1, // Single shard for in-memory SQLite test
	})
	defer writer.Close()

	const total = 10000

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var successCount atomic.Int64
	var errorCount atomic.Int64
	uuids := make([]string, total)
	errs := make([]error, total)

	start := time.Now()

	// Fire all 10000 writes concurrently
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rr := makeTestRequest(idx)
			uuid, err := writer.Write(ctx, rr, "test", "")
			if err != nil {
				errorCount.Add(1)
				errs[idx] = err
			} else {
				successCount.Add(1)
				uuids[idx] = uuid
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// Report metrics
	metrics := writer.Metrics()
	t.Logf("Completed %d writes in %v", total, elapsed)
	t.Logf("Success: %d, Errors: %d", successCount.Load(), errorCount.Load())
	t.Logf("Metrics: enqueued=%d flushed=%d batches=%d flush_errors=%d",
		metrics.Enqueued, metrics.Flushed, metrics.BatchCount, metrics.FlushErrors)
	t.Logf("Throughput: %.0f records/sec", float64(total)/elapsed.Seconds())

	// Print first few errors if any
	if errorCount.Load() > 0 {
		printed := 0
		for i, err := range errs {
			if err != nil && printed < 5 {
				t.Errorf("Write %d failed: %v", i, err)
				printed++
			}
		}
	}

	// Assertions
	if errorCount.Load() > 0 {
		t.Fatalf("Expected 0 errors, got %d", errorCount.Load())
	}

	// Verify all records exist in the database
	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("Count query failed: %v", err)
	}
	if count != total {
		t.Fatalf("Expected %d records in DB, got %d", total, count)
	}

	// Verify all UUIDs are unique and non-empty
	seen := make(map[string]bool, total)
	for i, uuid := range uuids {
		if uuid == "" {
			t.Fatalf("UUID %d is empty", i)
		}
		if seen[uuid] {
			t.Fatalf("Duplicate UUID at index %d: %s", i, uuid)
		}
		seen[uuid] = true
	}

	// Verify flush metrics match
	if metrics.Flushed != total {
		t.Errorf("Expected metrics.Flushed=%d, got %d", total, metrics.Flushed)
	}
	if metrics.FlushErrors != 0 {
		t.Errorf("Expected 0 flush errors, got %d", metrics.FlushErrors)
	}
}

func TestRecordWriter_DirectRepoComparison(t *testing.T) {
	// This test demonstrates the problem: direct SaveRecord calls
	// with concurrent writers hit SQLITE_BUSY on file-backed SQLite.
	// RecordWriter serializes them through one goroutine.

	db := newTestDB(t)
	repo := NewRepository(db)

	const total = 500

	ctx := context.Background()

	// --- Phase 1: Direct concurrent SaveRecord (the old way) ---
	var wg sync.WaitGroup
	var directErrors atomic.Int64

	start := time.Now()
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rr := makeTestRequest(idx)
			if _, err := repo.SaveRecord(ctx, rr, "direct", ""); err != nil {
				directErrors.Add(1)
			}
		}(i)
	}
	wg.Wait()
	directElapsed := time.Since(start)
	t.Logf("Direct SaveRecord: %d writes in %v (errors: %d, %.0f rps)",
		total, directElapsed, directErrors.Load(), float64(total)/directElapsed.Seconds())

	// --- Phase 2: RecordWriter (the new way) ---
	writer := NewRecordWriter(repo, RecordWriterConfig{
		BufferSize:    4096,
		BatchSize:     100,
		FlushInterval: 25 * time.Millisecond,
		Shards:        1, // Single shard for in-memory SQLite test
	})

	var writerErrors atomic.Int64
	start = time.Now()
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rr := makeTestRequest(idx + total) // different paths
			if _, err := writer.Write(ctx, rr, "batched", ""); err != nil {
				writerErrors.Add(1)
			}
		}(i)
	}
	wg.Wait()
	writer.Close()
	writerElapsed := time.Since(start)

	t.Logf("RecordWriter:      %d writes in %v (errors: %d, %.0f rps)",
		total, writerElapsed, writerErrors.Load(), float64(total)/writerElapsed.Seconds())

	if writerErrors.Load() > 0 {
		t.Errorf("RecordWriter had %d errors", writerErrors.Load())
	}

	// Both phases should have written their records
	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("Count query failed: %v", err)
	}
	expectedMin := total // at least the RecordWriter records should be there
	if count < expectedMin {
		t.Errorf("Expected at least %d records, got %d", expectedMin, count)
	}
	t.Logf("Total records in DB: %d", count)
}

func TestRecordWriter_GracefulShutdown(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	writer := NewRecordWriter(repo, RecordWriterConfig{
		BufferSize:    4096,
		BatchSize:     500, // large batch — most records will be pending at shutdown
		FlushInterval: 10 * time.Second, // long interval — only shutdown flush matters
		Shards:        1,                // Single shard for in-memory SQLite test
	})

	const total = 1000
	ctx := context.Background()

	var wg sync.WaitGroup
	var errors atomic.Int64

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rr := makeTestRequest(idx)
			if _, err := writer.Write(ctx, rr, "shutdown-test", ""); err != nil {
				errors.Add(1)
			}
		}(i)
	}

	// Close while writes are in-flight — should flush all buffered records
	go func() {
		time.Sleep(10 * time.Millisecond)
		writer.Close()
	}()

	wg.Wait()

	if errors.Load() > 0 {
		t.Logf("Note: %d writes returned errors (expected if closed before send)", errors.Load())
	}

	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("Count query failed: %v", err)
	}
	t.Logf("Records persisted after shutdown: %d / %d", count, total)

	// Even with early close, the majority should be persisted
	if count == 0 {
		t.Fatal("No records persisted — shutdown drain is broken")
	}
}

func TestRecordWriter_SmallBatchConfig(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	// Tiny batches to stress the flush path
	writer := NewRecordWriter(repo, RecordWriterConfig{
		BufferSize:    64,
		BatchSize:     5,
		FlushInterval: 5 * time.Millisecond,
		Shards:        1, // Single shard for in-memory SQLite test
	})
	defer writer.Close()

	const total = 500
	ctx := context.Background()

	var wg sync.WaitGroup
	var errors atomic.Int64

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rr := makeTestRequest(idx)
			if _, err := writer.Write(ctx, rr, "small-batch", ""); err != nil {
				errors.Add(1)
			}
		}(i)
	}
	wg.Wait()

	metrics := writer.Metrics()
	t.Logf("Batches: %d, Flushed: %d, Errors: %d", metrics.BatchCount, metrics.Flushed, metrics.FlushErrors)

	if errors.Load() > 0 {
		t.Fatalf("Expected 0 errors, got %d", errors.Load())
	}

	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("Count query failed: %v", err)
	}
	if count != total {
		t.Fatalf("Expected %d records, got %d", total, count)
	}

	// With batch size 5, we should have at least total/5 batches
	if metrics.BatchCount < int64(total/5)/2 { // some tolerance for time-based flushes
		t.Errorf("Expected at least %d batches, got %d", total/5/2, metrics.BatchCount)
	}
}

func TestSaveRecordsBatch(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)

	ctx := context.Background()

	// Create a batch of records
	const batchSize = 50
	records := make([]*HTTPRecord, batchSize)
	for i := 0; i < batchSize; i++ {
		rr := makeTestRequest(i)
		rec := &HTTPRecord{}
		if err := rec.FromHttpRequestResponse(rr); err != nil {
			t.Fatalf("Convert %d: %v", i, err)
		}
		rec.Source = "batch-test"
		records[i] = rec
	}

	uuids, err := repo.SaveRecordsBatch(ctx, records)
	if err != nil {
		t.Fatalf("SaveRecordsBatch failed: %v", err)
	}
	if len(uuids) != batchSize {
		t.Fatalf("Expected %d UUIDs, got %d", batchSize, len(uuids))
	}

	// Verify count
	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != batchSize {
		t.Fatalf("Expected %d records, got %d", batchSize, count)
	}

	// Verify UUIDs are unique
	seen := make(map[string]bool, batchSize)
	for _, uuid := range uuids {
		if uuid == "" {
			t.Fatal("Empty UUID in batch result")
		}
		if seen[uuid] {
			t.Fatalf("Duplicate UUID: %s", uuid)
		}
		seen[uuid] = true
	}
}

// TestRecordWriter_WithFileDB tests against a file-backed SQLite to match
// the real-world scenario where SQLITE_BUSY errors occur.
func TestRecordWriter_WithFileDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping file-backed DB test in short mode")
	}

	tmpDir := t.TempDir()
	dbCfg := config.DefaultDatabaseConfig()
	dbCfg.SQLite.Path = tmpDir + "/test.sqlite"
	dbCfg.SQLite.BusyTimeout = 5000
	dbCfg.SQLite.MaxOpenConns = 4

	db, err := NewDB(dbCfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}

	repo := NewRepository(db)
	writer := NewRecordWriter(repo, RecordWriterConfig{
		BufferSize:    8192,
		BatchSize:     200,
		FlushInterval: 25 * time.Millisecond,
		Shards:        1, // Single shard for in-memory SQLite test
	})
	defer writer.Close()

	const total = 10000
	ctx := context.Background()

	var wg sync.WaitGroup
	var errors atomic.Int64

	start := time.Now()
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rr := makeTestRequest(idx)
			if _, err := writer.Write(ctx, rr, "file-db-test", ""); err != nil {
				errors.Add(1)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	metrics := writer.Metrics()
	t.Logf("File-backed DB: %d writes in %v (%.0f rps)", total, elapsed, float64(total)/elapsed.Seconds())
	t.Logf("Metrics: batches=%d flushed=%d errors=%d", metrics.BatchCount, metrics.Flushed, metrics.FlushErrors)

	if errors.Load() > 0 {
		t.Fatalf("Expected 0 errors, got %d", errors.Load())
	}

	count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != total {
		t.Fatalf("Expected %d records, got %d", total, count)
	}
}
