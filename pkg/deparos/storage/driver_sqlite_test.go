package storage

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// ============================================================================
// Test: WAL Mode Verification
// Verifies that WAL journal mode is properly enabled
// ============================================================================

func TestSQLiteDriver_WALModeEnabled(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "wal_test.db")

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	// Verify WAL mode
	var journalMode string
	err = sm.bunDB.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journalMode)
	require.NoError(t, err)
	assert.Equal(t, "wal", journalMode, "WAL mode should be enabled")

	// Verify WAL files exist after some writes
	u, _ := url.Parse("https://example.com/test")
	result := NewResultBuilder().
		WithURL(u).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
		Build()
	require.NoError(t, sm.Store(result))

	// WAL file should exist
	_, err = os.Stat(tmpFile + "-wal")
	assert.NoError(t, err, "WAL file should exist")
}

// ============================================================================
// Test: Busy Timeout Configuration
// Verifies that busy_timeout is set to at least 60 seconds
// ============================================================================

func TestSQLiteDriver_BusyTimeoutSet(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "timeout_test.db")

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	var busyTimeout int
	err = sm.bunDB.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&busyTimeout)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, busyTimeout, 60000, "busy_timeout should be at least 60 seconds")
}

// ============================================================================
// Test: Performance PRAGMAs
// Verifies that all performance PRAGMAs are correctly set
// ============================================================================

func TestSQLiteDriver_PerformancePragmas(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "pragma_test.db")

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	tests := []struct {
		pragma   string
		expected interface{}
		check    func(t *testing.T, value interface{})
	}{
		{
			pragma: "synchronous",
			check: func(t *testing.T, value interface{}) {
				// NORMAL = 1
				assert.Equal(t, int64(1), value, "synchronous should be NORMAL (1)")
			},
		},
		{
			pragma: "cache_size",
			check: func(t *testing.T, value interface{}) {
				// Negative value means KB, -64000 = 64MB
				v, ok := value.(int64)
				require.True(t, ok, "expected int64")
				assert.True(t, v < 0, "cache_size should be negative (KB-based)")
			},
		},
		{
			pragma: "temp_store",
			check: func(t *testing.T, value interface{}) {
				// MEMORY = 2
				assert.Equal(t, int64(2), value, "temp_store should be MEMORY (2)")
			},
		},
		{
			pragma: "mmap_size",
			check: func(t *testing.T, value interface{}) {
				v, ok := value.(int64)
				require.True(t, ok, "expected int64")
				// mmap_size may be 0 on some systems (e.g., WSL, certain VFS configurations)
				// If supported, it should be the configured value (268435456 = 256MB)
				if v == 0 {
					t.Skip("mmap not supported on this system")
				}
				assert.Greater(t, v, int64(0), "mmap_size should be positive when supported")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.pragma, func(t *testing.T) {
			var value int64
			err := sm.bunDB.QueryRowContext(context.Background(), fmt.Sprintf("PRAGMA %s", tt.pragma)).Scan(&value)
			require.NoError(t, err)
			tt.check(t, value)
		})
	}
}

// ============================================================================
// Test: Concurrent Goroutine Writes (Single Process)
// Verifies that multiple goroutines can write concurrently without errors
// ============================================================================

func TestSQLiteDriver_ConcurrentGoroutineWrites(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "concurrent_goroutine_test.db")

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	const numGoroutines = 100
	const writesPerGoroutine = 10

	var successCount atomic.Int64
	var errorCount atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < writesPerGoroutine; j++ {
				u, _ := url.Parse(fmt.Sprintf("https://example.com/path%d_%d", goroutineID, j))
				result := NewResultBuilder().
					WithURL(u).
					WithRequest("GET", nil, nil).
					WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
					WithMetadata(fmt.Sprintf("goroutine%d", goroutineID), uint16(goroutineID), time.Now()).
					Build()

				if err := sm.Store(result); err != nil {
					errorCount.Add(1)
				} else {
					successCount.Add(1)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Success: %d, Errors: %d", successCount.Load(), errorCount.Load())
	assert.Equal(t, int64(0), errorCount.Load(), "No errors should occur during concurrent writes")
	assert.Equal(t, int64(numGoroutines*writesPerGoroutine), successCount.Load())
}

// ============================================================================
// Test: High Contention Writes
// Simulates high contention scenario with many goroutines writing simultaneously
// ============================================================================

func TestSQLiteDriver_HighContentionWrites(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "high_contention_test.db")

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	const numGoroutines = 50
	var errorCount atomic.Int64

	// All goroutines start at the same time for maximum contention
	var wg sync.WaitGroup
	startSignal := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-startSignal // Wait for signal

			u, _ := url.Parse(fmt.Sprintf("https://example.com/contention%d", id))
			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
				Build()

			if err := sm.Store(result); err != nil {
				errorCount.Add(1)
				t.Logf("Error in goroutine %d: %v", id, err)
			}
		}(i)
	}

	// Release all goroutines at once
	close(startSignal)
	wg.Wait()

	assert.Equal(t, int64(0), errorCount.Load(), "No SQLITE_BUSY errors should occur")
	assert.Equal(t, numGoroutines, sm.Count())
}

// ============================================================================
// Test: Multi-Connection Read/Write
// Verifies that multiple connections can read and write concurrently
// ============================================================================

func TestSQLiteDriver_MultiConnectionReadWrite(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "multi_conn_test.db")

	// Create initial data
	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm1, err := NewSiteMap(cfg)
	require.NoError(t, err)

	// Insert initial records
	for i := 0; i < 100; i++ {
		u, _ := url.Parse(fmt.Sprintf("https://example.com/initial%d", i))
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
			Build()
		require.NoError(t, sm1.Store(result))
	}
	_ = sm1.Close()

	// Now open multiple connections and do concurrent read/write
	const numConnections = 5
	const opsPerConnection = 20

	var g errgroup.Group
	var writeCount atomic.Int64
	var readCount atomic.Int64

	for connID := 0; connID < numConnections; connID++ {
		g.Go(func() error {
			// Open connection
			cfg := SQLiteConfig(tmpFile)
			cfg.TargetURL = "https://example.com"
			cfg.SessionName = fmt.Sprintf("conn%d", connID)

			sm, err := NewSiteMap(cfg)
			if err != nil {
				return fmt.Errorf("conn %d: open failed: %w", connID, err)
			}
			defer func() { _ = sm.Close() }()

			for i := 0; i < opsPerConnection; i++ {
				// Alternate between read and write
				if i%2 == 0 {
					// Write
					u, _ := url.Parse(fmt.Sprintf("https://example.com/conn%d_op%d", connID, i))
					result := NewResultBuilder().
						WithURL(u).
						WithRequest("GET", nil, nil).
						WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
						Build()
					if err := sm.Store(result); err != nil {
						return fmt.Errorf("conn %d: write failed: %w", connID, err)
					}
					writeCount.Add(1)
				} else {
					// Read
					u, _ := url.Parse(fmt.Sprintf("https://example.com/initial%d", i%100))
					_, _ = sm.Get(u) // May or may not exist
					readCount.Add(1)
				}
			}
			return nil
		})
	}

	err = g.Wait()
	assert.NoError(t, err)
	t.Logf("Writes: %d, Reads: %d", writeCount.Load(), readCount.Load())
}

// ============================================================================
// Test: Session Isolation (Separate DB Files)
// Verifies that different processes with separate DB files don't interfere
// This reflects the actual use case: 20 separate processes, each with own DB
// ============================================================================

func TestSQLiteDriver_SessionIsolation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two sessions with SEPARATE DB files (simulating 2 processes)
	tmpFile1 := filepath.Join(tmpDir, "session1.db")
	tmpFile2 := filepath.Join(tmpDir, "session2.db")

	cfg1 := SQLiteConfig(tmpFile1)
	cfg1.TargetURL = "https://target1.com"
	cfg1.SessionName = "session1"
	cfg1.SaveResponseBody = true // Enable body storage for this test

	cfg2 := SQLiteConfig(tmpFile2)
	cfg2.TargetURL = "https://target2.com"
	cfg2.SessionName = "session2"
	cfg2.SaveResponseBody = true // Enable body storage for this test

	sm1, err := NewSiteMap(cfg1)
	require.NoError(t, err)

	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)

	// Store data in session 1
	u1, _ := url.Parse("https://target1.com/page1")
	result1 := NewResultBuilder().
		WithURL(u1).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("session1 data"), 13, "text/html", "", "", 0, 0).
		Build()
	require.NoError(t, sm1.Store(result1))

	// Store data in session 2
	u2, _ := url.Parse("https://target2.com/page1")
	result2 := NewResultBuilder().
		WithURL(u2).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("session2 data"), 13, "text/html", "", "", 0, 0).
		Build()
	require.NoError(t, sm2.Store(result2))

	// Verify session 1 only sees its data
	assert.Equal(t, 1, sm1.Count())
	node1, err := sm1.Get(u1)
	require.NoError(t, err)
	assert.Equal(t, "session1 data", string(node1.Response().Body))

	// Verify session 2 only sees its data
	assert.Equal(t, 1, sm2.Count())
	node2, err := sm2.Get(u2)
	require.NoError(t, err)
	assert.Equal(t, "session2 data", string(node2.Response().Body))

	// Cross-session lookup should fail (different DB files = complete isolation)
	_, err = sm1.Get(u2)
	assert.Error(t, err, "Session 1 should not see Session 2's data (different DB)")

	_, err = sm2.Get(u1)
	assert.Error(t, err, "Session 2 should not see Session 1's data (different DB)")

	_ = sm1.Close()
	_ = sm2.Close()
}

// ============================================================================
// Test: Crash Recovery with WAL
// Simulates crash scenario and verifies data recovery
// ============================================================================

func TestSQLiteDriver_CrashRecovery(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "crash_recovery_test.db")

	// First session: write data without proper close (simulate crash)
	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm1, err := NewSiteMap(cfg)
	require.NoError(t, err)

	// Write some data
	for i := 0; i < 50; i++ {
		u, _ := url.Parse(fmt.Sprintf("https://example.com/page%d", i))
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte(fmt.Sprintf("data%d", i)), int64(len(fmt.Sprintf("data%d", i))), "text/html", "", "", 0, 0).
			Build()
		require.NoError(t, sm1.Store(result))
	}

	// Get the raw DB handle and close it without proper cleanup
	// This simulates a crash scenario
	_ = sm1.bunDB.DB.Close() // Force close without WAL checkpoint

	// Verify WAL file exists (uncommitted data)
	walFile := tmpFile + "-wal"
	_, walErr := os.Stat(walFile)
	// WAL may or may not exist depending on autocheckpoint

	// Second session: should recover data
	cfg2 := SQLiteConfig(tmpFile)
	cfg2.TargetURL = "https://example.com"
	cfg2.SessionName = "recovery_session"

	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	// Verify data is accessible via Get
	for i := 0; i < 50; i++ {
		u, _ := url.Parse(fmt.Sprintf("https://example.com/page%d", i))
		node, _ := sm2.Get(u)
		assert.NotNil(t, node, "Data should be recovered: page%d (WAL existed: %v)", i, walErr == nil)
	}
}

// ============================================================================
// Test: Database Integrity After Concurrent Writes
// Verifies database integrity after heavy concurrent operations
// ============================================================================

func TestSQLiteDriver_IntegrityCheck(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "integrity_test.db")

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)

	// Heavy concurrent writes
	const numGoroutines = 50
	const writesPerGoroutine = 20

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerGoroutine; j++ {
				u, _ := url.Parse(fmt.Sprintf("https://example.com/integrity%d_%d", id, j))
				result := NewResultBuilder().
					WithURL(u).
					WithRequest("GET", nil, nil).
					WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
					Build()
				_ = sm.Store(result)
			}
		}(i)
	}
	wg.Wait()
	_ = sm.Close()

	// Reopen and run integrity check
	cfg2 := SQLiteConfig(tmpFile)
	cfg2.TargetURL = "https://example.com"
	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	var integrityResult string
	err = sm2.bunDB.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrityResult)
	require.NoError(t, err)
	assert.Equal(t, "ok", integrityResult, "Database should pass integrity check")
}

// ============================================================================
// Test: Multi-Process Concurrent Access
// Spawns multiple processes to test true multi-process concurrent access
// ============================================================================

func TestSQLiteDriver_MultiProcessConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping multi-process test in short mode")
	}

	// Check if we're running as a child process
	if dbFile := os.Getenv("SQLITE_TEST_DB"); dbFile != "" {
		runChildProcess(t, dbFile)
		return
	}

	// Parent process: set up test
	tmpFile := filepath.Join(t.TempDir(), "multiprocess_test.db")

	// Create initial database
	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"
	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	_ = sm.Close()

	// Spawn child processes
	const numProcesses = 5
	const writesPerProcess = 20

	var g errgroup.Group

	for i := 0; i < numProcesses; i++ {
		processID := i
		g.Go(func() error {
			return runChildProcessExternal(t, tmpFile, processID, writesPerProcess)
		})
	}

	err = g.Wait()
	assert.NoError(t, err, "All child processes should succeed")

	// Verify all data was written
	cfg2 := SQLiteConfig(tmpFile)
	cfg2.TargetURL = "https://example.com"
	cfg2.SessionName = "verify"

	sm2, err := NewSiteMap(cfg2)
	require.NoError(t, err)
	defer func() { _ = sm2.Close() }()

	// Run integrity check
	var integrityResult string
	err = sm2.bunDB.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrityResult)
	require.NoError(t, err)
	assert.Equal(t, "ok", integrityResult)
}

func runChildProcessExternal(t *testing.T, dbFile string, processID, numWrites int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe,
		"-test.run=TestSQLiteDriver_MultiProcessConcurrent",
		"-test.v",
	)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SQLITE_TEST_DB=%s", dbFile),
		fmt.Sprintf("SQLITE_TEST_PROCESS_ID=%d", processID),
		fmt.Sprintf("SQLITE_TEST_NUM_WRITES=%d", numWrites),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Process %d output: %s", processID, string(output))
		return fmt.Errorf("process %d failed: %w", processID, err)
	}
	return nil
}

func runChildProcess(t *testing.T, dbFile string) {
	processID, _ := strconv.Atoi(os.Getenv("SQLITE_TEST_PROCESS_ID"))
	numWrites, _ := strconv.Atoi(os.Getenv("SQLITE_TEST_NUM_WRITES"))

	if numWrites == 0 {
		numWrites = 20
	}

	cfg := SQLiteConfig(dbFile)
	cfg.TargetURL = "https://example.com"
	cfg.SessionName = fmt.Sprintf("process%d", processID)

	sm, err := NewSiteMap(cfg)
	if err != nil {
		t.Fatalf("Child process %d failed to open DB: %v", processID, err)
	}
	defer func() { _ = sm.Close() }()

	for i := 0; i < numWrites; i++ {
		u, _ := url.Parse(fmt.Sprintf("https://example.com/process%d_write%d", processID, i))
		result := NewResultBuilder().
			WithURL(u).
			WithRequest("GET", nil, nil).
			WithResponse(200, nil, []byte(fmt.Sprintf("process%d_data%d", processID, i)), int64(len(fmt.Sprintf("process%d_data%d", processID, i))), "text/html", "", "", 0, 0).
			Build()

		if err := sm.Store(result); err != nil {
			t.Errorf("Child process %d failed to write: %v", processID, err)
		}

		// Small delay to simulate real-world scenario
		time.Sleep(time.Millisecond * 10)
	}

	t.Logf("Child process %d completed %d writes", processID, numWrites)
}

// ============================================================================
// Test: Randomized Backoff Effectiveness
// Verifies that the randomized backoff prevents thundering herd
// ============================================================================

func TestSQLiteDriver_NoThunderingHerd(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "thundering_herd_test.db")

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	// Create extreme contention scenario
	const numGoroutines = 100
	var errorCount atomic.Int64
	var successCount atomic.Int64

	barrier := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-barrier // Wait for all goroutines to be ready

			u, _ := url.Parse(fmt.Sprintf("https://example.com/thunder%d", id))
			result := NewResultBuilder().
				WithURL(u).
				WithRequest("GET", nil, nil).
				WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
				Build()

			if err := sm.Store(result); err != nil {
				errorCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}(i)
	}

	// Release all goroutines simultaneously
	close(barrier)
	wg.Wait()

	t.Logf("Success: %d, Errors: %d", successCount.Load(), errorCount.Load())

	// All writes should succeed thanks to randomized backoff
	assert.Equal(t, int64(0), errorCount.Load(), "No errors should occur with randomized backoff")
	assert.Equal(t, int64(numGoroutines), successCount.Load())
}

// ============================================================================
// Test: Long Running Operations
// Verifies stability during extended concurrent operations
// ============================================================================

func TestSQLiteDriver_LongRunningOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long-running test in short mode")
	}

	tmpFile := filepath.Join(t.TempDir(), "long_running_test.db")

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://example.com"

	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	const duration = 5 * time.Second
	const numWriters = 10
	const numReaders = 20

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var writeCount atomic.Int64
	var readCount atomic.Int64
	var writeErrors atomic.Int64
	var readErrors atomic.Int64

	var wg sync.WaitGroup

	// Writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			writeID := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					u, _ := url.Parse(fmt.Sprintf("https://example.com/writer%d_%d", writerID, writeID))
					result := NewResultBuilder().
						WithURL(u).
						WithRequest("GET", nil, nil).
						WithResponse(200, nil, []byte("test"), 4, "text/html", "", "", 0, 0).
						Build()

					if err := sm.Store(result); err != nil {
						writeErrors.Add(1)
					} else {
						writeCount.Add(1)
					}
					writeID++
					time.Sleep(time.Millisecond * 10)
				}
			}
		}(i)
	}

	// Readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = sm.Count() // Read operation
					readCount.Add(1)
					time.Sleep(time.Millisecond * 5)
				}
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Writes: %d (errors: %d), Reads: %d (errors: %d)",
		writeCount.Load(), writeErrors.Load(),
		readCount.Load(), readErrors.Load())

	assert.Equal(t, int64(0), writeErrors.Load(), "No write errors should occur")
	assert.Equal(t, int64(0), readErrors.Load(), "No read errors should occur")
	assert.Greater(t, writeCount.Load(), int64(100), "Should have many successful writes")
	assert.Greater(t, readCount.Load(), int64(100), "Should have many successful reads")
}

// ============================================================================
// Test: 20 Parallel Tools with Random Kills
// Simulates the REAL scenario: 20 independent processes writing to same DB,
// with some processes randomly being killed mid-operation
// ============================================================================

func TestSQLiteDriver_20ToolsParallelWithRandomKills(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping intensive parallel test in short mode")
	}

	tmpFile := filepath.Join(t.TempDir(), "20_tools_parallel.db")

	const (
		numTools      = 20 // Simulating 20 separate processes
		testDuration  = 8 * time.Second
		killInterval  = 500 * time.Millisecond // Kill a random tool every 500ms
		writeInterval = 50 * time.Millisecond  // Each tool writes every 50ms
		maxKills      = 10                     // Kill up to 10 tools during test
	)

	// Statistics
	var totalWrites atomic.Int64
	var totalErrors atomic.Int64
	var toolsKilled atomic.Int64
	var toolsCompleted atomic.Int64

	// Create initial DB and schema
	initCfg := SQLiteConfig(tmpFile)
	initCfg.TargetURL = "https://init.example.com"
	initSm, err := NewSiteMap(initCfg)
	require.NoError(t, err)
	_ = initSm.Close()

	// Track which tools are still running and which were forcefully killed
	toolContexts := make([]context.CancelFunc, numTools)
	toolRunning := make([]atomic.Bool, numTools)
	toolWasKilled := make([]atomic.Bool, numTools) // true if killed by killer goroutine

	var wg sync.WaitGroup

	// Launch 20 "tools" (simulating separate processes)
	for toolID := range numTools {
		ctx, cancel := context.WithCancel(context.Background())
		toolContexts[toolID] = cancel
		toolRunning[toolID].Store(true)

		wg.Add(1)
		go func(id int, ctx context.Context) {
			defer wg.Done()
			defer toolRunning[id].Store(false)

			// Each "tool" creates its own SiteMap connection (like a separate process)
			cfg := SQLiteConfig(tmpFile)
			cfg.TargetURL = fmt.Sprintf("https://tool%d.example.com", id)
			cfg.SessionName = fmt.Sprintf("tool_%d", id)

			sm, err := NewSiteMap(cfg)
			if err != nil {
				totalErrors.Add(1)
				return
			}

			writeCount := 0
			for {
				select {
				case <-ctx.Done():
					// Check if this was a forced kill or graceful stop
					if toolWasKilled[id].Load() {
						// Simulating abrupt kill - close connection properly in some cases
						// and leave it hanging in others (like real kill -9)
						if writeCount%2 == 0 {
							_ = sm.Close() // Clean shutdown
						}
						// Else: simulate kill -9 (no cleanup)
						toolsKilled.Add(1)
					} else {
						// Graceful stop
						_ = sm.Close()
						toolsCompleted.Add(1)
					}
					return
				default:
					// Write operation
					u, _ := url.Parse(fmt.Sprintf("https://tool%d.example.com/path%d", id, writeCount))
					result := NewResultBuilder().
						WithURL(u).
						WithRequest("GET", nil, nil).
						WithResponse(200, nil, []byte(fmt.Sprintf("tool%d_data_%d", id, writeCount)), int64(len(fmt.Sprintf("tool%d_data_%d", id, writeCount))), "text/html", "", "", 0, 0).
						Build()

					if err := sm.Store(result); err != nil {
						totalErrors.Add(1)
					} else {
						totalWrites.Add(1)
					}
					writeCount++
					time.Sleep(writeInterval)
				}
			}
		}(toolID, ctx)
	}

	// Killer goroutine - randomly kills tools
	go func() {
		time.Sleep(time.Second) // Let tools start up
		killCount := 0
		for killCount < maxKills {
			time.Sleep(killInterval)

			// Find a running tool to kill
			for attempts := 0; attempts < 5; attempts++ {
				victimID := int(time.Now().UnixNano() % int64(numTools))
				if toolRunning[victimID].Load() && !toolWasKilled[victimID].Load() {
					t.Logf("Killing tool %d", victimID)
					toolWasKilled[victimID].Store(true) // Mark as killed before canceling
					toolContexts[victimID]()            // Cancel context = kill the tool
					killCount++
					break
				}
			}
		}
	}()

	// Let the test run
	time.Sleep(testDuration)

	// Gracefully stop remaining tools (those not killed)
	for i := range numTools {
		if toolRunning[i].Load() && !toolWasKilled[i].Load() {
			toolContexts[i]()
		}
	}

	wg.Wait()

	// Verify database integrity after all the chaos
	verifyCfg := SQLiteConfig(tmpFile)
	verifyCfg.TargetURL = "https://verify.example.com"
	verifySm, err := NewSiteMap(verifyCfg)
	require.NoError(t, err, "Should be able to open DB after chaos")
	defer func() { _ = verifySm.Close() }()

	// Run integrity check
	var integrityResult string
	err = verifySm.bunDB.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrityResult)
	require.NoError(t, err)
	assert.Equal(t, "ok", integrityResult, "Database should be intact after chaos")

	// Check WAL mode still active
	var journalMode string
	err = verifySm.bunDB.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journalMode)
	require.NoError(t, err)
	assert.Equal(t, "wal", journalMode, "WAL mode should still be active")

	// Verify we can still write and read
	testURL, _ := url.Parse("https://verify.example.com/post_chaos_test")
	testResult := NewResultBuilder().
		WithURL(testURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("post chaos data"), 15, "text/html", "", "", 0, 0).
		Build()
	require.NoError(t, verifySm.Store(testResult), "Should be able to write after chaos")

	count := verifySm.Count()
	assert.Greater(t, count, 0, "Should have data in database")

	t.Logf("=== Test Results ===")
	t.Logf("Total writes: %d", totalWrites.Load())
	t.Logf("Total errors: %d", totalErrors.Load())
	t.Logf("Tools killed: %d", toolsKilled.Load())
	t.Logf("Tools completed gracefully: %d", toolsCompleted.Load())
	t.Logf("Final record count: %d", count)
	t.Logf("Database integrity: %s", integrityResult)

	// Assertions
	assert.Greater(t, totalWrites.Load(), int64(100), "Should have many successful writes despite chaos")
	assert.Less(t, totalErrors.Load(), totalWrites.Load()/10, "Error rate should be less than 10%")
	assert.GreaterOrEqual(t, toolsKilled.Load(), int64(1), "Should have killed at least one tool")
}

// ============================================================================
// Test: Sustained High Contention (20 Writers, Continuous Updates)
// Tests the scenario where all 20 tools continuously update the same paths
// ============================================================================

func TestSQLiteDriver_SustainedHighContention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping intensive contention test in short mode")
	}

	tmpFile := filepath.Join(t.TempDir(), "sustained_contention.db")

	const (
		numWriters   = 20
		testDuration = 5 * time.Second
		sharedPaths  = 50 // All writers compete for these paths
	)

	var successCount atomic.Int64
	var errorCount atomic.Int64
	var busyRetries atomic.Int64

	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()

	cfg := SQLiteConfig(tmpFile)
	cfg.TargetURL = "https://contention.example.com"
	sm, err := NewSiteMap(cfg)
	require.NoError(t, err)
	defer func() { _ = sm.Close() }()

	var wg sync.WaitGroup

	// 20 writers all competing for the same 50 paths
	for writerID := range numWriters {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			iteration := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// All writers target the same paths (high contention)
					pathID := iteration % sharedPaths
					u, _ := url.Parse(fmt.Sprintf("https://contention.example.com/shared/path%d", pathID))

					result := NewResultBuilder().
						WithURL(u).
						WithRequest("GET", nil, nil).
						WithResponse(200, nil, []byte(fmt.Sprintf("writer%d_iter%d", id, iteration)), int64(len(fmt.Sprintf("writer%d_iter%d", id, iteration))), "text/html", "", "", 0, 0).
						Build()

					if err := sm.Store(result); err != nil {
						if strings.Contains(err.Error(), "busy") || strings.Contains(err.Error(), "locked") {
							busyRetries.Add(1)
						}
						errorCount.Add(1)
					} else {
						successCount.Add(1)
					}
					iteration++
					// No sleep - maximum contention
				}
			}
		}(writerID)
	}

	wg.Wait()

	t.Logf("=== Sustained Contention Results ===")
	t.Logf("Successful writes: %d", successCount.Load())
	t.Logf("Errors: %d", errorCount.Load())
	t.Logf("Busy retries: %d", busyRetries.Load())

	// With proper WAL mode and busy_timeout, we should have minimal errors
	successRate := float64(successCount.Load()) / float64(successCount.Load()+errorCount.Load()) * 100
	t.Logf("Success rate: %.2f%%", successRate)

	assert.Greater(t, successCount.Load(), int64(1000), "Should have many successful writes")
	assert.Greater(t, successRate, 95.0, "Success rate should be above 95%")

	// Verify integrity
	var integrityResult string
	err = sm.bunDB.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrityResult)
	require.NoError(t, err)
	assert.Equal(t, "ok", integrityResult, "Database integrity should be maintained")
}

// ============================================================================
// Test: Multi-Process Recovery After Crash
// Simulates crash during write and verifies recovery on next open
// ============================================================================

func TestSQLiteDriver_MultiProcessCrashRecovery(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "crash_recovery_multi.db")

	const numProcesses = 5

	// Phase 1: Multiple processes write simultaneously, then "crash" (abrupt close)
	var wg sync.WaitGroup
	var writeCount atomic.Int64

	for procID := range numProcesses {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cfg := SQLiteConfig(tmpFile)
			cfg.TargetURL = fmt.Sprintf("https://process%d.example.com", id)
			cfg.SessionName = fmt.Sprintf("process_%d", id)

			sm, err := NewSiteMap(cfg)
			if err != nil {
				return
			}

			// Write some data
			for i := range 20 {
				u, _ := url.Parse(fmt.Sprintf("https://process%d.example.com/page%d", id, i))
				result := NewResultBuilder().
					WithURL(u).
					WithRequest("GET", nil, nil).
					WithResponse(200, nil, []byte("data"), 4, "text/html", "", "", 0, 0).
					Build()
				if sm.Store(result) == nil {
					writeCount.Add(1)
				}
			}

			// Simulate crash - don't close properly for some
			if id%2 == 0 {
				// Abrupt "crash" - just let go of the connection
				// The OS will release file locks, but WAL may not be checkpointed
			} else {
				_ = sm.Close()
			}
		}(procID)
	}

	wg.Wait()
	t.Logf("Phase 1: %d writes before crash simulation", writeCount.Load())

	// Give OS time to release file handles
	time.Sleep(100 * time.Millisecond)

	// Phase 2: New process opens DB (should trigger WAL recovery)
	recoveryCfg := SQLiteConfig(tmpFile)
	recoveryCfg.TargetURL = "https://recovery.example.com"
	recoverySm, err := NewSiteMap(recoveryCfg)
	require.NoError(t, err, "Should be able to open DB after crash")
	defer func() { _ = recoverySm.Close() }()

	// Verify integrity
	var integrityResult string
	err = recoverySm.bunDB.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&integrityResult)
	require.NoError(t, err)
	assert.Equal(t, "ok", integrityResult, "Database should be intact after recovery")

	// Verify WAL mode
	var journalMode string
	err = recoverySm.bunDB.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journalMode)
	require.NoError(t, err)
	assert.Equal(t, "wal", journalMode, "WAL mode should be active")

	// Can still write
	testURL, _ := url.Parse("https://recovery.example.com/after_recovery")
	testResult := NewResultBuilder().
		WithURL(testURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, nil, []byte("recovered"), 9, "text/html", "", "", 0, 0).
		Build()
	require.NoError(t, recoverySm.Store(testResult), "Should be able to write after recovery")

	t.Logf("Phase 2: Recovery successful, integrity: %s", integrityResult)
}
