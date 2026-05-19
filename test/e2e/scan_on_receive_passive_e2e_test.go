//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/queue"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestScanOnReceive_RunsPassiveModules is a regression guard for the bug
// where `vigolium server -A --scan-on-receive` silently dropped all 91
// passive modules because pkg/cli/server.go built runnerOpts without
// setting PassiveModules. The fix wires PassiveModules: "all" via the
// newServerRunnerOptions helper; this test proves the end-to-end effect —
// that a passive-only finding (security-headers-missing) actually appears
// on an ingested record scanned via the scan-on-receive runner.
//
// If someone re-introduces the regression (drops PassiveModules from the
// server-mode Options), the runner will load zero passive modules and the
// poll loop below will exhaust its deadline without finding a passive
// finding — failing the test.
func TestScanOnReceive_RunsPassiveModules(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Target server returns HTML without security headers and 404 everywhere
	// else so active-module probing completes quickly and the scan focuses
	// on the ingested record.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><body>hi</body></html>`))
	})
	target := httptest.NewServer(mux)
	defer target.Close()

	db, repo := setupTestDB(t)

	// scan-on-receive expects the caller (normally server.go) to create the
	// scan record up front — the runner reads UUID from opts.ScanUUID and
	// advances the cursor on it.
	scan := &database.Scan{
		UUID:        "scan-test-passive-sor",
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "test-scan-on-receive-passive",
		Status:      "running",
		Target:      target.URL,
		ScanSource:  "scan-on-receive",
		ScanMode:    "incremental",
		StartedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateScanWithCursor(ctx, scan))

	rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", stripScheme(target.URL))
	rr, err := httpmsg.ParseRawRequestWithURL(rawReq, target.URL)
	require.NoError(t, err)
	_, err = repo.SaveRecord(ctx, rr, "ingest-server", database.DefaultProjectUUID)
	require.NoError(t, err)

	opts := newServerRunnerOptionsForTest()
	opts.ScanOnReceive = true
	opts.SkipIngestion = true
	opts.ScanUUID = scan.UUID
	opts.ScanOnReceiveIdleTimeout = 3 * time.Second
	opts.Concurrency = 10
	opts.MaxPerHost = 100
	opts.Targets = []string{target.URL}

	tmpDir := t.TempDir()
	q, err := queue.NewDiskQueue(queue.DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: 100,
	})
	require.NoError(t, err)
	defer q.Close()

	r, err := runner.NewWithInputSource(opts, queue.NewQueueInputSource(q))
	require.NoError(t, err)
	r.SetSettings(config.DefaultSettings())
	r.SetRepository(repo)

	runDone := make(chan error, 1)
	go func() { runDone <- r.RunNativeScan() }()
	t.Cleanup(func() { r.Close() })

	// Poll for the passive finding rather than wait for the full scan to
	// complete — the active-module sweep can take a while even against
	// localhost, but the passive pipeline runs immediately after the
	// baseline fetch on the first record, so the passive finding is the
	// earliest signal we can check for.
	deadline := time.Now().Add(60 * time.Second)
	var sawSecurityHeadersMissing bool
	var lastPassiveIDs []string
	for time.Now().Before(deadline) {
		var findings []*database.Finding
		if err := db.NewSelect().Model(&findings).Scan(ctx); err == nil {
			lastPassiveIDs = lastPassiveIDs[:0]
			for _, f := range findings {
				if f.ModuleType == "passive" {
					lastPassiveIDs = append(lastPassiveIDs, f.ModuleID)
				}
				if f.ModuleID == "security-headers-missing" {
					sawSecurityHeadersMissing = true
				}
			}
			if sawSecurityHeadersMissing {
				break
			}
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("test context cancelled while polling for findings")
		}
	}

	assert.True(t, sawSecurityHeadersMissing,
		"scan-on-receive must produce the security-headers-missing finding — "+
			"its absence means passive modules are NOT loaded in server mode "+
			"(regression: pkg/cli/server.go must set PassiveModules: \"all\" "+
			"via newServerRunnerOptions). passive findings seen: %v", lastPassiveIDs)
	assert.NotEmpty(t, lastPassiveIDs,
		"scan-on-receive must run passive modules")
}

// TestScanOnReceive_DoesNotFanOutOnFindingArtefacts is a regression guard
// for the bug where `vigolium server --scan-on-receive` would process one
// ingested request, but each vulnerability finding produced by the executor
// gets persisted as a new http_record (source="finding",
// executor.go:1474-1488), which DBInputSource then polls back in and scans
// again — fanning one ingested request out to dozens of re-scanned rows.
// The fix restricts the scan-on-receive DB poller to records whose source
// is in database.IngestRecordSources.
//
// This test seeds a "finding"-sourced record before the scan starts and
// asserts the scan does NOT pick it up. If the regression returns, the
// DBInputSource will consume the finding row, the scan cursor will advance
// past it, and the ProcessedCount/CursorUUID assertions will fail.
func TestScanOnReceive_DoesNotFanOutOnFindingArtefacts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><body>hi</body></html>`))
	})
	target := httptest.NewServer(mux)
	defer target.Close()

	_, repo := setupTestDB(t)

	scan := &database.Scan{
		UUID:        "scan-test-shallow-nofanout",
		ProjectUUID: database.DefaultProjectUUID,
		Name:        "test-scan-on-receive-nofanout",
		Status:      "running",
		Target:      target.URL,
		ScanSource:  "scan-on-receive",
		ScanMode:    "incremental",
		StartedAt:   time.Now(),
	}
	require.NoError(t, repo.CreateScanWithCursor(ctx, scan))

	// One user-ingested record (should be scanned) …
	ingestRaw := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", stripScheme(target.URL))
	ingestRR, err := httpmsg.ParseRawRequestWithURL(ingestRaw, target.URL)
	require.NoError(t, err)
	ingestUUID, err := repo.SaveRecord(ctx, ingestRR, "ingest-server", database.DefaultProjectUUID)
	require.NoError(t, err)

	// … and one finding-artefact record at a different path (should NOT be
	// scanned in shallow mode — it's noise created as a byproduct of
	// scanning, not user-ingested traffic). Different path ensures
	// deduplication doesn't collapse it onto the ingest row.
	findingRaw := fmt.Sprintf("GET /attack?payload=1 HTTP/1.1\r\nHost: %s\r\n\r\n", stripScheme(target.URL))
	findingRR, err := httpmsg.ParseRawRequestWithURL(findingRaw, target.URL+"/attack?payload=1")
	require.NoError(t, err)
	findingUUID, err := repo.SaveRecord(ctx, findingRR, "finding", database.DefaultProjectUUID)
	require.NoError(t, err)
	require.NotEqual(t, ingestUUID, findingUUID, "test setup: ingest vs finding rows must be distinct")

	opts := newServerRunnerOptionsForTest()
	opts.ScanOnReceive = true
	opts.SkipIngestion = true
	opts.ScanUUID = scan.UUID
	opts.ScanOnReceiveIdleTimeout = 2 * time.Second
	opts.Concurrency = 10
	opts.MaxPerHost = 100
	opts.Targets = []string{target.URL}

	tmpDir := t.TempDir()
	q, err := queue.NewDiskQueue(queue.DiskQueueConfig{BaseDir: tmpDir, MaxRecordsPerSegment: 100})
	require.NoError(t, err)
	defer q.Close()

	r, err := runner.NewWithInputSource(opts, queue.NewQueueInputSource(q))
	require.NoError(t, err)
	r.SetSettings(config.DefaultSettings())
	r.SetRepository(repo)

	runDone := make(chan error, 1)
	go func() { runDone <- r.RunNativeScan() }()
	t.Cleanup(func() { r.Close() })

	// Wait for the scan to idle-timeout (it picks up the ingest-server row,
	// scans it, then idles). Bounded by the outer context.
	select {
	case err := <-runDone:
		require.NoError(t, err, "scan-on-receive runner failed")
	case <-ctx.Done():
		t.Fatal("scan didn't complete within timeout")
	}

	// Invariant: the scan's cursor UUID advanced to the ingest-server row
	// only — NOT to the finding row. If the source filter regressed, the
	// poller would also consume the finding row and CursorUUID would move
	// past it (to whichever row is created_at-later in the DB).
	finalScan, err := repo.GetScanByUUID(ctx, scan.UUID)
	require.NoError(t, err)
	assert.Equal(t, ingestUUID, finalScan.CursorUUID,
		"scan cursor must stop at the ingest-server row; reaching any other "+
			"row means the source filter regressed and finding-artefacts are "+
			"being polled back into the scan (fan-out bug).")
}

// stripScheme returns the host:port portion of an http:// URL.
func stripScheme(u string) string {
	const prefix = "http://"
	if len(u) > len(prefix) && u[:len(prefix)] == prefix {
		return u[len(prefix):]
	}
	return u
}

// newServerRunnerOptionsForTest mirrors pkg/cli.newServerRunnerOptions so the
// e2e test can assert the full invariant without importing the internal CLI
// package (which uses global flag state). Keep this in sync with the helper
// in pkg/cli/server.go — the unit test in pkg/cli/server_options_test.go
// guards the shape of that helper separately.
func newServerRunnerOptionsForTest() *types.Options {
	return &types.Options{
		Concurrency:    50,
		MaxPerHost:     20,
		MaxHostError:   30,
		Timeout:        10 * time.Second,
		Retries:        1,
		Silent:         true,
		Modules:        []string{"all"},
		PassiveModules: []string{"all"},
	}
}
