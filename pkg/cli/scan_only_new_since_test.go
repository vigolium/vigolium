package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// scan --only-new-since <scan> assesses the stored records added after that
// scan finished and no other, and refuses what it cannot honour.
func TestScanOnlyNewSinceAssessesOnlyNewRecords(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>ok " + r.URL.RawQuery + "</html>"))
	}))
	defer srv.Close()

	e := newB5Env(t)
	db := newDBAtPath(t, e.db)
	repo := database.NewRepository(db)
	ctx := context.Background()
	for _, p := range []string{"/old", "/new"} {
		rr, err := httpmsg.GetRawRequestFromURL(srv.URL + p + "?q=1")
		require.NoError(t, err)
		_, err = repo.SaveRecord(ctx, rr, database.RecordSourceIngestCLI, database.DefaultProjectUUID)
		require.NoError(t, err)
	}
	_, err := db.ExecContext(ctx, `UPDATE http_records SET created_at = '2026-01-01 00:00:00' WHERE path LIKE '/old%'`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `UPDATE http_records SET created_at = '2026-06-01 00:00:00' WHERE path LIKE '/new%'`)
	require.NoError(t, err)
	const (
		finished = "0a000001-0000-4000-8000-000000000001"
		running  = "0a000002-0000-4000-8000-000000000002"
	)
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: finished, ProjectUUID: database.DefaultProjectUUID,
		Status: "completed", StartedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), FinishedAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}))
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: running, ProjectUUID: database.DefaultProjectUUID,
		Status: "running", StartedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}))
	require.NoError(t, db.Close())

	code, out, errOut := e.run(t, nil, "scan", "--only-new-since", finished[:10], "-m", "reflected-ssti", "-c", "2", "--scanning-max-duration", "60s", "-j")
	require.Equal(t, 0, code, "%s\n%s", out, errOut)
	mu.Lock()
	require.Positive(t, hits["/new"], "the record added after the scan was not assessed: %v", hits)
	require.Zero(t, hits["/old"], "a record older than the cursor was assessed: %v", hits)
	mu.Unlock()

	// The run's row records where it started.
	db = newDBAtPath(t, e.db)
	var mode, start string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT scan_mode, CAST(start_cursor_at AS TEXT) FROM scans WHERE uuid NOT IN (?, ?) ORDER BY started_at DESC LIMIT 1`,
		finished, running).Scan(&mode, &start))
	require.NoError(t, db.Close())
	require.Equal(t, "incremental", mode)
	require.True(t, strings.HasPrefix(start, "2026-03-01"), "start_cursor_at = %s", start)

	for name, args := range map[string][]string{
		"with a target":  {"scan", "--only-new-since", finished, "-t", srv.URL, "-j"},
		"with records":   {"scan", "--only-new-since", finished, "--record-uuid", "abcdefgh1", "-j"},
		"stateless":      {"scan", "--only-new-since", finished, "-S", "-j"},
		"unfinished":     {"scan", "--only-new-since", running, "-j"},
		"empty argument": {"scan", "--only-new-since", "", "-j"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, _ := e.run(t, nil, args...)
			require.Equal(t, 2, code, out)
		})
	}
	code, out, _ = e.run(t, nil, "scan", "--only-new-since", "ffffffff-dead", "-j")
	require.Equal(t, 1, code, out)
	require.Contains(t, out, "scan_not_found")
}
