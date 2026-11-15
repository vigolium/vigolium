package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// --- §3 request-boundary limits -------------------------------------------

// startBodyLimitTestServer serves a body-limit-guarded route on a real
// localhost port. A real listener is required rather than app.Test: the whole
// subject here is chunked framing, and app.Test hands fasthttp a serialized
// request with a literal Content-Length rather than a chunked stream.
func startBodyLimitTestServer(t *testing.T, handler fiber.Handler) string {
	t.Helper()
	app := fiber.New(fiber.Config{
		BodyLimit:         defaultMaxUploadBytes,
		StreamRequestBody: true,
	})
	app.Use(DefaultBodyLimitMiddleware())
	app.Post("/api/thing", handler)
	app.Post("/api/import", handler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	go func() { _ = app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(2 * time.Second) })
	return "http://" + ln.Addr().String()
}

// postChunked sends body with Transfer-Encoding: chunked (net/http uses it
// whenever ContentLength is unknown and the body isn't a known-length type).
// A nil response with a non-nil error means the server refused mid-send, which
// is a legitimate outcome for a grossly oversized body.
func postChunked(url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, io.NopCloser(body))
	if err != nil {
		return nil, err
	}
	req.ContentLength = -1
	return (&http.Client{Timeout: 30 * time.Second}).Do(req)
}

func mustPostChunked(t *testing.T, url string, body io.Reader) *http.Response {
	t.Helper()
	resp, err := postChunked(url, body)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	return resp
}

// TestBodyLimitRejectsModestlyOversizedBody is the case the
// declared-Content-Length check never covered: a chunked request carries no
// length to inspect. A body somewhat over the cap must get a clean 413 — the
// bounded drain exists so this sender finishes rather than eating a reset — and
// the handler must not run.
func TestBodyLimitRejectsModestlyOversizedBody(t *testing.T) {
	handlerRan := false
	base := startBodyLimitTestServer(t, func(c fiber.Ctx) error {
		handlerRan = true
		return c.SendStatus(fiber.StatusOK)
	})

	resp := mustPostChunked(t, base+"/api/thing", io.LimitReader(filler{}, defaultBodyLimit+(1<<20)))
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != fiber.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if handlerRan {
		t.Fatal("handler ran for an oversized body; it must be rejected in middleware")
	}
	// The unread tail makes keep-alive reuse unsafe. Assert via resp.Close,
	// which net/http populates from the Connection header (it strips the
	// hop-by-hop header itself, so the map is empty).
	if !resp.Close {
		t.Fatal("response did not signal Connection: close; an undrained body would corrupt the next request on this connection")
	}
}

// TestBodyLimitDoesNotDrainOversizedBody is the memory property itself: the old
// `len(c.Body()) > limit` read the whole stream first — bounded only by the
// 512 MB framework ceiling — so a sender who omits Content-Length could grow the
// heap far past a 4 MB route limit on a request that was always going to be
// rejected. The server must stop reading near the cap.
//
// Whether the client gets a 413 or a connection reset is not the assertion: a
// body this far past the budget outruns the courtesy drain by design.
func TestBodyLimitDoesNotDrainOversizedBody(t *testing.T) {
	handlerRan := false
	base := startBodyLimitTestServer(t, func(c fiber.Ctx) error {
		handlerRan = true
		return c.SendStatus(fiber.StatusOK)
	})

	const sent = 128 << 20 // well past both the cap and the drain budget
	counted := &countingReader{r: io.LimitReader(filler{}, sent)}
	if resp, err := postChunked(base+"/api/thing", counted); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != fiber.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}
	}

	if handlerRan {
		t.Fatal("handler ran for an oversized body; it must be rejected in middleware")
	}
	// Slack for the client's own buffering plus the drain budget; what matters
	// is that it is nowhere near the 128 MB offered.
	budget := int64(defaultBodyLimit + maxOversizeDrainBytes + (8 << 20))
	if got := counted.n.Load(); got > budget {
		t.Fatalf("server consumed %d bytes of a %d-byte body (budget %d); the read is not bounded",
			got, sent, budget)
	}
}

// TestBodyLimitAllowsUndeclaredBodyUnderCap makes sure the bounded read is a
// limit and not a rewrite: a chunked body within the cap must reach the handler
// byte for byte.
func TestBodyLimitAllowsUndeclaredBodyUnderCap(t *testing.T) {
	var got []byte
	base := startBodyLimitTestServer(t, func(c fiber.Ctx) error {
		got = append([]byte(nil), c.Body()...)
		return c.SendStatus(fiber.StatusOK)
	})

	want := bytes.Repeat([]byte("x"), 64*1024)
	resp := mustPostChunked(t, base+"/api/thing", bytes.NewReader(want))
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("handler saw %d bytes, want %d", len(got), len(want))
	}
}

// TestBodyLimitSkipsExemptUploadRoutes guards the exemption: the import and
// upload routes stage their payload themselves and must keep their stream, so
// the 4 MB cap must not apply and the body must still arrive as a stream.
func TestBodyLimitSkipsExemptUploadRoutes(t *testing.T) {
	var sawStream bool
	var read int
	base := startBodyLimitTestServer(t, func(c fiber.Ctx) error {
		sawStream = c.Request().IsBodyStream()
		read = len(c.Body())
		return c.SendStatus(fiber.StatusOK)
	})

	size := defaultBodyLimit + 1024
	resp := mustPostChunked(t, base+"/api/import", io.LimitReader(filler{}, int64(size)))
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200 (exempt route must not be capped)", resp.StatusCode)
	}
	if !sawStream {
		t.Fatal("exempt route lost its request body stream")
	}
	if read != size {
		t.Fatalf("exempt route received %d bytes, want %d", read, size)
	}
}

// filler is an endless source of body bytes.
type filler struct{}

func (filler) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// countingReader records how many bytes the server pulled through it.
//
// The counter is atomic because net/http drains the request body on its own
// write goroutine, which outlives the response the test goroutine reads: after
// an early 413 the client may still be writing when we check the total.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// --- §19 bounded log reads ------------------------------------------------

// TestReadLogTailReturnsEnd locks in that the cap takes the END of the file.
// Taking the head would be worse than not capping at all: a log viewer polling
// a running scan would be pinned to output from hours ago.
func TestReadLogTailReturnsEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	body := []byte(strings.Repeat("A", 1000) + "TAIL")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, size, err := readLogTail(path, 10)
	if err != nil {
		t.Fatalf("readLogTail: %v", err)
	}
	if size != int64(len(body)) {
		t.Fatalf("size = %d, want %d", size, len(body))
	}
	if len(data) != 10 {
		t.Fatalf("len(data) = %d, want 10", len(data))
	}
	if !bytes.HasSuffix(data, []byte("TAIL")) {
		t.Fatalf("data = %q, want the end of the file", data)
	}
}

// TestReadLogTailWholeFileUnderLimit: a small log comes back intact, so the cap
// is invisible to the ordinary case.
func TestReadLogTailWholeFileUnderLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	body := []byte("short log\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, size, err := readLogTail(path, defaultLogTailBytes)
	if err != nil {
		t.Fatalf("readLogTail: %v", err)
	}
	if size != int64(len(body)) || !bytes.Equal(data, body) {
		t.Fatalf("got %q (size %d), want %q", data, size, body)
	}
}

// TestQueryByteLimitClamps: ?max_bytes= can raise the budget for a deliberate
// download but not remove it. Shared by the log endpoints and the artifact
// endpoint, so the clamp is asserted once.
func TestQueryByteLimitClamps(t *testing.T) {
	app := fiber.New()
	var got int64
	app.Get("/l", func(c fiber.Ctx) error {
		got = queryByteLimit(c, defaultLogTailBytes, maxLogTailBytes)
		return c.SendStatus(fiber.StatusOK)
	})

	for _, tc := range []struct {
		query string
		want  int64
	}{
		{"", defaultLogTailBytes},
		{"?max_bytes=0", defaultLogTailBytes},
		{"?max_bytes=-5", defaultLogTailBytes},
		{"?max_bytes=nonsense", defaultLogTailBytes},
		{"?max_bytes=4096", 4096},
		{"?max_bytes=" + strconv.Itoa(maxLogTailBytes*4), maxLogTailBytes},
	} {
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/l"+tc.query, nil))
		if err != nil {
			t.Fatalf("app.Test(%q): %v", tc.query, err)
		}
		_ = resp.Body.Close()
		if got != tc.want {
			t.Fatalf("queryByteLimit(%q) = %d, want %d", tc.query, got, tc.want)
		}
	}
}

// --- §13/§26 agent terminal statuses --------------------------------------

// TestIsTerminalAgentStatusCoversCombinedAudit: "completed_with_errors" is what
// a multi-driver audit writes when one leg fails. Missing from the terminal set
// it meant the SSE log follower spun until its two-hour cap on a run that had
// already finished.
func TestIsTerminalAgentStatusCoversCombinedAudit(t *testing.T) {
	if !database.IsTerminalAgenticScanStatus("completed_with_errors") {
		t.Fatal(`"completed_with_errors" must be terminal`)
	}
	for _, status := range []string{"running", "pending", ""} {
		if database.IsTerminalAgenticScanStatus(status) {
			t.Fatalf("database.IsTerminalAgenticScanStatus(%q) = true, want false", status)
		}
	}
}

// TestAgenticScanStatusByUUID covers the narrow read the log follower polls
// twice a second in place of a whole blob-bearing row.
func TestAgenticScanStatusByUUID(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	run := &database.AgenticScan{
		UUID:        "run-status-1",
		ProjectUUID: database.DefaultProjectUUID,
		Mode:        "autopilot",
		AgentName:   "olium",
		Status:      "completed_with_errors",
		ResultJSON:  strings.Repeat("x", 4096),
	}
	if err := repo.CreateAgenticScan(ctx, run); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}

	got, err := repo.AgenticScanStatusByUUID(ctx, "run-status-1")
	if err != nil {
		t.Fatalf("AgenticScanStatusByUUID: %v", err)
	}
	if got != "completed_with_errors" {
		t.Fatalf("status = %q, want completed_with_errors", got)
	}

	if _, err := repo.AgenticScanStatusByUUID(ctx, "nope"); err == nil {
		t.Fatal("want error for a missing run")
	}
}

// TestListAgenticScanSummariesOmitsBlobs is the point of the projection: the
// list handlers render counters and timestamps, so the megabyte-scale columns
// must not be transferred to build them. The narrow read must otherwise return
// exactly what the full read does.
func TestListAgenticScanSummariesOmitsBlobs(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	blob := strings.Repeat("y", 8192)
	for i := range 3 {
		run := &database.AgenticScan{
			UUID:           fmt.Sprintf("run-list-%d", i),
			ProjectUUID:    database.DefaultProjectUUID,
			Mode:           "autopilot",
			AgentName:      "olium",
			Status:         "completed",
			FindingCount:   i + 1,
			TargetURL:      "https://example.test/",
			ResultJSON:     blob,
			AgentRawOutput: blob,
			PromptSent:     blob,
			InputRaw:       blob,
		}
		if err := repo.CreateAgenticScan(ctx, run); err != nil {
			t.Fatalf("CreateAgenticScan: %v", err)
		}
	}

	full, fullTotal, err := repo.ListAgenticScans(ctx, database.DefaultProjectUUID, "", 50, 0)
	if err != nil {
		t.Fatalf("ListAgenticScans: %v", err)
	}
	summaries, sumTotal, err := repo.ListAgenticScanSummaries(ctx, database.DefaultProjectUUID, "", 50, 0)
	if err != nil {
		t.Fatalf("ListAgenticScanSummaries: %v", err)
	}

	if fullTotal != sumTotal || len(full) != len(summaries) {
		t.Fatalf("summary read returned %d/%d rows, full read %d/%d", len(summaries), sumTotal, len(full), fullTotal)
	}
	for i, s := range summaries {
		// The fields the DTOs actually render must survive.
		if s.UUID != full[i].UUID || s.Status != full[i].Status ||
			s.FindingCount != full[i].FindingCount || s.TargetURL != full[i].TargetURL {
			t.Fatalf("summary %d lost a rendered field: %+v vs %+v", i, s, full[i])
		}
		// The blobs must not have been read.
		if s.ResultJSON != "" || s.AgentRawOutput != "" || s.PromptSent != "" || s.InputRaw != "" {
			t.Fatalf("summary %d carries a blob column; the projection is not being applied", i)
		}
		// ...and the full read must still carry them, so the detail endpoint
		// and the --json CLI paths are unaffected.
		if full[i].ResultJSON != blob {
			t.Fatalf("full read %d lost result_json", i)
		}
	}
}

// --- §31 route policy -----------------------------------------------------

// TestCORSAllowsPatch: PATCH /api/findings/:id/status is the only way a browser
// marks a finding triaged, and a verb absent from AllowMethods fails the
// preflight before the route is ever consulted.
func TestCORSAllowsPatch(t *testing.T) {
	app := fiber.New()
	registerRoutes(app, &Handlers{}, ServerConfig{
		CORSAllowedOrigins: "https://ui.example.test",
		NoAuth:             true,
		DemoOnly:           true, // keeps the route table small; CORS registers before it
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/findings/1/status", nil)
	req.Header.Set("Origin", "https://ui.example.test")
	req.Header.Set("Access-Control-Request-Method", "PATCH")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	allowed := resp.Header.Get("Access-Control-Allow-Methods")
	if !strings.Contains(strings.ToUpper(allowed), "PATCH") {
		t.Fatalf("Access-Control-Allow-Methods = %q, want it to include PATCH", allowed)
	}
}

// TestViewOnlyRegistersStorageReads: the storage GETs are viewer routes, so a
// view-only deployment must still serve them. They used to be registered after
// the view-only early return, which made them 404 in exactly the mode whose
// whole purpose is reading.
func TestViewOnlyRegistersStorageReads(t *testing.T) {
	app := fiber.New()
	registerRoutes(app, &Handlers{}, ServerConfig{NoAuth: true, ViewOnly: true})

	for _, path := range []string{
		"/api/storage/source/thing.zip",
		"/api/storage/results/scan-uuid",
	} {
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil))
		if err != nil {
			t.Fatalf("app.Test(%s): %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == fiber.StatusNotFound {
			t.Fatalf("%s is unrouted in view-only mode; storage reads must be registered before the early return", path)
		}
	}

	// The writes must still be gone.
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/api/storage/upload-source", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("upload-source status = %d, want 404 in view-only mode", resp.StatusCode)
	}
}

// --- §7/§8/§9 scan admission, scoping and dry-run cost --------------------

// scanRecordsTestApp wires the two record-scan routes over an in-memory DB.
func scanRecordsTestApp(t *testing.T) (*fiber.App, *Handlers) {
	t.Helper()
	repo := newTestRepo(t)
	h := newBasicHandlers(t, ServerConfig{Concurrency: 5}, nil, repo.DB(), repo, config.DefaultSettings())
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(nil))
	app.Post("/api/scan-records", h.HandleScanRecords)
	app.Post("/api/scan-all-records", h.HandleScanAllRecords)
	return app, h
}

// seedRecords inserts n http_records in the default project and returns their
// UUIDs.
func seedRecords(t *testing.T, repo *database.Repository, n int) []string {
	t.Helper()
	uuids := make([]string, n)
	for i := range n {
		uuids[i] = fmt.Sprintf("rec-%d", i)
		rec := &database.HTTPRecord{
			UUID:        uuids[i],
			ProjectUUID: database.DefaultProjectUUID,
			URL:         fmt.Sprintf("https://example.test/%d", i),
			Hostname:    "example.test",
			Method:      http.MethodGet,
			StatusCode:  200,
		}
		if _, err := repo.DB().NewInsert().Model(rec).Exec(context.Background()); err != nil {
			t.Fatalf("insert record: %v", err)
		}
	}
	return uuids
}

// mustPostJSON is postJSON with the error folded into t.Fatal.
func mustPostJSON(t *testing.T, app *fiber.App, path string, body any) (*http.Response, string) {
	t.Helper()
	resp, data, err := postJSON(app, path, body)
	if err != nil {
		t.Fatalf("postJSON(%s): %v", path, err)
	}
	return resp, string(data)
}

// countScanRows counts scan rows, optionally filtered by status. A blank status
// counts every row.
func countScanRows(t *testing.T, repo *database.Repository, status string) int {
	t.Helper()
	q := repo.DB().NewSelect().Model((*database.Scan)(nil))
	if status != "" {
		q = q.Where("status = ?", status)
	}
	n, err := q.Count(context.Background())
	if err != nil {
		t.Fatalf("count scans (%q): %v", status, err)
	}
	return int(n)
}

// TestRecordScanConflictPersistsNothing: a project with a scan already running
// must be refused without persisting anything. Before admission moved ahead of
// the work, every rejection wrote a scan row that no code path would ever
// advance out of "pending", so the scan list filled with rows a UI is entitled
// to poll forever.
func TestRecordScanConflictPersistsNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body func(uuids []string) any
	}{
		{"selective", "/api/scan-records", func(u []string) any {
			return map[string]any{"record_uuids": u}
		}},
		// The filter path's wasted work is a query enumerating every matching UUID.
		{"all-records", "/api/scan-all-records", func([]string) any { return map[string]any{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, h := scanRecordsTestApp(t)
			// Real records, so the request gets past validation and actually
			// reaches the admission check.
			uuids := seedRecords(t, h.repo, 2)

			// Mark the default project busy.
			h.scanMu.Lock()
			h.getProjectScanState(database.DefaultProjectUUID).running = true
			h.scanMu.Unlock()

			resp, _ := mustPostJSON(t, app, tc.path, tc.body(uuids))
			if resp.StatusCode != fiber.StatusConflict {
				t.Fatalf("status = %d, want 409", resp.StatusCode)
			}
			if n := countScanRows(t, h.repo, ""); n != 0 {
				t.Fatalf("%d scan rows left by a rejected request, want 0", n)
			}
		})
	}
}

// TestScanRecordsRejectsOversizedSelection: record_uuids used to be bounded
// only by the 4 MB body limit, i.e. ~100k entries, each of which becomes an
// IN(...) term and then a resident element of the scan's input source.
func TestScanRecordsRejectsOversizedSelection(t *testing.T) {
	app, _ := scanRecordsTestApp(t)

	uuids := make([]string, maxSelectiveScanRecords+1)
	for i := range uuids {
		uuids[i] = strconv.Itoa(i)
	}

	resp, msg := mustPostJSON(t, app, "/api/scan-records", map[string]any{"record_uuids": uuids})
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(msg, "too many record_uuids") {
		t.Fatalf("body = %s, want the selection-size error", msg)
	}
}

// TestScanAllRecordsDryRunReportsCount: the dry run must keep reporting the
// same records_to_scan and the same "dry_run" scan row after switching from
// enumerating every matching UUID to counting them.
func TestScanAllRecordsDryRunReportsCount(t *testing.T) {
	app, h := scanRecordsTestApp(t)
	seedRecords(t, h.repo, 5)

	resp, body := mustPostJSON(t, app, "/api/scan-all-records", map[string]any{"dry_run": true})
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d (%s), want 200", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"records_to_scan":5`) {
		t.Fatalf("body = %s, want records_to_scan 5", body)
	}
	if !strings.Contains(body, `"status":"dry_run"`) {
		t.Fatalf("body = %s, want a dry_run status", body)
	}
	if n := countScanRows(t, h.repo, "dry_run"); n != 1 {
		t.Fatalf("%d dry_run scan rows, want 1", n)
	}
}
