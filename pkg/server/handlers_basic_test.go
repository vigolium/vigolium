package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/queue"
)

// fakeQueue is a minimal queue.Queue implementation for handler tests that
// only need a queue with controllable Metrics(). All task-moving methods are
// no-ops since the basic handlers under test never enqueue or dequeue.
type fakeQueue struct {
	metrics *queue.QueueMetrics
}

func (f *fakeQueue) Enqueue(context.Context, *queue.ScanTask) error   { return nil }
func (f *fakeQueue) Dequeue(context.Context) (*queue.ScanTask, error) { return nil, nil }
func (f *fakeQueue) Ack(string) error                                 { return nil }
func (f *fakeQueue) Close() error                                     { return nil }
func (f *fakeQueue) Metrics() *queue.QueueMetrics                     { return f.metrics }

// newBasicHandlers builds a Handlers with NoAgent set so NewHandlers does not
// start the agent engine / cleanup goroutine, keeping the test hermetic.
func newBasicHandlers(t *testing.T, cfg ServerConfig, q queue.Queue, db *database.DB, repo *database.Repository, settings *config.Settings) *Handlers {
	t.Helper()
	cfg.NoAgent = true
	h := NewHandlers(q, db, repo, nil, cfg, settings, nil, nil)
	t.Cleanup(func() { h.Close() })
	return h
}

// doGet drives a GET against a Fiber app and returns status + body.
func doGet(t *testing.T, app *fiber.App, path string, headers map[string]string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// -----------------------------------------------------------------------------
// Simple response handlers: health / app-info / server-info
// -----------------------------------------------------------------------------

func TestHandleHealth(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/health", h.HandleHealth)

	status, body := doGet(t, app, "/health", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var resp HealthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.Status != "healthy" {
		t.Errorf("status field = %q, want healthy", resp.Status)
	}
	if _, err := time.Parse(time.RFC3339, resp.Timestamp); err != nil {
		t.Errorf("timestamp %q not RFC3339: %v", resp.Timestamp, err)
	}
}

func TestHandleAppInfo(t *testing.T) {
	cfg := ServerConfig{
		Version:   "9.9.9",
		Author:    "test-author",
		BuildTime: "2026-01-01",
		// 40-char commit should be truncated to the first 7.
		Commit: "abcdef0123456789012345678901234567890123",
	}
	h := newBasicHandlers(t, cfg, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/api/info", h.HandleAppInfo)

	status, body := doGet(t, app, "/api/info", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var resp AppInfoResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.Name != "vigolium" {
		t.Errorf("name = %q, want vigolium", resp.Name)
	}
	if resp.Version != "9.9.9" {
		t.Errorf("version = %q, want 9.9.9", resp.Version)
	}
	if resp.Author != "test-author" {
		t.Errorf("author = %q, want test-author", resp.Author)
	}
	if resp.LicenseSPDX != "AGPL-3.0-or-later" {
		t.Errorf("license = %q", resp.LicenseSPDX)
	}
	if resp.Commit != "abcdef0" {
		t.Errorf("commit = %q, want truncated abcdef0", resp.Commit)
	}
}

func TestHandleAppInfo_ShortCommitNotTruncated(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{Commit: "abc12"}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Get("/api/info", h.HandleAppInfo)

	_, body := doGet(t, app, "/api/info", nil)
	var resp AppInfoResponse
	_ = json.Unmarshal(body, &resp)
	if resp.Commit != "abc12" {
		t.Errorf("short commit should pass through verbatim, got %q", resp.Commit)
	}
}

func TestHandleServerInfo(t *testing.T) {
	cfg := ServerConfig{
		Version:         "1.2.3",
		Author:          "ops",
		License:         "enterprise",
		ServiceAddr:     ":9002",
		IngestProxyAddr: ":9003",
		Commit:          "deadbeefcafebabe1234",
		DemoOnly:        true,
		ViewOnly:        true,
	}
	q := &fakeQueue{metrics: &queue.QueueMetrics{Depth: 42}}
	h := newBasicHandlers(t, cfg, q, nil, nil, nil)
	app := fiber.New()
	app.Get("/server-info", h.HandleServerInfo)

	status, body := doGet(t, app, "/server-info", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var resp ServerInfoResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.Version != "1.2.3" {
		t.Errorf("version = %q", resp.Version)
	}
	if resp.QueueDepth != 42 {
		t.Errorf("queue_depth = %d, want 42", resp.QueueDepth)
	}
	if resp.ProxyAddr != ":9003" {
		t.Errorf("proxy_addr = %q", resp.ProxyAddr)
	}
	if resp.License != "enterprise" {
		t.Errorf("license = %q", resp.License)
	}
	if resp.Commit != "deadbee" {
		t.Errorf("commit = %q, want truncated deadbee", resp.Commit)
	}
	if !resp.DemoOnly || !resp.ViewOnly {
		t.Errorf("demo/view flags not propagated: demo=%v view=%v", resp.DemoOnly, resp.ViewOnly)
	}
	if resp.Uptime == "" {
		t.Errorf("uptime should be non-empty")
	}
}

func TestHandleServerInfo_NilQueueMetricsTreatedAsZero(t *testing.T) {
	// fakeQueue with nil metrics — HandleServerInfo must fall back to a zero
	// QueueMetrics rather than panic.
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{metrics: nil}, nil, nil, nil)
	app := fiber.New()
	app.Get("/server-info", h.HandleServerInfo)

	status, body := doGet(t, app, "/server-info", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	var resp ServerInfoResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.QueueDepth != 0 {
		t.Errorf("queue_depth = %d, want 0 fallback", resp.QueueDepth)
	}
}

func TestHandleServerInfo_WithDBCounts(t *testing.T) {
	db, repo := newProjectModelTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)
	insertFinding(t, db, database.DefaultProjectUUID)

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{metrics: &queue.QueueMetrics{}}, db, repo, nil)
	app := fiber.New()
	app.Get("/server-info", h.HandleServerInfo)

	_, body := doGet(t, app, "/server-info", nil)
	var resp ServerInfoResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, body)
	}
	if resp.TotalRecords != 1 {
		t.Errorf("total_records = %d, want 1", resp.TotalRecords)
	}
	if resp.TotalFindings != 1 {
		t.Errorf("total_findings = %d, want 1", resp.TotalFindings)
	}
}

// -----------------------------------------------------------------------------
// countCache
// -----------------------------------------------------------------------------

// insertRecord adds a minimal valid HTTPRecord row directly via Bun.
func insertRecord(t *testing.T, db *database.DB, projectUUID string) {
	t.Helper()
	rec := &database.HTTPRecord{
		UUID:        "rec-" + projectUUID + "-" + randSuffix(),
		ProjectUUID: projectUUID,
		Scheme:      "https",
		Hostname:    "example.test",
		Port:        443,
		Method:      "GET",
		Path:        "/",
		URL:         "https://example.test/",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "hash-" + randSuffix(),
	}
	if _, err := db.NewInsert().Model(rec).Exec(context.Background()); err != nil {
		t.Fatalf("insert record: %v", err)
	}
}

// insertFinding adds a minimal valid Finding row directly via Bun.
func insertFinding(t *testing.T, db *database.DB, projectUUID string) {
	t.Helper()
	f := &database.Finding{
		ProjectUUID:     projectUUID,
		HTTPRecordUUIDs: []string{"rec-x"},
		ModuleID:        "test-module",
		ModuleName:      "Test Module",
		Severity:        "high",
		Confidence:      "firm",
		FindingHash:     "fhash-" + randSuffix(),
		FoundAt:         time.Now().UTC(),
	}
	if _, err := db.NewInsert().Model(f).Exec(context.Background()); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
}

var randCounter int

func randSuffix() string {
	randCounter++
	return time.Now().Format("150405.000000000") + "-" + itoa(randCounter)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestCountCache_RefreshAndCache(t *testing.T) {
	db, _ := newProjectModelTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)
	insertFinding(t, db, database.DefaultProjectUUID)

	// Large TTL: first Get reads from DB, subsequent Gets within TTL are cached.
	cc := newCountCache(time.Hour)
	rec, fnd := cc.Get(db)
	if rec != 1 || fnd != 1 {
		t.Fatalf("first Get = (%d,%d), want (1,1)", rec, fnd)
	}

	// Mutate the DB, then Get again. Because we're inside the TTL the cache must
	// NOT refresh — it should still report the stale (1,1).
	insertRecord(t, db, database.DefaultProjectUUID)
	insertFinding(t, db, database.DefaultProjectUUID)
	rec, fnd = cc.Get(db)
	if rec != 1 || fnd != 1 {
		t.Errorf("cached Get after mutation = (%d,%d), want stale (1,1) within TTL", rec, fnd)
	}
}

func TestCountCache_ExpiredTTLRefreshes(t *testing.T) {
	db, _ := newProjectModelTestDB(t)
	insertRecord(t, db, database.DefaultProjectUUID)

	// Zero TTL → every Get is considered expired and refreshes from the DB.
	cc := newCountCache(0)
	if rec, _ := cc.Get(db); rec != 1 {
		t.Fatalf("first Get records = %d, want 1", rec)
	}

	insertRecord(t, db, database.DefaultProjectUUID)
	insertRecord(t, db, database.DefaultProjectUUID)
	if rec, _ := cc.Get(db); rec != 3 {
		t.Errorf("expired-TTL Get records = %d, want 3 (refreshed)", rec)
	}
}

// -----------------------------------------------------------------------------
// Scan-state accessors: getProjectScanState / IsScanRunning
// -----------------------------------------------------------------------------

func TestScanStateAccessors(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)

	// No scans yet.
	if h.IsScanRunning() {
		t.Fatalf("IsScanRunning should be false with no scans")
	}

	// getProjectScanState lazily creates an entry and returns the same pointer.
	h.scanMu.Lock()
	st1 := h.getProjectScanState("proj-a")
	st2 := h.getProjectScanState("proj-a")
	h.scanMu.Unlock()
	if st1 != st2 {
		t.Fatalf("getProjectScanState returned different pointers for same project")
	}
	if st1.running {
		t.Errorf("new scan state should not be running")
	}

	// Mark proj-a running → IsScanRunning true.
	h.scanMu.Lock()
	st1.running = true
	h.scanMu.Unlock()
	if !h.IsScanRunning() {
		t.Errorf("IsScanRunning should be true once a project is running")
	}

	// A second, distinct project gets its own state.
	h.scanMu.Lock()
	stB := h.getProjectScanState("proj-b")
	h.scanMu.Unlock()
	if stB == st1 {
		t.Errorf("distinct projects must not share scan state")
	}

	// Clearing the running flag flips IsScanRunning back to false.
	h.scanMu.Lock()
	st1.running = false
	h.scanMu.Unlock()
	if h.IsScanRunning() {
		t.Errorf("IsScanRunning should be false after clearing the only running scan")
	}
}

// -----------------------------------------------------------------------------
// NewServer config defaulting
// -----------------------------------------------------------------------------

func TestNewServer_AppliesConfigDefaults(t *testing.T) {
	// Pass a zero-value config (NoAgent so no engine spins up) and verify the
	// timeout/addr defaults are filled in.
	cfg := ServerConfig{NoAgent: true}
	s := NewServer(cfg, &fakeQueue{}, nil, nil, nil, nil, nil)
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	got := s.Config()
	if got.ServiceAddr != ":9002" {
		t.Errorf("ServiceAddr = %q, want :9002", got.ServiceAddr)
	}
	if got.ReadTimeout != 10*time.Second {
		t.Errorf("ReadTimeout = %v, want 10s", got.ReadTimeout)
	}
	if got.WriteTimeout != 60*time.Second {
		t.Errorf("WriteTimeout = %v, want 60s", got.WriteTimeout)
	}
	if got.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", got.IdleTimeout)
	}
	if got.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 30s", got.ShutdownTimeout)
	}
}

func TestNewServer_PreservesExplicitConfig(t *testing.T) {
	cfg := ServerConfig{
		NoAgent:         true,
		ServiceAddr:     "127.0.0.1:1234",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    7 * time.Second,
		IdleTimeout:     9 * time.Second,
		ShutdownTimeout: 11 * time.Second,
	}
	s := NewServer(cfg, &fakeQueue{}, nil, nil, nil, nil, nil)
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	got := s.Config()
	if got.ServiceAddr != "127.0.0.1:1234" {
		t.Errorf("ServiceAddr overwritten: %q", got.ServiceAddr)
	}
	if got.ReadTimeout != 5*time.Second {
		t.Errorf("ReadTimeout overwritten: %v", got.ReadTimeout)
	}
	if got.ShutdownTimeout != 11*time.Second {
		t.Errorf("ShutdownTimeout overwritten: %v", got.ShutdownTimeout)
	}
}

func TestServerQueueAccessor(t *testing.T) {
	q := &fakeQueue{}
	s := NewServer(ServerConfig{NoAgent: true}, q, nil, nil, nil, nil, nil)
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	if s.Queue() != q {
		t.Errorf("Queue() did not return the injected queue")
	}
}

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg.ServiceAddr != ":9002" {
		t.Errorf("ServiceAddr = %q", cfg.ServiceAddr)
	}
	if cfg.ReadTimeout != 10*time.Second {
		t.Errorf("ReadTimeout = %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 60*time.Second {
		t.Errorf("WriteTimeout = %v", cfg.WriteTimeout)
	}
}

// -----------------------------------------------------------------------------
// Auth handlers (pure logic, no live runtime)
// -----------------------------------------------------------------------------

func TestHandleLogin(t *testing.T) {
	const code = "vgl_login_secret_code"
	store := NewUserStore([]FileUser{
		{Name: "alice", Email: "alice@test.local", AccessCode: code, Role: RoleAdmin},
	})
	h := newBasicHandlers(t, ServerConfig{UserStore: store}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Post("/api/auth/login", h.HandleLogin)

	post := func(body string) (int, []byte) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}

	t.Run("valid credentials", func(t *testing.T) {
		status, body := post(`{"username":"alice","access_code":"` + code + `"}`)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", status, body)
		}
		var resp LoginResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Token != code {
			t.Errorf("token = %q, want %q", resp.Token, code)
		}
		if resp.User.Name != "alice" || resp.User.Role != RoleAdmin {
			t.Errorf("user mismatch: %+v", resp.User)
		}
	})

	t.Run("wrong access code", func(t *testing.T) {
		status, _ := post(`{"username":"alice","access_code":"nope"}`)
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		status, _ := post(`{"username":"alice"}`)
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		status, _ := post(`{not json`)
		if status != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", status)
		}
	})
}

func TestHandleUserInfo(t *testing.T) {
	t.Run("no user, no-auth mode returns admin", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{NoAuth: true}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Get("/api/user/info", h.HandleUserInfo)
		status, body := doGet(t, app, "/api/user/info", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		var u LoginUser
		_ = json.Unmarshal(body, &u)
		if u.Role != RoleAdmin {
			t.Errorf("role = %q, want admin in no-auth mode", u.Role)
		}
	})

	t.Run("no user, auth mode returns 401", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{NoAuth: false}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		app.Get("/api/user/info", h.HandleUserInfo)
		status, _ := doGet(t, app, "/api/user/info", nil)
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
	})

	t.Run("resolved user echoed back", func(t *testing.T) {
		h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
		app := fiber.New()
		// Inject a resolved user into locals before the handler runs.
		app.Get("/api/user/info", func(c fiber.Ctx) error {
			c.Locals(authUserLocalsKey, &ResolvedUser{
				UUID: "u-1", Name: "carol", Email: "carol@test.local", Role: RoleOperator,
			})
			return h.HandleUserInfo(c)
		})
		status, body := doGet(t, app, "/api/user/info", nil)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		var u LoginUser
		_ = json.Unmarshal(body, &u)
		if u.Name != "carol" || u.Role != RoleOperator || u.UUID != "u-1" {
			t.Errorf("user mismatch: %+v", u)
		}
	})
}
