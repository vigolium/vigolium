package spitolas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// unlockFixtureSPA is a client-gated app: /admin renders only with a token in
// localStorage and an admin role from GET /api/me (which the real server
// refuses), then reads GET /api/admin/users and sends POST /api/admin/audit.
// Without the token the client guard sends the visitor to /login.
const unlockFixtureSPA = `<!doctype html><html><head><title>Fixture</title></head>
<body><div id="app">loading</div><script>
async function render() {
  const app = document.getElementById('app');
  const toLogin = () => { history.replaceState(null, '', '/login'); document.title = 'Login'; app.textContent = 'Please log in'; };
  if (location.pathname === '/admin') {
    const token = localStorage.getItem('token');
    if (!token) return toLogin();
    const me = await fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } })
      .then(r => r.ok ? r.json() : null).catch(() => null);
    if (!me || me.role !== 'admin') return toLogin();
    const users = await fetch('/api/admin/users').then(r => r.json());
    document.title = 'Admin';
    app.textContent = 'Admin panel: ' + users.length + ' users';
    fetch('/api/admin/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: 'view-admin' }) }).catch(() => {});
    return;
  }
  if (location.pathname === '/login') { document.title = 'Login'; app.textContent = 'Please log in'; return; }
  document.title = 'Home'; app.textContent = 'Welcome home';
}
window.addEventListener('popstate', render);
render();
</script></body></html>`

// unlockFixture serves unlockFixtureSPA and counts what reached the server.
type unlockFixture struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string // "METHOD /path"
}

func newUnlockFixture(t *testing.T) *unlockFixture {
	t.Helper()
	f := &unlockFixture{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		switch r.URL.Path {
		case "/api/me":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"not logged in"}`))
		case "/api/admin/users":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1,"name":"ada"},{"id":2,"name":"bob"}]`))
		case "/api/admin/audit":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(unlockFixtureSPA))
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *unlockFixture) count(methodPath string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.seen {
		if s == methodPath {
			n++
		}
	}
	return n
}

func runFixtureWalk(t *testing.T, doc string) (*UnlockWalkResult, *memWalkSink) {
	t.Helper()
	p := mustProfile(t, doc)
	sink := &memWalkSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := UnlockWalk(ctx, UnlockWalkConfig{Profile: p, Sink: sink})
	if err != nil {
		t.Fatalf("UnlockWalk: %v", err)
	}
	if len(res.Routes) != 1 {
		t.Fatalf("routes = %+v, want one", res.Routes)
	}
	return res, sink
}

func TestUnlockWalkReachesGatedView(t *testing.T) {
	if testing.Short() {
		t.Skip("launches a real browser")
	}
	f := newUnlockFixture(t)
	res, sink := runFixtureWalk(t, `{"origin":"`+f.URL+`","settleMs":3000,
		"localStorage":{"token":"forged-token"},
		"stubs":[{"method":"GET","path":"/api/me","status":200,"contentType":"application/json","body":"{\"role\":\"admin\"}"}],
		"routes":["/admin"]}`)

	admin := res.Routes[0]
	if admin.Redirected || !strings.HasSuffix(admin.FinalURL, "/admin") || !strings.Contains(admin.TextSample, "Admin panel: 2 users") {
		t.Fatalf("admin view not reached: %+v", admin)
	}
	if admin.Title != "Admin" {
		t.Errorf("title = %q, want Admin", admin.Title)
	}

	// The real read is reported with the record it is stored as.
	var users *UnlockRequest
	for i, q := range admin.Requests {
		if q.Method == "GET" && strings.HasSuffix(q.URL, "/api/admin/users") {
			users = &admin.Requests[i]
		}
	}
	if users == nil || users.Status != 200 || !strings.HasPrefix(users.RecordUUID, "rec-") {
		t.Fatalf("GET /api/admin/users not reported as a stored real request: %+v", admin.Requests)
	}

	// The write was failed in the browser and reported by shape.
	if len(admin.AbortedWrites) != 1 || admin.AbortedWrites[0].Method != "POST" ||
		!strings.HasSuffix(admin.AbortedWrites[0].URL, "/api/admin/audit") ||
		!strings.Contains(admin.AbortedWrites[0].Body, "view-admin") || admin.AbortedWrites[0].ContentType != "application/json" {
		t.Fatalf("aborted writes = %+v", admin.AbortedWrites)
	}
	if n := f.count("POST /api/admin/audit"); n != 0 {
		t.Fatalf("the server received %d POST /api/admin/audit; writes must never leave the browser", n)
	}

	// The stub answered /api/me in the browser: the server never saw it, it
	// is not stored and it is not listed as a request.
	if len(admin.StubsHit) != 1 || admin.StubsHit[0].Path != "/api/me" || len(res.StubsNeverHit) != 0 {
		t.Fatalf("stubs hit = %+v, never hit = %+v", admin.StubsHit, res.StubsNeverHit)
	}
	if n := f.count("GET /api/me"); n != 0 {
		t.Fatalf("the server received %d GET /api/me; the stub must answer it", n)
	}
	for _, u := range sink.urls {
		if strings.HasSuffix(u, "/api/me") {
			t.Fatalf("the stubbed /api/me response was stored: %v", sink.urls)
		}
	}
	for _, q := range admin.Requests {
		if strings.HasSuffix(q.URL, "/api/me") {
			t.Fatalf("the stubbed request is listed as real: %+v", admin.Requests)
		}
	}
	if !slices.ContainsFunc(sink.urls, func(u string) bool { return strings.HasSuffix(u, "/api/admin/users") }) {
		t.Fatalf("the real read was not stored: %v", sink.urls)
	}
	if res.Totals.Rendered != 1 || res.Totals.AbortedWrites != 1 || res.Totals.StubsHit != 1 || res.Totals.RecordsStored < 2 {
		t.Errorf("totals = %+v", res.Totals)
	}
}

func TestUnlockWalkWithoutProfileIsRedirected(t *testing.T) {
	if testing.Short() {
		t.Skip("launches a real browser")
	}
	f := newUnlockFixture(t)
	res, _ := runFixtureWalk(t, `{"origin":"`+f.URL+`","routes":["/admin"]}`)
	admin := res.Routes[0]
	if !admin.Redirected || !strings.HasSuffix(admin.FinalURL, "/login") || !strings.Contains(admin.TextSample, "Please log in") {
		t.Fatalf("without the profile the guard must redirect: %+v", admin)
	}
	if f.count("GET /api/admin/users") != 0 || len(admin.AbortedWrites) != 0 {
		t.Fatalf("the gated view ran without the profile: seen %v, aborted %+v", f.seen, admin.AbortedWrites)
	}
	if res.Totals.Redirected != 1 || res.Totals.Rendered != 0 {
		t.Errorf("totals = %+v", res.Totals)
	}
}
