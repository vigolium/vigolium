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

// unlockClickFixtureSPA renders /admin only for a token and role admin from
// GET /api/me (the real server answers 401), then shows controls that fire
// their calls only when clicked: a search (a GET), an export (a POST), and
// two destructive controls a GET could still act on (a purge button fetching
// GET /api/admin/purge, a logout link).
const unlockClickFixtureSPA = `<!doctype html><html><head><title>Fixture</title></head>
<body><div id="app">loading</div><script>
async function render() {
  const app = document.getElementById('app');
  const toLogin = () => { history.replaceState(null, '', '/login'); document.title = 'Login'; app.textContent = 'Please log in'; };
  if (location.pathname === '/admin') {
    if (!localStorage.getItem('token')) return toLogin();
    const me = await fetch('/api/me').then(r => r.ok ? r.json() : null).catch(() => null);
    if (!me || me.role !== 'admin') return toLogin();
    document.title = 'Admin';
    app.innerHTML = '<p>Admin panel</p>' +
      '<button id="search">Search</button>' +
      '<button id="export">Export</button>' +
      '<button id="purge">Delete all users</button>' +
      '<a id="out" href="/logout">Log out</a>';
    document.getElementById('search').onclick = () => fetch('/api/admin/search?q=').catch(() => {});
    document.getElementById('export').onclick = () => fetch('/api/admin/export', { method: 'POST', body: 'all' }).catch(() => {});
    document.getElementById('purge').onclick = () => fetch('/api/admin/purge').catch(() => {});
    return;
  }
  if (location.pathname === '/login') { document.title = 'Login'; app.textContent = 'Please log in'; return; }
  document.title = 'Home'; app.textContent = 'Welcome home';
}
window.addEventListener('popstate', render);
render();
</script></body></html>`

func newUnlockClickFixture(t *testing.T) *unlockFixture {
	t.Helper()
	f := &unlockFixture{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		switch r.URL.Path {
		case "/api/me":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"not logged in"}`))
		case "/api/admin/search", "/api/admin/purge", "/api/admin/export":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(unlockClickFixtureSPA))
		}
	}))
	t.Cleanup(f.Close)
	return f
}

const unlockClickProfile = `,"settleMs":3000,"localStorage":{"token":"forged"},
	"rewrites":[{"method":"GET","path":"/api/me","status":200,"set":[{"pointer":"/role","value":"admin"}]}],
	"routes":["/admin"]}`

// A rewrite turns the real 401 into an admin answer and the view renders; the
// rewritten exchange is reported as a rewrite and never stored. The click
// loop fires the search (stored, via click) and the export (a write, failed
// and reported by shape), and never clicks the destructive controls.
func TestUnlockWalkRewriteAndClicks(t *testing.T) {
	if testing.Short() {
		t.Skip("launches a real browser")
	}
	f := newUnlockClickFixture(t)
	res, sink := runFixtureWalk(t, `{"origin":"`+f.URL+`"`+unlockClickProfile)
	admin := res.Routes[0]
	if admin.Redirected || !strings.Contains(admin.TextSample, "Admin panel") {
		t.Fatalf("the rewrite did not unlock the view: %+v", admin)
	}

	// The rewritten answer: real request, never evidence.
	if f.count("GET /api/me") == 0 {
		t.Fatalf("a rewritten request must reach the target; seen %v", f.seen)
	}
	if len(admin.RewritesHit) == 0 || !admin.RewritesHit[0].Applied || admin.RewritesHit[0].UpstreamStatus != 401 || admin.RewritesHit[0].Status != 200 {
		t.Fatalf("rewrites_hit = %+v", admin.RewritesHit)
	}
	for _, u := range sink.urls {
		if strings.HasSuffix(u, "/api/me") {
			t.Fatalf("the rewritten /api/me exchange was stored: %v", sink.urls)
		}
	}
	for _, q := range admin.Requests {
		if strings.HasSuffix(q.URL, "/api/me") {
			t.Fatalf("the rewritten request is listed as real: %+v", admin.Requests)
		}
	}

	// The clicks.
	if f.count("GET /api/admin/search") == 0 {
		t.Fatalf("the search click sent nothing; clicks %+v, seen %v", admin.Clicks, f.seen)
	}
	var search *UnlockRequest
	for i, q := range admin.Requests {
		if strings.Contains(q.URL, "/api/admin/search") {
			search = &admin.Requests[i]
		}
	}
	if search == nil || search.Via != "click" || search.RecordUUID == "" {
		t.Fatalf("the search request is not reported as a stored click request: %+v", admin.Requests)
	}
	if n := f.count("POST /api/admin/export"); n != 0 {
		t.Fatalf("a click's write reached the server %d time(s)", n)
	}
	exported := false
	for _, a := range admin.AbortedWrites {
		if strings.HasSuffix(a.URL, "/api/admin/export") && a.Via == "click" {
			exported = true
		}
	}
	if !exported {
		t.Fatalf("the export click's write is not reported by shape: %+v", admin.AbortedWrites)
	}
	if f.count("GET /api/admin/purge") != 0 || f.count("GET /logout") != 0 {
		t.Fatalf("a destructive control was clicked: seen %v, clicks %+v", f.seen, admin.Clicks)
	}
	if admin.ClicksSkippedDestructive < 2 {
		t.Errorf("clicks_skipped_destructive = %d, want the purge button and the logout link", admin.ClicksSkippedDestructive)
	}
	kinds := map[string]bool{}
	for _, c := range admin.Clicks {
		kinds[c.Kind] = true
	}
	if !kinds[unlockTriggerSearch] || !kinds[unlockTriggerExport] {
		t.Errorf("clicks = %+v", admin.Clicks)
	}
	if res.Totals.Clicks != len(admin.Clicks) || res.Totals.RewritesApplied == 0 || res.ClicksRefused != "" {
		t.Errorf("totals = %+v, clicks_refused %q", res.Totals, res.ClicksRefused)
	}
}

// Under a write grant the walk clicks nothing and says why.
func TestUnlockWalkRefusesClicksUnderWriteGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("launches a real browser")
	}
	f := newUnlockClickFixture(t)
	p := mustProfile(t, `{"origin":"`+f.URL+`"`+unlockClickProfile)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := UnlockWalk(ctx, UnlockWalkConfig{Profile: p, Sink: &memWalkSink{}, AllowWrites: true})
	if err != nil {
		t.Fatalf("UnlockWalk: %v", err)
	}
	admin := res.Routes[0]
	if admin.Redirected || !strings.Contains(admin.TextSample, "Admin panel") {
		t.Fatalf("view not reached: %+v", admin)
	}
	if res.ClicksRefused != "writes_allowed" || len(admin.Clicks) != 0 || res.Totals.Clicks != 0 {
		t.Fatalf("clicks under a write grant: refused %q, clicks %+v", res.ClicksRefused, admin.Clicks)
	}
	if f.count("GET /api/admin/search") != 0 || f.count("POST /api/admin/export") != 0 {
		t.Fatalf("a control was clicked under a write grant: seen %v", f.seen)
	}
}
