package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// unlockWalkFixture is a client-gated SPA: /admin renders only with a token in
// localStorage and an admin role from GET /api/me (refused by the server),
// then reads GET /api/admin/users and sends POST /api/admin/audit.
const unlockWalkFixture = `<!doctype html><html><head><title>Fixture</title></head>
<body><div id="app">loading</div><script>
async function render() {
  const app = document.getElementById('app');
  const toLogin = () => { history.replaceState(null, '', '/login'); app.textContent = 'Please log in'; };
  if (location.pathname !== '/admin') { app.textContent = 'Welcome'; return; }
  const token = localStorage.getItem('token');
  if (!token) return toLogin();
  const me = await fetch('/api/me').then(r => r.ok ? r.json() : null).catch(() => null);
  if (!me || me.role !== 'admin') return toLogin();
  const users = await fetch('/api/admin/users').then(r => r.json());
  app.textContent = 'Admin panel: ' + users.length + ' users';
  fetch('/api/admin/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"event":"view"}' }).catch(() => {});
}
window.addEventListener('popstate', render);
render();
</script></body></html>`

type unlockWalkServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newUnlockWalkServer(t *testing.T) *unlockWalkServer {
	t.Helper()
	s := &unlockWalkServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		switch r.URL.Path {
		case "/api/me":
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/admin/users":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1},{"id":2}]`))
		case "/api/admin/audit":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(unlockWalkFixture))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *unlockWalkServer) saw(methodPath string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.seen {
		if v == methodPath {
			return true
		}
	}
	return false
}

func (s *unlockWalkServer) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func writeUnlockProfile(t *testing.T, doc string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "unlock.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A profile the walk cannot honour exits 2 before anything is launched or
// sent: the fixture sees no request.
func TestKitUnlockWalk_RefusesBeforeLaunch(t *testing.T) {
	srv := newUnlockWalkServer(t)
	st := seedC6Store(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no profile", nil, "--profile is required"},
		{"not json", []string{"--profile", writeUnlockProfile(t, `{"origin":`)}, "not a JSON unlock profile"},
		{"stub off origin", []string{"--profile", writeUnlockProfile(t, `{"origin":"`+srv.URL+`","stubs":[{"method":"GET","path":"https://evil.example/api/me","status":200}],"routes":["/admin"]}`)},
			"not on the profile origin"},
		{"route off origin", []string{"--profile", writeUnlockProfile(t, `{"origin":"`+srv.URL+`","routes":["https://evil.example/admin"]}`)}, "not on the profile origin"},
		{"origin pin", []string{"--profile", writeUnlockProfile(t, `{"origin":"`+srv.URL+`"}`), "--origin", "https://other.example"}, "is not the --origin"},
		{"empty scope required", []string{"--profile", writeUnlockProfile(t, `{"origin":"`+srv.URL+`"}`), "--require-scope"}, "names no hosts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"kit", "unlock-walk", "-j"}, tc.args...)
			code, out, errOut := st.run(t, args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2\n%s\n%s", code, out, errOut)
			}
			if !strings.Contains(out+errOut, tc.want) {
				t.Fatalf("output does not say %q:\n%s\n%s", tc.want, out, errOut)
			}
		})
	}
	if n := srv.requests(); n != 0 {
		t.Fatalf("a refused profile sent %d request(s) to the target", n)
	}
}

// End to end: the walk reaches the gated view, stores the real read as an
// unlock-walk record remarked client-unlocked, never stores the stub's
// response, and the write never reaches the server.
func TestKitUnlockWalk_StoresRealExchanges(t *testing.T) {
	if testing.Short() {
		t.Skip("launches a real browser")
	}
	srv := newUnlockWalkServer(t)
	st := seedC6Store(t)
	profile := writeUnlockProfile(t, `{"origin":"`+srv.URL+`","settleMs":3000,
		"localStorage":{"token":"forged"},
		"stubs":[{"method":"GET","path":"/api/me","status":200,"contentType":"application/json","body":"{\"role\":\"admin\"}"}],
		"routes":["/admin"]}`)

	code, out, errOut := st.run(t, "kit", "unlock-walk", "--profile", profile, "--origin", srv.URL, "-j")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	doc := decodeOne(t, out)
	it := items(t, doc)
	if len(it) != 1 || it[0]["stored"] != true {
		t.Fatalf("items = %v", it)
	}
	routes, _ := it[0]["routes"].([]any)
	if len(routes) != 1 {
		t.Fatalf("routes = %v", it[0]["routes"])
	}
	admin := routes[0].(map[string]any)
	if admin["redirected"] != false || !strings.Contains(admin["text_sample"].(string), "Admin panel: 2 users") {
		t.Fatalf("admin view not reached: %v", admin)
	}
	var usersUUID string
	for _, q := range admin["requests"].([]any) {
		q := q.(map[string]any)
		if strings.HasSuffix(q["url"].(string), "/api/admin/users") {
			usersUUID, _ = q["record_uuid"].(string)
		}
		if strings.HasSuffix(q["url"].(string), "/api/me") {
			t.Fatalf("the stubbed request is listed as real: %v", q)
		}
	}
	if usersUUID == "" {
		t.Fatalf("GET /api/admin/users has no record_uuid: %v", admin["requests"])
	}
	if aborted, _ := admin["aborted_writes"].([]any); len(aborted) != 1 {
		t.Fatalf("aborted_writes = %v", admin["aborted_writes"])
	}
	if srv.saw("POST /api/admin/audit") || srv.saw("GET /api/me") {
		t.Fatalf("a write or a stubbed request reached the server: %v", srv.seen)
	}

	repo, closeDB := openC6Repo(t, st)
	defer closeDB()
	ctx := context.Background()
	rec, err := repo.GetRecordByUUID(ctx, usersUUID)
	if err != nil {
		t.Fatalf("record %s: %v", usersUUID, err)
	}
	if rec.Source != "unlock-walk" || !strings.Contains(strings.Join(rec.Remarks, ","), "client-unlocked") {
		t.Fatalf("record source %q remarks %v, want unlock-walk + client-unlocked", rec.Source, rec.Remarks)
	}
	var stubbed int
	if err := repo.DB().NewRaw("SELECT COUNT(*) FROM http_records WHERE url LIKE ?", "%/api/me%").Scan(ctx, &stubbed); err != nil {
		t.Fatal(err)
	}
	if stubbed != 0 {
		t.Fatalf("%d record(s) hold the stubbed /api/me exchange", stubbed)
	}
}
