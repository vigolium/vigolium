package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// fingerprintFixture is an origin with a page, a linked icon, robots.txt, a
// reflective CORS policy, an Allow header, a 404 for /missing.txt, and a soft
// 404: every other unknown path answers 200 with the same "not found" page.
type fingerprintFixture struct {
	srv     *httptest.Server
	mu      sync.Mutex
	methods map[string]int
	hits    int
	// dropFor is path -> how long after its first request every request for
	// it has its connection closed without an answer (the transport's own
	// immediate re-sends land inside the window); hitsAt is path -> when each
	// request for it arrived.
	dropFor map[string]time.Duration
	hitsAt  map[string][]time.Time
}

var fixtureIcon = []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("icon-bytes", 20))

func newFingerprintFixture(t *testing.T) *fingerprintFixture {
	t.Helper()
	f := &fingerprintFixture{methods: map[string]int{}, dropFor: map[string]time.Duration{}, hitsAt: map[string][]time.Time{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.methods[r.Method]++
		f.hits++
		now := time.Now()
		f.hitsAt[r.URL.Path] = append(f.hitsAt[r.URL.Path], now)
		window, drop := f.dropFor[r.URL.Path]
		drop = drop && now.Sub(f.hitsAt[r.URL.Path][0]) < window
		f.mu.Unlock()
		if drop {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Server", "fixture/1.0")
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Fixture App</title><link rel="icon" href="/static/icon.png"></head><body>home</body></html>`))
		case "/static/icon.png":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(fixtureIcon)
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
		case "/missing.txt":
			http.NotFound(w, r)
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>About us</title></head><body><h1>About</h1><p>a real page with different content</p></body></html>`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>Page not found</title></head><body>Sorry, nothing here.</body></html>`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestFingerprintStoresHostFacts(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")

	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	assert.Equal(t, "fingerprint", doc["command"])
	items := doc["items"].([]any)
	require.Len(t, items, 1, "one origin")
	host := items[0].(map[string]any)
	assert.Equal(t, "Fixture App", host["title"])
	assert.Equal(t, "fixture/1.0", host["server"])
	assert.EqualValues(t, recon.ShodanFaviconHash(fixtureIcon), host["favicon_mmh3"])
	assert.Equal(t, true, host["soft_not_found"])
	fp := host["fingerprint"].(map[string]any)
	assert.Equal(t, "standard", fp["depth"])
	require.NotNil(t, fp["cors"])
	assert.Equal(t, true, fp["cors"].(map[string]any)["reflective"])

	f.mu.Lock()
	methods := map[string]int{}
	for k, v := range f.methods {
		methods[k] = v
	}
	hits := f.hits
	f.mu.Unlock()
	for m := range methods {
		assert.Contains(t, []string{"GET", "HEAD", "OPTIONS", "POST"}, m, "only reads are sent")
	}

	// Every request the phase sent is a stored record, source fingerprint.
	code, stdout, stderr = runA3(t, home, "traffic", "-j", "--compact", "--source", "fingerprint", "--all", "--fields", "uuid")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	stored := oneDoc(t, stdout, stderr)["total"].(float64)
	assert.Positive(t, stored)
	assert.LessOrEqual(t, int(stored), hits, "never more records than requests the origin saw")

	// The not-found baseline separates a real page from the soft-404 template,
	// and counts a genuine 404 as not found.
	code, stdout, stderr = runA3(t, home, "hosts", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	nf := oneDoc(t, stdout, stderr)["items"].([]any)[0].(map[string]any)["not_found"].(map[string]any)
	assert.EqualValues(t, 200, nf["status"])
	assert.NotEmpty(t, nf["signature"])
}

func TestFingerprintLightDepthAndBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")

	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "light", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	f.mu.Lock()
	light := f.hits
	f.hits = 0
	f.mu.Unlock()
	assert.LessOrEqual(t, light, 14, "light depth stays near nine reads (plus the scheme/preflight checks)")

	code, stdout, stderr = runA3(t, home, "fingerprint", "-t", f.srv.URL, "--max-requests-per-host", "5", "-j")
	f.mu.Lock()
	budgeted := f.hits
	f.mu.Unlock()
	assert.LessOrEqual(t, budgeted, 6, "the request budget holds for the phase (stdout:\n%s\nstderr:\n%s)", stdout, stderr)
	_ = code

	code, _, _ = runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "deep")
	assert.Equal(t, 2, code, "an unknown depth is a usage error")
}

func TestFingerprintRefusesOutOfScopeTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "nomatch.example")
	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "-j")
	require.Equal(t, 2, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, string(apicontract.CodeOutOfScope), errorCode(t, stdout))
	f.mu.Lock()
	defer f.mu.Unlock()
	assert.Zero(t, f.hits, "an out-of-scope target is refused before any request")
}

// After a fingerprint, traffic rows say whether they are the origin's
// not-found page: the soft-404 template and a real 404 are, a real page is not.
func TestTrafficMatchesNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")
	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "light", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	list := t.TempDir() + "/urls.txt"
	require.NoError(t, writeFile(list, f.srv.URL+"/no-such-page-xyz\n"+f.srv.URL+"/missing.txt\n"+f.srv.URL+"/about\n"))
	code, stdout, stderr = runA3(t, home, "ingest", "-i", list, "--fetch-responses", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	urls := []string{"--url", f.srv.URL + "/no-such-page-xyz", "--url", f.srv.URL + "/missing.txt", "--url", f.srv.URL + "/about"}
	code, stdout, stderr = runA3(t, home, append([]string{"traffic", "-j", "--fields", "url,matches_not_found"}, urls...)...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	got := map[string]any{}
	for _, it := range oneDoc(t, stdout, stderr)["items"].([]any) {
		row := it.(map[string]any)
		u := row["url"].(string)
		got[u[strings.LastIndex(u, "/"):]] = row["matches_not_found"]
	}
	assert.Equal(t, true, got["/no-such-page-xyz"], "the soft-404 template is the not-found page")
	assert.Equal(t, true, got["/missing.txt"], "a 404 is not found")
	assert.Equal(t, false, got["/about"], "a real page is not")

	code, stdout, stderr = runA3(t, home, append([]string{"traffic", "-j", "--exclude-not-found", "--fields", "url"}, urls...)...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	assert.Len(t, doc["items"], 1)
	assert.EqualValues(t, 2, doc["not_found_excluded"])
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

// Every entry point to a fingerprint-only run shapes the document as host
// facts: `--fields` takes the hosts vocabulary, and `run fingerprint` sets the
// depth with --fingerprint-depth.
func TestFingerprintDocumentShapesAsHosts(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")

	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "light", "-j", "--fields", "hostname,title,favicon_mmh3")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	row := oneDoc(t, stdout, stderr)["items"].([]any)[0].(map[string]any)
	assert.Len(t, row, 3)
	assert.Equal(t, "Fixture App", row["title"])

	code, stdout, stderr = runA3(t, home, "run", "fingerprint", "-t", f.srv.URL, "--fingerprint-depth", "light", "-j", "--compact")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	host := oneDoc(t, stdout, stderr)["items"].([]any)[0].(map[string]any)
	assert.Equal(t, "Fixture App", host["title"])
	assert.NotContains(t, host, "fingerprint", "--compact drops the nested report")
}

// fingerprintReport runs `fingerprint -j` and returns the one origin's nested
// report.
func fingerprintReport(t *testing.T, home string, args ...string) map[string]any {
	t.Helper()
	code, stdout, stderr := runA3(t, home, append([]string{"fingerprint", "-j"}, args...)...)
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	items := doc["items"].([]any)
	require.Len(t, items, 1)
	return items[0].(map[string]any)["fingerprint"].(map[string]any)
}

// A probe whose connection drops is asked once more after a backoff, and the
// second answer is the one the report reads: no error, the path is found. The
// drop window outlasts the transport's immediate re-sends, so only the phase's
// own retry can recover the read.
func TestFingerprintRetriesADroppedProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	f.dropFor["/robots.txt"] = 300 * time.Millisecond
	home := a3Home(t, "*")

	fp := fingerprintReport(t, home, "-t", f.srv.URL, "--depth", "light", "--retries", "0")
	assert.NotContains(t, fp, "errors", "the retry answered")
	assert.Nil(t, fp["probe_errors"])
	var paths []string
	for _, w := range fp["well_known"].([]any) {
		paths = append(paths, w.(map[string]any)["path"].(string))
	}
	assert.Contains(t, paths, "/robots.txt")
}

// A probe that never answers is retried once and then listed in errors[] as a
// network failure; probe_errors counts it.
func TestFingerprintListsProbeErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	f.dropFor["/robots.txt"] = time.Hour
	home := a3Home(t, "*")

	fp := fingerprintReport(t, home, "-t", f.srv.URL, "--depth", "light", "--retries", "0")
	assert.EqualValues(t, 1, fp["probe_errors"])
	errs := fp["errors"].([]any)
	require.Len(t, errs, 1)
	e := errs[0].(map[string]any)
	assert.Equal(t, "/robots.txt", e["path"])
	assert.Equal(t, "network", e["kind"])
	assert.Equal(t, "well-known", e["probe"])
	assert.NotEmpty(t, e["error"])
	f.mu.Lock()
	hits := f.hitsAt["/robots.txt"]
	f.mu.Unlock()
	require.NotEmpty(t, hits)
	assert.GreaterOrEqual(t, hits[len(hits)-1].Sub(hits[0]), 500*time.Millisecond, "the retry comes after the backoff")

	// The request budget's refusals are named as such, not as network
	// failures.
	fp = fingerprintReport(t, home, "-t", f.srv.URL, "--depth", "light", "--max-requests-per-host", "3")
	errs = fp["errors"].([]any)
	require.NotEmpty(t, errs)
	kinds := map[string]int{}
	for _, raw := range errs {
		kinds[raw.(map[string]any)["kind"].(string)]++
	}
	assert.Positive(t, kinds["budget"], "%v", errs)
	assert.EqualValues(t, len(errs), fp["probe_errors"], "probe_errors counts every listed error")
}
