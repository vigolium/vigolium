package go_debug_endpoint_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

const (
	heapBody = "heap profile: 12: 2097152 [34: 8388608] @ heap/1048576\n" +
		"1: 1048576 [1: 1048576] @ 0x47a1b2 0x47b3c4\n" +
		"# runtime.MemStats\n# Alloc = 2097152\n# HeapAlloc = 2097152\n# NumGC = 3\n"
	goroutineBody = "goroutine profile: total 7\n3 @ 0x43a1b2 0x44c3d4\n#\t0x43a1b1\tmain.handler+0x21\n"
	cmdlineBody   = "/usr/local/bin/myapp\x00--config\x00/etc/app.conf\x00--db-token\x00s3cr3t\x00"
	expvarBody    = `{"cmdline":["/usr/local/bin/myapp","-port=8080"],"memstats":{"Alloc":2097152,"HeapAlloc":2097152,"NumGC":3,"PauseNs":[0,0]}}`
	symbolBody    = "num_symbols: 1\n"
	indexBody     = `<html><head><title>/debug/pprof/</title></head><body>
/debug/pprof/<br>
Types of profiles available:
<table><tr><td>5</td><td><a href="goroutine?debug=1">goroutine</a></td></tr></table>
<a href="goroutine?debug=2">full goroutine stack dump</a>
</body></html>`
)

// servePprofText writes a pprof text-profile response (status 200, text/plain),
// mirroring the real handler so the module's Content-Type gate is exercised.
func servePprofText(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// pprofTextServer returns a server that serves body as a pprof text profile only
// at exactPath and 404s every other path — the shape a real pprof mux presents
// (an unknown sub-path is "not found"), and the setup most detection tests need.
func pprofTextServer(exactPath, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == exactPath {
			servePprofText(w, body)
			return
		}
		http.NotFound(w, r)
	}))
}

// TestScanPerRequest_DetectsHeap drives the scan against a host exposing
// /debug/pprof/heap and 404ing every unknown sub-path (as a real pprof mux does),
// so the soft-404, sibling-catch-all, and reproduce gates all pass and the High
// heap finding fires.
func TestScanPerRequest_DetectsHeap(t *testing.T) {
	t.Parallel()
	srv := pprofTextServer("/debug/pprof/heap", heapBody)
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected exactly the heap finding")
	assert.Equal(t, "Go pprof Heap Profile Exposed", res[0].Info.Name)
	assert.Equal(t, "medium", res[0].Info.Severity.String())
	assert.Contains(t, res[0].URL, "/debug/pprof/heap")
}

// TestScanPerRequest_DetectsCmdline confirms the command-line handler (NUL-joined
// os.Args) is recognized and reported High.
func TestScanPerRequest_DetectsCmdline(t *testing.T) {
	t.Parallel()
	srv := pprofTextServer("/debug/pprof/cmdline", cmdlineBody)
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "Go pprof Command Line Exposed", res[0].Info.Name)
	assert.Equal(t, "medium", res[0].Info.Severity.String())
}

// TestScanPerRequest_DetectsGoroutine confirms the goroutine dump header anchor.
func TestScanPerRequest_DetectsGoroutine(t *testing.T) {
	t.Parallel()
	srv := pprofTextServer("/debug/pprof/goroutine", goroutineBody)
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "Go pprof Goroutine Dump Exposed", res[0].Info.Name)
}

// TestScanPerRequest_DetectsExpvar confirms /debug/vars (cmdline+memstats JSON) is
// recognized independently of the pprof mux.
func TestScanPerRequest_DetectsExpvar(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/vars" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(expvarBody))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "Go expvar Debug Variables Exposed", res[0].Info.Name)
}

// TestScanPerRequest_IndexInfersProfileAndTraceWithoutInvoking verifies the
// DoS-safe path: a confirmed index yields the index finding plus the inferred
// /profile and /trace findings, while the scanner NEVER requests /profile or
// /trace (which would load the target).
func TestScanPerRequest_IndexInfersProfileAndTraceWithoutInvoking(t *testing.T) {
	t.Parallel()
	var profileHit, traceHit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/debug/pprof/profile":
			profileHit.Store(true)
			http.NotFound(w, r)
		case "/debug/pprof/trace":
			traceHit.Store(true)
			http.NotFound(w, r)
		case "/debug/pprof/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(indexBody))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)

	names := findingNames(res)
	assert.Contains(t, names, "Go pprof Debug Index Exposed")
	assert.Contains(t, names, "Go pprof CPU Profile Endpoint Exposed")
	assert.Contains(t, names, "Go pprof Execution Trace Endpoint Exposed")
	assert.False(t, profileHit.Load(), "the scanner must never request /debug/pprof/profile (DoS)")
	assert.False(t, traceHit.Load(), "the scanner must never request /debug/pprof/trace (DoS)")
}

// TestScanPerRequest_WalksContextPath confirms a pprof handler mounted under a
// context path (/api/debug/pprof/heap) is found from a seed URL deeper in that
// tree — the path-walking requirement.
func TestScanPerRequest_WalksContextPath(t *testing.T) {
	t.Parallel()
	srv := pprofTextServer("/api/debug/pprof/heap", heapBody)
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/api/v1/users"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "context-path-mounted pprof must be found via path walking")
	assert.Contains(t, res[0].URL, "/api/debug/pprof/heap")
}

// TestScanPerRequest_NoFalsePositiveOn404 ensures a host that 404s every probe
// yields nothing.
func TestScanPerRequest_NoFalsePositiveOn404(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/api/v1/users"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

// TestScanPerRequest_SubDirCatchAllSuppressed ensures the sibling-path baseline
// drops a catch-all scoped to the /debug/pprof/ prefix: every child returns the
// heap body, so a guaranteed-nonexistent sibling matches the same markers and the
// finding is suppressed even though the root soft-404 probe (a 404 at the root)
// cannot see it.
func TestScanPerRequest_SubDirCatchAllSuppressed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
			servePprofText(w, heapBody) // same body for EVERY child path
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a sub-directory catch-all serving the heap body for every child must be suppressed")
}

// TestScanPerRequest_DeepOnlyEndpointsGated confirms a Low-value handler (symbol)
// is skipped at normal intensity and probed only when DeepScan is set.
func TestScanPerRequest_DeepOnlyEndpointsGated(t *testing.T) {
	t.Parallel()
	srv := pprofTextServer("/debug/pprof/symbol", symbolBody)
	defer srv.Close()

	normal, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, normal, "symbol is deep-only and must not be probed at normal intensity")

	deep, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{DeepScan: true})
	require.NoError(t, err)
	require.Len(t, deep, 1, "symbol must be probed under DeepScan")
	assert.Equal(t, "Go pprof Symbol Endpoint Exposed", deep[0].Info.Name)
}

func findingNames(res []*output.ResultEvent) []string {
	names := make([]string, 0, len(res))
	for _, r := range res {
		names = append(names, r.Info.Name)
	}
	return names
}
