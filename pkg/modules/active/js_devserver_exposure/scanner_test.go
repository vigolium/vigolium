package js_devserver_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.ID() != ModuleID {
		t.Errorf("ID = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name = %q, want %q", m.Name(), ModuleName)
	}
}

func TestDevProbes(t *testing.T) {
	if len(devProbes) == 0 {
		t.Fatal("expected at least one dev probe")
	}
	for _, p := range devProbes {
		if p.path == "" {
			t.Error("probe path is empty")
		}
		if p.name == "" {
			t.Error("probe name is empty")
		}
		if p.desc == "" {
			t.Errorf("probe %q has no description", p.name)
		}
	}
}

// TestScanPerRequest_SPACatchAllNoFalsePositive reproduces the metaframework FP
// class on this module: a single-page-app behind a catch-all reverse proxy that
// serves a 200 text/html shell for EVERY path — and varies it per path (echoing
// the path) so the exact-hash 404 fingerprint does NOT catch it. The marker-less
// probes (/__remix_dev/, /__open-in-editor, /__esbuild__/, /__parcel_hmr/) must
// not fire on the HTML shell.
func TestScanPerRequest_SPACatchAllNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Echo the path so every response differs — defeating the 404 hash gate
		// and proving the HTML-shell gate is what rejects the finding.
		_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="en"><head>` +
			`<meta name="viewport" content="width=device-width,initial-scale=1">` +
			`<title>app ` + r.URL.Path + `</title></head><body><div id="root"></div></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an SPA catch-all serving an HTML shell for every path must not yield a dev-server finding")
}

// TestScanPerRequest_DetectsEsbuildSSE drives a host that exposes a real esbuild
// dev endpoint (a non-HTML event stream) at /__esbuild__/ while 404ing the
// fingerprint path, and asserts the finding still fires.
func TestScanPerRequest_DetectsEsbuildSSE(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/__esbuild__/") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: change\ndata: {\"added\":[],\"removed\":[]}\n\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>app</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a real non-HTML esbuild dev endpoint must still be detected")
	assert.True(t, strings.Contains(res[0].Info.Name, "esbuild"), "finding should name the esbuild dev server")
}

// TestIsHTMLShell covers the shell-detection helper directly.
func TestIsHTMLShell(t *testing.T) {
	t.Parallel()
	assert.True(t, isHTMLShell("text/html; charset=utf-8", ""))
	assert.True(t, isHTMLShell("", "<!DOCTYPE html><html></html>"))
	assert.True(t, isHTMLShell("", "  <html><body>x</body></html>"))
	assert.False(t, isHTMLShell("text/event-stream", "event: change\ndata: {}"))
	assert.False(t, isHTMLShell("application/json", `{"websocket":"...}`))
}
