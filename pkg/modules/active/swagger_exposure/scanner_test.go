package swagger_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	m := New()
	if m.ID() != ModuleID {
		t.Errorf("ID() = %q, want %q", m.ID(), ModuleID)
	}
	if m.Severity() != severity.Low {
		t.Errorf("Severity() = %v, want Low", m.Severity())
	}
	if !m.ScanScopes().Has(modkit.ScanScopeRequest) {
		t.Error("expected ScanScopeRequest to be set")
	}
	if len(m.Tags()) == 0 {
		t.Error("expected tags to be set")
	}
}

func TestCanProcess(t *testing.T) {
	m := New()
	if m.CanProcess(nil) {
		t.Error("CanProcess(nil) should return false")
	}
	rawReq := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	rr := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequest(rawReq), nil)
	if !m.CanProcess(rr) {
		t.Error("CanProcess should return true for valid request")
	}
}

func TestIncludesBaseCanProcess(t *testing.T) {
	if New().IncludesBaseCanProcess() {
		t.Error("IncludesBaseCanProcess should return false")
	}
}

func TestProbePaths(t *testing.T) {
	if len(probePaths) == 0 {
		t.Fatal("probePaths should not be empty")
	}
	has := make(map[string]bool, len(probePaths))
	for _, p := range probePaths {
		if has[p] {
			t.Errorf("duplicate probe path %q", p)
		}
		has[p] = true
	}
	for _, exp := range []string{"swagger-ui.html", "openapi.json", "v3/api-docs"} {
		if !has[exp] {
			t.Errorf("probePaths missing %q", exp)
		}
	}
}

func TestLooksLikeSwaggerUI(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"swagger loader", `<div id="swagger-ui"></div><script>window.ui = SwaggerUIBundle({})</script>`, true},
		{"swagger div alone", `<div id="swagger-ui"></div>`, false},
		{"swagger bundle alone", `<script>window.ui = SwaggerUIBundle({})</script>`, false},
		{"redoc loader", `<redoc spec-url="/openapi.json"></redoc><script src="redoc.standalone.js"></script>`, true},
		{"redoc tag alone", `<redoc></redoc>`, false},
		{"plain html", `<html><body>hello world</body></html>`, false},
		{"empty", ``, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeSwaggerUI([]byte(c.body)); got != c.want {
				t.Errorf("looksLikeSwaggerUI(%q) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}

// TestScanPerRequest_NoFP_SlugReflectingRoute reproduces the slug-reflection FP
// class: a content route under /api/ echoes the requested slug into the page, so
// /api/redoc returns 200 HTML containing the word "redoc" and self-matches the
// "redoc" UI marker even though no ReDoc page is served. The SlugReflectionFP
// control (a canary sibling that reflects too) must suppress it.
func TestScanPerRequest_NoFP_SlugReflectingRoute(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slug, ok := strings.CutPrefix(r.URL.Path, "/api/"); ok && slug != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>` + slug +
				` — Docs</title></head><body><h1>Documentation for ` + slug +
				`</h1><p>Everything about ` + slug + ` on our platform.</p></body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Observe a page under /api/ so CandidateBasePaths walks /api and the module
	// probes /api/redoc (UI marker == reflected slug).
	rr := modtest.Request(t, srv.URL+"/api/products")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a slug-reflecting content route must not yield a swagger/redoc-exposure finding")
}

// TestScanPerRequest_NoFP_RootLevelReflectingShell reproduces the ROOT-level slug
// reflection the sub-directory test above does not cover — the branding.roche.com
// class. A path-reflecting SPA/CMS shell returns one 200 page for every unknown
// route and echoes the requested slug into it, so /redoc and /swagger-ui/ return the
// shell with "redoc"/"swagger-ui" reflected, self-matching those UI markers with no
// docs page behind them. The wildcard-shell guard and the root-aware SlugReflectionFP
// (which probes a web-root canary for these single-segment paths) must suppress it.
func TestScanPerRequest_NoFP_RootLevelReflectingShell(t *testing.T) {
	t.Parallel()
	shell := func(seg string) string {
		return `<!DOCTYPE html><html class="mod modLayout"><head><title>Brand</title></head><body>` +
			strings.Repeat(`<div class="mod skel"></div>`, 60) +
			`<script>window.__ctx={"route_initial":true,"view":"` + seg + `","user":[]};</script>` +
			`</body></html>`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "https://login.example.com/", http.StatusFound)
			return
		}
		seg := strings.Trim(r.URL.Path, "/")
		if i := strings.LastIndex(seg, "/"); i >= 0 {
			seg = seg[i+1:]
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(shell(seg)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a path-reflecting SPA/CMS shell must not yield a swagger/redoc-exposure finding")
}

// TestScanPerRequest_DetectsRealReDocRootPath confirms the root-level guards do not
// kill the true positive: a genuine ReDoc UI mounted at /redoc (site root serves a
// distinct homepage, random paths 404, so no reflection) must still surface.
func TestScanPerRequest_DetectsRealReDocRootPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redoc":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>API docs</title></head>` +
				`<body><redoc spec-url="/openapi.json"></redoc>` +
				`<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>` +
				`</body></html>`))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><h1>Welcome</h1><p>corporate homepage</p></body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a genuine ReDoc UI at root /redoc (siblings 404) must still yield a finding")
	assert.Contains(t, res[0].URL, "/redoc")
}

// TestScanPerRequest_DetectsRealReDocSubPath confirms the guard does not kill the
// true positive: a genuine ReDoc UI mounted at /api/redoc (siblings 404, so no
// slug reflection) must still surface a finding.
func TestScanPerRequest_DetectsRealReDocSubPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redoc" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>API docs</title></head>` +
				`<body><redoc spec-url="/api/openapi.json"></redoc>` +
				`<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>` +
				`</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a genuine ReDoc UI at /api/redoc (siblings 404) must still yield a finding")
	assert.Contains(t, res[0].URL, "/api/redoc")
}
