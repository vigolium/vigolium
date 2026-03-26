package testutil

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
)

// TestServer wraps httptest.Server for serving test HTML files.
type TestServer struct {
	server  *httptest.Server
	baseDir string
}

// NewTestServer creates a new test server serving files from testdata/html/.
func NewTestServer() *TestServer {
	ts := &TestServer{
		baseDir: filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html"),
	}

	mux := http.NewServeMux()
	// Serve files from testdata/html/
	fileServer := http.FileServer(http.Dir(ts.baseDir))
	mux.Handle("/", fileServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// NewTestServerWithDir creates a new test server serving files from a custom directory.
func NewTestServerWithDir(dir string) *TestServer {
	ts := &TestServer{
		baseDir: dir,
	}

	mux := http.NewServeMux()
	fileServer := http.FileServer(http.Dir(ts.baseDir))
	mux.Handle("/", fileServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// NewTestServerWithHandler creates a new test server with a custom handler.
func NewTestServerWithHandler(handler http.Handler) *TestServer {
	ts := &TestServer{}
	ts.server = httptest.NewServer(handler)
	return ts
}

// NewTestServerWithHTML creates a simple test server that serves a single HTML string.
func NewTestServerWithHTML(htmlContent string) *TestServer {
	ts := &TestServer{}
	ts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(htmlContent))
	}))
	return ts
}

// URL returns the base URL of the test server.
func (ts *TestServer) URL() string {
	return ts.server.URL
}

// URLFor returns the URL for a specific file path.
func (ts *TestServer) URLFor(path string) string {
	if path == "" {
		return ts.server.URL
	}
	if path[0] != '/' {
		path = "/" + path
	}
	return ts.server.URL + path
}

// Close shuts down the test server.
func (ts *TestServer) Close() {
	ts.server.Close()
}

// Client returns an HTTP client configured for the test server.
func (ts *TestServer) Client() *http.Client {
	return ts.server.Client()
}

// SimpleSiteServer creates a test server serving the simple-site test files.
func SimpleSiteServer() *TestServer {
	return NewTestServerWithDir(filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "simple-site"))
}

// FormTestServer creates a test server serving form test files.
func FormTestServer() *TestServer {
	return NewTestServerWithDir(filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "forms"))
}

// ClickableTestServer creates a test server serving clickable test files.
func ClickableTestServer() *TestServer {
	return NewTestServerWithDir(filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "clickable"))
}

// SimpleInputSiteServer creates a test server serving the simple-input-site test files.
func SimpleInputSiteServer() *TestServer {
	// Serve both the site directory and the lib directory for jQuery
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve simple-input-site directory
	siteServer := http.FileServer(http.Dir(filepath.Join(baseDir, "simple-input-site")))
	mux.Handle("/", siteServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// SimpleJsSiteServer creates a test server serving the simple-js-site test files.
func SimpleJsSiteServer() *TestServer {
	// Serve both the site directory and the lib directory for jQuery
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve simple-js-site directory
	siteServer := http.FileServer(http.Dir(filepath.Join(baseDir, "simple-js-site")))
	mux.Handle("/", siteServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// SiteServer creates a test server serving the site test files.
func SiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve site directory
	siteServer := http.FileServer(http.Dir(baseDir))
	mux.Handle("/", siteServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// IFrameSiteServer creates a test server serving the iframe test files.
func IFrameSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve iframe directory as root
	iframeServer := http.FileServer(http.Dir(filepath.Join(baseDir, "iframe")))
	mux.Handle("/", iframeServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// PopupSiteServer creates a test server serving the popup test files.
func PopupSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve popup directory as root
	popupServer := http.FileServer(http.Dir(filepath.Join(baseDir, "popup")))
	mux.Handle("/", popupServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// InfiniteSiteServer creates a test server serving the infinite state test file.
func InfiniteSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	return NewTestServerWithDir(baseDir)
}

// BasicAuthServer creates a test server with HTTP Basic Authentication.
func BasicAuthServer(username, password string) *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Test"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.FileServer(http.Dir(baseDir)).ServeHTTP(w, r)
	})

	ts.server = httptest.NewServer(handler)
	return ts
}

// UnderXPathSiteServer creates a test server serving underxpath.html test.
func UnderXPathSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve js directory for scripts
	jsServer := http.FileServer(http.Dir(filepath.Join(baseDir, "js")))
	mux.Handle("/js/", http.StripPrefix("/js/", jsServer))
	// Serve site directory
	siteServer := http.FileServer(http.Dir(baseDir))
	mux.Handle("/", siteServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// LargeSiteServer creates a test server serving the main large test site.
func LargeSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve js directory for scripts
	jsServer := http.FileServer(http.Dir(filepath.Join(baseDir, "js")))
	mux.Handle("/js/", http.StripPrefix("/js/", jsServer))
	// Serve formhandler directory
	formServer := http.FileServer(http.Dir(filepath.Join(baseDir, "formhandler")))
	mux.Handle("/formhandler/", http.StripPrefix("/formhandler/", formServer))
	// Serve site directory
	siteServer := http.FileServer(http.Dir(baseDir))
	mux.Handle("/", siteServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// ClickableSiteServer creates a test server serving clickable test site.
func ClickableSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve clickable directory as root
	clickableServer := http.FileServer(http.Dir(filepath.Join(baseDir, "clickable")))
	mux.Handle("/", clickableServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// DownloadSiteServer creates a test server serving download test site.
func DownloadSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve download directory as root
	downloadServer := http.FileServer(http.Dir(filepath.Join(baseDir, "download")))
	mux.Handle("/", downloadServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// ClickablesSiteServer creates a test server for clickable element tests.
// Note: This is distinct from ClickableSiteServer which serves the same files but
// is used for element extraction tests (CandidateElementExtractorTest).
func ClickablesSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve clickable directory as root
	clickableServer := http.FileServer(http.Dir(filepath.Join(baseDir, "clickable")))
	mux.Handle("/", clickableServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// HiddenElementsSiteServer creates a test server for hidden elements tests.
func HiddenElementsSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve hidden-elements-site directory as root
	hiddenServer := http.FileServer(http.Dir(filepath.Join(baseDir, "hidden-elements-site")))
	mux.Handle("/", hiddenServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// CrawlScopeSiteServer creates a test server for custom scope tests.
func CrawlScopeSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html", "site")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve crawlscope directory
	crawlscopeServer := http.FileServer(http.Dir(filepath.Join(baseDir, "crawlscope")))
	mux.Handle("/crawlscope/", http.StripPrefix("/crawlscope/", crawlscopeServer))
	// Also serve at root for direct access
	mux.Handle("/", crawlscopeServer)

	ts.server = httptest.NewServer(mux)
	return ts
}

// MAKSiteServer creates a test server serving the MAK test site.
// This site is designed to test MAK (Multi-Armed Krawler) adaptive action selection.
// Structure:
// - index.html: 6 clickable elements (btn1, btn2, btn3, link1, link2, form submit)
// - state_btn1 -> state_btn1_deep (depth 2, reward 1 then 0)
// - state_btn2 -> state_btn2_a, state_btn2_b, state_btn2_c (high reward: 3 actions)
// - state_btn3 (terminal, reward 0)
// - state_link1 -> state_link1_x, state_link1_y (medium reward: 2 actions)
// - state_link2 (terminal, reward 0)
// - state_form1 -> state_form1_final (reward 1 then 0)
//
// Total: 14 states with varying reward structure (0, 1, 2, 3 new actions)
func MAKSiteServer() *TestServer {
	baseDir := filepath.Join(getProjectRoot(), "test", "spitolas", "testdata", "html")
	ts := &TestServer{
		baseDir: baseDir,
	}

	mux := http.NewServeMux()
	// Serve lib directory for jQuery
	libServer := http.FileServer(http.Dir(filepath.Join(baseDir, "lib")))
	mux.Handle("/lib/", http.StripPrefix("/lib/", libServer))
	// Serve mak-site directory
	siteServer := http.FileServer(http.Dir(filepath.Join(baseDir, "mak-site")))
	mux.Handle("/", siteServer)

	ts.server = httptest.NewServer(mux)
	return ts
}
