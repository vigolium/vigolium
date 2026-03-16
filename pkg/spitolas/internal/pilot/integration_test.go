//go:build integration

// integration_test.go — Tests with real headless browser validating plan expectations.
// Run with: go test -v -tags=integration -timeout=300s ./pkg/spitolas/internal/pilot/...
package pilot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appconfig "github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/state"
)

// testApp is a multi-page web app for integration testing.
const testAppHTML = `<!DOCTYPE html>
<html>
<head><title>Test App</title></head>
<body>
<h1>Test Application</h1>
<h2>Welcome Page</h2>
<nav>
  <a href="/">Home</a> |
  <a href="/login">Login</a> |
  <a href="/dashboard">Dashboard</a> |
  <a href="/logout">Logout</a>
</nav>
<main>
  <p>Welcome to the test application.</p>
  <a href="/about">About Us</a>
  <button onclick="document.getElementById('result').textContent='clicked!'">Click Me</button>
  <div id="result"></div>
  <form action="/search" method="GET">
    <input type="text" name="q" placeholder="Search..." required>
    <select name="category">
      <option value="all">All</option>
      <option value="users">Users</option>
      <option value="posts">Posts</option>
    </select>
    <input type="checkbox" name="exact" id="exact-match"> Exact match
    <button type="submit">Search</button>
  </form>
</main>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
<h1>Dashboard</h1>
<h2>Overview</h2>
<nav>
  <a href="/">Home</a> |
  <a href="/dashboard">Dashboard</a> |
  <a href="/settings">Settings</a>
</nav>
<main>
  <button>Create New</button>
  <table>
    <tr><td><a href="/item/1">Item 1</a></td><td><button>Delete</button></td></tr>
    <tr><td><a href="/item/2">Item 2</a></td><td><button>Delete</button></td></tr>
  </table>
</main>
</body>
</html>`

func setupTestApp(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(testAppHTML))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Login</title></head><body>
<h1>Login</h1>
<form action="/login" method="POST">
  <input type="text" name="username" placeholder="Username" required>
  <input type="password" name="password" placeholder="Password" required>
  <button type="submit">Log In</button>
</form>
</body></html>`))
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>About</title></head><body><h1>About Us</h1><a href="/">Back</a></body></html>`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Search Results</title></head><body><h1>Search Results</h1><h2>Results for: ` + q + `</h2><a href="/">Back</a></body></html>`))
	})
	return httptest.NewServer(mux)
}

// sharedBrowser holds a single browser instance shared across all tests in this file.
type sharedBrowser struct {
	cfg  *config.Config
	pool *browser.Pool
	b    *browser.Browser
}

func newSharedBrowser(t *testing.T, serverURL string) *sharedBrowser {
	t.Helper()
	cfg, err := config.New(serverURL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.BrowserCount = 1
	cfg.UseCDPDetection = true // enable CDP detection for better element extraction

	pool, err := browser.NewPool(cfg)
	if err != nil {
		t.Fatalf("browser.NewPool: %v", err)
	}
	b := pool.Get()
	if b == nil {
		pool.Close()
		t.Fatal("no browser from pool")
	}
	return &sharedBrowser{cfg: cfg, pool: pool, b: b}
}

func (sb *sharedBrowser) close() { sb.pool.Close() }

func (sb *sharedBrowser) newPilotCrawler(t *testing.T, serverURL string) *PilotCrawler {
	t.Helper()
	page, err := sb.b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := page.Navigate(serverURL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	_ = page.WaitStable(sb.cfg.DOMStableTime)

	graph := state.NewGraph()
	formHandler := form.NewHandler(sb.cfg)
	extractor := action.NewCandidateElementExtractor(sb.cfg)
	extractor.SetClickOnce(false)
	tr, _ := NewSessionTrace("")

	html, _ := page.HTMLWithFramesFiltered(sb.cfg.CrawlFrames, sb.cfg.ExcludeFrames)
	pageURL, _ := page.URL()
	strippedDOM := state.StripDOM(html, sb.cfg.DOMStripTags, sb.cfg.DOMStripAttrs)
	indexState := state.New(pageURL, html, strippedDOM, 0)
	graph.AddState(indexState)

	return &PilotCrawler{
		config:       sb.cfg,
		pilotConfig:  &PilotConfig{},
		agentDef:     appconfig.AgentDef{},
		browserPool:  sb.pool,
		graph:        graph,
		formHandler:  formHandler,
		extractor:    extractor,
		checkpoints:  NewCheckpointTracker(""),
		entities:     NewEntityTracker(),
		trace:        tr,
		blacklist:    NewBlacklist(),
		currentPage:  page,
		currentState: indexState,
		crawlPhase:   PhaseBreadth,
	}
}

func callTool(t *testing.T, bc *PilotCrawler, tool string, args map[string]string) ToolResult {
	t.Helper()
	result, err := bc.HandleTool(context.Background(), tool, args)
	if err != nil {
		t.Fatalf("HandleTool(%s) error: %v", tool, err)
	}
	var tr ToolResult
	if err := json.Unmarshal([]byte(result), &tr); err != nil {
		t.Fatalf("HandleTool(%s) invalid JSON: %v\nraw: %s", tool, err, result)
	}
	return tr
}

// TestPilotIntegration runs all browser-based integration tests using a shared browser.
func TestPilotIntegration(t *testing.T) {
	server := setupTestApp(t)
	defer server.Close()

	sb := newSharedBrowser(t, server.URL)
	defer sb.close()

	// Plan §"Action Results ARE the Context"
	t.Run("ActionToolsReturnPageState", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "click", map[string]string{"xpath": "//a[contains(text(),'About')]"})
		if tr.PageState == "" {
			t.Error("click should return page_state")
		}
		if !strings.Contains(tr.PageState, "=== PAGE STATE ===") {
			t.Error("page_state should contain PAGE STATE header")
		}
		if !strings.Contains(tr.PageState, "About") {
			t.Error("page_state should reflect new page after click")
		}

		tr = callTool(t, bc, "navigate", map[string]string{"url": server.URL + "/dashboard"})
		if !strings.Contains(tr.PageState, "Dashboard") {
			t.Error("navigate page_state should contain Dashboard")
		}

		tr = callTool(t, bc, "go_back", nil)
		if tr.PageState == "" {
			t.Error("go_back should return page_state")
		}
	})

	// Plan §"Page State Serialization"
	t.Run("PageStateSerialization", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		ps, err := bc.SerializePage(context.Background(), bc.currentPage, bc.currentState)
		if err != nil {
			t.Fatal(err)
		}

		sections := []string{
			"=== PAGE STATE ===", "URL:", "Title:",
			"=== HEADINGS ===", "=== NAVIGATION ===",
			"=== CLICKABLE ELEMENTS", "=== FORMS",
			"=== FEEDBACK ===", "=== CHECKPOINT COMPASS ===",
		}
		for _, section := range sections {
			if !strings.Contains(ps, section) {
				t.Errorf("page state missing section: %q", section)
			}
		}
		if !strings.Contains(ps, "h1:") {
			t.Error("headings should show h1 prefix")
		}
		if !strings.Contains(ps, "[0]") {
			t.Error("clickable elements should be indexed starting at [0]")
		}
		if !strings.Contains(ps, "xpath=") {
			t.Error("clickable elements should include xpath")
		}
		if !strings.Contains(ps, "Form #0:") {
			t.Error("forms should be numbered starting at Form #0")
		}
	})

	// Plan §"Auto-blacklist detection"
	t.Run("AutoBlacklist", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)
		bc.autoDetectBlacklist(context.Background())

		entries := bc.blacklist.All()
		if len(entries) == 0 {
			// Debug: show what elements were found
			elements, _ := bc.extractor.Extract(context.Background(), bc.currentPage)
			for _, e := range elements {
				xpath := ""
				if e.Identification != nil {
					xpath = e.Identification.Value
				}
				t.Logf("element: text=%q href=%q xpath=%q", e.Text, e.Href, xpath)
			}
			t.Fatal("auto-blacklist should detect logout link")
		}

		// Verify it's the logout element
		found := false
		for _, entry := range entries {
			if strings.Contains(entry.Reason, "logout") || strings.Contains(entry.Reason, "/logout") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("blacklist should contain a logout entry, got: %+v", entries)
		}
	})

	// Plan §"click blacklist enforcement with browser"
	t.Run("BlacklistEnforcement", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)
		bc.autoDetectBlacklist(context.Background())

		for _, entry := range bc.blacklist.All() {
			tr := callTool(t, bc, "click", map[string]string{"xpath": entry.XPath})
			if tr.Success {
				t.Error("clicking blacklisted element should fail")
			}
			if !strings.Contains(tr.Error, "BLOCKED") {
				t.Errorf("expected BLOCKED error, got: %s", tr.Error)
			}
		}
	})

	// Plan §"click → navigate to new page"
	t.Run("ClickNavigates", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "click", map[string]string{"xpath": "//a[contains(text(),'About')]"})
		if !tr.Success {
			t.Fatalf("click failed: %s", tr.Error)
		}
		if !strings.Contains(tr.PageState, "About Us") {
			t.Error("after clicking About link, page should show About Us")
		}
		if bc.currentState == nil {
			t.Error("currentState should be updated after click")
		}
	})

	// Plan §"type_text clears existing value first"
	t.Run("TypeText", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "type_text", map[string]string{
			"xpath": "//input[@name='q']",
			"value": "test query",
		})
		if !tr.Success {
			t.Fatalf("type_text failed: %s", tr.Error)
		}
	})

	// Plan §"select_option"
	t.Run("SelectOption", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "select_option", map[string]string{
			"xpath": "//select[@name='category']",
			"value": "Users",
		})
		if !tr.Success {
			t.Fatalf("select_option failed: %s", tr.Error)
		}
	})

	// Plan §"navigate to URL"
	t.Run("Navigate", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "navigate", map[string]string{"url": server.URL + "/login"})
		if !tr.Success {
			t.Fatalf("navigate failed: %s", tr.Error)
		}
		if !strings.Contains(tr.PageState, "Login") {
			t.Error("navigate should show Login page")
		}
		if bc.graph.StateCount() < 2 {
			t.Error("navigate to new page should create new state in graph")
		}
	})

	// Plan §"go_back"
	t.Run("GoBack", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		callTool(t, bc, "navigate", map[string]string{"url": server.URL + "/login"})
		tr := callTool(t, bc, "go_back", nil)
		if !tr.Success {
			t.Fatalf("go_back failed: %s", tr.Error)
		}
		if !strings.Contains(tr.PageState, "Test Application") {
			t.Error("go_back should return to index page")
		}
	})

	// Plan §"submit_form"
	t.Run("SubmitForm", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		callTool(t, bc, "type_text", map[string]string{
			"xpath": "//input[@name='q']",
			"value": "hello",
		})
		tr := callTool(t, bc, "submit_form", map[string]string{
			"form_xpath": "//form",
		})
		if !tr.Success {
			t.Fatalf("submit_form failed: %s", tr.Error)
		}
		if !strings.Contains(tr.PageState, "Search Results") {
			t.Error("submit_form should navigate to search results")
		}
	})

	// Plan §"execute_js"
	t.Run("ExecuteJS", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "execute_js", map[string]string{"code": "document.title"})
		if !tr.Success {
			t.Fatalf("execute_js failed: %s", tr.Error)
		}
		if title, ok := tr.Data.(string); !ok || title != "Test App" {
			t.Errorf("execute_js should return page title, got: %v", tr.Data)
		}
	})

	// Plan §"screenshot"
	t.Run("Screenshot", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "screenshot", nil)
		if !tr.Success {
			t.Fatalf("screenshot failed: %s", tr.Error)
		}
		data, ok := tr.Data.(string)
		if !ok || len(data) < 100 {
			t.Error("screenshot should return base64 PNG data")
		}
	})

	// Plan §"get_page_text"
	t.Run("GetPageText", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "get_page_text", nil)
		if !tr.Success {
			t.Fatalf("get_page_text failed: %s", tr.Error)
		}
		text, ok := tr.Data.(string)
		if !ok || !strings.Contains(text, "Welcome") {
			t.Error("get_page_text should return visible text content")
		}
	})

	// Plan §"get_element_text"
	t.Run("GetElementText", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "get_element_text", map[string]string{"xpath": "//main"})
		if !tr.Success {
			t.Fatalf("get_element_text failed: %s", tr.Error)
		}
		text, ok := tr.Data.(string)
		if !ok || !strings.Contains(text, "Welcome") {
			t.Error("get_element_text should return element content")
		}
	})

	// Plan §"check"
	t.Run("Check", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "check", map[string]string{
			"xpath":   "//input[@id='exact-match']",
			"checked": "true",
		})
		if !tr.Success {
			t.Fatalf("check failed: %s", tr.Error)
		}
		result, _ := bc.currentPage.Eval(`document.getElementById('exact-match').checked`)
		if checked, ok := result.(bool); !ok || !checked {
			t.Error("checkbox should be checked after check tool")
		}
	})

	// Plan §"scroll"
	t.Run("Scroll", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		tr := callTool(t, bc, "scroll", map[string]string{"direction": "down", "amount": "300"})
		if !tr.Success {
			t.Fatalf("scroll failed: %s", tr.Error)
		}
		if tr.PageState == "" {
			t.Error("scroll should return page_state")
		}
	})

	// Plan §"get_state_graph" with edges
	t.Run("GetStateGraph", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		callTool(t, bc, "navigate", map[string]string{"url": server.URL + "/login"})
		callTool(t, bc, "navigate", map[string]string{"url": server.URL + "/dashboard"})

		tr := callTool(t, bc, "get_state_graph", nil)
		if !tr.Success {
			t.Fatal("get_state_graph should succeed")
		}
		data := tr.Data.(map[string]any)
		stateCount := int(data["state_count"].(float64))
		if stateCount < 3 {
			t.Errorf("expected at least 3 states, got %d", stateCount)
		}
		if _, hasEdges := data["edges"]; !hasEdges {
			t.Error("get_state_graph should include edges")
		}
		if data["current_state"] == nil || data["current_state"].(string) == "" {
			t.Error("get_state_graph should show current_state")
		}
	})

	// Plan §"Action Replay Log" — recording with real browser actions
	t.Run("ActionLogRecording", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		callTool(t, bc, "navigate", map[string]string{"url": server.URL + "/login"})
		callTool(t, bc, "type_text", map[string]string{
			"xpath": "//input[@name='username']",
			"value": "admin",
		})

		entries := bc.trace.Entries(0)
		if len(entries) < 2 {
			t.Fatalf("expected at least 2 entries, got %d", len(entries))
		}
		if entries[0].Tool != "navigate" {
			t.Errorf("entry 0 should be navigate, got %s", entries[0].Tool)
		}
		if entries[1].Tool != "type_text" {
			t.Errorf("entry 1 should be type_text, got %s", entries[1].Tool)
		}
		for i, e := range entries {
			if e.Seq != i+1 {
				t.Errorf("entry %d: Seq should be %d, got %d", i, i+1, e.Seq)
			}
		}
	})

	// Plan §"Read-only tools not recorded"
	t.Run("ReadOnlyNotRecorded", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		callTool(t, bc, "get_page_text", nil)
		callTool(t, bc, "screenshot", nil)
		callTool(t, bc, "get_state_graph", nil)
		callTool(t, bc, "get_todo_list", nil)

		if bc.trace.Len() != 0 {
			t.Errorf("read-only tools should not be recorded, got %d entries", bc.trace.Len())
		}
	})

	// Plan §"DOM mutations create new states"
	t.Run("NavigationCreatesStates", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)
		initial := bc.graph.StateCount()

		callTool(t, bc, "navigate", map[string]string{"url": server.URL + "/login"})
		if bc.graph.StateCount() <= initial {
			t.Error("navigating to login should create a new state")
		}
		callTool(t, bc, "navigate", map[string]string{"url": server.URL + "/dashboard"})
		if bc.graph.StateCount() <= initial+1 {
			t.Error("navigating to dashboard should create another state")
		}
	})

	// Checkpoint Compass in page state
	t.Run("CompassInPageState", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		bc.checkpoints.Create("login", "Login page", "Test login", nil, "", "", "", PhaseBreadth, 500)
		bc.checkpoints.Create("dashboard", "Dashboard", "Check widgets", nil, "", "", "", PhaseBreadth, 500)

		ps, _ := bc.SerializePage(context.Background(), bc.currentPage, bc.currentState)
		if !strings.Contains(ps, "=== CHECKPOINT COMPASS ===") {
			t.Error("page state should include checkpoint compass")
		}
		if !strings.Contains(ps, "2 pending") {
			t.Error("compass should show 2 pending checkpoints")
		}
	})

	// Full form flow: type → select → check → submit
	t.Run("FullFormFlow", func(t *testing.T) {
		bc := sb.newPilotCrawler(t, server.URL)

		callTool(t, bc, "type_text", map[string]string{
			"xpath": "//input[@name='q']",
			"value": "security test",
		})
		callTool(t, bc, "select_option", map[string]string{
			"xpath": "//select[@name='category']",
			"value": "Users",
		})
		callTool(t, bc, "check", map[string]string{
			"xpath":   "//input[@id='exact-match']",
			"checked": "true",
		})
		tr := callTool(t, bc, "submit_form", map[string]string{
			"form_xpath": "//form",
		})
		if !tr.Success {
			t.Fatalf("submit_form failed: %s", tr.Error)
		}
		if !strings.Contains(tr.PageState, "Search Results") {
			t.Error("should navigate to search results after full form flow")
		}
		if bc.trace.Len() != 4 {
			t.Errorf("expected 4 action log entries, got %d", bc.trace.Len())
		}
	})
}
