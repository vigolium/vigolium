package config

import (
	"strings"
	"testing"
	"time"
)

func TestConfigNew(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		wantURL string
	}{
		{
			name:    "valid http URL",
			url:     "http://example.com",
			wantErr: false,
			wantURL: "http://example.com",
		},
		{
			name:    "valid https URL",
			url:     "https://example.com/page",
			wantErr: false,
			wantURL: "https://example.com/page",
		},
		{
			name:    "URL without scheme fails (requires full URL)",
			url:     "example.com",
			wantErr: true, // Config requires valid URL with host parsed correctly
		},
		{
			name:    "empty URL fails",
			url:     "",
			wantErr: true,
		},
		{
			name:    "URL with path",
			url:     "https://example.com/path/to/page",
			wantErr: false,
			wantURL: "https://example.com/path/to/page",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := New(tt.url)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("config is nil")
			}

			if cfg.URL.String() != tt.wantURL {
				t.Errorf("URL = %q, want %q", cfg.URL.String(), tt.wantURL)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg, err := New("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check default values match Crawljax defaults
	if cfg.MaxDepth != 0 {
		t.Errorf("MaxDepth = %d, want 0 (unlimited)", cfg.MaxDepth)
	}
	if cfg.MaxStates != 0 {
		t.Errorf("MaxStates = %d, want 0 (unlimited)", cfg.MaxStates)
	}
	if cfg.MaxDuration != 0 {
		t.Errorf("MaxDuration = %v, want 0 (unlimited)", cfg.MaxDuration)
	}

	// Browser defaults
	if !cfg.Headless {
		t.Error("Headless should be true by default")
	}
	if cfg.BrowserCount != 1 {
		t.Errorf("BrowserCount = %d, want 1", cfg.BrowserCount)
	}

	// Wait times (Crawljax defaults: 200ms)
	if cfg.WaitAfterReload != 200*time.Millisecond {
		t.Errorf("WaitAfterReload = %v, want 200ms", cfg.WaitAfterReload)
	}
	if cfg.WaitAfterEvent != 200*time.Millisecond {
		t.Errorf("WaitAfterEvent = %v, want 200ms", cfg.WaitAfterEvent)
	}
	if cfg.PageLoadTimeout != 30*time.Second {
		t.Errorf("PageLoadTimeout = %v, want 30s", cfg.PageLoadTimeout)
	}

	// Clickable detection
	// CRAWLJAX PARITY: CDP detection is OFF by default
	// Must be explicitly enabled via clickElementsWithClickEventHandler()
	if cfg.UseCDPDetection {
		t.Error("UseCDPDetection should be false by default (Crawljax parity)")
	}
	if !cfg.ClickOnce {
		t.Error("ClickOnce should be true by default")
	}
	if !cfg.CrawlFrames {
		t.Error("CrawlFrames should be true by default (Crawljax default)")
	}

	// Form handling
	if !cfg.FormFillEnabled {
		t.Error("FormFillEnabled should be true by default")
	}
	if cfg.FormFillMode != FormFillNormal {
		t.Errorf("FormFillMode = %q, want %q", cfg.FormFillMode, FormFillNormal)
	}

	// Crawljax parity options (disabled by default)
	if cfg.AvoidUnrelatedBacktracking {
		t.Error("AvoidUnrelatedBacktracking should be false by default")
	}
	if cfg.AvoidDifferentBacktracking {
		t.Error("AvoidDifferentBacktracking should be false by default")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config passes",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name: "nil URL fails",
			modify: func(c *Config) {
				c.URL = nil
			},
			wantErr: true,
			errMsg:  "URL is required",
		},
		{
			name: "invalid scheme fails",
			modify: func(c *Config) {
				c.URL.Scheme = "ftp"
			},
			wantErr: true,
			errMsg:  "scheme must be http or https",
		},
		{
			name: "negative MaxDepth fails",
			modify: func(c *Config) {
				c.MaxDepth = -1
			},
			wantErr: true,
			errMsg:  "MaxDepth",
		},
		{
			name: "negative MaxStates fails",
			modify: func(c *Config) {
				c.MaxStates = -1
			},
			wantErr: true,
			errMsg:  "MaxStates",
		},
		{
			name: "zero BrowserCount fails",
			modify: func(c *Config) {
				c.BrowserCount = 0
			},
			wantErr: true,
			errMsg:  "BrowserCount",
		},
		{
			name: "invalid FormFillMode fails",
			modify: func(c *Config) {
				c.FormFillMode = "invalid"
			},
			wantErr: true,
			errMsg:  "FormFillMode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := New("https://example.com")
			if err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			tt.modify(cfg)

			err = cfg.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfigBuilder(t *testing.T) {
	cfg, _ := New("https://example.com")

	// Test chaining
	cfg.SetMaxDepth(5).
		SetMaxStates(100).
		SetMaxDuration(10*time.Minute).
		SetHeadless(false).
		SetBasicAuth("user", "pass").
		SetProxy("http://proxy:8080").
		AddClickSelector(".custom-btn").
		AddExcludeSelector(".ignore").
		AddFormInput("id", "name", "text", "John").
		AddCrawlCondition(CondURLContains, "/valid/", false).
		AddWaitCondition("/slow/", "#loaded", true, 5*time.Second).
		EnableCDPDetection(false).
		EnableFormFill(false).
		SetFormFillMode(FormFillRandom).
		SetRandomizeElements(true).
		SetAvoidUnrelatedBacktracking(true).
		SetAvoidDifferentBacktracking(true)

	// Verify values
	if cfg.MaxDepth != 5 {
		t.Errorf("MaxDepth = %d, want 5", cfg.MaxDepth)
	}
	if cfg.MaxStates != 100 {
		t.Errorf("MaxStates = %d, want 100", cfg.MaxStates)
	}
	if cfg.MaxDuration != 10*time.Minute {
		t.Errorf("MaxDuration = %v, want 10m", cfg.MaxDuration)
	}
	if cfg.Headless {
		t.Error("Headless should be false")
	}
	if cfg.BasicAuthUser != "user" || cfg.BasicAuthPass != "pass" {
		t.Errorf("BasicAuth = %s:%s, want user:pass", cfg.BasicAuthUser, cfg.BasicAuthPass)
	}
	if cfg.ProxyURL != "http://proxy:8080" {
		t.Errorf("ProxyURL = %q, want http://proxy:8080", cfg.ProxyURL)
	}

	// Check click selectors (should include defaults + custom)
	found := false
	for _, sel := range cfg.ClickSelectors {
		if sel == ".custom-btn" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ClickSelectors should contain .custom-btn")
	}

	// Check exclude selectors
	if len(cfg.ExcludeSelectors) != 1 || cfg.ExcludeSelectors[0] != ".ignore" {
		t.Errorf("ExcludeSelectors = %v, want [.ignore]", cfg.ExcludeSelectors)
	}

	// Check form inputs
	if len(cfg.FormInputs) != 1 {
		t.Errorf("FormInputs length = %d, want 1", len(cfg.FormInputs))
	}

	// Check conditions
	if len(cfg.CrawlConditions) != 1 {
		t.Errorf("CrawlConditions length = %d, want 1", len(cfg.CrawlConditions))
	}
	if len(cfg.WaitConditions) != 1 {
		t.Errorf("WaitConditions length = %d, want 1", len(cfg.WaitConditions))
	}

	if cfg.UseCDPDetection {
		t.Error("UseCDPDetection should be false")
	}
	if cfg.FormFillEnabled {
		t.Error("FormFillEnabled should be false")
	}
	if cfg.FormFillMode != FormFillRandom {
		t.Errorf("FormFillMode = %q, want random", cfg.FormFillMode)
	}
	if !cfg.RandomizeElements {
		t.Error("RandomizeElements should be true")
	}
	if !cfg.AvoidUnrelatedBacktracking {
		t.Error("AvoidUnrelatedBacktracking should be true")
	}
	if !cfg.AvoidDifferentBacktracking {
		t.Error("AvoidDifferentBacktracking should be true")
	}
}

func TestConfigGetBasicAuthURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		user    string
		pass    string
		wantURL string
	}{
		{
			name:    "no auth",
			url:     "https://example.com",
			user:    "",
			pass:    "",
			wantURL: "https://example.com",
		},
		{
			name:    "with auth",
			url:     "https://example.com",
			user:    "admin",
			pass:    "secret",
			wantURL: "https://admin:secret@example.com",
		},
		{
			name:    "with auth and path",
			url:     "https://example.com/path",
			user:    "user",
			pass:    "pass",
			wantURL: "https://user:pass@example.com/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _ := New(tt.url)
			cfg.SetBasicAuth(tt.user, tt.pass)

			got := cfg.GetBasicAuthURL()
			if got != tt.wantURL {
				t.Errorf("GetBasicAuthURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestDefaultClickSelectors(t *testing.T) {
	selectors := DefaultClickSelectors()

	// Should include common clickable elements
	expected := []string{"a", "button", "[onclick]", "[role=button]", "input[type=submit]"}
	for _, exp := range expected {
		found := false
		for _, sel := range selectors {
			if sel == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultClickSelectors should contain %q", exp)
		}
	}

	// Should include Angular/Vue selectors
	angularVue := []string{"[ng-click]", "[v-on\\:click]", "[\\@click]"}
	for _, sel := range angularVue {
		found := false
		for _, s := range selectors {
			if s == sel {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultClickSelectors should contain framework selector %q", sel)
		}
	}
}

func TestDefaultStripTags(t *testing.T) {
	tags := DefaultStripTags()

	expected := []string{"script", "style", "noscript", "meta", "link"}
	for _, exp := range expected {
		found := false
		for _, tag := range tags {
			if tag == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultStripTags should contain %q", exp)
		}
	}
}

func TestDefaultStripAttrs(t *testing.T) {
	attrs := DefaultStripAttrs()

	expected := []string{"id", "class", "style", "data-*"}
	for _, exp := range expected {
		found := false
		for _, attr := range attrs {
			if attr == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultStripAttrs should contain %q", exp)
		}
	}
}

func TestConditionConfig(t *testing.T) {
	cfg, _ := New("https://example.com")

	// Add various condition types
	cfg.AddCrawlCondition(CondURLContains, "/valid/", false)
	cfg.AddCrawlCondition(CondURLMatches, "^https://", false)
	cfg.AddCrawlCondition(CondElementExists, "#main", false)
	cfg.AddCrawlCondition(CondElementVisible, ".content", false)
	cfg.AddCrawlCondition(CondJavaScript, "return true;", false)
	cfg.AddCrawlCondition(CondXPathExists, "//div[@id='test']", false)
	cfg.AddCrawlCondition(CondDOMRegex, "<div.*?>", false)

	if len(cfg.CrawlConditions) != 7 {
		t.Errorf("CrawlConditions length = %d, want 7", len(cfg.CrawlConditions))
	}

	// Check first condition
	cond := cfg.CrawlConditions[0]
	if cond.Type != CondURLContains {
		t.Errorf("cond.Type = %v, want CondURLContains", cond.Type)
	}
	if cond.Value != "/valid/" {
		t.Errorf("cond.Value = %q, want /valid/", cond.Value)
	}
	if cond.Negate {
		t.Error("cond.Negate should be false")
	}
}

func TestWaitConditionConfig(t *testing.T) {
	cfg, _ := New("https://example.com")

	cfg.AddWaitCondition("/slow/", "#content", true, 5*time.Second)
	cfg.AddWaitCondition("/ajax/", ".loaded", false, 3*time.Second)

	if len(cfg.WaitConditions) != 2 {
		t.Errorf("WaitConditions length = %d, want 2", len(cfg.WaitConditions))
	}

	// Check first wait condition
	wait := cfg.WaitConditions[0]
	if wait.URLPattern != "/slow/" {
		t.Errorf("wait.URLPattern = %q, want /slow/", wait.URLPattern)
	}
	if wait.Selector != "#content" {
		t.Errorf("wait.Selector = %q, want #content", wait.Selector)
	}
	if !wait.Visible {
		t.Error("wait.Visible should be true")
	}
	if wait.Timeout != 5*time.Second {
		t.Errorf("wait.Timeout = %v, want 5s", wait.Timeout)
	}
}

func TestFormInputConfig(t *testing.T) {
	cfg, _ := New("https://example.com")

	// CRAWLJAX PARITY: Uses Identification(How, Value) instead of CSS selector
	cfg.AddFormInput("id", "user", "text", "john", "jane")
	cfg.AddFormInput("id", "country", "select", "us", "uk", "vn")
	cfg.AddFormInput("id", "agree", "checkbox", "yes")

	if len(cfg.FormInputs) != 3 {
		t.Errorf("FormInputs length = %d, want 3", len(cfg.FormInputs))
	}

	// Check first input
	input := cfg.FormInputs[0]
	if input.How != "id" {
		t.Errorf("input.How = %q, want id", input.How)
	}
	if input.Value != "user" {
		t.Errorf("input.Value = %q, want user", input.Value)
	}
	if input.Type != "text" {
		t.Errorf("input.Type = %q, want text", input.Type)
	}
	if len(input.Values) != 2 || input.Values[0] != "john" || input.Values[1] != "jane" {
		t.Errorf("input.Values = %v, want [john jane]", input.Values)
	}
}

func TestFormFillModes(t *testing.T) {
	if FormFillNormal != "normal" {
		t.Errorf("FormFillNormal = %q, want normal", FormFillNormal)
	}
	if FormFillRandom != "random" {
		t.Errorf("FormFillRandom = %q, want random", FormFillRandom)
	}
}

func TestConditionTypes(t *testing.T) {
	types := []ConditionType{
		CondURLContains,
		CondURLMatches,
		CondElementExists,
		CondElementVisible,
		CondJavaScript,
		CondXPathExists,
		CondDOMRegex,
		CondCountLimit,
	}

	// Ensure all types are distinct
	seen := make(map[ConditionType]bool)
	for _, typ := range types {
		if seen[typ] {
			t.Errorf("duplicate condition type: %v", typ)
		}
		seen[typ] = true
	}
}
