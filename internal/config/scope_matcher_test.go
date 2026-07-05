package config

import (
	"testing"
)

func TestIsStaticFile_DefaultConfig(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	tests := []struct {
		path   string
		static bool
	}{
		// Fonts
		{"/assets/fonts/roboto.woff2", true},
		{"/fonts/arial.ttf", true},
		{"/fonts/icon.eot", true},
		{"/fonts/main.otf", true},
		{"/fonts/web.woff", true},

		// Images
		{"/img/logo.png", true},
		{"/img/banner.jpg", true},
		{"/img/banner.jpeg", true},
		{"/img/photo.gif", true},
		{"/img/bg.webp", true},
		{"/img/icon.ico", true},
		{"/img/photo.avif", true},
		{"/img/pic.bmp", true},

		// Vector images
		{"/assets/icon.svg", true},
		{"/design/logo.eps", true},

		// Video
		{"/media/video.mp4", true},
		{"/media/clip.webm", true},
		{"/media/movie.avi", true},
		{"/media/show.mkv", true},

		// Audio
		{"/audio/song.mp3", true},
		{"/audio/clip.wav", true},
		{"/audio/track.ogg", true},
		{"/audio/music.flac", true},

		// Not static — should pass through
		{"/api/v1/users", false},
		{"/login", false},
		{"/index.html", false},
		{"/app.js", false},
		{"/style.css", false},
		{"/data.json", false},
		{"/api/v1/config.yaml", false},
		{"/", false},
		{"", false},
		{"/path/to/resource", false},
	}

	for _, tt := range tests {
		got := m.IsStaticFile(tt.path)
		if got != tt.static {
			t.Errorf("isStaticFile(%q) = %v, want %v", tt.path, got, tt.static)
		}
	}
}

func TestIsStaticFile_CaseInsensitive(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	paths := []string{
		"/img/LOGO.PNG",
		"/img/Logo.Jpg",
		"/fonts/ROBOTO.WOFF2",
		"/media/VIDEO.MP4",
	}

	for _, p := range paths {
		if !m.IsStaticFile(p) {
			t.Errorf("isStaticFile(%q) = false, want true (case-insensitive)", p)
		}
	}
}

func TestIsStaticFile_Disabled(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg)

	// staticExts should not be built when disabled
	if len(m.staticExts) > 0 {
		t.Error("staticExts should be empty when IgnoreStaticFile is false")
	}

	if m.IsStaticFile("/img/logo.png") {
		t.Error("isStaticFile should return false when IgnoreStaticFile is disabled")
	}
}

func TestIsStaticFile_EmptyExtensionMap(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.IgnoreStaticFile = true
	cfg.IgnoreStaticContentType = map[string][]string{}
	m := NewScopeMatcher(cfg)

	if m.IsStaticFile("/img/logo.png") {
		t.Error("isStaticFile should return false with empty extension map")
	}
}

func TestIsStaticFile_CustomExtensions(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.IgnoreStaticContentType = map[string][]string{
		"custom": {".xyz", ".abc"},
	}
	m := NewScopeMatcher(cfg)

	if !m.IsStaticFile("/file.xyz") {
		t.Error("isStaticFile(/file.xyz) = false, want true")
	}
	if !m.IsStaticFile("/file.abc") {
		t.Error("isStaticFile(/file.abc) = false, want true")
	}
	// Default extensions should not exist since we replaced the map
	if m.IsStaticFile("/img/logo.png") {
		t.Error("isStaticFile(/img/logo.png) should be false with custom-only extensions")
	}
}

func TestIsStaticFile_ExtensionWithoutDot(t *testing.T) {
	cfg := ScopeConfig{
		IgnoreStaticFile:        true,
		IgnoreStaticContentType: map[string][]string{"test": {"xyz"}}, // no leading dot
	}
	m := NewScopeMatcher(cfg)

	// Constructor should add the dot prefix
	if !m.IsStaticFile("/file.xyz") {
		t.Error("isStaticFile(/file.xyz) = false, want true (dot auto-prefixed)")
	}
}

func TestInScope_StaticFileBlocked(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	input := ScopeMatchInput{
		Host:       "example.com",
		Path:       "/assets/logo.png",
		StatusCode: 200,
	}

	if m.InScope(input) {
		t.Error("InScope should return false for static file /assets/logo.png")
	}
}

func TestInScope_NonStaticAllowed(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	input := ScopeMatchInput{
		Host:       "example.com",
		Path:       "/api/v1/users",
		StatusCode: 200,
	}

	if !m.InScope(input) {
		t.Error("InScope should return true for /api/v1/users")
	}
}

func TestInScope_StaticFileAllowedWhenDisabled(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg)

	input := ScopeMatchInput{
		Host:       "example.com",
		Path:       "/assets/logo.png",
		StatusCode: 200,
	}

	if !m.InScope(input) {
		t.Error("InScope should return true for static file when IgnoreStaticFile is false")
	}
}

func TestInScopeRequest_StaticFileBlocked(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	if m.InScopeRequest("example.com", "/fonts/roboto.woff2", "", "") {
		t.Error("InScopeRequest should return false for static file /fonts/roboto.woff2")
	}
}

func TestInScopeRequest_NonStaticAllowed(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	if !m.InScopeRequest("example.com", "/api/login", "application/json", "") {
		t.Error("InScopeRequest should return true for /api/login")
	}
}

func TestInScopeRequest_StaticFileAllowedWhenDisabled(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg)

	if !m.InScopeRequest("example.com", "/fonts/roboto.woff2", "", "") {
		t.Error("InScopeRequest should return true for static file when IgnoreStaticFile is false")
	}
}

func TestIsPassAll_WithStaticFilter(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	if m.IsPassAll() {
		t.Error("IsPassAll should return false when static file filtering is active")
	}
}

func TestIsPassAll_WithoutStaticFilter(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.IgnoreStaticFile = false
	cfg.MaxRequestBodySize = 0
	cfg.MaxResponseBodySize = 0
	m := NewScopeMatcher(cfg)

	if !m.IsPassAll() {
		t.Error("IsPassAll should return true when static file filtering is disabled and all rules are default")
	}
}

func TestInScope_QueryStringDoesNotAffectExtension(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	// filepath.Ext handles this correctly — it only looks at the path component
	// But URL paths with query strings should be tested
	// Note: the Path field in ScopeMatchInput is expected to be just the path,
	// not including the query string. Test that behavior is correct.
	input := ScopeMatchInput{
		Host:       "example.com",
		Path:       "/api/data",
		StatusCode: 200,
	}
	if !m.InScope(input) {
		t.Error("InScope should return true for /api/data (no extension)")
	}
}

func TestCheckBodySize_WithinLimits(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	action, maxReq, maxResp := m.CheckBodySize(100, 200)
	if action != BodySizeOK {
		t.Errorf("expected BodySizeOK, got %d", action)
	}
	if maxReq != 100 || maxResp != 200 {
		t.Errorf("expected maxReq=100 maxResp=200, got %d %d", maxReq, maxResp)
	}
}

func TestCheckBodySize_RequestExceedsTruncate(t *testing.T) {
	cfg := ScopeConfig{
		MaxRequestBodySize:     1024,
		MaxResponseBodySize:    0, // unlimited
		BodySizeExceededAction: "truncate",
	}
	m := NewScopeMatcher(cfg)

	action, maxReq, maxResp := m.CheckBodySize(2048, 500)
	if action != BodySizeTruncate {
		t.Errorf("expected BodySizeTruncate, got %d", action)
	}
	if maxReq != 1024 {
		t.Errorf("expected maxReq=1024, got %d", maxReq)
	}
	if maxResp != 500 {
		t.Errorf("expected maxResp=500 (unchanged), got %d", maxResp)
	}
}

func TestCheckBodySize_ResponseExceedsDrop(t *testing.T) {
	cfg := ScopeConfig{
		MaxRequestBodySize:     0, // unlimited
		MaxResponseBodySize:    512,
		BodySizeExceededAction: "drop",
	}
	m := NewScopeMatcher(cfg)

	action, _, maxResp := m.CheckBodySize(100, 1024)
	if action != BodySizeDrop {
		t.Errorf("expected BodySizeDrop, got %d", action)
	}
	if maxResp != 512 {
		t.Errorf("expected maxResp=512, got %d", maxResp)
	}
}

func TestCheckBodySize_SkipScan(t *testing.T) {
	cfg := ScopeConfig{
		MaxRequestBodySize:     500,
		MaxResponseBodySize:    500,
		BodySizeExceededAction: "skip-scan",
	}
	m := NewScopeMatcher(cfg)

	action, maxReq, maxResp := m.CheckBodySize(1000, 1000)
	if action != BodySizeSkipScan {
		t.Errorf("expected BodySizeSkipScan, got %d", action)
	}
	if maxReq != 500 || maxResp != 500 {
		t.Errorf("expected maxReq=500 maxResp=500, got %d %d", maxReq, maxResp)
	}
}

func TestCheckBodySize_ZeroLimitsUnlimited(t *testing.T) {
	cfg := ScopeConfig{
		MaxRequestBodySize:     0,
		MaxResponseBodySize:    0,
		BodySizeExceededAction: "drop",
	}
	m := NewScopeMatcher(cfg)

	action, _, _ := m.CheckBodySize(999999999, 999999999)
	if action != BodySizeOK {
		t.Errorf("expected BodySizeOK with zero limits, got %d", action)
	}
}

func TestCheckBodySize_DefaultActionIsTruncate(t *testing.T) {
	cfg := ScopeConfig{
		MaxRequestBodySize:     100,
		BodySizeExceededAction: "", // empty should default to truncate
	}
	m := NewScopeMatcher(cfg)

	action, _, _ := m.CheckBodySize(200, 0)
	if action != BodySizeTruncate {
		t.Errorf("expected BodySizeTruncate for empty action, got %d", action)
	}
}

func TestIsPassAll_WithBodySizeLimits(t *testing.T) {
	cfg := ScopeConfig{
		Host:                ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		Path:                ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		StatusCode:          ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		RequestContentType:  ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		ResponseContentType: ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		RequestString:       ScopeRule{Include: []string{}, Exclude: []string{}},
		ResponseString:      ScopeRule{Include: []string{}, Exclude: []string{}},
		MaxRequestBodySize:  1 << 20,
	}
	m := NewScopeMatcher(cfg)

	if m.IsPassAll() {
		t.Error("IsPassAll should return false when MaxRequestBodySize is set")
	}
}

func TestInScope_PathWithDotInDirectory(t *testing.T) {
	cfg := *DefaultScopeConfig()
	m := NewScopeMatcher(cfg)

	// Path with dot in directory name but no static extension at the end
	input := ScopeMatchInput{
		Host:       "example.com",
		Path:       "/api/v1.2/users",
		StatusCode: 200,
	}
	if !m.InScope(input) {
		t.Error("InScope should return true for /api/v1.2/users (dot in directory, not in final segment)")
	}
}

// --- Origin Mode Tests ---

func TestParseOriginTargets_URLs(t *testing.T) {
	targets := parseOriginTargets([]string{
		"http://www.example.com",
		"https://api.example.com:8443/path",
		"http://192.168.1.1:8080",
	})

	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}

	// www.example.com
	if targets[0].exactHost != "www.example.com" {
		t.Errorf("target[0].exactHost = %q, want %q", targets[0].exactHost, "www.example.com")
	}
	if targets[0].etldPlus1 != "example.com" {
		t.Errorf("target[0].etldPlus1 = %q, want %q", targets[0].etldPlus1, "example.com")
	}
	if targets[0].keyword != "example" {
		t.Errorf("target[0].keyword = %q, want %q", targets[0].keyword, "example")
	}
	if targets[0].isIP {
		t.Error("target[0].isIP should be false")
	}

	// api.example.com
	if targets[1].exactHost != "api.example.com" {
		t.Errorf("target[1].exactHost = %q, want %q", targets[1].exactHost, "api.example.com")
	}
	if targets[1].etldPlus1 != "example.com" {
		t.Errorf("target[1].etldPlus1 = %q, want %q", targets[1].etldPlus1, "example.com")
	}

	// IP target
	if targets[2].exactHost != "192.168.1.1" {
		t.Errorf("target[2].exactHost = %q, want %q", targets[2].exactHost, "192.168.1.1")
	}
	if !targets[2].isIP {
		t.Error("target[2].isIP should be true")
	}
}

func TestParseOriginTargets_BareHosts(t *testing.T) {
	targets := parseOriginTargets([]string{
		"example.com",
		"10.0.0.1:443",
	})

	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	if targets[0].exactHost != "example.com" {
		t.Errorf("target[0].exactHost = %q, want %q", targets[0].exactHost, "example.com")
	}
	if targets[1].exactHost != "10.0.0.1" {
		t.Errorf("target[1].exactHost = %q, want %q", targets[1].exactHost, "10.0.0.1")
	}
	if !targets[1].isIP {
		t.Error("target[1].isIP should be true")
	}
}

func TestParseOriginTargets_Dedup(t *testing.T) {
	targets := parseOriginTargets([]string{
		"http://example.com",
		"https://example.com",
		"http://Example.COM:8080/path",
	})

	if len(targets) != 1 {
		t.Fatalf("expected 1 target after dedup, got %d", len(targets))
	}
}

func TestParseOriginTargets_EdgeCases(t *testing.T) {
	targets := parseOriginTargets([]string{"", "  ", "://invalid"})
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets for empty/invalid inputs, got %d", len(targets))
	}
}

func TestOriginMode_Strict(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "strict"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "http://www.example.com")

	tests := []struct {
		host string
		want bool
	}{
		{"www.example.com", true},
		{"example.com", false},
		{"api.example.com", false},
		{"examplesite.com", false},
		{"evil.com", false},
	}

	for _, tt := range tests {
		got := m.hostInScope(tt.host)
		if got != tt.want {
			t.Errorf("strict: hostInScope(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestOriginMode_Balanced(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "balanced"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "http://www.example.com")

	tests := []struct {
		host string
		want bool
	}{
		{"www.example.com", true},
		{"example.com", true},
		{"api.example.com", true},
		{"sub.api.example.com", true},
		{"examplesite.com", false},
		{"test-example.net", false},
		{"evil.com", false},
	}

	for _, tt := range tests {
		got := m.hostInScope(tt.host)
		if got != tt.want {
			t.Errorf("balanced: hostInScope(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestOriginMode_Relaxed(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "relaxed"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "http://www.example.com")

	tests := []struct {
		host string
		want bool
	}{
		{"www.example.com", true},
		{"example.com", true},
		{"api.example.com", true},
		{"examplesite.com", true},
		{"test-example.net", true},
		{"evil.com", false},
		{"google.com", false},
		// A third-party host whose subdomain label merely contains the keyword
		// but whose registrable domain is unrelated must be out of scope. Guards
		// against a bare strings.Contains(host, keyword) match.
		{"example.evil.com", false},
	}

	for _, tt := range tests {
		got := m.hostInScope(tt.host)
		if got != tt.want {
			t.Errorf("relaxed: hostInScope(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

// TestOriginMode_Relaxed_ThirdPartyKeywordSubstring is a regression test for the
// SSO/login-wall case where a scan of admin-newcheckbox-test.roche.com (keyword
// "roche") pulled the Cloudflare Access wall rochegroup.cloudflareaccess.com into
// scope — because "rochegroup" contains "roche" — and deparos discovery then
// actively probed that unrelated third-party host. Relaxed must match the keyword
// against the registrable-domain leading label, not the full hostname.
func TestOriginMode_Relaxed_ThirdPartyKeywordSubstring(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "relaxed"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "https://admin-newcheckbox-test.roche.com")

	tests := []struct {
		host string
		want bool
	}{
		{"admin-newcheckbox-test.roche.com", true}, // the target
		{"wam.roche.com", true},                    // same registrable domain (roche.com IdP)
		{"roche.io", true},                         // same org, different TLD
		{"rochegroup.com", true},                   // brand domain, keyword in registrable label
		{"rochegroup.cloudflareaccess.com", false}, // third-party wall — registrable label "cloudflareaccess"
		{"roche.somecdn.net", false},               // keyword only in a subdomain label
		{"rochegroup", false},                      // single-label host, no eTLD+1 — must not leak via substring
	}

	for _, tt := range tests {
		if got := m.hostInScope(tt.host); got != tt.want {
			t.Errorf("relaxed(roche): hostInScope(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestOriginMode_All(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "all"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "http://www.example.com")

	hosts := []string{"www.example.com", "evil.com", "anything.org", "192.168.1.1"}
	for _, host := range hosts {
		if !m.hostInScope(host) {
			t.Errorf("all: hostInScope(%q) = false, want true", host)
		}
	}
}

func TestOriginMode_MultipleTargets(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "balanced"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "http://app.example.com", "http://api.other.org")

	tests := []struct {
		host string
		want bool
	}{
		{"app.example.com", true},
		{"www.example.com", true},
		{"api.other.org", true},
		{"other.org", true},
		{"evil.com", false},
	}

	for _, tt := range tests {
		got := m.hostInScope(tt.host)
		if got != tt.want {
			t.Errorf("multi-target balanced: hostInScope(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestOriginMode_ANDedWithGlobRules(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "balanced"
	cfg.IgnoreStaticFile = false
	// Only allow *.example.com via glob (exclude api.example.com)
	cfg.Host = ScopeRule{
		Include: []string{"*.example.com"},
		Exclude: []string{"api.example.com"},
	}
	m := NewScopeMatcher(cfg, "http://www.example.com")

	tests := []struct {
		host string
		want bool
	}{
		{"www.example.com", true},  // passes glob AND origin
		{"sub.example.com", true},  // passes glob AND origin
		{"api.example.com", false}, // excluded by glob
		{"example.com", false},     // doesn't match glob *.example.com
		{"evil.com", false},        // fails both
	}

	for _, tt := range tests {
		got := m.hostInScope(tt.host)
		if got != tt.want {
			t.Errorf("AND glob+origin: hostInScope(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestOriginMode_BackwardCompat_NoTargets(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "strict"
	cfg.IgnoreStaticFile = false
	// No targets passed — should not filter anything
	m := NewScopeMatcher(cfg)

	if !m.hostInScope("anything.com") {
		t.Error("no targets + strict: hostInScope should return true (no origin targets to filter against)")
	}
}

func TestOriginMode_IPTarget_ExactMatchRegardlessOfMode(t *testing.T) {
	for _, mode := range []string{"strict", "balanced", "relaxed"} {
		t.Run(mode, func(t *testing.T) {
			cfg := *DefaultScopeConfig()
			cfg.CLIOriginMode = mode
			cfg.IgnoreStaticFile = false
			m := NewScopeMatcher(cfg, "http://10.0.0.1:8080")

			if !m.hostInScope("10.0.0.1") {
				t.Errorf("IP target %s: hostInScope(10.0.0.1) = false, want true", mode)
			}
			if m.hostInScope("10.0.0.2") {
				t.Errorf("IP target %s: hostInScope(10.0.0.2) = true, want false", mode)
			}
		})
	}
}

func TestOriginMode_CacheInvalidation(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "strict"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "http://example.com")

	// First call — cached
	if !m.hostInScope("example.com") {
		t.Fatal("first call should return true")
	}
	if m.hostInScope("evil.com") {
		t.Fatal("evil.com should be false")
	}

	// Invalidate cache
	m.InvalidateCache()

	// Should still work correctly after invalidation
	if !m.hostInScope("example.com") {
		t.Error("after invalidation: example.com should still return true")
	}
	if m.hostInScope("evil.com") {
		t.Error("after invalidation: evil.com should still return false")
	}
}

func TestOriginMode_IsPassAll(t *testing.T) {
	// IsPassAll should be false when origin mode is active with targets
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "balanced"
	cfg.IgnoreStaticFile = false
	cfg.MaxRequestBodySize = 0
	cfg.MaxResponseBodySize = 0
	m := NewScopeMatcher(cfg, "http://example.com")

	if m.IsPassAll() {
		t.Error("IsPassAll should return false when origin mode is balanced with targets")
	}

	// IsPassAll should be true when origin mode is "all"
	cfg2 := *DefaultScopeConfig()
	cfg2.CLIOriginMode = "all"
	cfg2.IgnoreStaticFile = false
	cfg2.MaxRequestBodySize = 0
	cfg2.MaxResponseBodySize = 0
	m2 := NewScopeMatcher(cfg2, "http://example.com")

	if !m2.IsPassAll() {
		t.Error("IsPassAll should return true when origin mode is all")
	}
}

func TestOriginMode_InScope_Integration(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "balanced"
	m := NewScopeMatcher(cfg, "http://www.example.com")

	tests := []struct {
		host    string
		path    string
		inScope bool
	}{
		{"www.example.com", "/api/users", true},
		{"api.example.com", "/login", true},
		{"evil.com", "/api/users", false},
		{"www.example.com", "/img/logo.png", false}, // static file
	}

	for _, tt := range tests {
		input := ScopeMatchInput{
			Host:       tt.host,
			Path:       tt.path,
			StatusCode: 200,
		}
		got := m.InScope(input)
		if got != tt.inScope {
			t.Errorf("InScope(%q, %q) = %v, want %v", tt.host, tt.path, got, tt.inScope)
		}
	}
}

func TestExtractHostFromTarget(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://example.com", "example.com"},
		{"https://example.com:8443/path?q=1", "example.com"},
		{"http://192.168.1.1:8080", "192.168.1.1"},
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"10.0.0.1:8080", "10.0.0.1"},
		{"", ""},
		{"  ", ""},
	}

	for _, tt := range tests {
		got := extractHostFromTarget(tt.input)
		if got != tt.want {
			t.Errorf("extractHostFromTarget(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestOriginMode_CoUKDomain(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "balanced"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "http://www.example.co.uk")

	tests := []struct {
		host string
		want bool
	}{
		{"www.example.co.uk", true},
		{"example.co.uk", true},
		{"api.example.co.uk", true},
		{"example.com", false},
		{"evil.co.uk", false},
	}

	for _, tt := range tests {
		got := m.hostInScope(tt.host)
		if got != tt.want {
			t.Errorf("co.uk balanced: hostInScope(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestOriginMode_EmptyOriginMode(t *testing.T) {
	cfg := *DefaultScopeConfig()
	cfg.CLIOriginMode = "" // empty should default to "relaxed"
	cfg.IgnoreStaticFile = false
	m := NewScopeMatcher(cfg, "http://example.com")

	// With relaxed default, evil.com should be out of scope (no keyword match)
	if m.hostInScope("evil.com") {
		t.Error("empty origin mode should default to relaxed: evil.com should be out of scope")
	}
	// But a host containing the keyword "example" should be in scope
	if !m.hostInScope("example.com") {
		t.Error("empty origin mode should default to relaxed: example.com should be in scope")
	}
}

func TestOriginMode_ModeTable(t *testing.T) {
	// Comprehensive table test matching the plan's behavior table
	target := "http://www.example.com"

	type row struct {
		host     string
		strict   bool
		balanced bool
		relaxed  bool
		all      bool
	}

	table := []row{
		{"www.example.com", true, true, true, true},
		{"example.com", false, true, true, true},
		{"api.example.com", false, true, true, true},
		{"examplesite.com", false, false, true, true},
		{"test-example.net", false, false, true, true},
		{"evil.com", false, false, false, true},
	}

	for _, mode := range []string{"strict", "balanced", "relaxed", "all"} {
		t.Run(mode, func(t *testing.T) {
			cfg := *DefaultScopeConfig()
			cfg.CLIOriginMode = mode
			cfg.IgnoreStaticFile = false
			m := NewScopeMatcher(cfg, target)

			for _, r := range table {
				var want bool
				switch mode {
				case "strict":
					want = r.strict
				case "balanced":
					want = r.balanced
				case "relaxed":
					want = r.relaxed
				case "all":
					want = r.all
				}

				got := m.hostInScope(r.host)
				if got != want {
					t.Errorf("%s: hostInScope(%q) = %v, want %v", mode, r.host, got, want)
				}
			}
		})
	}
}
