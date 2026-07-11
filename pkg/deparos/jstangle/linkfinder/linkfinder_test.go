package linkfinder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractPaths(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantURLs []string
	}{
		{
			name: "fetch call",
			body: `fetch('/api/users')`,
			wantURLs: []string{
				"/api/users",
			},
		},
		{
			name: "axios get",
			body: `axios.get('/v1/products')`,
			wantURLs: []string{
				"/v1/products",
			},
		},
		{
			name: "jquery post",
			body: `$.post('/auth/login')`,
			wantURLs: []string{
				"/auth/login",
			},
		},
		{
			name: "object notation",
			body: `const config = { url: '/api/data' }`,
			wantURLs: []string{
				"/api/data",
			},
		},
		{
			name: "variable assignment",
			body: `const API_URL = '/api/v1/resource'`,
			wantURLs: []string{
				"/api/v1/resource",
			},
		},
		{
			name: "template literal path",
			body: "fetch(`/api/users/123`)",
			wantURLs: []string{
				"/api/users/123",
			},
		},
		{
			name: "minified code",
			body: `a.get("/api"),b.post("/users")`,
			wantURLs: []string{
				"/api",
				"/users",
			},
		},
		{
			name: "escaped characters",
			body: `url: "\/api\/escaped"`,
			wantURLs: []string{
				"/api/escaped",
			},
		},
		{
			name: "query strings",
			body: `fetch('/search?q=test&page=1')`,
			wantURLs: []string{
				"/search?q=test&page=1",
			},
		},
		{
			name: "multiple paths",
			body: `
				fetch('/api/users');
				axios.get('/api/products');
				$.ajax('/api/orders');
			`,
			wantURLs: []string{
				"/api/users",
				"/api/products",
				"/api/orders",
			},
		},
		{
			name: "XMLHttpRequest open",
			body: `request.open('GET', '/api/data')`,
			wantURLs: []string{
				"/api/data",
			},
		},
		{
			name: "window.open",
			body: `window.open('/popup/info.html')`,
			wantURLs: []string{
				"/popup/info.html",
			},
		},
		{
			name: "path with file extension",
			body: `href="/static/app.js"`,
			wantURLs: []string{
				"/static/app.js",
			},
		},
		{
			name: "PHP file",
			body: `"submit.php?action=save"`,
			wantURLs: []string{
				"submit.php?action=save",
			},
		},
		{
			name: "action attribute",
			body: `action="/form/submit"`,
			wantURLs: []string{
				"/form/submit",
			},
		},
		{
			name: "src attribute",
			body: `src="/assets/config.xml"`,
			wantURLs: []string{
				"/assets/config.xml",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			foundURLs := ExtractPaths([]byte(tt.body))

			// Check that all expected URLs were found
			for _, wantURL := range tt.wantURLs {
				assert.Contains(t, foundURLs, wantURL, "Expected to find URL: %s", wantURL)
			}
		})
	}
}

func TestExtractPaths_SpamFilter(t *testing.T) {
	spamCases := []string{
		// Dangerous URL-encoded characters
		`"/path%00injection"`,
		`"/path%22quote"`,
		`"/path%27quote"`,
		`"/path%3Cscript%3E"`,
		`"/path%3cimg"`,
		`"/path%3escript"`,
		`"/path%7Cpipe"`,
		`"/path%7cpipe"`,
		// URL-encoded brackets
		`"quote%5D/2019/"`,
		`"quote%5D"`,
		`"quote%5d"`,
		`"%5Bfoo"`,
		`"%5bbar"`,
		`"abc%5D/def"`,
		`"/path%5B%5D"`,
		// JS template garbage patterns (encoded)
		`"/js/+t%5Bn"`,
		`"/js/+e%5Bn.action%5D%5Bn.actionurl%5D"`,
		`"/en/+t%5Bn.image%5D"`,
		`"/en/+t%5Bn.url%5D"`,
		`"/en/+t%5Bn"`,
		`"/js/Estimado/+t%5Bn.url%5D"`,
		`"/locales/add/1/+e%5Bn.action%5D%5Bn"`,
		`"/locales/1/+e%5Bn.action%5D%5Bn.actionurl%5D"`,
		`"/api/+t%5Bn.image%5D"`,
		// JS template garbage patterns (decoded)
		`"+t[n.image]/"`,
		`"+e[n.action]/"`,
		`"/api/+t[n.url]"`,
		`"/js/+e[n.action][n.actionurl]"`,
		// Unbalanced brackets
		`"/plain]"`,
		`"/["`,
		`"/]"`,
		`"/foo]bar"`,
		`"/[bar"`,
		`"/[[["`,
		`"/]]]"`,
		`"/users/]"`,
		`"/api/["`,
		`"plain]"`,
		`"abc/plain]"`,
		`"]plan"`,
		`"text/plain]"`,
		// Regex metacharacter patterns (standalone segments)
		`"+((t-m)"`,
		`"+((n-v)"`,
		`".*microsites.*"`,
		`"++test"`,
		`"+*pattern"`,
		`"(?=lookahead)"`,
		`"(?!negative)"`,
		`"[^negation]"`,
		// Regex patterns in paths
		`"/users/+((t-m)"`,
		`"/users/+((n-v)"`,
		`"/users/.*microsites.*"`,
		`"/api/++test"`,
		// Comma-prefixed segments
		`",fn=test"`,
		`",id=123"`,
		`"/aem/,fn="`,
		`"/api/,name=value"`,
		// Unbalanced parentheses
		`"/api/test(foo"`,
		`"/users/(incomplete"`,
		`"func(arg"`,
		// Data URIs
		`"data:image/png;base64,ABC123"`,
		// Mailto
		`"mailto:test@example.com"`,
		// CSS values
		`"10px"`,
		`"#ffffff"`,
		`"rgb(255,255,255)"`,
		`"rgba(0,0,0,0.5)"`,
		// Short strings
		`"en"`,
		`"us"`,
		`"px"`,
		// Pure numbers
		`"123"`,
		`"456"`,
		// JavaScript constants
		`"true"`,
		`"false"`,
		`"null"`,
		`"undefined"`,
		// Dates
		`"2024-01-01"`,
		`"12:30"`,
		// Template vars only
		`"${baseUrl}"`,
		// CSS rules
		`"@media"`,
		`"@keyframes"`,
		// Spaces/pipes
		`"hello world"`,
		`"a|b"`,
		// CONSTANTS
		`"MY_CONSTANT"`,
		`"API_KEY"`,
		// MIME types
		`"text/html"`,
		`"application/json"`,
		// Version numbers
		`"v1.2.3"`,
		`"2.0.0"`,
		// CSS keywords
		`"block"`,
		`"inline"`,
		`"center"`,
		`"solid"`,
	}

	for _, spam := range spamCases {
		t.Run(spam, func(t *testing.T) {
			foundURLs := ExtractPaths([]byte(spam))

			// Should not extract spam content
			assert.Empty(t, foundURLs, "Should not extract spam: %s", spam)
		})
	}
}

func TestExtractPaths_EmptyBody(t *testing.T) {
	foundURLs := ExtractPaths([]byte{})
	assert.Empty(t, foundURLs)
}

func TestExtractPaths_MinifiedJS(t *testing.T) {
	// Real-world minified JavaScript snippet
	body := `!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():fetch("/api/v1/config").then(function(e){return e.json()}).then(function(t){axios.post("/api/v1/track",{data:t})})}(this,function(){var e="/api/v1/users";return{getUsers:function(){return fetch(e)},getPosts:function(){return fetch("/api/v1/posts")}}})`

	foundURLs := ExtractPaths([]byte(body))

	// Should find all API paths in minified code
	expectedPaths := []string{
		"/api/v1/config",
		"/api/v1/track",
		"/api/v1/users",
		"/api/v1/posts",
	}

	for _, expected := range expectedPaths {
		assert.Contains(t, foundURLs, expected, "Should find path in minified JS: %s", expected)
	}
}

func TestExtractPaths_Deduplication(t *testing.T) {
	// Body with duplicate paths
	body := `
		fetch('/api/users');
		fetch('/api/users');
		axios.get('/api/users');
	`

	foundURLs := ExtractPaths([]byte(body))

	// Count occurrences
	count := 0
	for _, u := range foundURLs {
		if u == "/api/users" {
			count++
		}
	}
	assert.Equal(t, 1, count, "Should deduplicate paths")
}

func TestHelperFunctions(t *testing.T) {
	t.Run("startsWithAlphabets", func(t *testing.T) {
		assert.True(t, startsWithAlphabets("api/users"))
		assert.True(t, startsWithAlphabets("API/USERS"))
		assert.False(t, startsWithAlphabets("/api"))
		assert.False(t, startsWithAlphabets("123"))
		assert.False(t, startsWithAlphabets(""))
	})

	t.Run("getExtensionOfPath", func(t *testing.T) {
		assert.Equal(t, "js", getExtensionOfPath("/app.js"))
		assert.Equal(t, "html", getExtensionOfPath("/page.html"))
		assert.Equal(t, "php", getExtensionOfPath("/submit.php?action=save"))
		assert.Equal(t, "json", getExtensionOfPath("/data.json#section"))
		assert.Equal(t, "", getExtensionOfPath("/api/users"))
	})

	t.Run("validateEnclosurePairs", func(t *testing.T) {
		assert.True(t, validateEnclosurePairs("{baseUrl}"))
		assert.False(t, validateEnclosurePairs("baseUrl"))
		assert.False(t, validateEnclosurePairs("{baseUrl"))
		assert.False(t, validateEnclosurePairs("baseUrl}"))
	})

	t.Run("filterNewLines", func(t *testing.T) {
		assert.Equal(t, "hello world", filterNewLines("hello\nworld"))
		assert.Equal(t, "hello world", filterNewLines("hello\r\nworld"))
		assert.Equal(t, "hello world", filterNewLines("  hello\tworld  "))
	})
}

func BenchmarkExtractPaths(b *testing.B) {
	// Realistic JavaScript content
	jsContent := `
		const API_BASE = '/api/v1';

		function loadUsers() {
			return fetch('/api/v1/users')
				.then(res => res.json());
		}

		function createUser(data) {
			return axios.post('/api/v1/users', data);
		}

		const routes = {
			users: '/api/v1/users',
			posts: '/api/v1/posts',
			comments: '/api/v1/comments',
			auth: {
				login: '/api/v1/auth/login',
				logout: '/api/v1/auth/logout',
				register: '/api/v1/auth/register'
			}
		};

		$.ajax({
			url: '/api/v1/settings',
			method: 'GET'
		});
	`

	body := []byte(jsContent)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractPaths(body)
	}
}

func TestIsSpamURL(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		isSpam bool
	}{
		// Spam patterns
		{"empty", "", true},
		{"data uri", "data:image/png;base64,ABC", true},
		{"mailto", "mailto:test@example.com", true},
		{"css value px", "10px", true},
		{"css value hex", "#ffffff", true},
		{"constant", "MY_CONSTANT", true},
		{"mime type html", "text/html", true},
		{"mime type json", "application/json", true},
		{"unbalanced bracket close", "/api/users]", true},
		{"unbalanced bracket open", "/api/[users", true},
		{"js garbage", "/api/+t[n.image]", true},
		{"short string", "en", true},
		{"pure number", "123", true},
		{"js constant true", "true", true},
		{"js constant false", "false", true},
		{"js constant null", "null", true},
		{"date format", "2024-01-01", true},
		{"template var", "${baseUrl}", true},
		{"css at rule", "@media", true},
		{"space in path", "hello world", true},
		{"pipe in path", "a|b", true},
		{"version number", "v1.2.3", true},
		{"css keyword", "block", true},
		{"regex meta", "/users/+((t-m)", true},
		{"comma prefix", "/api/,fn=test", true},

		// Valid URLs
		{"api path", "/api/users", false},
		{"nested api path", "/api/v1/users/123", false},
		{"file with ext", "/static/app.js", false},
		{"query string", "/search?q=test", false},
		{"path with dash", "/my-api/endpoint", false},
		{"path with underscore", "/my_api/endpoint", false},
		{"deep path", "/a/b/c/d/e", false},
		{"path with param placeholder", "/users/[id]", false},
		{"path with curly placeholder", "/api/{version}/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSpamURL(tt.url)
			assert.Equal(t, tt.isSpam, result, "IsSpamURL(%q) = %v, want %v", tt.url, result, tt.isSpam)
		})
	}
}
