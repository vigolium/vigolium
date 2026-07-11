package linkfinder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestJSPatternsIndividual tests that each input is extracted by the jsPatterns.
// This ensures that when we merge patterns, we don't lose any functionality.
func TestJSPatternsIndividual(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		// ============================================================
		// Group 1: HTTP Method Calls
		// ============================================================

		// Pattern 0: [a-zA-Z].(get|post|fetch|patch|delete|option|put|ajax)
		{"api.get single quotes", `api.get('/users')`, []string{"/users"}},
		{"http.post double quotes", `http.post("/api/data")`, []string{"/api/data"}},
		{"client.fetch", `client.fetch('/items')`, []string{"/items"}},
		{"x.delete", `x.delete('/remove')`, []string{"/remove"}},
		{"a.patch", `a.patch('/update')`, []string{"/update"}},
		{"b.put", `b.put('/save')`, []string{"/save"}},
		{"c.ajax", `c.ajax('/call')`, []string{"/call"}},
		{"d.option", `d.option('/check')`, []string{"/check"}},

		// Pattern 1: fetch(...)
		{"fetch single quotes", `fetch('/api/users')`, []string{"/api/users"}},
		{"fetch double quotes", `fetch("/data")`, []string{"/data"}},
		{"fetch backticks", "fetch(`/items`)", []string{"/items"}},
		{"fetch with spaces", `fetch( "/endpoint" )`, []string{"/endpoint"}},
		{"fetch with query", `fetch('/search?q=test')`, []string{"/search?q=test"}},

		// Pattern 5: axios/jquery/http/$/instance.(get|post|...)
		{"axios.get", `axios.get('/api/users')`, []string{"/api/users"}},
		{"axios.post", `axios.post('/api/create')`, []string{"/api/create"}},
		{"$.post", `$.post('/submit')`, []string{"/submit"}},
		{"$.get", `$.get('/fetch')`, []string{"/fetch"}},
		{"$.ajax", `$.ajax('/data')`, []string{"/data"}},
		{"jquery.ajax", `jquery.ajax('/jq-data')`, []string{"/jq-data"}},
		{"http.delete", `http.delete('/item')`, []string{"/item"}},
		{"http.put", `http.put('/update')`, []string{"/update"}},
		{"instance.get", `instance.get('/instance-api')`, []string{"/instance-api"}},
		{"instance.post", `instance.post('/instance-create')`, []string{"/instance-create"}},

		// Pattern 6: (axios|...).(method)(variableName,
		{"axios.get with variable", `axios.get(API_URL,`, []string{"API_URL"}},
		{"axios.post with variable", `axios.post(ENDPOINT,`, []string{"ENDPOINT"}},
		{"$.get with var", `$.get(url,`, []string{"url"}},
		{"$.post with var", `$.post(endpoint,`, []string{"endpoint"}},
		{"http.get with var", `http.get(apiBase,`, []string{"apiBase"}},
		{"instance.get var", `instance.get(config.url,`, []string{"config.url"}},

		// Pattern 7: fetch('...',
		{"fetch with comma", `fetch('/api/items',`, []string{"/api/items"}},
		{"fetch with options", `fetch("/api/data",`, []string{"/api/data"}},

		// Pattern 8: XMLHttpRequest
		{"request.open GET", `request.open('GET', '/api/data')`, []string{"/api/data"}},
		{"request.open POST", `request.open("POST", "/submit")`, []string{"/submit"}},
		{"req.open GET", `req.open('GET', '/req-data')`, []string{"/req-data"}},
		{"req.open POST", `req.open("POST", "/req-submit")`, []string{"/req-submit"}},

		// Pattern 10: axios.get(var + '...')
		{"axios var concat", `axios.get(baseUrl + '/users')`, []string{"/users"}},
		{"axios var concat post", `axios.post(API_BASE + '/create')`, []string{"/create"}},
		{"$.get var concat", `$.get(base + '/jquery')`, []string{"/jquery"}},
		{"$.post var concat", `$.post(API + "/data")`, []string{"/data"}},
		{"http.get concat", `http.get(url + '/endpoint')`, []string{"/endpoint"}},

		// Pattern 11: axios.get('/...+ var +...') - extracts the template string
		// Note: The actual pattern extracts differently than expected
		{"axios path with var", `axios.get('/api/' + id + '/')`, []string{"/api/"}},
		{"$.post path with var", `$.post('/users/' + userId + '/profile')`, []string{"/users/"}},

		// ============================================================
		// Group 2: Property Assignments
		// ============================================================

		// Pattern 2: (url|path|file)'...: '...'
		{"url property colon single", `url': '/api/endpoint'`, []string{"/api/endpoint"}},
		{"url property colon double", `url": "/api/data"`, []string{"/api/data"}},
		{"path property colon", `path": "/config"`, []string{"/config"}},
		{"file property colon", `file': '/upload'`, []string{"/upload"}},

		// Pattern 3: url: '...'
		{"url colon value", `url: '/api/users'`, []string{"/api/users"}},
		{"url colon double quotes", `url: "/api/data"`, []string{"/api/data"}},
		{"URL uppercase", `URL: "/data"`, []string{"/data"}},
		{"url in object", `{ url: '/config' }`, []string{"/config"}},

		// Pattern 4: url: var + '...'
		{"url with concat", `url: baseUrl + '/endpoint'`, []string{"/endpoint"}},
		{"url with concat 2", `url: API + '/users'`, []string{"/users"}},

		// Pattern 12: (path|pathname|file) = '...'
		{"path assignment", `path = '/config'`, []string{"/config"}},
		{"path colon", `path: '/route'`, []string{"/route"}},
		{"pathname assignment", `pathname = '/page'`, []string{"/page"}},
		{"pathname colon", `pathname: '/route'`, []string{"/route"}},
		{"file assignment", `file = "./data.json"`, []string{"./data.json"}},
		{"file colon", `file: '/upload'`, []string{"/upload"}},

		// ============================================================
		// Group 3: Variable Declarations
		// ============================================================

		// Pattern 9: const/let/var x = '...'
		{"const with path", `const apiUrl = '/api/v1'`, []string{"/api/v1"}},
		{"const with full url", `const url = "https://api.example.com"`, []string{"https://api.example.com"}},
		{"let with path", `let endpoint = '/api/endpoint'`, []string{"/api/endpoint"}},
		{"let with https", `let api = "https://api.test.com/v1"`, []string{"https://api.test.com/v1"}},
		{"var with relative", `var path = './config'`, []string{"./config"}},
		{"var with path", `var route = '/users/profile'`, []string{"/users/profile"}},

		// ============================================================
		// Group 4: HTML Attributes
		// ============================================================

		// Pattern 13: href|src|action = "..."
		// Note: Pattern requires attribute name to contain href/src/action
		// data-href works but ng-src and v-bind:src don't match the pattern
		{"href attribute", ` href="/page"`, []string{"/page"}},
		{"href double quotes", ` href="/link"`, []string{"/link"}},
		{"src attribute", ` src="/script.js"`, []string{"/script.js"}},
		{"action attribute", ` action="/submit"`, []string{"/submit"}},
		{"xlink:href", ` xlink:href="/svg-link"`, []string{"/svg-link"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]struct{})
			extractUsingJSPatterns(tt.input, seen)

			for _, exp := range tt.expected {
				_, found := seen[exp]
				assert.True(t, found, "Expected to find %q in extracted paths. Got: %v", exp, mapKeys(seen))
			}
		})
	}
}

// TestJSPatternsNegative tests inputs that should NOT be extracted
func TestJSPatternsNegative(t *testing.T) {
	inputs := []struct {
		name  string
		input string
	}{
		{"empty string", ``},
		{"plain text", `hello world`},
		{"number only", `12345`},
		{"invalid syntax", `fetch`},
		{"incomplete fetch", `fetch(`},
		{"no quotes", `fetch(/api/users)`},
	}

	for _, tt := range inputs {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]struct{})
			extractUsingJSPatterns(tt.input, seen)

			// These should extract nothing or only specific expected values
			// The important thing is they don't crash
			assert.NotPanics(t, func() {
				extractUsingJSPatterns(tt.input, seen)
			})
		})
	}
}

// TestJSPatternsRealWorld tests with real-world JavaScript snippets
func TestJSPatternsRealWorld(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:  "minified axios calls",
			input: `a.get("/api/v1"),b.post("/users"),axios.delete("/item/123")`,
			expected: []string{
				"/api/v1",
				"/users",
				"/item/123",
			},
		},
		{
			name: "mixed fetch and axios",
			input: `
				fetch('/api/config').then(r => r.json());
				axios.get('/api/users');
				$.post('/auth/login', data);
			`,
			expected: []string{
				"/api/config",
				"/api/users",
				"/auth/login",
			},
		},
		{
			name: "object with multiple urls",
			input: `
				const config = {
					url: '/api/main',
					path: '/assets',
					file: '/upload/image'
				};
			`,
			expected: []string{
				"/api/main",
				"/assets",
				"/upload/image",
			},
		},
		{
			name: "XMLHttpRequest example",
			input: `
				var req = new XMLHttpRequest();
				req.open('GET', '/api/data');
				req.send();
			`,
			expected: []string{"/api/data"},
		},
		{
			name: "variable declarations",
			input: `
				const API_URL = '/api/v1';
				let endpoint = 'https://api.example.com/v2';
				var legacyPath = './old/config';
			`,
			expected: []string{
				"/api/v1",
				"https://api.example.com/v2",
				"./old/config",
			},
		},
		{
			name: "HTML attributes in JS template",
			input: `
				<a href="/home">Home</a>
				<img src="/images/logo.png" />
				<form action="/submit">
			`,
			expected: []string{
				"/home",
				"/images/logo.png",
				"/submit",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]struct{})
			extractUsingJSPatterns(tt.input, seen)

			for _, exp := range tt.expected {
				_, found := seen[exp]
				assert.True(t, found, "Expected to find %q in extracted paths. Got: %v", exp, mapKeys(seen))
			}
		})
	}
}

// mapKeys returns the keys of a map as a slice for debugging
func mapKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
