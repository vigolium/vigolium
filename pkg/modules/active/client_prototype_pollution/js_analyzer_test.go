package client_prototype_pollution

import (
	"testing"
)

func TestExtractInlineScripts(t *testing.T) {
	tests := []struct {
		name string
		html string
		want int
	}{
		{
			name: "single inline script",
			html: `<html><script>var x = 1;</script></html>`,
			want: 1,
		},
		{
			name: "multiple inline scripts",
			html: `<html><script>var a = 1;</script><script>var b = 2;</script></html>`,
			want: 2,
		},
		{
			name: "external script skipped",
			html: `<html><script src="/app.js"></script><script>var x = 1;</script></html>`,
			want: 1,
		},
		{
			name: "all external scripts",
			html: `<html><script src="/a.js"></script><script src="/b.js"></script></html>`,
			want: 0,
		},
		{
			name: "empty script tag",
			html: `<html><script>   </script></html>`,
			want: 0,
		},
		{
			name: "no scripts",
			html: `<html><body><p>Hello</p></body></html>`,
			want: 0,
		},
		{
			name: "mixed scripts",
			html: `<html>
				<script src="https://cdn.example.com/lib.js"></script>
				<script>
					$.extend(true, defaults, userInput);
				</script>
				<script type="text/javascript">
					var config = {};
				</script>
			</html>`,
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractInlineScripts(tt.html)
			if len(got) != tt.want {
				t.Errorf("extractInlineScripts() returned %d scripts, want %d", len(got), tt.want)
				for i, s := range got {
					t.Logf("  script[%d]: %s", i, s)
				}
			}
		})
	}
}

func TestExtractInlineScripts_Content(t *testing.T) {
	html := `<html><script>var vulnerable = $.extend(true, {}, input);</script></html>`
	scripts := extractInlineScripts(html)
	if len(scripts) != 1 {
		t.Fatalf("expected 1 script, got %d", len(scripts))
	}
	if scripts[0] != "var vulnerable = $.extend(true, {}, input);" {
		t.Errorf("unexpected content: %s", scripts[0])
	}
}

func TestExtractExternalScriptURLs(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "single external script",
			html: `<script src="/js/app.js"></script>`,
			want: []string{"/js/app.js"},
		},
		{
			name: "multiple external scripts",
			html: `<script src="/a.js"></script><script src="/b.js"></script>`,
			want: []string{"/a.js", "/b.js"},
		},
		{
			name: "double quotes",
			html: `<script src="https://example.com/app.js"></script>`,
			want: []string{"https://example.com/app.js"},
		},
		{
			name: "single quotes",
			html: `<script src='https://example.com/app.js'></script>`,
			want: []string{"https://example.com/app.js"},
		},
		{
			name: "inline script no src",
			html: `<script>var x = 1;</script>`,
			want: nil,
		},
		{
			name: "no scripts",
			html: `<html><body></body></html>`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractExternalScriptURLs(tt.html)
			if len(got) != len(tt.want) {
				t.Fatalf("expected %d URLs, got %d: %v", len(tt.want), len(got), got)
			}
			for i, url := range got {
				if url != tt.want[i] {
					t.Errorf("URL[%d] = %q, want %q", i, url, tt.want[i])
				}
			}
		})
	}
}

func TestIsCDNURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js", true},
		{"https://unpkg.com/vue@3.2.0/dist/vue.global.js", true},
		{"https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js", true},
		{"https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js", true},
		{"https://code.jquery.com/jquery-3.6.0.min.js", true},
		{"https://example.com/js/app.js", false},
		{"https://mysite.com/vendor/custom.js", false},
		{"/js/local.js", false},
		{"invalid-url", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isCDNURL(tt.url)
			if got != tt.want {
				t.Errorf("isCDNURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestResolveScriptURL(t *testing.T) {
	tests := []struct {
		name      string
		pageURL   string
		scriptSrc string
		want      string
	}{
		{
			name:      "absolute URL",
			pageURL:   "https://example.com/page",
			scriptSrc: "https://cdn.example.com/app.js",
			want:      "https://cdn.example.com/app.js",
		},
		{
			name:      "relative path",
			pageURL:   "https://example.com/page",
			scriptSrc: "/js/app.js",
			want:      "https://example.com/js/app.js",
		},
		{
			name:      "relative to current",
			pageURL:   "https://example.com/pages/about",
			scriptSrc: "app.js",
			want:      "https://example.com/pages/app.js",
		},
		{
			name:      "protocol relative",
			pageURL:   "https://example.com/page",
			scriptSrc: "//cdn.example.com/app.js",
			want:      "https://cdn.example.com/app.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveScriptURL(tt.pageURL, tt.scriptSrc)
			if got != tt.want {
				t.Errorf("resolveScriptURL(%q, %q) = %q, want %q", tt.pageURL, tt.scriptSrc, got, tt.want)
			}
		})
	}
}
