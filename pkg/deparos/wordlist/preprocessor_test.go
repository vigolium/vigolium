package wordlist

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestHTMLPreprocessor(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "strip tags",
			input: "<div>hello</div><span>world</span>",
			want:  "hello world",
		},
		{
			name:  "decode entities",
			input: "<p>&amp; &lt; &gt; &quot;</p>",
			want:  "& < > \"",
		},
		{
			name:  "extract attributes",
			input: `<a href="/api/users" title="User List">Link</a>`,
			want:  "/api/users User List Link",
		},
		{
			name:  "nested tags",
			input: "<div><p><span>nested</span></p></div>",
			want:  "nested",
		},
		{
			name:  "preserve script content",
			input: "<script>var api = '/admin';</script>",
			want:  "var api = '/admin';",
		},
		{
			name:  "extract comments",
			input: "<!-- secret endpoint: /api/hidden -->",
			want:  " secret endpoint: /api/hidden ",
		},
		{
			name:  "whitespace handling",
			input: "<div>  multiple   spaces  </div>",
			want:  "multiple   spaces",
		},
	}

	prep := &HTMLPreprocessor{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := prep.Process(context.Background(), strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			data, err := io.ReadAll(result)
			if err != nil {
				t.Fatalf("failed to read result: %v", err)
			}

			got := strings.TrimSpace(string(data))
			want := strings.TrimSpace(tt.want)

			if !strings.Contains(got, want) && got != want {
				t.Errorf("got %q, want to contain %q", got, want)
			}
		})
	}
}

func TestJSONPreprocessor(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:         "simple object",
			input:        `{"name": "john", "email": "john@example.com"}`,
			wantContains: []string{"name", "john", "email", "john@example.com"},
		},
		{
			name:         "nested object",
			input:        `{"user": {"name": "bob"}}`,
			wantContains: []string{"user", "name", "bob"},
		},
		{
			name:         "array of strings",
			input:        `["admin", "user", "guest"]`,
			wantContains: []string{"admin", "user", "guest"},
		},
		{
			name:            "skip numbers and booleans",
			input:           `{"id": 123, "active": true, "name": "test"}`,
			wantContains:    []string{"id", "name", "test"},
			wantNotContains: []string{"123", "true"},
		},
		{
			name:            "skip null",
			input:           `{"value": null, "name": "test"}`,
			wantContains:    []string{"value", "name", "test"},
			wantNotContains: []string{"null"},
		},
	}

	prep := &JSONPreprocessor{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := prep.Process(context.Background(), strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			data, err := io.ReadAll(result)
			if err != nil {
				t.Fatalf("failed to read result: %v", err)
			}

			got := string(data)

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("expected to contain %q, got %q", want, got)
				}
			}

			for _, notWant := range tt.wantNotContains {
				if strings.Contains(got, notWant) {
					t.Errorf("should not contain %q, got %q", notWant, got)
				}
			}
		})
	}
}

func TestJSPreprocessor(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:         "double quoted strings",
			input:        `var url = "https://api.example.com";`,
			wantContains: []string{"https://api.example.com"},
		},
		{
			name:         "single quoted strings",
			input:        `var path = '/admin/users';`,
			wantContains: []string{"/admin/users"},
		},
		{
			name:         "template literals",
			input:        "var msg = `Hello World`;",
			wantContains: []string{"Hello World"},
		},
		{
			name:            "skip line comments",
			input:           "// this is a comment\nvar x = 'test';",
			wantContains:    []string{"test"},
			wantNotContains: []string{"comment"},
		},
		{
			name:            "skip block comments",
			input:           "/* block comment */ var y = 'value';",
			wantContains:    []string{"value"},
			wantNotContains: []string{"block"},
		},
		{
			name:         "escape sequences",
			input:        `var escaped = "hello\nworld";`,
			wantContains: []string{"hello\nworld"},
		},
		{
			name:         "multiple strings",
			input:        `var a = "first"; var b = 'second';`,
			wantContains: []string{"first", "second"},
		},
	}

	prep := &JSPreprocessor{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := prep.Process(context.Background(), strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			data, err := io.ReadAll(result)
			if err != nil {
				t.Fatalf("failed to read result: %v", err)
			}

			got := string(data)

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("expected to contain %q, got %q", want, got)
				}
			}

			for _, notWant := range tt.wantNotContains {
				if strings.Contains(got, notWant) {
					t.Errorf("should not contain %q, got %q", notWant, got)
				}
			}
		})
	}
}

func TestCSSPreprocessor(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantContains []string
	}{
		{
			name:         "class selectors",
			input:        ".container { display: flex; } .admin-panel { color: red; }",
			wantContains: []string{"container", "admin-panel"},
		},
		{
			name:         "ID selectors",
			input:        "#main-content { width: 100%; } #sidebar { float: left; }",
			wantContains: []string{"main-content", "sidebar"},
		},
		{
			name:         "URL function",
			input:        `background: url('/images/bg.png');`,
			wantContains: []string{"/images/bg.png"},
		},
		{
			name:         "import statement",
			input:        `@import "theme.css";`,
			wantContains: []string{"theme.css"},
		},
		{
			name:         "custom properties",
			input:        `:root { --primary-color: #333; }`,
			wantContains: []string{"primary-color"},
		},
		{
			name:         "mixed selectors",
			input:        ".btn#submit-btn { cursor: pointer; }",
			wantContains: []string{"btn", "submit-btn"},
		},
	}

	prep := &CSSPreprocessor{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := prep.Process(context.Background(), strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			data, err := io.ReadAll(result)
			if err != nil {
				t.Fatalf("failed to read result: %v", err)
			}

			got := string(data)

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("expected to contain %q, got %q", want, got)
				}
			}
		})
	}
}

func TestTextPreprocessor(t *testing.T) {
	input := "hello world test"
	prep := &TextPreprocessor{}

	result, err := prep.Process(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := io.ReadAll(result)
	if err != nil {
		t.Fatalf("failed to read result: %v", err)
	}

	if string(data) != input {
		t.Errorf("text preprocessor should pass through unchanged, got %q, want %q", string(data), input)
	}
}

func TestPreprocessorRegistry(t *testing.T) {
	registry := NewPreprocessorRegistry()

	tests := []struct {
		contentType string
		checkFunc   func(Preprocessor) bool
	}{
		{"text/html", func(p Preprocessor) bool { _, ok := p.(*HTMLPreprocessor); return ok }},
		{"text/html; charset=utf-8", func(p Preprocessor) bool { _, ok := p.(*HTMLPreprocessor); return ok }},
		{"application/json", func(p Preprocessor) bool { _, ok := p.(*JSONPreprocessor); return ok }},
		{"application/vnd.api+json", func(p Preprocessor) bool { _, ok := p.(*JSONPreprocessor); return ok }},
		{"application/javascript", func(p Preprocessor) bool { _, ok := p.(*JSPreprocessor); return ok }},
		{"text/javascript", func(p Preprocessor) bool { _, ok := p.(*JSPreprocessor); return ok }},
		{"text/css", func(p Preprocessor) bool { _, ok := p.(*CSSPreprocessor); return ok }},
		{"text/plain", func(p Preprocessor) bool { _, ok := p.(*TextPreprocessor); return ok }},
		{"unknown/type", func(p Preprocessor) bool { _, ok := p.(*TextPreprocessor); return ok }},
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			prep := registry.Get(tt.contentType)
			if !tt.checkFunc(prep) {
				t.Errorf("for content-type %q, got unexpected preprocessor type %T", tt.contentType, prep)
			}
		})
	}
}

func TestShouldProcess(t *testing.T) {
	tests := []struct {
		contentType string
		want        bool
	}{
		{"text/html", true},
		{"application/json", true},
		{"text/javascript", true},
		{"text/css", true},
		{"text/plain", true},
		{"application/xml", true},
		{"image/png", false},
		{"image/jpeg", false},
		{"audio/mpeg", false},
		{"video/mp4", false},
		{"font/woff2", false},
		{"application/octet-stream", false},
		{"application/pdf", false},
		{"application/zip", false},
		{"application/gzip", false},
		{"", true}, // Unknown should be processed
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			got := ShouldProcess(tt.contentType)
			if got != tt.want {
				t.Errorf("ShouldProcess(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

func TestGetContentType(t *testing.T) {
	registry := NewPreprocessorRegistry()

	tests := []struct {
		contentType string
		want        ContentType
	}{
		{"text/html", ContentTypeHTML},
		{"text/html; charset=utf-8", ContentTypeHTML},
		{"application/xhtml+xml", ContentTypeHTML},
		{"application/json", ContentTypeJSON},
		{"text/json", ContentTypeJSON},
		{"application/vnd.api+json", ContentTypeJSON},
		{"application/javascript", ContentTypeJavaScript},
		{"text/javascript", ContentTypeJavaScript},
		{"text/css", ContentTypeCSS},
		{"application/xml", ContentTypeXML},
		{"text/xml", ContentTypeXML},
		{"application/rss+xml", ContentTypeXML},
		{"text/plain", ContentTypeText},
		{"unknown/type", ContentTypeText},
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			got := registry.GetContentType(tt.contentType)
			if got != tt.want {
				t.Errorf("GetContentType(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}
