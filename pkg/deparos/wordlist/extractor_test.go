package wordlist

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestExtractor_HTML(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
	<div class="container admin-panel">
		<a href="/api/users">Users</a>
		<span id="user-count">100</span>
	</div>
	<script>var apiEndpoint = "/api/v1/data";</script>
</body>
</html>`

	cfg := DefaultConfig()
	cfg.MinLength = 2
	cfg.DelimExceptions = "-"
	cfg.MaxCombine = 2
	cfg.FilterKeywords = true
	extractor := NewExtractor(cfg)

	var got []string
	err := extractor.ExtractBytes(context.Background(), []byte(html), "text/html", func(token *Token) {
		got = append(got, token.Value)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should extract: Test, Page, container, admin, panel, admin-panel, api, users, user, count, user-count, etc.
	// Keywords like "div", "span", "href" should be filtered

	// Check some expected tokens are present
	expected := []string{"Test", "Page", "container", "admin", "panel", "admin-panel", "api", "users"}
	for _, e := range expected {
		found := false
		for _, g := range got {
			if g == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected token %q not found in %v", e, got)
		}
	}

	// Check keywords are filtered
	filtered := []string{"div", "span", "href", "html", "body", "head", "title", "script"}
	for _, f := range filtered {
		for _, g := range got {
			if strings.EqualFold(g, f) {
				t.Errorf("keyword %q should be filtered but found in output", f)
				break
			}
		}
	}
}

func TestExtractor_JSON(t *testing.T) {
	json := `{
		"user": {
			"name": "john_doe",
			"email": "john@example.com",
			"roles": ["admin", "user"]
		},
		"api_endpoint": "/api/v1/users",
		"count": 100,
		"active": true
	}`

	cfg := DefaultConfig()
	cfg.MinLength = 2
	cfg.DelimExceptions = "_"
	cfg.MaxCombine = 2
	cfg.FilterKeywords = false // JSON has minimal keywords
	extractor := NewExtractor(cfg)

	var got []string
	err := extractor.ExtractBytes(context.Background(), []byte(json), "application/json", func(token *Token) {
		got = append(got, token.Value)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should extract string keys and values
	expected := []string{"user", "name", "john", "doe", "john_doe", "email", "example", "com", "roles", "admin", "api", "endpoint", "api_endpoint", "users", "count", "active"}
	for _, e := range expected {
		found := false
		for _, g := range got {
			if g == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected token %q not found in %v", e, got)
		}
	}
}

func TestExtractor_JavaScript(t *testing.T) {
	js := `
// Configuration
const API_URL = "https://api.example.com/v1";
var adminEndpoint = '/admin/dashboard';

function getUserData(userId) {
	// Fetch user data
	return fetch(API_URL + "/users/" + userId);
}

/*
 * Multi-line comment
 * with some text
 */
let config = {
	"api-key": "secret123",
	endpoint: '/api/config'
};
`

	cfg := DefaultConfig()
	cfg.MinLength = 2
	cfg.DelimExceptions = "-"
	cfg.MaxCombine = 2
	cfg.FilterKeywords = true
	extractor := NewExtractor(cfg)

	var got []string
	err := extractor.ExtractBytes(context.Background(), []byte(js), "application/javascript", func(token *Token) {
		got = append(got, token.Value)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should extract string literals only
	// Note: "config" is a JS keyword and filtered. "https" may be split by ":" as delimiter
	expected := []string{"api", "example", "com", "admin", "dashboard", "users", "api-key", "secret123"}
	for _, e := range expected {
		found := false
		for _, g := range got {
			if g == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected token %q not found in %v", e, got)
		}
	}
}

func TestExtractor_CSS(t *testing.T) {
	css := `
.container {
	display: flex;
}

#main-content {
	background: url('/images/bg.png');
}

.admin-panel {
	--custom-color: #fff;
}

@import "theme.css";

@keyframes slideIn {
	from { transform: translateX(-100%); }
	to { transform: translateX(0); }
}
`

	cfg := DefaultConfig()
	cfg.MinLength = 2
	cfg.DelimExceptions = "-"
	cfg.MaxCombine = 2
	cfg.FilterKeywords = true
	extractor := NewExtractor(cfg)

	var got []string
	err := extractor.ExtractBytes(context.Background(), []byte(css), "text/css", func(token *Token) {
		got = append(got, token.Value)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should extract class names, IDs, and URLs
	// Note: "content" and "color" are CSS keywords and will be filtered individually,
	// but "main-content" and "custom-color" combinations should still appear
	expected := []string{"container", "main", "main-content", "images", "png", "admin", "panel", "admin-panel", "custom", "custom-color", "theme", "css"}
	for _, e := range expected {
		found := false
		for _, g := range got {
			if g == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected token %q not found in %v", e, got)
		}
	}
}

func TestExtractor_PlainText(t *testing.T) {
	text := `
user-management api-endpoint
admin_panel user_settings
configuration.json
test123 data456
`

	cfg := DefaultConfig()
	cfg.MinLength = 2
	cfg.DelimExceptions = "-_"
	cfg.MaxCombine = 2
	cfg.FilterKeywords = false
	extractor := NewExtractor(cfg)

	var got []string
	err := extractor.ExtractBytes(context.Background(), []byte(text), "text/plain", func(token *Token) {
		got = append(got, token.Value)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"user", "management", "user-management", "api", "endpoint", "api-endpoint", "admin", "panel", "admin_panel", "user_settings", "configuration", "json", "test123", "data456"}
	for _, e := range expected {
		found := false
		for _, g := range got {
			if g == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected token %q not found in %v", e, got)
		}
	}
}

func TestExtractor_LocalDedupWithinSingleExtraction(t *testing.T) {
	// Within a single extraction, consecutive duplicates should be filtered by localSeen
	extractor := NewExtractor(DefaultConfig())

	var got []string
	err := extractor.ExtractBytes(context.Background(), []byte("hello hello hello world world"), "text/plain", func(token *Token) {
		got = append(got, token.Value)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have hello and world only once each (local dedup within single extraction)
	counts := make(map[string]int)
	for _, g := range got {
		counts[g]++
	}

	if counts["hello"] != 1 {
		t.Errorf("expected 'hello' once, got %d times", counts["hello"])
	}
	if counts["world"] != 1 {
		t.Errorf("expected 'world' once, got %d times", counts["world"])
	}
}

func TestExtractor_NoDedupAcrossExtractions(t *testing.T) {
	// Across multiple extractions, the same words should be emitted again
	// (global dedup is now handled by ObservedProvider, not Extractor)
	extractor := NewExtractor(DefaultConfig())

	// First extraction
	var got1 []string
	err := extractor.ExtractBytes(context.Background(), []byte("hello world"), "text/plain", func(token *Token) {
		got1 = append(got1, token.Value)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second extraction with same words
	var got2 []string
	err = extractor.ExtractBytes(context.Background(), []byte("hello world again"), "text/plain", func(token *Token) {
		got2 = append(got2, token.Value)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// "hello" and "world" SHOULD be in second result (no global dedup in Extractor anymore)
	foundHello := false
	foundWorld := false
	for _, g := range got2 {
		if g == "hello" {
			foundHello = true
		}
		if g == "world" {
			foundWorld = true
		}
	}

	if !foundHello {
		t.Errorf("expected 'hello' in second extraction (no global dedup)")
	}
	if !foundWorld {
		t.Errorf("expected 'world' in second extraction (no global dedup)")
	}

	// "again" should also be in second result
	foundAgain := false
	for _, g := range got2 {
		if g == "again" {
			foundAgain = true
			break
		}
	}
	if !foundAgain {
		t.Errorf("new token 'again' should be in output")
	}
}

func TestExtractor_ThreadSafety(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 1
	cfg.FilterKeywords = false
	extractor := NewExtractor(cfg)

	var wg sync.WaitGroup
	numGoroutines := 10
	var mu sync.Mutex
	allTokens := make([]string, 0)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			input := strings.Repeat("word"+string(rune('A'+id))+" ", 100)
			err := extractor.ExtractBytes(context.Background(), []byte(input), "text/plain", func(token *Token) {
				mu.Lock()
				allTokens = append(allTokens, token.Value)
				mu.Unlock()
			})
			if err != nil {
				t.Errorf("goroutine %d error: %v", id, err)
			}
		}(i)
	}

	wg.Wait()

	// Should have extracted tokens from all goroutines
	if len(allTokens) < numGoroutines {
		t.Errorf("expected at least %d tokens, got %d", numGoroutines, len(allTokens))
	}
}

func TestExtractor_SkipBinaryContentTypes(t *testing.T) {
	binaryTypes := []string{
		"image/png",
		"image/jpeg",
		"audio/mpeg",
		"video/mp4",
		"font/woff2",
		"application/octet-stream",
		"application/pdf",
		"application/zip",
	}

	for _, ct := range binaryTypes {
		t.Run(ct, func(t *testing.T) {
			extractor := NewExtractor(DefaultConfig())

			var got []string
			err := extractor.ExtractBytes(context.Background(), []byte("hello world test"), ct, func(token *Token) {
				got = append(got, token.Value)
			})

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != 0 {
				t.Errorf("expected no tokens for binary content type %s, got %v", ct, got)
			}
		})
	}
}

func TestExtractor_ContentTypeDetection(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    ContentType
	}{
		{
			name:    "detect HTML",
			content: "<!DOCTYPE html><html><body>test</body></html>",
			want:    ContentTypeHTML,
		},
		{
			name:    "detect JSON object",
			content: `{"key": "value"}`,
			want:    ContentTypeJSON,
		},
		{
			name:    "detect JSON array",
			content: `["item1", "item2"]`,
			want:    ContentTypeJSON,
		},
		{
			name:    "detect JavaScript function",
			content: `function test() { return 1; }`,
			want:    ContentTypeJavaScript,
		},
		{
			name:    "detect JavaScript const",
			content: `const API = "test";`,
			want:    ContentTypeJavaScript,
		},
		{
			name:    "detect CSS class",
			content: `.container { display: flex; }`,
			want:    ContentTypeCSS,
		},
		{
			name:    "detect CSS ID",
			content: `#main { width: 100%; }`,
			want:    ContentTypeCSS,
		},
		{
			name:    "detect XML",
			content: `<?xml version="1.0"?><root></root>`,
			want:    ContentTypeXML,
		},
		{
			name:    "default to text",
			content: `just some plain text here`,
			want:    ContentTypeText,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectContentType([]byte(tt.content))
			if got != tt.want {
				t.Errorf("DetectContentType() = %v, want %v", got, tt.want)
			}
		})
	}
}
