package wordlist

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// Helper to run tokenizer and collect results
func tokenize(t *testing.T, cfg *Config, input string, contentType ContentType) []string {
	t.Helper()
	tokenizer := NewTokenizer(cfg)
	seen := make(map[string]struct{})
	var tokens []string

	err := tokenizer.Tokenize(context.Background(), strings.NewReader(input), contentType, seen, func(token *Token) {
		tokens = append(tokens, token.Value)
	})
	if err != nil {
		t.Fatalf("tokenize error: %v", err)
	}
	return tokens
}

// Helper to check if two slices have the same elements (order-independent)
func sameElements(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

func TestTokenizer_BasicAlphaNum(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "simple words",
			input: "hello world test",
			want:  []string{"hello", "world", "test"},
		},
		{
			name:  "mixed case",
			input: "Hello World TEST",
			want:  []string{"Hello", "World", "TEST"},
		},
		{
			name:  "with numbers",
			input: "user123 test456 admin",
			want:  []string{"user123", "test456", "admin"},
		},
		{
			name:  "special chars split",
			input: "admin/api/users",
			want:  []string{"admin", "api", "users"},
		},
		{
			name:  "multiple separators",
			input: "hello...world///test",
			want:  []string{"hello", "world", "test"},
		},
		{
			name:  "unicode filtered",
			input: "hello世界world",
			want:  []string{"hello", "world"},
		},
		{
			name:  "numbers only",
			input: "123 456 789",
			want:  []string{"123", "456", "789"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MinLength = 1
			cfg.FilterKeywords = false

			got := tokenize(t, cfg, tt.input, ContentTypeText)
			if !sameElements(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenizer_MinMaxLength(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		minLength int
		maxLength int
		want      []string
	}{
		{
			name:      "filter short",
			input:     "a ab abc abcd",
			minLength: 3,
			maxLength: 64,
			want:      []string{"abc", "abcd"},
		},
		{
			name:      "filter long",
			input:     "short medium verylongwordhere",
			minLength: 1,
			maxLength: 10,
			want:      []string{"short", "medium"},
		},
		{
			name:      "default min length 3",
			input:     "ab abc abcd",
			minLength: 3,
			maxLength: 64,
			want:      []string{"abc", "abcd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MinLength = tt.minLength
			cfg.MaxLength = tt.maxLength
			cfg.FilterKeywords = false

			got := tokenize(t, cfg, tt.input, ContentTypeText)
			if !sameElements(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenizer_DelimExceptions(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		delimExceptions string
		maxCombine      int
		want            []string
	}{
		{
			name:            "hyphen exception",
			input:           "admin-api",
			delimExceptions: "-",
			maxCombine:      2,
			want:            []string{"admin", "api", "admin-api"},
		},
		{
			name:            "underscore exception",
			input:           "user_config",
			delimExceptions: "_",
			maxCombine:      2,
			want:            []string{"user", "config", "user_config"},
		},
		{
			name:            "both hyphen and underscore",
			input:           "admin-api_v2",
			delimExceptions: "-_",
			maxCombine:      2,
			// admin-api_v2 with both - and _ as delims
			// Segments: admin, api, v2
			// Note: current implementation uses the LAST delimiter for all combinations
			// So both combos use _ (the last seen delimiter)
			want: []string{"admin", "api", "v2", "admin_api", "api_v2"},
		},
		{
			name:            "three segments max combine 2",
			input:           "admin-api-v2",
			delimExceptions: "-",
			maxCombine:      2,
			// Segments: admin, api, v2
			// 2-segment combos: admin-api, api-v2
			want: []string{"admin", "api", "v2", "admin-api", "api-v2"},
		},
		{
			name:            "three segments max combine 3",
			input:           "admin-api-v2",
			delimExceptions: "-",
			maxCombine:      3,
			// Segments: admin, api, v2
			// 2-segment combos: admin-api, api-v2
			// 3-segment combos: admin-api-v2
			want: []string{"admin", "api", "v2", "admin-api", "api-v2", "admin-api-v2"},
		},
		{
			name:            "four segments max combine 2",
			input:           "get-user-by-id",
			delimExceptions: "-",
			maxCombine:      2,
			// Segments: get, user, by, id
			// 2-segment combos: get-user, user-by, by-id
			want: []string{"get", "user", "by", "id", "get-user", "user-by", "by-id"},
		},
		{
			name:            "no delim exception",
			input:           "admin-api",
			delimExceptions: "",
			maxCombine:      2,
			// Without delim exception, - is just a separator
			want: []string{"admin", "api"},
		},
		{
			name:            "max combine 1 disables combinations",
			input:           "admin-api-v2",
			delimExceptions: "-",
			maxCombine:      1,
			// Only individual segments, no combinations
			want: []string{"admin", "api", "v2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MinLength = 1
			cfg.DelimExceptions = tt.delimExceptions
			cfg.MaxCombine = tt.maxCombine
			cfg.FilterKeywords = false

			got := tokenize(t, cfg, tt.input, ContentTypeText)
			if !sameElements(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenizer_GlobalDedup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 1
	cfg.FilterKeywords = false
	tokenizer := NewTokenizer(cfg)
	seen := make(map[string]struct{})

	// First tokenization
	var tokens1 []string
	err := tokenizer.Tokenize(context.Background(), strings.NewReader("hello world hello"), ContentTypeText, seen, func(token *Token) {
		tokens1 = append(tokens1, token.Value)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have only unique tokens
	if !sameElements(tokens1, []string{"hello", "world"}) {
		t.Errorf("first tokenize: got %v, want [hello world]", tokens1)
	}

	// Second tokenization with same seen map
	var tokens2 []string
	err = tokenizer.Tokenize(context.Background(), strings.NewReader("hello new world"), ContentTypeText, seen, func(token *Token) {
		tokens2 = append(tokens2, token.Value)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have "new" since hello and world were already seen
	if !sameElements(tokens2, []string{"new"}) {
		t.Errorf("second tokenize: got %v, want [new]", tokens2)
	}
}

func TestTokenizer_URLDecode(t *testing.T) {
	// NOTE: URL decode is NOT currently implemented in the tokenizer.
	// The AutoURLDecode config option exists but is not used.
	// These tests document the ACTUAL current behavior where % acts as a delimiter.
	tests := []struct {
		name          string
		input         string
		autoURLDecode bool
		want          []string
	}{
		{
			name:          "percent acts as delimiter",
			input:         "admin%20api",
			autoURLDecode: true,
			// % is not alphanumeric, so it acts as a delimiter
			// Output: "admin", "20api"
			want: []string{"admin", "20api"},
		},
		{
			name:          "percent acts as delimiter disabled",
			input:         "admin%20api",
			autoURLDecode: false,
			// Same behavior regardless of autoURLDecode
			want: []string{"admin", "20api"},
		},
		{
			name:          "percent in path",
			input:         "admin%2Fapi",
			autoURLDecode: true,
			// % is delimiter, then 2Fapi is alphanumeric
			want: []string{"admin", "2Fapi"},
		},
		{
			name:          "multiple percent chars",
			input:         "hello%20world%2Ftest",
			autoURLDecode: true,
			// Each % acts as delimiter
			want: []string{"hello", "20world", "2Ftest"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MinLength = 1
			cfg.AutoURLDecode = tt.autoURLDecode
			cfg.FilterKeywords = false

			got := tokenize(t, cfg, tt.input, ContentTypeText)
			if !sameElements(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenizer_KeywordFiltering(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		contentType    ContentType
		filterKeywords bool
		want           []string
	}{
		{
			name:           "filter HTML keywords",
			input:          "div span admin container",
			contentType:    ContentTypeHTML,
			filterKeywords: true,
			// "div" and "span" are HTML keywords, should be filtered
			want: []string{"admin", "container"},
		},
		{
			name:           "filter JS keywords",
			input:          "function admin const config",
			contentType:    ContentTypeJavaScript,
			filterKeywords: true,
			// "function" and "const" are JS keywords, should be filtered
			// "config" is also a common JS keyword
			want: []string{"admin"},
		},
		{
			name:           "filter disabled",
			input:          "div span admin",
			contentType:    ContentTypeHTML,
			filterKeywords: false,
			// Nothing filtered
			want: []string{"div", "span", "admin"},
		},
		{
			name:           "case insensitive filter",
			input:          "DIV SPAN Admin",
			contentType:    ContentTypeHTML,
			filterKeywords: true,
			// DIV and SPAN should still be filtered (case insensitive)
			want: []string{"Admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MinLength = 1
			cfg.FilterKeywords = tt.filterKeywords

			got := tokenize(t, cfg, tt.input, tt.contentType)
			if !sameElements(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenizer_Position(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 1
	cfg.FilterKeywords = false
	tokenizer := NewTokenizer(cfg)
	seen := make(map[string]struct{})

	var positions []int
	err := tokenizer.Tokenize(context.Background(), strings.NewReader("hello world"), ContentTypeText, seen, func(token *Token) {
		positions = append(positions, token.Position)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// "hello" starts at 0, "world" starts at 6
	if len(positions) != 2 {
		t.Fatalf("expected 2 positions, got %d", len(positions))
	}
	if positions[0] != 0 {
		t.Errorf("first token position: got %d, want 0", positions[0])
	}
	if positions[1] != 6 {
		t.Errorf("second token position: got %d, want 6", positions[1])
	}
}

func TestTokenizer_EmptyInput(t *testing.T) {
	cfg := DefaultConfig()
	tokenizer := NewTokenizer(cfg)
	seen := make(map[string]struct{})

	var tokens []string
	err := tokenizer.Tokenize(context.Background(), strings.NewReader(""), ContentTypeText, seen, func(token *Token) {
		tokens = append(tokens, token.Value)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tokens) != 0 {
		t.Errorf("expected no tokens for empty input, got %v", tokens)
	}
}

func TestTokenizer_ContextCancellation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinLength = 1
	tokenizer := NewTokenizer(cfg)
	seen := make(map[string]struct{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := tokenizer.Tokenize(ctx, strings.NewReader("hello world"), ContentTypeText, seen, func(token *Token) {})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func BenchmarkTokenizer(b *testing.B) {
	cfg := DefaultConfig()
	cfg.FilterKeywords = false
	tokenizer := NewTokenizer(cfg)

	input := strings.Repeat("hello world test admin api users config ", 1000)
	reader := strings.NewReader(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seen := make(map[string]struct{})
		reader.Reset(input)
		_ = tokenizer.Tokenize(context.Background(), reader, ContentTypeText, seen, func(token *Token) {})
	}
}
