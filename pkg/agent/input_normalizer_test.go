package agent

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestDetectInputType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected InputType
	}{
		{
			name:     "URL with https",
			input:    "https://example.com/api/login",
			expected: InputTypeURL,
		},
		{
			name:     "URL with http",
			input:    "http://localhost:8080/test",
			expected: InputTypeURL,
		},
		{
			name:     "Curl command",
			input:    "curl -X POST https://example.com/api -d '{\"user\":\"admin\"}'",
			expected: InputTypeCurl,
		},
		{
			name:     "Curl command with dollar prefix",
			input:    "$ curl https://example.com/api",
			expected: InputTypeCurl,
		},
		{
			name:     "Raw HTTP GET request",
			input:    "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expected: InputTypeRaw,
		},
		{
			name:     "Raw HTTP POST request",
			input:    "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}",
			expected: InputTypeRaw,
		},
		{
			name:     "UUID record",
			input:    "550e8400-e29b-41d4-a716-446655440000",
			expected: InputTypeRecordUUID,
		},
		{
			name:     "Burp XML",
			input:    "<?xml version=\"1.0\"?><items><item><url>https://example.com</url></item></items>",
			expected: InputTypeBurp,
		},
		{
			name:     "Burp XML items only",
			input:    "<items><item><url>https://example.com</url></item></items>",
			expected: InputTypeBurp,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: InputTypeUnknown,
		},
		{
			name:     "Whitespace only",
			input:    "   \n\t  ",
			expected: InputTypeUnknown,
		},
		{
			name:     "Random text",
			input:    "hello world",
			expected: InputTypeUnknown,
		},
		{
			name:     "Base64-encoded GET request",
			input:    base64.StdEncoding.EncodeToString([]byte("GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n")),
			expected: InputTypeBase64,
		},
		{
			name:     "Base64-encoded POST request with body",
			input:    base64.StdEncoding.EncodeToString([]byte("POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}")),
			expected: InputTypeBase64,
		},
		{
			name:     "Base64-encoded Burp-style export (long)",
			input:    "R0VUIC9yZXN0L3Byb2R1Y3RzL3NlYXJjaD9xPWFwcGxlIEhUVFAvMS4xCkhvc3Q6IGxvY2FsaG9zdDozMDAwCnNlYy1jaC11YS1wbGF0Zm9ybTogIm1hY09TIgpBdXRob3JpemF0aW9uOiBCZWFyZXIgZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBaQ0k2TVN3aWRYTmxjbTVoYldVaU9pSmhaRzFwYmlJc0luSnZiR1VpT2lKaFpHMXBiaUlzSW1saGRDSTZNVGMzTXpBM05qTXlOU3dpWlhod0lqb3hOemN6TURjNU9USTFmUS5jMmxuYm1GMGRYSmxYMmRsYm1WeVlYUmxaRjkzYVhSb1gzTmxZM0psZERFeU13CkFjY2VwdC1MYW5ndWFnZTogZW4tVVMsZW47cT0wLjkKQWNjZXB0OiBhcHBsaWNhdGlvbi9qc29uLCB0ZXh0L3BsYWluLCAqLyoKc2VjLWNoLXVhOiAiQ2hyb21pdW0iO3Y9IjE0NSIsICJOb3Q6QS1CcmFuZCI7dj0iOTkiClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xNDUuMC4wLjAgU2FmYXJpLzUzNy4zNgpzZWMtY2gtdWEtbW9iaWxlOiA/MApDb25uZWN0aW9uOiBrZWVwLWFsaXZlCg==",
			expected: InputTypeBase64,
		},
		{
			name:     "Short base64 that is not HTTP",
			input:    base64.StdEncoding.EncodeToString([]byte("hello world this is not http")),
			expected: InputTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectInputType(tt.input)
			if result != tt.expected {
				t.Errorf("DetectInputType(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeInput_URL(t *testing.T) {
	records, err := NormalizeInput(context.Background(), "https://example.com/api/test", InputTypeURL, nil)
	if err != nil {
		t.Fatalf("NormalizeInput URL failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Request() == nil {
		t.Fatal("expected non-nil request")
	}
}

func TestNormalizeInput_Curl(t *testing.T) {
	records, err := NormalizeInput(context.Background(), "curl -X POST https://example.com/api -H 'Content-Type: application/json' -d '{\"key\":\"value\"}'", InputTypeCurl, nil)
	if err != nil {
		t.Fatalf("NormalizeInput Curl failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}

func TestNormalizeInput_Raw(t *testing.T) {
	raw := "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n"
	records, err := NormalizeInput(context.Background(), raw, InputTypeRaw, nil)
	if err != nil {
		t.Fatalf("NormalizeInput Raw failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}

func TestNormalizeInput_RecordUUID_NoRepo(t *testing.T) {
	_, err := NormalizeInput(context.Background(), "550e8400-e29b-41d4-a716-446655440000", InputTypeRecordUUID, nil)
	if err == nil {
		t.Fatal("expected error for record UUID without repo")
	}
}

func TestNormalizeInput_AutoDetect(t *testing.T) {
	records, err := NormalizeInput(context.Background(), "https://example.com/api", "", nil)
	if err != nil {
		t.Fatalf("NormalizeInput auto-detect URL failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}

func TestNormalizeInput_Base64(t *testing.T) {
	raw := "GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	records, err := NormalizeInput(context.Background(), encoded, "", nil)
	if err != nil {
		t.Fatalf("NormalizeInput Base64 failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Request() == nil {
		t.Fatal("expected non-nil request")
	}
	method := records[0].Request().Method()
	if method != "GET" {
		t.Errorf("expected method GET, got %q", method)
	}
}

func TestNormalizeInput_Base64_BurpExport(t *testing.T) {
	// Real-world Burp base64 export
	input := "R0VUIC9yZXN0L3Byb2R1Y3RzL3NlYXJjaD9xPWFwcGxlIEhUVFAvMS4xCkhvc3Q6IGxvY2FsaG9zdDozMDAwCnNlYy1jaC11YS1wbGF0Zm9ybTogIm1hY09TIgpBdXRob3JpemF0aW9uOiBCZWFyZXIgZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBaQ0k2TVN3aWRYTmxjbTVoYldVaU9pSmhaRzFwYmlJc0luSnZiR1VpT2lKaFpHMXBiaUlzSW1saGRDSTZNVGMzTXpBM05qTXlOU3dpWlhod0lqb3hOemN6TURjNU9USTFmUS5jMmxuYm1GMGRYSmxYMmRsYm1WeVlYUmxaRjkzYVhSb1gzTmxZM0psZERFeU13CkFjY2VwdC1MYW5ndWFnZTogZW4tVVMsZW47cT0wLjkKQWNjZXB0OiBhcHBsaWNhdGlvbi9qc29uLCB0ZXh0L3BsYWluLCAqLyoKc2VjLWNoLXVhOiAiQ2hyb21pdW0iO3Y9IjE0NSIsICJOb3Q6QS1CcmFuZCI7dj0iOTkiClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xNDUuMC4wLjAgU2FmYXJpLzUzNy4zNgpzZWMtY2gtdWEtbW9iaWxlOiA/MApTZWMtRmV0Y2gtU2l0ZTogc2FtZS1vcmlnaW4KU2VjLUZldGNoLU1vZGU6IGNvcnMKU2VjLUZldGNoLURlc3Q6IGVtcHR5ClJlZmVyZXI6IGh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC8KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlLCBicgpDb29raWU6IGxhbmd1YWdlPWVuOwpJZi1Ob25lLU1hdGNoOiBXLyIzNTRjLXYzWjVpOVZJUzI3S2RJUHZleTQxWFBCUFdTSSIKQ29ubmVjdGlvbjoga2VlcC1hbGl2ZQo="

	records, err := NormalizeInput(context.Background(), input, "", nil)
	if err != nil {
		t.Fatalf("NormalizeInput Base64 Burp export failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	req := records[0].Request()
	if req == nil {
		t.Fatal("expected non-nil request")
	}
	if req.Method() != "GET" {
		t.Errorf("expected GET, got %q", req.Method())
	}
	if req.Path() != "/rest/products/search?q=apple" {
		t.Errorf("unexpected path: %q", req.Path())
	}
}

func TestTargetURLFromInput_Base64(t *testing.T) {
	raw := "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	targetURL, err := TargetURLFromInput(context.Background(), encoded, "", nil)
	if err != nil {
		t.Fatalf("TargetURLFromInput Base64 failed: %v", err)
	}
	if targetURL == "" {
		t.Fatal("expected non-empty target URL")
	}
}
