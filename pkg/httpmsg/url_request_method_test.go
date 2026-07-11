package httpmsg

import (
	"testing"
)

// TestGetRawRequestFromURLWithMethod verifies that non-GET discoveries preserve
// their method, headers, and body across import instead of being flattened to a
// bodyless GET (which would lose API/form coverage during dynamic assessment).
func TestGetRawRequestFromURLWithMethod(t *testing.T) {
	t.Run("post with body and headers", func(t *testing.T) {
		rr, err := GetRawRequestFromURLWithMethod(
			"https://api.example.com/users",
			"post",
			map[string]string{"Content-Type": "application/json", "X-Api-Key": "k"},
			[]byte(`{"name":"alice"}`),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := rr.Request().Method(); got != "POST" {
			t.Errorf("method = %q, want POST", got)
		}
		if got := string(rr.Request().Body()); got != `{"name":"alice"}` {
			t.Errorf("body = %q, want the stored JSON body", got)
		}
		if got := rr.Request().Header("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if got := rr.Request().Header("X-Api-Key"); got != "k" {
			t.Errorf("X-Api-Key = %q, want k", got)
		}
		// Content-Length must be derived from the body, not the stored map.
		if got := rr.Request().Header("Content-Length"); got != "16" {
			t.Errorf("Content-Length = %q, want 16", got)
		}
		if line := requestLine(rr.Request().Raw()); line != "POST /users HTTP/1.1" {
			t.Errorf("request-line = %q, want POST /users HTTP/1.1", line)
		}
	})

	t.Run("empty method and body falls back to GET", func(t *testing.T) {
		rr, err := GetRawRequestFromURLWithMethod("https://h.example.com/a", "", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := rr.Request().Method(); got != "GET" {
			t.Errorf("method = %q, want GET", got)
		}
	})

	t.Run("get with body keeps body", func(t *testing.T) {
		rr, err := GetRawRequestFromURLWithMethod("https://h.example.com/graphql", "GET", nil, []byte("query{}"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := rr.Request().Method(); got != "GET" {
			t.Errorf("method = %q, want GET", got)
		}
		if got := string(rr.Request().Body()); got != "query{}" {
			t.Errorf("body = %q, want query{}", got)
		}
	})

	t.Run("crlf in header value is dropped", func(t *testing.T) {
		rr, err := GetRawRequestFromURLWithMethod(
			"https://h.example.com/x",
			"PUT",
			map[string]string{"X-Evil": "a\r\nInjected: 1", "X-Good": "ok"},
			[]byte("body"),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := rr.Request().Header("Injected"); got != "" {
			t.Errorf("header injection leaked: Injected = %q", got)
		}
		if got := rr.Request().Header("X-Good"); got != "ok" {
			t.Errorf("X-Good = %q, want ok", got)
		}
	})
}
