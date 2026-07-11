package runner

import "testing"

func TestBrowserAuthFromHeaders(t *testing.T) {
	headers := []string{
		"Cookie: session=abc; theme=dark",
		"Authorization: Bearer tok123",
		"X-Api-Key: k1",
		"Host: example.com",  // hop-by-hop-ish: must be dropped
		"Content-Length: 42", // connection-scoped: must be dropped
		"  ",                 // malformed: skipped
		"NoColonHeaderValue", // malformed: skipped
		"Empty:",             // empty value: skipped
	}

	cookies, extra := browserAuthFromHeaders(headers)

	// Cookies: the single Cookie header splits into two cookies.
	got := map[string]string{}
	for _, c := range cookies {
		got[c.Name] = c.Value
	}
	if len(got) != 2 || got["session"] != "abc" || got["theme"] != "dark" {
		t.Fatalf("cookies = %#v, want session=abc, theme=dark", got)
	}

	// Extra headers: Authorization + X-Api-Key kept; Host/Content-Length/Cookie dropped.
	if extra["Authorization"] != "Bearer tok123" {
		t.Errorf("extra Authorization = %q, want %q", extra["Authorization"], "Bearer tok123")
	}
	if extra["X-Api-Key"] != "k1" {
		t.Errorf("extra X-Api-Key = %q, want %q", extra["X-Api-Key"], "k1")
	}
	for _, dropped := range []string{"Host", "Content-Length", "Cookie", "NoColonHeaderValue", "Empty"} {
		if _, ok := extra[dropped]; ok {
			t.Errorf("extra unexpectedly contains %q", dropped)
		}
	}
}

func TestBrowserAuthFromHeadersEmpty(t *testing.T) {
	cookies, extra := browserAuthFromHeaders(nil)
	if cookies != nil {
		t.Errorf("cookies = %#v, want nil", cookies)
	}
	if extra != nil {
		t.Errorf("extra = %#v, want nil", extra)
	}
}
