package cli

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestBrowserReplayHeaders(t *testing.T) {
	rec := &database.HTTPRecord{
		RawRequest: []byte("GET /x HTTP/1.1\r\nHost: example.com\r\n" +
			"Authorization: Bearer tok\r\nCookie: sid=abc\r\n" +
			"User-Agent: curl/8\r\nX-Other: drop\r\n\r\n"),
	}
	got := browserReplayHeaders(rec)

	want := map[string]string{
		"Authorization": "Bearer tok",
		"Cookie":        "sid=abc",
		"User-Agent":    "curl/8",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d headers %v, want %d %v", len(got), got, len(want), want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("header %q = %q, want %q", k, got[k], v)
		}
	}
	// Only session-bearing headers are forwarded — everything else is dropped.
	if _, ok := got["X-Other"]; ok {
		t.Error("non-session header X-Other should not be forwarded")
	}
}

func TestBrowserReplayHeaders_CaseInsensitive(t *testing.T) {
	// HTTP/2-style lowercased header names must still match.
	rec := &database.HTTPRecord{
		RawRequest: []byte("GET /x HTTP/1.1\r\nhost: example.com\r\ncookie: sid=z\r\n\r\n"),
	}
	if got := browserReplayHeaders(rec); got["Cookie"] != "sid=z" {
		t.Fatalf("Cookie = %q, want sid=z (got %v)", got["Cookie"], got)
	}
}

func TestBrowserReplayHeaders_None(t *testing.T) {
	rec := &database.HTTPRecord{
		RawRequest: []byte("GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"),
	}
	if got := browserReplayHeaders(rec); got != nil {
		t.Errorf("expected nil when no session headers present, got %v", got)
	}
}
