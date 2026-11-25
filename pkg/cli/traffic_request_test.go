package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// TestRequestViewIsTheWholeRequest holds the item a deterministic reader
// (gimorra's transform admission) parses: the method off the request line,
// the URL, every header in order with duplicates, and the body as stored.
func TestRequestViewIsTheWholeRequest(t *testing.T) {
	head := "POST /v2/orders?limit=5 HTTP/1.1\r\nHost: api.example.test\r\nX-Ts: 1700000000\r\nX-Signature: 0b26e1\r\nAuthorization: Bearer tok-1\r\nX-Dup: a\r\nX-Dup: b"
	got := requestView("uuid-1", "https://api.example.test/v2/orders?limit=5", head, []byte(`{"qty":1}`), false)

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	_ = json.Unmarshal(raw, &keys)
	for _, k := range []string{"uuid", "method", "url", "target", "headers", "body", "body_encoding", "complete"} {
		if _, ok := keys[k]; !ok {
			t.Fatalf("item lacks %q: %s", k, raw)
		}
	}
	if got.Target != "/v2/orders?limit=5" {
		t.Fatalf("target = %q", got.Target)
	}
	if odd := requestView("u", "https://h/a/b", "GET /a/%2F?x=%2f&y HTTP/1.1", nil, false); odd.Target != "/a/%2F?x=%2f&y" {
		t.Fatalf("target not byte for byte: %q", odd.Target)
	}
	if got.Method != "POST" || got.Body != `{"qty":1}` || got.BodyEncoding != "utf8" || !got.Complete {
		t.Fatalf("view = %+v", got)
	}
	if len(got.Headers) != 6 || got.Headers[3].Name != "Authorization" || got.Headers[3].Value != "Bearer tok-1" ||
		got.Headers[5].Value != "b" {
		t.Fatalf("headers = %+v", got.Headers)
	}
}

func TestRequestViewDecodesGzipAndBase64sBinary(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte("hello"))
	_ = w.Close()
	if got := requestView("u", "https://h/", "PUT / HTTP/1.1\r\nHost: h", gz.Bytes(), false); got.Body != "hello" || got.BodyEncoding != "utf8" {
		t.Fatalf("gzip body = %+v", got)
	}
	bin := []byte{0xff, 0xfe, 0x00, 0x01}
	got := requestView("u", "https://h/", "PUT / HTTP/1.1\r\nHost: h", bin, false)
	if got.BodyEncoding != "base64" || got.Body != base64.StdEncoding.EncodeToString(bin) {
		t.Fatalf("binary body = %+v", got)
	}
	if empty := requestView("u", "https://h/", "GET / HTTP/1.1", nil, false); empty.Headers == nil || empty.Body != "" {
		t.Fatalf("empty = %+v", empty)
	}
}

// Under redaction the credential header is masked like every other view.
func TestRequestViewRedactsOnlyWhenAsked(t *testing.T) {
	// A masked view sets the package-level viewsRedacted for the rest of the invocation; reset it
	// here as json_redact_test.go does, or every envelope a later test renders reads as redacted.
	t.Cleanup(func() { viewsRedacted.Store(false) })
	head := "GET / HTTP/1.1\r\nAuthorization: Bearer secret-token-value"
	if got := requestView("u", "https://h/", head, nil, true); got.Headers[0].Value == "Bearer secret-token-value" {
		t.Fatalf("redacted view kept the credential: %+v", got.Headers)
	}
}
