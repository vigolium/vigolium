package httpmsg

import (
	"strings"
	"testing"
)

func pointsByName(t *testing.T, raw string) map[string]InsertionPoint {
	t.Helper()
	pts, err := CreateAllInsertionPoints([]byte(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]InsertionPoint{}
	for _, p := range pts {
		out[p.Type().String()+":"+p.Name()] = p
	}
	return out
}

// Pre-encoded payloads reach the server as written: '%' is not
// re-escaped, while bytes that cannot appear literally are.
func TestBuildPreEncoded_QueryAndHeader(t *testing.T) {
	raw := "GET /a?file=x HTTP/1.1\r\nHost: h.test\r\nX-Custom: v\r\n\r\n"
	pts := pointsByName(t, raw)
	var q, hdr InsertionPoint
	for k, p := range pts {
		if strings.HasSuffix(k, ":file") {
			q = p
		}
		if strings.HasSuffix(k, ":X-Custom") {
			hdr = p
		}
	}
	if q == nil || hdr == nil {
		t.Fatalf("missing points: %v", pts)
	}

	for _, tc := range []struct{ payload, want string }{
		{"%252e%252e%252fetc%252fpasswd", "?file=%252e%252e%252fetc%252fpasswd "},
		{"../etc/passwd%00.jpg", "?file=../etc/passwd%00.jpg "},
		{"%C0%AE%C0%AE/etc", "?file=%C0%AE%C0%AE/etc "},
		{"a\rb c#d", "?file=a%0Db%20c%23d "},
	} {
		got := string(BuildPreEncoded(q, []byte(tc.payload)))
		if !strings.Contains(got, tc.want) {
			t.Errorf("query %q: request line %q lacks %q", tc.payload, strings.SplitN(got, "\r\n", 2)[0], tc.want)
		}
	}
	// BuildRequest still double-encodes, as before.
	if got := string(q.BuildRequest([]byte("%00"))); !strings.Contains(got, "?file=%2500 ") {
		t.Errorf("BuildRequest changed: %q", strings.SplitN(got, "\r\n", 2)[0])
	}

	got := string(BuildPreEncoded(hdr, []byte("v%0d%0aSet-Cookie: x=1")))
	if !strings.Contains(got, "X-Custom: v%0d%0aSet-Cookie: x=1\r\n") {
		t.Errorf("header pre-encoded payload altered: %q", got)
	}
	got = string(BuildPreEncoded(hdr, []byte("v\r\nInjected: 1")))
	if strings.Contains(got, "\r\nInjected: 1") {
		t.Errorf("raw CRLF in a pre-encoded header payload split the request: %q", got)
	}
}

// Point types without a percent layer fall back to BuildRequest.
func TestBuildPreEncoded_JSONFallsBack(t *testing.T) {
	raw := "POST /a HTTP/1.1\r\nHost: h.test\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"k\":\"v\"}"
	for _, p := range pointsByName(t, raw) {
		if p.Name() != "k" || p.Type() != INS_PARAM_JSON {
			continue
		}
		if string(BuildPreEncoded(p, []byte("%00"))) != string(p.BuildRequest([]byte("%00"))) {
			t.Error("JSON pre-encoded build must equal BuildRequest")
		}
		return
	}
	t.Fatal("no JSON point k")
}
