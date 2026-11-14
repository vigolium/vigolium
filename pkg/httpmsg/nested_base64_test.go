package httpmsg

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// A base64url-unpadded JSON state parameter round-trips: the child's payload is
// re-wrapped in the same base64 variant (MISS-13). Before, detection missed the
// URL-safe/unpadded variant entirely, and even a std-base64 value went back as
// the raw JSON document.
func TestNestedBase64URLUnpaddedRoundTrip(t *testing.T) {
	doc := `{"redirect":"/home?x=1","nonce":"abc~~~>"}` // '>' / '~' force URL-alphabet chars
	state := base64.RawURLEncoding.EncodeToString([]byte(doc))
	if !strings.ContainsAny(state, "-_") {
		t.Fatalf("fixture %q has no URL-alphabet characters", state)
	}
	raw := "GET /cb?state=" + state + "&code=1 HTTP/1.1\r\nHost: h.test\r\n\r\n"

	pts, err := CreateAllInsertionPoints([]byte(raw), true)
	if err != nil {
		t.Fatal(err)
	}
	var child InsertionPoint
	for _, p := range pts {
		if _, ok := p.(*NestedInsertionPoint); ok && p.Name() == "redirect" {
			child = p
		}
	}
	if child == nil {
		t.Fatal("no nested insertion point for redirect inside the base64url state")
	}

	built := string(child.BuildRequest([]byte("PAYLOAD")))
	line := strings.SplitN(built, "\r\n", 2)[0]
	q := strings.Fields(line)[1]
	u, err := url.Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	got := u.Query().Get("state")
	decoded, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("state %q is not base64url-unpadded: %v", got, err)
	}
	var m map[string]string
	if err := json.Unmarshal(decoded, &m); err != nil {
		t.Fatalf("decoded state %q is not JSON: %v", decoded, err)
	}
	if m["redirect"] != "PAYLOAD" || m["nonce"] != "abc~~~>" {
		t.Fatalf("decoded state = %v", m)
	}
}

func TestDecodeBase64Variant(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want base64Variant
		ok   bool
	}{
		{base64.StdEncoding.EncodeToString([]byte("{\"a\":1}")), base64VariantStd, true},
		{base64.URLEncoding.EncodeToString([]byte("{\"a\":\"??>\"}")), base64VariantURL, true},
		{base64.RawStdEncoding.EncodeToString([]byte("{\"a\":1}x")), base64VariantRawStd, true},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", 0, false}, // JWT-shaped
	} {
		_, v, ok := decodeBase64Variant(tc.in)
		if ok != tc.ok || (ok && v != tc.want) {
			t.Errorf("decodeBase64Variant(%q) = (%v, %v), want (%v, %v)", tc.in, v, ok, tc.want, tc.ok)
		}
	}
}

// encodePayloadForIP uses the point's own encoder (NEW-14): a path parameter
// encodes space as %20, not '+'.
func TestEncodePayloadForIPMatchesBuildRequest(t *testing.T) {
	raw := "GET /a/b?q=1 HTTP/1.1\r\nHost: h.test\r\n\r\n"
	pts, err := CreateAllInsertionPoints([]byte(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pts {
		pip, ok := p.(*ParameterInsertionPoint)
		if !ok {
			continue
		}
		if got, want := string(encodePayloadForIP(pip, []byte("a b+c"))), string(pip.encodePayload([]byte("a b+c"))); got != want {
			t.Errorf("%s %s: encodePayloadForIP=%q, encodePayload=%q", p.Type(), p.Name(), got, want)
		}
	}
}
