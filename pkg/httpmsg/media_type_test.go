package httpmsg

import "testing"

func TestClassifyMediaType(t *testing.T) {
	cases := []struct {
		raw   string
		body  string
		canon string
		want  ContentType
	}{
		{"application/json", "", "application/json", ContentTypeJSON},
		{"Application/JSON; charset=UTF-8", "", "application/json", ContentTypeJSON},
		{"application/vnd.api+json", "", "application/json", ContentTypeJSON},
		{"application/problem+json", "", "application/json", ContentTypeJSON},
		{"text/json", "", "application/json", ContentTypeJSON},
		{"application/x-json", "", "application/json", ContentTypeJSON},
		{"application/soap+xml; charset=utf-8", "", "application/xml", ContentTypeXML},
		{"text/xml", "", "application/xml", ContentTypeXML},
		{"APPLICATION/XML", "", "application/xml", ContentTypeXML},
		{"application/x-www-form-urlencoded; charset=UTF-8", "", "application/x-www-form-urlencoded", ContentTypeURLEncoded},
		{"multipart/form-data; boundary=x", "", "multipart/form-data", ContentTypeMultipart},
		{"application/x-amf", "", "application/x-amf", ContentTypeAMF},
		{"application/octet-stream", "{}", "application/octet-stream", ContentTypeUnknown},
		// Sniffing: missing type or text/plain.
		{"", `{"a":1}`, "application/json", ContentTypeJSON},
		{"text/plain", ` [1,2] `, "application/json", ContentTypeJSON},
		{"text/plain", `{not json`, "text/plain", ContentTypeUnknown},
		{"", `<a><b>1</b></a>`, "application/xml", ContentTypeXML},
		{"text/plain;charset=utf-8", `a=1&b=2`, "application/x-www-form-urlencoded", ContentTypeURLEncoded},
		{"", `a=1`, "application/x-www-form-urlencoded", ContentTypeURLEncoded},
		{"text/plain", `hello world`, "text/plain", ContentTypeUnknown},
		{"", ``, "", ContentTypeUnknown},
	}
	for _, c := range cases {
		canon, got := ClassifyMediaType(c.raw, []byte(c.body))
		if got != c.want || canon != c.canon {
			t.Errorf("ClassifyMediaType(%q, %q) = (%q, %v), want (%q, %v)", c.raw, c.body, canon, got, c.canon, c.want)
		}
	}
}

// A vendor +json body, mixed-case JSON and a SOAP body now yield body
// insertion points (MISS-10); before, the exact-string switch gave none.
func TestAnalyzeRequest_StructuredSuffixBodies(t *testing.T) {
	for _, tc := range []struct{ ct, body string }{
		{"application/vnd.api+json", `{"user":"alice"}`},
		{"Application/JSON", `{"user":"alice"}`},
		{"application/soap+xml", `<Envelope><user>alice</user></Envelope>`},
		{"text/plain", `{"user":"alice"}`},
	} {
		raw := "POST /api HTTP/1.1\r\nHost: x.test\r\nContent-Type: " + tc.ct + "\r\n\r\n" + tc.body
		info, err := AnalyzeRequest([]byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", tc.ct, err)
		}
		found := false
		for _, p := range info.Parameters {
			if p.Name() == "user" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no body parameter 'user' extracted", tc.ct)
		}
	}
}
