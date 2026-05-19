package mcp

import "testing"

func TestDetectFromParts(t *testing.T) {
	cases := []struct {
		name      string
		reqHdr    map[string]string
		urlPath   string
		respHdr   map[string]string
		body      string
		wantStrng bool
		wantAny   bool
	}{
		{
			name:      "session header",
			respHdr:   map[string]string{"Mcp-Session-Id": "abc"},
			body:      "{}",
			wantStrng: true,
			wantAny:   true,
		},
		{
			name:      "json-rpc with method",
			body:      `{"jsonrpc":"2.0","id":1,"result":{"tools":[]},"method":"tools/list"}`,
			urlPath:   "/mcp",
			wantStrng: true,
			wantAny:   true,
		},
		{
			name:    "raw json-rpc only",
			body:    `{"jsonrpc":"2.0","id":1,"result":{}}`,
			wantAny: true,
		},
		{
			name:    "noise",
			body:    `<html>nothing here</html>`,
			wantAny: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := DetectFromParts(c.reqHdr, c.urlPath, c.respHdr, c.body)
			if f.Any() != c.wantAny {
				t.Fatalf("Any() got %v want %v: flags=%#v", f.Any(), c.wantAny, f)
			}
			if f.Strong() != c.wantStrng {
				t.Fatalf("Strong() got %v want %v: flags=%#v", f.Strong(), c.wantStrng, f)
			}
		})
	}
}
