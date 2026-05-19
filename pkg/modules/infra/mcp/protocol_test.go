package mcp

import (
	"strings"
	"testing"
)

func TestParseSSE(t *testing.T) {
	body := "event: message\nid: 1\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\nevent: ping\ndata: {}\n\n"
	events := ParseSSE(body)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d: %#v", len(events), events)
	}
	if events[0].Event != "message" || events[0].ID != "1" || !strings.Contains(events[0].Data, `"ok":true`) {
		t.Fatalf("first event mismatch: %#v", events[0])
	}
	if events[1].Event != "ping" {
		t.Fatalf("second event mismatch: %#v", events[1])
	}
}

func TestExtractJSONFromSSE(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "raw json",
			in:   `{"jsonrpc":"2.0","id":1,"result":{}}`,
			want: `{"jsonrpc":"2.0","id":1,"result":{}}`,
		},
		{
			name: "sse",
			in:   "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n",
			want: `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractJSONFromSSE(c.in)
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestParseInitializeResponse(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"test","version":"0.1.0"}}}`
	res, err := ParseInitializeResponse(body)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if res.ProtocolVersion != "2025-03-26" {
		t.Fatalf("protocol version mismatch: %q", res.ProtocolVersion)
	}
	if res.ServerInfo == nil || res.ServerInfo.Name != "test" {
		t.Fatalf("server info mismatch: %#v", res.ServerInfo)
	}
}

func TestParseToolsListResponse(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"Echo tool","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}]}}`
	res, err := ParseToolsListResponse(body)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != "echo" {
		t.Fatalf("tool list mismatch: %#v", res.Tools)
	}
}

func TestBuildInitializeRequest(t *testing.T) {
	body := string(BuildInitializeRequest())
	for _, marker := range []string{`"jsonrpc":"2.0"`, `"method":"initialize"`, `"protocolVersion":"2025-03-26"`, `"clientInfo"`} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected marker %q in %s", marker, body)
		}
	}
}
