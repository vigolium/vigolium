package httpmsg

import (
	"net/url"
	"testing"
)

func TestHostPortKey(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"http://Example.COM/a", "example.com:80"},
		{"https://example.com/a", "example.com:443"},
		{"http://example.com:8080/x?y=1", "example.com:8080"},
		{"http://[::1]:9000/", "[::1]:9000"},
	}
	for _, tc := range cases {
		rr, err := GetRawRequestFromURL(tc.url)
		if err != nil {
			t.Fatalf("GetRawRequestFromURL(%q): %v", tc.url, err)
		}
		if got := HostPortKey(rr); got != tc.want {
			t.Errorf("HostPortKey(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
	if got := HostPortKey(nil); got != "" {
		t.Errorf("HostPortKey(nil) = %q, want empty", got)
	}
}

// The breaker key must not depend on the method: a GET failure has to
// quarantine POSTs to the same host:port.
func TestHostPortKey_MethodIndependent(t *testing.T) {
	get, err := GetRawRequestFromURL("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	post := NewHttpRequestResponse(get.Request().WithMethod("POST"), nil)
	if get.ID() == post.ID() {
		t.Fatal("precondition: ID() should differ by method")
	}
	if HostPortKey(get) != HostPortKey(post) {
		t.Errorf("HostPortKey differs by method: %q vs %q", HostPortKey(get), HostPortKey(post))
	}
}

func TestURLHostPortAndOrigin(t *testing.T) {
	cases := []struct {
		url, hostPort, origin string
	}{
		{"http://Example.COM/a", "example.com:80", "http://example.com:80"},
		{"HTTPS://example.com", "example.com:443", "https://example.com:443"},
		{"wss://example.com:8443/x", "example.com:8443", "wss://example.com:8443"},
		{"http://[::1]/", "[::1]:80", "http://[::1]:80"},
		{"ftp://example.com/", "example.com:80", "ftp://example.com:80"},
		{"/relative", "", ""},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		if got := URLHostPort(u); got != tc.hostPort {
			t.Errorf("URLHostPort(%q) = %q, want %q", tc.url, got, tc.hostPort)
		}
		if got := URLOrigin(u); got != tc.origin {
			t.Errorf("URLOrigin(%q) = %q, want %q", tc.url, got, tc.origin)
		}
	}
	if URLHostPort(nil) != "" || URLOrigin(nil) != "" {
		t.Error("nil URL should yield empty keys")
	}
}

func TestOriginKeyAndTargetHostPortKey(t *testing.T) {
	rr, err := GetRawRequestFromURL("https://Example.com:8443/admin")
	if err != nil {
		t.Fatal(err)
	}
	if got := OriginKey(rr); got != "https://example.com:8443" {
		t.Errorf("OriginKey = %q", got)
	}
	if got := TargetHostPortKey(rr); got != "example.com:8443" {
		t.Errorf("TargetHostPortKey = %q", got)
	}
	if OriginKey(nil) != "" || TargetHostPortKey(nil) != "" {
		t.Error("nil item should yield empty keys")
	}
}
