package proxyenv

import (
	"net/http"
	"net/url"
	"testing"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func route(c Choice, raw string) string {
	u, _ := url.Parse(raw)
	r := c.For(u)
	if r == nil {
		return "direct"
	}
	return r.URL.String() + " " + r.Source
}

func TestResolveBySchemeAndNoProxy(t *testing.T) {
	c := Resolve("", env(map[string]string{
		"HTTPS_PROXY": "http://127.0.0.1:9",
		"http_proxy":  "127.0.0.1:8080",
		"NO_PROXY":    "localhost, .corp.example, 10.0.0.0/8, 192.168.1.5, api.test:8443",
	}))
	cases := map[string]string{
		"https://example.com/":     "http://127.0.0.1:9 HTTPS_PROXY",
		"http://example.com/":      "http://127.0.0.1:8080 http_proxy",
		"http://127.0.0.1:18931/":  "http://127.0.0.1:8080 http_proxy", // loopback is not exempt by itself
		"http://localhost:3000/":   "direct",
		"https://a.corp.example/":  "direct",
		"https://corp.example/":    "direct",
		"https://xcorp.example/":   "http://127.0.0.1:9 HTTPS_PROXY",
		"http://10.2.3.4/":         "direct",
		"http://192.168.1.5:81/":   "direct",
		"https://api.test:8443/":   "direct",
		"https://api.test/":        "http://127.0.0.1:9 HTTPS_PROXY",
		"http://[::1]:8080/x":      "http://127.0.0.1:8080 http_proxy",
		"https://LOCALHOST/path":   "direct",
		"https://sub.localhost/ok": "direct",
	}
	for target, want := range cases {
		if got := route(c, target); got != want {
			t.Errorf("%s: got %q, want %q", target, got, want)
		}
	}
}

func TestResolveAllProxyAndFlag(t *testing.T) {
	c := Resolve("", env(map[string]string{"ALL_PROXY": "socks5://127.0.0.1:1080", "NO_PROXY": "*"}))
	if got := route(c, "https://example.com/"); got != "direct" {
		t.Errorf("NO_PROXY=* got %q", got)
	}
	c = Resolve("", env(map[string]string{"all_proxy": "socks5://127.0.0.1:1080", "HTTP_PROXY": "http://h:1"}))
	if got := route(c, "https://example.com/"); got != "socks5://127.0.0.1:1080 all_proxy" {
		t.Errorf("all_proxy fallback got %q", got)
	}
	if got := route(c, "http://example.com/"); got != "http://h:1 HTTP_PROXY" {
		t.Errorf("scheme proxy beats ALL_PROXY, got %q", got)
	}

	// --proxy overrides the environment and ignores NO_PROXY.
	c = Resolve("http://burp:8080", env(map[string]string{"HTTPS_PROXY": "http://other:1", "NO_PROXY": "*"}))
	if got := route(c, "https://127.0.0.1/"); got != "http://burp:8080 --proxy" {
		t.Errorf("--proxy got %q", got)
	}
	if len(c.Routes()) != 1 || c.Routes()[0].Source != SourceFlag {
		t.Errorf("flag routes = %+v", c.Routes())
	}
	if v, _ := c.NoProxy(); v != "" {
		t.Errorf("NO_PROXY does not apply under --proxy, got %q", v)
	}
}

func TestResolveNothingAndBadValue(t *testing.T) {
	c := Resolve("", env(nil))
	if c.Any() || c.Func() != nil || c.Describe("http://x/") != "" || c.Summary() != "" {
		t.Errorf("empty environment proxies something: %+v", c)
	}
	c = Resolve("", env(map[string]string{"HTTPS_PROXY": "http://"}))
	if c.Err() == nil {
		t.Error("an unparseable proxy is reported")
	}
}

func TestFuncAndDescribe(t *testing.T) {
	c := Resolve("", env(map[string]string{"HTTPS_PROXY": "http://user:secret@127.0.0.1:9", "NO_PROXY": "localhost"}))
	f := c.Func()
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	if u, err := f(req); err != nil || u == nil || u.Host != "127.0.0.1:9" {
		t.Errorf("func = %v %v", u, err)
	}
	req, _ = http.NewRequest("GET", "http://example.com/", nil)
	if u, _ := f(req); u != nil {
		t.Errorf("http has no proxy, got %v", u)
	}
	if got := c.Describe("https://example.com/"); got != "http://user:xxxxx@127.0.0.1:9 (from HTTPS_PROXY)" {
		t.Errorf("describe = %q", got)
	}
	if got := c.Describe("https://localhost:3000/"); got != "direct (NO_PROXY)" {
		t.Errorf("describe bypass = %q", got)
	}
	if got := c.Summary(); got != "http://user:xxxxx@127.0.0.1:9 for https targets (HTTPS_PROXY); NO_PROXY=localhost" {
		t.Errorf("summary = %q", got)
	}
}

// VIGOLIUM_PROXY reaches proxyenv as the flag's value and is named for itself.
func TestVigoliumProxySource(t *testing.T) {
	c := Resolve("http://burp:8080", env(map[string]string{"VIGOLIUM_PROXY": "http://burp:8080", "NO_PROXY": "*"}))
	if got := route(c, "https://localhost/"); got != "http://burp:8080 VIGOLIUM_PROXY" {
		t.Errorf("got %q", got)
	}
	if r := c.ForHost("https", "x"); r == nil || !r.Everything {
		t.Errorf("VIGOLIUM_PROXY proxies everything like --proxy")
	}
}
