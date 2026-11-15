package http

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/projectdiscovery/rawhttp"

	"github.com/vigolium/vigolium/pkg/http/proxyenv"
)

// The scan transports take the environment proxy by scheme, honour NO_PROXY
// and do not bypass loopback on their own; --proxy overrides all of it.
func TestApplyExplicitProxyFollowsProxyenv(t *testing.T) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "localhost")

	proxyOf := func(tr *http.Transport, raw string) string {
		if tr.Proxy == nil {
			return "direct"
		}
		req, _ := http.NewRequest("GET", raw, nil)
		u, err := tr.Proxy(req)
		if err != nil || u == nil {
			return "direct"
		}
		return u.Host
	}
	tr := &http.Transport{}
	applyExplicitProxy(tr, "", "test")
	for target, want := range map[string]string{
		"https://127.0.0.1:18931/": "127.0.0.1:9", // loopback still proxied
		"https://localhost:3000/":  "direct",      // NO_PROXY
		"http://example.com/":      "direct",      // HTTPS_PROXY is for https only
	} {
		if got := proxyOf(tr, target); got != want {
			t.Errorf("%s: %s, want %s", target, got, want)
		}
	}

	tr = &http.Transport{}
	applyExplicitProxy(tr, "http://burp:8080", "test")
	if got := proxyOf(tr, "https://localhost:3000/"); got != "burp:8080" {
		t.Errorf("--proxy: %s, want burp:8080", got)
	}
}

// The raw client is chosen per request: direct for a NO_PROXY host.
func TestRawClientSetPerRequest(t *testing.T) {
	choice := proxyenv.Resolve("", func(k string) string {
		return map[string]string{"HTTP_PROXY": "http://127.0.0.1:9", "NO_PROXY": "127.0.0.1"}[k]
	})
	set := newRawClientSet(*rawhttp.DefaultOptions, nil, choice)
	direct, _ := url.Parse("http://127.0.0.1:8000/")
	proxied, _ := url.Parse("http://example.com/")
	if c := set.forURL(direct); c != set.direct || c.Options.Proxy != "" {
		t.Errorf("NO_PROXY host must use the direct client")
	}
	if c := set.forURL(proxied); c == set.direct || c.Options.Proxy != "http://127.0.0.1:9" {
		t.Errorf("proxied host must use the proxy client, got %q", c.Options.Proxy)
	}
}
