package runner

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
}

// The plan states the effective proxy, where it came from, and the route of
// every admitted target.
func TestPlanProxy(t *testing.T) {
	clearProxyEnv(t)
	if p := planProxy("", []string{"http://127.0.0.1:1/"}); p != nil {
		t.Fatalf("no proxy configured, got %+v", p)
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "localhost")
	p := planProxy("", []string{"https://127.0.0.1:18931/", "https://localhost:3000/", "http://example.com/"})
	if p == nil || len(p.Routes) != 1 || p.Routes[0].Source != "HTTPS_PROXY" || p.Routes[0].Scheme != "https" {
		t.Fatalf("routes = %+v", p)
	}
	if p.NoProxy != "localhost" || p.NoProxySource != "NO_PROXY" {
		t.Errorf("no_proxy = %q from %q", p.NoProxy, p.NoProxySource)
	}
	want := map[string]string{
		"https://127.0.0.1:18931/": "http://127.0.0.1:9 (from HTTPS_PROXY)",
		"https://localhost:3000/":  "direct (NO_PROXY)",
		"http://example.com/":      "direct",
	}
	for k, v := range want {
		if p.Targets[k] != v {
			t.Errorf("%s: %q, want %q", k, p.Targets[k], v)
		}
	}

	p = planProxy("http://burp:8080", nil)
	if len(p.Routes) != 1 || p.Routes[0].Source != "--proxy" || p.Routes[0].Scheme != "*" || p.NoProxy != "" {
		t.Errorf("--proxy plan = %+v", p)
	}
}

// An unreachable target sent through an environment proxy names that proxy
// and its variable, so a dead proxy is not read as a dead target.
func TestProxyUnreachableHint(t *testing.T) {
	clearProxyEnv(t)
	issues := []database.TargetIssue{{Target: "http://127.0.0.1:18931/"}}
	if h := ProxyUnreachableHint("", issues); h != "" {
		t.Errorf("no proxy, hint %q", h)
	}
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	h := ProxyUnreachableHint("", issues)
	if !strings.Contains(h, "127.0.0.1:9") || !strings.Contains(h, "HTTP_PROXY") || !strings.Contains(h, "NO_PROXY") {
		t.Errorf("hint = %q", h)
	}
	t.Setenv("NO_PROXY", "127.0.0.1")
	if h := ProxyUnreachableHint("", issues); h != "" {
		t.Errorf("a direct target gets no proxy hint: %q", h)
	}
	if h := ProxyUnreachableHint("http://burp:8080", issues); !strings.Contains(h, "from --proxy") {
		t.Errorf("flag hint = %q", h)
	}
}
