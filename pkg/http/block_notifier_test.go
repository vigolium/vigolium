package http

import (
	"io"
	"net/http"
	"strings"
	"testing"

	httpUtils "github.com/projectdiscovery/utils/http"
)

// buildChain builds a filled ResponseChain from primitives for notifier tests.
func buildChain(t *testing.T, status int, header http.Header, body string) *httpUtils.ResponseChain {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	resp := &http.Response{
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
	for chain.Has() {
		if err := chain.Fill(); err != nil {
			t.Fatal(err)
		}
		if !chain.Previous() {
			break
		}
	}
	return chain
}

func cloudflareBlockChain(t *testing.T) *httpUtils.ResponseChain {
	return buildChain(t, 403, http.Header{
		"Server":       {"cloudflare"},
		"Content-Type": {"text/html; charset=UTF-8"},
	}, "<title>Attention Required! | Cloudflare</title>")
}

func TestBlockNotifier_FiresOncePerHost(t *testing.T) {
	var notices []BlockNotice
	n := &blockNotifier{seen: make(map[string]struct{})}
	n.sink = func(bn BlockNotice) { notices = append(notices, bn) }

	c1 := cloudflareBlockChain(t)
	n.report("example.com", c1)
	c1.Close()

	// Second block on the same host must not re-warn.
	c2 := cloudflareBlockChain(t)
	n.report("example.com", c2)
	c2.Close()

	if len(notices) != 1 {
		t.Fatalf("want exactly 1 notice for a host, got %d", len(notices))
	}
	got := notices[0]
	if got.Host != "example.com" {
		t.Errorf("host: want example.com, got %q", got.Host)
	}
	if got.WAFType != "cloudflare" {
		t.Errorf("waf type: want cloudflare, got %q", got.WAFType)
	}
	if got.Status != 403 {
		t.Errorf("status: want 403, got %d", got.Status)
	}
}

func TestBlockNotifier_PerHostIndependent(t *testing.T) {
	var hosts []string
	n := &blockNotifier{seen: make(map[string]struct{})}
	n.sink = func(bn BlockNotice) { hosts = append(hosts, bn.Host) }

	for _, h := range []string{"a.example.com", "b.example.com"} {
		c := cloudflareBlockChain(t)
		n.report(h, c)
		c.Close()
	}
	if len(hosts) != 2 {
		t.Fatalf("want a warning per distinct host, got %d: %v", len(hosts), hosts)
	}
}

func TestBlockNotifier_IgnoresNonBlock(t *testing.T) {
	fired := false
	n := &blockNotifier{seen: make(map[string]struct{})}
	n.sink = func(BlockNotice) { fired = true }

	// A healthy 200 must never warn.
	c := buildChain(t, 200, http.Header{"Server": {"cloudflare"}}, "<html>ok</html>")
	n.report("example.com", c)
	c.Close()

	if fired {
		t.Fatal("notifier fired on a non-blocking 200 response")
	}
}

func TestBlockNotifier_PlainForbiddenDoesNotSuppressLaterBlock(t *testing.T) {
	var count int
	n := &blockNotifier{seen: make(map[string]struct{})}
	n.sink = func(BlockNotice) { count++ }

	// An ordinary application 403 with no WAF/CDN signature: no warning, and the
	// host must NOT be marked seen (otherwise a real block later is swallowed).
	plain := buildChain(t, 403, http.Header{"Content-Type": {"application/json"}}, `{"error":"no access"}`)
	n.report("example.com", plain)
	plain.Close()
	if count != 0 {
		t.Fatalf("plain 403 should not warn, got %d", count)
	}

	// Now the edge starts actually blocking the same host.
	block := cloudflareBlockChain(t)
	n.report("example.com", block)
	block.Close()
	if count != 1 {
		t.Fatalf("genuine WAF block after a plain 403 should warn once, got %d", count)
	}
}

func TestBlockNotifier_NilSafe(t *testing.T) {
	// No sink installed: report must be a no-op, not a panic.
	n := &blockNotifier{seen: make(map[string]struct{})}
	c := cloudflareBlockChain(t)
	n.report("example.com", c)
	c.Close()

	// Nil notifier (e.g. never initialized) must also be safe.
	var nilN *blockNotifier
	c2 := cloudflareBlockChain(t)
	nilN.report("example.com", c2)
	c2.Close()
}

// report classifies resp, then reports it as the hot path does.
func (n *blockNotifier) report(host string, resp *httpUtils.ResponseChain) {
	if n == nil || n.sink == nil || host == "" || resp == nil {
		return
	}
	n.reportBlock(host, classifyWAFBlock(resp), responseChainStatus(resp))
}
