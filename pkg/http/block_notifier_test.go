package http

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
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
	n.reportBlock(host, classifyWAFBlock(resp), responseChainStatus(resp), BlockTransportRequester)
}

// A CDN in the path is not a block: an application's own 403 behind
// Cloudflare (Server and Cf-Ray ride on every proxied response) must not count
// toward BlockCounts, or the scan's edge_blocked caveat fires on every
// authorization check behind a CDN.
func TestClassifyWAFBlock_AppForbiddenBehindCDNIsNotABlock(t *testing.T) {
	app := buildChain(t, 403, http.Header{
		"Server":       {"cloudflare"},
		"Cf-Ray":       {"8a1b2c3d4e5f-AMS"},
		"Content-Type": {"application/json"},
	}, `{"error":"insufficient_scope"}`)
	defer app.Close()
	if got := classifyWAFBlock(app); got != nil {
		t.Fatalf("app 403 behind Cloudflare classified as a block: %+v", got)
	}

	n := &blockNotifier{seen: make(map[string]struct{})}
	n.reportBlock("example.com", classifyWAFBlock(app), 403, BlockTransportRequester)
	edge := cloudflareBlockChain(t)
	defer edge.Close()
	n.reportBlock("edge.example.com", classifyWAFBlock(edge), 403, BlockTransportRequester)
	counts := map[string]int64{}
	n.counts.Range(func(k, v any) bool { counts[k.(string)] = v.(*atomic.Int64).Load(); return true })
	if counts["example.com"] != 0 || counts["edge.example.com"] != 1 {
		t.Fatalf("block counts = %v, want only edge.example.com", counts)
	}
}

// A vendor challenge served on 200 is classified (the block-status gate alone
// never looked at it), and the notice says challenge with the vendor named.
func TestClassifyWAFBlock_ChallengeOn200(t *testing.T) {
	ch := buildChain(t, 200, http.Header{"Content-Type": {"text/html"}},
		`<html><title>Just a moment...</title><script>window._cf_chl_opt={cvId:'3'}</script></html>`)
	defer ch.Close()
	block := classifyWAFBlock(ch)
	if block == nil || block.Kind() != "challenge" || block.Vendor() != "cloudflare" {
		t.Fatalf("200 Cloudflare challenge = %+v, want a cloudflare challenge", block)
	}

	ok := buildChain(t, 200, http.Header{"Content-Type": {"text/html"}}, `<html>Welcome</html>`)
	defer ok.Close()
	if got := classifyWAFBlock(ok); got != nil {
		t.Fatalf("an ordinary 200 classified as %+v", got)
	}
}

// Every sender reports through one notifier: a block the discovery transport
// saw first is the host's one notice, carries its transport and kind, counts
// toward BlockCounts, and a later requester block on the host stays silent.
func TestRequester_ReportBlockSharesTheNotifier(t *testing.T) {
	r := &Requester{blockNotifier: &blockNotifier{seen: make(map[string]struct{})}}
	var notices []BlockNotice
	r.SetBlockNotifier(func(n BlockNotice) { notices = append(notices, n) })

	app := buildChain(t, 403, http.Header{"Content-Type": {"text/html"}}, "<h1>Forbidden</h1>")
	defer app.Close()
	r.ReportBlock("app.test", classifyWAFBlock(app), 403, BlockTransportDiscovery)
	r.blockNotifier.reportBlock("app.test", classifyWAFBlock(app), 403, BlockTransportRequester)
	r.ReportBlock("app.test", nil, 200, BlockTransportSpider)

	if len(notices) != 1 {
		t.Fatalf("notices = %+v, want exactly one", notices)
	}
	if n := notices[0]; n.Transport != BlockTransportDiscovery || n.Kind != "refused" || n.Status != 403 {
		t.Fatalf("notice = %+v, want discovery/refused/403", n)
	}
	if got := r.BlockCounts()["app.test"]; got != 2 {
		t.Fatalf("BlockCounts = %d, want 2 (nil block is not a block)", got)
	}
	var nilR *Requester
	nilR.ReportBlock("x", classifyWAFBlock(app), 403, BlockTransportSpider) // nil-safe
}
