package runner

import (
	nethttp "net/http"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/waf"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// A block the generic rule alone matched carries no vendor and kind refused;
// a vendor block and a challenge name their vendor.
func TestBlockEvent_GenericIsUnnamed(t *testing.T) {
	refused := blockEvent(http.BlockNotice{Host: "app.test", WAFType: "generic", Status: 403,
		Kind: waf.KindRefused, Transport: http.BlockTransportRequester})
	if refused.Type != scanevents.TypeWAFBlock || refused.Vendor != "" || refused.BlockKind != "refused" {
		t.Fatalf("generic-only block = %+v, want block_kind refused and no vendor", refused)
	}
	if refused.Transport != "requester" || refused.StatusCode != 403 {
		t.Fatalf("transport/status lost: %+v", refused)
	}

	vendor := blockEvent(http.BlockNotice{Host: "app.test", WAFType: "cloudflare", Status: 403, Kind: waf.KindVendor})
	if vendor.Vendor != "cloudflare" || vendor.BlockKind != "vendor" {
		t.Fatalf("vendor block = %+v", vendor)
	}
	ch := blockEvent(http.BlockNotice{Host: "app.test", WAFType: "akamai", Status: 200,
		Kind: waf.KindChallenge, Transport: http.BlockTransportSpider})
	if ch.Vendor != "akamai" || ch.BlockKind != "challenge" || ch.Transport != "spider" || ch.StatusCode != 200 {
		t.Fatalf("challenge = %+v", ch)
	}
}

func TestFormatBlockNoticeLine_Kinds(t *testing.T) {
	if line := FormatBlockNoticeLine(http.BlockNotice{Host: "a", WAFType: "generic", Status: 403, Kind: waf.KindRefused}); !strings.Contains(line, "unnamed refusal") {
		t.Fatalf("generic line %q", line)
	}
	if line := FormatBlockNoticeLine(http.BlockNotice{Host: "a", WAFType: "cloudflare", Status: 200, Kind: waf.KindChallenge}); !strings.Contains(line, "cloudflare challenge") {
		t.Fatalf("challenge line %q", line)
	}
}

// Discovery's transport classifier reports blocks (and 2xx challenges) on the
// scan requester's notifier as transport "discovery"; an ordinary response is
// not reported, and a classifier without a requester still classifies.
func TestWAFBlockClassifier_ReportsDiscoveryBlocks(t *testing.T) {
	req := http.NewOfflineRequester("test")
	var notices []http.BlockNotice
	req.SetBlockNotifier(func(n http.BlockNotice) { notices = append(notices, n) })
	c := wafBlockClassifier{requester: req}

	html := nethttp.Header{"Content-Type": {"text/html"}}
	if !c.IsBlockStatus(200) || !c.IsBlockStatus(403) || c.IsBlockStatus(404) {
		t.Fatal("candidate statuses: 200 and 403 in, 404 out")
	}
	if c.IsHostBlock("app.test", 200, html, []byte("<p>welcome</p>")) {
		t.Fatal("an ordinary 200 is not a block")
	}
	if !c.IsHostBlock("app.test", 200, html, []byte(`<script>window._cf_chl_opt={}</script>`)) {
		t.Fatal("a 200 Cloudflare challenge is a block")
	}
	if len(notices) != 1 || notices[0].Transport != http.BlockTransportDiscovery ||
		notices[0].Kind != waf.KindChallenge || notices[0].WAFType != "cloudflare" {
		t.Fatalf("notices = %+v, want one discovery cloudflare challenge", notices)
	}
	if req.BlockCounts()["app.test"] != 1 {
		t.Fatalf("BlockCounts = %v", req.BlockCounts())
	}
	if !(wafBlockClassifier{}).IsHostBlock("x.test", 403, html, []byte("You have been blocked")) {
		t.Fatal("a requester-less classifier still classifies")
	}
}

// The crawl's block hook reports on the requester's notifier as "spider".
func TestSpiderBlockReporter(t *testing.T) {
	if spiderBlockReporter(nil) != nil || spiderBlockReporter(&phaseInfra{}) != nil {
		t.Fatal("no requester, no reporter")
	}
	req := http.NewOfflineRequester("test")
	var notices []http.BlockNotice
	req.SetBlockNotifier(func(n http.BlockNotice) { notices = append(notices, n) })
	report := spiderBlockReporter(&phaseInfra{httpRequester: req})
	report("app.test", 202, waf.ClassifyResponse(202, nethttp.Header{"X-Amzn-Waf-Action": {"challenge"}}, nil))
	if len(notices) != 1 || notices[0].Transport != http.BlockTransportSpider || notices[0].Kind != waf.KindChallenge ||
		notices[0].Status != 202 {
		t.Fatalf("notices = %+v", notices)
	}
}
