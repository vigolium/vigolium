package js_beautify

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// webpackMinified is a single-line minified webpack-5 bundle (over the
// worth-beautifying gate) reused across the end-to-end module tests.
const webpackMinified = `(()=>{"use strict";var e={100:(e,t,r)=>{const n=r(200);` +
	`t.listUsers=function(){return fetch(n.base+"/users",{method:"GET"}).then(x=>x.json())};` +
	`t.createUser=function(u){return fetch(n.base+"/users",{method:"POST",body:JSON.stringify(u)})};` +
	`t.deleteUser=function(id){return fetch(n.base+"/users/"+id,{method:"DELETE"})}},` +
	`200:(e,t)=>{t.base="/api/v3";t.timeout=3e4;t.headers={"X-Api":"1"}},` +
	`300:(e,t,r)=>{const n=r(200);t.listPosts=function(p){return fetch(n.base+"/posts?page="+p)}}},t={};` +
	`function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};` +
	`return e[n](o,o.exports,r),o.exports}r.n=e=>e;var n=r(100),s=r(300);console.log(n,s)})();`

// --- capture fakes for the write-back / tagging rails ---

type fixedResolver string

func (f fixedResolver) ResolveRequestUUID(string) string { return string(f) }

type captureRewriter struct {
	uuid  string
	raw   []byte
	calls int
}

type captureArtifactWriter struct {
	artifact *modkit.DerivedArtifact
	calls    int
}

func (c *captureArtifactWriter) StoreDerivedArtifact(_ context.Context, artifact *modkit.DerivedArtifact) error {
	c.calls++
	clone := *artifact
	clone.Content = append([]byte(nil), artifact.Content...)
	c.artifact = &clone
	return nil
}

func (c *captureRewriter) RewriteRecordResponse(_ context.Context, uuid string, raw []byte) error {
	c.uuid = uuid
	c.raw = raw
	c.calls++
	return nil
}

type captureAnnotator struct{ remarks map[string][]string }

func (c *captureAnnotator) AppendRemarks(_ context.Context, ann map[string][]string) error {
	if c.remarks == nil {
		c.remarks = map[string][]string{}
	}
	for k, v := range ann {
		c.remarks[k] = append(c.remarks[k], v...)
	}
	return nil
}

func TestScanPerRequest_PreservesRawAndStoresArtifact(t *testing.T) {
	if getScanner() == nil {
		t.Skip("skipping: no valid jstangle binary available")
	}
	m := New()

	rr := modtest.Response(
		modtest.Request(t, "http://target.test/_next/static/chunks/app.js"),
		"application/javascript", webpackMinified,
	)
	rw := &captureRewriter{}
	aw := &captureArtifactWriter{}
	an := &captureAnnotator{}
	sc := &modkit.ScanContext{
		RequestUUIDResolver: fixedResolver("rec-1"),
		RecordRewriter:      rw,
		ArtifactWriter:      aw,
		RemarksAnnotator:    an,
	}

	results, err := m.ScanPerRequest(rr, sc)
	if err != nil {
		t.Fatalf("ScanPerRequest error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	// Captured traffic is immutable; the full derived document is stored beside it.
	if rw.calls != 0 {
		t.Fatalf("raw response rewriter called %d times, want 0", rw.calls)
	}
	if aw.calls != 1 || aw.artifact == nil {
		t.Fatalf("artifact writer called %d times, want 1", aw.calls)
	}
	if aw.artifact.RecordUUID != "rec-1" || aw.artifact.Kind != "beautified-source" {
		t.Errorf("artifact linkage = %q/%q", aw.artifact.RecordUUID, aw.artifact.Kind)
	}
	if !strings.Contains(string(aw.artifact.Content), "// =====") || !strings.Contains(string(aw.artifact.Content), "fetch") {
		t.Errorf("stored artifact is not the beautified document: %.200q", aw.artifact.Content)
	}

	// The record must be tagged.
	if got := an.remarks["rec-1"]; !slices.Contains(got, "js-beautified-artifact") {
		t.Errorf("remarks for rec-1 = %v, want js-beautified-artifact", got)
	}

	// Finding metadata proves that raw evidence was preserved.
	if f := results[0]; f.Metadata["rewritten"] != false || f.Metadata["rawPreserved"] != true || f.Metadata["artifactStored"] != true {
		t.Errorf("unexpected immutability metadata: %v", f.Metadata)
	}
}

func TestScanPerRequest_InlineHTML(t *testing.T) {
	if getScanner() == nil {
		t.Skip("skipping: no valid jstangle binary available")
	}
	m := New()

	html := `<!doctype html><html><head><title>x</title>` +
		`<script src="/vendor.js"></script>` +
		`<script>` + webpackMinified + `</script>` +
		`</head><body>hi</body></html>`
	rr := modtest.Response(
		modtest.Request(t, "http://target.test/dashboard"),
		"text/html", html,
	)
	rw := &captureRewriter{}
	an := &captureAnnotator{}
	sc := &modkit.ScanContext{
		RequestUUIDResolver: fixedResolver("rec-2"),
		RecordRewriter:      rw,
		RemarksAnnotator:    an,
	}

	results, err := m.ScanPerRequest(rr, sc)
	if err != nil {
		t.Fatalf("ScanPerRequest error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	// An HTML page body must NOT be overwritten.
	if rw.calls != 0 {
		t.Errorf("HTML page response should not be rewritten, got %d calls", rw.calls)
	}
	// Tagged as inline, and finding metadata says inline.
	if got := an.remarks["rec-2"]; !slices.Contains(got, "js-inline-beautified") {
		t.Errorf("remarks for rec-2 = %v, want js-inline-beautified", got)
	}
	f := results[0]
	if f.Metadata["inline"] != true {
		t.Errorf("metadata inline = %v, want true", f.Metadata["inline"])
	}
	// The beautified inline JS is carried in evidence.
	if len(f.AdditionalEvidence) == 0 || !strings.Contains(f.AdditionalEvidence[0], "fetch") {
		t.Errorf("expected beautified inline JS in evidence, got %v", f.AdditionalEvidence)
	}
}

func TestScanPerRequest_SkipsVendorContent(t *testing.T) {
	if getScanner() == nil {
		t.Skip("skipping: no valid jstangle binary available")
	}
	m := New()

	// A vendor analytics runtime served from the TARGET's own domain under a
	// neutral filename — the URL gate can't catch it, but the content gate must.
	// Long and minified enough that it would otherwise be beautified.
	ga := `(function(){window.GoogleAnalyticsObject="ga";var ga=function(){(ga.q=ga.q||[]).push(arguments)};` +
		`ga.l=+new Date();var s=document.createElement("script");s.async=1;s.src="//www.google-analytics.com/analytics.js";` +
		`var f=document.getElementsByTagName("script")[0];f.parentNode.insertBefore(s,f);ga("create","UA-000000-1","auto");` +
		`ga("send","pageview");ga("set","anonymizeIp",true);ga("require","displayfeatures");` +
		`ga("require","linkid");window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag("js",new Date());})();`

	rr := modtest.Response(
		modtest.Request(t, "http://target.test/assets/main.js"),
		"application/javascript", ga,
	)
	res, err := m.ScanPerRequest(rr, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest error: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("vendor-content script should be skipped, got %d findings", len(res))
	}
}

type fakeScope struct{ inScope map[string]bool }

func (f fakeScope) IsHostInScope(host string) bool { return f.inScope[host] }

func TestScanPerRequest_TargetIsVendor(t *testing.T) {
	if getScanner() == nil {
		t.Skip("skipping: no valid jstangle binary available")
	}
	m := New()

	// A (webpack) script served from a known vendor host — PostHog.
	rr := modtest.Response(
		modtest.Request(t, "https://us.i.posthog.com/static/array.js"),
		"application/javascript", webpackMinified,
	)

	// Third-party (not the scan target): skipped.
	thirdParty := &modkit.ScanContext{
		Scope: fakeScope{inScope: map[string]bool{"app.example.com": true}},
	}
	if res, _ := m.ScanPerRequest(rr, thirdParty); len(res) != 0 {
		t.Errorf("third-party vendor script should be skipped, got %d findings", len(res))
	}

	// Scan IS targeting the vendor (pentesting PostHog): beautified.
	targeting := &modkit.ScanContext{
		Scope: fakeScope{inScope: map[string]bool{"us.i.posthog.com": true}},
	}
	if res, _ := m.ScanPerRequest(rr, targeting); len(res) != 1 {
		t.Errorf("vendor script should be beautified when it is the scan target, got %d findings", len(res))
	}

	// No scope configured (e.g. ingested traffic): treated as third-party → skipped.
	noScope := &modkit.ScanContext{}
	if res, _ := m.ScanPerRequest(rr, noScope); len(res) != 0 {
		t.Errorf("with no scope, vendor script should be skipped, got %d findings", len(res))
	}
}

func TestModule_Metadata(t *testing.T) {
	m := New()
	if m.ID() != "js-beautify" {
		t.Errorf("ID() = %q, want js-beautify", m.ID())
	}
	if m.Severity() != severity.Info {
		t.Errorf("Severity() = %v, want Info", m.Severity())
	}
	if m.ScanScopes() == 0 {
		t.Error("ScanScopes() must be non-zero")
	}
	if m.Scope() != modkit.PassiveScanScopeResponse {
		t.Errorf("Scope() = %v, want response", m.Scope())
	}
}

func TestWorthBeautifying(t *testing.T) {
	cases := []struct {
		name string
		code string
		want bool
	}{
		{"tiny", `var x = 1;`, false},
		{"pretty short", "function ok() {\n  return 1;\n}\n", false},
		{"minified long single line", "var a=1;" + strings.Repeat("b=b+1;", 200), true},
		{"webpack marker", `(function(){ __webpack_require__(3); })();` + strings.Repeat(" //x", 200), true},
		{"next flight marker", `self.__next_f.push([1,"data"]);` + strings.Repeat("z", 600), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := worthBeautifying(c.code); got != c.want {
				t.Errorf("worthBeautifying(%q...) = %v, want %v", c.code[:min(20, len(c.code))], got, c.want)
			}
		})
	}
}

func TestExtractInlineScripts(t *testing.T) {
	html := `<!doctype html><html><head>
<script src="/app.js"></script>
<script type="application/json">{"a":1}</script>
<script>window.API="/api/v1";function go(){fetch(API+"/x")}</script>
<script type="module">import x from "./m.js"; x()</script>
<script type="text/x-template"><div>tmpl</div></script>
</head></html>`

	out := extractInlineScripts(html)
	if !strings.Contains(out, `window.API="/api/v1"`) {
		t.Errorf("expected inline script JS in output, got: %q", out)
	}
	if !strings.Contains(out, `import x from "./m.js"`) {
		t.Errorf("expected module script JS in output, got: %q", out)
	}
	// External src, JSON, and template scripts must be excluded.
	if strings.Contains(out, "/app.js") {
		t.Error("external src script should be excluded")
	}
	if strings.Contains(out, `"a":1`) {
		t.Error("application/json script should be excluded")
	}
	if strings.Contains(out, "tmpl") {
		t.Error("text/x-template script should be excluded")
	}
}

func TestExtractInlineScripts_None(t *testing.T) {
	if got := extractInlineScripts(`<html><body>no scripts</body></html>`); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestScanPerRequest_EndToEnd(t *testing.T) {
	if getScanner() == nil {
		t.Skip("skipping: no valid jstangle binary available")
	}
	m := New()

	bundle := `(()=>{"use strict";var e={100:(e,t,r)=>{const n=r(200);` +
		`t.listUsers=function(){return fetch(n.base+"/users",{method:"GET"}).then(x=>x.json())};` +
		`t.createUser=function(u){return fetch(n.base+"/users",{method:"POST",body:JSON.stringify(u)})};` +
		`t.deleteUser=function(id){return fetch(n.base+"/users/"+id,{method:"DELETE"})}},` +
		`200:(e,t)=>{t.base="/api/v3";t.timeout=3e4;t.headers={"X-Api":"1"}},` +
		`300:(e,t,r)=>{const n=r(200);t.listPosts=function(p){return fetch(n.base+"/posts?page="+p)}}},t={};` +
		`function r(n){var a=t[n];if(void 0!==a)return a.exports;var o=t[n]={exports:{}};` +
		`return e[n](o,o.exports,r),o.exports}r.n=e=>e;var n=r(100),s=r(300);console.log(n,s)})();`

	rr := modtest.Response(
		modtest.Request(t, "http://target.test/_next/static/chunks/app.js"),
		"application/javascript", bundle,
	)

	// Bare ScanContext (no repo) — module still emits the info finding, just
	// without the DB overwrite/tag side effects.
	results, err := m.ScanPerRequest(rr, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	f := results[0]
	if f.Info.Severity != severity.Info {
		t.Errorf("severity = %v, want Info", f.Info.Severity)
	}
	if f.ModuleID != "js-beautify" {
		t.Errorf("ModuleID = %q", f.ModuleID)
	}
	// Recovered webpack module paths land in ExtractedResults.
	if len(f.ExtractedResults) == 0 {
		t.Error("expected recovered module paths in ExtractedResults")
	}
	// Beautified document is carried in evidence.
	if len(f.AdditionalEvidence) == 0 || !strings.Contains(f.AdditionalEvidence[0], "fetch") {
		t.Errorf("expected beautified evidence containing code, got %v", f.AdditionalEvidence)
	}
	if fmtStr, _ := f.Metadata["format"].(string); fmtStr != "webpack" {
		t.Errorf("metadata format = %v, want webpack", f.Metadata["format"])
	}

	// A vendor analytics script (filename matches a library pattern) must be
	// skipped even when minified/bundled.
	vrr := modtest.Response(
		modtest.Request(t, "http://target.test/static/gtag.js"),
		"application/javascript", bundle,
	)
	vres, _ := m.ScanPerRequest(vrr, &modkit.ScanContext{})
	if len(vres) != 0 {
		t.Errorf("vendor analytics script should be skipped, got %d findings", len(vres))
	}

	// A CDN-hosted library must also be skipped.
	crr := modtest.Response(
		modtest.Request(t, "https://cdn.jsdelivr.net/npm/app/dist/bundle.min.js"),
		"application/javascript", bundle,
	)
	cres, _ := m.ScanPerRequest(crr, &modkit.ScanContext{})
	if len(cres) != 0 {
		t.Errorf("CDN-hosted script should be skipped, got %d findings", len(cres))
	}
}

func TestCanProcess(t *testing.T) {
	m := New()

	// JS content-type response is processable.
	jsResp := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar a=1;"
	rr := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequest([]byte("GET /app.js HTTP/1.1\r\nHost: t\r\n\r\n")),
		httpmsg.NewHttpResponse([]byte(jsResp)),
	)
	if !m.CanProcess(rr) {
		t.Error("expected CanProcess true for JS response")
	}

	// Empty body is not processable.
	emptyResp := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"
	rr2 := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequest([]byte("GET /app.js HTTP/1.1\r\nHost: t\r\n\r\n")),
		httpmsg.NewHttpResponse([]byte(emptyResp)),
	)
	if m.CanProcess(rr2) {
		t.Error("expected CanProcess false for empty body")
	}

	// Non-JS, non-HTML content type is not processable.
	pngResp := "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG"
	rr3 := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequest([]byte("GET /a.png HTTP/1.1\r\nHost: t\r\n\r\n")),
		httpmsg.NewHttpResponse([]byte(pngResp)),
	)
	if m.CanProcess(rr3) {
		t.Error("expected CanProcess false for image response")
	}
}
