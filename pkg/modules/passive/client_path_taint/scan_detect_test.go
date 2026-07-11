package client_path_taint

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/modules/infra/csptflow"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// requireBinary skips when the embedded jstangle binary isn't available (e.g. a
// fresh checkout before the binary is provisioned).
func requireBinary(t *testing.T) {
	t.Helper()
	sc, err := jstangle.NewScanner(jstangle.DefaultConfig())
	if err != nil || sc.EnsureBinary() != nil {
		t.Skip("skipping: no valid jstangle binary available")
	}
}

// scan runs the passive module over a synthetic response and returns the
// findings plus the ScanContext (so a caller can assert the published tech tag).
func scan(t *testing.T, contentType, body string) ([]*output.ResultEvent, *modkit.ScanContext, string) {
	t.Helper()
	rr := modtest.Request(t, "http://example.com/app")
	rr = modtest.Response(rr, contentType, body)
	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	res, err := New().ScanPerRequest(rr, sc)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	return res, sc, "example.com"
}

// --- real-jstangle integration tests -------------------------------------

// TestCSPT_DetectsFetchHashFlow: the canonical CSPT pattern —
// fetch('/api/items/' + location.hash) — must produce a candidate finding and
// publish the cspt-candidate tech tag.
func TestCSPT_DetectsFetchHashFlow(t *testing.T) {
	requireBinary(t)
	js := `fetch('/api/items/' + location.hash.slice(1)).then(r => r.json());`
	res, sc, host := scan(t, "application/javascript", js)
	require.NotEmpty(t, res, "expected a CSPT candidate for hash -> fetch path")

	f := res[0]
	assert.Equal(t, output.RecordKindCandidate, f.RecordKind)
	assert.True(t, sc.TechStack.Has(host, TechTagCSPTCandidate), "cspt-candidate tag must be published")
	assert.Contains(t, f.Info.Description, "location.hash")
}

// TestCSPT_DetectsInlineScriptFlow: same flow inside an inline <script> of an
// HTML document is extracted and analyzed.
func TestCSPT_DetectsInlineScriptFlow(t *testing.T) {
	requireBinary(t)
	html := `<html><head><script>
		var q = new URLSearchParams(location.search);
		var xhr = new XMLHttpRequest();
		xhr.open('GET', '/api/user/' + q.get('id'));
		xhr.send();
	</script></head><body></body></html>`
	res, sc, host := scan(t, "text/html", html)
	require.NotEmpty(t, res, "expected a CSPT candidate for search -> XHR path")
	assert.True(t, sc.TechStack.Has(host, TechTagCSPTCandidate))
}

// TestCSPT_NoFindingForConstantPath: a URL source is read but never reaches the
// request path (the fetch target is a constant) — no flow, no candidate, and the
// tech tag must NOT be published.
func TestCSPT_NoFindingForConstantPath(t *testing.T) {
	requireBinary(t)
	js := `var x = location.hash; fetch('/api/items/static');`
	res, sc, host := scan(t, "application/javascript", js)
	assert.Empty(t, res, "a constant request path must not produce a candidate")
	assert.False(t, sc.TechStack.Has(host, TechTagCSPTCandidate), "no candidate -> no tech tag")
}

// TestCSPT_DoesNotMislabelDomXss: a DOM-XSS flow (source -> innerHTML) is owned
// by dom_xss_taint and must never be reported as a CSPT candidate here.
func TestCSPT_DoesNotMislabelDomXss(t *testing.T) {
	requireBinary(t)
	js := `document.getElementById('o').innerHTML = location.hash;`
	res, sc, host := scan(t, "application/javascript", js)
	assert.Empty(t, res, "a DOM-XSS flow must not be labeled CSPT")
	assert.False(t, sc.TechStack.Has(host, TechTagCSPTCandidate))
}

// TestCSPT_IgnoresNonScriptResponses: JSON/media responses are skipped by the
// extractor/gate before any analysis (no binary needed).
func TestCSPT_IgnoresNonScriptResponses(t *testing.T) {
	res, _, _ := scan(t, "application/json", `{"location.hash":"fetch XMLHttpRequest"}`)
	assert.Empty(t, res, "JSON responses must be ignored")
}

// --- pure candidate-selection unit tests (no binary) ---------------------

// TestSelectCandidates_NetworkFlowSelected: the clientRequestInjection class is
// selected and its prefix/method parsed. Belt: the same flow arriving as both a
// DomFlow and a BrowserFlow dedups to one candidate.
func TestSelectCandidates_NetworkFlowSelected(t *testing.T) {
	dom := []jstangle.DomFlow{{
		FlowType: "clientRequestInjection",
		Source:   "location.hash",
		Sink:     "network.fetch",
		Snippet:  "fetch('/api/items/' + location.hash.slice(1))",
		Line:     7,
	}}
	browser := []jstangle.BrowserSecurityFlowFact{{
		FlowType: "clientRequestInjection",
		Source:   "location.hash",
		Sink:     "network.fetch",
		Evidence: "fetch('/api/items/' + location.hash.slice(1))",
	}}
	got := selectCandidates(dom, browser)
	require.Len(t, got, 1, "duplicate dom/browser flow must collapse to one candidate")
	assert.Equal(t, "/api/items/", got[0].Prefix)
	assert.Equal(t, "GET", got[0].Method)
	assert.Equal(t, 7, got[0].Line)
}

// TestSelectCandidates_MethodInference covers XHR .open() and fetch {method:...}.
func TestSelectCandidates_MethodInference(t *testing.T) {
	got := selectCandidates([]jstangle.DomFlow{
		{FlowType: "clientRequestInjection", Source: "location.search", Sink: "XMLHttpRequest.open",
			Snippet: "xhr.open('POST', '/api/data/' + q.get('id'))"},
		{FlowType: "clientRequestInjection", Source: "location.hash", Sink: "network.fetch",
			Snippet: "fetch('/api/items/' + location.hash, {method:'DELETE'})"},
	}, nil)
	require.Len(t, got, 2)
	assert.Equal(t, "POST", got[0].Method)
	assert.Equal(t, "/api/data/", got[0].Prefix)
	assert.Equal(t, "DELETE", got[1].Method)
}

// TestSelectCandidates_RejectsDomXssAndRedirect: DOM-XSS and open-redirect flows
// are owned by other modules and must be rejected here.
func TestSelectCandidates_RejectsDomXssAndRedirect(t *testing.T) {
	got := selectCandidates([]jstangle.DomFlow{
		{FlowType: "domXss", Source: "location.hash", Sink: "innerHTML", Snippet: "el.innerHTML = location.hash"},
		{FlowType: "openRedirect", Source: "location.hash", Sink: "location.href", Snippet: "location.href = location.hash"},
	}, nil)
	assert.Empty(t, got)
}

// TestSelectCandidates_RejectsNonURLSource: an allowlisted/constant source that
// is not URL-controlled (e.g. a config value) is not a CSPT candidate even when
// it reaches a network sink.
func TestSelectCandidates_RejectsNonURLSource(t *testing.T) {
	got := selectCandidates([]jstangle.DomFlow{
		{FlowType: "clientRequestInjection", Source: "config.baseUrl", Sink: "network.fetch",
			Snippet: "fetch(config.baseUrl + '/items')"},
	}, nil)
	assert.Empty(t, got, "a non-URL source must not be a CSPT candidate")
}

// TestSelectCandidates_FallbackByRegex: when the helper doesn't set the dedicated
// flow class, a URL source + network sink still selects (belt-and-suspenders).
func TestSelectCandidates_FallbackByRegex(t *testing.T) {
	got := selectCandidates([]jstangle.DomFlow{
		{FlowType: "", Source: "location.pathname", Sink: "network.fetch",
			Snippet: "fetch('/api/x/' + location.pathname)"},
	}, nil)
	require.Len(t, got, 1)
	assert.Equal(t, "/api/x/", got[0].Prefix)
}

func TestParsePrefix(t *testing.T) {
	assert.Equal(t, "/api/items/", csptflow.ParsePrefix("fetch('/api/items/' + location.hash)"))
	assert.Equal(t, "/api/data/", csptflow.ParsePrefix("xhr.open('GET', '/api/data/' + q.get('id'))"))
	assert.Equal(t, "https://x/api/", csptflow.ParsePrefix("fetch(`https://x/api/` + h)"))
	assert.Equal(t, "", csptflow.ParsePrefix("fetch(base + location.hash)"))
}

func TestGateRegexes(t *testing.T) {
	assert.True(t, gateSourceRe.MatchString("location.hash"))
	assert.True(t, gateSourceRe.MatchString("new URLSearchParams(location.search)"))
	assert.True(t, gateSinkRe.MatchString("fetch('/x')"))
	assert.True(t, gateSinkRe.MatchString("xhr.open('GET','/x')"))
	assert.False(t, gateSinkRe.MatchString("console.log(x)"))
	assert.False(t, strings.Contains("", "cspt")) // sanity
}
