package discovery

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/spider"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
)

// TestNodeServedConfirmsExtension gates the sitemap-walk confirmation: only a
// stored node that was actually served (2xx, or an auth wall) may confirm its
// URL's extension; a 404/redirect/5xx or a node with no response must not.
func TestNodeServedConfirmsExtension(t *testing.T) {
	mkNode := func(status int, hasResp bool) *storage.DiscoveredNode {
		u, _ := url.Parse("http://example.test/legacy/run.cfm")
		n := storage.NewDiscoveredNode(u)
		if hasResp {
			n.SetData(nil, &storage.ResponseData{StatusCode: status}, nil)
		}
		return n
	}

	cases := []struct {
		name    string
		status  int
		hasResp bool
		want    bool
	}{
		{"200 served", 200, true, true},
		{"204 served", 204, true, true},
		{"401 auth wall", 401, true, true},
		{"403 auth wall", 403, true, true},
		{"301 redirect", 301, true, false},
		{"404 not found", 404, true, false},
		{"500 server error", 500, true, false},
		{"unknown status", 0, true, false},
		{"no response recorded", 0, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, nodeServedConfirmsExtension(mkNode(tc.status, tc.hasResp)))
		})
	}
}

// TestExtensionConfirmAllowed covers the source-type + SPA gate that decides
// whether a spider link may confirm a server-side extension for fuzzing.
func TestExtensionConfirmAllowed(t *testing.T) {
	engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
	require.NoError(t, err)
	defer engine.Stop()

	// genuine = a reference the application actually makes (trusted on a non-SPA
	// host); the rest are URL-like strings scavenged from JS/HTML body text.
	cases := []struct {
		src     spider.LinkSourceType
		genuine bool
	}{
		{spider.SourceHTMLAttribute, true},
		{spider.SourceMetaRefresh, true},
		{spider.SourceHTTPHeader, true},
		{spider.SourceRobotsTxt, true},
		{spider.SourceInlineURL, false},
		{spider.SourceJavaScript, false},
		{spider.SourceScriptContent, false},
		{spider.SourceComment, false},
		{spider.SourceEventHandler, false},
		{spider.SourceFlashSWF, false},
	}

	for _, tc := range cases {
		engine.startURLIsModernApp = false
		assert.Equal(t, tc.genuine, engine.extensionConfirmAllowed(tc.src),
			"non-SPA: %s", tc.src)

		// A SPA serves its index shell for every path, so no source confirms.
		engine.startURLIsModernApp = true
		assert.False(t, engine.extensionConfirmAllowed(tc.src), "SPA: %s", tc.src)
	}
}

// TestApplyFileMetadata_ObservedConfirmGate proves the confirmObserved flag
// gates only the extension confirmation — names/paths are still harvested.
func TestApplyFileMetadata_ObservedConfirmGate(t *testing.T) {
	t.Run("suppressed: extension not confirmed, name still harvested", func(t *testing.T) {
		engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
		require.NoError(t, err)
		defer engine.Stop()

		var confirmed []string
		engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
			confirmed = append(confirmed, ev.Extension)
		})

		before := engine.observedNames.Count()
		// This is the exact shape pulled from a JS bundle in the bug report.
		engine.applyFileMetadata("//Reports/Pages/Folder.aspx", 0, false)

		assert.False(t, engine.isExtensionConfirmed("aspx"),
			"aspx must NOT be confirmed from an untrusted/JS-scraped path")
		assert.Empty(t, confirmed, "no confirmation callback should fire")
		assert.Greater(t, engine.observedNames.Count(), before,
			"the filename should still be harvested for discovery")
	})

	t.Run("allowed: extension confirmed", func(t *testing.T) {
		engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
		require.NoError(t, err)
		defer engine.Stop()

		var confirmed []string
		engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
			confirmed = append(confirmed, ev.Extension)
		})

		engine.applyFileMetadata("/admin/login.php", 0, true)

		assert.True(t, engine.isExtensionConfirmed("php"),
			"php should be confirmed from a trusted served path")
		assert.Contains(t, confirmed, "php")
	})
}

func mkLink(t *testing.T, rawURL string, src spider.LinkSourceType) *spider.DiscoveredLink {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &spider.DiscoveredLink{URL: u, SourceType: src}
}

// TestCollectValidatedLinks_NoEagerConfirmUnderConfirmRequired proves that under
// ConfirmRequired (the default) a spider link NEVER confirms a server-side
// extension on its own — not a same-host <a href>, not a cross-host one, not a
// JS-scraped path. This is the engineering.grab.com regression: /sharer.php (FB
// share button), /citation.cfm (ACM link), and /Blog/Pages/x.aspx (MSDN link)
// were all "confirmed" from <a href>s on a static blog. Confirmation is now
// deferred to the served path; filenames are still harvested for discovery.
func TestCollectValidatedLinks_NoEagerConfirmUnderConfirmRequired(t *testing.T) {
	// One genuine, same-host <a href> per candidate stack — none may confirm from
	// the link alone. The gate is extension-agnostic: it covers the whole
	// candidate set (php/asp/aspx/ashx/asmx/jsp/jspx/jspa/do/action/cfm/cfml/cgi),
	// not just the php/cfm/aspx seen in the original report.
	links := []*spider.DiscoveredLink{
		mkLink(t, "http://example.test/admin/login.php", spider.SourceHTMLAttribute),
		mkLink(t, "http://example.test/legacy/run.cfm", spider.SourceHTMLAttribute),
		mkLink(t, "http://example.test/app/home.jsp", spider.SourceHTMLAttribute),
		mkLink(t, "http://example.test/struts/save.action", spider.SourceHTMLAttribute),
		mkLink(t, "http://example.test/svc/handler.ashx", spider.SourceHTMLAttribute),
		mkLink(t, "http://example.test/svc/legacy.asmx", spider.SourceHTMLAttribute),
		mkLink(t, "http://example.test/bin/run.cgi", spider.SourceHTMLAttribute),
		mkLink(t, "http://other.test/Blog/Pages/r-class.aspx", spider.SourceHTMLAttribute), // cross-host
		mkLink(t, "http://example.test/PDC/ajaxreq.do", spider.SourceJavaScript),           // JS-scraped
	}

	for _, spa := range []bool{false, true} {
		engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
		require.NoError(t, err)
		engine.startURLIsModernApp = spa

		got := map[string]bool{}
		engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) { got[ev.Extension] = true })

		before := engine.observedNames.Count()
		engine.collectValidatedLinks(links, 0)

		assert.Empty(t, got, "no extension may be confirmed from a link under ConfirmRequired (spa=%v)", spa)
		assert.Greater(t, engine.observedNames.Count(), before,
			"filenames must still be harvested for discovery (spa=%v)", spa)
		engine.Stop()
	}
}

// TestOnFileDiscovered_ConfirmsServedExtensionInScope proves the deferred
// confirm-on-served path that replaces eager link-time confirmation: a same-host
// file the server actually serves (via a genuine-reference provenance, confirmExt
// = true) confirms its extension, while an out-of-scope served file is
// scope-dropped and never confirms.
func TestOnFileDiscovered_ConfirmsServedExtensionInScope(t *testing.T) {
	cfg := confirmTestConfig("http://example.test/", false)
	cfg.Target.ScopeMode = "exact" // so other.test is genuinely out of scope
	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()
	// Keep the test focused on the confirmation decision — no derivation fan-out.
	engine.config.Target.Recursion.Enabled = false

	got := map[string]bool{}
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) { got[ev.Extension] = true })

	// In-scope served files → confirmed (this is what a real served route reaches
	// once the analyzer classifies it as a genuine, non-soft-404 resource). The
	// served confirmation is uniform across the candidate set, not just cfm/php.
	for _, tc := range []struct{ url, ext string }{
		{"http://example.test/legacy/run.cfm", "cfm"},
		{"http://example.test/app/home.jsp", "jsp"},
		{"http://example.test/struts/save.action", "action"},
		{"http://example.test/svc/handler.ashx", "ashx"},
	} {
		require.NoError(t, engine.OnFileDiscovered(tc.url, 0, true))
		assert.True(t, engine.isExtensionConfirmed(tc.ext), "%s should confirm once a same-host file is served", tc.ext)
		assert.True(t, got[tc.ext], "%s callback should fire", tc.ext)
	}

	// Out-of-scope served file → scope-dropped before metadata extraction.
	require.NoError(t, engine.OnFileDiscovered("http://other.test/x.php", 0, true))
	assert.False(t, engine.isExtensionConfirmed("php"), "a cross-host file must not confirm")
}

// TestOnFileDiscovered_BruteForcedHitDoesNotConfirm is the partnergears.grab.com
// regression: a brute-force fuzz wordlist guess (/axis2//axis2-web/HappyAxis.jsp,
// fuzz.txt) answered with a non-soft-404 200 by a catch-all SPA shell reached
// OnFileDiscovered and "confirmed" .jsp via the observed source, queuing a full
// *.jsp wordlist sweep on a host that runs no JSP at all. With confirmExt=false
// (a guessed provenance) the extension must NOT confirm — but the filename is
// still harvested for discovery.
func TestOnFileDiscovered_BruteForcedHitDoesNotConfirm(t *testing.T) {
	engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
	require.NoError(t, err)
	defer engine.Stop()
	engine.config.Target.Recursion.Enabled = false

	got := map[string]bool{}
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) { got[ev.Extension] = true })

	before := engine.observedNames.Count()
	require.NoError(t, engine.OnFileDiscovered("http://example.test/axis2//axis2-web/HappyAxis.jsp", 0, false))

	assert.False(t, engine.isExtensionConfirmed("jsp"),
		"a brute-forced guess must not confirm .jsp off a catch-all 200")
	assert.Empty(t, got, "no extension-confirm callback should fire for a guessed path")
	assert.Greater(t, engine.observedNames.Count(), before,
		"the filename should still be harvested for discovery")
}

// TestFoundByConfirmsExtension pins the provenance allow-list: genuine
// application references confirm a served extension; every brute-forced task type
// (and any unknown/future type) does not.
func TestFoundByConfirmsExtension(t *testing.T) {
	genuine := []string{"spider", "js-extracted", "jsfetch", "form", "redirect"}
	for _, fb := range genuine {
		assert.True(t, foundByConfirmsExtension(fb), "%q is a genuine reference and should confirm", fb)
	}

	guessed := []string{
		"fuzzer", "numeric", "ext-variant", "malformed-path-probe",
		"short-file-no-ext", "short-file-custom-ext", "short-file-observed-ext",
		"long-file-no-ext", "long-file-custom-ext", "long-file-observed-ext",
		"short-dir", "long-dir", "wordlist", "observed-no-ext", "observed",
		"", "something-new",
	}
	for _, fb := range guessed {
		assert.False(t, foundByConfirmsExtension(fb), "%q is a guess and must not confirm", fb)
	}
}

// TestCollectValidatedLinks_LegacyEagerConfirm proves legacy (non-ConfirmRequired)
// mode is unchanged: a genuine same-host <a href> still seeds its server-side
// extension at link time, while a JS-scraped path and a SPA host do not.
func TestCollectValidatedLinks_LegacyEagerConfirm(t *testing.T) {
	run := func(t *testing.T, spa bool) *Engine {
		t.Helper()
		cfg := confirmTestConfig("http://example.test/", false)
		cfg.Extensions.ConfirmRequired = false // legacy eager path
		engine, err := testEngineWithConfig(cfg)
		require.NoError(t, err)
		engine.startURLIsModernApp = spa
		engine.collectValidatedLinks([]*spider.DiscoveredLink{
			mkLink(t, "http://example.test/legacy/run.cfm", spider.SourceHTMLAttribute),
			mkLink(t, "http://example.test/PDC/ajaxreq.php", spider.SourceJavaScript),
		}, 0)
		return engine
	}

	t.Run("non-SPA: HTML <a href> seeds, JS-scraped suppressed", func(t *testing.T) {
		engine := run(t, false)
		defer engine.Stop()
		assert.True(t, engine.observedExtensions.Contains([]byte("cfm")), "cfm from <a href> should be observed")
		assert.False(t, engine.observedExtensions.Contains([]byte("php")), "php from JS must not be observed")
	})

	t.Run("SPA: even HTML <a href> suppressed", func(t *testing.T) {
		engine := run(t, true)
		defer engine.Stop()
		assert.False(t, engine.observedExtensions.Contains([]byte("cfm")), "no seed on a SPA host")
	})
}
