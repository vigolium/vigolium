package discovery

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// confirmTestConfig builds an engine config with the extension-confirm pipeline
// enabled. TestObserved is left off so confirmExtension does not try to generate
// dynamic tasks (which need storage); the tests assert the confirmation decision
// itself (callback + confirmed/observed state).
func confirmTestConfig(startURL string, probe bool) *config.Config {
	return &config.Config{
		Target: config.TargetConfig{
			StartURL:  startURL,
			Mode:      config.ModeFilesAndDirs,
			Recursion: config.RecursionConfig{Enabled: true, MaxDepth: 16},
		},
		Filenames: config.FilenameConfig{Wordlists: config.WordlistConfig{}},
		Extensions: config.ExtensionConfig{
			ConfirmRequired:       true,
			ConfirmViaObserved:    true,
			ConfirmViaFingerprint: true,
			ConfirmViaProbe:       probe,
			Candidates:            []string{"php", "aspx", "ashx", "jsp", "jspx", "do", "action", "cgi", "cfm"},
			ProbeFilenames:        []string{"index"},
			TestObserved:          false,
			TestNoExtension:       true,
		},
		Engine: config.EngineConfig{
			CaseSensitivity:  config.CaseInsensitive,
			DiscoveryThreads: 4,
			Timeout:          30 * time.Second,
		},
	}
}

func TestNormalizeExt(t *testing.T) {
	cases := map[string]string{
		"php":       "php",
		".php":      "php",
		"..PHP":     "php",
		"  .Action": "action",
		"ASPX ":     "aspx",
		"":          "",
		".":         "",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeExt(in), "normalizeExt(%q)", in)
	}
}

func TestStartURLDirectory(t *testing.T) {
	cases := map[string]string{
		"http://h/admin.php":         "/",
		"http://h/app/index.php?x=1": "/app/",
		"http://h/app/v1/":           "/app/v1/",
		"http://h":                   "/",
		"http://h/a/b/c.jsp#frag":    "/a/b/",
	}
	for in, wantPath := range cases {
		u, err := url.Parse(in)
		require.NoError(t, err)
		dir := startURLDirectory(u)
		require.NotNil(t, dir)
		assert.Equal(t, wantPath, dir.Path, "startURLDirectory(%q).Path", in)
		assert.Empty(t, dir.RawQuery)
		assert.Empty(t, dir.Fragment)
	}
}

func TestConfirmExtension_DedupCallbackAndCandidateGate(t *testing.T) {
	engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
	require.NoError(t, err)
	defer engine.Stop()

	var events []ExtensionConfirmEvent
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
		events = append(events, ev)
	})

	// First confirmation succeeds.
	assert.True(t, engine.confirmExtension("php", "test", "detail", 0))
	assert.True(t, engine.isExtensionConfirmed("php"))
	assert.True(t, engine.observedExtensions.Contains([]byte("php")), "php should be in observed extensions")

	// Repeat confirmation (with dotted/upper form) is a no-op.
	assert.False(t, engine.confirmExtension(".PHP", "test", "again", 0))

	// Non-candidate extension is rejected outright.
	assert.False(t, engine.confirmExtension("html", "test", "", 0))
	assert.False(t, engine.isExtensionConfirmed("html"))

	// Exactly one callback fired (the first php confirmation).
	require.Len(t, events, 1)
	assert.Equal(t, "php", events[0].Extension)
	assert.Equal(t, "test", events[0].Source)
}

func TestConfirmExtensionsFromHeaders_Fingerprint(t *testing.T) {
	tests := []struct {
		name     string
		header   http.Header
		wantExts []string
		noneExts []string
	}{
		{
			name:     "PHPSESSID ⇒ php",
			header:   http.Header{"Set-Cookie": {"PHPSESSID=abc; path=/"}},
			wantExts: []string{"php"},
			noneExts: []string{"aspx", "jsp"},
		},
		{
			name:     "JSESSIONID ⇒ jsp/jspx/do/action",
			header:   http.Header{"Set-Cookie": {"JSESSIONID=xyz; Path=/"}},
			wantExts: []string{"jsp", "jspx", "do", "action"},
			noneExts: []string{"php", "aspx"},
		},
		{
			name:     "ASP.NET_SessionId ⇒ aspx/ashx",
			header:   http.Header{"Set-Cookie": {"ASP.NET_SessionId=q; path=/"}},
			wantExts: []string{"aspx", "ashx"},
			noneExts: []string{"php", "jsp"},
		},
		{
			name:     "static site ⇒ nothing",
			header:   http.Header{"Server": {"nginx"}},
			noneExts: []string{"php", "aspx", "jsp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
			require.NoError(t, err)
			defer engine.Stop()

			engine.confirmExtensionsFromHeaders(tt.header.Get, tt.header.Values("Set-Cookie"), "test", 0)

			for _, e := range tt.wantExts {
				assert.True(t, engine.isExtensionConfirmed(e), "%s should be confirmed", e)
			}
			for _, e := range tt.noneExts {
				assert.False(t, engine.isExtensionConfirmed(e), "%s should NOT be confirmed", e)
			}
		})
	}
}

func TestConfirmStartURLExtensions_ObservedSeedExt(t *testing.T) {
	// Start URL is itself a .php file ⇒ php confirmed via the "observed" source.
	// Probe disabled so no network is needed.
	engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/admin.php", false))
	require.NoError(t, err)
	defer engine.Stop()

	var sources []string
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
		if ev.Extension == "php" {
			sources = append(sources, ev.Source)
		}
	})

	engine.confirmStartURLExtensions()

	assert.True(t, engine.isExtensionConfirmed("php"), "php should be confirmed from the .php start URL")
	require.NotEmpty(t, sources)
	assert.Equal(t, "observed", sources[0])
}

// probeServer serves a real resource at /index.<ext> and 404s everything else,
// so the analyzer sees index.<ext> as distinct from the soft-404 baseline.
func probeServer(realPath string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == realPath {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>real application home page with unique content</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
}

func TestProbeCandidateExtensions_ConfirmsRealRoute(t *testing.T) {
	server := probeServer("/index.php")
	defer server.Close()

	engine, err := testEngineWithConfig(confirmTestConfig(server.URL, true))
	require.NoError(t, err)
	defer engine.Stop()
	engine.config.Extensions.Candidates = []string{"php"}

	var confirmed []string
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
		confirmed = append(confirmed, ev.Extension)
	})

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	// Learn the soft-404 baseline first (initSession does this before probing in
	// production), so the wildcard differential can recognise the 404s.
	require.NoError(t, engine.learnBaselineFingerprints(u))
	engine.probeCandidateExtensions(startURLDirectory(u), 0)

	assert.True(t, engine.isExtensionConfirmed("php"), "php should be confirmed via probe of index.php")
	assert.Contains(t, confirmed, "php")
}

func TestProbeCandidateExtensions_CatchAllNotConfirmed(t *testing.T) {
	// Catch-all server: identical 200 for every path. index.php must NOT confirm
	// because it is indistinguishable from the per-extension soft-404 baseline.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>catch-all landing page</body></html>"))
	}))
	defer server.Close()

	engine, err := testEngineWithConfig(confirmTestConfig(server.URL, true))
	require.NoError(t, err)
	defer engine.Stop()
	engine.config.Extensions.Candidates = []string{"php"}

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	require.NoError(t, engine.learnBaselineFingerprints(u))
	engine.probeCandidateExtensions(startURLDirectory(u), 0)

	assert.False(t, engine.isExtensionConfirmed("php"),
		"php must NOT be confirmed on a catch-all host")
}
