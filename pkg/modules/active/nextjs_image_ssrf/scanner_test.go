package nextjs_image_ssrf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// nextJSBody fingerprints the host as Next.js so ScanPerHost proceeds past the
// framework gate (jsframework.HasNextJSMarkers looks for __NEXT_DATA__ / /_next/).
const nextJSBody = `<html><head></head><body><script id="__NEXT_DATA__">{}</script><img src="/_next/image"/></body></html>`

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.ID() != ModuleID {
		t.Errorf("ID = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name = %q, want %q", m.Name(), ModuleName)
	}
}

func TestInBandProbes(t *testing.T) {
	if len(inBandProbes) == 0 {
		t.Fatal("expected at least one in-band probe")
	}
	for _, p := range inBandProbes {
		if p.url == "" {
			t.Error("probe URL is empty")
		}
		if len(p.markers) == 0 {
			t.Errorf("probe %q has no markers", p.url)
		}
	}
}

func scanHost(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextJSBody)
	client := modtest.Requester(t)
	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerHost: %v", err)
	}
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.Info.Confidence.String())
	}
	return out
}

// TestNextJSImageSSRF_Positive: the optimizer genuinely proxies the AWS metadata
// listing (plain text, multiple distinct tokens), while the benign baseline and
// other targets carry no markers. Exactly one Tentative finding.
func TestNextJSImageSSRF_Positive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.RawQuery, "169.254.169.254/latest"):
			_, _ = io.WriteString(w, "ami-id\nami-launch-index\ninstance-id\nlocal-hostname\n")
		case strings.Contains(r.URL.RawQuery, "192.0.2.1"):
			_, _ = io.WriteString(w, "image optimization error: could not fetch url")
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()

	conf := scanHost(t, srv)
	if len(conf) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(conf))
	}
	if conf[0] != "tentative" {
		t.Errorf("in-band finding should be tentative, got %q", conf[0])
	}
}

// TestNextJSImageSSRF_HTMLCatchAll reproduces the generic-marker FP: a SPA
// catch-all serves its own HTML page (mentioning "compute"/"localhost") for ANY
// url=, including the metadata targets. The HTML-rejection + baseline gates must
// suppress every probe.
func TestNextJSImageSSRF_HTMLCatchAll(t *testing.T) {
	const spa = `<!doctype html><html><head><title>app</title></head><body>` +
		`<script>const compute=1,region='x';if(window.location.hostname==='localhost'){}</script>` +
		`</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, spa)
	}))
	defer srv.Close()

	if conf := scanHost(t, srv); len(conf) != 0 {
		t.Fatalf("HTML catch-all must not be reported, got %v", conf)
	}
}

// TestNextJSImageSSRF_PlainCatchAll: a plain-text catch-all returns metadata-like
// tokens for ANY url=, including the benign baseline. The baseline-subtraction gate
// must unmask it as a catch-all even though the body is not HTML.
func TestNextJSImageSSRF_PlainCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ami-id instance-id local-hostname compute vmId vmSize")
	}))
	defer srv.Close()

	if conf := scanHost(t, srv); len(conf) != 0 {
		t.Fatalf("plain-text catch-all must be suppressed by the baseline gate, got %v", conf)
	}
}

// nextStatusTemplate renders a long fixed optimizer status page that only echoes
// the target host word — the shape that defeats a bare-token check, since two
// renderings differ only by the host and are therefore >0.95 similar.
func nextStatusTemplate(host string) string {
	return "Image optimization request log entry. The optimizer attempted to fetch the requested upstream image " +
		"resource and prepare a resized variant for delivery to the client browser as part of the standard pipeline. " +
		"The remote endpoint did not return a renderable image payload so this diagnostic notice is shown instead of " +
		"binary output and no upstream bytes are included anywhere in this particular message under the safety policy. " +
		"The requested upstream host recorded for this attempt was " + host + " and the optimizer cache layer reported " +
		"a miss for the associated transform key while the retry budget for this request path was left fully intact."
}

// TestNextJSImageSSRF_LocalhostSameTemplate is the differential test for the
// html-expected (localhost) probe. The optimizer answers every url= with the same
// fixed status template that only echoes the host word, so "localhost" appears for
// http://127.0.0.1 but is absent from the dead-host (192.0.2.1) baseline. The
// fresh-token check alone would report it; the differential gate (the bodies are
// otherwise identical) must suppress it — the optimizer did not reach localhost.
func TestNextJSImageSSRF_LocalhostSameTemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.RawQuery, "127.0.0.1"):
			_, _ = io.WriteString(w, nextStatusTemplate("localhost"))
		case strings.Contains(r.URL.RawQuery, "192.0.2.1"):
			_, _ = io.WriteString(w, nextStatusTemplate("192.0.2.1"))
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()

	if conf := scanHost(t, srv); len(conf) != 0 {
		t.Fatalf("a fixed template that only echoes the host word must not be reported as localhost SSRF, got %v", conf)
	}
}
