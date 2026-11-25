package http_request_smuggling

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestNew(t *testing.T) {
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, severity.Suspect, m.Severity())
	assert.Equal(t, severity.Tentative, m.Confidence())
	assert.Equal(t, modkit.ScanScopeHost, m.ScanScopes())
}

func TestCanProcess(t *testing.T) {
	m := New()

	t.Run("nil context", func(t *testing.T) {
		assert.False(t, m.CanProcess(nil))
	})

	t.Run("no request", func(t *testing.T) {
		ctx := httpmsg.NewHttpRequestResponse(nil, nil)
		assert.False(t, m.CanProcess(ctx))
	})

	t.Run("request without response", func(t *testing.T) {
		ctx, err := httpmsg.ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		assert.False(t, m.CanProcess(ctx), "smuggling needs a baseline response to compare timing against")
	})

	t.Run("request with response", func(t *testing.T) {
		ctx, err := httpmsg.ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		require.NoError(t, err)
		resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		ctxWithResp := httpmsg.NewHttpRequestResponse(ctx.Request(), resp)
		assert.True(t, m.CanProcess(ctxWithResp))
	})
}

// TestProbesWellFormed verifies every desync probe carries the conflicting
// Content-Length / Transfer-Encoding headers that make it a smuggling probe.
// A probe that lost one of these headers (e.g. via a refactor) would silently
// stop testing for desync while still appearing in the probe list.
func TestProbesWellFormed(t *testing.T) {
	assert.NotEmpty(t, probes, "probe table must not be empty")

	names := map[string]struct{}{}
	for i, p := range probes {
		assert.NotEmpty(t, p.name, "probe[%d] must have a name", i)
		assert.NotEmpty(t, p.desc, "probe[%d] (%s) must have a description", i, p.name)
		assert.NotEmpty(t, p.body, "probe[%d] (%s) must have a body", i, p.name)

		_, hasCL := httpmsg.FindHttpHeader(p.headers, "Content-Length")
		_, hasTE := httpmsg.FindHttpHeader(p.headers, "Transfer-Encoding")
		assert.True(t, hasCL, "probe[%d] (%s) must set Content-Length to create a desync", i, p.name)
		assert.True(t, hasTE, "probe[%d] (%s) must set Transfer-Encoding to create a desync", i, p.name)

		if _, dup := names[p.name]; dup {
			t.Errorf("duplicate probe name %q", p.name)
		}
		names[p.name] = struct{}{}
	}
}

// TestBuildRequest_PreservesDeclaredContentLength is the regression test for
// the bug that neutered every probe: the builder used to set the probe's
// headers and then call SetBody, which recomputes Content-Length to match the
// body it is given. The deliberate disagreement between Content-Length and the
// body — the entire attack primitive — was repaired on the way out, so
// "Content-Length: 4" left as 11 or 19 and the probe became an ordinary,
// correctly framed POST.
func TestBuildRequest_PreservesDeclaredContentLength(t *testing.T) {
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			ctx, err := httpmsg.ParseRawRequest("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n")
			require.NoError(t, err)

			raw, built := buildRequest(ctx, p)
			require.True(t, built)
			out := string(raw)

			declared, ok := httpmsg.FindHttpHeader(p.headers, "Content-Length")
			require.True(t, ok)

			assert.Contains(t, out, "Content-Length: "+declared+"\r\n",
				"the probe's declared Content-Length must reach the wire verbatim; "+
					"recomputing it to the real body length (%d) removes the CL/TE conflict",
				len(p.body))
			assert.Equal(t, 1, strings.Count(out, "Content-Length:"),
				"exactly one Content-Length header — a second, recomputed one is the same bug")
			assert.True(t, strings.HasSuffix(out, p.body),
				"probe body must be attached verbatim")
		})
	}
}

// TestBuildRequest_TETEKeepsBothHeaders covers the TE.TE obfuscation probe,
// whose two Transfer-Encoding headers differ only in case. Probes used to be
// built from a map, and since RemoveHeader matches case-insensitively, applying
// "Transfer-Encoding" and "Transfer-encoding" in Go's randomized map order left
// exactly ONE of them — a different one from run to run. The probe never tested
// TE.TE, and a focused rerun of a reported finding could legitimately come back
// empty.
func TestBuildRequest_TETEKeepsBothHeaders(t *testing.T) {
	var teTe smugglingProbe
	for _, p := range probes {
		if p.name == "TE.TE Obfuscation" {
			teTe = p
		}
	}
	require.NotEmpty(t, teTe.name, "TE.TE probe must exist")

	ctx, err := httpmsg.ParseRawRequest("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)

	raw, ok := buildRequest(ctx, teTe)
	require.True(t, ok)
	out := string(raw)

	assert.Contains(t, out, "Transfer-Encoding: chunked\r\n")
	assert.Contains(t, out, "Transfer-encoding: x\r\n",
		"the lower-cased duplicate is the obfuscation; without it this is not a TE.TE probe")
	assert.Equal(t, 2, strings.Count(strings.ToLower(out), "transfer-encoding:"),
		"TE.TE needs exactly two Transfer-Encoding headers")
}

// TestBuildRequest_IsDeterministic guards the same bug from the other side:
// the bytes must be identical on every build, so a finding can actually be
// reproduced by re-running the module.
func TestBuildRequest_IsDeterministic(t *testing.T) {
	ctx, err := httpmsg.ParseRawRequest(
		"GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nCookie: a=b\r\n\r\n")
	require.NoError(t, err)

	for _, p := range probes {
		first, ok := buildRequest(ctx, p)
		require.True(t, ok)
		for i := 0; i < 50; i++ {
			again, ok := buildRequest(ctx, p)
			require.True(t, ok)
			require.Equal(t, string(first), string(again),
				"probe %q must build byte-identically every time", p.name)
		}
	}
}

// TestBuildRequest_StripsCapturedFramingHeaders verifies the crafted framing
// is the ONLY framing present: a Content-Length or Transfer-Encoding carried by
// the captured request must not survive alongside the probe's own.
func TestBuildRequest_StripsCapturedFramingHeaders(t *testing.T) {
	ctx, err := httpmsg.ParseRawRequest(
		"POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n" +
			"Transfer-Encoding: gzip\r\nX-Keep: yes\r\n\r\nhello")
	require.NoError(t, err)

	raw, ok := buildRequest(ctx, probes[0])
	require.True(t, ok)
	out := string(raw)

	assert.Equal(t, 1, strings.Count(out, "Content-Length:"),
		"the captured Content-Length must be stripped, leaving only the probe's")
	assert.NotContains(t, out, "Transfer-Encoding: gzip",
		"the captured Transfer-Encoding must be stripped")
	assert.Contains(t, out, "X-Keep: yes", "unrelated captured headers must be preserved")
}

// engagementReadings are the real timing series from the request-smuggling
// findings this module produced across a live engagement. Every one was a false
// positive: the "well-formed control" was within 1.08x-1.52x of the probe, so
// the latency was general to POST traffic on that host and not attributable to
// framing. The old gate compared the control against the host's GET baseline
// instead of against the probe, and with a 5s absolute floor in that comparison
// ANY control under 5 seconds counted as "fast" — one of these controls took
// 6.5s and was still reported as proof the probe's slowness was desync-specific.
var engagementReadings = []struct {
	name    string
	probe   time.Duration
	control time.Duration
}{
	{"assets.hyatt.com TE.CL", 9893 * time.Millisecond, 6504 * time.Millisecond},
	{"mfa.bmo.gs.com/ooba/mechanisms TE.CL", 5290 * time.Millisecond, 4478 * time.Millisecond},
	{"mfa.bmo.gs.com/ooba TE.TE", 6608 * time.Millisecond, 4916 * time.Millisecond},
	{"marquee-qa.gs.com TE.TE", 5337 * time.Millisecond, 4956 * time.Millisecond},
	{"accounts.gs.com/oauth2 TE.CL", 6260 * time.Millisecond, 4240 * time.Millisecond},
	{"accounts.gs.com/device/authorize TE.CL", 6363 * time.Millisecond, 4880 * time.Millisecond},
	{"meechum.prod.netflix.net/test ChunkExt", 6681 * time.Millisecond, 4543 * time.Millisecond},
}

// TestDesyncSlower_RejectsEngagementFalsePositives replays every false positive
// the module reported in the field through the new gate. All of them must be
// rejected on the probe-vs-control comparison alone.
func TestDesyncSlower_RejectsEngagementFalsePositives(t *testing.T) {
	for _, r := range engagementReadings {
		t.Run(r.name, func(t *testing.T) {
			assert.False(t, desyncSlower(r.probe, r.control),
				"probe %s vs control %s is a %.2fx differential — a request that CANNOT "+
					"desync was nearly as slow, so the latency is general, not framing",
				r.probe, r.control, float64(r.probe)/float64(r.control))
		})
	}
}

// TestDesyncSlower_AcceptsGenuineDifferential is the other half: a real CL.TE
// stall, where the well-formed control answers promptly and the probe hangs
// until a read timeout, must still be caught.
func TestDesyncSlower_AcceptsGenuineDifferential(t *testing.T) {
	assert.True(t, desyncSlower(10*time.Second, 200*time.Millisecond),
		"a fast control against a hung probe is the signature the class predicts")
	assert.True(t, desyncSlower(30*time.Second, 1500*time.Millisecond),
		"client-timeout probe against a responsive control")
}

// TestDesyncSlower_Gates covers each condition independently.
func TestDesyncSlower_Gates(t *testing.T) {
	// Ratio met, but both are fast: 150ms vs 40ms is scheduling noise.
	assert.False(t, desyncSlower(150*time.Millisecond, 40*time.Millisecond),
		"must clear the absolute floor, not just the ratio")

	// Over the floor and a big absolute margin, but the control is slow too.
	assert.False(t, desyncSlower(9*time.Second, 4*time.Second),
		"must be >3x the control, not merely slower than it")

	// Over the floor and over the ratio, but the absolute margin is tiny.
	assert.False(t, desyncSlower(5100*time.Millisecond, 1700*time.Millisecond),
		"must clear the absolute margin so a marginal gap cannot ride the ratio")

	assert.False(t, desyncSlower(time.Second, time.Second))
}

func TestMedianDuration(t *testing.T) {
	assert.Equal(t, time.Duration(0), medianDuration(nil))
	assert.Equal(t, 2*time.Second, medianDuration([]time.Duration{2 * time.Second}))
	// The median must discard the outlier, which is the point of sampling.
	assert.Equal(t, 300*time.Millisecond, medianDuration([]time.Duration{
		300 * time.Millisecond, 20 * time.Second, 280 * time.Millisecond,
	}))
}

// cloudflareEdgeRestrictedBody is the body Cloudflare served for the real
// false-positive report: a 403 "Edge IP Restricted" (error 1034) page. The
// request was rejected at the edge and never reached an origin frontend/backend
// chain, so the 7.3s vs 1.4s timing gap was edge processing, not a desync.
const cloudflareEdgeRestrictedBody = `<!doctype html>
<html class="no-js" lang="en-US">
  <head><title>Edge IP Restricted | example.com | Cloudflare</title></head>
  <body>
    <div id="cf-error-details" class="p-0">
      <h1><span>Error</span> <span>1034</span></h1>
      <h2 class="text-gray-600">Edge IP Restricted</h2>
      <link rel="stylesheet" href="/cdn-cgi/styles/main.css" />
      <span>Cloudflare Ray ID: <strong>a05680a3b81891cc</strong></span>
    </div>
  </body>
</html>`

// TestLooksLikeEdgeBlockPage covers the body-marker block detection that backs
// the smuggling false-positive fix.
func TestLooksLikeEdgeBlockPage(t *testing.T) {
	t.Run("cloudflare edge ip restricted (the reported FP)", func(t *testing.T) {
		assert.True(t, looksLikeEdgeBlockPage(cloudflareEdgeRestrictedBody),
			"Cloudflare 403 edge block page must be recognized so it never backs a finding")
	})

	t.Run("various edge/WAF markers", func(t *testing.T) {
		blocks := []string{
			`<div id="cf-error-details">Attention Required! | Cloudflare</div>`,
			`Access Denied - server: AkamaiGHost`,
			`The request could not be satisfied. Generated by cloudfront`,
			`<html>error 1020 access denied</html>`,
			`<html>The requested URL was rejected. Consult your administrator.</html>`,
		}
		for _, b := range blocks {
			assert.True(t, looksLikeEdgeBlockPage(b), "should flag block page: %q", b)
		}
	})

	t.Run("markers the shared detector owns are not duplicated here", func(t *testing.T) {
		// These live in the shared signature table (waf.Signatures), which
		// isEdgeOrGateResponse consults first through infra's detector. Repeating them locally is how marker sets drift apart;
		// TestIsEdgeOrGateResponse proves the coverage is still there.
		for _, b := range []string{
			`Request unsuccessful. Incapsula incident ID: 123`,
			`<div>_Incapsula_Resource</div>`,
		} {
			assert.False(t, looksLikeEdgeBlockPage(b),
				"already covered by infra, should not be duplicated locally: %q", b)
		}
	})

	t.Run("legitimate origin response is not a block", func(t *testing.T) {
		assert.False(t, looksLikeEdgeBlockPage(""))
		assert.False(t, looksLikeEdgeBlockPage(`<html><body>Welcome to the app dashboard</body></html>`))
		assert.False(t, looksLikeEdgeBlockPage(`{"status":"ok","data":[]}`))
	})
}

// TestIsEdgeOrGateResponse covers the "did this actually reach the origin's
// parser chain?" gate. Every false positive from the engagement answered from an
// edge or an auth gate — a CloudFront 404, an Akamai 503, a 401 bearer challenge
// — and none of those can evidence a back-end framing disagreement.
func TestIsEdgeOrGateResponse(t *testing.T) {
	t.Run("cloudfront 404 edge rejection", func(t *testing.T) {
		rc := modtest.ResponseChain(t, 404, http.Header{"Server": {"AmazonS3"}},
			`<html><body>AdmitOne</body></html>`)
		assert.True(t, isEdgeOrGateResponse(rc),
			"a CloudFront/S3 edge 404 is not an application response; the old status "+
				"list stopped at 503 and let this through")
	})

	t.Run("401 bearer auth gate", func(t *testing.T) {
		rc := modtest.ResponseChain(t, 401, http.Header{
			"Www-Authenticate": {`Bearer error="invalid_request", error_description="No bearer token found"`},
		}, "<html>401</html>")
		assert.True(t, isEdgeOrGateResponse(rc),
			"the request was rejected on credentials before the app processed it")
	})

	t.Run("ordinary application 404 is not a block", func(t *testing.T) {
		rc := modtest.ResponseChain(t, 404, http.Header{"Content-Type": {"application/json"}},
			`{"error":"no such order","order_id":42}`)
		assert.False(t, isEdgeOrGateResponse(rc),
			"widening the status list must not swallow real application responses")
	})

	t.Run("ordinary 200 is not a block", func(t *testing.T) {
		rc := modtest.ResponseChain(t, 200, nil, `{"status":"ok"}`)
		assert.False(t, isEdgeOrGateResponse(rc))
	})

	t.Run("incapsula interstitial, via the shared detector", func(t *testing.T) {
		rc := modtest.ResponseChain(t, 200, nil,
			`<html>Request unsuccessful. Incapsula incident ID: 123-456</html>`)
		assert.True(t, isEdgeOrGateResponse(rc),
			"markers dropped from the local list must still be caught by infra's")
	})

	t.Run("nil is safe", func(t *testing.T) {
		assert.False(t, isEdgeOrGateResponse(nil))
	})
}

// TestConnectionWillClose covers the precondition that has no timing component
// at all: smuggling needs a connection the next request will reuse. Several
// engagement findings were raised against hosts answering Connection: close,
// where there is no socket to poison no matter what the clock says.
func TestConnectionWillClose(t *testing.T) {
	t.Run("explicit close header", func(t *testing.T) {
		rc := modtest.ResponseChain(t, 200, http.Header{"Connection": {"close"}}, "ok")
		assert.True(t, connectionWillClose(rc))
	})

	t.Run("keep-alive", func(t *testing.T) {
		rc := modtest.ResponseChain(t, 200, http.Header{"Connection": {"keep-alive"}}, "ok")
		assert.False(t, connectionWillClose(rc))
	})

	t.Run("absent header", func(t *testing.T) {
		rc := modtest.ResponseChain(t, 200, nil, "ok")
		assert.False(t, connectionWillClose(rc))
	})

	t.Run("nil is safe", func(t *testing.T) {
		assert.False(t, connectionWillClose(nil))
	})
}

// TestBuildResult_CarriesConfirmationEvidence asserts the confirmation
// differential — the reconfirmed slow probe and the re-measured fast control —
// is preserved on the finding as AdditionalEvidence and Metadata, rather than
// collapsed to a one-line prose claim that "the control returned fast".
func TestBuildResult_CarriesConfirmationEvidence(t *testing.T) {
	ctx, err := httpmsg.ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)
	probeRaw, ok := buildRequest(ctx, probes[0])
	require.True(t, ok)

	ev := desyncEvidence{
		reElapsed:   8 * time.Second,
		probeResp:   "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		ctrlElapsed: 300 * time.Millisecond,
		ctrlResp:    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	}
	control := controlReading{
		median: 280 * time.Millisecond,
		raw:    []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\n1"),
	}

	res := buildResult(ctx, probeRaw, probes[0], control, 7*time.Second, false, ev)
	require.NotNil(t, res)

	assert.NotEmpty(t, res.Response, "the reconfirmed probe response should be the primary response pair")
	require.NotEmpty(t, res.AdditionalEvidence, "the confirmation differential must travel as evidence")
	joined := strings.Join(res.AdditionalEvidence, "\n")
	assert.Contains(t, joined, "# [reconfirm probe", "expected the reconfirmed probe pair")
	assert.Contains(t, joined, "# [well-formed control", "expected the fast control pair")

	require.NotNil(t, res.Metadata)
	assert.Equal(t, ev.reElapsed.Milliseconds(), res.Metadata["reconfirm_ms"])
	assert.Equal(t, ev.ctrlElapsed.Milliseconds(), res.Metadata["control_ms"])
	assert.Equal(t, control.median.Milliseconds(), res.Metadata["control_median_ms"])
	assert.Equal(t, controlSamples, res.Metadata["control_samples"])

	// The differential the finding rests on must be legible in the evidence,
	// not merely asserted.
	extracted := strings.Join(res.ExtractedResults, "\n")
	assert.Contains(t, extracted, "well-formed control")
	assert.Contains(t, extracted, "Differential:")
}

// TestControlProbe_IsUnambiguous verifies the control is an unambiguous, well-formed
// POST: no Transfer-Encoding and a Content-Length that matches its body, so it
// can never trigger a CL/TE desync.
func TestControlProbe_IsUnambiguous(t *testing.T) {
	ctx, err := httpmsg.ParseRawRequest(
		"GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n")
	require.NoError(t, err)

	raw, ok := buildRequest(ctx, controlProbe)
	require.True(t, ok)

	out := string(raw)
	assert.True(t, strings.HasPrefix(out, "POST "), "control must be a POST")
	assert.NotContains(t, strings.ToLower(out), "transfer-encoding:",
		"control must drop Transfer-Encoding to avoid any framing ambiguity")
	assert.Contains(t, strings.ToLower(out), "content-length: 1",
		"control body length must match its Content-Length")
	assert.True(t, strings.HasSuffix(out, "1"), "control must carry the well-formed body")
}

// TestControlMatchesProbeShape checks the two are comparable: same method, same
// request target, same non-framing headers. If they differed in anything but
// framing, the timing difference would not isolate framing.
func TestControlMatchesProbeShape(t *testing.T) {
	ctx, err := httpmsg.ParseRawRequest(
		"GET /api/v1/thing?a=1 HTTP/1.1\r\nHost: example.com\r\nCookie: s=1\r\nAccept: */*\r\n\r\n")
	require.NoError(t, err)

	probeRaw, ok := buildRequest(ctx, probes[0])
	require.True(t, ok)
	controlRaw, ok := buildRequest(ctx, controlProbe)
	require.True(t, ok)

	probeLine := strings.SplitN(string(probeRaw), "\r\n", 2)[0]
	controlLine := strings.SplitN(string(controlRaw), "\r\n", 2)[0]
	assert.Equal(t, probeLine, controlLine,
		"probe and control must address the same resource with the same method")

	for _, h := range []string{"Host: example.com", "Cookie: s=1", "Accept: */*"} {
		assert.Contains(t, string(probeRaw), h)
		assert.Contains(t, string(controlRaw), h)
	}
}
