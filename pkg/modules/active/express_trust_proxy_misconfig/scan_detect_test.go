package express_trust_proxy_misconfig

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestScanPerRequest_DetectsHostInjection reflects the X-Forwarded-Host header
// into the response body, which the module treats as a trust-proxy
// misconfiguration (host taken from a client-controlled header).
func TestScanPerRequest_DetectsHostInjection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the X-Forwarded-Host into a generated absolute URL.
		xfh := r.Header.Get("X-Forwarded-Host")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<a href=\"https://" + xfh + "/reset\">link</a>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when X-Forwarded-Host is reflected into the body")
}

// TestScanPerRequest_NoFalsePositive serves a fixed body that never reflects any
// injected proxy header, so no probe should fire.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>static content with no reflection</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a response that ignores forwarded headers must not yield a finding")
}

// TestScanPerRequest_TransientBlockNoFalsePositive reproduces the reported IP
// bypass false positive: the scan hammered the host into a 429/403 on the
// captured baseline, but the limit cleared by the time the probes ran. A bare
// 403→200 status flap must not be reported as an X-Forwarded-For bypass.
func TestScanPerRequest_TransientBlockNoFalsePositive(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Only the first request (the captured baseline) is blocked; everything
		// after — with or without forwarding headers — is allowed, and never
		// reflects an injected host/port.
		if atomic.AddInt64(&n, 1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("<html><body>welcome, no reflection here</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a transient blocked baseline that clears must not be reported as an X-Forwarded-* bypass")
}

// TestScanPerRequest_ReproducibleIPBypass is the positive counterpart: the server
// reliably denies (403) requests without a trusted source IP and allows (200)
// those carrying the spoofed X-Forwarded-For. The split is reproducible and
// header-attributable, so it must surface.
func TestScanPerRequest_ReproducibleIPBypass(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			_, _ = w.Write([]byte("<html><body>internal admin ok</body></html>"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a reproducible 403→200 X-Forwarded-For bypass must be reported")
	assert.Contains(t, res[0].Info.Name, "X-Forwarded-For")
}

// TestScanPerRequest_IPSizeJitterNoFalsePositive reproduces the body-size FP: the
// server ignores forwarding headers but its body grows every request (dynamic
// content). The variance-control + reproducibility gate must keep silent.
func TestScanPerRequest_IPSizeJitterNoFalsePositive(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c := atomic.AddInt64(&n, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>" + strings.Repeat("A", 200+int(c)*200) + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "natural per-request body growth must not be reported as an X-Forwarded-For size change")
}

// TestScanPerRequest_DetectsPortReflection echoes X-Forwarded-Port into a
// generated URL. The port is absent from the no-header baseline and reflects
// reproducibly, so the confirmation gate must keep the finding.
func TestScanPerRequest_DetectsPortReflection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if port := r.Header.Get("X-Forwarded-Port"); port != "" {
			_, _ = w.Write([]byte("<a href=\"https://host:" + port + "/cb\">link</a>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>no port here</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when X-Forwarded-Port is reflected and reproducible")
	assert.Contains(t, res[0].Info.Name, "X-Forwarded-Port")
}

// TestScanPerRequest_NoFalsePositive_PortAlreadyInBaseline reproduces the FP the
// confirmation gate exists to catch: the injected port string appears in EVERY
// response (including the no-header baseline) because it is pre-existing page
// content, not a header reflection. The baseline-absence check must drop it.
func TestScanPerRequest_NoFalsePositive_PortAlreadyInBaseline(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// The ":1337" string is baked into the page regardless of any header.
		_, _ = w.Write([]byte("<a href=\"https://cdn.example:" + injectedPort + "/asset\">static</a>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a port string present in the no-header baseline must not be reported as injection")
}

// TestScanPerRequest_VolatileSecureCookieNoFalsePositive reproduces the reported
// X-Forwarded-Proto false positive (a.pages-perf.example.com behind Cloudflare
// Access): the baseline 302 issues a volatile edge affinity cookie carrying the
// Secure flag, but the proto-downgrade probe response carries NO Set-Cookie at
// all. A cookie that simply vanishes is not a Secure-flag strip, so the old bare
// "Secure present in baseline, absent in probe" substring check must no longer
// fire.
func TestScanPerRequest_VolatileSecureCookieNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Edge-style affinity cookie: issued (with Secure) ONLY when no
		// X-Forwarded-Proto header is present, never re-issued on the probe.
		if r.Header.Get("X-Forwarded-Proto") == "" {
			w.Header().Set("Set-Cookie", "_cfuvid=abc123; HttpOnly; SameSite=None; Secure; Path=/")
		}
		w.WriteHeader(http.StatusFound) // 302, empty body — same with or without the header
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a volatile edge cookie that simply disappears from the probe must not be reported as a Secure-flag strip")
}

// TestScanPerRequest_DetectsGenuineSecureStrip is the positive counterpart: the
// app re-issues the SAME session cookie WITHOUT the Secure flag when it trusts
// X-Forwarded-Proto: http. That is a real downgrade, reproducible across fresh
// samples, so it surfaces — but as Tentative confidence (a behavioural baseline
// diff, the weakest signal class).
func TestScanPerRequest_DetectsGenuineSecureStrip(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") == "http" {
			// Trusts the spoofed proto → drops Secure off the same cookie.
			w.Header().Set("Set-Cookie", "sess=abc; HttpOnly; Path=/")
		} else {
			w.Header().Set("Set-Cookie", "sess=abc; HttpOnly; Secure; Path=/")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>dashboard</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a reproducible Secure-flag strip on a re-issued cookie must be reported")
	assert.Contains(t, res[0].Info.Name, "X-Forwarded-Proto")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence, "proto-downgrade behavioural diffs ship as Tentative")
}

// TestSecureCookieStripped exercises the structural cookie-strip helper directly.
func TestSecureCookieStripped(t *testing.T) {
	t.Parallel()
	// Same cookie re-issued without Secure → genuine strip.
	assert.Equal(t, "sess", secureCookieStripped(
		"Set-Cookie: sess=a; Secure; Path=/\r\n",
		"Set-Cookie: sess=a; Path=/\r\n",
	))
	// Secure cookie vanishes from the probe entirely → NOT a strip (the FP).
	assert.Empty(t, secureCookieStripped(
		"Set-Cookie: _cfuvid=a; HttpOnly; SameSite=None; Secure; Path=/\r\n",
		"Content-Length: 0\r\n",
	))
	// Different cookie issued without Secure, original Secure cookie still present.
	assert.Empty(t, secureCookieStripped(
		"Set-Cookie: sess=a; Secure\r\n",
		"Set-Cookie: sess=a; Secure\r\nSet-Cookie: other=b\r\n",
	))
	// "Secure" only as a substring of a value, never a real directive.
	assert.Empty(t, secureCookieStripped(
		"Set-Cookie: token=Secureish; Path=/\r\n",
		"Set-Cookie: token=Secureish; Path=/\r\n",
	))
}

// TestCheckHostInjection exercises the pure host-reflection helper directly.
func TestCheckHostInjection(t *testing.T) {
	t.Parallel()
	assert.NotEmpty(t, checkHostInjection("<a href=https://"+injectedHost+"/x>", "", ""))
	assert.NotEmpty(t, checkHostInjection("", "", "https://"+injectedHost+"/cb"))
	assert.Empty(t, checkHostInjection("clean body", "clean headers", "/local"))
}

// TestCheckPortInjection exercises the pure port-reflection helper directly.
func TestCheckPortInjection(t *testing.T) {
	t.Parallel()
	assert.NotEmpty(t, checkPortInjection("", "https://host:"+injectedPort+"/cb"))
	assert.NotEmpty(t, checkPortInjection("https://host:"+injectedPort+"/x", ""))
	assert.Empty(t, checkPortInjection("https://host/x", "/local"))
}
