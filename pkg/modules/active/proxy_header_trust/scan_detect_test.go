package proxy_header_trust

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestCanProcess gates on the presence of a captured response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://127.0.0.1/")
	assert.False(t, m.CanProcess(rr), "no response attached → not processable")

	withResp := modtest.Response(rr, "text/html", "ok")
	assert.True(t, m.CanProcess(withResp))
}

// TestScanPerRequest_DetectsForwardedHostReflection drives the real scan method
// against a server that reflects X-Forwarded-Host into the response body — the
// classic host-injection sink the module probes with its sentinel host.
func TestScanPerRequest_DetectsForwardedHostReflection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		_, _ = fmt.Fprintf(w, "<html><body>link: https://%s/x</body></html>", xfh)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when X-Forwarded-Host is reflected")

	var found bool
	for _, r := range res {
		if r.Info.Name == "Proxy Header Trust: X-Forwarded-Host Injection" {
			found = true
		}
	}
	assert.True(t, found, "expected the X-Forwarded-Host injection finding")
}

// TestScanPerRequest_DetectsForwardedProtoChange drives the X-Forwarded-Proto
// branch: the server changes its response status when the spoofed proto header
// is present, which the module observes as a behavioral change versus the plain
// baseline (a non-access-denied status, so not attributed to a WAF).
func TestScanPerRequest_DetectsForwardedProtoChange(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			w.WriteHeader(http.StatusTeapot) // 418: distinct, not access-denied
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	var found bool
	for _, r := range res {
		if r.Info.Name == "Proxy Header Trust: X-Forwarded-Proto Confusion" {
			found = true
		}
	}
	assert.True(t, found, "expected an X-Forwarded-Proto confusion finding")
}

// TestScanPerRequest_NoFalsePositive ensures a static server that ignores every
// forwarding header — and returns a stable status/body — yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>static, no header trust</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that ignores forwarding headers must not yield a finding")
}

// TestScanPerRequest_ForwardedForJitterNoFalsePositive reproduces the reported
// false positive: a server that ignores forwarding headers but whose body grows
// on every request (e.g. rotating tokens, view counts, ads). The old one-shot
// baseline-vs-probe size delta tripped on this benign jitter and reported a High
// "IP Bypass". The variance-control + reproducibility gate must now suppress it,
// because the spoofed-IP probes land inside the same size band as the no-header
// fetches.
func TestScanPerRequest_ForwardedForJitterNoFalsePositive(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Body length grows with every request, independent of any header — pure
		// per-request variance. The delta easily exceeds the old 50-byte / 30% gate.
		c := atomic.AddInt64(&n, 1)
		_, _ = w.Write([]byte(strings.Repeat("A", 200+int(c)*200)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "natural per-request size jitter must not be reported as an X-Forwarded-For issue")
}

// TestScanPerRequest_ForwardedForTransientBlockNoFalsePositive reproduces the
// reported "IP Bypass" false positive: the scan hammered the host into a 429, so
// the single captured baseline was rate-limited, but the limit cleared by the
// time the probes ran. The old code read the 429→200 status flap as an
// X-Forwarded-For access-control bypass even though the header did nothing. The
// reproducible, interleaved confirmation must suppress it — the no-header control
// comes back 200, proving the block was transient, not header-attributable. (It
// must also not fire the X-Forwarded-Proto branch on the same 429→200 flap.)
func TestScanPerRequest_ForwardedForTransientBlockNoFalsePositive(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Only the very first request (the captured baseline) is rate-limited;
		// every later request — with or without forwarding headers — is allowed.
		if atomic.AddInt64(&n, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("welcome"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a transient rate-limited baseline that clears must not be reported as an X-Forwarded-* bypass")
}

// TestScanPerRequest_ForwardedForReproducibleBypass is the positive counterpart
// for the access-control branch: a server that reliably denies (403) requests
// without a trusted source IP and allows (200) those carrying the spoofed
// X-Forwarded-For. The split is reproducible and header-attributable, so it must
// surface as the High X-Forwarded-For IP Bypass finding.
func TestScanPerRequest_ForwardedForReproducibleBypass(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			_, _ = w.Write([]byte("admin ok"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)

	var got *string
	for _, r := range res {
		if r.Info.Name == "Proxy Header Trust: X-Forwarded-For IP Bypass" {
			name := r.Info.Severity.String() + "/" + r.Info.Confidence.String()
			got = &name
		}
	}
	require.NotNil(t, got, "expected an IP Bypass finding when a spoofed X-Forwarded-For reproducibly flips 403→200")
	assert.Equal(t, "high/firm", *got, "a reproducible access-control bypass must be High/Firm")
}

// TestScanPerRequest_ForwardedForContentVariation is the positive counterpart: a
// server that consistently serves much larger content when it trusts the spoofed
// X-Forwarded-For source IP. The shift is reproducible and far outside the page's
// (zero) natural variance, so it must surface — as the accurately-scoped
// Medium/Tentative "Content Variation" finding, not a High bypass claim.
func TestScanPerRequest_ForwardedForContentVariation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			_, _ = w.Write([]byte(strings.Repeat("INTERNAL", 200))) // 1600 bytes
			return
		}
		_, _ = w.Write([]byte("public"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)

	var got *string
	for _, r := range res {
		if r.Info.Name == "Proxy Header Trust: X-Forwarded-For Content Variation" {
			name := r.Info.Severity.String() + "/" + r.Info.Confidence.String()
			got = &name
		}
	}
	require.NotNil(t, got, "expected a Content Variation finding when content reproducibly tracks the spoofed IP")
	assert.Equal(t, "medium/tentative", *got, "size-based content variation must be Medium/Tentative, not a High bypass")
}

// TestScanPerRequest_ForwardedHostStaticSentinelNoFalsePositive reproduces a
// single-echo / coincidental-string false positive: the body always contains the
// fixed sentinel host string but never reflects the actual X-Forwarded-Host. The
// fresh-canary confirmation must drop it (the canary never appears).
func TestScanPerRequest_ForwardedHostStaticSentinelNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Hardcoded mention of the sentinel host, independent of any header.
		_, _ = fmt.Fprintf(w, "<html><body>contact %s for support</body></html>", injectedHost)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "Proxy Header Trust: X-Forwarded-Host Injection", r.Info.Name,
			"a fixed sentinel string that does not track the fresh canary must not be reported")
	}
}

// TestScanPerRequest_ForwardedProtoTransientNoFalsePositive reproduces a transient
// X-Forwarded-Proto status flip: only the FIRST https probe returns 418, then it
// reverts to 200. The reproducibility gate must drop it.
func TestScanPerRequest_ForwardedProtoTransientNoFalsePositive(t *testing.T) {
	t.Parallel()
	var httpsSeen int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			if atomic.AddInt64(&httpsSeen, 1) == 1 {
				w.WriteHeader(http.StatusTeapot) // one-shot flip
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "Proxy Header Trust: X-Forwarded-Proto Confusion", r.Info.Name,
			"a one-shot X-Forwarded-Proto status flip must not be reported")
	}
}

// TestScanPerRequest_AttachesBaselineEvidence asserts the differential evidence is
// preserved: a confirmed finding carries the no-header baseline request/response as
// a labeled AdditionalEvidence pair (while the spoofed-header probe stays the
// primary pair), rather than discarding the comparison side that proves the bug.
func TestScanPerRequest_AttachesBaselineEvidence(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		_, _ = fmt.Fprintf(w, "<html><body>link: https://%s/x</body></html>", xfh)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)

	var finding *output.ResultEvent
	for _, r := range res {
		if r.Info.Name == "Proxy Header Trust: X-Forwarded-Host Injection" {
			finding = r
		}
	}
	require.NotNil(t, finding, "expected the X-Forwarded-Host injection finding")
	require.NotEmpty(t, finding.AdditionalEvidence, "finding must carry the baseline comparison as evidence")

	var hasBaseline bool
	for _, ev := range finding.AdditionalEvidence {
		if strings.HasPrefix(ev, "# [baseline]\n") {
			hasBaseline = true
			assert.Contains(t, ev, output.EvidenceSeparator, "an evidence entry must be a request/response pair")
		}
	}
	assert.True(t, hasBaseline, "expected a labeled baseline evidence pair")
	// The attack pair stays primary and distinct from the baseline.
	assert.Contains(t, finding.Request, "X-Forwarded-Host", "primary request should be the spoofed-header probe")
}

// TestScanPerRequest_ForwardedProtoAttachesNegativeControl asserts the proto
// finding carries both comparison axes: the no-header baseline AND the benign
// "http" negative control that proves the change is specific to the "https"
// value, rather than discarding the value-attribution side of the proof. The
// server stably returns 418 only for X-Forwarded-Proto: https (200 otherwise),
// so the change is reproducible and http-attributable.
func TestScanPerRequest_ForwardedProtoAttachesNegativeControl(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") == "https" {
			w.WriteHeader(http.StatusTeapot) // stable, https-specific flip
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)

	var finding *output.ResultEvent
	for _, r := range res {
		if r.Info.Name == "Proxy Header Trust: X-Forwarded-Proto Confusion" {
			finding = r
		}
	}
	require.NotNil(t, finding, "expected the X-Forwarded-Proto confusion finding")
	require.NotEmpty(t, finding.AdditionalEvidence, "finding must carry evidence")

	joined := strings.Join(finding.AdditionalEvidence, "\n")
	assert.Contains(t, joined, "# [baseline", "the no-header baseline comparison pair must still be attached")
	assert.Contains(t, joined, "# [negative control", "the benign 'http' negative-control pair must be attached")
}
