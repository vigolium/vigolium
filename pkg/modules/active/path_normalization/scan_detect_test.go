package path_normalization

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
)

// normalizationHandler simulates a reverse-proxy / backend path-normalization
// inconsistency for the "..;/" payload. The module probes a fuzzed path
// (base + "..;/"*i) expecting status 400, then the backed-off path
// (base + "..;/"*(i-1)) expecting an "internal" status with a fingerprint that
// differs from the baseline, root, and non-existent reference responses.
//
// We model that as: a path carrying an EVEN number of "..;/" segments is
// rejected (400, the public/proxy view), while an ODD number normalizes through
// to a distinct internal resource (200 with a unique body). Every other path —
// the baseline, root, and the non-existent probe — returns a uniform 404 page,
// so the internal 200 fingerprint is clearly anomalous.
//
// Crucially, the internal resource is reached ONLY for traversal that lands in the
// real "/app/" directory tree; a traversal from a nonexistent sibling directory
// 404s. This is the realistic shape (the reached resource depends on which real
// ancestor the traversal collapses into) and distinguishes a genuine bypass from a
// host that serves ONE generic body for any traversal shape regardless of base —
// the latter is a false positive, exercised separately below.
func normalizationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RequestURI()
		n := strings.Count(raw, "..;/")
		switch {
		case n == 0:
			// Baseline / root / non-existent probes.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><head><title>Not Found</title></head><body>404</body></html>"))
		case n%2 == 0:
			// Even repetitions: rejected by the proxy (public view).
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("<html><head><title>Bad Request</title></head><body>400</body></html>"))
		case !strings.HasPrefix(raw, "/app/"):
			// Odd repetitions from a base outside the real "/app/" tree reach no
			// resource — the reached resource is ancestor-specific, not a generic
			// body served for the traversal shape.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><head><title>Not Found</title></head><body>404</body></html>"))
		default:
			// Odd repetitions within the real tree normalize through to an internal
			// resource with a distinctive body/title so its fingerprint diverges
			// from the refs.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><head><title>Internal Admin Console</title></head><body>" +
				"secret internal dashboard with privileged operations and many distinct words here " +
				"to ensure the fingerprint diverges from the uniform not-found page used elsewhere" +
				"</body></html>"))
		}
	}
}

// TestScanPerRequest_DetectsNormalization drives the real scan method against a
// host whose proxy/backend disagree on path normalization for "..;/" and
// asserts the module reports a finding.
func TestScanPerRequest_DetectsNormalization(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(normalizationHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/page")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a path-normalization finding when the backed-off path reaches an anomalous internal resource")
	assert.Equal(t, ModuleID, res[0].ModuleID)
}

// hardenedHandler models a hardened identity/CIAM-style host: an over-traversed
// path (2+ traversal segments) is rejected with 400, while a backed-off path
// (a single traversal segment) returns an error status (403/404/500) with a
// distinctive error page — exactly the shape that produced the reported false
// positive (`/newpassword..%2f..%2f..%2f` -> 400, backed-off -> 403). No path
// normalization actually occurs; the host simply returns 400 for malformed
// paths and a default-deny/error page otherwise.
func hardenedHandler(internalStatus int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := strings.Count(r.URL.RequestURI(), "..")
		switch {
		case n >= 2:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("<html><head><title>Bad Request</title></head><body>400 malformed path</body></html>"))
		case n == 1:
			// Distinctive error page so it differs from the baseline/root/
			// non-existent reference fingerprints — the only thing that kept the
			// old oracle from filtering it.
			w.WriteHeader(internalStatus)
			_, _ = w.Write([]byte("<html><head><title>Forbidden</title></head><body>access denied to this protected resource</body></html>"))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><title>Login</title></head><body>welcome to the identity portal</body></html>"))
		}
	}
}

// TestScanPerRequest_NoFalsePositiveOnHardenedErrorStatuses is the regression
// guard for the reported path-normalization false positive: a host that answers
// over-traversal with 400 and backed-off traversal with a generic error status
// (403/404/500) must NOT be flagged, because an error response is not a reached
// internal resource. Before the fix every one of these would have been reported.
func TestScanPerRequest_NoFalsePositiveOnHardenedErrorStatuses(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		status := status
		t.Run(fmt.Sprintf("backed_off_%d", status), func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(hardenedHandler(status))
			defer srv.Close()

			client := modtest.Requester(t)
			rr := modtest.Request(t, srv.URL+"/newpassword")

			res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
			require.NoError(t, err)
			assert.Emptyf(t, res, "a hardened host returning %d for backed-off traversal paths must not be flagged", status)
		})
	}
}

// differentialHandler models the "both 200 but materially different" oracle: the
// clean path and the root/non-existent probes return a small public page, an
// over-traversed path (2+ "..;/" segments) is rejected with 400, and a single
// "..;/" segment normalizes through to a large, distinctly different internal
// resource. This is the canonical proxy/backend disagreement the module reports.
func differentialHandler() http.HandlerFunc {
	internal := "INTERNAL ADMIN DASHBOARD " + strings.Repeat("privileged-internal-operation ", 80)
	public := "<html><body>public landing page</body></html>"
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RequestURI()
		switch strings.Count(raw, "..;/") {
		case 0:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(public))
		case 1:
			// The internal resource is reached only when the traversal lands in the
			// real "/app/" tree; a traversal from a nonexistent sibling directory
			// returns the ordinary public page (not the internal resource), so the
			// finding tracks an ancestor-specific resource rather than a generic body
			// served for any traversal shape.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			if strings.HasPrefix(raw, "/app/") {
				_, _ = w.Write([]byte(internal))
			} else {
				_, _ = w.Write([]byte(public))
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
		}
	}
}

// TestScanPerRequest_DetectsDifferentialContent asserts the differential oracle:
// when the clean path and the traversal-bearing path both return 200 but the
// traversal response is a materially different resource, the module flags it.
func TestScanPerRequest_DetectsDifferentialContent(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(differentialHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/resource")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when a backed-off traversal path reaches a 200 resource that differs substantially from the clean baseline")
	assert.Equal(t, ModuleID, res[0].ModuleID)
	assert.NotEmpty(t, res[0].AdditionalEvidence, "finding must carry baseline/over-traversal/confirmation evidence")
}

// binaryCDNHandler reproduces the reported false positive: an Adobe-Scene7 /
// Akamai-style image CDN. The clean image path (and a single normalized segment)
// return 200 image/webp with per-request varying bytes (smart-imaging + cache
// variants), while an over-traversed path is rejected with 400. No path
// normalization bug exists — the CDN simply rejects malformed suffixes and serves
// images whose bytes are not byte-stable between requests.
func binaryCDNHandler() http.HandlerFunc {
	var seq int32
	return func(w http.ResponseWriter, r *http.Request) {
		n := strings.Count(r.URL.RequestURI(), "..;/")
		if n >= 2 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
			return
		}
		// n == 0 (clean/root/non-existent) and n == 1 (one normalized segment)
		// both serve an image with per-request varying bytes.
		v := atomic.AddInt32(&seq, 1)
		w.Header().Set("Content-Type", "image/webp")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("RIFF" + strings.Repeat("x", 200+int(v)*37) + "WEBP"))
	}
}

// TestScanPerRequest_NoFalsePositiveOnBinaryCDNAsset is the regression guard for
// the reported false positive (media-assets.globex.com): a binary image CDN with
// a query string on the URL and per-request varying bytes must NOT be flagged.
// The backed-off traversal path returns a 200 image/webp, but image/binary
// content is excluded from the status oracle (it is the static-root oracle's
// domain), and the per-request byte variance must not be mistaken for a divergent
// internal resource.
func TestScanPerRequest_NoFalsePositiveOnBinaryCDNAsset(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(binaryCDNHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	// Query string present, mirroring a real Scene7 image request.
	rr := modtest.Request(t, srv.URL+"/is/image/globex/visualization?wid=800&fmt=webp")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a binary image CDN with varying bytes must not be flagged as a path-normalization bypass")
}

// TestScanPerRequest_NoFalsePositiveDegenerateBackoff guards the other root cause:
// a host that rejects any traversal suffix with 400 and serves the clean path with
// 200 (the normal behaviour of almost every server) must NOT be flagged. The old
// oracle reported this via the degenerate i=1 case (backed-off path == the clean
// original URL); starting at i=2 removes it.
func TestScanPerRequest_NoFalsePositiveDegenerateBackoff(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any path carrying a traversal token is rejected; the clean path is served.
		raw := strings.ToLower(r.URL.RequestURI())
		if strings.Contains(raw, "..") || strings.Contains(raw, "%2e") ||
			strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>the canonical resource served cleanly</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/is/image/globex/visualization?wid=800")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "rejecting traversal suffixes with 400 while serving the clean path with 200 is not a bypass")
}

// rateLimitedBaselineHandler reproduces the reported false positive
// (biz-portal.initech.com.sg): a Webflow-style CDN where an upward `..//`
// traversal normalizes to the public homepage, the over-traversed path
// overshoots the root and is rejected (400), and the clean path / root / a
// non-existent sibling are all transiently RATE-LIMITED (429) during the scan.
// The old accessUnlock oracle read "clean path 429 (not 2xx) / traversal 200" as
// "the traversal unlocked access", reporting High. A 429 is a transient rate
// limit, not an access-control denial, so no bypass exists.
func rateLimitedBaselineHandler() http.HandlerFunc {
	home := "<html><body>" + strings.Repeat("public homepage marketing content here ", 60) + "</body></html>"
	return func(w http.ResponseWriter, r *http.Request) {
		switch n := strings.Count(r.URL.RequestURI(), "..//"); {
		case n >= 2:
			// Over-traversed: overshoots the root, rejected as malformed.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
		case n == 1:
			// Backed-off traversal normalizes to the public homepage.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(home))
		default:
			// Clean path, root, and non-existent probes are all rate-limited.
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("429 too many requests"))
		}
	}
}

// TestScanPerRequest_NoFalsePositiveRateLimitedBaseline is the regression guard
// for the rate-limited accessUnlock false positive: a clean path that returns
// 429 must NOT be read as "access denied" so that a backed-off traversal
// reaching 200 is reported as an unlock. A 429 is transient infrastructure, not
// a stable access-control decision.
func TestScanPerRequest_NoFalsePositiveRateLimitedBaseline(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(rateLimitedBaselineHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/cny2025-terms")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a rate-limited (429) clean path must not be read as an access-control denial that the traversal unlocked")
}

// cloudFrontBlockedBaselineHandler is normalizationHandler with ONE change: the
// clean protected path is blocked by a CloudFront WAF rule (Server: CloudFront,
// "Request blocked") instead of a plain 404. An odd-repetition traversal within
// the real tree still normalizes through to a distinct internal 200 resource — a
// path shape that evades the edge rule. Without the edge-block gate this reads as
// accessUnlock (403 baseline → 200 backed-off, exactly like the detected positive
// case), but the "forbidden" side is edge mitigation, not app access control.
func cloudFrontBlockedBaselineHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RequestURI()
		n := strings.Count(raw, "..;/")
		switch {
		case n == 0 && r.URL.Path == "/app/page":
			// CloudFront WAF deterministically blocks the literal protected path.
			w.Header().Set("Server", "CloudFront")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html><body><H1>403 ERROR</H1>Request blocked. Generated by cloudfront (CloudFront)</body></html>"))
		case n == 0:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><head><title>Not Found</title></head><body>404</body></html>"))
		case n%2 == 0:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("<html><head><title>Bad Request</title></head><body>400</body></html>"))
		case !strings.HasPrefix(raw, "/app/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><head><title>Not Found</title></head><body>404</body></html>"))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><head><title>Internal Admin Console</title></head><body>" +
				"secret internal dashboard with privileged operations and many distinct words here " +
				"to ensure the fingerprint diverges from the uniform not-found page used elsewhere" +
				"</body></html>"))
		}
	}
}

// TestScanPerRequest_NoFalsePositiveCloudFrontBlockedBaseline is the regression
// guard for the WAF-block-baseline false positive: a clean path blocked by a
// CloudFront edge rule (a vendor block, not an app 401/403) must NOT be read as an
// access-control denial that a traversal shape "unlocked" when that shape merely
// evaded the edge rule. Same server as TestScanPerRequest_DetectsNormalization
// (which reports), the only difference being the vendor edge-block baseline.
func TestScanPerRequest_NoFalsePositiveCloudFrontBlockedBaseline(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(cloudFrontBlockedBaselineHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/page")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a CloudFront/WAF edge-block baseline must not be reported as a path-normalization access unlock")
}

// resolvesToRootHandler reproduces the differential variant of the same false
// positive, where the clean baseline is a real 200 page but the upward `..//`
// traversal normalizes to the public homepage (a materially different body, so
// the differential oracle fires) and the ROOT reference probe is transiently
// rate-limited on its FIRST fetch — poisoning the catch-all guard's stored root
// signature exactly as observed in the field. A subsequent (fresh) root fetch
// returns the homepage, so the backed-off resource is provably just the public
// root. No bypass exists.
func resolvesToRootHandler() http.HandlerFunc {
	home := "<html><body>" + strings.Repeat("public homepage marketing content here ", 60) + "</body></html>"
	contact := "<html><body>" + strings.Repeat("contact us form distinct page ", 60) + "</body></html>"
	var rootHits int32
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RequestURI()
		switch n := strings.Count(raw, "..//"); {
		case n >= 2:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
		case n == 1:
			// Backed-off traversal normalizes to the public homepage.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(home))
		case raw == "/":
			// Root: rate-limited on the first probe (poisons the stored
			// reference), then serves the homepage on the fresh re-fetch.
			if atomic.AddInt32(&rootHits, 1) == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte("429 too many requests"))
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(home))
		case strings.Contains(raw, "nonexistent"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>404 not found</body></html>"))
		default:
			// The clean baseline is a real, distinct 200 page.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(contact))
		}
	}
}

// TestScanPerRequest_NoFalsePositiveResolvesToRoot is the regression guard for
// the differential/catch-all variant: even when the initial root reference is
// poisoned by a transient 429, the fresh root re-fetch must recognise the
// backed-off resource as the public homepage and drop the finding.
func TestScanPerRequest_NoFalsePositiveResolvesToRoot(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(resolvesToRootHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/contact")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an upward traversal that normalizes to the public homepage must not be reported, even when the initial root reference was rate-limited")
}

// traversalShapeCatchAllHandler reproduces the reported false positive
// (dialog1.acme.com, a Salesforce Lightning site behind a reverse proxy). An
// upward `..%2f` traversal with no target suffix collapses to the site root, but
// the proxy sees the raw traversal-shaped path and renders a GENERIC error page
// ("This feature is not available in your country") for it — a body that is
// BYTE-IDENTICAL for every base segment (`/111213..%2f..%2f`,
// `/auraCmpDef..%2f..%2f`, `/DLG_Access_Login..%2f..%2f` all returned the same
// 1365-byte page in the field). Meanwhile the clean base path serves a large,
// distinct resource and the clean site root serves the real homepage, so the
// clean-root reference guards never match the error page. No resource the clean
// URL could not otherwise reach is exposed — the "reached resource" is the host's
// generic reaction to the traversal shape.
func traversalShapeCatchAllHandler() http.HandlerFunc {
	// Base-INDEPENDENT generic error page served for any collapsed traversal.
	errPage := "<html><head><title>Welcome</title></head><body>" +
		"<span class=\"error-msg-box\">This feature is not available in your country.</span>" +
		"</body></html>"
	homepage := "<html><body>" + strings.Repeat("real public homepage content here ", 40) + "</body></html>"
	cleanResource := "<html><body>" + strings.Repeat("large distinct aura component definition payload ", 200) + "</body></html>"
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RequestURI()
		switch k := strings.Count(raw, "..%2f"); {
		case k >= 3:
			// Over-traversed: overshoots the root, rejected as malformed.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
		case k == 2:
			// Backed-off traversal collapses to root; the proxy renders a generic
			// error page for the traversal-shaped path — identical for any base.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(errPage))
		case k == 1:
			// A single `..%2f` leaves a literal weird segment that maps to nothing.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>404 not found</body></html>"))
		case raw == "/":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(homepage))
		case raw == "/auraCmpDef":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(cleanResource))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>404 not found</body></html>"))
		}
	}
}

// TestScanPerRequest_NoFalsePositiveTraversalShapeCatchAll is the regression guard
// for the reported dialog1.acme.com false positives: a host that serves ONE
// generic error page for any collapsed upward traversal (identical regardless of
// base segment) must NOT be flagged, even though the clean base resource and the
// clean site root are both distinct 2xx pages that defeat the clean-path reference
// guards. Only the same-depth random-base collapse control recognises that the
// "reached resource" is independent of the leading segments. This finding was
// emitted before the fix; it must be empty after.
func TestScanPerRequest_NoFalsePositiveTraversalShapeCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(traversalShapeCatchAllHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/auraCmpDef")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host serving one base-independent generic error page for any collapsed traversal must not be flagged as a path-normalization bypass")
}

// TestScanPerRequest_NoFalsePositive ensures a host that returns a uniform
// response for every path (no normalization divergence) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Identical response for every path: nothing diverges, nothing flips to 400.
		_, _ = w.Write([]byte("<html><head><title>App</title></head><body>welcome</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/page")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with uniform responses must not yield a path-normalization finding")
}
