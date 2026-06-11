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
		default:
			// Odd repetitions: normalize through to an internal resource with a
			// distinctive body/title so its fingerprint diverges from the refs.
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
		switch strings.Count(r.URL.RequestURI(), "..;/") {
		case 0:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(public))
		case 1:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(internal))
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
// the reported false positive (media-assets.stryker.com): a binary image CDN with
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
	rr := modtest.Request(t, srv.URL+"/is/image/stryker/visualization?wid=800&fmt=webp")

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
	rr := modtest.Request(t, srv.URL+"/is/image/stryker/visualization?wid=800")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "rejecting traversal suffixes with 400 while serving the clean path with 200 is not a bypass")
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
