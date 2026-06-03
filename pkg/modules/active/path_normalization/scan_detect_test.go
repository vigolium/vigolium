package path_normalization

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
