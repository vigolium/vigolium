package path_normalization

import (
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
