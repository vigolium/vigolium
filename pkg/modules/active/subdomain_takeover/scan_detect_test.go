package subdomain_takeover

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// fakeCNAME is an injectable CNAME resolver for deterministic DNS-gate tests.
type fakeCNAME struct {
	cname string
	err   error
}

func (f fakeCNAME) LookupCNAME(string) (string, error) { return f.cname, f.err }

// The real DNS/CNAME resolution that picks a candidate host is out of scope for
// a loopback test, but ScanPerHost re-fetches GET / and matches the response
// body/status against the deprovisioned-service fingerprint table — that
// detection logic is fully drivable against an httptest server.

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// TestCanProcess requires a captured response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))
	assert.False(t, m.CanProcess(modtest.Request(t, "http://127.0.0.1/")))
	withResp := modtest.Response(modtest.Request(t, "http://127.0.0.1/"), "text/html", "x")
	assert.True(t, m.CanProcess(withResp))
}

// TestScanPerHost_DetectsHerokuCandidate drives the real scan method against a
// server returning Heroku's "No such app" page with a 404. The provider-bound
// CNAME and replayed fingerprint establish a candidate, not actual claimability.
func TestScanPerHost_DetectsHerokuCandidate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>No such app</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	m := New()
	m.resolver = fakeCNAME{cname: "vigolium-test.herokuapp.com."} // dangling CNAME → Heroku

	res, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a dangling-subdomain candidate when the CNAME points at the deprovisioned Heroku app")
	assert.Equal(t, "Dangling Subdomain Candidate: Heroku", res[0].Info.Name)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, res[0].EvidenceGrade)
	assert.False(t, res[0].IsFinding(), "provider fingerprinting alone must not claim takeover")
}

// TestScanPerHost_CNAMEMismatchNoFinding ensures the Heroku "No such app"
// fingerprint is NOT reported when the host's CNAME does not point at Heroku —
// the marker is then a coincidental/offline-service match, not a takeover.
func TestScanPerHost_CNAMEMismatchNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>No such app</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	m := New()
	m.resolver = fakeCNAME{cname: "origin.example.com."} // not Heroku

	res, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a Heroku fingerprint without a Heroku CNAME must not be reported")
}

// TestScanPerHost_DNSInconclusiveIsObservation preserves the useful HTTP
// fingerprint while preventing a transient DNS failure from becoming a finding.
func TestScanPerHost_DNSInconclusiveIsObservation(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>No such app</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	m := New()
	m.resolver = fakeCNAME{err: fmt.Errorf("dns timeout")} // inconclusive

	res, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an inconclusive DNS error should retain the security observation")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeObservation, res[0].EvidenceGrade)
	assert.False(t, res[0].IsFinding())
	assert.Equal(t, false, res[0].Metadata["dns_conclusive"])
}

func TestCNAMEPatternRequiresDomainBoundary(t *testing.T) {
	t.Parallel()
	assert.True(t, cnameMatchesPattern("vigolium-test.herokuapp.com", "herokuapp.com"))
	assert.False(t, cnameMatchesPattern("vigolium-test.herokuapp.com.evil.example", "herokuapp.com"))
	assert.False(t, cnameMatchesPattern("evilherokuapp.com", "herokuapp.com"))
	assert.True(t, cnameMatchesPattern("bucket.s3-website-us-east-1.amazonaws.com", ".s3-website"))
	assert.False(t, cnameMatchesPattern("bucket.s3-website.evil.example", ".s3-website"))
}

// TestScanPerHost_StatusMismatchNoFinding ensures a body marker that requires a
// specific status code does not fire when the status differs. GitHub Pages
// requires a 404; here the marker appears under a 200.
func TestScanPerHost_StatusMismatchNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// GitHub Pages marker, but served with 200 instead of the required 404.
		_, _ = w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "fingerprint with status-code mismatch must not fire")
}

// TestScanPerHost_NoFalsePositive ensures a healthy page yields no finding.
func TestScanPerHost_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Welcome, this site is live.</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a live site must not yield a takeover finding")
}

// TestTruncate caps over-long bodies and leaves short ones intact.
func TestTruncate(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "abc", truncate("abc", 5))
	assert.Equal(t, "abcde...", truncate("abcdefghij", 5))
}
