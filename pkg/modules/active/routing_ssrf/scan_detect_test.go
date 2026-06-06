package routing_ssrf

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

func absoluteForm(requestURI string) bool {
	return strings.HasPrefix(requestURI, "http://") || strings.HasPrefix(requestURI, "https://")
}

// TestRoutingSSRF_Positive: a proxy that, when the request line names the AWS
// metadata host, fetches it and returns its content. The module must connect to
// the victim, write the absolute-form target, see the ami-id marker, confirm it,
// and report exactly one High finding.
func TestRoutingSSRF_Positive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "169.254.169.254") {
			_, _ = io.WriteString(w, "ami-id: ami-0abc123\ninstance-id: i-0deadbeef\nlocal-hostname: ip-10-0-0-5\n")
			return
		}
		_, _ = io.WriteString(w, "<html><body>normal application page</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	got := res[0]
	if !strings.Contains(strings.ToLower(strings.Join(got.ExtractedResults, " ")), "ami-id") {
		t.Errorf("finding should record the ami-id marker, got %v", got.ExtractedResults)
	}
	if got.Info.Severity.String() == "" || got.Info.Confidence.String() == "" {
		t.Errorf("finding missing severity/confidence: %+v", got.Info)
	}
}

// TestRoutingSSRF_Negative: a plain proxy that ignores the absolute-form target
// and always serves the same page. No marker ever appears → no finding.
func TestRoutingSSRF_Negative(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html><body>normal application page</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no findings for a non-routing proxy, got %d: %+v", len(res), res)
	}
}

// TestRoutingSSRF_DecoyGate: a catch-all that returns the metadata marker for ANY
// absolute-form target (but not for the origin-form baseline). The marker looks
// "fresh" vs the baseline, so the decoy-negative control is what must suppress it:
// the benign TEST-NET decoy also yields the marker, proving a canned page rather
// than a reached endpoint. The module must NOT report.
func TestRoutingSSRF_DecoyGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if absoluteForm(r.RequestURI) {
			_, _ = io.WriteString(w, "ami-id: canned-for-every-absolute-target\n")
			return
		}
		_, _ = io.WriteString(w, "<html><body>normal application page</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/index")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("ScanPerRequest: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("decoy-negative gate must suppress a catch-all marker, got %d findings: %+v", len(res), res)
	}
}
