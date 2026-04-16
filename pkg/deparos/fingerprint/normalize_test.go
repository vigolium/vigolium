package fingerprint

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

func TestNormalizeBody_StripsFullPath(t *testing.T) {
	u, _ := url.Parse("http://example.com/ftp/api/Challenges/1/rest/user/security-question")
	body := []byte(`<html><body>403 Forbidden: /ftp/api/Challenges/1/rest/user/security-question</body></html>`)

	got := NormalizeBody(body, u)

	if bytes.Contains(got, []byte("/ftp/api/Challenges")) {
		t.Errorf("full path should be stripped, got: %s", got)
	}
	if !bytes.Contains(got, []byte(pathSentinel)) {
		t.Errorf("expected sentinel in output, got: %s", got)
	}
}

func TestNormalizeBody_StripsLongSegments(t *testing.T) {
	// Path containing "Challenges" and "security-question" — segments >= 6 chars.
	u, _ := url.Parse("http://h/api/Challenges/1/security-question")
	// Body echoes segments individually (breadcrumb-style).
	body := []byte(`<html><body>Path: api > Challenges > 1 > security-question</body></html>`)

	got := NormalizeBody(body, u)

	if bytes.Contains(got, []byte("Challenges")) {
		t.Errorf("long segment 'Challenges' should be stripped, got: %s", got)
	}
	if bytes.Contains(got, []byte("security-question")) {
		t.Errorf("long segment 'security-question' should be stripped, got: %s", got)
	}
	// Short segments must NOT be stripped.
	if !bytes.Contains(got, []byte("api")) {
		t.Errorf("short segment 'api' must NOT be stripped, got: %s", got)
	}
}

func TestNormalizeBody_PreservesUnrelatedContent(t *testing.T) {
	u, _ := url.Parse("http://h/products/12345")
	body := []byte(`<html><body><h1>Welcome</h1><p>Our REST API serves users worldwide.</p></body></html>`)

	got := NormalizeBody(body, u)

	// "REST", "API", "users" are short → must survive.
	if string(got) != string(body) {
		t.Errorf("body without path echo should pass through unchanged.\norig: %s\ngot:  %s", body, got)
	}
}

func TestNormalizeBody_NilURLOrEmptyBody(t *testing.T) {
	if got := NormalizeBody([]byte("hello"), nil); string(got) != "hello" {
		t.Errorf("nil URL must pass body through, got: %s", got)
	}
	u, _ := url.Parse("http://h/x")
	if got := NormalizeBody(nil, u); got != nil {
		t.Errorf("nil body must remain nil, got: %v", got)
	}
}

func TestNormalizeBody_QueryValueStripped(t *testing.T) {
	u, _ := url.Parse("http://h/search?q=very-distinctive-query-value")
	body := []byte(`Result for: very-distinctive-query-value (no matches)`)

	got := NormalizeBody(body, u)

	if bytes.Contains(got, []byte("very-distinctive-query-value")) {
		t.Errorf("query value should be stripped, got: %s", got)
	}
}

// TestSampleStable_ReproducesJuiceShopFTPTrap is the regression test for the
// Juice Shop /ftp soft-403 trap. The fake server returns 403 + the requested
// path echoed in the body for any subpath. After normalization the resulting
// fingerprint samples MUST hash to the same BodyContent / VisibleText so the
// learner can build a usable signature.
func TestSampleStable_ReproducesJuiceShopFTPTrap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `<html><body><h1>403 Forbidden</h1><p>You don't have permission to access %s on this server.</p></body></html>`, r.URL.Path)
	}))
	defer srv.Close()

	probePaths := []string{
		"/ftp/api/Challenges/1/rest/user/security-question",
		"/ftp/v3/ip-country/api/Challenges/1/rest/user/login",
		"/ftp/random-different-path/totally-unrelated-segment",
	}

	samples := make([]*Sample, 0, len(probePaths))
	for _, p := range probePaths {
		s := fetchSample(t, srv.URL+p)
		samples = append(samples, s)
	}

	// Status code is always 403 — sanity.
	for i, s := range samples {
		if s.GetHash(StatusCode) != 403 {
			t.Fatalf("sample %d: status hash %d, want 403", i, s.GetHash(StatusCode))
		}
	}

	// After normalization, BodyContent must match across all 3 samples.
	bodyHash := samples[0].GetHash(BodyContent)
	if bodyHash == 0 {
		t.Fatal("expected non-zero BodyContent hash on sample 0")
	}
	for i, s := range samples[1:] {
		if got := s.GetHash(BodyContent); got != bodyHash {
			t.Errorf("sample %d: BodyContent hash %d, want %d (normalization should make hashes match)", i+1, got, bodyHash)
		}
	}

	// Same for VisibleText (HTML attribute).
	textHash := samples[0].GetHash(VisibleText)
	if textHash != 0 {
		for i, s := range samples[1:] {
			if got := s.GetHash(VisibleText); got != textHash {
				t.Errorf("sample %d: VisibleText hash %d, want %d", i+1, got, textHash)
			}
		}
	}
}

// fetchSample issues a GET against the given URL and returns the
// corresponding fingerprint Sample (with normalization applied).
func fetchSample(t *testing.T, rawURL string) *Sample {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	rc := responsechain.NewResponseChain(resp, 0)
	if err := rc.Fill(); err != nil {
		rc.Close()
		t.Fatalf("fill response: %v", err)
	}
	defer rc.Close()

	s, err := NewSampleFromRC(rc)
	if err != nil {
		t.Fatalf("extract sample: %v", err)
	}
	return s
}

// TestNormalizeBody_StripOrderLongerFirst ensures longer needles are applied
// before shorter ones, so segment-stripping doesn't fragment the full path.
func TestNormalizeBody_StripOrderLongerFirst(t *testing.T) {
	u, _ := url.Parse("http://h/Challenges/abc/Challenges")
	body := []byte("PATH=/Challenges/abc/Challenges TOKEN=Challenges")

	got := NormalizeBody(body, u)

	// Should have replaced the full path AND the orphan trailing "Challenges".
	if bytes.Contains(got, []byte("Challenges")) {
		t.Errorf("expected all 'Challenges' occurrences stripped, got: %s", got)
	}
}

// TestNormalizeBody_RoundTripWithSampleHash sanity-checks that two samples
// from synthetic responses (constructed in-process) hash identically when
// their bodies differ only in the echoed path.
func TestNormalizeBody_RoundTripWithSampleHash(t *testing.T) {
	mk := func(path string) *Sample {
		body := io.NopCloser(strings.NewReader(fmt.Sprintf("Forbidden: %s end", path)))
		req := &http.Request{Method: "GET", URL: &url.URL{Scheme: "http", Host: "h", Path: path}}
		hdr := http.Header{}
		hdr.Set("Content-Type", "text/plain")
		resp := &http.Response{
			StatusCode: 403,
			Header:     hdr,
			Body:       body,
			Request:    req,
		}
		rc := responsechain.NewResponseChain(resp, 0)
		if err := rc.Fill(); err != nil {
			t.Fatalf("fill: %v", err)
		}
		defer rc.Close()
		s, err := NewSampleFromRC(rc)
		if err != nil {
			t.Fatalf("sample: %v", err)
		}
		return s
	}

	a := mk("/ftp/api/Challenges/1/rest/user/security-question")
	b := mk("/ftp/v3/ip-country/api/Challenges/totally-different")

	if ha, hb := a.GetHash(BodyContent), b.GetHash(BodyContent); ha != hb {
		t.Errorf("normalized BodyContent hashes differ: %d vs %d", ha, hb)
	}
}
