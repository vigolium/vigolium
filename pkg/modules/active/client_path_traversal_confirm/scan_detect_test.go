package client_path_traversal_confirm

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/infra/csptflow"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const htmlPage = `<html><head><script>fetch('/api/items/' + location.hash.slice(1))</script></head><body></body></html>`

// navMode selects how the fake browser resolves an injected value.
type navMode int

const (
	navNormal          navMode = iota // benign -> under prefix, ../ -> escaped
	navControlEscapes                 // even the benign control escapes (unstable page)
	navEncodedNoEscape                // ../ stays percent-encoded as data (no escape)
)

// fakeNavigate returns a Navigate seam that mimics browser URL normalization
// without launching a browser. It keys off the injected fragment value.
func fakeNavigate(mode navMode, method string) func(context.Context, NavRequest) ([]CapturedRequest, error) {
	return func(_ context.Context, nav NavRequest) ([]CapturedRequest, error) {
		val := fragmentValue(nav.URL)
		escaping := strings.HasPrefix(val, "../")
		token := strings.TrimPrefix(val, "../")
		switch {
		case escaping && mode == navEncodedNoEscape:
			return []CapturedRequest{{URL: "http://example.com/api/items/%2e%2e%2f" + token, Method: method}}, nil
		case escaping:
			return []CapturedRequest{{URL: "http://example.com/api/" + token, Method: method}}, nil
		case mode == navControlEscapes:
			return []CapturedRequest{{URL: "http://example.com/api/" + val, Method: method}}, nil
		default:
			return []CapturedRequest{{URL: "http://example.com/api/items/" + val, Method: method}}, nil
		}
	}
}

func fragmentValue(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return ""
	}
	if u.Fragment != "" {
		return u.Fragment
	}
	return u.Query().Get("cspt")
}

func fakeRecover(cands ...Candidate) func(context.Context, string, string) []Candidate {
	return func(_ context.Context, _, _ string) []Candidate {
		return cands
	}
}

// harness builds a tech-marked (or not) ScanContext + response and a module with
// injected seams, then runs ScanPerRequest.
func run(t *testing.T, markTech bool, nav func(context.Context, NavRequest) ([]CapturedRequest, error), cands ...Candidate) []*modResult {
	t.Helper()
	rr := modtest.Request(t, "http://example.com/app")
	rr = modtest.Response(rr, "text/html", htmlPage)

	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	if markTech {
		sc.MarkTech("example.com", TechTagCSPTCandidate)
	}

	m := New()
	m.Navigate = nav
	m.RecoverCandidates = fakeRecover(cands...)

	res, err := m.ScanPerRequest(rr, nil, sc)
	require.NoError(t, err)
	out := make([]*modResult, len(res))
	for i, r := range res {
		out[i] = &modResult{sev: r.Info.Severity, conf: r.Info.Confidence, desc: r.Info.Description, evidence: r.AdditionalEvidence}
	}
	return out
}

type modResult struct {
	sev      severity.Severity
	conf     severity.Confidence
	desc     string
	evidence []string
}

var hashCandidate = Candidate{SourceParam: "location.hash", Prefix: "/api/items/", Method: "GET"}

// (1) POSITIVE: both canaries escape and the control stays under the prefix.
func TestConfirm_PositiveGetEscape(t *testing.T) {
	got := run(t, true, fakeNavigate(navNormal, "GET"), hashCandidate)
	require.Len(t, got, 1, "expected one confirmed CSPT finding")
	assert.Equal(t, severity.Low, got[0].sev, "a GET path escape is Low")
	assert.Equal(t, severity.Firm, got[0].conf)
	assert.NotContains(t, got[0].desc, "CSRF", "must never label the primitive CSRF")
	assert.Contains(t, strings.Join(got[0].evidence, "\n"), "payload #1 (escaped)")
}

// (2) NEGATIVE: the control also escapes → unstable → no finding.
func TestConfirm_NegativeControlEscapes(t *testing.T) {
	got := run(t, true, fakeNavigate(navControlEscapes, "GET"), hashCandidate)
	assert.Empty(t, got, "an unstable page whose control escapes must not confirm")
}

// (3) NEGATIVE: the ../ payload stays percent-encoded as data → no escape → no finding.
func TestConfirm_NegativeEncodedAsData(t *testing.T) {
	got := run(t, true, fakeNavigate(navEncodedNoEscape, "GET"), hashCandidate)
	assert.Empty(t, got, "an encoded ../ that stays under the prefix must not confirm")
}

// (4) NEGATIVE: the cspt-candidate tech tag is not marked → fail-closed → no finding.
func TestConfirm_NegativeTechNotMarked(t *testing.T) {
	navCalled := false
	nav := func(ctx context.Context, r NavRequest) ([]CapturedRequest, error) {
		navCalled = true
		return fakeNavigate(navNormal, "GET")(ctx, r)
	}
	got := run(t, false, nav, hashCandidate)
	assert.Empty(t, got, "must not run without the cspt-candidate tech tag")
	assert.False(t, navCalled, "the browser seam must not be invoked when fail-closed")
}

// (5) DELETE candidate that escapes → Medium/Firm (state-changing primitive).
func TestConfirm_DeleteEscapeIsMedium(t *testing.T) {
	cand := Candidate{SourceParam: "location.hash", Prefix: "/api/items/", Method: "DELETE"}
	got := run(t, true, fakeNavigate(navNormal, "DELETE"), cand)
	require.Len(t, got, 1)
	assert.Equal(t, severity.Medium, got[0].sev, "a non-GET (state-changing) escape is Medium")
	assert.Equal(t, severity.Firm, got[0].conf)
}

// A candidate without a known prefix can't be confirmed (nothing to escape from).
func TestConfirm_NoPrefixSkipped(t *testing.T) {
	cand := Candidate{SourceParam: "location.hash", Prefix: "", Method: "GET"}
	got := run(t, true, fakeNavigate(navNormal, "GET"), cand)
	assert.Empty(t, got)
}

// --- pure normalize / escape helper unit tests ---------------------------

func TestEscapesPrefix(t *testing.T) {
	cases := []struct {
		name       string
		prefix     string
		requestURL string
		wantEscape bool
		wantNorm   string
	}{
		{"literal-dotdot-escapes", "/api/items/", "http://h/api/items/../vgl", true, "/api/vgl"},
		{"already-normalized-escape", "/api/items/", "http://h/api/vgl-cspt-x", true, "/api/vgl-cspt-x"},
		{"encoded-dotdot-stays-data", "/api/items/", "http://h/api/items/%2e%2e%2fvgl", false, "/api/items/%2e%2e%2fvgl"},
		{"benign-under-prefix", "/api/items/", "http://h/api/items/abc", false, "/api/items/abc"},
		{"exact-prefix", "/api/items/", "http://h/api/items", false, "/api/items"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			esc, norm := escapesPrefix(tc.prefix, tc.requestURL)
			assert.Equal(t, tc.wantEscape, esc)
			assert.Equal(t, tc.wantNorm, norm)
		})
	}
}

func TestBuildNavURL(t *testing.T) {
	assert.Equal(t, "http://example.com/app#../x", buildNavURL("http://example.com/app", "location.hash", "../x"))
	got := buildNavURL("http://example.com/app", "location.search", "../x")
	u, _ := url.Parse(got)
	assert.Equal(t, "../x", u.Query().Get("cspt"))
}

func TestInferMethodAndPrefix(t *testing.T) {
	assert.Equal(t, "POST", csptflow.InferMethod("xhr.open('POST','/api/x/'+h)"))
	assert.Equal(t, "DELETE", csptflow.InferMethod("fetch('/api/x/'+h,{method:'DELETE'})"))
	assert.Equal(t, "GET", csptflow.InferMethod("fetch('/api/x/'+h)"))
	assert.Equal(t, "/api/items/", csptflow.ParsePrefix("fetch('/api/items/'+location.hash)"))
}
