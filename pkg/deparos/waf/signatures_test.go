package waf

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// The table compiles, its ids are <vendor>.<kind>.<slug>, and every classifying row's statuses pass the
// candidate gate (a row the gate filters out could never fire).
func TestSignatures_TableIsValid(t *testing.T) {
	if _, err := compileSignatures(Signatures); err != nil {
		t.Fatal(err)
	}
	for _, s := range Signatures {
		parts := strings.SplitN(s.ID, ".", 3)
		if len(parts) != 3 || parts[0] != s.Vendor || parts[1] != s.Kind || parts[2] == "" {
			t.Errorf("id %q does not read <vendor>.<kind>.<slug> for vendor %q kind %q", s.ID, s.Vendor, s.Kind)
		}
		if s.Kind == KindSigPresence {
			continue
		}
		for _, code := range s.Match.Status {
			if !IsCandidateStatusCode(code) {
				t.Errorf("%s applies on %d, which IsCandidateStatusCode drops", s.ID, code)
			}
		}
	}
}

func TestCompileSignatures_RejectsBadRows(t *testing.T) {
	for name, row := range map[string]Signature{
		"unknown kind":     {ID: "x.y.z", Vendor: "x", Kind: "y", Match: Match{Status: []int{403}, BodyOp: OpContains, Body: "a"}},
		"matches nothing":  {ID: "x.block.z", Vendor: "x", Kind: KindSigBlock, Match: Match{Status: []int{403}}},
		"unknown requires": {ID: "x.block.z", Vendor: "x", Kind: KindSigBlock, Match: Match{Status: []int{403}}, Requires: []string{"nope"}},
		"bad regex":        {ID: "x.block.z", Vendor: "x", Kind: KindSigBlock, Match: Match{Status: []int{403}, BodyOp: OpRegex, Body: "("}},
		"status-less":      {ID: "x.block.z", Vendor: "x", Kind: KindSigBlock, Match: Match{BodyOp: OpContains, Body: "a"}},
		"presence status":  {ID: "x.presence.z", Vendor: "x", Kind: KindSigPresence, Match: Match{Status: []int{403}, Header: "X", HeaderOp: OpExists}},
	} {
		if _, err := compileSignatures([]Signature{row}); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}

// The published form round-trips: rows decoded from their JSON are the table,
// and compile to the same classifier.
func TestSignatures_JSONRoundTrip(t *testing.T) {
	raw, err := json.Marshal(Signatures)
	if err != nil {
		t.Fatal(err)
	}
	var back []Signature
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, Signatures) {
		t.Fatal("decoded rows differ from the table")
	}
	if _, err := compileSignatures(back); err != nil {
		t.Fatal(err)
	}
}

// Where the classifiers this table replaced disagreed, the stricter reading
// holds.
func TestSignatures_ReconciledDisagreements(t *testing.T) {
	html := "text/html"
	type want struct{ kind, vendor string }
	cases := []struct {
		name   string
		status int
		header http.Header
		body   string
		want   want
	}{
		// _Incapsula_Resource: Imperva's sensor, on ordinary pages too.
		{"incapsula resource on a 200 is no challenge", 200, http.Header{"Content-Type": {html}, "X-Iinfo": {"1-2-3"}},
			`<script src="/_Incapsula_Resource?SWJIYLWA=719d"></script>`, want{}},
		{"incapsula resource on a 403 without imperva's header", 403, http.Header{"Content-Type": {html}},
			`<script src="/_Incapsula_Resource?SWJIYLWA=719d"></script>`, want{}},
		{"incapsula resource on a 403 behind imperva", 403, http.Header{"X-Iinfo": {"1-2-3"}},
			`<script src="/_Incapsula_Resource?SWJIYLWA=719d"></script>`, want{KindVendor, "imperva"}},
		// Cf-Mitigated: only its documented value.
		{"cf-mitigated challenge on a 200", 200, http.Header{"Cf-Mitigated": {"challenge"}}, "", want{KindChallenge, "cloudflare"}},
		{"cf-mitigated challenge on a 403", 403, http.Header{"Cf-Mitigated": {"challenge"}}, "", want{KindChallenge, "cloudflare"}},
		{"cf-mitigated with another value", 200, http.Header{"Cf-Mitigated": {"block"}}, "", want{}},
		// The JSD injector path rides ordinary Cloudflare pages.
		{"challenge-platform path on a 200", 200, http.Header{"Content-Type": {html}},
			`<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1"></script>`, want{}},
		// A generic phrase is not Imperva's page.
		{"request unsuccessful alone", 403, http.Header{"Content-Type": {"text/plain"}}, "Request unsuccessful", want{}},
		// A Turnstile widget is not a Cloudflare block.
		{"turnstile script on a 403", 403, http.Header{"Content-Type": {html}},
			`<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>`, want{}},
		// An origin-failure page is the edge, not a block.
		{"cloudfront 502 page", 502, http.Header{"Server": {"CloudFront"}}, "The request could not be satisfied.", want{}},
		// Front Door's header is presence, like every edge's.
		{"x-azure-ref alone on a 403", 403, http.Header{"X-Azure-Ref": {"0abc"}}, `{"e":1}`, want{}},
		{"x-azure-ref on a 429", 429, http.Header{"X-Azure-Ref": {"0abc"}}, "", want{KindVendor, "azure"}},
		// F5 ASM's stock blocking page answers 200 OK.
		{"f5 default page on a 200", 200, http.Header{"Content-Type": {html}},
			`<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br><br>Your support ID is: 1234</body></html>`,
			want{KindVendor, "f5_bigip"}},
		{"f5 sentence in a 200 json body", 200, http.Header{"Content-Type": {"application/json"}},
			`{"faq":"The requested URL was rejected. Please consult with your administrator."}`, want{}},
		// Infra's own markers survive.
		{"netlify challenge on a 403", 403, http.Header{"Content-Type": {html}}, `<form action="/.netlify/submit-challenge">`, want{KindChallenge, "netlify"}},
		{"managed challenge noscript", 200, nil, `<noscript>Enable JavaScript and cookies to continue</noscript>`, want{KindChallenge, "cloudflare"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := ClassifyResponse(c.status, c.header, []byte(c.body))
			if c.want.kind == "" {
				if res.Kind() == KindVendor || res.Kind() == KindChallenge {
					t.Fatalf("got %+v, want no edge attribution", res)
				}
				return
			}
			if res.Kind() != c.want.kind || res.Vendor() != c.want.vendor {
				t.Fatalf("got kind %q vendor %q (%+v), want %q %q", res.Kind(), res.Vendor(), res, c.want.kind, c.want.vendor)
			}
		})
	}
}
