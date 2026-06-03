package nosqli_operator_injection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestContainsNoSQLError(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"mongodb error", "MongoError: bad query", true},
		{"couchdb error", `{"error":"bad_request","reason":"invalid_json"}`, false},
		{"couchdb org", "org.apache.couchdb.error", true},
		{"no error", "normal response body", false},
		{"empty", "", false},
		{"duplicate key", "E11000 duplicate key error", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsNoSQLError(tt.body)
			if got != tt.expected {
				t.Errorf("containsNoSQLError(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeAuthBypass(t *testing.T) {
	tests := []struct {
		name           string
		baselineStatus int
		probeStatus    int
		expected       bool
	}{
		{"401 to 200", 401, 200, true},
		{"403 to 200", 403, 200, true},
		{"401 to 302", 401, 302, false},
		{"200 to 200", 200, 200, false},
		{"403 to 403", 403, 403, false},
		{"401 to 201", 401, 201, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeAuthBypass(tt.baselineStatus, tt.probeStatus)
			if got != tt.expected {
				t.Errorf("analyzeAuthBypass(%d, %d) = %v, want %v", tt.baselineStatus, tt.probeStatus, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeSizeIncrease(t *testing.T) {
	tests := []struct {
		name        string
		baselineLen int
		probeLen    int
		expected    bool
	}{
		{"significant increase", 100, 500, true},
		{"small increase", 100, 120, false},
		{"no increase", 100, 100, false},
		{"decrease", 100, 50, false},
		{"zero baseline large probe", 0, 300, true},
		{"zero baseline small probe", 0, 50, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeSizeIncrease(tt.baselineLen, tt.probeLen)
			if got != tt.expected {
				t.Errorf("analyzeSizeIncrease(%d, %d) = %v, want %v", tt.baselineLen, tt.probeLen, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeTimeDelay(t *testing.T) {
	tests := []struct {
		name             string
		baselineDuration time.Duration
		probeDuration    time.Duration
		expected         bool
	}{
		{"full sleep delay", 20 * time.Millisecond, 10000 * time.Millisecond, true},
		{"just above threshold", 10 * time.Millisecond, 7100 * time.Millisecond, true},
		{"just below threshold", 10 * time.Millisecond, 6900 * time.Millisecond, false},
		{"jitter only", 10 * time.Millisecond, 200 * time.Millisecond, false},
		{"no delay", 10 * time.Millisecond, 10 * time.Millisecond, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeTimeDelay(tt.baselineDuration, tt.probeDuration)
			if got != tt.expected {
				t.Errorf("analyzeTimeDelay() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNormalizeResponse(t *testing.T) {
	// Two responses that differ only in a rotating token + timestamp should
	// normalize to the same structural string.
	a := `{"ok":true,"token":"a8Hk2Lp9QzXc4Rt0","ts":1717000001}`
	b := `{"ok":true,"token":"Zq7Wn1Mv3Bd6Yj5K","ts":1717009999}`
	if normalizeResponse(a) != normalizeResponse(b) {
		t.Errorf("token/timestamp noise should normalize away:\n  %q\n  %q", normalizeResponse(a), normalizeResponse(b))
	}
}

func TestDiceSimilarity(t *testing.T) {
	if s := diceSimilarity("identical", "identical"); s != 1 {
		t.Errorf("identical strings = %v, want 1", s)
	}
	if s := diceSimilarity("the quick brown fox", "the quick brown fox jumps"); s < 0.6 {
		t.Errorf("near-identical strings = %v, want high", s)
	}
	if s := diceSimilarity("welcome back, your account dashboard", "access denied"); s > 0.4 {
		t.Errorf("structurally different strings = %v, want low", s)
	}
}

func TestConfirmBooleanDiff(t *testing.T) {
	// Noisy endpoint: every response carries a fresh token; true/false bodies
	// differ only in that token. Must NOT be confirmed (the reported FP).
	noisyTrue1 := `{"status":"challenge","cid":"7Hk2Lp9QzXc4Rt0aa","seq":1}`
	noisyTrue2 := `{"status":"challenge","cid":"Zq7Wn1Mv3Bd6Yj5Kbb","seq":2}`
	noisyFalse := `{"status":"challenge","cid":"Mn4Bv8Cx2Za6Qw1Ecc","seq":3}`
	if confirmBooleanDiff(noisyTrue1, noisyTrue2, noisyFalse, "") {
		t.Error("noisy endpoint with rotating tokens must not be confirmed as boolean injection")
	}

	// Genuine boolean injection: always-true returns the record list (stable across
	// repeats), always-false returns an empty/denied page.
	vulnTrue1 := `<html><body><ul><li>alice</li><li>bob</li><li>carol</li></ul></body></html>`
	vulnTrue2 := `<html><body><ul><li>alice</li><li>bob</li><li>carol</li></ul></body></html>`
	vulnFalse := `<html><body><p>No results found.</p></body></html>`
	if !confirmBooleanDiff(vulnTrue1, vulnTrue2, vulnFalse, "") {
		t.Error("stable true vs diverging false should be confirmed")
	}
}

// TestScanPerInsertionPoint_NoisyEndpoint reproduces the reported false positive:
// a challenge-style endpoint (à la DataDome /js/) that echoes a fresh rotating
// token in every response. The structure never changes with the payload, so the
// scanner must report nothing.
func TestScanPerInsertionPoint_NoisyEndpoint(t *testing.T) {
	var seq int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt64(&seq, 1)
		// Same JSON shape every time; only the opaque token + counter rotate.
		_, _ = fmt.Fprintf(w, `{"status":"challenge","cid":"tok%020dABCDEF","seq":%d}`, n*1009, n)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/js/", "jspl=ABCDEFGHIJKLMNOP")
	// Attach a representative baseline response (also rotating-token shaped).
	rr = modtest.Response(rr, "application/json", `{"status":"challenge","cid":"tok00000000000000000000ABCDEF","seq":0}`)
	ip := modtest.InsertionPoint(t, rr, "jspl")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding on a noisy rotating-token endpoint, got %d: %+v", len(res), res)
	}
}

// TestScanPerInsertionPoint_LargeByDefaultEndpoint reproduces the size-change
// false positive: the endpoint returns a large body for ANY request (the
// captured baseline merely happened to be small), so a $regex/$exists operator
// payload looks like it "increased" the response. The reproducible-growth gate
// re-fetches the original value, finds a fresh clean response is just as large,
// and reports nothing.
func TestScanPerInsertionPoint_LargeByDefaultEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always large, identical regardless of the injected operator.
		_, _ = fmt.Fprintf(w, `{"items":[%s]}`, strings.TrimSuffix(strings.Repeat(`"x",`, 400), ","))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/search", "q=widget")
	// Small captured baseline — every live response dwarfs it, so the size-change
	// pre-filter trips, but a fresh clean fetch is just as large.
	rr = modtest.Response(rr, "application/json", `{"items":[]}`)
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding when a fresh clean fetch is just as large as the payload response, got %d: %+v", len(res), res)
	}
}

// TestScanPerInsertionPoint_EmptyBaselineStaticPage reproduces the reported
// Cloudflare-Access false positive: a static SSO login page that renders the
// SAME large HTML regardless of the injected operator, captured with an EMPTY
// baseline body (the gzip body was not decoded at capture time) but a served
// 200 status. The size oracle must not read 0→N as data exfiltration.
func TestScanPerInsertionPoint_EmptyBaselineStaticPage(t *testing.T) {
	page := "<html><body>" + strings.Repeat("<div>please sign in</div>", 1500) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, page)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/cdn-cgi/access/login?redirect_url=%2F", "")
	// Served 200 but captured with an empty body (gzip not decoded at capture).
	rr = modtest.Response(rr, "text/html", "")
	ip := modtest.InsertionPoint(t, rr, "redirect_url")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding on a static page with an empty captured baseline, got %d: %+v", len(res), res)
	}
}

func TestResponsesDiverge(t *testing.T) {
	// Same static page returned for clean and payload — must NOT diverge.
	page := "<html><body>" + strings.Repeat("<div>login form</div>", 200) + "</body></html>"
	if responsesDiverge(page, page) {
		t.Error("identical static pages must not be treated as divergent (data exfiltration)")
	}

	// Genuine exfiltration: clean has no records, the payload returns a record list.
	clean := `{"items":[]}`
	leaked := `{"items":[` + strings.TrimSuffix(strings.Repeat(`{"user":"x","email":"y"},`, 50), ",") + `]}`
	if !responsesDiverge(clean, leaked) {
		t.Error("an empty result set vs a populated one should diverge")
	}

	// Empty bodies cannot establish divergence.
	if responsesDiverge("", page) || responsesDiverge(page, "") {
		t.Error("empty body must not count as divergent")
	}
}

func TestGetPayloadsForType(t *testing.T) {
	jsonPayloads := getPayloadsForType(httpmsg.INS_PARAM_JSON)
	if len(jsonPayloads) == 0 {
		t.Error("expected JSON payloads, got none")
	}

	urlPayloads := getPayloadsForType(httpmsg.INS_PARAM_URL)
	if len(urlPayloads) == 0 {
		t.Error("expected URL payloads, got none")
	}

	bodyPayloads := getPayloadsForType(httpmsg.INS_PARAM_BODY)
	if len(bodyPayloads) == 0 {
		t.Error("expected body payloads, got none")
	}

	// JSON payloads should include JSON operators
	hasJSON := false
	for _, p := range jsonPayloads {
		if p.value == `{"$ne":""}` {
			hasJSON = true
			break
		}
	}
	if !hasJSON {
		t.Error("JSON payloads should include $ne operator")
	}

	// URL payloads should include array syntax
	hasArray := false
	for _, p := range urlPayloads {
		if p.value == "[$ne]=" {
			hasArray = true
			break
		}
	}
	if !hasArray {
		t.Error("URL payloads should include array syntax")
	}
}
