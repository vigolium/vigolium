package nosqli_operator_injection

import (
	"fmt"
	"io"
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

// TestTestTimeBasedPayload_BlockedResponseDropped covers the time-based FP class:
// a WAF answers the sleep payload with a 403 that only arrives after a long stall
// (the edge parking/throttling the request, not a backend query running the
// sleep). Without the block gate the slow response confirms a phantom time delay;
// with it the probe is dropped because a blocked response is never a sleep oracle.
func TestTestTimeBasedPayload_BlockedResponseDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "sleep(") {
			// Flush the 403 status before stalling so the delay lands on the body
			// (clear of the requester's response-header timeout). The probe still
			// reads as a block (403) AND takes ~8s — without the gate that slow
			// blocked response would confirm a phantom time delay.
			w.WriteHeader(http.StatusForbidden)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(8 * time.Second) // long enough to clear the time-delay threshold
			_, _ = io.WriteString(w, "blocked")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`) // fast, small clean baseline
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestJSON(t, srv.URL+"/api/users", `{"user":"smith"}`)
	ip := modtest.InsertionPoint(t, rr, "user")
	payload := nosqliPayload{value: `{"$where":"sleep(10000)"}`, detectType: detectTimeDelay, desc: "time-based"}

	res, err := New().testTimeBasedPayload(rr, ip, client, payload)
	if err != nil {
		t.Fatalf("testTimeBasedPayload: %v", err)
	}
	if res != nil {
		t.Fatalf("a blocked (403) response must not be reported as time-based NoSQLi, got: %+v", res)
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

// TestBooleanDiffPairsAreTrueFalse guards the regression that caused the reported
// false positive: each boolean-diff pair must couple a genuinely always-TRUE
// payload with a genuinely always-FALSE one. The previous positional pairing
// compared two always-true payloads (`' || '1'=='1` vs `" || "1"=="1`) against
// each other, so any endpoint noise looked like a boolean signal.
func TestBooleanDiffPairsAreTrueFalse(t *testing.T) {
	if len(booleanDiffPairs) == 0 {
		t.Fatal("expected boolean diff pairs, got none")
	}
	for _, p := range booleanDiffPairs {
		if p.truePayload == p.falsePayload {
			t.Errorf("pair has identical true/false payloads: %q", p.truePayload)
		}
		trueIsTautology := strings.Contains(p.truePayload, "1'=='1") ||
			strings.Contains(p.truePayload, `1"=="1`) ||
			strings.Contains(p.truePayload, "return true")
		falseIsContradiction := strings.Contains(p.falsePayload, "1'=='2") ||
			strings.Contains(p.falsePayload, `1"=="2`) ||
			strings.Contains(p.falsePayload, "return false")
		if !trueIsTautology {
			t.Errorf("true payload %q is not an always-true condition", p.truePayload)
		}
		if !falseIsContradiction {
			t.Errorf("false payload %q is not an always-false condition", p.falsePayload)
		}
	}
}

func TestConfirmBooleanDiffMulti(t *testing.T) {
	list := "<html><body><ul>" + strings.Repeat("<li>user record</li>", 40) + "</ul></body></html>"
	empty := "<html><body><p>No results</p></body></html>"

	// Genuine: stable always-true cluster, stable always-false cluster, clear divergence.
	if !confirmBooleanDiffMulti([]string{list, list, list}, []string{empty, empty}, list) {
		t.Error("stable true/false clusters with clear divergence should confirm")
	}

	// Randomizing endpoint: the always-true samples disagree with EACH OTHER, so
	// the noise floor is blown — no true/false difference can be trusted.
	randTrue := []string{
		"the quick brown fox jumps over the lazy dog every morning",
		"a completely different sentence with unrelated vocabulary here",
		"yet another paragraph sharing almost nothing with the others now",
	}
	randFalse := []string{
		"random structure number four with its own distinct wording today",
		"and a fifth body that again looks nothing like the previous ones",
	}
	if confirmBooleanDiffMulti(randTrue, randFalse, "") {
		t.Error("a randomizing endpoint (true samples disagree among themselves) must not confirm")
	}

	// True and false return identical content — no signal.
	if confirmBooleanDiffMulti([]string{list, list, list}, []string{list, list}, "") {
		t.Error("identical true/false content must not confirm")
	}

	// Baseline matches the FALSE condition more than the true one — inversion, drop.
	if confirmBooleanDiffMulti([]string{list, list}, []string{empty, empty}, empty) {
		t.Error("when the normal response tracks the false condition, must not confirm")
	}

	// A single true sample cannot establish the noise floor.
	if confirmBooleanDiffMulti([]string{list}, []string{empty, empty}, "") {
		t.Error("fewer than two true samples must not confirm")
	}
}

func TestLooksBinary(t *testing.T) {
	if !looksBinary("RIFF\x2c\x00\x00\x00WEBPVP8 \x10\x00\x00\x90\x01") {
		t.Error("WEBP byte stream should look binary")
	}
	if looksBinary("<html><body>hello world</body></html>") {
		t.Error("HTML must not look binary")
	}
	if looksBinary(`{"items":[{"a":1,"b":"x"}]}`) {
		t.Error("JSON must not look binary")
	}
	if looksBinary("") {
		t.Error("empty body must not look binary")
	}
	if looksBinary("héllo wörld café naïve — über résumé") {
		t.Error("UTF-8 multibyte text must not look binary")
	}
}

func TestIsBinaryContentType(t *testing.T) {
	for _, ct := range []string{"image/webp", "image/png", "audio/mpeg", "video/mp4", "application/octet-stream", "font/woff2", "application/pdf"} {
		if !isBinaryContentType(ct) {
			t.Errorf("%q should be classified binary", ct)
		}
	}
	for _, ct := range []string{"text/html", "application/json", "text/plain; charset=utf-8", "application/xml", ""} {
		if isBinaryContentType(ct) {
			t.Errorf("%q should not be classified binary", ct)
		}
	}
}

// TestScanPerInsertionPoint_BinaryImageEndpoint reproduces the reported false
// positive: an Adobe Scene7/Akamai dynamic-image endpoint (?$preset$) that returns
// binary WEBP bytes. The captured baseline was the text/html Akamai block page, so
// CanProcess's content-type gate passed — but the probe responses are binary, and a
// text differential over image bytes is meaningless. The probe-level binary guard
// must abandon the insertion point with no finding.
func TestScanPerInsertionPoint_BinaryImageEndpoint(t *testing.T) {
	webp := "RIFF\x2c\x00\x00\x00WEBPVP8 " + strings.Repeat("\x00\x01\x02\x03\x04", 80)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/webp")
		_, _ = io.WriteString(w, webp)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/is/image/logo?preset=1", "")
	// Baseline captured as the text/html block page (the reported FP): CanProcess
	// sees text/html and proceeds, but every probe returns binary image bytes.
	rr = modtest.Response(rr, "text/html", "<html><head><title>Access Denied</title></head><body>Access Denied</body></html>")
	ip := modtest.InsertionPoint(t, rr, "preset")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding on a binary (image) endpoint, got %d: %+v", len(res), res)
	}
}

// TestScanPerInsertionPoint_FlappingBlockEndpoint covers the other half of the
// reported FP: the endpoint randomly flaps between a 403 Akamai "Access Denied"
// block and a served 200 page, and the 200 page ignores the payload entirely. The
// block samples are rejected by the block guard; the served samples are identical
// for true and false (no divergence). Either way nothing is reported.
func TestScanPerInsertionPoint_FlappingBlockEndpoint(t *testing.T) {
	content := "<html><body>" + strings.Repeat("<p>welcome to the site</p>", 30) + "</body></html>"
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt64(&n, 1)%2 == 0 {
			w.Header().Set("Server", "AkamaiGHost")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>Access Denied</BODY></HTML>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, content) // identical regardless of the injected value
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/search?q=widget", "")
	rr = modtest.Response(rr, "text/html", content)
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding on a flapping 403/200 endpoint that ignores the payload, got %d: %+v", len(res), res)
	}
}

// TestScanPerInsertionPoint_GenuineBooleanInjection is the positive case that the
// pairing fix must still detect: the endpoint returns a record list for the
// always-true condition and an empty page for the always-false condition, stably
// and as text. The fixed true/false pairing plus multi-sample confirmation must
// report exactly one boolean-injection finding.
func TestScanPerInsertionPoint_GenuineBooleanInjection(t *testing.T) {
	list := "<html><body><ul>" + strings.Repeat("<li>record for user smith</li>", 60) + "</ul></body></html>"
	empty := "<html><body><p>No matching records found.</p></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		v := r.FormValue("q")
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(v, "=='2") || strings.Contains(v, "return false") {
			_, _ = io.WriteString(w, empty)
			return
		}
		_, _ = io.WriteString(w, list)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/users", "q=smith")
	// Normal (un-injected) response tracks the always-true cluster.
	rr = modtest.Response(rr, "text/html", list)
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected exactly one boolean-injection finding, got %d: %+v", len(res), res)
	}
	if res[0].Info.Name != "NoSQL Boolean-based Injection" {
		t.Errorf("unexpected finding name: %q", res[0].Info.Name)
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
