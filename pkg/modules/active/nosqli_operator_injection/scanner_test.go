package nosqli_operator_injection

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// testCmpRe extracts `A==B` comparisons (after quote stripping) so a mock backend
// can evaluate an injected boolean for ANY constant, the way a real vulnerable
// endpoint does — exercising the secondary-literal reconfirmation, not just the
// primary `1`/`2` constants.
var testCmpRe = regexp.MustCompile(`(\w+)==(\w+)`)

// injectedConditionIsFalse mimics a backend that genuinely evaluates an injected
// boolean: it returns true when the value carries an always-FALSE condition for any
// constant (1==2, 9==8, 4==5, or "return false").
func injectedConditionIsFalse(v string) bool {
	if strings.Contains(v, "return false") {
		return true
	}
	stripped := strings.NewReplacer("'", "", `"`, "").Replace(v)
	for _, m := range testCmpRe.FindAllStringSubmatch(stripped, -1) {
		if m[1] != m[2] {
			return true
		}
	}
	return false
}

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

// sleepArgRe extracts the millisecond argument of an injected $where sleep().
var sleepArgRe = regexp.MustCompile(`sleep\((\d+)\)`)

// requestedSleepMs returns the sleep(ms) argument in the request body, or 0.
func requestedSleepMs(r *http.Request) int {
	b, _ := io.ReadAll(r.Body)
	m := sleepArgRe.FindStringSubmatch(string(b))
	if m == nil {
		return 0
	}
	ms, _ := strconv.Atoi(m[1])
	return ms
}

// TestTestTimeBasedPayload_DetectsScalingSleep drives the time-based leg against a
// sink whose delay equals the injected $where sleep duration; the scaling
// confirmation must report a finding.
func TestTestTimeBasedPayload_DetectsScalingSleep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ms := requestedSleepMs(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(time.Duration(ms) * time.Millisecond) // delay scales with the injected sleep
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestJSON(t, srv.URL+"/api/users", `{"user":"smith"}`)
	ip := modtest.InsertionPoint(t, rr, "user")
	payload := nosqliPayload{value: whereSleep(timeBasedHighMs), detectType: detectTimeDelay, desc: "time-based"}

	res, err := New().testTimeBasedPayload(rr, ip, client, payload)
	if err != nil {
		t.Fatalf("testTimeBasedPayload: %v", err)
	}
	if res == nil {
		t.Fatal("expected a time-based finding when the delay scales with the injected sleep duration")
	}
}

// TestTestTimeBasedPayload_RejectsNonScalingSpike is the key scaling test: a sink
// that stalls only for the LARGE sleep payload (a WAF/path reacting to the payload,
// not executing it) — while the no-sleep control and the small sleep return fast —
// must be rejected. The high probe clears the coarse threshold, but its delay does
// not scale: the small sleep added nothing over the control.
func TestTestTimeBasedPayload_RejectsNonScalingSpike(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-second timing test in -short mode")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Only the large payload triggers the stall; the control (sleep(0)) and the
		// small sleep return fast — a non-proportional spike, not a real sleep.
		if strings.Contains(string(b), fmt.Sprintf("sleep(%d)", timeBasedHighMs)) {
			time.Sleep(time.Duration(timeBasedHighMs) * time.Millisecond)
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestJSON(t, srv.URL+"/api/users", `{"user":"smith"}`)
	ip := modtest.InsertionPoint(t, rr, "user")
	payload := nosqliPayload{value: whereSleep(timeBasedHighMs), detectType: detectTimeDelay, desc: "time-based"}

	res, err := New().testTimeBasedPayload(rr, ip, client, payload)
	if err != nil {
		t.Fatalf("testTimeBasedPayload: %v", err)
	}
	if res != nil {
		t.Fatalf("a non-scaling spike on only the large payload must not be reported, got: %+v", res)
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

// responseWithStatus attaches a synthetic response carrying an arbitrary status
// line and header block to rr, so a test can model a captured baseline that is a
// WAF/CDN block page (a non-200 status with vendor Server headers) rather than the
// 200-only baseline modtest.Response builds.
func responseWithStatus(rr *httpmsg.HttpRequestResponse, statusLine, headers, body string) *httpmsg.HttpRequestResponse {
	raw := "HTTP/1.1 " + statusLine + "\r\n" + headers +
		fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)) + body
	resp := httpmsg.NewHttpResponse([]byte(raw))
	return httpmsg.NewHttpRequestResponse(rr.Request(), resp)
}

// cloudFrontBlockPage is the CloudFront "Request blocked" error body verbatim
// enough for the edge-block detector's body-marker backstop; the Server header is
// the primary signal.
const cloudFrontBlockPage = "<!DOCTYPE HTML><HTML><HEAD><TITLE>ERROR: The request could not be satisfied</TITLE></HEAD>" +
	"<BODY><H1>403 ERROR</H1><H2>The request could not be satisfied.</H2>Request blocked.\n" +
	"Generated by cloudfront (CloudFront)</BODY></HTML>"

// TestScanPerInsertionPoint_CloudFrontBlockedBaseline reproduces the reported
// false positive: a spider-submitted form value of ~1400 random characters
// tripped a CloudFront length/anomaly rule, so the captured baseline for the
// parameter is a 403 "Request blocked" edge page. A short "[$ne]=" operator value
// simply does not trip that rule and returns the normal 200 page — a 403→200
// transition that must NOT be read as a NoSQL auth bypass. The edge-blocked
// captured baseline is discarded, so the status-delta and size-delta paths never
// compare the operator response against edge mitigation.
func TestScanPerInsertionPoint_CloudFrontBlockedBaseline(t *testing.T) {
	page := "<html><body>" + strings.Repeat("<div>emergency care content</div>", 1500) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The origin behind the edge serves the same 200 page for every value; only
		// the edge (not modeled here) blocked the original long value.
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, page)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	longValue := strings.Repeat("dvjrwejbvxypjaki", 90) // ~1440 chars, like the spider form-fill
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/es/en/emergency-care.html?Comments="+longValue, "")
	// Captured baseline: the CloudFront 403 block page the edge returned for the
	// long value.
	rr = responseWithStatus(rr, "403 Forbidden",
		"Server: CloudFront\r\nContent-Type: text/html\r\nX-Cache: Error from cloudfront\r\n",
		cloudFrontBlockPage)
	ip := modtest.InsertionPoint(t, rr, "Comments")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding when the captured baseline is a CloudFront edge block, got %d: %+v", len(res), res)
	}
}

// TestScanPerInsertionPoint_LengthWafBenignControlAllowed covers the custom-WAF
// variant the vendor-block detector cannot recognize: a plain 403 (no vendor
// Server header, no challenge markers) returned for any long value and 200 for any
// short value. The captured baseline is a genuine-looking app 403, so it is NOT
// discarded and the auth-bypass path runs — but the benign-control isolation in
// confirmAuthBypass sends a short OPERATOR-FREE value, sees it allowed (200) just
// like the operator, and concludes the operator is not the discriminator (the WAF
// gates on value length), so nothing is reported.
func TestScanPerInsertionPoint_LengthWafBenignControlAllowed(t *testing.T) {
	const lenThreshold = 40
	page := "<html><body>" + strings.Repeat("<div>content</div>", 1500) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Query().Get("q")) > lenThreshold {
			// Plain app-style 403 — no vendor header, no block markers.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "<html><body>forbidden</body></html>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, page)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	longValue := strings.Repeat("abcd", 20) // 80 chars, over the WAF threshold
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/search?q="+longValue, "")
	// Captured baseline: the plain 403 the WAF returned for the long value (no
	// vendor header — the edge-block gate must NOT fire, so confirmAuthBypass runs).
	rr = responseWithStatus(rr, "403 Forbidden",
		"Content-Type: text/html\r\n", "<html><body>forbidden</body></html>")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected no finding when a benign operator-free value is allowed just like the operator, got %d: %+v", len(res), res)
	}
}

// TestScanPerInsertionPoint_GenuineAuthBypassStillReported guards against the two
// FP fixes over-suppressing a real NoSQL auth bypass: a benign operator-free value
// (and the original base value) are DENIED with a plain app 403, while only a
// MongoDB operator value ("[$ne]=") is allowed (200). The operator is genuinely
// the discriminator, so the finding must still fire.
func TestScanPerInsertionPoint_GenuineAuthBypassStillReported(t *testing.T) {
	dataPage := `{"users":[` + strings.TrimSuffix(strings.Repeat(`{"u":"x"},`, 40), ",") + `]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("token")
		// Only a MongoDB operator value unlocks the data; any plain value is denied.
		if strings.Contains(v, "$ne") || strings.Contains(v, "$gt") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, dataPage)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"forbidden"}`)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/api/record?token=secret123", "")
	rr = responseWithStatus(rr, "403 Forbidden",
		"Content-Type: application/json\r\n", `{"error":"forbidden"}`)
	ip := modtest.InsertionPoint(t, rr, "token")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("expected a genuine NoSQL auth bypass (only the operator value is allowed) to still be reported")
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

		// The secondary recheck must use DIFFERENT always-true/always-false
		// constants so a cached or coincidental primary divergence cannot satisfy it.
		if p.secTruePayload == p.truePayload || p.secFalsePayload == p.falsePayload {
			t.Errorf("secondary constants must differ from primary: %q / %q", p.truePayload, p.falsePayload)
		}
		if p.secTruePayload == p.secFalsePayload {
			t.Errorf("secondary pair has identical true/false payloads: %q", p.secTruePayload)
		}
		secTrueIsTautology := strings.Contains(p.secTruePayload, "9'=='9") ||
			strings.Contains(p.secTruePayload, `9"=="9`) ||
			strings.Contains(p.secTruePayload, "return 4==4")
		secFalseIsContradiction := strings.Contains(p.secFalsePayload, "9'=='8") ||
			strings.Contains(p.secFalsePayload, `9"=="8`) ||
			strings.Contains(p.secFalsePayload, "return 4==5")
		if !secTrueIsTautology {
			t.Errorf("secondary true payload %q is not an always-true condition", p.secTruePayload)
		}
		if !secFalseIsContradiction {
			t.Errorf("secondary false payload %q is not an always-false condition", p.secFalsePayload)
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
		// A real injectable backend evaluates the condition for ANY constant, so
		// both the primary (1==2) and the secondary recheck (9==8 / 4==5) flip the
		// response — exactly what the secondary-literal confirmation requires.
		if injectedConditionIsFalse(v) {
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

// firstPathFolderIP returns the first URL-path-folder insertion point in rr, the
// surface where the chope false positives lived (a cosmetic `{city}-restaurants`
// segment).
func firstPathFolderIP(t *testing.T, rr *httpmsg.HttpRequestResponse) httpmsg.InsertionPoint {
	t.Helper()
	points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints: %v", err)
	}
	for _, p := range points {
		if p.Type() == httpmsg.INS_URL_PATH_FOLDER {
			return p
		}
	}
	t.Fatal("no path-folder insertion point found")
	return nil
}

// TestScanPerInsertionPoint_SecondaryLiteralNonReproduction reproduces the core
// chope false positive at the logic layer: a NON-injectable endpoint whose response
// happens to diverge for the PRIMARY always-false literal (=='2) — a one-off quirk,
// a transient, an unrelated routing rule — but does NOT reproduce that divergence
// for the secondary constants (9==8 / 4==5). The secondary-literal confirmation
// must reject it.
func TestScanPerInsertionPoint_SecondaryLiteralNonReproduction(t *testing.T) {
	list := "<html><body><ul>" + strings.Repeat("<li>record</li>", 60) + "</ul></body></html>"
	empty := "<html><body><p>No matching records found.</p></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		v := r.FormValue("q")
		w.Header().Set("Content-Type", "text/html")
		// Only the exact primary false literal flips the response — a real boolean
		// oracle would flip for every always-false constant, this does not.
		if strings.Contains(v, "=='2") {
			_, _ = io.WriteString(w, empty)
			return
		}
		_, _ = io.WriteString(w, list)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "POST", srv.URL+"/api/users", "q=smith")
	rr = modtest.Response(rr, "text/html", list)
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a differential that does not reproduce with new constants must not be reported, got %d: %+v", len(res), res)
	}
}

// TestScanPerInsertionPoint_InertPathSegmentSkipped reproduces the chope path-FP
// surface: a catch-all route that returns the SAME page for any path-segment value
// (the `{city}-restaurants` segment is cosmetic, not a query key). The relevance
// precheck (#5) sends one benign value, sees the baseline page returned, and skips
// the boolean-diff path before running any full probe set.
func TestScanPerInsertionPoint_InertPathSegmentSkipped(t *testing.T) {
	page := "<html><body>" + strings.Repeat("<p>restaurant listing</p>", 40) + "</body></html>"
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page) // identical regardless of the path segment
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/city-restaurants/restaurant/rise", "")
	rr = modtest.Response(rr, "text/html", page)
	ip := firstPathFolderIP(t, rr)

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a cosmetic catch-all path segment must not be reported, got %d: %+v", len(res), res)
	}
	if n := atomic.LoadInt64(&hits); n > 2 {
		t.Fatalf("relevance precheck should skip after a single benign probe, got %d requests", n)
	}
}

// TestScanPerInsertionPoint_LargeHTMLPageSkipped covers the surface gate (#4): a
// large rendered text/html content page (the chope ~200 KB restaurant page) is not
// a compact query/auth endpoint, so the boolean-diff path skips it WITHOUT sending
// any probe traffic.
func TestScanPerInsertionPoint_LargeHTMLPageSkipped(t *testing.T) {
	big := "<html><body>" + strings.Repeat("<div>content block</div>", 6000) + "</body></html>" // >100 KB
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/city-restaurants/restaurant/rise", "")
	rr = modtest.Response(rr, "text/html", big)
	ip := firstPathFolderIP(t, rr)

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("a large HTML content page must not be boolean-diffed, got %d: %+v", len(res), res)
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Fatalf("surface gate should send no traffic on a large HTML page, got %d requests", n)
	}
}

func TestConfirmBooleanDiffWithControl(t *testing.T) {
	list := "<html><body><ul>" + strings.Repeat("<li>user record</li>", 40) + "</ul></body></html>"
	empty := "<html><body><p>No results</p></body></html>"

	// Stable benign control + clear true/false divergence → confirm.
	if !confirmBooleanDiffWithControl([]string{list, list}, []string{list, list, list}, []string{empty, empty}, list) {
		t.Error("stable control with clear true/false divergence should confirm")
	}

	// The benign control splits across its own samples (cadence-correlated variance):
	// even a clean true/false divergence must be rejected as a scheduling artifact.
	splitNeutral := []string{
		list,
		"<html><body><div>" + strings.Repeat("an entirely different control body shape", 40) + "</div></body></html>",
	}
	if confirmBooleanDiffWithControl(splitNeutral, []string{list, list, list}, []string{empty, empty}, list) {
		t.Error("a control that splits on the same cadence must be rejected (scheduling artifact)")
	}

	// Fewer than two control samples cannot measure cadence-correlated noise.
	if confirmBooleanDiffWithControl([]string{list}, []string{list, list, list}, []string{empty, empty}, list) {
		t.Error("fewer than two control samples must not confirm")
	}
}

func TestPathOrHeaderInsertionTypes(t *testing.T) {
	for _, ty := range []httpmsg.InsertionPointType{httpmsg.INS_HEADER, httpmsg.INS_URL_PATH_FOLDER, httpmsg.INS_URL_PATH_FILENAME} {
		if !pathOrHeaderInsertionTypes.Contains(ty) {
			t.Errorf("type %d should be classified path/header", ty)
		}
	}
	for _, ty := range []httpmsg.InsertionPointType{httpmsg.INS_PARAM_URL, httpmsg.INS_PARAM_BODY, httpmsg.INS_PARAM_JSON} {
		if pathOrHeaderInsertionTypes.Contains(ty) {
			t.Errorf("type %d should NOT be classified path/header", ty)
		}
	}
}
