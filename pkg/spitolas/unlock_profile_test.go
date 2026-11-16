package spitolas

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

func mustProfile(t *testing.T, doc string) *UnlockProfile {
	t.Helper()
	p, err := ParseUnlockProfile([]byte(doc))
	if err != nil {
		t.Fatalf("ParseUnlockProfile: %v", err)
	}
	return p
}

func TestParseUnlockProfileDefaultsAndNormalises(t *testing.T) {
	p := mustProfile(t, `{"origin":"HTTPS://App.Test:443/","routes":["/admin"],
		"stubs":[{"method":"get","path":"https://app.test/api/me","status":200,"body":"{}"}]}`)
	if p.Origin != "https://app.test" {
		t.Errorf("origin = %q, want https://app.test", p.Origin)
	}
	if p.MaxRoutes != DefaultUnlockMaxRoutes || p.SettleMs != DefaultUnlockSettleMs {
		t.Errorf("defaults = maxRoutes %d settleMs %d", p.MaxRoutes, p.SettleMs)
	}
	if s := p.Stubs[0]; s.Method != "GET" || s.Path != "/api/me" {
		t.Errorf("stub normalised to %+v, want GET /api/me", s)
	}
}

func TestParseUnlockProfileRefusals(t *testing.T) {
	big := strings.Repeat("a", MaxUnlockStubBody+1)
	cases := []struct {
		name, doc, want string
	}{
		{"unknown key", `{"origin":"https://a.test","localStore":{}}`, "unknown field"},
		{"no origin", `{"routes":["/"]}`, "origin is required"},
		{"origin with path", `{"origin":"https://a.test/app"}`, "no path"},
		{"origin not http", `{"origin":"file:///etc"}`, "http:// or https://"},
		{"stub off origin", `{"origin":"https://a.test","stubs":[{"method":"GET","path":"https://evil.test/api/me","status":200}]}`, "not on the profile origin"},
		{"stub other port", `{"origin":"https://a.test","stubs":[{"method":"GET","path":"https://a.test:8443/x","status":200}]}`, "not on the profile origin"},
		{"stub scheme-relative", `{"origin":"https://a.test","stubs":[{"method":"GET","path":"//evil.test/x","status":200}]}`, "single /"},
		{"stub query", `{"origin":"https://a.test","stubs":[{"method":"GET","path":"/api?x=1","status":200}]}`, "query"},
		{"stub redirect", `{"origin":"https://a.test","stubs":[{"method":"GET","path":"/x","status":302}]}`, "2xx, 4xx or 5xx"},
		{"stub body", `{"origin":"https://a.test","stubs":[{"method":"GET","path":"/x","status":200,"body":"` + big + `"}]}`, "over the 65536-byte limit"},
		{"stub method", `{"origin":"https://a.test","stubs":[{"method":"GE T","path":"/x","status":200}]}`, "method token"},
		{"route off origin", `{"origin":"https://a.test","routes":["https://evil.test/admin"]}`, "not on the profile origin"},
		{"route scheme-relative", `{"origin":"https://a.test","routes":["//evil.test/admin"]}`, "not on the profile origin"},
		{"maxRoutes over cap", `{"origin":"https://a.test","maxRoutes":201}`, "maxRoutes 201"},
		{"settle over cap", `{"origin":"https://a.test","settleMs":10001}`, "settleMs 10001"},
		{"cookie value", `{"origin":"https://a.test","cookies":[{"name":"s","value":"a;b"}]}`, "cookies[0]"},
		{"cookie name", `{"origin":"https://a.test","cookies":[{"name":"a b","value":"x"}]}`, "cookie token"},
		{"trailing data", `{"origin":"https://a.test"} {}`, "trailing data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseUnlockProfile([]byte(tc.doc))
			if err == nil {
				t.Fatalf("accepted %s", tc.doc)
			}
			if !errors.Is(err, ErrInvalidUnlockProfile) {
				t.Errorf("err %v does not wrap ErrInvalidUnlockProfile", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to say %q", err, tc.want)
			}
		})
	}
}

func TestMatchStub(t *testing.T) {
	p := mustProfile(t, `{"origin":"http://127.0.0.1:8080","stubs":[
		{"method":"GET","path":"/api/me","status":200},
		{"method":"GET","path":"/api/users/:id","status":200},
		{"method":"POST","path":"/api/{tenant}/graphql","status":200}]}`)
	origin, _ := url.Parse(p.Origin)
	cases := []struct {
		method, url string
		want        int
	}{
		{"GET", "http://127.0.0.1:8080/api/me", 0},
		{"get", "http://127.0.0.1:8080/api/me?x=1", 0},
		{"POST", "http://127.0.0.1:8080/api/me", -1},
		{"GET", "http://127.0.0.1:8080/api/me/", -1},
		{"GET", "http://127.0.0.1:8080/api/users/42", 1},
		{"GET", "http://127.0.0.1:8080/api/users/", -1},
		{"GET", "http://127.0.0.1:8080/api/users/42/x", -1},
		{"POST", "http://127.0.0.1:8080/api/acme/graphql", 2},
		{"GET", "http://127.0.0.1:9090/api/me", -1},
		{"GET", "https://127.0.0.1:8080/api/me", -1},
		{"GET", "http://evil.test/api/me", -1},
	}
	for _, tc := range cases {
		u, _ := url.Parse(tc.url)
		if got := p.matchStub(origin, tc.method, u); got != tc.want {
			t.Errorf("matchStub(%s %s) = %d, want %d", tc.method, tc.url, got, tc.want)
		}
	}
}

// A scheme's default port written out is the same origin.
func TestSameUnlockOriginDefaultPort(t *testing.T) {
	origin, err := parseUnlockOrigin("https://App.test")
	if err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]bool{
		"https://app.test:443/x": true,
		"https://APP.test/x":     true,
		"http://app.test:443/x":  false,
		"https://app.test:8443/": false,
	} {
		u, _ := url.Parse(raw)
		if got := sameUnlockOrigin(origin, u); got != want {
			t.Errorf("sameUnlockOrigin(%s) = %v, want %v", raw, got, want)
		}
	}
	p := mustProfile(t, `{"origin":"https://app.test","routes":["/a","https://app.test:443/b"]}`)
	if got, want := strings.Join(p.Targets(), " "), "https://app.test/ https://app.test/a https://app.test:443/b"; got != want {
		t.Errorf("Targets() = %q, want %q", got, want)
	}
}

// The seed literal is one JSON string: whatever the profile holds, the script
// source around it cannot be closed or escaped from.
func TestUnlockSeedJSONIsADataLiteral(t *testing.T) {
	p := mustProfile(t, `{"origin":"https://a.test","localStorage":{"k":"\"); alert(1); (\"","x":"</script><script>alert(2)</script>"},
		"sessionStorage":{"line":"a b"}}`)
	lit, err := unlockSeedJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(lit[1:len(lit)-1], "<> ") || strings.Count(lit, `"`)-strings.Count(lit, `\"`) != 2 {
		t.Fatalf("literal is not a closed, escaped string: %s", lit)
	}
	var inner string
	if err := json.Unmarshal([]byte(lit), &inner); err != nil {
		t.Fatalf("literal does not decode as a string: %v", err)
	}
	var doc struct {
		Origin         string            `json:"origin"`
		LocalStorage   map[string]string `json:"localStorage"`
		SessionStorage map[string]string `json:"sessionStorage"`
	}
	if err := json.Unmarshal([]byte(inner), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Origin != "https://a.test" || doc.LocalStorage["k"] != `"); alert(1); ("` || doc.SessionStorage["line"] != "a b" {
		t.Errorf("seeds did not round-trip: %+v", doc)
	}
}

func newTestWalk(t *testing.T, doc string, allowWrites bool) (*unlockWalk, *memWalkSink) {
	t.Helper()
	p := mustProfile(t, doc)
	origin, _ := url.Parse(p.Origin)
	sink := &memWalkSink{}
	w := &unlockWalk{
		ctx: t.Context(), cfg: UnlockWalkConfig{Profile: p, Sink: sink, AllowWrites: allowWrites},
		profile: p, origin: origin, buckets: []*unlockBucket{{}}, stubHits: make([]int, len(p.Stubs)),
		stored: map[string]storedExchange{},
	}
	return w, sink
}

func paused(method, rawURL string, rt proto.NetworkResourceType, body string) *proto.FetchRequestPaused {
	return &proto.FetchRequestPaused{
		RequestID:    "r1",
		ResourceType: rt,
		Request: &proto.NetworkRequest{Method: method, URL: rawURL, PostData: body,
			Headers: proto.NetworkHeaders{"Content-Type": gson.New("application/json"), "Authorization": gson.New("Bearer forged")}},
	}
}

// decide stubs, fails and continues by the profile; the writer then drops
// what was stubbed or never sent, whatever order its events arrive in.
func TestUnlockWalkDecideAndWrite(t *testing.T) {
	w, sink := newTestWalk(t, `{"origin":"http://app.test","stubs":[{"method":"GET","path":"/api/me","status":200,"contentType":"application/json","body":"{\"role\":\"admin\"}"}]}`, false)

	d := w.decide(paused("GET", "http://app.test/api/me", proto.NetworkResourceTypeFetch, ""))
	if d.Verdict != browser.InterceptFulfill || d.Status != 200 || string(d.Body) != `{"role":"admin"}` || d.ContentType != "application/json" {
		t.Errorf("stub decision = %+v", d)
	}
	d = w.decide(paused("POST", "http://app.test/api/admin/audit", proto.NetworkResourceTypeFetch, `{"event":"view"}`))
	if d.Verdict != browser.InterceptFail {
		t.Errorf("write decision = %+v, want fail", d)
	}
	if d = w.decide(paused("POST", "http://tracker.test/collect", proto.NetworkResourceTypePing, "x")); d.Verdict != browser.InterceptFail {
		t.Errorf("third-party write decision = %+v, want fail", d)
	}
	if d = w.decide(paused("GET", "http://app.test/api/admin/users", proto.NetworkResourceTypeXHR, "")); d.Verdict != browser.InterceptContinue {
		t.Errorf("read decision = %+v, want continue", d)
	}
	if d = w.decide(paused("GET", "http://app.test/static/app.js", proto.NetworkResourceTypeScript, "")); d.Verdict != browser.InterceptContinue {
		t.Errorf("asset decision = %+v, want continue", d)
	}

	b := w.buckets[0]
	if len(b.stubs) != 1 || b.stubs[0].Stub != 0 {
		t.Errorf("stub hits = %+v", b.stubs)
	}
	if len(b.aborted) != 1 || b.aborted[0].Method != "POST" || b.aborted[0].Body != `{"event":"view"}` ||
		b.aborted[0].ContentType != "application/json" || strings.Join(b.aborted[0].HeaderNames, ",") != "authorization,content-type" {
		t.Errorf("aborted = %+v", b.aborted)
	}
	if w.abortedOutOfScope != 1 {
		t.Errorf("abortedOutOfScope = %d, want 1", w.abortedOutOfScope)
	}
	if len(b.requests) != 1 || b.requests[0].URL != "http://app.test/api/admin/users" {
		t.Errorf("requests = %+v (the script is stored, not listed)", b.requests)
	}

	entry := func(method, u string, status int) *network.TrafficEntry {
		return &network.TrafficEntry{Request: network.RequestData{Method: method, URL: u, Headers: map[string]string{}},
			Response: &network.ResponseData{Status: status, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{}`)}}
	}
	for _, e := range []*network.TrafficEntry{
		entry("GET", "http://app.test/api/me", 200),           // the stub's response
		entry("POST", "http://app.test/api/admin/audit", 200), // a write (never sent)
		entry("GET", "http://cdn.test/lib.js", 200),           // off origin, no scope
		{Request: network.RequestData{Method: "GET", URL: "http://app.test/gone"}, Error: "net::ERR_FAILED"},
		entry("GET", "http://app.test/api/admin/users", 200), // real
	} {
		if err := w.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.urls) != 1 || sink.urls[0] != "http://app.test/api/admin/users" {
		t.Fatalf("stored %v, want only the real admin read", sink.urls)
	}

	res := &UnlockWalkResult{}
	w.finish(res)
	if got := res.Landing.Requests; len(got) != 1 || got[0].RecordUUID != "rec-1" || got[0].Status != 200 {
		t.Errorf("landing requests = %+v", got)
	}
	if res.Totals.RecordsStored != 1 || res.Totals.AbortedWrites != 1 || res.Totals.AbortedOutOfScope != 1 || res.Totals.StubsHit != 1 {
		t.Errorf("totals = %+v", res.Totals)
	}
	if len(res.StubsNeverHit) != 0 {
		t.Errorf("stubs_never_hit = %+v", res.StubsNeverHit)
	}
}

// With a write grant, an in-scope write reaches the target and its exchange
// is stored; an out-of-scope write is still failed.
func TestUnlockWalkAllowWrites(t *testing.T) {
	w, sink := newTestWalk(t, `{"origin":"http://app.test"}`, true)
	if d := w.decide(paused("POST", "http://app.test/api/audit", proto.NetworkResourceTypeFetch, "{}")); d.Verdict != browser.InterceptContinue {
		t.Errorf("granted write = %+v, want continue", d)
	}
	if d := w.decide(paused("POST", "http://tracker.test/collect", proto.NetworkResourceTypeFetch, "{}")); d.Verdict != browser.InterceptFail {
		t.Errorf("out-of-scope write = %+v, want fail", d)
	}
	_ = w.Write(&network.TrafficEntry{Request: network.RequestData{Method: "POST", URL: "http://app.test/api/audit"},
		Response: &network.ResponseData{Status: 201}})
	if len(sink.urls) != 1 {
		t.Errorf("stored %v, want the granted write", sink.urls)
	}
}

func TestSameRouteTarget(t *testing.T) {
	target, _ := url.Parse("http://app.test/admin")
	hash, _ := url.Parse("http://app.test/#/admin")
	cases := []struct {
		target *url.URL
		final  string
		want   bool
	}{
		{target, "http://app.test/admin", true},
		{target, "http://app.test/admin/", true},
		{target, "http://app.test/admin?tab=1", true},
		{target, "http://app.test/login", false},
		{target, "http://other.test/admin", false},
		{hash, "http://app.test/#/admin", true},
		{hash, "http://app.test/#/login", false},
	}
	for _, tc := range cases {
		if got := sameRouteTarget(tc.target, tc.final); got != tc.want {
			t.Errorf("sameRouteTarget(%s, %s) = %v, want %v", tc.target, tc.final, got, tc.want)
		}
	}
}

// memWalkSink records what a walk stored, handing out rec-N ids.
type memWalkSink struct {
	urls []string
}

func (m *memWalkSink) SaveUnlockWalkRecord(_ context.Context, rr *httpmsg.HttpRequestResponse) (string, error) {
	u, err := rr.URL()
	if err != nil {
		return "", err
	}
	m.urls = append(m.urls, u.String())
	return "rec-" + strconv.Itoa(len(m.urls)), nil
}
