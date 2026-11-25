package spitolas

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/network"
)

func TestParseUnlockProfileRewritesAndClicks(t *testing.T) {
	p := mustProfile(t, `{"origin":"https://app.test","rewrites":[
		{"method":"get","path":"https://app.test/api/me","status":200,"set":[{"pointer":"/role","value":"admin"}]},
		{"method":"GET","path":"/api/users/:id","set":[{"pointer":"/data/0/admin","value":true}]}]}`)
	if r := p.Rewrites[0]; r.Method != "GET" || r.Path != "/api/me" || r.Status != 200 {
		t.Errorf("rewrite normalised to %+v", r)
	}
	if p.ClicksPerRoute() != DefaultUnlockClicksPerRoute || p.MaxClicksPerRoute == nil {
		t.Errorf("click cap default = %v", p.MaxClicksPerRoute)
	}
	off := mustProfile(t, `{"origin":"https://app.test","maxClicksPerRoute":0}`)
	if off.ClicksPerRoute() != 0 {
		t.Errorf("maxClicksPerRoute 0 must turn clicking off, got %d", off.ClicksPerRoute())
	}
	// The profile round-trips: what Parse fills is what a caller reads back.
	raw, _ := json.Marshal(p)
	if !strings.Contains(string(raw), `"maxClicksPerRoute":6`) || !strings.Contains(string(raw), `"pointer":"/data/0/admin"`) {
		t.Errorf("marshalled profile = %s", raw)
	}
	if _, err := ParseUnlockProfile(raw); err != nil {
		t.Errorf("re-parse of a marshalled profile: %v", err)
	}
}

func TestUnlockRewriteApply(t *testing.T) {
	cases := []struct {
		name, rewrite, body string
		upstream            int
		wantStatus          int
		wantBody, wantErr   string
	}{
		{"status only keeps body", `{"status":200}`, `{"error":"no"}`, 401, 200, `{"error":"no"}`, ""},
		{"set adds a member on a 401", `{"status":200,"set":[{"pointer":"/role","value":"admin"}]}`, `{"error":"no"}`, 401, 200, `{"error":"no","role":"admin"}`, ""},
		{"set replaces, keeps status", `{"set":[{"pointer":"/user/role","value":"admin"}]}`, `{"user":{"role":"guest","id":7}}`, 200, 200, `{"user":{"id":7,"role":"admin"}}`, ""},
		{"array element and append", `{"set":[{"pointer":"/items/0/admin","value":true},{"pointer":"/items/-","value":{"id":2}}]}`, `{"items":[{"id":1,"admin":false}]}`, 200, 200, `{"items":[{"admin":true,"id":1},{"id":2}]}`, ""},
		{"escaped pointer", `{"set":[{"pointer":"/a~1b/c~0d","value":1}]}`, `{"a/b":{"c~d":0}}`, 200, 200, `{"a/b":{"c~d":1}}`, ""},
		{"large numbers survive", `{"set":[{"pointer":"/ok","value":true}]}`, `{"id":12345678901234567890,"ok":false}`, 200, 200, `{"id":12345678901234567890,"ok":true}`, ""},
		{"html is not escaped", `{"set":[{"pointer":"/ok","value":true}]}`, `{"t":"<b>&</b>","ok":false}`, 200, 200, `{"ok":true,"t":"<b>&</b>"}`, ""},
		{"missing container", `{"set":[{"pointer":"/user/role","value":"admin"}]}`, `{"data":{}}`, 200, 0, "", `member "user" does not exist`},
		{"index out of range", `{"set":[{"pointer":"/items/3","value":1}]}`, `{"items":[1]}`, 200, 0, "", "not an element"},
		{"not json", `{"set":[{"pointer":"/role","value":"admin"}]}`, `<html>login</html>`, 200, 0, "", "not JSON"},
		{"scalar parent", `{"set":[{"pointer":"/role/x","value":1}]}`, `{"role":"guest"}`, 200, 0, "", "not an object or an array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r UnlockRewrite
			if err := json.Unmarshal([]byte(tc.rewrite), &r); err != nil {
				t.Fatal(err)
			}
			status, body, err := r.apply(tc.upstream, []byte(tc.body))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if status != tc.wantStatus || string(body) != tc.wantBody {
				t.Errorf("apply = %d %s, want %d %s", status, body, tc.wantStatus, tc.wantBody)
			}
		})
	}

	var r UnlockRewrite
	_ = json.Unmarshal([]byte(`{"set":[{"pointer":"/a","value":1}]}`), &r)
	if _, _, err := r.apply(200, []byte(`{"a":"`+strings.Repeat("x", MaxUnlockRewriteUpstream)+`"}`)); err == nil || !strings.Contains(err.Error(), "over the") {
		t.Errorf("an upstream body over the limit must not be decoded: %v", err)
	}
}

func TestRewriteFetchPatterns(t *testing.T) {
	p := mustProfile(t, `{"origin":"https://app.test","rewrites":[
		{"method":"GET","path":"/api/users/{id}/roles","status":200},
		{"method":"POST","path":"/api/users/{id}/roles","status":200},
		{"method":"GET","path":"/api/a*b","status":200}]}`)
	origin, _ := url.Parse(p.Origin)
	got := p.rewriteFetchPatterns(origin)
	want := []string{`https://app.test/api/users/*/roles*`, `https://app.test/api/a\*b*`}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("patterns = %q, want %q", got, want)
	}
}

// The invariant that makes a rewrite safe: a rewritten answer is never
// evidence. Its request is sent but never listed as a request, its exchange
// is never stored whatever order the capture sees it in, and the walk reports
// it as a rewrite with the upstream status beside the one the page got.
func TestUnlockRewriteIsNeverEvidence(t *testing.T) {
	w, sink := newTestWalk(t, `{"origin":"http://app.test","rewrites":[
		{"method":"GET","path":"/api/me","status":200,"set":[{"pointer":"/role","value":"admin"}]},
		{"method":"GET","path":"/api/menu","set":[{"pointer":"/items/-","value":"admin"}]},
		{"method":"GET","path":"/api/never","status":200}]}`, false)

	if d := w.decide(paused("GET", "http://app.test/api/me", proto.NetworkResourceTypeFetch, "")); d.Verdict != browser.InterceptContinue {
		t.Fatalf("a rewritten request must reach the target: %+v", d)
	}
	if d := w.decide(paused("GET", "http://app.test/api/menu?lang=en", proto.NetworkResourceTypeXHR, "")); d.Verdict != browser.InterceptContinue {
		t.Fatalf("decision = %+v", d)
	}
	if d := w.decide(paused("GET", "http://app.test/api/admin/users", proto.NetworkResourceTypeXHR, "")); d.Verdict != browser.InterceptContinue {
		t.Fatalf("decision = %+v", d)
	}
	if b := w.buckets[0]; len(b.requests) != 1 || !strings.HasSuffix(b.requests[0].URL, "/api/admin/users") {
		t.Fatalf("requests = %+v; a rewritten request is never listed as a request", b.requests)
	}

	respond := func(rawURL string, status int, body string) (browser.InterceptDecision, int, []byte, error) {
		e := paused("GET", rawURL, proto.NetworkResourceTypeFetch, "")
		e.ResponseStatusCode = &status
		d := w.decideResponse(e)
		if d.Verdict != browser.InterceptRewrite {
			return d, 0, nil, nil
		}
		st, out, err := d.Rewrite(status, []byte(body))
		return d, st, out, err
	}
	if _, st, out, err := respond("http://app.test/api/me", 401, `{"error":"not logged in"}`); err != nil || st != 200 || string(out) != `{"error":"not logged in","role":"admin"}` {
		t.Fatalf("rewrite of /api/me = %d %s %v", st, out, err)
	}
	if _, _, _, err := respond("http://app.test/api/menu?lang=en", 200, `<html>`); err == nil {
		t.Fatalf("a rewrite of a non-JSON answer must not apply")
	}
	if d, _, _, _ := respond("http://app.test/api/admin/users", 200, `[]`); d.Verdict != browser.InterceptContinue {
		t.Fatalf("an answer no rewrite matches passes unchanged: %+v", d)
	}

	entry := func(method, u string, status int, body string) *network.TrafficEntry {
		return &network.TrafficEntry{Request: network.RequestData{Method: method, URL: u, Headers: map[string]string{}},
			Response: &network.ResponseData{Status: status, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(body)}}
	}
	for _, e := range []*network.TrafficEntry{
		entry("GET", "http://app.test/api/me", 200, `{"role":"admin"}`), // the rewritten answer
		entry("GET", "http://app.test/api/me", 401, `{"error":"x"}`),    // the upstream answer, had it been seen
		entry("GET", "http://app.test/api/menu?lang=en", 200, `<html>`), // matched, not applied: still not evidence
		entry("GET", "http://app.test/api/admin/users", 200, `[]`),      // real
	} {
		if err := w.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.urls) != 1 || sink.urls[0] != "http://app.test/api/admin/users" {
		t.Fatalf("stored %v, want only the real read: a rewritten exchange is never stored", sink.urls)
	}

	res := &UnlockWalkResult{}
	w.finish(res)
	hits := res.Landing.RewritesHit
	if len(hits) != 2 {
		t.Fatalf("rewrites_hit = %+v", hits)
	}
	if h := hits[0]; h.Rewrite != 0 || !h.Applied || h.UpstreamStatus != 401 || h.Status != 200 || h.Error != "" {
		t.Errorf("hit[0] = %+v", h)
	}
	if h := hits[1]; h.Rewrite != 1 || h.Applied || h.UpstreamStatus != 200 || h.Status != 200 || !strings.Contains(h.Error, "not JSON") {
		t.Errorf("hit[1] = %+v", h)
	}
	if res.Totals.RewritesHit != 2 || res.Totals.RewritesApplied != 1 || res.Totals.RealRequests != 1 || res.Totals.RecordsStored != 1 {
		t.Errorf("totals = %+v", res.Totals)
	}
	if len(res.RewritesNeverHit) != 1 || res.RewritesNeverHit[0].Path != "/api/never" || res.RewritesNeverHit[0].Rewrite != 2 {
		t.Errorf("rewrites_never_hit = %+v", res.RewritesNeverHit)
	}
	for _, q := range res.Landing.Requests {
		if strings.Contains(q.URL, "/api/me") || strings.Contains(q.URL, "/api/menu") {
			t.Errorf("rewritten request listed as real: %+v", q)
		}
	}
}

// A rewrite never lifts the method gate: a write it matches is failed and
// reported by shape like any other, and never reaches the response stage.
func TestUnlockRewriteKeepsTheMethodGate(t *testing.T) {
	w, sink := newTestWalk(t, `{"origin":"http://app.test","rewrites":[{"method":"POST","path":"/api/graphql","status":200}]}`, false)
	if d := w.decide(paused("POST", "http://app.test/api/graphql", proto.NetworkResourceTypeFetch, `{"query":"{me{role}}"}`)); d.Verdict != browser.InterceptFail {
		t.Fatalf("a rewritten write without a grant must be failed: %+v", d)
	}
	if b := w.buckets[0]; len(b.aborted) != 1 {
		t.Fatalf("aborted = %+v", b.aborted)
	}
	_ = w.Write(&network.TrafficEntry{Request: network.RequestData{Method: "POST", URL: "http://app.test/api/graphql"},
		Response: &network.ResponseData{Status: 200}})
	if len(sink.urls) != 0 {
		t.Fatalf("stored %v", sink.urls)
	}

	// With a grant the write is sent, still never listed nor stored.
	w, sink = newTestWalk(t, `{"origin":"http://app.test","rewrites":[{"method":"POST","path":"/api/graphql","status":200}]}`, true)
	if d := w.decide(paused("POST", "http://app.test/api/graphql", proto.NetworkResourceTypeFetch, `{}`)); d.Verdict != browser.InterceptContinue {
		t.Fatalf("decision = %+v", d)
	}
	_ = w.Write(&network.TrafficEntry{Request: network.RequestData{Method: "POST", URL: "http://app.test/api/graphql"},
		Response: &network.ResponseData{Status: 200}})
	if b := w.buckets[0]; len(b.requests) != 0 || len(sink.urls) != 0 {
		t.Fatalf("requests %+v, stored %v", b.requests, sink.urls)
	}
}
