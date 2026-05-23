package database

import (
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestScopeEvaluator(t *testing.T) {
	// No rules → everything in scope.
	empty := NewScopeEvaluator(nil)
	if !empty.IsInScope("https", "any.host", 443, "GET", "/x") {
		t.Error("empty evaluator should allow everything")
	}

	rules := []*Scope{
		{Name: "block-images", RuleType: "exclude", PathPattern: "/*.png", Priority: 1, Enabled: true},
		{Name: "include-app", RuleType: "include", HostPattern: "app.example.com", Methods: []string{"GET", "POST"}, Schemes: []string{"https"}, Ports: []int{443}, Priority: 2, Enabled: true},
		{Name: "disabled", RuleType: "include", HostPattern: "*", Enabled: false},
	}
	e := NewScopeEvaluator(rules)

	// Matches exclude rule first (first match wins).
	if e.IsInScope("https", "app.example.com", 443, "GET", "/logo.png") {
		t.Error("png path should be excluded")
	}
	// Matches include rule.
	if !e.IsInScope("https", "app.example.com", 443, "POST", "/api") {
		t.Error("app.example.com POST should be included")
	}
	// Wrong scheme → no include match → default exclude.
	if e.IsInScope("http", "app.example.com", 443, "GET", "/api") {
		t.Error("http scheme should not match https-only include")
	}
	// Unknown host → default exclude.
	if e.IsInScope("https", "evil.example.com", 443, "GET", "/api") {
		t.Error("unknown host should default to exclude")
	}
	// Wrong port → no match.
	if e.IsInScope("https", "app.example.com", 8080, "GET", "/api") {
		t.Error("wrong port should not match include")
	}
	// Wrong method → no match.
	if e.IsInScope("https", "app.example.com", 443, "DELETE", "/api") {
		t.Error("DELETE should not match GET/POST include")
	}
}

func TestHasDynamicSegment(t *testing.T) {
	cases := map[string]bool{
		"/users/123":      true,
		"/v1/users":       false,
		"/static/app.css": false,
		"/items/550e8400-e29b-41d4-a716-446655440000": true,
		"/a/deadbeefcafe": true, // long hex
		"/":               false,
	}
	for path, want := range cases {
		if got := HasDynamicSegment(path); got != want {
			t.Errorf("HasDynamicSegment(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestRecordToHttpRequestResponse(t *testing.T) {
	rec := &HTTPRecord{
		Scheme:      "https",
		Hostname:    "conv.example.com",
		URL:         "https://conv.example.com/path?q=1",
		RawRequest:  []byte("GET /path?q=1 HTTP/1.1\r\nHost: conv.example.com\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhi"),
		HasResponse: true,
	}
	rr, err := RecordToHttpRequestResponse(rec)
	if err != nil {
		t.Fatalf("RecordToHttpRequestResponse: %v", err)
	}
	if rr.Request() == nil {
		t.Fatal("converted request is nil")
	}
	u, err := rr.URL()
	if err != nil {
		t.Fatalf("URL: %v", err)
	}
	if !strings.Contains(u.String(), "conv.example.com") {
		t.Errorf("URL not preserved: %s", u.String())
	}
	if rr.Response() == nil {
		t.Error("response should be attached")
	}

	// Fallback path: URL only, no raw request.
	rec2 := &HTTPRecord{URL: "https://fallback.example.com/"}
	if _, err := RecordToHttpRequestResponse(rec2); err != nil {
		t.Errorf("RecordToHttpRequestResponse(url-only): %v", err)
	}
}

func TestGetStatsAndTopHostsAndFormat(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordP(t, repo, DefaultProjectUUID, "GET", "stats.example.com", "/a", 200)
	insertRecordP(t, repo, DefaultProjectUUID, "POST", "stats.example.com", "/b", 404)
	insertRecordP(t, repo, DefaultProjectUUID, "GET", "other.example.com", "/c", 500)
	saveFindingP(t, repo, DefaultProjectUUID, "mod", SeverityHigh)

	filters := QueryFilters{ProjectUUID: DefaultProjectUUID}

	stats, err := db.GetStats(ctx, filters)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.Records.HTTPRecords != 3 {
		t.Errorf("stats http records = %d, want 3", stats.Records.HTTPRecords)
	}
	if stats.Findings.Total != 1 {
		t.Errorf("stats findings total = %d, want 1", stats.Findings.Total)
	}
	if stats.HTTPMethods["GET"] != 2 {
		t.Errorf("GET count = %d, want 2", stats.HTTPMethods["GET"])
	}
	if stats.StatusCodes.Success != 1 || stats.StatusCodes.ClientErr != 1 || stats.StatusCodes.ServerErr != 1 {
		t.Errorf("status breakdown wrong: %+v", stats.StatusCodes)
	}

	topHosts, err := db.GetTopHosts(ctx, filters, 10)
	if err != nil {
		t.Fatalf("GetTopHosts: %v", err)
	}
	if len(topHosts) != 2 {
		t.Errorf("GetTopHosts = %d, want 2", len(topHosts))
	}

	// FormatStats should produce non-empty output.
	out := FormatStats(stats)
	if out == "" {
		t.Error("FormatStats returned empty string")
	}
}

func TestFromHttpRequestResponseRoundTrip(t *testing.T) {
	// Sanity that the conversion used elsewhere produces a usable record.
	rr, err := httpmsg.ParseRawRequest("GET /probe HTTP/1.1\r\nHost: rt.example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	rec := &HTTPRecord{}
	if err := rec.FromHttpRequestResponse(rr); err != nil {
		t.Fatalf("FromHttpRequestResponse: %v", err)
	}
	if rec.Hostname != "rt.example.com" || rec.Method != "GET" {
		t.Errorf("conversion wrong: host=%q method=%q", rec.Hostname, rec.Method)
	}
}
