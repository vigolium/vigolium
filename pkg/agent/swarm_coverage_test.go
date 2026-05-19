package agent

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func mkRecord(t *testing.T, method, path string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := []byte(method + " " + path + " HTTP/1.1\r\nHost: x.test\r\n\r\n")
	req := httpmsg.NewHttpRequest(raw)
	return httpmsg.NewHttpRequestResponse(req, nil)
}

func TestAnalyzePlanCoverage_FullCoverage(t *testing.T) {
	plan := &SwarmPlan{
		FocusAreas: []string{
			"SQL injection in /api/users",
			"XSS in /api/products",
		},
	}
	records := []*httpmsg.HttpRequestResponse{
		mkRecord(t, "POST", "/api/users/login"),
		mkRecord(t, "GET", "/api/products/list"),
	}
	cov := AnalyzePlanCoverage(plan, records)
	if len(cov.MissingPrefixes) != 0 {
		t.Errorf("expected zero missing prefixes, got: %+v", cov.MissingPrefixes)
	}
	if cov.CoveredPrefixes != 2 {
		t.Errorf("expected 2 covered prefixes, got %d", cov.CoveredPrefixes)
	}
}

func TestAnalyzePlanCoverage_PartialCoverage(t *testing.T) {
	plan := &SwarmPlan{
		FocusAreas: []string{"SQL injection in /api/users"},
		Notes:      "Focus on the user-facing API only.",
	}
	records := []*httpmsg.HttpRequestResponse{
		mkRecord(t, "POST", "/api/users/login"),
		mkRecord(t, "GET", "/admin/dashboard"),
		mkRecord(t, "GET", "/billing/invoices"),
		mkRecord(t, "GET", "/api/users/profile"), // same cluster as 1st
	}
	cov := AnalyzePlanCoverage(plan, records)
	wantMissing := map[string]bool{"/admin/dashboard": true, "/billing/invoices": true}
	if len(cov.MissingPrefixes) != len(wantMissing) {
		t.Fatalf("missing prefixes: want %d, got %d (%v)", len(wantMissing), len(cov.MissingPrefixes), cov.MissingPrefixes)
	}
	for _, p := range cov.MissingPrefixes {
		if !wantMissing[p] {
			t.Errorf("unexpected missing prefix %q", p)
		}
	}
}

func TestAnalyzePlanCoverage_ParentPathCoversChildren(t *testing.T) {
	// Plan mentions "/api" as a top-level focus; records under "/api/users"
	// should be considered covered through parent-path matching.
	plan := &SwarmPlan{FocusAreas: []string{"Review /api authorization boundaries"}}
	records := []*httpmsg.HttpRequestResponse{
		mkRecord(t, "GET", "/api/users/1"),
		mkRecord(t, "GET", "/api/products/foo"),
	}
	cov := AnalyzePlanCoverage(plan, records)
	if len(cov.MissingPrefixes) != 0 {
		t.Errorf("/api parent should cover /api/* clusters, got missing: %+v", cov.MissingPrefixes)
	}
}

func TestAnalyzePlanCoverage_RootPrefixNotOverbroad(t *testing.T) {
	// Records under "/" alone should not be treated as covering arbitrary
	// other prefixes. (Older logic could match every prefix as a sub-path
	// of "/" and silently report 0 missing.)
	plan := &SwarmPlan{FocusAreas: []string{"Investigate /."}}
	records := []*httpmsg.HttpRequestResponse{
		mkRecord(t, "GET", "/admin/dashboard"),
	}
	cov := AnalyzePlanCoverage(plan, records)
	if cov.CoveredPrefixes == 1 {
		t.Errorf("'/' should not cover /admin via parent-prefix match — got coverage=%+v", cov)
	}
}

func TestAnalyzePlanCoverage_NilPlanIsZero(t *testing.T) {
	cov := AnalyzePlanCoverage(nil, []*httpmsg.HttpRequestResponse{mkRecord(t, "GET", "/x")})
	if cov.TotalPrefixes != 0 || len(cov.MissingPrefixes) != 0 {
		t.Errorf("nil plan should yield empty coverage, got: %+v", cov)
	}
}

func TestRecordsForPrefixes_FiltersAndPreservesOrder(t *testing.T) {
	records := []*httpmsg.HttpRequestResponse{
		mkRecord(t, "GET", "/api/users/1"),
		mkRecord(t, "POST", "/admin/login"),
		mkRecord(t, "GET", "/api/users/2"),
		mkRecord(t, "GET", "/static/style.css"),
	}
	got := RecordsForPrefixes(records, []string{"/api/users", "/admin/login"})
	if len(got) != 3 {
		t.Errorf("expected 3 records, got %d", len(got))
	}
	// Order must match input order.
	if got[0].Request().Path() != "/api/users/1" {
		t.Errorf("expected /api/users/1 first, got %q", got[0].Request().Path())
	}
	if got[1].Request().Path() != "/admin/login" {
		t.Errorf("expected /admin/login second, got %q", got[1].Request().Path())
	}
}

func TestPlanMentionedPrefixes_PicksOutPaths(t *testing.T) {
	plan := &SwarmPlan{
		FocusAreas: []string{
			"SQL injection in /rest/user/login (POST)",
			"IDOR in basket (GET /rest/basket/:id)",
		},
		Notes: "Also check /admin/users for privilege escalation.",
	}
	got := planMentionedPrefixes(plan)
	for _, want := range []string{"/rest/user", "/rest/basket", "/admin/users"} {
		if !got[want] {
			t.Errorf("expected mentioned prefix %q in: %v", want, got)
		}
	}
}
