package agent

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestExtractPlanReferencedPaths_DedupesAndStrips(t *testing.T) {
	plan := &SwarmPlan{
		FocusAreas: []string{
			"SQLi in /api/users?id=",
			"IDOR in basket (GET /rest/basket/:id)",
			"/api/users/", // dup of above (trailing slash)
		},
		Notes: "Also check /admin/login and /api/users for privilege escalation.",
	}
	got := extractPlanReferencedPaths(plan)
	wantSet := map[string]bool{
		"/api/users":   true,
		"/rest/basket": true,
		"/admin/login": true,
	}
	for _, p := range got {
		if !wantSet[p] {
			// Allow /rest/basket/:id-style with the colon stripped — the
			// regex character class excludes `:` so it should land as
			// "/rest/basket" — fine. But unknown paths shouldn't appear.
			t.Errorf("unexpected planner-referenced path %q", p)
		}
		delete(wantSet, p)
	}
	for want := range wantSet {
		t.Errorf("missing expected path %q in: %v", want, got)
	}
}

func TestFilterUntestedPaths_OnlyKeepsUntested(t *testing.T) {
	// Records (after trim): {"/api/users/profile", "/api/users"}
	// Inputs: /api/users (exact match → covered),
	//         /admin/dashboard (untested),
	//         /api/users/profile (exact match → covered).
	// Only /admin/dashboard should survive.
	records := []*httpmsg.HttpRequestResponse{
		mkRecord(t, "GET", "/api/users/profile"),
		mkRecord(t, "GET", "/api/users/"),
	}
	in := []string{"/api/users", "/admin/dashboard", "/api/users/profile"}
	got := filterUntestedPaths(in, records)
	if len(got) != 1 || got[0] != "/admin/dashboard" {
		t.Fatalf("expected just [/admin/dashboard] untested, got %v", got)
	}
}

func TestFilterUntestedPaths_AllUntestedWhenNoRecords(t *testing.T) {
	in := []string{"/a", "/b"}
	if got := filterUntestedPaths(in, nil); len(got) != 2 {
		t.Errorf("with no records, all inputs are untested; got %v", got)
	}
}

func TestResolvePathsToURLs_BuildsAbsolute(t *testing.T) {
	urls := resolvePathsToURLs("https://target.test:8443/ignored", []string{"/admin", "billing/x"}, 10)
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %v", len(urls), urls)
	}
	if urls[0] != "https://target.test:8443/admin" {
		t.Errorf("URL 0: want https://target.test:8443/admin, got %q", urls[0])
	}
	if urls[1] != "https://target.test:8443/billing/x" {
		t.Errorf("URL 1: want https://target.test:8443/billing/x, got %q", urls[1])
	}
}

func TestResolvePathsToURLs_CapEnforced(t *testing.T) {
	urls := resolvePathsToURLs("https://t.test", []string{"/a", "/b", "/c", "/d"}, 2)
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs (cap=2), got %d: %v", len(urls), urls)
	}
}

func TestResolvePathsToURLs_RejectsEmpty(t *testing.T) {
	if got := resolvePathsToURLs("", []string{"/a"}, 5); got != nil {
		t.Errorf("expected nil for empty target, got: %v", got)
	}
	if got := resolvePathsToURLs("https://t.test", nil, 5); got != nil {
		t.Errorf("expected nil for empty paths, got: %v", got)
	}
}
