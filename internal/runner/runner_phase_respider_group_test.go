package runner

import "testing"

// TestGroupReSpiderSeedsByHost verifies seeds are grouped by host, preserving
// first-appearance host order and each host's original (score) seed order — so a
// per-host browser session crawls a host's seeds consecutively without reordering
// across hosts.
func TestGroupReSpiderSeedsByHost(t *testing.T) {
	chosen := []respiderSeed{
		{url: "https://a.example/1", hostKey: "a.example", score: 90},
		{url: "https://b.example/1", hostKey: "b.example", score: 80},
		{url: "https://a.example/2", hostKey: "a.example", score: 70},
		{url: "https://c.example/1", hostKey: "c.example", score: 60},
		{url: "https://b.example/2", hostKey: "b.example", score: 50},
	}

	groups := groupReSpiderSeedsByHost(chosen)

	if len(groups) != 3 {
		t.Fatalf("expected 3 host groups, got %d", len(groups))
	}
	// First-appearance host order: a, b, c.
	wantHosts := []string{"a.example", "b.example", "c.example"}
	for i, g := range groups {
		if g[0].hostKey != wantHosts[i] {
			t.Errorf("group %d host = %q, want %q", i, g[0].hostKey, wantHosts[i])
		}
		for _, s := range g {
			if s.hostKey != g[0].hostKey {
				t.Errorf("group %d mixes hosts: %q vs %q", i, s.hostKey, g[0].hostKey)
			}
		}
	}
	// Within-host order preserved (a: /1 then /2; b: /1 then /2).
	if len(groups[0]) != 2 || groups[0][0].url != "https://a.example/1" || groups[0][1].url != "https://a.example/2" {
		t.Errorf("host a group order wrong: %+v", groups[0])
	}
	if len(groups[1]) != 2 || groups[1][0].url != "https://b.example/1" || groups[1][1].url != "https://b.example/2" {
		t.Errorf("host b group order wrong: %+v", groups[1])
	}
	if len(groups[2]) != 1 {
		t.Errorf("host c should have 1 seed, got %d", len(groups[2]))
	}
}

func TestGroupReSpiderSeedsByHostEmpty(t *testing.T) {
	if groups := groupReSpiderSeedsByHost(nil); len(groups) != 0 {
		t.Errorf("expected no groups for nil input, got %d", len(groups))
	}
}
