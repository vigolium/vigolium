package fuzz

import "testing"

// Headers the request does not carry are not positions unless asked for.
func TestSyntheticHeadersAreOptIn(t *testing.T) {
	raw := []byte("GET /item?id=1 HTTP/1.1\r\nHost: h\r\nUser-Agent: x\r\n\r\n")
	has := func(ps []Position, name string) bool {
		for _, p := range ps {
			if p.Name == name {
				return true
			}
		}
		return false
	}
	for _, mode := range []string{"all", "headers"} {
		ps, err := ResolvePositions(raw, Selectors{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		if has(ps, "X-Forwarded-For") || has(ps, "Referer") {
			t.Fatalf("--fuzz %s included a synthetic header: %v", mode, ps)
		}
		if !has(ps, "User-Agent") {
			t.Fatalf("--fuzz %s dropped a real header", mode)
		}
	}
	ps, err := ResolvePositions(raw, Selectors{Mode: "headers:synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	if !has(ps, "X-Forwarded-For") {
		t.Fatalf("headers:synthetic left out X-Forwarded-For: %v", ps)
	}
}

func TestNearestMarker(t *testing.T) {
	for raw, want := range map[string]string{
		"GET /item?id=FUZ HTTP/1.1\r\nHost: h\r\n\r\n":   "FUZ",
		"GET /item?id=fuzz HTTP/1.1\r\nHost: h\r\n\r\n":  "fuzz",
		"GET /item?id=FUZZZ HTTP/1.1\r\nHost: h\r\n\r\n": "FUZZZ",
		"GET /item?id=1 HTTP/1.1\r\nHost: h\r\n\r\n":     "",
	} {
		if got := NearestMarker([]byte(raw), DefaultKeyword); got != want {
			t.Errorf("NearestMarker(%q) = %q, want %q", raw, got, want)
		}
	}
}
