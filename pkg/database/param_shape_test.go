package database

import "testing"

func TestParamShapeRepresentative(t *testing.T) {
	cases := []struct {
		name        string
		desc        recordURLDesc
		coalescable bool
		wantSameKey *recordURLDesc // optional: another record whose shape key should match
	}{
		{"get with query is coalescable", recordURLDesc{method: "GET", url: "https://a.com/search?q=1"}, true,
			&recordURLDesc{method: "GET", url: "https://a.com/search?q=2"}},
		{"get without query is not", recordURLDesc{method: "GET", url: "https://a.com/about"}, false, nil},
		{"post with unseen body is not coalescable", recordURLDesc{method: "POST", url: "https://a.com/search?q=1"}, false, nil},
		{"put with unseen body is not coalescable", recordURLDesc{method: "PUT", url: "https://a.com/x?a=1"}, false, nil},
		{"method case insensitive", recordURLDesc{method: "get", url: "https://a.com/s?x=1"}, true, nil},
		// POST whose form body shape is visible via stored params IS coalescable.
		{"post with form body is coalescable",
			recordURLDesc{method: "POST", url: "https://a.com/login", contentType: "application/x-www-form-urlencoded",
				params: []EmbeddedParam{{Name: "user", Value: "a", Type: "body"}, {Name: "pass", Value: "1", Type: "body"}}},
			true,
			&recordURLDesc{method: "POST", url: "https://a.com/login", contentType: "application/x-www-form-urlencoded",
				params: []EmbeddedParam{{Name: "user", Value: "b", Type: "body"}, {Name: "pass", Value: "2", Type: "body"}}}},
		// JSON body shape via stored json params.
		{"post with json body is coalescable",
			recordURLDesc{method: "POST", url: "https://a.com/api", contentType: "application/json",
				params: []EmbeddedParam{{Name: "name", Value: "x", Type: "json"}}},
			true, nil},
		// Multipart (file-upload risk) is never coalesced even with body params.
		{"multipart is not coalescable",
			recordURLDesc{method: "POST", url: "https://a.com/upload", contentType: "multipart/form-data; boundary=z",
				params: []EmbeddedParam{{Name: "file", Value: "x", Type: "body"}}},
			false, nil},
		// A body-bearing content length with no visible params is an unseen body.
		{"non-zero body with no params is not coalescable",
			recordURLDesc{method: "POST", url: "https://a.com/x", contentLength: 42}, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, _, coalescable := paramShapeRepresentative(tc.desc)
			if coalescable != tc.coalescable {
				t.Fatalf("coalescable = %v, want %v", coalescable, tc.coalescable)
			}
			if tc.wantSameKey != nil {
				key2, _, _ := paramShapeRepresentative(*tc.wantSameKey)
				if key != key2 {
					t.Errorf("shape keys differ for value-only-different records: %q vs %q", key, key2)
				}
			}
		})
	}
}

func TestParamShapeRepresentative_DistinguishesShapes(t *testing.T) {
	rep := func(method, rawURL string) (string, string, bool) {
		return paramShapeRepresentative(recordURLDesc{method: method, url: rawURL})
	}
	// Different param-name sets => different shape keys.
	k1, _, _ := rep("GET", "https://a.com/p?id=1")
	k2, _, _ := rep("GET", "https://a.com/p?id=1&debug=1")
	if k1 == k2 {
		t.Error("different param-name sets must produce different shape keys")
	}
	// Same names, different order => same key; value differences => same key.
	k3, v3, _ := rep("GET", "https://a.com/p?a=1&b=2")
	k4, v4, _ := rep("GET", "https://a.com/p?b=9&a=8")
	if k3 != k4 {
		t.Error("param order must not affect the shape key")
	}
	if v3 == v4 {
		t.Error("different values must produce different value signatures")
	}
	// Different host or path => different shape.
	k5, _, _ := rep("GET", "https://b.com/p?a=1")
	if k3 == k5 {
		t.Error("different host must produce a different shape key")
	}
	// Same path+params but different method => different shape (GET ?a=1 vs a
	// form POST with a body param a) must not collapse together.
	getKey, _, _ := rep("GET", "https://a.com/r?a=1")
	postKey, _, postOK := paramShapeRepresentative(recordURLDesc{
		method: "POST", url: "https://a.com/r", contentType: "application/x-www-form-urlencoded",
		params: []EmbeddedParam{{Name: "a", Value: "1", Type: "body"}},
	})
	if !postOK || getKey == postKey {
		t.Error("different methods must produce different shape keys")
	}
}

func TestCoalesceUUIDsByParamShape(t *testing.T) {
	desc := map[string]recordURLDesc{
		// Same shape /search?q=*, 5 value-distinct GETs.
		"u1": {method: "GET", url: "https://a.com/search?q=1"},
		"u2": {method: "GET", url: "https://a.com/search?q=2"},
		"u3": {method: "GET", url: "https://a.com/search?q=3"},
		"u4": {method: "GET", url: "https://a.com/search?q=4"},
		"u5": {method: "GET", url: "https://a.com/search?q=1"}, // identical value to u1
		// A different shape (extra param) — kept independently.
		"u6": {method: "GET", url: "https://a.com/search?q=1&page=2"},
		// A POST — never coalesced.
		"u7": {method: "POST", url: "https://a.com/search?q=1"},
		// A param-less GET — never coalesced.
		"u8": {method: "GET", url: "https://a.com/about"},
		// Unknown UUID (not in desc) — always kept.
	}
	uuids := []string{"u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "unknown"}

	kept, dropped := coalesceUUIDsByParamShape(uuids, desc, 3)

	// u1,u2,u3 kept (3 value-distinct); u4 dropped (cap); u5 dropped (dup of u1).
	// u6 (distinct shape), u7 (POST), u8 (no query), unknown all kept.
	wantKept := map[string]bool{"u1": true, "u2": true, "u3": true, "u6": true, "u7": true, "u8": true, "unknown": true}
	if len(kept) != len(wantKept) {
		t.Fatalf("kept = %v, want %d entries", kept, len(wantKept))
	}
	for _, k := range kept {
		if !wantKept[k] {
			t.Errorf("unexpected kept uuid %q", k)
		}
	}
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2 (u4 cap + u5 dup)", dropped)
	}

	// Order is preserved.
	if kept[0] != "u1" || kept[1] != "u2" || kept[2] != "u3" {
		t.Errorf("order not preserved: %v", kept)
	}
}

func TestCoalesceUUIDsByParamShape_Disabled(t *testing.T) {
	desc := map[string]recordURLDesc{
		"u1": {method: "GET", url: "https://a.com/s?q=1"},
		"u2": {method: "GET", url: "https://a.com/s?q=2"},
	}
	uuids := []string{"u1", "u2"}
	kept, dropped := coalesceUUIDsByParamShape(uuids, desc, 0)
	if len(kept) != 2 || dropped != 0 {
		t.Errorf("maxSamples=0 must be a no-op, got kept=%v dropped=%d", kept, dropped)
	}
}

func TestCoalesceUUIDsByParamShape_PriorityOrderWins(t *testing.T) {
	// When the input is in priority order, the first (highest-priority) samples
	// claim the cap. Here u_hi appears before the lower-priority same-value u_lo.
	desc := map[string]recordURLDesc{
		"hi": {method: "GET", url: "https://a.com/s?q=1"},
		"lo": {method: "GET", url: "https://a.com/s?q=1"}, // same value
	}
	kept, dropped := coalesceUUIDsByParamShape([]string{"hi", "lo"}, desc, 3)
	if len(kept) != 1 || kept[0] != "hi" || dropped != 1 {
		t.Errorf("priority record must win the slot, got kept=%v dropped=%d", kept, dropped)
	}
}
