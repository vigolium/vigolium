package fragment

import "testing"

func TestNewExtractorDefaults(t *testing.T) {
	e := NewExtractor()
	if len(e.selectors) == 0 {
		t.Error("default selectors should be populated")
	}
	if e.minWidth != 50 || e.minHeight != 50 {
		t.Errorf("min size = (%v, %v), want (50, 50)", e.minWidth, e.minHeight)
	}
	if e.minSubtree != 4 {
		t.Errorf("minSubtree = %d, want 4", e.minSubtree)
	}
	if e.maxFragments != 100 {
		t.Errorf("maxFragments = %d, want 100", e.maxFragments)
	}
}

func TestExtractorBuilders(t *testing.T) {
	sel := []string{"div", "section"}
	e := NewExtractor().
		WithSelectors(sel).
		WithMinSize(10, 20).
		WithMinSubtree(2).
		WithMaxFragments(7)

	if len(e.selectors) != 2 {
		t.Errorf("selectors len = %d, want 2", len(e.selectors))
	}
	if e.minWidth != 10 || e.minHeight != 20 {
		t.Errorf("min size = (%v, %v), want (10, 20)", e.minWidth, e.minHeight)
	}
	if e.minSubtree != 2 {
		t.Errorf("minSubtree = %d, want 2", e.minSubtree)
	}
	if e.maxFragments != 7 {
		t.Errorf("maxFragments = %d, want 7", e.maxFragments)
	}
}

func TestExtractorGetters(t *testing.T) {
	m := map[string]interface{}{
		"name":   "header",
		"id":     float64(12),
		"width":  float64(3.5),
		"absent": nil,
	}

	if getString(m, "name") != "header" {
		t.Errorf("getString = %q, want header", getString(m, "name"))
	}
	if getString(m, "missing") != "" {
		t.Error("getString of missing key should be empty")
	}
	// Wrong type returns zero value.
	if getString(m, "id") != "" {
		t.Error("getString of non-string should be empty")
	}

	if getInt(m, "id") != 12 {
		t.Errorf("getInt = %d, want 12", getInt(m, "id"))
	}
	if getInt(m, "missing") != 0 {
		t.Error("getInt of missing key should be 0")
	}

	if getFloat(m, "width") != 3.5 {
		t.Errorf("getFloat = %v, want 3.5", getFloat(m, "width"))
	}
	if getFloat(m, "missing") != 0 {
		t.Error("getFloat of missing key should be 0")
	}
}

func TestExtractorParseFragment(t *testing.T) {
	e := NewExtractor()
	data := map[string]interface{}{
		"id":          float64(5),
		"xpath":       "/html/body/header",
		"subtreeSize": float64(12),
		"selector":    "header",
		"tagName":     "HEADER",
		"domHash":     "deadbeef",
		"contentHash": "cafebabe",
		"parentID":    float64(1),
		"childIDs":    []interface{}{float64(6), float64(7)},
		"rect": map[string]interface{}{
			"x":      float64(0),
			"y":      float64(10),
			"width":  float64(800),
			"height": float64(60),
		},
	}

	frag := e.parseFragment(data)
	if frag == nil {
		t.Fatal("parseFragment returned nil")
	}
	if frag.ID != 5 || frag.XPath != "/html/body/header" || frag.SubtreeSize != 12 {
		t.Errorf("basic fields mismatch: %+v", frag)
	}
	if frag.Selector != "header" || frag.TagName != "HEADER" {
		t.Errorf("selector/tag mismatch: %q %q", frag.Selector, frag.TagName)
	}
	if frag.DOMHash != "deadbeef" || frag.ContentHash != "cafebabe" {
		t.Errorf("hash fields mismatch: %q %q", frag.DOMHash, frag.ContentHash)
	}
	if frag.ParentID != 1 {
		t.Errorf("ParentID = %d, want 1", frag.ParentID)
	}
	if len(frag.ChildIDs) != 2 || frag.ChildIDs[0] != 6 || frag.ChildIDs[1] != 7 {
		t.Errorf("ChildIDs = %v, want [6 7]", frag.ChildIDs)
	}
	if frag.Rect.Width != 800 || frag.Rect.Height != 60 || frag.Rect.Y != 10 {
		t.Errorf("rect mismatch: %+v", frag.Rect)
	}
}

func TestExtractorParseFragmentNoParent(t *testing.T) {
	e := NewExtractor()
	// No parentID key => ParentID defaults to -1.
	frag := e.parseFragment(map[string]interface{}{"id": float64(1), "xpath": "/x"})
	if frag.ParentID != -1 {
		t.Errorf("ParentID = %d, want -1 when absent", frag.ParentID)
	}
}

func TestExtractorParseFragments(t *testing.T) {
	e := NewExtractor()

	// Non-array input yields an empty slice (no error).
	got, err := e.parseFragments("not an array")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("non-array input should produce 0 fragments, got %d", len(got))
	}

	arr := []interface{}{
		map[string]interface{}{"id": float64(1), "xpath": "/a"},
		"not a map", // skipped
		map[string]interface{}{"id": float64(2), "xpath": "/b"},
	}
	frags, err := e.parseFragments(arr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frags) != 2 {
		t.Fatalf("parseFragments len = %d, want 2 (non-map skipped)", len(frags))
	}
	if frags[0].XPath != "/a" || frags[1].XPath != "/b" {
		t.Errorf("parsed xpaths = %q %q, want /a /b", frags[0].XPath, frags[1].XPath)
	}
}
