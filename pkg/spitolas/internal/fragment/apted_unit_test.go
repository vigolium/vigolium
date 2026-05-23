package fragment

import "testing"

func TestParseAPTEDTreeInvalidType(t *testing.T) {
	// A non-map result is rejected.
	if _, err := parseAPTEDTree("not a map"); err == nil {
		t.Error("parseAPTEDTree should error on non-map input")
	}
}

func TestParseAPTEDTreeErrorField(t *testing.T) {
	// An "error" field surfaces as an error.
	_, err := parseAPTEDTree(map[string]interface{}{"error": "Element not found"})
	if err == nil {
		t.Error("parseAPTEDTree should error when result carries an error field")
	}
}

func TestParseAPTEDTreeSimple(t *testing.T) {
	// Single node, no children.
	tree, err := parseAPTEDTree(map[string]interface{}{"label": "div"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil || tree.Label != "div" {
		t.Fatalf("unexpected tree: %+v", tree)
	}
	if !tree.IsLeaf() {
		t.Error("single node should be a leaf")
	}
}

func TestParseAPTEDTreeNested(t *testing.T) {
	data := map[string]interface{}{
		"label": "div",
		"children": []interface{}{
			map[string]interface{}{"label": "span"},
			map[string]interface{}{
				"label": "ul",
				"children": []interface{}{
					map[string]interface{}{"label": "li"},
				},
			},
			// A malformed child (missing label) is silently skipped.
			map[string]interface{}{"children": []interface{}{}},
		},
	}

	tree, err := parseAPTEDTree(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.Label != "div" {
		t.Errorf("root label = %q, want %q", tree.Label, "div")
	}
	// Two well-formed children (span, ul); the malformed one is skipped.
	if len(tree.Children) != 2 {
		t.Fatalf("children = %d, want 2 (malformed skipped)", len(tree.Children))
	}
	// The ul subtree contributes to the overall size.
	if tree.Size() != 4 { // div + span + ul + li
		t.Errorf("Size() = %d, want 4", tree.Size())
	}
}

func TestParseAPTEDNodeMissingLabel(t *testing.T) {
	if _, err := parseAPTEDNode(map[string]interface{}{}); err == nil {
		t.Error("parseAPTEDNode should error when label is missing")
	}
}

func TestCompareFragmentTreesViaStringInput(t *testing.T) {
	a := StringToAPTEDTree("div{span,p}")
	b := StringToAPTEDTree("div{span,p}")
	if sim := CompareFragmentTrees(a, b); sim != 1.0 {
		t.Errorf("identical trees similarity = %v, want 1.0", sim)
	}

	c := StringToAPTEDTree("div{span,p}")
	d := StringToAPTEDTree("section{a,b,c}")
	if sim := CompareFragmentTrees(c, d); sim >= 1.0 {
		t.Errorf("different trees similarity = %v, want < 1.0", sim)
	}
}
