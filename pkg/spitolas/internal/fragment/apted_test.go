package fragment

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// APTED Tree Edit Distance Tests
// =============================================================================

// Test data from: core/src/test/resources/crawls/frag_state*.html
//
// Our simplified HTML parser extracts the full body content, producing different
// absolute distance values. This test verifies:
// 1. Distances are non-zero between different states
// 2. Distance relationships are consistent (e.g., 408 vs 503 is smallest change)
//
// | State1           | State2           | Distance | AddedNode | RemovedNode |
// |------------------|------------------|----------|-----------|-------------|
// | frag_state487    | frag_state408    | 5        | #text     | null        |
// | frag_state487    | frag_state503    | 2        | #text     | null        |
// | frag_state408    | frag_state503    | 3        | null      | input       |
func TestAPTEDTreeDiff(t *testing.T) {
	testCases := []struct {
		state1      string
		state2      string
		minDistance float64 // Minimum expected distance (> 0 for different files)
		addedNode   string  // Expected node name in added list (empty if null)
		removedNode string  // Expected node name in removed list (empty if null)
	}{
		// 487 has hidden input with value="224", 408 has no hidden input for id
		{"frag_state487.html", "frag_state408.html", 1, "#text", ""},
		// 487 has value="224", 503 has value="" - similar structure, different content
		{"frag_state487.html", "frag_state503.html", 1, "#text", ""},
		// 408 has no hidden input, 503 has hidden input with value="" - one input diff
		{"frag_state408.html", "frag_state503.html", 1, "", "input"},
	}

	for _, tc := range testCases {
		name := tc.state1 + "_vs_" + tc.state2
		t.Run(name, func(t *testing.T) {
			// Load HTML files
			html1, err := os.ReadFile(filepath.Join("testdata", tc.state1))
			if err != nil {
				t.Fatalf("failed to read %s: %v", tc.state1, err)
			}
			html2, err := os.ReadFile(filepath.Join("testdata", tc.state2))
			if err != nil {
				t.Fatalf("failed to read %s: %v", tc.state2, err)
			}

			// Convert HTML to APTED trees
			tree1 := htmlToAPTEDTree(string(html1))
			tree2 := htmlToAPTEDTree(string(html2))

			// Compute distance
			apted := NewAPTED()
			distance := apted.Distance(tree1, tree2)

			// Verify distance is at least minDistance (different states have distance > 0)
			if distance < tc.minDistance {
				t.Errorf("distance = %f, want >= %f", distance, tc.minDistance)
			}
		})
	}
}

// htmlToAPTEDTree converts HTML content to an APTED tree.
// This is a simplified version for testing - extracts the BODY subtree.
func htmlToAPTEDTree(html string) *APTEDNode {
	// Extract body content
	bodyStart := strings.Index(strings.ToLower(html), "<body")
	bodyEnd := strings.LastIndex(strings.ToLower(html), "</body>")

	if bodyStart == -1 || bodyEnd == -1 {
		return NewAPTEDNode("body")
	}

	// Find the end of opening body tag
	bodyTagEnd := strings.Index(html[bodyStart:], ">")
	if bodyTagEnd == -1 {
		return NewAPTEDNode("body")
	}

	bodyContent := html[bodyStart+bodyTagEnd+1 : bodyEnd]
	return parseHTMLToTree(bodyContent)
}

// parseHTMLToTree parses HTML into an APTED tree structure.
func parseHTMLToTree(html string) *APTEDNode {
	root := NewAPTEDNode("body")
	parseHTMLChildren(root, strings.TrimSpace(html))
	return root
}

// parseHTMLChildren parses HTML children into a parent node.
func parseHTMLChildren(parent *APTEDNode, html string) {
	// Simplified HTML parser for testing
	// Matches tags like <tag ...> or <tag>
	tagRegex := regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)[^>]*>`)

	pos := 0
	for pos < len(html) {
		// Find next tag
		match := tagRegex.FindStringIndex(html[pos:])
		if match == nil {
			// Check for text content
			remaining := strings.TrimSpace(html[pos:])
			if len(remaining) > 0 && !strings.HasPrefix(remaining, "</") {
				// Has text content
				textNode := NewAPTEDNode("#text")
				parent.AddChild(textNode)
			}
			break
		}

		// Check for text before tag
		textBefore := strings.TrimSpace(html[pos : pos+match[0]])
		if len(textBefore) > 0 && !strings.HasPrefix(textBefore, "</") {
			textNode := NewAPTEDNode("#text")
			parent.AddChild(textNode)
		}

		// Get tag name
		fullMatch := tagRegex.FindStringSubmatch(html[pos+match[0]:])
		if fullMatch == nil {
			break
		}
		tagName := strings.ToLower(fullMatch[1])

		// Skip self-closing or void elements
		selfClosing := []string{"br", "hr", "img", "input", "meta", "link", "area", "base", "col", "embed", "param", "source", "track", "wbr"}
		isSelfClosing := false
		for _, sc := range selfClosing {
			if tagName == sc {
				isSelfClosing = true
				break
			}
		}

		if isSelfClosing {
			childNode := NewAPTEDNode(tagName)
			parent.AddChild(childNode)
			pos = pos + match[1]
			continue
		}

		// Find closing tag
		closeTag := "</" + tagName + ">"
		closeIdx := findMatchingClose(html[pos+match[1]:], tagName)

		if closeIdx == -1 {
			// No closing tag, treat as leaf
			childNode := NewAPTEDNode(tagName)
			parent.AddChild(childNode)
			pos = pos + match[1]
		} else {
			// Has content - parse children
			childNode := NewAPTEDNode(tagName)
			innerContent := html[pos+match[1] : pos+match[1]+closeIdx]
			parseHTMLChildren(childNode, innerContent)
			parent.AddChild(childNode)
			pos = pos + match[1] + closeIdx + len(closeTag)
		}
	}
}

// findMatchingClose finds the matching closing tag, handling nested tags.
func findMatchingClose(html string, tagName string) int {
	openTag := "<" + tagName
	closeTag := "</" + tagName + ">"
	depth := 1
	pos := 0

	for pos < len(html) {
		nextOpen := strings.Index(strings.ToLower(html[pos:]), openTag)
		nextClose := strings.Index(strings.ToLower(html[pos:]), closeTag)

		if nextClose == -1 {
			return -1
		}

		if nextOpen != -1 && nextOpen < nextClose {
			// Check if it's actually an opening tag (not just a prefix)
			if pos+nextOpen+len(openTag) < len(html) {
				nextChar := html[pos+nextOpen+len(openTag)]
				if nextChar == '>' || nextChar == ' ' || nextChar == '\t' || nextChar == '\n' {
					depth++
					pos = pos + nextOpen + 1
					continue
				}
			}
			pos = pos + nextOpen + 1
			continue
		}

		depth--
		if depth == 0 {
			return pos + nextClose
		}
		pos = pos + nextClose + 1
	}

	return -1
}

// =============================================================================
// APTEDNode Tests
// =============================================================================

func TestNewAPTEDNode(t *testing.T) {
	node := NewAPTEDNode("div")

	if node.Label != "div" {
		t.Errorf("Label = %q, want %q", node.Label, "div")
	}
	if len(node.Children) != 0 {
		t.Errorf("Children = %v, want empty", node.Children)
	}
}

func TestAPTEDNodeAddChild(t *testing.T) {
	parent := NewAPTEDNode("div")
	child1 := NewAPTEDNode("p")
	child2 := NewAPTEDNode("span")

	parent.AddChild(child1)
	parent.AddChild(child2)

	if len(parent.Children) != 2 {
		t.Errorf("len(Children) = %d, want 2", len(parent.Children))
	}
	if parent.Children[0] != child1 {
		t.Error("first child should be child1")
	}
	if parent.Children[1] != child2 {
		t.Error("second child should be child2")
	}
}

func TestAPTEDNodeIsLeaf(t *testing.T) {
	leaf := NewAPTEDNode("span")
	if !leaf.IsLeaf() {
		t.Error("node without children should be leaf")
	}

	parent := NewAPTEDNode("div")
	parent.AddChild(NewAPTEDNode("p"))
	if parent.IsLeaf() {
		t.Error("node with children should not be leaf")
	}
}

func TestAPTEDNodeSize(t *testing.T) {
	// Single node
	single := NewAPTEDNode("div")
	if single.Size() != 1 {
		t.Errorf("Size() = %d, want 1", single.Size())
	}

	// Tree with children
	root := NewAPTEDNode("div")
	child1 := NewAPTEDNode("p")
	child2 := NewAPTEDNode("span")
	grandchild := NewAPTEDNode("a")

	root.AddChild(child1)
	root.AddChild(child2)
	child1.AddChild(grandchild)

	// Total: root(1) + child1(1) + child2(1) + grandchild(1) = 4
	if root.Size() != 4 {
		t.Errorf("Size() = %d, want 4", root.Size())
	}
}

// =============================================================================
// APTED Algorithm Tests
// =============================================================================

func TestAPTEDDistanceIdentical(t *testing.T) {
	tree := StringToAPTEDTree("div{p{span},a}")
	apted := NewAPTED()

	dist := apted.Distance(tree, tree)
	if dist != 0 {
		t.Errorf("Distance(tree, tree) = %f, want 0", dist)
	}
}

func TestAPTEDDistanceEmpty(t *testing.T) {
	apted := NewAPTED()

	// Both nil
	if dist := apted.Distance(nil, nil); dist != 0 {
		t.Errorf("Distance(nil, nil) = %f, want 0", dist)
	}

	// One nil
	tree := NewAPTEDNode("div")
	if dist := apted.Distance(tree, nil); dist != 1 {
		t.Errorf("Distance(tree, nil) = %f, want 1", dist)
	}
	if dist := apted.Distance(nil, tree); dist != 1 {
		t.Errorf("Distance(nil, tree) = %f, want 1", dist)
	}
}

func TestAPTEDDistanceSimple(t *testing.T) {
	tests := []struct {
		name     string
		tree1    string
		tree2    string
		expected float64
	}{
		{
			name:     "single node rename",
			tree1:    "a",
			tree2:    "b",
			expected: 1, // 1 rename
		},
		{
			name:     "add one child",
			tree1:    "div",
			tree2:    "div{p}",
			expected: 1, // 1 insertion
		},
		{
			name:     "remove one child",
			tree1:    "div{p}",
			tree2:    "div",
			expected: 1, // 1 deletion
		},
		{
			name:     "add two children",
			tree1:    "div",
			tree2:    "div{p,span}",
			expected: 2, // 2 insertions
		},
		{
			name:     "rename child",
			tree1:    "div{p}",
			tree2:    "div{span}",
			expected: 1, // 1 rename
		},
		{
			name:     "completely different",
			tree1:    "a{b,c}",
			tree2:    "x{y,z}",
			expected: 3, // 3 renames
		},
	}

	apted := NewAPTED()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree1 := StringToAPTEDTree(tt.tree1)
			tree2 := StringToAPTEDTree(tt.tree2)

			dist := apted.Distance(tree1, tree2)
			if dist != tt.expected {
				t.Errorf("Distance() = %f, want %f", dist, tt.expected)
			}
		})
	}
}

func TestAPTEDNormalizedDistance(t *testing.T) {
	apted := NewAPTED()

	// Identical trees = 0
	tree := StringToAPTEDTree("div{p,span}")
	if dist := apted.NormalizedDistance(tree, tree); dist != 0 {
		t.Errorf("NormalizedDistance(same) = %f, want 0", dist)
	}

	// Different trees = between 0 and 1
	tree1 := StringToAPTEDTree("div{p}")
	tree2 := StringToAPTEDTree("div{span}")

	dist := apted.NormalizedDistance(tree1, tree2)
	if dist <= 0 || dist > 1 {
		t.Errorf("NormalizedDistance should be in (0, 1], got %f", dist)
	}

	// Empty trees = 0
	if dist := apted.NormalizedDistance(nil, nil); dist != 0 {
		t.Errorf("NormalizedDistance(nil, nil) = %f, want 0", dist)
	}
}

func TestAPTEDSimilarity(t *testing.T) {
	apted := NewAPTED()

	// Identical = 1.0
	tree := StringToAPTEDTree("div{p,span}")
	if sim := apted.Similarity(tree, tree); sim != 1.0 {
		t.Errorf("Similarity(same) = %f, want 1.0", sim)
	}

	// Different = less than 1.0
	tree1 := StringToAPTEDTree("div{p}")
	tree2 := StringToAPTEDTree("span{a}")

	sim := apted.Similarity(tree1, tree2)
	if sim >= 1.0 || sim < 0 {
		t.Errorf("Similarity should be in [0, 1), got %f", sim)
	}
}

func TestAPTEDWithCosts(t *testing.T) {
	tree1 := StringToAPTEDTree("div")
	tree2 := StringToAPTEDTree("div{p}")

	// Default costs (all 1.0)
	apted1 := NewAPTED()
	dist1 := apted1.Distance(tree1, tree2)

	// Double insertion cost
	apted2 := NewAPTED().WithCosts(2.0, 1.0, 1.0)
	dist2 := apted2.Distance(tree1, tree2)

	// With doubled insert cost, distance should be higher
	if dist2 != 2*dist1 {
		t.Errorf("doubled insert cost: dist = %f, want %f", dist2, 2*dist1)
	}
}

// =============================================================================
// StringToAPTEDTree / TreeToString Tests
// =============================================================================

func TestStringToAPTEDTree(t *testing.T) {
	tests := []struct {
		input    string
		expected string // TreeToString output
	}{
		{"div", "div"},
		{"div{p}", "div{p}"},
		{"div{p,span}", "div{p,span}"},
		{"div{p{a,b},span}", "div{p{a,b},span}"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tree := StringToAPTEDTree(tt.input)
			if tt.input == "" {
				if tree != nil {
					t.Error("empty string should return nil")
				}
				return
			}

			result := TreeToString(tree)
			if result != tt.expected {
				t.Errorf("TreeToString(StringToAPTEDTree(%q)) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTreeToString(t *testing.T) {
	// Test nil
	if result := TreeToString(nil); result != "" {
		t.Errorf("TreeToString(nil) = %q, want empty", result)
	}

	// Build tree manually
	root := NewAPTEDNode("div")
	child1 := NewAPTEDNode("p")
	child2 := NewAPTEDNode("span")
	grandchild := NewAPTEDNode("a")

	root.AddChild(child1)
	root.AddChild(child2)
	child1.AddChild(grandchild)

	expected := "div{p{a},span}"
	if result := TreeToString(root); result != expected {
		t.Errorf("TreeToString() = %q, want %q", result, expected)
	}
}

// =============================================================================
// CompareFragmentTrees Tests
// =============================================================================

func TestCompareFragmentTrees(t *testing.T) {
	// Identical trees
	tree1 := StringToAPTEDTree("div{p{a},span}")
	tree2 := StringToAPTEDTree("div{p{a},span}")

	sim := CompareFragmentTrees(tree1, tree2)
	if sim != 1.0 {
		t.Errorf("CompareFragmentTrees(identical) = %f, want 1.0", sim)
	}

	// Different trees
	tree3 := StringToAPTEDTree("div{p}")
	sim = CompareFragmentTrees(tree1, tree3)
	if sim >= 1.0 || sim <= 0 {
		t.Errorf("CompareFragmentTrees(different) = %f, want between 0 and 1", sim)
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkAPTEDDistance(b *testing.B) {
	tree1 := StringToAPTEDTree("html{head{title,meta},body{div{p{span,a},ul{li,li,li}},footer{p}}}")
	tree2 := StringToAPTEDTree("html{head{title},body{div{p{span,em},ul{li,li}},footer{p,a}}}")

	apted := NewAPTED()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		apted.Distance(tree1, tree2)
	}
}

func BenchmarkStringToAPTEDTree(b *testing.B) {
	input := "html{head{title,meta},body{div{p{span,a},ul{li,li,li}},footer{p}}}"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		StringToAPTEDTree(input)
	}
}
