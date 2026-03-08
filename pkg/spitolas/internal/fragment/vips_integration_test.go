package fragment

import (
	"encoding/json"
	"html"
	"os"
	"strconv"
	"strings"
	"testing"

	htmlpkg "golang.org/x/net/html"
)

// =============================================================================
// VIPS Integration Tests with Real HTML
// Mirrors Crawljax's FragGenTests and TreeDiffParamTest
//
// Test values are taken directly from Crawljax Java tests:
// - TreeDiffParamTest.java: exact tree edit distances
// - FragGenTests.java: exact candidate counts, state comparisons
// =============================================================================

// VipsNodeFromHTML represents a node parsed from Crawljax-annotated HTML.
// Crawljax saves VIPS metadata as HTML attributes (rectangle, doc, isvisualblock, etc.)
type VipsNodeFromHTML struct {
	TagName       string
	XPath         string
	Rectangle     Rect
	DoC           int
	IsVisualBlock bool
	IsDividable   bool
	FontSize      int
	FontWeight    string
	Children      []*VipsNodeFromHTML
}

// parseVipsHTML parses Crawljax-annotated HTML into VipsNodeFromHTML tree.
func parseVipsHTML(htmlContent string) (*VipsNodeFromHTML, error) {
	doc, err := htmlpkg.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}

	var root *VipsNodeFromHTML
	var parse func(*htmlpkg.Node, string, *VipsNodeFromHTML)
	parse = func(n *htmlpkg.Node, xpath string, parent *VipsNodeFromHTML) {
		if n.Type != htmlpkg.ElementNode {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				parse(c, xpath, parent)
			}
			return
		}

		tagName := strings.ToLower(n.Data)
		currentXPath := buildXPath(xpath, n)

		node := &VipsNodeFromHTML{
			TagName:  tagName,
			XPath:    currentXPath,
			Children: make([]*VipsNodeFromHTML, 0),
		}

		// Parse VIPS attributes
		for _, attr := range n.Attr {
			switch attr.Key {
			case "rectangle":
				node.Rectangle = parseRectangleAttr(attr.Val)
			case "doc":
				node.DoC, _ = strconv.Atoi(attr.Val)
			case "isvisualblock":
				node.IsVisualBlock = attr.Val == "true"
			case "isdividable":
				node.IsDividable = attr.Val == "true"
			case "fontsize":
				node.FontSize, _ = strconv.Atoi(attr.Val)
			case "fontweight":
				node.FontWeight = attr.Val
			}
		}

		if parent != nil {
			parent.Children = append(parent.Children, node)
		}

		// Find root (body element)
		if tagName == "body" {
			root = node
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			parse(c, currentXPath, node)
		}
	}

	parse(doc, "", nil)
	return root, nil
}

// buildXPath builds XPath for an element.
func buildXPath(parentXPath string, n *htmlpkg.Node) string {
	if n.Type != htmlpkg.ElementNode {
		return parentXPath
	}

	tagName := strings.ToUpper(n.Data)
	index := 1

	// Count preceding siblings with same tag
	for sibling := n.PrevSibling; sibling != nil; sibling = sibling.PrevSibling {
		if sibling.Type == htmlpkg.ElementNode && strings.EqualFold(sibling.Data, n.Data) {
			index++
		}
	}

	if parentXPath == "" {
		return "/" + tagName + "[" + strconv.Itoa(index) + "]"
	}
	return parentXPath + "/" + tagName + "[" + strconv.Itoa(index) + "]"
}

// parseRectangleAttr parses rectangle JSON attribute.
func parseRectangleAttr(val string) Rect {
	// Unescape HTML entities
	val = html.UnescapeString(val)

	var rectData struct {
		X      float64 `json:"x"`
		Y      float64 `json:"y"`
		Width  float64 `json:"width"`
		Height float64 `json:"height"`
	}

	if err := json.Unmarshal([]byte(val), &rectData); err != nil {
		return Rect{}
	}

	return Rect{
		X:      rectData.X,
		Y:      rectData.Y,
		Width:  rectData.Width,
		Height: rectData.Height,
	}
}

// countVisualBlocks counts visual blocks in the tree.
func countVisualBlocks(node *VipsNodeFromHTML) int {
	if node == nil {
		return 0
	}

	count := 0
	if node.IsVisualBlock {
		count = 1
	}

	for _, child := range node.Children {
		count += countVisualBlocks(child)
	}

	return count
}

// countNodes counts total nodes in the tree.
func countNodes(node *VipsNodeFromHTML) int {
	if node == nil {
		return 0
	}

	count := 1
	for _, child := range node.Children {
		count += countNodes(child)
	}

	return count
}

// collectVisualBlocksFromHTML collects all visual blocks from parsed HTML.
func collectVisualBlocksFromHTML(node *VipsNodeFromHTML) []*VipsNodeFromHTML {
	var blocks []*VipsNodeFromHTML

	var collect func(*VipsNodeFromHTML)
	collect = func(n *VipsNodeFromHTML) {
		if n == nil {
			return
		}
		if n.IsVisualBlock {
			blocks = append(blocks, n)
		}
		for _, child := range n.Children {
			collect(child)
		}
	}

	collect(node)
	return blocks
}

// =============================================================================
// Visual Block Count Tests with Exact Values
// Values from Crawljax annotated HTML files (isvisualblock="true" count)
// =============================================================================

func TestVipsHTMLParsing_State408_ExactCounts(t *testing.T) {
	htmlContent, err := os.ReadFile("testdata/frag_state408.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root, err := parseVipsHTML(string(htmlContent))
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	if root == nil {
		t.Fatal("Root node is nil")
	}

	// Assert exact values
	if root.TagName != "body" {
		t.Errorf("root.TagName = %q, want \"body\"", root.TagName)
	}

	// Root rectangle from Crawljax HTML: {"x":0,"y":5,"width":1200,"height":715}
	if root.Rectangle.Width != 1200 {
		t.Errorf("root.Rectangle.Width = %f, want 1200", root.Rectangle.Width)
	}
	if root.Rectangle.Height != 715 {
		t.Errorf("root.Rectangle.Height = %f, want 715", root.Rectangle.Height)
	}

	// Visual block count from HTML file (counted isvisualblock="true")
	visualBlockCount := countVisualBlocks(root)
	expectedVisualBlocks := 18 // Counted from frag_state408.html
	if visualBlockCount != expectedVisualBlocks {
		t.Errorf("visualBlockCount = %d, want %d", visualBlockCount, expectedVisualBlocks)
	}

	// Total node count
	nodeCount := countNodes(root)
	expectedNodes := 52 // Counted from frag_state408.html
	if nodeCount != expectedNodes {
		t.Errorf("nodeCount = %d, want %d", nodeCount, expectedNodes)
	}
}

func TestVipsHTMLParsing_State487_ExactCounts(t *testing.T) {
	htmlContent, err := os.ReadFile("testdata/frag_state487.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root, err := parseVipsHTML(string(htmlContent))
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	visualBlockCount := countVisualBlocks(root)
	expectedVisualBlocks := 20 // Counted from frag_state487.html
	if visualBlockCount != expectedVisualBlocks {
		t.Errorf("visualBlockCount = %d, want %d", visualBlockCount, expectedVisualBlocks)
	}

	nodeCount := countNodes(root)
	expectedNodes := 57 // Counted from frag_state487.html
	if nodeCount != expectedNodes {
		t.Errorf("nodeCount = %d, want %d", nodeCount, expectedNodes)
	}
}

func TestVipsHTMLParsing_State503_ExactCounts(t *testing.T) {
	htmlContent, err := os.ReadFile("testdata/frag_state503.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root, err := parseVipsHTML(string(htmlContent))
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	visualBlockCount := countVisualBlocks(root)
	expectedVisualBlocks := 18 // Counted from frag_state503.html
	if visualBlockCount != expectedVisualBlocks {
		t.Errorf("visualBlockCount = %d, want %d", visualBlockCount, expectedVisualBlocks)
	}

	nodeCount := countNodes(root)
	expectedNodes := 55 // Counted from frag_state503.html
	if nodeCount != expectedNodes {
		t.Errorf("nodeCount = %d, want %d", nodeCount, expectedNodes)
	}
}

func TestVipsHTMLParsing_State296_ExactCounts(t *testing.T) {
	htmlContent, err := os.ReadFile("testdata/frag_state296.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root, err := parseVipsHTML(string(htmlContent))
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	visualBlockCount := countVisualBlocks(root)
	expectedVisualBlocks := 27 // Counted from frag_state296.html
	if visualBlockCount != expectedVisualBlocks {
		t.Errorf("visualBlockCount = %d, want %d", visualBlockCount, expectedVisualBlocks)
	}

	nodeCount := countNodes(root)
	expectedNodes := 102 // Counted from frag_state296.html
	if nodeCount != expectedNodes {
		t.Errorf("nodeCount = %d, want %d", nodeCount, expectedNodes)
	}
}

func TestVipsHTMLParsing_State297_ExactCounts(t *testing.T) {
	htmlContent, err := os.ReadFile("testdata/frag_state297.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root, err := parseVipsHTML(string(htmlContent))
	if err != nil {
		t.Fatalf("Failed to parse HTML: %v", err)
	}

	visualBlockCount := countVisualBlocks(root)
	expectedVisualBlocks := 31 // Counted from frag_state297.html
	if visualBlockCount != expectedVisualBlocks {
		t.Errorf("visualBlockCount = %d, want %d", visualBlockCount, expectedVisualBlocks)
	}

	nodeCount := countNodes(root)
	expectedNodes := 109 // Counted from frag_state297.html
	if nodeCount != expectedNodes {
		t.Errorf("nodeCount = %d, want %d", nodeCount, expectedNodes)
	}
}

// =============================================================================
// Tree Diff Tests with Exact Values from Crawljax TreeDiffParamTest.java
//
// From TreeDiffParamTest.java:
//   {"frag_state487.html", "frag_state408.html", 5, "#text", null}
//   {"frag_state487.html", "frag_state503.html", 2, "#text", null}
//   {"frag_state408.html", "frag_state503.html", 3, null, "input"}
// =============================================================================

func TestTreeDiff_State487_vs_State408_ExactDistance(t *testing.T) {
	// From Crawljax TreeDiffParamTest.java: distance = 5
	html1, err := os.ReadFile("testdata/frag_state487.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	html2, err := os.ReadFile("testdata/frag_state408.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root1, _ := parseVipsHTML(string(html1))
	root2, _ := parseVipsHTML(string(html2))

	tree1 := vipsNodeToAPTED(root1)
	tree2 := vipsNodeToAPTED(root2)

	apted := NewAPTED()
	distance := int(apted.Distance(tree1, tree2))

	// Crawljax TreeDiffParamTest.java: assertEquals(5, distance)
	expectedDistance := 5
	if distance != expectedDistance {
		t.Errorf("distance = %d, want %d (from Crawljax TreeDiffParamTest)", distance, expectedDistance)
	}
}

func TestTreeDiff_State487_vs_State503_ExactDistance(t *testing.T) {
	// From Crawljax TreeDiffParamTest.java: distance = 2
	html1, err := os.ReadFile("testdata/frag_state487.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	html2, err := os.ReadFile("testdata/frag_state503.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root1, _ := parseVipsHTML(string(html1))
	root2, _ := parseVipsHTML(string(html2))

	tree1 := vipsNodeToAPTED(root1)
	tree2 := vipsNodeToAPTED(root2)

	apted := NewAPTED()
	distance := int(apted.Distance(tree1, tree2))

	// Crawljax TreeDiffParamTest.java: assertEquals(2, distance)
	expectedDistance := 2
	if distance != expectedDistance {
		t.Errorf("distance = %d, want %d (from Crawljax TreeDiffParamTest)", distance, expectedDistance)
	}
}

func TestTreeDiff_State408_vs_State503_ExactDistance(t *testing.T) {
	// From Crawljax TreeDiffParamTest.java: distance = 3
	html1, err := os.ReadFile("testdata/frag_state408.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	html2, err := os.ReadFile("testdata/frag_state503.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root1, _ := parseVipsHTML(string(html1))
	root2, _ := parseVipsHTML(string(html2))

	tree1 := vipsNodeToAPTED(root1)
	tree2 := vipsNodeToAPTED(root2)

	apted := NewAPTED()
	distance := int(apted.Distance(tree1, tree2))

	// Crawljax TreeDiffParamTest.java: assertEquals(3, distance)
	expectedDistance := 3
	if distance != expectedDistance {
		t.Errorf("distance = %d, want %d (from Crawljax TreeDiffParamTest)", distance, expectedDistance)
	}
}

// vipsNodeToAPTED converts VipsNodeFromHTML to APTEDNode.
func vipsNodeToAPTED(node *VipsNodeFromHTML) *APTEDNode {
	if node == nil {
		return nil
	}

	aptedNode := &APTEDNode{
		Label:    node.TagName,
		Children: make([]*APTEDNode, 0, len(node.Children)),
	}

	for _, child := range node.Children {
		if childNode := vipsNodeToAPTED(child); childNode != nil {
			aptedNode.Children = append(aptedNode.Children, childNode)
		}
	}

	return aptedNode
}

// =============================================================================
// Simple DOM Tree Diff Test - Exact value from Crawljax FragGenTests.java
//
// From FragGenTests.testTreeDiffSimpleDOM():
//   assertEquals(distance, 1.0, 0.0);
//   assertTrue(addedNodes.get(0).getNodeName().equalsIgnoreCase("span"));
//   assertTrue(removedNodes.get(0).getNodeName().equalsIgnoreCase("div"));
// =============================================================================

func TestTreeDiffSimpleDOM_ExactDistance(t *testing.T) {
	// Exact strings from Crawljax FragGenTests.testTreeDiffSimpleDOM()
	docString1 := `<HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=UTF-8"></HEAD><BODY><SPAN id="testdiv"><a></a></SPAN><DIV style="colour:#FF0000"><H>Header</H></DIV></BODY></HTML>`
	docString2 := `<HTML><HEAD><META http-equiv="Content-Type" content="text/html; charset=UTF-8"></HEAD><BODY><DIV id="testdiv"><a></a></DIV><DIV style="colour:#FF0000"><H>Header</H></DIV></BODY></HTML>`

	tree1 := parseHTMLToAPTED(docString1)
	tree2 := parseHTMLToAPTED(docString2)

	if tree1 == nil || tree2 == nil {
		t.Fatal("Failed to parse HTML strings")
	}

	apted := NewAPTED()
	distance := int(apted.Distance(tree1, tree2))

	// Crawljax FragGenTests.java: assertEquals(distance, 1.0, 0.0)
	// The change is SPAN -> DIV (rename operation = 1)
	expectedDistance := 1
	if distance != expectedDistance {
		t.Errorf("distance = %d, want %d (from Crawljax FragGenTests.testTreeDiffSimpleDOM)", distance, expectedDistance)
	}
}

// parseHTMLToAPTED parses HTML string to APTEDNode tree.
func parseHTMLToAPTED(htmlStr string) *APTEDNode {
	doc, err := htmlpkg.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil
	}

	var convert func(*htmlpkg.Node) *APTEDNode
	convert = func(n *htmlpkg.Node) *APTEDNode {
		if n == nil {
			return nil
		}

		if n.Type != htmlpkg.ElementNode {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == htmlpkg.ElementNode {
					return convert(c)
				}
			}
			return nil
		}

		node := &APTEDNode{
			Label:    strings.ToLower(n.Data),
			Children: make([]*APTEDNode, 0),
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == htmlpkg.ElementNode {
				if child := convert(c); child != nil {
					node.Children = append(node.Children, child)
				}
			}
		}

		return node
	}

	return convert(doc)
}

// =============================================================================
// Near-Duplicate Detection Test - From Crawljax FragGenTests.testFragGenComparisonND2()
//
// From FragGenTests.java:
//   Assert.assertFalse("The two states are near-duplicates, not equal", state1.equals(state2));
//   Assert.assertEquals("The two states are NEAR_DUPLICATE2", StateComparision.NEARDUPLICATE2, comp);
// =============================================================================

func TestNearDuplicateDetection_State296_vs_State297(t *testing.T) {
	html1, err := os.ReadFile("testdata/frag_state296.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	html2, err := os.ReadFile("testdata/frag_state297.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root1, _ := parseVipsHTML(string(html1))
	root2, _ := parseVipsHTML(string(html2))

	// Collect visual blocks
	blocks1 := collectVisualBlocksFromHTML(root1)
	blocks2 := collectVisualBlocksFromHTML(root2)

	// Assert exact visual block counts
	expectedBlocks1 := 27
	expectedBlocks2 := 31
	if len(blocks1) != expectedBlocks1 {
		t.Errorf("state296 visual blocks = %d, want %d", len(blocks1), expectedBlocks1)
	}
	if len(blocks2) != expectedBlocks2 {
		t.Errorf("state297 visual blocks = %d, want %d", len(blocks2), expectedBlocks2)
	}

	// Convert to fragments
	fragments1 := make([]*Fragment, len(blocks1))
	for i, block := range blocks1 {
		fragments1[i] = &Fragment{
			ID:      i,
			XPath:   block.XPath,
			Rect:    block.Rectangle,
			TagName: block.TagName,
		}
		fragments1[i].SetDOMHash(block.XPath + block.TagName)
	}

	fragments2 := make([]*Fragment, len(blocks2))
	for i, block := range blocks2 {
		fragments2[i] = &Fragment{
			ID:      i,
			XPath:   block.XPath,
			Rect:    block.Rectangle,
			TagName: block.TagName,
		}
		fragments2[i].SetDOMHash(block.XPath + block.TagName)
	}

	// Compare states
	similarity := CompareFragments(fragments1, fragments2)

	// From Crawljax: states are NEARDUPLICATE2, meaning high similarity but not equal
	// NEARDUPLICATE2 threshold in Crawljax is typically > 0.9
	minSimilarity := 0.9
	if similarity < minSimilarity {
		t.Errorf("similarity = %f, want >= %f (NEARDUPLICATE2 from Crawljax)", similarity, minSimilarity)
	}
	if similarity == 1.0 {
		t.Errorf("similarity = %f, states should NOT be identical (from Crawljax: assertFalse equals)", similarity)
	}
}

// =============================================================================
// DoC Distribution Test - Values from Crawljax annotated HTML
// =============================================================================

func TestVisualBlockDoC_State408_ExactDistribution(t *testing.T) {
	htmlContent, err := os.ReadFile("testdata/frag_state408.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root, _ := parseVipsHTML(string(htmlContent))
	blocks := collectVisualBlocksFromHTML(root)

	// Count DoC distribution
	docCounts := make(map[int]int)
	for _, block := range blocks {
		docCounts[block.DoC]++
	}

	// From frag_state408.html: DoC values are 10 (15 blocks) and 11 (3 blocks)
	expectedDoC10 := 15
	expectedDoC11 := 3

	if docCounts[10] != expectedDoC10 {
		t.Errorf("DoC=10 count = %d, want %d", docCounts[10], expectedDoC10)
	}
	if docCounts[11] != expectedDoC11 {
		t.Errorf("DoC=11 count = %d, want %d", docCounts[11], expectedDoC11)
	}

	// Total should match visual block count
	totalDoC := docCounts[10] + docCounts[11]
	expectedTotal := 18
	if totalDoC != expectedTotal {
		t.Errorf("total DoC blocks = %d, want %d", totalDoC, expectedTotal)
	}
}

// =============================================================================
// Rectangle Validation Tests - Exact values from Crawljax HTML
// =============================================================================

func TestVisualBlockRectangles_State408_AllValid(t *testing.T) {
	htmlContent, err := os.ReadFile("testdata/frag_state408.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root, _ := parseVipsHTML(string(htmlContent))
	blocks := collectVisualBlocksFromHTML(root)

	// All 18 visual blocks should have valid rectangles
	expectedBlocks := 18
	if len(blocks) != expectedBlocks {
		t.Errorf("visual blocks = %d, want %d", len(blocks), expectedBlocks)
	}

	validRects := 0
	for _, block := range blocks {
		if block.Rectangle.Width > 0 && block.Rectangle.Height > 0 {
			validRects++
		}
	}

	// All blocks should have valid rectangles
	if validRects != expectedBlocks {
		t.Errorf("valid rectangles = %d, want %d (all blocks)", validRects, expectedBlocks)
	}
}

// =============================================================================
// Fragment Extraction Test
// =============================================================================

func TestExtractFragmentsFromAnnotatedHTML_State408(t *testing.T) {
	htmlContent, err := os.ReadFile("testdata/frag_state408.html")
	if err != nil {
		t.Skipf("Test file not found: %v", err)
	}

	root, _ := parseVipsHTML(string(htmlContent))
	blocks := collectVisualBlocksFromHTML(root)

	// Extract fragments
	fragments := make([]*Fragment, len(blocks))
	for i, block := range blocks {
		frag := NewFragment(i, block.XPath, block.Rectangle, 1)
		frag.TagName = block.TagName
		frag.Influence = float64(block.DoC) / 11.0
		fragments[i] = frag
	}

	// Assert exact count
	expectedFragments := 18
	if len(fragments) != expectedFragments {
		t.Errorf("fragments = %d, want %d", len(fragments), expectedFragments)
	}

	// Verify all fragments have valid data
	for i, frag := range fragments {
		if frag.XPath == "" {
			t.Errorf("fragment[%d].XPath is empty", i)
		}
		if frag.Influence < 0 || frag.Influence > 1 {
			t.Errorf("fragment[%d].Influence = %f, want [0,1]", i, frag.Influence)
		}
		if frag.Rect.Width <= 0 || frag.Rect.Height <= 0 {
			t.Errorf("fragment[%d] has invalid rectangle: %+v", i, frag.Rect)
		}
	}
}
