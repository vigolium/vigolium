package fragment

import (
	"testing"
)

// =============================================================================
// VIPS Block Tests - Mirrors Java Crawljax's visual block handling
// =============================================================================

func TestNewVisualBlock(t *testing.T) {
	rect := Rect{X: 10, Y: 20, Width: 100, Height: 200}
	block := NewVisualBlock(5, "/html/body/div", rect)

	if block.ID != 5 {
		t.Errorf("ID = %d, want 5", block.ID)
	}
	if block.ParentID != -1 {
		t.Errorf("ParentID = %d, want -1 (default)", block.ParentID)
	}
	if block.XPath != "/html/body/div" {
		t.Errorf("XPath = %q, want /html/body/div", block.XPath)
	}
	if block.Rect != rect {
		t.Errorf("Rect = %+v, want %+v", block.Rect, rect)
	}
	if block.DoC != 11 {
		t.Errorf("DoC = %d, want 11 (default)", block.DoC)
	}
	if !block.IsDividable {
		t.Error("IsDividable should be true by default")
	}
	if block.IsVisualBlock {
		t.Error("IsVisualBlock should be false by default")
	}
	if len(block.Children) != 0 {
		t.Errorf("Children = %v, want empty slice", block.Children)
	}
}

func TestVisualBlockAddChild(t *testing.T) {
	parent := NewVisualBlock(1, "/html/body", Rect{})
	child1 := NewVisualBlock(2, "/html/body/div[1]", Rect{})
	child2 := NewVisualBlock(3, "/html/body/div[2]", Rect{})

	parent.AddChild(child1)
	parent.AddChild(child2)

	if len(parent.Children) != 2 {
		t.Errorf("len(Children) = %d, want 2", len(parent.Children))
	}
	if child1.Parent != parent {
		t.Error("child1.Parent should be parent")
	}
	if child1.ParentID != 1 {
		t.Errorf("child1.ParentID = %d, want 1", child1.ParentID)
	}
	if child2.Parent != parent {
		t.Error("child2.Parent should be parent")
	}
}

func TestVisualBlockIsLeafIsRoot(t *testing.T) {
	root := NewVisualBlock(1, "/html", Rect{})
	middle := NewVisualBlock(2, "/html/body", Rect{})
	leaf := NewVisualBlock(3, "/html/body/p", Rect{})

	root.AddChild(middle)
	middle.AddChild(leaf)

	// Root tests
	if !root.IsRoot() {
		t.Error("root.IsRoot() should be true")
	}
	if root.IsLeaf() {
		t.Error("root.IsLeaf() should be false")
	}

	// Middle tests
	if middle.IsRoot() {
		t.Error("middle.IsRoot() should be false")
	}
	if middle.IsLeaf() {
		t.Error("middle.IsLeaf() should be false")
	}

	// Leaf tests
	if leaf.IsRoot() {
		t.Error("leaf.IsRoot() should be false")
	}
	if !leaf.IsLeaf() {
		t.Error("leaf.IsLeaf() should be true")
	}
}

func TestVisualBlockGetArea(t *testing.T) {
	block := NewVisualBlock(1, "/html", Rect{X: 0, Y: 0, Width: 100, Height: 200})
	area := block.GetArea()
	if area != 20000 {
		t.Errorf("GetArea() = %f, want 20000", area)
	}
}

func TestVisualBlockContains(t *testing.T) {
	outer := NewVisualBlock(1, "/html/body", Rect{X: 0, Y: 0, Width: 800, Height: 600})
	inner := NewVisualBlock(2, "/html/body/div", Rect{X: 100, Y: 100, Width: 200, Height: 200})
	separate := NewVisualBlock(3, "/html/body/aside", Rect{X: 900, Y: 0, Width: 200, Height: 200})

	if !outer.Contains(inner) {
		t.Error("outer should contain inner")
	}
	if inner.Contains(outer) {
		t.Error("inner should not contain outer")
	}
	if outer.Contains(separate) {
		t.Error("outer should not contain separate (outside bounds)")
	}
}

func TestVisualBlockToFragment(t *testing.T) {
	block := NewVisualBlock(5, "/html/body/div", Rect{X: 10, Y: 20, Width: 100, Height: 200})
	block.Selector = "#main"
	block.TagName = "div"
	block.DOMHash = "abcd1234"
	block.ContentHash = "efgh5678"
	block.ParentID = 1
	block.DoC = 8
	block.SubtreeSize = 15

	child1 := NewVisualBlock(6, "/html/body/div/p[1]", Rect{})
	child2 := NewVisualBlock(7, "/html/body/div/p[2]", Rect{})
	block.AddChild(child1)
	block.AddChild(child2)

	frag := block.ToFragment()

	if frag.ID != 5 {
		t.Errorf("frag.ID = %d, want 5", frag.ID)
	}
	if frag.XPath != "/html/body/div" {
		t.Errorf("frag.XPath = %q, want /html/body/div", frag.XPath)
	}
	if frag.Selector != "#main" {
		t.Errorf("frag.Selector = %q, want #main", frag.Selector)
	}
	if frag.TagName != "div" {
		t.Errorf("frag.TagName = %q, want div", frag.TagName)
	}
	if frag.DOMHash != "abcd1234" {
		t.Errorf("frag.DOMHash = %q, want abcd1234", frag.DOMHash)
	}
	if frag.ContentHash != "efgh5678" {
		t.Errorf("frag.ContentHash = %q, want efgh5678", frag.ContentHash)
	}
	if frag.ParentID != 1 {
		t.Errorf("frag.ParentID = %d, want 1", frag.ParentID)
	}
	// Influence should be DoC/11 = 8/11 ≈ 0.727
	expectedInfluence := float64(8) / 11.0
	if frag.Influence != expectedInfluence {
		t.Errorf("frag.Influence = %f, want %f", frag.Influence, expectedInfluence)
	}
	if len(frag.ChildIDs) != 2 {
		t.Errorf("len(frag.ChildIDs) = %d, want 2", len(frag.ChildIDs))
	}
	if frag.ChildIDs[0] != 6 || frag.ChildIDs[1] != 7 {
		t.Errorf("frag.ChildIDs = %v, want [6, 7]", frag.ChildIDs)
	}
}

// =============================================================================
// VipsRectangle Tests
// =============================================================================

func TestNewVipsRectangle(t *testing.T) {
	rect := Rect{X: 50, Y: 100, Width: 200, Height: 300}
	vr := NewVipsRectangle(10, 5, "/html/body/main", rect)

	if vr.ID != 10 {
		t.Errorf("ID = %d, want 10", vr.ID)
	}
	if vr.ParentID != 5 {
		t.Errorf("ParentID = %d, want 5", vr.ParentID)
	}
	if vr.XPath != "/html/body/main" {
		t.Errorf("XPath = %q, want /html/body/main", vr.XPath)
	}
	if vr.Rect != rect {
		t.Errorf("Rect = %+v, want %+v", vr.Rect, rect)
	}
	if vr.DoC != 11 {
		t.Errorf("DoC = %d, want 11 (default)", vr.DoC)
	}
	if len(vr.NestedBlocks) != 0 {
		t.Errorf("NestedBlocks = %v, want empty", vr.NestedBlocks)
	}
}

func TestVipsRectangleAddNestedBlock(t *testing.T) {
	vr := NewVipsRectangle(1, 0, "/html/body", Rect{})

	vr.AddNestedBlock("/html/body/div[1]")
	vr.AddNestedBlock("/html/body/div[2]")
	vr.AddNestedBlock("/html/body/div[3]")

	if len(vr.NestedBlocks) != 3 {
		t.Errorf("len(NestedBlocks) = %d, want 3", len(vr.NestedBlocks))
	}
	if vr.NestedBlocks[0] != "/html/body/div[1]" {
		t.Errorf("NestedBlocks[0] = %q, want /html/body/div[1]", vr.NestedBlocks[0])
	}
}

// =============================================================================
// VIPS Utils Tests - Element Classification
// =============================================================================

func TestIsInlineElement(t *testing.T) {
	tests := []struct {
		tagName  string
		expected bool
	}{
		{"span", true},
		{"SPAN", true},
		{"em", true},
		{"strong", true},
		{"b", true},
		{"i", true},
		{"img", true},
		{"input", true},
		{"button", true},
		{"label", true},
		{"div", false},
		{"p", false},
		{"section", false},
		{"article", false},
		{"a", false},  // 'a' is special - treated as block for VIPS
		{"br", false}, // 'br' is line break
		{"table", false},
		{"ul", false},
		{"li", false},
	}

	for _, tt := range tests {
		t.Run(tt.tagName, func(t *testing.T) {
			result := IsInlineElement(tt.tagName)
			if result != tt.expected {
				t.Errorf("IsInlineElement(%q) = %v, want %v", tt.tagName, result, tt.expected)
			}
		})
	}
}

func TestIsSemanticElement(t *testing.T) {
	tests := []struct {
		tagName  string
		expected bool
	}{
		{"article", true},
		{"ARTICLE", true},
		{"section", true},
		{"header", true},
		{"footer", true},
		{"nav", true},
		{"aside", true},
		{"main", true},
		{"div", false},
		{"span", false},
		{"p", false},
		{"table", false},
	}

	for _, tt := range tests {
		t.Run(tt.tagName, func(t *testing.T) {
			result := IsSemanticElement(tt.tagName)
			if result != tt.expected {
				t.Errorf("IsSemanticElement(%q) = %v, want %v", tt.tagName, result, tt.expected)
			}
		})
	}
}

func TestIsTextNode(t *testing.T) {
	tests := []struct {
		tagName  string
		expected bool
	}{
		{"#text", true},
		{"text", true},
		{"TEXT", true},
		{"#TEXT", true},
		{"div", false},
		{"span", false},
		{"p", false},
	}

	for _, tt := range tests {
		t.Run(tt.tagName, func(t *testing.T) {
			result := IsTextNode(tt.tagName)
			if result != tt.expected {
				t.Errorf("IsTextNode(%q) = %v, want %v", tt.tagName, result, tt.expected)
			}
		})
	}
}

func TestIsTableElement(t *testing.T) {
	tests := []struct {
		tagName  string
		expected bool
	}{
		{"table", true},
		{"TABLE", true},
		{"tr", true},
		{"td", true},
		{"th", true},
		{"thead", true},
		{"tbody", true},
		{"tfoot", true},
		{"div", false},
		{"span", false},
		{"ul", false},
	}

	for _, tt := range tests {
		t.Run(tt.tagName, func(t *testing.T) {
			result := IsTableElement(tt.tagName)
			if result != tt.expected {
				t.Errorf("IsTableElement(%q) = %v, want %v", tt.tagName, result, tt.expected)
			}
		})
	}
}

func TestIsFormElement(t *testing.T) {
	tests := []struct {
		tagName  string
		expected bool
	}{
		{"form", true},
		{"FORM", true},
		{"input", true},
		{"select", true},
		{"textarea", true},
		{"button", true},
		{"label", true},
		{"div", false},
		{"span", false},
		{"p", false},
	}

	for _, tt := range tests {
		t.Run(tt.tagName, func(t *testing.T) {
			result := IsFormElement(tt.tagName)
			if result != tt.expected {
				t.Errorf("IsFormElement(%q) = %v, want %v", tt.tagName, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// RectInfo Tests
// =============================================================================

func TestRectInfoToRect(t *testing.T) {
	ri := RectInfo{X: 10, Y: 20, Width: 100, Height: 200}
	rect := ri.ToRect()

	if rect.X != 10 {
		t.Errorf("rect.X = %f, want 10", rect.X)
	}
	if rect.Y != 20 {
		t.Errorf("rect.Y = %f, want 20", rect.Y)
	}
	if rect.Width != 100 {
		t.Errorf("rect.Width = %f, want 100", rect.Width)
	}
	if rect.Height != 200 {
		t.Errorf("rect.Height = %f, want 200", rect.Height)
	}
}

func TestRectInfoIsValid(t *testing.T) {
	tests := []struct {
		name     string
		ri       RectInfo
		expected bool
	}{
		{
			name:     "valid rectangle",
			ri:       RectInfo{X: 10, Y: 20, Width: 100, Height: 200},
			expected: true,
		},
		{
			name:     "at origin with size",
			ri:       RectInfo{X: 0, Y: 0, Width: 50, Height: 50},
			expected: true,
		},
		{
			name:     "zero width",
			ri:       RectInfo{X: 10, Y: 20, Width: 0, Height: 100},
			expected: false,
		},
		{
			name:     "zero height",
			ri:       RectInfo{X: 10, Y: 20, Width: 100, Height: 0},
			expected: false,
		},
		{
			name:     "negative X",
			ri:       RectInfo{X: -10, Y: 20, Width: 100, Height: 200},
			expected: false,
		},
		{
			name:     "negative Y",
			ri:       RectInfo{X: 10, Y: -20, Width: 100, Height: 200},
			expected: false,
		},
		{
			name:     "all zeros",
			ri:       RectInfo{X: 0, Y: 0, Width: 0, Height: 0},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ri.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRectInfoGetArea(t *testing.T) {
	ri := RectInfo{X: 10, Y: 20, Width: 100, Height: 200}
	area := ri.GetArea()
	if area != 20000 {
		t.Errorf("GetArea() = %f, want 20000", area)
	}
}

// =============================================================================
// DoC Calculation Tests
// =============================================================================

func TestCalculateDoC(t *testing.T) {
	tests := []struct {
		name        string
		info        *VipsNodeInfo
		ruleApplied int
		minDoC      int
		maxDoC      int
	}{
		{
			name: "semantic element gets higher DoC",
			info: &VipsNodeInfo{
				TagName:    "article",
				ChildCount: 2,
			},
			ruleApplied: 0,
			minDoC:      6,
			maxDoC:      11,
		},
		{
			name: "single child increases DoC",
			info: &VipsNodeInfo{
				TagName:    "div",
				ChildCount: 1,
			},
			ruleApplied: 0,
			minDoC:      5,
			maxDoC:      11,
		},
		{
			name: "many children decreases DoC",
			info: &VipsNodeInfo{
				TagName:    "div",
				ChildCount: 15,
			},
			ruleApplied: 0,
			minDoC:      1,
			maxDoC:      5,
		},
		{
			name: "text-only content increases DoC",
			info: &VipsNodeInfo{
				TagName:     "p",
				HasOnlyText: true,
				ChildCount:  0,
			},
			ruleApplied: 0,
			minDoC:      6,
			maxDoC:      11,
		},
		{
			name: "table element",
			info: &VipsNodeInfo{
				TagName:    "table",
				ChildCount: 5,
			},
			ruleApplied: 0,
			minDoC:      7,
			maxDoC:      7,
		},
		{
			name: "form element",
			info: &VipsNodeInfo{
				TagName:    "form",
				ChildCount: 5,
			},
			ruleApplied: 0,
			minDoC:      8,
			maxDoC:      8,
		},
		{
			name: "rule 4 with bold",
			info: &VipsNodeInfo{
				TagName:    "div",
				FontWeight: "bold",
				ChildCount: 2,
			},
			ruleApplied: 4,
			minDoC:      10,
			maxDoC:      10,
		},
		{
			name: "rule 4 without bold",
			info: &VipsNodeInfo{
				TagName:    "div",
				FontWeight: "normal",
				ChildCount: 2,
			},
			ruleApplied: 4,
			minDoC:      9,
			maxDoC:      9,
		},
		{
			name: "rule 7 (background color)",
			info: &VipsNodeInfo{
				TagName:    "div",
				ChildCount: 2,
			},
			ruleApplied: 7,
			minDoC:      7,
			maxDoC:      7,
		},
		{
			name: "rule 9 with anchor",
			info: &VipsNodeInfo{
				TagName:    "a",
				ChildCount: 1,
			},
			ruleApplied: 9,
			minDoC:      11,
			maxDoC:      11,
		},
		{
			name: "rule 12 with li",
			info: &VipsNodeInfo{
				TagName:    "li",
				ChildCount: 2,
			},
			ruleApplied: 12,
			minDoC:      8,
			maxDoC:      8,
		},
		{
			name: "rule 12 with other",
			info: &VipsNodeInfo{
				TagName:    "div",
				ChildCount: 2,
			},
			ruleApplied: 12,
			minDoC:      7,
			maxDoC:      7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := CalculateDoC(tt.info, tt.ruleApplied)
			if doc < tt.minDoC || doc > tt.maxDoC {
				t.Errorf("CalculateDoC() = %d, want between %d and %d", doc, tt.minDoC, tt.maxDoC)
			}
		})
	}
}

// =============================================================================
// Iteration Thresholds Tests - Mirrors Crawljax's threshold reduction
// =============================================================================

func TestIterationThresholds(t *testing.T) {
	tests := []struct {
		numIterations int
		expectedLen   int
		checkFirst    SizeThreshold
		checkLast     SizeThreshold
	}{
		{
			numIterations: 10,
			expectedLen:   10,
			checkFirst:    SizeThreshold{Width: 350, Height: 350}, // (10-5)*50+100 = 350
			checkLast:     SizeThreshold{Width: 1, Height: 1},
		},
		{
			numIterations: 5,
			expectedLen:   5,
			checkFirst:    SizeThreshold{Width: 100, Height: 100}, // Min 100
			checkLast:     SizeThreshold{Width: 1, Height: 1},
		},
		{
			numIterations: 1,
			expectedLen:   1,
			checkFirst:    SizeThreshold{Width: 1, Height: 1},
			checkLast:     SizeThreshold{Width: 1, Height: 1},
		},
	}

	for _, tt := range tests {
		t.Run("iterations="+string(rune('0'+tt.numIterations)), func(t *testing.T) {
			thresholds := IterationThresholds(tt.numIterations)

			if len(thresholds) != tt.expectedLen {
				t.Errorf("len(thresholds) = %d, want %d", len(thresholds), tt.expectedLen)
			}

			// Check first threshold
			if thresholds[0] != tt.checkFirst {
				t.Errorf("thresholds[0] = %+v, want %+v", thresholds[0], tt.checkFirst)
			}

			// Check last threshold (should always be 1x1)
			if thresholds[len(thresholds)-1] != tt.checkLast {
				t.Errorf("thresholds[last] = %+v, want %+v", thresholds[len(thresholds)-1], tt.checkLast)
			}
		})
	}
}

func TestIterationThresholdsDecreasing(t *testing.T) {
	thresholds := IterationThresholds(10)

	// Verify thresholds are generally decreasing
	for i := 1; i < len(thresholds); i++ {
		prev := thresholds[i-1]
		curr := thresholds[i]

		// Each threshold should be <= previous
		if curr.Width > prev.Width || curr.Height > prev.Height {
			t.Errorf("threshold[%d] = %+v should be <= threshold[%d] = %+v", i, curr, i-1, prev)
		}
	}
}

// =============================================================================
// Separator Tests
// =============================================================================

func TestNewHorizontalSeparator(t *testing.T) {
	sep := NewHorizontalSeparator(10, 100, 500)

	if !sep.IsHorizontal {
		t.Error("IsHorizontal should be true")
	}
	if sep.IsVertical {
		t.Error("IsVertical should be false")
	}
	if sep.StartX != 10 {
		t.Errorf("StartX = %f, want 10", sep.StartX)
	}
	if sep.StartY != 100 {
		t.Errorf("StartY = %f, want 100", sep.StartY)
	}
	if sep.EndX != 500 {
		t.Errorf("EndX = %f, want 500", sep.EndX)
	}
	if sep.EndY != 100 {
		t.Errorf("EndY = %f, want 100 (same as StartY)", sep.EndY)
	}
}

func TestNewVerticalSeparator(t *testing.T) {
	sep := NewVerticalSeparator(200, 50, 400)

	if sep.IsHorizontal {
		t.Error("IsHorizontal should be false")
	}
	if !sep.IsVertical {
		t.Error("IsVertical should be true")
	}
	if sep.StartX != 200 {
		t.Errorf("StartX = %f, want 200", sep.StartX)
	}
	if sep.StartY != 50 {
		t.Errorf("StartY = %f, want 50", sep.StartY)
	}
	if sep.EndX != 200 {
		t.Errorf("EndX = %f, want 200 (same as StartX)", sep.EndX)
	}
	if sep.EndY != 400 {
		t.Errorf("EndY = %f, want 400", sep.EndY)
	}
}

func TestSeparatorLength(t *testing.T) {
	hSep := NewHorizontalSeparator(10, 100, 510)
	if hSep.Length() != 500 {
		t.Errorf("horizontal Length() = %f, want 500", hSep.Length())
	}

	vSep := NewVerticalSeparator(200, 50, 350)
	if vSep.Length() != 300 {
		t.Errorf("vertical Length() = %f, want 300", vSep.Length())
	}
}

// =============================================================================
// VipsSeparatorDetector Tests
// =============================================================================

func TestNewVipsSeparatorDetector(t *testing.T) {
	detector := NewVipsSeparatorDetector(1200, 800)

	if detector.pageWidth != 1200 {
		t.Errorf("pageWidth = %d, want 1200", detector.pageWidth)
	}
	if detector.pageHeight != 800 {
		t.Errorf("pageHeight = %d, want 800", detector.pageHeight)
	}
	if len(detector.horizontalSeparators) != 0 {
		t.Error("horizontalSeparators should be empty initially")
	}
	if len(detector.verticalSeparators) != 0 {
		t.Error("verticalSeparators should be empty initially")
	}
}

func TestVipsSeparatorDetectorDetectSeparators(t *testing.T) {
	detector := NewVipsSeparatorDetector(800, 600)

	// Create two blocks with a gap between them (vertically stacked)
	block1 := NewVisualBlock(1, "/div[1]", Rect{X: 0, Y: 0, Width: 800, Height: 200})
	block2 := NewVisualBlock(2, "/div[2]", Rect{X: 0, Y: 300, Width: 800, Height: 200})
	block1.IsVisualBlock = true
	block2.IsVisualBlock = true

	blocks := []*VisualBlock{block1, block2}
	detector.DetectSeparators(blocks)

	// Should detect horizontal separator between blocks
	hSeps := detector.GetHorizontalSeparators()
	if len(hSeps) == 0 {
		t.Error("should detect at least one horizontal separator")
	}
}

func TestVipsSeparatorDetectorSideBySide(t *testing.T) {
	detector := NewVipsSeparatorDetector(800, 600)

	// Create two blocks side by side
	block1 := NewVisualBlock(1, "/div[1]", Rect{X: 0, Y: 0, Width: 300, Height: 400})
	block2 := NewVisualBlock(2, "/div[2]", Rect{X: 400, Y: 0, Width: 300, Height: 400})
	block1.IsVisualBlock = true
	block2.IsVisualBlock = true

	blocks := []*VisualBlock{block1, block2}
	detector.DetectSeparators(blocks)

	// Should detect vertical separator between blocks
	vSeps := detector.GetVerticalSeparators()
	if len(vSeps) == 0 {
		t.Error("should detect at least one vertical separator")
	}
}

func TestVipsSeparatorDetectorNormalize(t *testing.T) {
	detector := NewVipsSeparatorDetector(800, 600)

	// Create blocks with varying gaps
	block1 := NewVisualBlock(1, "/div[1]", Rect{X: 0, Y: 0, Width: 800, Height: 100})
	block2 := NewVisualBlock(2, "/div[2]", Rect{X: 0, Y: 150, Width: 800, Height: 100}) // 50px gap
	block3 := NewVisualBlock(3, "/div[3]", Rect{X: 0, Y: 350, Width: 800, Height: 100}) // 100px gap

	blocks := []*VisualBlock{block1, block2, block3}
	detector.DetectSeparators(blocks)
	detector.NormalizeSeparatorWeights()

	allSeps := detector.GetAllSeparators()
	if len(allSeps) == 0 {
		return // No separators to check
	}

	// After normalization, weights should be between 0 and 1
	for _, sep := range allSeps {
		if sep.Weight < 0 || sep.Weight > 1 {
			t.Errorf("normalized weight %f should be between 0 and 1", sep.Weight)
		}
	}
}

// =============================================================================
// VisualStructureConstructor Tests
// =============================================================================

func TestNewVisualStructureConstructor(t *testing.T) {
	constructor := NewVisualStructureConstructor(8)

	if constructor.pDoC != 8 {
		t.Errorf("pDoC = %d, want 8", constructor.pDoC)
	}
	if len(constructor.separators) != 0 {
		t.Error("separators should be empty initially")
	}
}

func TestVisualStructureConstructorSetPageSize(t *testing.T) {
	constructor := NewVisualStructureConstructor(11)
	constructor.SetPageSize(1200, 800)

	if constructor.pageWidth != 1200 {
		t.Errorf("pageWidth = %d, want 1200", constructor.pageWidth)
	}
	if constructor.pageHeight != 800 {
		t.Errorf("pageHeight = %d, want 800", constructor.pageHeight)
	}
}

func TestVisualStructureConstructorConstruct(t *testing.T) {
	constructor := NewVisualStructureConstructor(11)
	constructor.SetPageSize(800, 600)

	// Create a simple hierarchy
	root := NewVisualBlock(0, "/html/body", Rect{X: 0, Y: 0, Width: 800, Height: 600})
	root.IsVisualBlock = true

	child1 := NewVisualBlock(1, "/html/body/div[1]", Rect{X: 0, Y: 0, Width: 400, Height: 300})
	child1.IsVisualBlock = true

	child2 := NewVisualBlock(2, "/html/body/div[2]", Rect{X: 400, Y: 0, Width: 400, Height: 300})
	child2.IsVisualBlock = true

	root.AddChild(child1)
	root.AddChild(child2)

	constructor.SetVipsBlocks(root)
	structure := constructor.ConstructVisualStructure()

	if structure == nil {
		t.Fatal("ConstructVisualStructure() returned nil")
	}
	if structure.PageWidth != 800 {
		t.Errorf("PageWidth = %d, want 800", structure.PageWidth)
	}
	if structure.PageHeight != 600 {
		t.Errorf("PageHeight = %d, want 600", structure.PageHeight)
	}
	if structure.PDoC != 11 {
		t.Errorf("PDoC = %d, want 11", structure.PDoC)
	}
	if len(structure.Blocks) == 0 {
		t.Error("Blocks should not be empty")
	}
}

func TestVisualStructureConstructorExportToFragments(t *testing.T) {
	constructor := NewVisualStructureConstructor(11)
	constructor.SetPageSize(800, 600)

	root := NewVisualBlock(0, "/html/body", Rect{X: 0, Y: 0, Width: 800, Height: 600})
	root.IsVisualBlock = true
	root.DOMHash = "root-hash"

	child := NewVisualBlock(1, "/html/body/div", Rect{X: 100, Y: 100, Width: 200, Height: 200})
	child.IsVisualBlock = true
	child.DOMHash = "child-hash"

	root.AddChild(child)

	constructor.SetVipsBlocks(root)
	constructor.ConstructVisualStructure()

	fragments := constructor.ExportToFragments()

	if len(fragments) == 0 {
		t.Fatal("ExportToFragments() returned empty slice")
	}

	// Verify fragments have proper IDs
	for _, frag := range fragments {
		if frag.XPath == "" {
			t.Error("fragment XPath should not be empty")
		}
	}
}

func TestVisualStructureConstructorExportToRectangles(t *testing.T) {
	constructor := NewVisualStructureConstructor(11)
	constructor.SetPageSize(800, 600)

	root := NewVisualBlock(0, "/html/body", Rect{X: 0, Y: 0, Width: 800, Height: 600})
	root.IsVisualBlock = true

	constructor.SetVipsBlocks(root)
	constructor.ConstructVisualStructure()

	rectangles := constructor.ExportToRectangles()

	if len(rectangles) == 0 {
		t.Fatal("ExportToRectangles() returned empty slice")
	}

	for _, rect := range rectangles {
		if rect.XPath == "" {
			t.Error("rectangle XPath should not be empty")
		}
	}
}

// =============================================================================
// VIPS Main Class Tests
// =============================================================================

func TestNewVIPS(t *testing.T) {
	vips := NewVIPS()

	if vips.pDoC != 11 {
		t.Errorf("pDoC = %d, want 11 (default)", vips.pDoC)
	}
	if vips.numIterations != 10 {
		t.Errorf("numIterations = %d, want 10 (default)", vips.numIterations)
	}
	if vips.minWidth != 10 {
		t.Errorf("minWidth = %f, want 10 (default)", vips.minWidth)
	}
	if vips.minHeight != 10 {
		t.Errorf("minHeight = %f, want 10 (default)", vips.minHeight)
	}
}

func TestVIPSWithPDoC(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{5, 5},
		{1, 1},
		{11, 11},
		{0, 1},   // Clamped to min
		{-5, 1},  // Clamped to min
		{15, 11}, // Clamped to max
	}

	for _, tt := range tests {
		vips := NewVIPS().WithPDoC(tt.input)
		if vips.pDoC != tt.expected {
			t.Errorf("WithPDoC(%d): pDoC = %d, want %d", tt.input, vips.pDoC, tt.expected)
		}
	}
}

func TestVIPSWithIterations(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{5, 5},
		{10, 10},
		{1, 1},
		{20, 20},
		{0, 1},   // Clamped to min
		{-1, 1},  // Clamped to min
		{25, 20}, // Clamped to max
	}

	for _, tt := range tests {
		vips := NewVIPS().WithIterations(tt.input)
		if vips.numIterations != tt.expected {
			t.Errorf("WithIterations(%d): numIterations = %d, want %d", tt.input, vips.numIterations, tt.expected)
		}
	}
}

func TestVIPSWithMinSize(t *testing.T) {
	vips := NewVIPS().WithMinSize(50, 100)

	if vips.minWidth != 50 {
		t.Errorf("minWidth = %f, want 50", vips.minWidth)
	}
	if vips.minHeight != 100 {
		t.Errorf("minHeight = %f, want 100", vips.minHeight)
	}
}

func TestVIPSConfigDefault(t *testing.T) {
	config := DefaultVIPSConfig()

	if config.PDoC != 11 {
		t.Errorf("PDoC = %d, want 11", config.PDoC)
	}
	if config.NumIterations != 10 {
		t.Errorf("NumIterations = %d, want 10", config.NumIterations)
	}
	if config.MinWidth != 10 {
		t.Errorf("MinWidth = %f, want 10", config.MinWidth)
	}
	if config.MinHeight != 10 {
		t.Errorf("MinHeight = %f, want 10", config.MinHeight)
	}
}

func TestNewVIPSWithConfig(t *testing.T) {
	config := VIPSConfig{
		PDoC:          8,
		NumIterations: 5,
		MinWidth:      20,
		MinHeight:     30,
	}

	vips := NewVIPSWithConfig(config)

	if vips.pDoC != 8 {
		t.Errorf("pDoC = %d, want 8", vips.pDoC)
	}
	if vips.numIterations != 5 {
		t.Errorf("numIterations = %d, want 5", vips.numIterations)
	}
	if vips.minWidth != 20 {
		t.Errorf("minWidth = %f, want 20", vips.minWidth)
	}
	if vips.minHeight != 30 {
		t.Errorf("minHeight = %f, want 30", vips.minHeight)
	}
}

func TestVIPSGettersWithoutExtraction(t *testing.T) {
	vips := NewVIPS()

	// Before extraction, all getters should return zero values
	if vips.GetFragmentCount() != 0 {
		t.Errorf("GetFragmentCount() = %d, want 0 before extraction", vips.GetFragmentCount())
	}
	if vips.GetVisualBlocks() != nil {
		t.Error("GetVisualBlocks() should be nil before extraction")
	}
	if vips.GetSeparators() != nil {
		t.Error("GetSeparators() should be nil before extraction")
	}
	if vips.GetRootBlock() != nil {
		t.Error("GetRootBlock() should be nil before extraction")
	}
	if vips.GetVisualStructure() != nil {
		t.Error("GetVisualStructure() should be nil before extraction")
	}
}

// =============================================================================
// HDN (Highest Differentiator Node) Tests
// =============================================================================

func TestFindClosestFragment(t *testing.T) {
	fragments := []*Fragment{
		{ID: 1, XPath: "/html/body"},
		{ID: 2, XPath: "/html/body/div"},
		{ID: 3, XPath: "/html/body/div/p"},
		{ID: 4, XPath: "/html/body/aside"},
	}

	tests := []struct {
		xpath      string
		expectedID int
		desc       string
	}{
		{"/html/body/div/p/span", 3, "should match closest parent"},
		{"/html/body/div/a", 2, "should match div"},
		{"/html/body/aside/nav", 4, "should match aside"},
		{"/html/body", 1, "should match exactly"},
		{"/html/head", -1, "should not match"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := findClosestFragment(fragments, tt.xpath)
			if tt.expectedID == -1 {
				if result != nil {
					t.Errorf("expected nil, got fragment ID %d", result.ID)
				}
			} else {
				if result == nil {
					t.Errorf("expected fragment ID %d, got nil", tt.expectedID)
				} else if result.ID != tt.expectedID {
					t.Errorf("expected fragment ID %d, got %d", tt.expectedID, result.ID)
				}
			}
		})
	}
}

func TestFindFragmentByXPath(t *testing.T) {
	fragments := []*Fragment{
		{ID: 1, XPath: "/html/body"},
		{ID: 2, XPath: "/html/body/div"},
		{ID: 3, XPath: "/html/body/div/p"},
	}

	tests := []struct {
		xpath    string
		expected bool
		desc     string
	}{
		{"/html/body", true, "should find body"},
		{"/html/body/div", true, "should find div"},
		{"/html/body/div/p", true, "should find p"},
		{"/html/body/aside", false, "should not find aside"},
		{"/html/head", false, "should not find head"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result, found := findFragmentByXPath(fragments, tt.xpath)
			if found != tt.expected {
				t.Errorf("found = %v, want %v", found, tt.expected)
			}
			if tt.expected && result == nil {
				t.Error("expected fragment but got nil")
			}
		})
	}
}

func TestUniqueFragments(t *testing.T) {
	f1 := &Fragment{ID: 1, XPath: "/div[1]"}
	f2 := &Fragment{ID: 2, XPath: "/div[2]"}
	f3 := &Fragment{ID: 3, XPath: "/div[3]"}

	// Include duplicates
	fragments := []*Fragment{f1, f2, f1, f3, f2, f1, f3}

	result := uniqueFragments(fragments)

	if len(result) != 3 {
		t.Errorf("len(result) = %d, want 3", len(result))
	}

	// Verify all unique fragments are present
	ids := make(map[int]bool)
	for _, f := range result {
		ids[f.ID] = true
	}
	if !ids[1] || !ids[2] || !ids[3] {
		t.Error("missing expected fragment IDs")
	}
}

// =============================================================================
// Dynamic Fragment Detection Tests
// =============================================================================

func TestDynamicFragmentDetectorDetectByContentChange(t *testing.T) {
	detector := NewDynamicFragmentDetector(nil)

	// Create state 1 fragments
	state1 := []*Fragment{
		{ID: 1, XPath: "/div[1]", ContentHash: "hash1"},
		{ID: 2, XPath: "/div[2]", ContentHash: "hash2"},
	}

	// Create state 2 fragments with different content for div[2]
	state2 := []*Fragment{
		{ID: 1, XPath: "/div[1]", ContentHash: "hash1"},         // Same
		{ID: 2, XPath: "/div[2]", ContentHash: "hash2_changed"}, // Changed
	}

	dynamic := detector.DetectDynamicFragments(state1, state2)

	// The fragment at /div[2] should be marked as dynamic in both states
	if len(dynamic) == 0 {
		t.Error("should detect dynamic fragments")
	}

	// Verify the fragments are marked as dynamic
	for _, f := range state1 {
		if f.XPath == "/div[2]" && !f.IsDynamic {
			t.Error("state1 /div[2] should be marked dynamic")
		}
	}
	for _, f := range state2 {
		if f.XPath == "/div[2]" && !f.IsDynamic {
			t.Error("state2 /div[2] should be marked dynamic")
		}
	}
}

func TestDynamicFragmentDetectorByDOMDiff(t *testing.T) {
	detector := NewDynamicFragmentDetector(nil)

	fragments := []*Fragment{
		{ID: 1, XPath: "/html/body"},
		{ID: 2, XPath: "/html/body/div"},
		{ID: 3, XPath: "/html/body/div/p"},
	}

	diffXPaths := []string{
		"/html/body/div/p/span",
		"/html/body/div/a",
	}

	dynamic := detector.DetectDynamicByDOMDiff(fragments, diffXPaths)

	// Should mark fragments that contain the diff paths as dynamic
	if len(dynamic) == 0 {
		t.Error("should detect dynamic fragments from DOM diff")
	}
}

// =============================================================================
// Candidate Element Tests
// =============================================================================

func TestCandidateElementLinkerGetCandidatesInFragment(t *testing.T) {
	linker := NewCandidateElementLinker(nil)

	candidates := []*CandidateElement{
		{XPath: "/div[1]/a", FragmentID: 1},
		{XPath: "/div[1]/button", FragmentID: 1},
		{XPath: "/div[2]/a", FragmentID: 2},
		{XPath: "/div[3]/input", FragmentID: 3},
	}

	result := linker.GetCandidatesInFragment(candidates, 1)

	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2", len(result))
	}

	for _, c := range result {
		if c.FragmentID != 1 {
			t.Errorf("FragmentID = %d, want 1", c.FragmentID)
		}
	}
}

func TestCandidateElementLinkerGetUnprocessedCandidates(t *testing.T) {
	linker := NewCandidateElementLinker(nil)

	candidates := []*CandidateElement{
		{XPath: "/a[1]", IsProcessed: false},
		{XPath: "/a[2]", IsProcessed: true},
		{XPath: "/a[3]", IsProcessed: false},
		{XPath: "/a[4]", IsProcessed: true},
	}

	result := linker.GetUnprocessedCandidates(candidates)

	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2", len(result))
	}

	for _, c := range result {
		if c.IsProcessed {
			t.Error("returned candidate should not be processed")
		}
	}
}
