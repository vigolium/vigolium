package fragment

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// VipsParser implements the VIPS visual block detection algorithm.
type VipsParser struct {
	page *browser.Page

	// Size thresholds for current iteration
	sizeThresholdWidth  int
	sizeThresholdHeight int

	// Page dimensions
	pageWidth  int
	pageHeight int

	// Current visual block being processed
	currentBlock *VisualBlock

	// Statistics
	visualBlockCount int
}

// NewVipsParser creates a new VIPS parser.
func NewVipsParser(page *browser.Page) *VipsParser {
	return &VipsParser{
		page:                page,
		sizeThresholdWidth:  80,
		sizeThresholdHeight: 80,
	}
}

// SetThresholds sets the size thresholds for visual block detection.
func (p *VipsParser) SetThresholds(width, height int) {
	p.sizeThresholdWidth = width
	p.sizeThresholdHeight = height
}

// SetPageSize sets the page dimensions.
func (p *VipsParser) SetPageSize(width, height int) {
	p.pageWidth = width
	p.pageHeight = height
}

// Parse executes VIPS visual block detection on the page.
// Returns the root visual block with hierarchy.
func (p *VipsParser) Parse() (*VisualBlock, error) {
	p.visualBlockCount = 0

	// Get all node info from the page via JavaScript
	nodes, err := p.extractNodeInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to extract node info: %w", err)
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes found in page")
	}

	// Build visual block tree from node info
	root := p.buildBlockTree(nodes)
	if root == nil {
		return nil, fmt.Errorf("failed to build block tree")
	}

	// Apply VIPS rules to divide blocks
	p.divideBlockTree(root, nodes)

	return root, nil
}

// extractNodeInfo extracts VIPS-relevant information from all DOM nodes.
func (p *VipsParser) extractNodeInfo() (map[string]*VipsNodeInfo, error) {
	script := fmt.Sprintf(`() => {
		const nodes = {};
		const thresholdW = %d;
		const thresholdH = %d;

		function processNode(node, parentXPath) {
			if (!node || node.nodeType !== Node.ELEMENT_NODE) return;

			const xpath = getXPath(node);
			const rect = node.getBoundingClientRect();
			const style = window.getComputedStyle(node);

			// Skip invisible elements
			if (style.display === 'none' || style.visibility === 'hidden') return;
			if (rect.width <= 0 || rect.height <= 0) return;

			const children = Array.from(node.children);
			const childXPaths = children
				.filter(c => {
					const r = c.getBoundingClientRect();
					return r.width > 0 && r.height > 0;
				})
				.map(c => getXPath(c));

			// Check text content
			const textNodes = Array.from(node.childNodes).filter(n => n.nodeType === Node.TEXT_NODE);
			const hasText = textNodes.some(t => t.textContent.trim().length > 0);
			const textLength = textNodes.reduce((sum, t) => sum + t.textContent.trim().length, 0);

			// Check if all children are inline/text
			const hasOnlyText = children.length === 0 && hasText;
			const hasInlineOnly = children.every(c => isInlineElement(c.tagName.toLowerCase()));

			// Check for special elements
			const containsHR = node.querySelector('hr') !== null;
			const containsTable = node.querySelector('table') !== null || node.tagName.toLowerCase() === 'table';
			const containsP = node.querySelector('p') !== null || node.tagName.toLowerCase() === 'p';
			const containsImg = node.querySelector('img') !== null || node.tagName.toLowerCase() === 'img';

			nodes[xpath] = {
				tagName: node.tagName.toLowerCase(),
				xpath: xpath,
				selector: getSelector(node),
				rect: {
					x: rect.x + window.scrollX,
					y: rect.y + window.scrollY,
					width: rect.width,
					height: rect.height
				},
				isDisplayed: style.display !== 'none' && style.visibility !== 'hidden',
				backgroundColor: style.backgroundColor,
				fontSize: parseInt(style.fontSize) || 12,
				fontWeight: style.fontWeight,
				childCount: childXPaths.length,
				textLength: textLength,
				hasText: hasText,
				hasOnlyText: hasOnlyText,
				hasInlineOnly: hasInlineOnly,
				containsHR: containsHR,
				containsTable: containsTable,
				containsP: containsP,
				containsImg: containsImg,
				isVirtual: false,
				children: childXPaths
			};

			// Process children
			for (const child of children) {
				processNode(child, xpath);
			}
		}

		function isInlineElement(tag) {
			const inline = ['a','abbr','acronym','b','bdo','big','button','cite','code',
				'dfn','em','i','img','input','kbd','label','map','object','output',
				'q','samp','select','option','small','span','strong','sub','sup',
				'textarea','time','tt','var'];
			return inline.includes(tag);
		}

		function getXPath(el) {
			const parts = [];
			while (el && el.nodeType === Node.ELEMENT_NODE) {
				let idx = 1;
				let sibling = el.previousElementSibling;
				while (sibling) {
					if (sibling.tagName === el.tagName) idx++;
					sibling = sibling.previousElementSibling;
				}
				parts.unshift(el.tagName.toLowerCase() + '[' + idx + ']');
				el = el.parentElement;
			}
			return '/' + parts.join('/');
		}

		function getSelector(el) {
			if (el.id) return '#' + el.id;
			const parts = [];
			while (el && el.nodeType === Node.ELEMENT_NODE) {
				let selector = el.tagName.toLowerCase();
				if (el.id) {
					parts.unshift('#' + el.id);
					break;
				}
				if (el.className && typeof el.className === 'string') {
					const classes = el.className.split(/\s+/).filter(c => c).slice(0, 2);
					if (classes.length) selector += '.' + classes.join('.');
				}
				let sibling = el;
				let nth = 1;
				while (sibling = sibling.previousElementSibling) {
					if (sibling.tagName === el.tagName) nth++;
				}
				if (nth > 1) selector += ':nth-of-type(' + nth + ')';
				parts.unshift(selector);
				el = el.parentElement;
			}
			return parts.join(' > ');
		}

		// Start from body
		const body = document.body;
		if (body) {
			processNode(body, '');
		}

		return nodes;
	}`, p.sizeThresholdWidth, p.sizeThresholdHeight)

	result, err := p.page.Eval(script)
	if err != nil {
		return nil, err
	}

	// Parse result into map
	nodes := make(map[string]*VipsNodeInfo)

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nodes, nil
	}

	for xpath, nodeData := range resultMap {
		nodeMap, ok := nodeData.(map[string]interface{})
		if !ok {
			continue
		}

		info := &VipsNodeInfo{
			TagName:  getString(nodeMap, "tagName"),
			XPath:    xpath,
			Selector: getString(nodeMap, "selector"),
		}

		// Parse rect
		if rectData, ok := nodeMap["rect"].(map[string]interface{}); ok {
			info.Rect = RectInfo{
				X:      getFloat(rectData, "x"),
				Y:      getFloat(rectData, "y"),
				Width:  getFloat(rectData, "width"),
				Height: getFloat(rectData, "height"),
			}
		}

		info.IsDisplayed = getBool(nodeMap, "isDisplayed")
		info.BackgroundColor = getString(nodeMap, "backgroundColor")
		info.FontSize = getInt(nodeMap, "fontSize")
		info.FontWeight = getString(nodeMap, "fontWeight")
		info.ChildCount = getInt(nodeMap, "childCount")
		info.TextLength = getInt(nodeMap, "textLength")
		info.HasText = getBool(nodeMap, "hasText")
		info.HasOnlyText = getBool(nodeMap, "hasOnlyText")
		info.HasInlineOnly = getBool(nodeMap, "hasInlineOnly")
		info.ContainsHR = getBool(nodeMap, "containsHR")
		info.ContainsTable = getBool(nodeMap, "containsTable")
		info.ContainsP = getBool(nodeMap, "containsP")
		info.ContainsImg = getBool(nodeMap, "containsImg")

		// Parse children
		if children, ok := nodeMap["children"].([]interface{}); ok {
			for _, c := range children {
				if s, ok := c.(string); ok {
					info.Children = append(info.Children, s)
				}
			}
		}

		nodes[xpath] = info
	}

	return nodes, nil
}

// buildBlockTree builds a visual block tree from node info.
func (p *VipsParser) buildBlockTree(nodes map[string]*VipsNodeInfo) *VisualBlock {
	// Find body node
	var bodyXPath string
	for xpath, info := range nodes {
		if info.TagName == "body" {
			bodyXPath = xpath
			break
		}
	}

	if bodyXPath == "" {
		return nil
	}

	return p.createBlock(bodyXPath, nodes, nil, 0)
}

// createBlock creates a visual block from node info.
func (p *VipsParser) createBlock(xpath string, nodes map[string]*VipsNodeInfo, parent *VisualBlock, id int) *VisualBlock {
	info, ok := nodes[xpath]
	if !ok {
		return nil
	}

	block := NewVisualBlock(id, xpath, info.Rect.ToRect())
	block.TagName = info.TagName
	block.Selector = info.Selector
	block.Parent = parent
	if parent != nil {
		block.ParentID = parent.ID
	}

	// Set metadata
	block.BackgroundColor = info.BackgroundColor
	block.FontSize = info.FontSize
	block.FontWeight = info.FontWeight
	block.ContainsTable = info.ContainsTable
	block.PCount = 0
	if info.ContainsP {
		block.PCount = 1
	}
	block.ImageCount = 0
	if info.ContainsImg {
		block.ImageCount = 1
	}
	block.LinkTextLength = info.TextLength

	// Build children recursively
	childID := id + 1
	for _, childXPath := range info.Children {
		childBlock := p.createBlock(childXPath, nodes, block, childID)
		if childBlock != nil {
			block.Children = append(block.Children, childBlock)
			childID = p.getMaxID(childBlock) + 1
		}
	}

	return block
}

// getMaxID returns the maximum ID in a block subtree.
func (p *VipsParser) getMaxID(block *VisualBlock) int {
	maxID := block.ID
	for _, child := range block.Children {
		childMax := p.getMaxID(child)
		if childMax > maxID {
			maxID = childMax
		}
	}
	return maxID
}

// divideBlockTree applies VIPS rules to determine visual blocks.
func (p *VipsParser) divideBlockTree(block *VisualBlock, nodes map[string]*VipsNodeInfo) {
	if block == nil {
		return
	}

	info := nodes[block.XPath]
	if info == nil {
		return
	}

	p.currentBlock = block
	block.IsVisualBlock = false
	block.IsDividable = true

	// Apply VIPS rules
	ruleApplied, shouldDivide := p.applyVipsRules(block, info, nodes)

	if shouldDivide && block.IsDividable && !block.IsVisualBlock {
		// Dividable - process children
		block.AlreadyDivided = true
		for _, child := range block.Children {
			p.divideBlockTree(child, nodes)
		}
	} else {
		// Not dividable - mark as visual block
		if block.IsDividable {
			block.IsVisualBlock = true
			block.DoC = CalculateDoC(info, ruleApplied)
			p.visualBlockCount++
		}

		// Verify validity
		if !p.isValidBlock(block, info) {
			block.IsVisualBlock = false
		}
	}
}

// applyVipsRules applies VIPS rules based on node type.
// Returns (rule number applied, should divide).
func (p *VipsParser) applyVipsRules(block *VisualBlock, info *VipsNodeInfo, nodes map[string]*VipsNodeInfo) (int, bool) {
	tagName := strings.ToLower(info.TagName)

	switch {
	case IsInlineElement(tagName):
		return p.applyInlineRules(block, info, nodes)
	case tagName == "table":
		return p.applyTableRules(block, info, nodes)
	case tagName == "tr":
		return p.applyTrRules(block, info, nodes)
	case tagName == "td" || tagName == "th":
		return p.applyTdRules(block, info, nodes)
	case tagName == "p":
		return p.applyPRules(block, info, nodes)
	default:
		return p.applyOtherRules(block, info, nodes)
	}
}

// applyInlineRules applies rules for inline elements (1,2,3,4,5,6,8,9,11).
func (p *VipsParser) applyInlineRules(block *VisualBlock, info *VipsNodeInfo, nodes map[string]*VipsNodeInfo) (int, bool) {
	if p.ruleOne(block, info) {
		return 1, true
	}
	if p.ruleTwo(block, info) {
		return 2, true
	}
	if p.ruleThree(block, info) {
		return 3, true
	}
	if p.ruleFour(block, info) {
		return 4, true
	}
	if p.ruleFive(block, info) {
		return 5, true
	}
	if p.ruleSix(block, info) {
		return 6, true
	}
	if p.ruleEight(block, info) {
		return 8, true
	}
	if p.ruleNine(block, info) {
		return 9, true
	}
	if p.ruleEleven(block, info) {
		return 11, true
	}
	return 0, false
}

// applyTableRules applies rules for TABLE elements (1,2,3,7,9,12).
func (p *VipsParser) applyTableRules(block *VisualBlock, info *VipsNodeInfo, nodes map[string]*VipsNodeInfo) (int, bool) {
	if p.ruleOne(block, info) {
		return 1, true
	}
	if p.ruleTwo(block, info) {
		return 2, true
	}
	if p.ruleThree(block, info) {
		return 3, true
	}
	if p.ruleSeven(block, info, nodes) {
		return 7, true
	}
	if p.ruleNine(block, info) {
		return 9, true
	}
	if p.ruleTwelve(block, info) {
		return 12, true
	}
	return 0, false
}

// applyTrRules applies rules for TR elements (1,2,3,7,9,12).
func (p *VipsParser) applyTrRules(block *VisualBlock, info *VipsNodeInfo, nodes map[string]*VipsNodeInfo) (int, bool) {
	return p.applyTableRules(block, info, nodes)
}

// applyTdRules applies rules for TD elements (1,2,3,4,8,9,10,12).
func (p *VipsParser) applyTdRules(block *VisualBlock, info *VipsNodeInfo, nodes map[string]*VipsNodeInfo) (int, bool) {
	if p.ruleOne(block, info) {
		return 1, true
	}
	if p.ruleTwo(block, info) {
		return 2, true
	}
	if p.ruleThree(block, info) {
		return 3, true
	}
	if p.ruleFour(block, info) {
		return 4, true
	}
	if p.ruleEight(block, info) {
		return 8, true
	}
	if p.ruleNine(block, info) {
		return 9, true
	}
	if p.ruleTen(block) {
		return 10, true
	}
	if p.ruleTwelve(block, info) {
		return 12, true
	}
	return 0, false
}

// applyPRules applies rules for P elements (1,2,3,4,5,6,7,8,9,10,11,12).
func (p *VipsParser) applyPRules(block *VisualBlock, info *VipsNodeInfo, nodes map[string]*VipsNodeInfo) (int, bool) {
	if p.ruleOne(block, info) {
		return 1, true
	}
	if p.ruleTwo(block, info) {
		return 2, true
	}
	if p.ruleThree(block, info) {
		return 3, true
	}
	if p.ruleFour(block, info) {
		return 4, true
	}
	if p.ruleFive(block, info) {
		return 5, true
	}
	if p.ruleSix(block, info) {
		return 6, true
	}
	if p.ruleSeven(block, info, nodes) {
		return 7, true
	}
	if p.ruleEight(block, info) {
		return 8, true
	}
	if p.ruleNine(block, info) {
		return 9, true
	}
	if p.ruleTen(block) {
		return 10, true
	}
	if p.ruleEleven(block, info) {
		return 11, true
	}
	if p.ruleTwelve(block, info) {
		return 12, true
	}
	return 0, false
}

// applyOtherRules applies rules for other block elements (1,2,3,4,6,8,9,11).
func (p *VipsParser) applyOtherRules(block *VisualBlock, info *VipsNodeInfo, nodes map[string]*VipsNodeInfo) (int, bool) {
	if p.ruleOne(block, info) {
		return 1, true
	}
	if p.ruleTwo(block, info) {
		return 2, true
	}
	if p.ruleThree(block, info) {
		return 3, true
	}
	if p.ruleFour(block, info) {
		return 4, true
	}
	if p.ruleSix(block, info) {
		return 6, true
	}
	if p.ruleEight(block, info) {
		return 8, true
	}
	if p.ruleNine(block, info) {
		return 9, true
	}
	if p.ruleEleven(block, info) {
		return 11, true
	}
	return 0, false
}

// ruleOne: If not a text node and has no valid children, cannot be divided.
func (p *VipsParser) ruleOne(block *VisualBlock, info *VipsNodeInfo) bool {
	if IsTextNode(info.TagName) {
		return false
	}

	if len(block.Children) == 0 && !info.HasText && !info.ContainsImg {
		block.IsDividable = false
		return true
	}

	return false
}

// ruleTwo: If only one valid child and it's not text, divide.
func (p *VipsParser) ruleTwo(block *VisualBlock, info *VipsNodeInfo) bool {
	if len(block.Children) == 1 {
		child := block.Children[0]
		if !IsTextNode(child.TagName) {
			return true
		}
	}
	return false
}

// ruleThree: If root of sub-DOM tree with only one subtree, divide.
func (p *VipsParser) ruleThree(block *VisualBlock, info *VipsNodeInfo) bool {
	if strings.ToLower(info.TagName) != "body" {
		return false
	}
	return len(block.Children) == 1
}

// ruleFour: If all children are text/virtual text, do not divide.
func (p *VipsParser) ruleFour(block *VisualBlock, info *VipsNodeInfo) bool {
	if len(block.Children) == 0 {
		return false
	}

	// Check if all children are inline/text
	for _, child := range block.Children {
		if !IsInlineElement(child.TagName) && !IsTextNode(child.TagName) {
			return false
		}
	}

	block.IsVisualBlock = true
	block.IsDividable = false
	block.DoC = 10
	return true
}

// ruleFive: If one child is a line-break node, divide.
func (p *VipsParser) ruleFive(block *VisualBlock, info *VipsNodeInfo) bool {
	if len(block.Children) == 0 {
		return false
	}

	for _, child := range block.Children {
		if !IsInlineElement(child.TagName) {
			return true
		}
	}
	return false
}

// ruleSix: If contains HR element, divide.
func (p *VipsParser) ruleSix(block *VisualBlock, info *VipsNodeInfo) bool {
	return info.ContainsHR
}

// ruleSeven: If background color differs from a child, divide.
func (p *VipsParser) ruleSeven(block *VisualBlock, info *VipsNodeInfo, nodes map[string]*VipsNodeInfo) bool {
	if len(block.Children) == 0 {
		return false
	}

	parentBg := info.BackgroundColor

	for _, child := range block.Children {
		childInfo := nodes[child.XPath]
		if childInfo != nil && childInfo.BackgroundColor != parentBg {
			child.IsDividable = false
			child.IsVisualBlock = true
			child.DoC = 7
			return true
		}
	}
	return false
}

// ruleEight: If has text and size is small, do not divide.
func (p *VipsParser) ruleEight(block *VisualBlock, info *VipsNodeInfo) bool {
	if !info.HasText && info.TextLength == 0 {
		return false
	}

	area := info.Rect.GetArea()
	threshold := float64(p.sizeThresholdWidth * p.sizeThresholdHeight)

	if area > threshold {
		return false
	}

	// UL elements are special
	if strings.ToLower(info.TagName) == "ul" {
		return true
	}

	block.IsVisualBlock = true
	block.IsDividable = false
	return true
}

// ruleNine: If max child size is small, do not divide.
func (p *VipsParser) ruleNine(block *VisualBlock, info *VipsNodeInfo) bool {
	if len(block.Children) == 0 {
		return false
	}

	var maxSize float64
	for _, child := range block.Children {
		childSize := child.Rect.Area()
		if childSize > maxSize {
			maxSize = childSize
		}
	}

	threshold := float64(p.sizeThresholdWidth * p.sizeThresholdHeight)

	if maxSize > threshold {
		return true
	}

	block.IsVisualBlock = true
	block.IsDividable = false
	return true
}

// ruleTen: If previous sibling was not divided, do not divide.
func (p *VipsParser) ruleTen(block *VisualBlock) bool {
	if block.Parent == nil {
		return false
	}

	// Find previous sibling
	siblings := block.Parent.Children
	for i, sibling := range siblings {
		if sibling == block && i > 0 {
			prevSibling := siblings[i-1]
			return prevSibling.AlreadyDivided
		}
	}
	return false
}

// ruleEleven: Divide if not inline.
func (p *VipsParser) ruleEleven(block *VisualBlock, info *VipsNodeInfo) bool {
	return !IsInlineElement(info.TagName)
}

// ruleTwelve: Do not divide.
func (p *VipsParser) ruleTwelve(block *VisualBlock, info *VipsNodeInfo) bool {
	block.IsDividable = false
	block.IsVisualBlock = true
	return true
}

// isValidBlock checks if a block is valid (visible and within page bounds).
func (p *VipsParser) isValidBlock(block *VisualBlock, info *VipsNodeInfo) bool {
	rect := info.Rect

	if rect.X < 0 || rect.Y < 0 {
		return false
	}

	if p.pageWidth > 0 && rect.X+rect.Width > float64(p.pageWidth) {
		return false
	}

	if p.pageHeight > 0 && rect.Y+rect.Height > float64(p.pageHeight) {
		return false
	}

	if rect.Width <= 0 || rect.Height <= 0 {
		return false
	}

	if !info.IsDisplayed {
		return false
	}

	// Must have some content
	if info.TextLength == 0 && !info.ContainsImg && strings.ToLower(info.TagName) != "input" {
		return false
	}

	return true
}

// GetVisualBlocks returns all visual blocks from the tree.
func (p *VipsParser) GetVisualBlocks(root *VisualBlock) []*VisualBlock {
	var blocks []*VisualBlock
	p.collectVisualBlocks(root, &blocks)
	return blocks
}

func (p *VipsParser) collectVisualBlocks(block *VisualBlock, blocks *[]*VisualBlock) {
	if block.IsVisualBlock {
		*blocks = append(*blocks, block)
	}

	for _, child := range block.Children {
		p.collectVisualBlocks(child, blocks)
	}
}

// GetVisualBlockCount returns the count of detected visual blocks.
func (p *VipsParser) GetVisualBlockCount() int {
	return p.visualBlockCount
}

// Helper functions
func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
