package fragment

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// APTED implements the All Path Tree Edit Distance algorithm.
// This is a state-of-the-art algorithm for computing tree edit distance
// between DOM tree structures, comparison.
//
// References:
// - Pawlik, M., & Augsten, N. (2015). Efficient computation of the tree edit distance.
// - Pawlik, M., & Augsten, N. (2016). Tree edit distance: Robust and memory-efficient.

// APTEDNode represents a node in the tree for APTED computation.
type APTEDNode struct {
	Label    string       // Node label (tag name + key attributes)
	Children []*APTEDNode // Child nodes

	// Precomputed values for APTED algorithm
	id           int // Postorder ID
	leftmostLeaf int // Leftmost leaf descendant ID
	size         int // Subtree size
}

// NewAPTEDNode creates a new APTED node.
func NewAPTEDNode(label string) *APTEDNode {
	return &APTEDNode{
		Label:    label,
		Children: make([]*APTEDNode, 0),
	}
}

// AddChild adds a child node.
func (n *APTEDNode) AddChild(child *APTEDNode) {
	n.Children = append(n.Children, child)
}

// IsLeaf returns true if this node has no children.
func (n *APTEDNode) IsLeaf() bool {
	return len(n.Children) == 0
}

// Size returns the subtree size (including this node).
func (n *APTEDNode) Size() int {
	if n.size > 0 {
		return n.size
	}
	n.size = 1
	for _, child := range n.Children {
		n.size += child.Size()
	}
	return n.size
}

// APTED computes tree edit distance between two trees.
type APTED struct {
	// Cost model for edit operations
	insertCost float64
	deleteCost float64
	renameCost float64

	// Memoization tables
	forestDist [][]float64
	treeDist   [][]float64

	// Tree decomposition
	tree1Nodes []*APTEDNode
	tree2Nodes []*APTEDNode
}

// NewAPTED creates a new APTED calculator with default costs.
func NewAPTED() *APTED {
	return &APTED{
		insertCost: 1.0,
		deleteCost: 1.0,
		renameCost: 1.0,
	}
}

// WithCosts sets custom costs for edit operations.
func (a *APTED) WithCosts(insert, delete, rename float64) *APTED {
	a.insertCost = insert
	a.deleteCost = delete
	a.renameCost = rename
	return a
}

// Distance computes the tree edit distance between two trees.
// Returns a value >= 0, where 0 means identical trees.
func (a *APTED) Distance(tree1, tree2 *APTEDNode) float64 {
	if tree1 == nil && tree2 == nil {
		return 0
	}
	if tree1 == nil {
		return float64(tree2.Size()) * a.insertCost
	}
	if tree2 == nil {
		return float64(tree1.Size()) * a.deleteCost
	}

	// Index trees in postorder
	a.tree1Nodes = make([]*APTEDNode, 0)
	a.tree2Nodes = make([]*APTEDNode, 0)
	a.indexTree(tree1, &a.tree1Nodes)
	a.indexTree(tree2, &a.tree2Nodes)

	n := len(a.tree1Nodes)
	m := len(a.tree2Nodes)

	// Initialize distance matrices
	a.forestDist = make([][]float64, n+1)
	a.treeDist = make([][]float64, n+1)
	for i := range a.forestDist {
		a.forestDist[i] = make([]float64, m+1)
		a.treeDist[i] = make([]float64, m+1)
	}

	// Compute keyroots for both trees
	keyroots1 := a.computeKeyroots(tree1, a.tree1Nodes)
	keyroots2 := a.computeKeyroots(tree2, a.tree2Nodes)

	// Main APTED computation
	for _, kr1 := range keyroots1 {
		for _, kr2 := range keyroots2 {
			a.computeTreeDist(kr1, kr2)
		}
	}

	return a.treeDist[n][m]
}

// NormalizedDistance returns distance normalized to [0, 1] range.
// 0 = identical, 1 = completely different.
func (a *APTED) NormalizedDistance(tree1, tree2 *APTEDNode) float64 {
	dist := a.Distance(tree1, tree2)
	if tree1 == nil && tree2 == nil {
		return 0
	}

	size1, size2 := 0, 0
	if tree1 != nil {
		size1 = tree1.Size()
	}
	if tree2 != nil {
		size2 = tree2.Size()
	}

	maxSize := float64(size1 + size2)
	if maxSize == 0 {
		return 0
	}

	return dist / maxSize
}

// Similarity returns 1 - normalized distance (higher = more similar).
func (a *APTED) Similarity(tree1, tree2 *APTEDNode) float64 {
	return 1.0 - a.NormalizedDistance(tree1, tree2)
}

// indexTree indexes tree nodes in postorder and computes leftmost leaves.
func (a *APTED) indexTree(node *APTEDNode, nodes *[]*APTEDNode) int {
	if node == nil {
		return 0
	}

	leftmost := len(*nodes) + 1

	for _, child := range node.Children {
		childLeftmost := a.indexTree(child, nodes)
		if leftmost == len(*nodes)+1 {
			leftmost = childLeftmost
		}
	}

	node.id = len(*nodes) + 1
	node.leftmostLeaf = leftmost
	node.size = node.Size()
	*nodes = append(*nodes, node)

	return leftmost
}

// computeKeyroots computes keyroot nodes for the tree.
// Keyroots are nodes whose leftmost leaf is not shared with any ancestor.
func (a *APTED) computeKeyroots(root *APTEDNode, nodes []*APTEDNode) []int {
	n := len(nodes)
	visited := make(map[int]bool)
	keyroots := make([]int, 0)

	// Process nodes in reverse postorder (root first)
	for i := n - 1; i >= 0; i-- {
		node := nodes[i]
		if !visited[node.leftmostLeaf] {
			keyroots = append(keyroots, node.id)
			visited[node.leftmostLeaf] = true
		}
	}

	// Sort keyroots in ascending order
	for i := 0; i < len(keyroots)-1; i++ {
		for j := i + 1; j < len(keyroots); j++ {
			if keyroots[i] > keyroots[j] {
				keyroots[i], keyroots[j] = keyroots[j], keyroots[i]
			}
		}
	}

	return keyroots
}

// computeTreeDist computes tree distance for subtrees rooted at i and j.
func (a *APTED) computeTreeDist(i, j int) {
	node1 := a.tree1Nodes[i-1]
	node2 := a.tree2Nodes[j-1]

	l1 := node1.leftmostLeaf
	l2 := node2.leftmostLeaf

	// Initialize forest distance base cases
	a.forestDist[l1-1][l2-1] = 0

	for x := l1; x <= i; x++ {
		a.forestDist[x][l2-1] = a.forestDist[x-1][l2-1] + a.deleteCost
	}

	for y := l2; y <= j; y++ {
		a.forestDist[l1-1][y] = a.forestDist[l1-1][y-1] + a.insertCost
	}

	// Compute forest distances
	for x := l1; x <= i; x++ {
		xNode := a.tree1Nodes[x-1]
		for y := l2; y <= j; y++ {
			yNode := a.tree2Nodes[y-1]

			// Cost of renaming x to y
			renameCost := 0.0
			if xNode.Label != yNode.Label {
				renameCost = a.renameCost
			}

			if xNode.leftmostLeaf == l1 && yNode.leftmostLeaf == l2 {
				// Both are in the leftmost path
				a.forestDist[x][y] = min3(
					a.forestDist[x-1][y]+a.deleteCost,
					a.forestDist[x][y-1]+a.insertCost,
					a.forestDist[x-1][y-1]+renameCost,
				)
				a.treeDist[x][y] = a.forestDist[x][y]
			} else {
				// General case
				a.forestDist[x][y] = min3(
					a.forestDist[x-1][y]+a.deleteCost,
					a.forestDist[x][y-1]+a.insertCost,
					a.forestDist[xNode.leftmostLeaf-1][yNode.leftmostLeaf-1]+a.treeDist[x][y],
				)
			}
		}
	}
}

func min3(a, b, c float64) float64 {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

// FragmentToAPTEDTree converts a page fragment to an APTED tree.
// Uses JavaScript to extract DOM structure.
func FragmentToAPTEDTree(page *browser.Page, xpath string) (*APTEDNode, error) {
	script := fmt.Sprintf(`() => {
		function buildTree(node, maxDepth, depth) {
			if (!node || depth > maxDepth) return null;
			if (node.nodeType !== Node.ELEMENT_NODE) return null;

			const label = buildLabel(node);
			const children = [];

			for (const child of node.children) {
				const childTree = buildTree(child, maxDepth, depth + 1);
				if (childTree) {
					children.push(childTree);
				}
			}

			return { label, children };
		}

		function buildLabel(node) {
			let label = node.tagName.toLowerCase();

			// Add key attributes that affect structure
			if (node.id) {
				label += '#' + node.id;
			}
			if (node.className && typeof node.className === 'string') {
				const classes = node.className.split(/\s+/).filter(c => c).sort().slice(0, 3);
				if (classes.length) {
					label += '.' + classes.join('.');
				}
			}

			// Add role attribute for semantic elements
			const role = node.getAttribute('role');
			if (role) {
				label += '[role=' + role + ']';
			}

			return label;
		}

		// Find element by XPath
		const result = document.evaluate(
			%q,
			document,
			null,
			XPathResult.FIRST_ORDERED_NODE_TYPE,
			null
		);

		const element = result.singleNodeValue;
		if (!element) {
			return { error: 'Element not found' };
		}

		return buildTree(element, 10, 0);
	}`, xpath)

	result, err := page.Eval(script)
	if err != nil {
		return nil, fmt.Errorf("failed to extract DOM tree: %w", err)
	}

	return parseAPTEDTree(result)
}

// FragmentToAPTEDTreeBySelector converts a fragment to APTED tree using CSS selector.
func FragmentToAPTEDTreeBySelector(page *browser.Page, selector string) (*APTEDNode, error) {
	script := fmt.Sprintf(`() => {
		function buildTree(node, maxDepth, depth) {
			if (!node || depth > maxDepth) return null;
			if (node.nodeType !== Node.ELEMENT_NODE) return null;

			const label = buildLabel(node);
			const children = [];

			for (const child of node.children) {
				const childTree = buildTree(child, maxDepth, depth + 1);
				if (childTree) {
					children.push(childTree);
				}
			}

			return { label, children };
		}

		function buildLabel(node) {
			let label = node.tagName.toLowerCase();

			if (node.id) {
				label += '#' + node.id;
			}
			if (node.className && typeof node.className === 'string') {
				const classes = node.className.split(/\s+/).filter(c => c).sort().slice(0, 3);
				if (classes.length) {
					label += '.' + classes.join('.');
				}
			}

			const role = node.getAttribute('role');
			if (role) {
				label += '[role=' + role + ']';
			}

			return label;
		}

		const element = document.querySelector(%q);
		if (!element) {
			return { error: 'Element not found' };
		}

		return buildTree(element, 10, 0);
	}`, selector)

	result, err := page.Eval(script)
	if err != nil {
		return nil, fmt.Errorf("failed to extract DOM tree: %w", err)
	}

	return parseAPTEDTree(result)
}

// parseAPTEDTree parses JavaScript result into APTED tree.
func parseAPTEDTree(result interface{}) (*APTEDNode, error) {
	data, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid result type")
	}

	if errMsg, ok := data["error"].(string); ok && errMsg != "" {
		return nil, fmt.Errorf("%s", errMsg)
	}

	return parseAPTEDNode(data)
}

func parseAPTEDNode(data map[string]interface{}) (*APTEDNode, error) {
	label, _ := data["label"].(string)
	if label == "" {
		return nil, fmt.Errorf("missing label")
	}

	node := NewAPTEDNode(label)

	if children, ok := data["children"].([]interface{}); ok {
		for _, childData := range children {
			if childMap, ok := childData.(map[string]interface{}); ok {
				childNode, err := parseAPTEDNode(childMap)
				if err == nil {
					node.AddChild(childNode)
				}
			}
		}
	}

	return node, nil
}

// CompareFragmentsAPTED compares two fragments using APTED algorithm.
// Returns similarity score in [0, 1] range.
func CompareFragmentsAPTED(page *browser.Page, frag1, frag2 *Fragment) (float64, error) {
	tree1, err := FragmentToAPTEDTree(page, frag1.XPath)
	if err != nil {
		return 0, fmt.Errorf("failed to build tree for fragment 1: %w", err)
	}

	tree2, err := FragmentToAPTEDTree(page, frag2.XPath)
	if err != nil {
		return 0, fmt.Errorf("failed to build tree for fragment 2: %w", err)
	}

	apted := NewAPTED()
	return apted.Similarity(tree1, tree2), nil
}

// CompareFragmentTrees compares pre-built APTED trees.
func CompareFragmentTrees(tree1, tree2 *APTEDNode) float64 {
	apted := NewAPTED()
	return apted.Similarity(tree1, tree2)
}

// StringToAPTEDTree creates an APTED tree from a simple string representation.
// Format: "tag{child1{...},child2{...}}"
// Used for testing and simple structure comparisons.
func StringToAPTEDTree(s string) *APTEDNode {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	return parseTreeString(s)
}

func parseTreeString(s string) *APTEDNode {
	// Find label (everything before first '{' or entire string)
	braceIdx := strings.Index(s, "{")
	if braceIdx == -1 {
		return NewAPTEDNode(s)
	}

	label := s[:braceIdx]
	node := NewAPTEDNode(label)

	// Parse children
	if braceIdx < len(s)-1 && s[len(s)-1] == '}' {
		childrenStr := s[braceIdx+1 : len(s)-1]
		children := splitChildren(childrenStr)
		for _, childStr := range children {
			if child := parseTreeString(childStr); child != nil {
				node.AddChild(child)
			}
		}
	}

	return node
}

func splitChildren(s string) []string {
	var children []string
	var current strings.Builder
	depth := 0

	for _, ch := range s {
		switch ch {
		case '{':
			depth++
			current.WriteRune(ch)
		case '}':
			depth--
			current.WriteRune(ch)
		case ',':
			if depth == 0 {
				if str := strings.TrimSpace(current.String()); str != "" {
					children = append(children, str)
				}
				current.Reset()
			} else {
				current.WriteRune(ch)
			}
		default:
			current.WriteRune(ch)
		}
	}

	if str := strings.TrimSpace(current.String()); str != "" {
		children = append(children, str)
	}

	return children
}

// TreeToString converts an APTED tree back to string representation.
func TreeToString(node *APTEDNode) string {
	if node == nil {
		return ""
	}

	if len(node.Children) == 0 {
		return node.Label
	}

	var sb strings.Builder
	sb.WriteString(node.Label)
	sb.WriteRune('{')

	for i, child := range node.Children {
		if i > 0 {
			sb.WriteRune(',')
		}
		sb.WriteString(TreeToString(child))
	}

	sb.WriteRune('}')
	return sb.String()
}
