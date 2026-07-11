package linkfinder

// ahoCorasickMatcher implements the Aho-Corasick algorithm for multi-pattern string matching.
// It builds a finite state machine from patterns and matches in O(n + m + z) time
// where n = text length, m = total patterns length, z = number of matches.
//
// This is used for efficient blacklist checking instead of O(n*k) loop with strings.Contains.
type ahoCorasickMatcher struct {
	root *acNode
}

// acNode represents a node in the Aho-Corasick automaton.
type acNode struct {
	children map[byte]*acNode
	fail     *acNode
	output   bool // true if this node marks end of a pattern
}

// newACNode creates a new automaton node.
func newACNode() *acNode {
	return &acNode{
		children: make(map[byte]*acNode),
	}
}

// newAhoCorasickMatcher builds an Aho-Corasick automaton from the given patterns.
func newAhoCorasickMatcher(patterns []string) *ahoCorasickMatcher {
	m := &ahoCorasickMatcher{
		root: newACNode(),
	}

	// Build trie
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		m.addPattern(pattern)
	}

	// Build failure links using BFS
	m.buildFailureLinks()

	return m
}

// addPattern adds a single pattern to the trie.
func (m *ahoCorasickMatcher) addPattern(pattern string) {
	node := m.root
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if node.children[c] == nil {
			node.children[c] = newACNode()
		}
		node = node.children[c]
	}
	node.output = true
}

// buildFailureLinks builds the failure function using BFS.
func (m *ahoCorasickMatcher) buildFailureLinks() {
	queue := make([]*acNode, 0, 256)

	// Initialize depth-1 nodes: their fail links point to root
	for _, child := range m.root.children {
		child.fail = m.root
		queue = append(queue, child)
	}

	// BFS to build fail links for deeper nodes
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for c, child := range current.children {
			queue = append(queue, child)

			// Follow fail links to find the longest proper suffix
			failNode := current.fail
			for failNode != nil && failNode.children[c] == nil {
				failNode = failNode.fail
			}

			if failNode == nil {
				child.fail = m.root
			} else {
				child.fail = failNode.children[c]
				// Merge output - if fail node is an output, this node is too
				if child.fail.output {
					child.output = true
				}
			}
		}
	}
}

// ContainsAny returns true if text contains any of the patterns.
// This is the main matching function - O(n) where n = len(text).
func (m *ahoCorasickMatcher) ContainsAny(text string) bool {
	node := m.root

	for i := 0; i < len(text); i++ {
		c := text[i]

		// Follow failure links until we find a match or reach root
		for node != m.root && node.children[c] == nil {
			node = node.fail
		}

		if next := node.children[c]; next != nil {
			node = next
		}

		// Check if current node or any node in fail chain is an output
		if node.output {
			return true
		}
	}

	return false
}

// blacklistMatcher is the pre-built Aho-Corasick automaton for blacklist checking.
// Initialized once at package load time.
var blacklistMatcher = newAhoCorasickMatcher(blacklistWordlist)

// containsBlacklistedPattern checks if text contains any blacklisted pattern.
// Uses Aho-Corasick for O(n) matching instead of O(n*k) loop.
func containsBlacklistedPattern(text string) bool {
	return blacklistMatcher.ContainsAny(text)
}
