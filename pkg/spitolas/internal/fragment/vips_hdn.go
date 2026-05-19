package fragment

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// HDNDetector detects the Highest Differentiator Node for fragments.
//
// The HDN is the DOM node closest to the root that contains all nested blocks
// of a fragment. It's used for:
// - Fragment identification across states
// - DOM comparison
// - Change detection
type HDNDetector struct {
	page *browser.Page
}

// NewHDNDetector creates a new HDN detector.
func NewHDNDetector(page *browser.Page) *HDNDetector {
	return &HDNDetector{
		page: page,
	}
}

// DetectHDN finds the Highest Differentiator Node for a fragment.
// Returns the XPath of the HDN.
func (d *HDNDetector) DetectHDN(fragment *Fragment) (string, error) {
	if fragment == nil || fragment.XPath == "" {
		return "", nil
	}

	script := `(fragmentXPath) => {
		// Get the fragment root element
		const fragRoot = document.evaluate(
			fragmentXPath.replace(/\[(\d+)\]/g, '[position()=$1]'),
			document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null
		).singleNodeValue;

		if (!fragRoot) return null;

		// Find HDN by traversing up from fragment root
		// HDN is the highest ancestor that:
		// 1. Contains all children of the fragment
		// 2. Is not too far from the fragment root

		let hdn = fragRoot;
		let current = fragRoot.parentElement;
		let depth = 0;
		const maxDepth = 5;

		while (current && depth < maxDepth) {
			// Check if current element is still specific to this fragment
			// (i.e., doesn't contain many other significant elements)
			const siblings = Array.from(current.children).filter(c => c !== hdn);
			const significantSiblings = siblings.filter(s => {
				const rect = s.getBoundingClientRect();
				return rect.width > 50 && rect.height > 50;
			});

			// If there are significant siblings, stop here
			if (significantSiblings.length > 0) {
				break;
			}

			// Move up
			hdn = current;
			current = current.parentElement;
			depth++;
		}

		// Return XPath of HDN
		return getXPath(hdn);

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
	}`

	result, err := d.page.EvalWithArgs(script, fragment.XPath)
	if err != nil {
		return fragment.XPath, nil // Fallback to fragment XPath
	}

	if hdnXPath, ok := result.(string); ok && hdnXPath != "" {
		return hdnXPath, nil
	}

	return fragment.XPath, nil
}

// SetFragmentHDN sets HDN for all fragments.
func (d *HDNDetector) SetFragmentHDNs(fragments []*Fragment) error {
	for _, frag := range fragments {
		hdnXPath, err := d.DetectHDN(frag)
		if err != nil {
			// Use fragment XPath as fallback
			hdnXPath = frag.XPath
		}

		// Store HDN XPath in fragment metadata
		// We use the Selector field to store HDN for now
		// In a full implementation, Fragment would have an HDN field
		if hdnXPath != frag.XPath {
			// Append HDN info to content hash (for differentiation)
			frag.ContentHash = frag.ContentHash + "|hdn:" + hdnXPath
		}
	}

	return nil
}

// DynamicFragmentDetector detects fragments that change between states.
type DynamicFragmentDetector struct {
	page *browser.Page
}

// NewDynamicFragmentDetector creates a new dynamic fragment detector.
func NewDynamicFragmentDetector(page *browser.Page) *DynamicFragmentDetector {
	return &DynamicFragmentDetector{
		page: page,
	}
}

// DetectDynamicFragments compares two states and marks dynamic fragments.
// Returns the list of fragments that differ between states.
func (d *DynamicFragmentDetector) DetectDynamicFragments(
	state1Fragments []*Fragment,
	state2Fragments []*Fragment,
) []*Fragment {
	dynamicFragments := make([]*Fragment, 0)

	// Build hash maps for quick lookup
	state1Map := make(map[string]*Fragment)
	state2Map := make(map[string]*Fragment)

	for _, f := range state1Fragments {
		state1Map[f.DOMHash] = f
	}
	for _, f := range state2Fragments {
		state2Map[f.DOMHash] = f
	}

	// Find fragments with same XPath but different content
	xpathMap1 := make(map[string]*Fragment)
	for _, f := range state1Fragments {
		xpathMap1[f.XPath] = f
	}

	for _, f2 := range state2Fragments {
		if f1, exists := xpathMap1[f2.XPath]; exists {
			// Same location, check if content differs
			if f1.ContentHash != f2.ContentHash {
				// Mark both as dynamic
				f1.IsDynamic = true
				f2.IsDynamic = true
				dynamicFragments = append(dynamicFragments, f1)
				if f1 != f2 {
					dynamicFragments = append(dynamicFragments, f2)
				}
			}
		}
	}

	// Also check for fragments that only exist in one state
	// (might indicate dynamic content)
	for xpath, f := range xpathMap1 {
		if _, exists := findFragmentByXPath(state2Fragments, xpath); !exists {
			// Fragment disappeared - its parent might be dynamic
			if f.ParentID >= 0 {
				for _, parent := range state1Fragments {
					if parent.ID == f.ParentID {
						parent.IsDynamic = true
						dynamicFragments = append(dynamicFragments, parent)
						break
					}
				}
			}
		}
	}

	return uniqueFragments(dynamicFragments)
}

// DetectDynamicByDOMDiff uses DOM comparison to detect dynamic fragments.
func (d *DynamicFragmentDetector) DetectDynamicByDOMDiff(
	fragments []*Fragment,
	diffXPaths []string,
) []*Fragment {
	dynamicFragments := make([]*Fragment, 0)

	for _, xpath := range diffXPaths {
		// Find fragment that contains this XPath
		frag := findClosestFragment(fragments, xpath)
		if frag != nil && !frag.IsDynamic {
			frag.IsDynamic = true
			dynamicFragments = append(dynamicFragments, frag)
		}
	}

	return dynamicFragments
}

// findFragmentByXPath finds a fragment by XPath.
func findFragmentByXPath(fragments []*Fragment, xpath string) (*Fragment, bool) {
	for _, f := range fragments {
		if f.XPath == xpath {
			return f, true
		}
	}
	return nil, false
}

// findClosestFragment finds the fragment that most closely matches an XPath.
func findClosestFragment(fragments []*Fragment, xpath string) *Fragment {
	var closestFrag *Fragment
	closestLength := 0

	for _, frag := range fragments {
		if strings.HasPrefix(xpath, frag.XPath) {
			if len(frag.XPath) > closestLength {
				closestLength = len(frag.XPath)
				closestFrag = frag
			}
		}
	}

	return closestFrag
}

// uniqueFragments removes duplicate fragments from a slice.
func uniqueFragments(fragments []*Fragment) []*Fragment {
	seen := make(map[int]bool)
	result := make([]*Fragment, 0)

	for _, f := range fragments {
		if !seen[f.ID] {
			seen[f.ID] = true
			result = append(result, f)
		}
	}

	return result
}

// CandidateElementLinker links candidate elements to fragments.
type CandidateElementLinker struct {
	page *browser.Page
}

// NewCandidateElementLinker creates a new candidate element linker.
func NewCandidateElementLinker(page *browser.Page) *CandidateElementLinker {
	return &CandidateElementLinker{
		page: page,
	}
}

// CandidateElement represents a clickable element.
type CandidateElement struct {
	XPath       string
	Selector    string
	TagName     string
	Text        string
	Rect        Rect
	FragmentID  int  // ID of containing fragment
	IsProcessed bool // Whether this element has been clicked

	DuplicateAccess  int  // Number of duplicate access events
	EquivalentAccess int  // Number of equivalent access events
	DirectAccess     bool // Whether this element was directly accessed

	ClosestFragment    *Fragment // Closest fragment containing this element
	ClosestDomFragment *Fragment // Closest DOM fragment
}

// WasExplored returns true if this candidate was explored (direct, duplicate, or equivalent access).
func (c *CandidateElement) WasExplored() bool {
	return c.DirectAccess || c.DuplicateAccess > 0 || c.EquivalentAccess > 0
}

// IncrementDuplicateAccess increments both duplicate and equivalent access counters.
func (c *CandidateElement) IncrementDuplicateAccess() {
	c.DuplicateAccess++
	c.EquivalentAccess++
}

// IncrementEquivalentAccess increments only the equivalent access counter.
func (c *CandidateElement) IncrementEquivalentAccess() {
	c.EquivalentAccess++
}

// SetDirectAccess marks this element as directly accessed.
func (c *CandidateElement) SetDirectAccess(directAccess bool) {
	c.DirectAccess = directAccess
	c.IncrementDuplicateAccess()
}

// LinkCandidates finds all candidate elements and links them to fragments.
func (l *CandidateElementLinker) LinkCandidates(fragments []*Fragment) ([]*CandidateElement, error) {
	// Find all clickable elements
	candidates, err := l.findCandidateElements()
	if err != nil {
		return nil, err
	}

	// Link each candidate to its containing fragment
	for _, candidate := range candidates {
		frag := findClosestFragment(fragments, candidate.XPath)
		if frag != nil {
			candidate.FragmentID = frag.ID
		} else {
			candidate.FragmentID = -1
		}
	}

	return candidates, nil
}

// findCandidateElements finds all clickable elements on the page.
func (l *CandidateElementLinker) findCandidateElements() ([]*CandidateElement, error) {
	script := `() => {
		const candidates = [];

		// Clickable element selectors
		const selectors = [
			'a[href]',
			'button',
			'input[type="submit"]',
			'input[type="button"]',
			'[onclick]',
			'[role="button"]',
			'[role="link"]'
		];

		const elements = document.querySelectorAll(selectors.join(','));

		for (const el of elements) {
			const rect = el.getBoundingClientRect();

			// Skip invisible elements
			if (rect.width <= 0 || rect.height <= 0) continue;

			const style = window.getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden') continue;

			candidates.push({
				xpath: getXPath(el),
				selector: getSelector(el),
				tagName: el.tagName.toLowerCase(),
				text: el.textContent.trim().substring(0, 100),
				rect: {
					x: rect.x + window.scrollX,
					y: rect.y + window.scrollY,
					width: rect.width,
					height: rect.height
				}
			});
		}

		return candidates;

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
				parts.unshift(selector);
				el = el.parentElement;
			}
			return parts.join(' > ');
		}
	}`

	result, err := l.page.Eval(script)
	if err != nil {
		return nil, err
	}

	candidates := make([]*CandidateElement, 0)

	arr, ok := result.([]interface{})
	if !ok {
		return candidates, nil
	}

	for _, item := range arr {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		candidate := &CandidateElement{
			XPath:    getString(itemMap, "xpath"),
			Selector: getString(itemMap, "selector"),
			TagName:  getString(itemMap, "tagName"),
			Text:     getString(itemMap, "text"),
		}

		if rectData, ok := itemMap["rect"].(map[string]interface{}); ok {
			candidate.Rect = Rect{
				X:      getFloat(rectData, "x"),
				Y:      getFloat(rectData, "y"),
				Width:  getFloat(rectData, "width"),
				Height: getFloat(rectData, "height"),
			}
		}

		candidates = append(candidates, candidate)
	}

	return candidates, nil
}

// GetCandidatesInFragment returns all candidates within a specific fragment.
func (l *CandidateElementLinker) GetCandidatesInFragment(candidates []*CandidateElement, fragmentID int) []*CandidateElement {
	result := make([]*CandidateElement, 0)
	for _, c := range candidates {
		if c.FragmentID == fragmentID {
			result = append(result, c)
		}
	}
	return result
}

// GetUnprocessedCandidates returns candidates that haven't been processed yet.
func (l *CandidateElementLinker) GetUnprocessedCandidates(candidates []*CandidateElement) []*CandidateElement {
	result := make([]*CandidateElement, 0)
	for _, c := range candidates {
		if !c.IsProcessed {
			result = append(result, c)
		}
	}
	return result
}
