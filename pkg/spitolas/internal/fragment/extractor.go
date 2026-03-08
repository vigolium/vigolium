package fragment

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// LandmarkSelectors are CSS selectors for semantic landmarks used for fragment detection.
var LandmarkSelectors = []string{
	"header",
	"nav",
	"main",
	"aside",
	"footer",
	"article",
	"section",
	"[role=banner]",
	"[role=navigation]",
	"[role=main]",
	"[role=contentinfo]",
	"form",
	"table",
	"div[id]",
	"div[class]",
}

// Extractor extracts fragments from a page.
type Extractor struct {
	selectors     []string
	minWidth      float64
	minHeight     float64
	minSubtree    int
	maxFragments  int
	includeNested bool
}

// NewExtractor creates a new fragment extractor.
func NewExtractor() *Extractor {
	return &Extractor{
		selectors:     LandmarkSelectors,
		minWidth:      50,
		minHeight:     50,
		minSubtree:    4,
		maxFragments:  100,
		includeNested: true,
	}
}

// WithSelectors sets custom landmark selectors.
func (e *Extractor) WithSelectors(selectors []string) *Extractor {
	e.selectors = selectors
	return e
}

// WithMinSize sets minimum fragment size.
func (e *Extractor) WithMinSize(width, height float64) *Extractor {
	e.minWidth = width
	e.minHeight = height
	return e
}

// WithMinSubtree sets minimum subtree size.
func (e *Extractor) WithMinSubtree(size int) *Extractor {
	e.minSubtree = size
	return e
}

// WithMaxFragments sets maximum number of fragments to extract.
func (e *Extractor) WithMaxFragments(max int) *Extractor {
	e.maxFragments = max
	return e
}

// Extract extracts fragments from the page.
func (e *Extractor) Extract(page *browser.Page) ([]*Fragment, error) {
	// Build selector string
	selectorList := ""
	for i, sel := range e.selectors {
		if i > 0 {
			selectorList += ","
		}
		selectorList += sel
	}

	script := fmt.Sprintf(`() => {
		const fragments = [];
		const elements = document.querySelectorAll(%q);
		let id = 0;

		for (const el of elements) {
			if (id >= %d) break;

			const rect = el.getBoundingClientRect();

			// Skip elements that are too small or not visible
			if (rect.width < %f || rect.height < %f) continue;

			// Count nodes in subtree
			const subtreeSize = countNodes(el);
			if (subtreeSize < %d) continue;

			// Get DOM structure hash
			const domHash = getDOMHash(el);

			// Get text content hash
			const contentHash = getContentHash(el);

			fragments.push({
				id: id++,
				xpath: getXPath(el),
				selector: getSelector(el),
				tagName: el.tagName.toLowerCase(),
				subtreeSize: subtreeSize,
				rect: {
					x: rect.x,
					y: rect.y,
					width: rect.width,
					height: rect.height
				},
				domHash: domHash,
				contentHash: contentHash
			});
		}

		// Build parent-child relationships based on containment
		for (let i = 0; i < fragments.length; i++) {
			for (let j = 0; j < fragments.length; j++) {
				if (i === j) continue;
				if (contains(fragments[i].rect, fragments[j].rect)) {
					// i contains j, but we want the smallest container
					let isSmallest = true;
					for (let k = 0; k < fragments.length; k++) {
						if (k === i || k === j) continue;
						if (contains(fragments[k].rect, fragments[j].rect) &&
							contains(fragments[i].rect, fragments[k].rect)) {
							isSmallest = false;
							break;
						}
					}
					if (isSmallest) {
						fragments[j].parentID = fragments[i].id;
						if (!fragments[i].childIDs) fragments[i].childIDs = [];
						fragments[i].childIDs.push(fragments[j].id);
					}
				}
			}
		}

		return fragments;

		function countNodes(el) {
			let count = 1;
			for (const child of el.children) {
				count += countNodes(child);
			}
			return count;
		}

		function getDOMHash(el) {
			// Create a structure hash based on tag names and depths
			const structure = getStructure(el, 0);
			return simpleHash(structure);
		}

		function getStructure(el, depth) {
			if (depth > 5) return '';
			let str = el.tagName;
			for (const child of el.children) {
				str += '>' + getStructure(child, depth + 1);
			}
			return str;
		}

		function getContentHash(el) {
			const text = el.textContent.replace(/\s+/g, ' ').trim().substring(0, 1000);
			return simpleHash(text);
		}

		// HIGH PRIORITY FIX: Improved hash function with better collision resistance
		// Uses cyrb53 algorithm - fast, good distribution, 53-bit output
		function simpleHash(str, seed = 0) {
			let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
			for (let i = 0, ch; i < str.length; i++) {
				ch = str.charCodeAt(i);
				h1 = Math.imul(h1 ^ ch, 2654435761);
				h2 = Math.imul(h2 ^ ch, 1597334677);
			}
			h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
			h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
			h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
			h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
			// Return 16-character hex string for better uniqueness
			return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(16, '0');
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
				if (el.className) {
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

		function contains(a, b) {
			return a.x <= b.x &&
				a.y <= b.y &&
				a.x + a.width >= b.x + b.width &&
				a.y + a.height >= b.y + b.height;
		}
	}`, selectorList, e.maxFragments, e.minWidth, e.minHeight, e.minSubtree)

	result, err := page.Eval(script)
	if err != nil {
		return nil, fmt.Errorf("failed to extract fragments: %w", err)
	}

	return e.parseFragments(result)
}

func (e *Extractor) parseFragments(result interface{}) ([]*Fragment, error) {
	fragments := make([]*Fragment, 0)

	arr, ok := result.([]interface{})
	if !ok {
		return fragments, nil
	}

	for _, item := range arr {
		fragMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		frag := e.parseFragment(fragMap)
		if frag != nil {
			fragments = append(fragments, frag)
		}
	}

	return fragments, nil
}

func (e *Extractor) parseFragment(data map[string]interface{}) *Fragment {
	id := getInt(data, "id")
	xpath := getString(data, "xpath")
	subtreeSize := getInt(data, "subtreeSize")

	rect := Rect{}
	if rectData, ok := data["rect"].(map[string]interface{}); ok {
		rect.X = getFloat(rectData, "x")
		rect.Y = getFloat(rectData, "y")
		rect.Width = getFloat(rectData, "width")
		rect.Height = getFloat(rectData, "height")
	}

	frag := NewFragment(id, xpath, rect, subtreeSize)
	frag.Selector = getString(data, "selector")
	frag.TagName = getString(data, "tagName")
	frag.DOMHash = getString(data, "domHash")
	frag.ContentHash = getString(data, "contentHash")

	// Parse parent-child relationships
	if parentID, ok := data["parentID"]; ok {
		if pid, ok := parentID.(float64); ok {
			frag.ParentID = int(pid)
		}
	} else {
		frag.ParentID = -1
	}

	if childIDs, ok := data["childIDs"].([]interface{}); ok {
		for _, cid := range childIDs {
			if id, ok := cid.(float64); ok {
				frag.ChildIDs = append(frag.ChildIDs, int(id))
			}
		}
	}

	return frag
}

// Helper functions

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		if n, ok := v.(float64); ok {
			return int(n)
		}
	}
	return 0
}

func getFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		if n, ok := v.(float64); ok {
			return n
		}
	}
	return 0
}
