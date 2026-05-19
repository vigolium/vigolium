package action

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// CDP script to detect event listeners on elements.
const cdpScript = `
function getEventHandlers(xpath) {
	try {
		var result = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
		var a = result.singleNodeValue;
		var returnMap = {};
		if (a == null) {
			return returnMap;
		}

		// Method 1: Chrome DevTools getEventListeners API (requires includeCommandLineAPI=true)
		if (typeof getEventListeners === 'function') {
			var listeners = getEventListeners(a);
			if (listeners && listeners['click'] && listeners['click'].length > 0) {
				returnMap['eventListeners'] = listeners['click'][0].listener.toString();
				return returnMap;
			}
		}

		// Method 2: Check jQuery internal event data (for jQuery >= 1.8)
		// jQuery stores events in $._data(element, 'events')
		if (typeof jQuery !== 'undefined' || typeof $ !== 'undefined') {
			var jq = typeof jQuery !== 'undefined' ? jQuery : $;
			if (jq._data) {
				var events = jq._data(a, 'events');
				if (events && events['click'] && events['click'].length > 0) {
					returnMap['eventListeners'] = 'jQuery click handler';
					return returnMap;
				}
			}
		}

		return returnMap;
	} catch (e) {
		return {};
	}
}
`

// cdpComputedStylesheet is the CDP script to check multiple elements.
const cdpComputedStylesheet = `Array.from(%s).map(element => {return {xpath: element, attributes: getEventHandlers(element)}});`

// DetectClickablesCDP uses Chrome DevTools Protocol to find elements
// with click event listeners attached via JavaScript.
func DetectClickablesCDP(page *browser.Page) ([]ClickableResult, error) {
	// First, get all element XPaths in the body
	xpaths, err := getAllXPaths(page)
	if err != nil {
		return nil, fmt.Errorf("failed to get xpaths: %w", err)
	}

	if len(xpaths) == 0 {
		return nil, nil
	}

	// Build the CDP command
	xpathsJS := "["
	for i, xpath := range xpaths {
		if i > 0 {
			xpathsJS += ","
		}
		xpathsJS += fmt.Sprintf("%q", xpath)
	}
	xpathsJS += "]"

	expression := cdpScript + fmt.Sprintf(cdpComputedStylesheet, xpathsJS)

	// Execute via CDP
	result, err := page.EvalCDP(expression)
	if err != nil {
		return nil, fmt.Errorf("failed to execute CDP: %w", err)
	}

	clickables, _ := parseClickableResults(result)

	// If CDP getEventListeners didn't find anything, try jQuery-specific detection
	if len(clickables) == 0 {
		jqClickables, err := detectJQueryClickHandlers(page)
		if err == nil {
			clickables = append(clickables, jqClickables...)
		}
	}

	return clickables, nil
}

// detectJQueryClickHandlers specifically detects jQuery-attached click handlers
// which may not be visible to Chrome's getEventListeners() API.
func detectJQueryClickHandlers(page *browser.Page) ([]ClickableResult, error) {
	// CRITICAL: Must be an IIFE (Immediately Invoked Function Expression)
	// Arrow function `() => {}` is just a definition, not executed!
	script := `(function() {
		var results = [];
		if (typeof jQuery === 'undefined' && typeof $ === 'undefined') {
			return results;
		}

		var jq = typeof jQuery !== 'undefined' ? jQuery : $;
		if (!jq._data) {
			return results;
		}

		// Find all elements and check for jQuery click handlers
		var allElements = document.body.getElementsByTagName('*');
		for (var i = 0; i < allElements.length; i++) {
			var el = allElements[i];
			var events = jq._data(el, 'events');
			if (events && events.click && events.click.length > 0) {
				// Generate unique selector
				var selector = el.id ? '#' + el.id : el.tagName.toLowerCase();
				if (!el.id && el.className) {
					selector += '.' + el.className.split(' ').join('.');
				}
				results.push({
					selector: selector,
					hasListener: true
				});
			}
		}
		return results;
	})()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, err
	}

	clickables := make([]ClickableResult, 0)
	if arr, ok := result.([]interface{}); ok {
		for _, item := range arr {
			if itemMap, ok := item.(map[string]interface{}); ok {
				selector := ""
				if v, ok := itemMap["selector"].(string); ok {
					selector = v
				}
				if selector != "" {
					clickables = append(clickables, ClickableResult{
						Selector:    selector,
						HasListener: true,
					})
				}
			}
		}
	}

	return clickables, nil
}

// getAllXPaths returns XPaths for all elements in the body.
// CRITICAL FIX: Uses absolute XPath (starting with /html) instead of relative (//)
func getAllXPaths(page *browser.Page) ([]string, error) {
	// CRITICAL: Must be an IIFE (Immediately Invoked Function Expression)
	script := `(function() {
		// Define getXPath function FIRST (before using it)
		function getXPath(el) {
			var parts = [];
			var current = el;
			while (current && current.nodeType === Node.ELEMENT_NODE) {
				var idx = 1;
				var sibling = current.previousElementSibling;
				while (sibling) {
					if (sibling.tagName === current.tagName) idx++;
					sibling = sibling.previousElementSibling;
				}
				parts.unshift(current.tagName.toLowerCase() + '[' + idx + ']');
				current = current.parentElement;
			}
			// Return absolute XPath starting with /
			return '/' + parts.join('/');
		}

		var xpaths = [];
		var walker = document.createTreeWalker(
			document.body,
			NodeFilter.SHOW_ELEMENT,
			null,
			false
		);

		while (walker.nextNode()) {
			var node = walker.currentNode;
			// Skip script, style, and other non-interactive elements
			var tag = node.tagName.toLowerCase();
			if (['script', 'style', 'noscript', 'meta', 'link'].indexOf(tag) !== -1) {
				continue;
			}
			xpaths.push(getXPath(node));
		}
		return xpaths;
	})()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, err
	}

	if arr, ok := result.([]interface{}); ok {
		xpaths := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				xpaths = append(xpaths, s)
			}
		}
		return xpaths, nil
	}

	return nil, nil
}

// ClickableResult represents a detected clickable element.
type ClickableResult struct {
	XPath        string // XPath to element
	Selector     string // CSS selector
	HasListener  bool   // Has click event listener
	ListenerCode string // Event listener code (if available)
}

// parseClickableResults parses the CDP result into clickable results.
func parseClickableResults(result interface{}) ([]ClickableResult, error) {
	results := make([]ClickableResult, 0)

	arr, ok := result.([]interface{})
	if !ok {
		return results, nil
	}

	for _, item := range arr {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		xpath := ""
		if v, ok := itemMap["xpath"].(string); ok {
			xpath = v
		}

		hasListener := false
		listenerCode := ""

		if attrs, ok := itemMap["attributes"].(map[string]interface{}); ok {
			if len(attrs) > 0 {
				hasListener = true
				if code, ok := attrs["eventListeners"].(string); ok {
					listenerCode = code
				}
			}
		}

		if hasListener {
			results = append(results, ClickableResult{
				XPath:        xpath,
				HasListener:  hasListener,
				ListenerCode: listenerCode,
			})
		}
	}

	return results, nil
}

// DetectClickablesSimple uses JavaScript to find potentially clickable elements
// without relying on CDP's getEventListeners (which may not be available).
func DetectClickablesSimple(page *browser.Page) ([]ClickableResult, error) {
	// CRITICAL: Must be an IIFE (Immediately Invoked Function Expression)
	script := `(function() {
		var clickables = [];
		var seen = {};

		// Check for onclick attribute or event property
		function hasClickHandler(el) {
			if (el.onclick) return true;
			if (el.getAttribute('onclick')) return true;
			if (el.getAttribute('ng-click')) return true;
			if (el.getAttribute('v-on:click') || el.getAttribute('@click')) return true;
			if (el.getAttribute('data-click')) return true;
			return false;
		}

		// Get selector for element
		function getSelector(el) {
			if (el.id) return '#' + el.id;

			var parts = [];
			while (el && el.nodeType === Node.ELEMENT_NODE) {
				var selector = el.tagName.toLowerCase();
				if (el.id) {
					parts.unshift('#' + el.id);
					break;
				}
				var sibling = el;
				var nth = 1;
				while (sibling = sibling.previousElementSibling) {
					if (sibling.tagName === el.tagName) nth++;
				}
				if (nth > 1) selector += ':nth-of-type(' + nth + ')';
				parts.unshift(selector);
				el = el.parentElement;
			}
			return parts.join(' > ');
		}

		// Check all elements
		var walker = document.createTreeWalker(
			document.body,
			NodeFilter.SHOW_ELEMENT,
			null,
			false
		);

		while (walker.nextNode()) {
			var el = walker.currentNode;
			var tag = el.tagName.toLowerCase();

			// Skip non-visible elements
			var style = window.getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden') {
				continue;
			}

			// Check if potentially clickable
			var isClickable = false;
			var reason = '';

			// Inherently clickable tags
			if (['a', 'button', 'input', 'select', 'textarea'].indexOf(tag) !== -1) {
				if (tag === 'input') {
					var type = el.type.toLowerCase();
					if (['button', 'submit', 'reset', 'image'].indexOf(type) !== -1) {
						isClickable = true;
						reason = 'input-button';
					}
				} else if (tag === 'a') {
					isClickable = true;
					reason = 'anchor';
				} else if (tag === 'button') {
					isClickable = true;
					reason = 'button';
				}
			}

			// Role attribute
			if (!isClickable && el.getAttribute('role') === 'button') {
				isClickable = true;
				reason = 'role-button';
			}

			// Tabindex (focusable = potentially clickable)
			if (!isClickable && el.hasAttribute('tabindex')) {
				isClickable = true;
				reason = 'tabindex';
			}

			// Event handler attributes
			if (!isClickable && hasClickHandler(el)) {
				isClickable = true;
				reason = 'handler';
			}

			// Cursor style
			if (!isClickable && style.cursor === 'pointer') {
				isClickable = true;
				reason = 'cursor';
			}

			if (isClickable) {
				var selector = getSelector(el);
				if (!seen[selector]) {
					seen[selector] = true;
					clickables.push({
						selector: selector,
						tag: tag,
						reason: reason
					});
				}
			}
		}

		return clickables;
	})()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, err
	}

	results := make([]ClickableResult, 0)

	if arr, ok := result.([]interface{}); ok {
		for _, item := range arr {
			if itemMap, ok := item.(map[string]interface{}); ok {
				selector := ""
				if v, ok := itemMap["selector"].(string); ok {
					selector = v
				}

				if selector != "" {
					results = append(results, ClickableResult{
						Selector:    selector,
						HasListener: true,
					})
				}
			}
		}
	}

	return results, nil
}
