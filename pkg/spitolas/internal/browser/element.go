package browser

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/rod"
	"github.com/vigolium/vigolium/pkg/spitolas/rod/lib/proto"
)

// Element wraps rod.Element with additional functionality.
type Element struct {
	rodElem *rod.Element
	page    *Page

	// XPath cache (M1 performance improvement)
	cachedXPath    string
	cachedSelector string
	xpathCached    bool
	selectorCached bool
}

// Click clicks the element with fresh timeout.
// Uses config.ElementTimeout to reset context, preventing timeout inheritance from element search.
func (e *Element) Click() error {
	return e.rodElem.Timeout(e.page.config.ElementTimeout).Click(proto.InputMouseButtonLeft, 1)
}

// DoubleClick double-clicks the element with fresh timeout.
func (e *Element) DoubleClick() error {
	return e.rodElem.Timeout(e.page.config.ElementTimeout).Click(proto.InputMouseButtonLeft, 2)
}

// RightClick right-clicks the element with fresh timeout.
func (e *Element) RightClick() error {
	return e.rodElem.Timeout(e.page.config.ElementTimeout).Click(proto.InputMouseButtonRight, 1)
}

// Hover hovers over the element with fresh timeout.
func (e *Element) Hover() error {
	return e.rodElem.Timeout(e.page.config.ElementTimeout).Hover()
}

// Focus focuses the element.
func (e *Element) Focus() error {
	return e.rodElem.Focus()
}

// Input types text into the element.
func (e *Element) Input(text string) error {
	return e.rodElem.Input(text)
}

// Clear clears the element value.
func (e *Element) Clear() error {
	return e.rodElem.SelectAllText()
}

// SelectAllText selects all text in the element.
func (e *Element) SelectAllText() error {
	return e.rodElem.SelectAllText()
}

// Select selects options in a select element.
func (e *Element) Select(values []string) error {
	return e.rodElem.Select(values, true, rod.SelectorTypeText)
}

// SetFiles sets files for a file input element.
func (e *Element) SetFiles(paths []string) error {
	return e.rodElem.SetFiles(paths)
}

// Text returns the text content of the element.
func (e *Element) Text() (string, error) {
	return e.rodElem.Text()
}

// HTML returns the outer HTML of the element.
func (e *Element) HTML() (string, error) {
	return e.rodElem.HTML()
}

// Attribute returns an attribute value.
func (e *Element) Attribute(name string) (string, error) {
	val, err := e.rodElem.Attribute(name)
	if err != nil {
		return "", err
	}
	if val == nil {
		return "", nil
	}
	return *val, nil
}

// Property returns a property value.
func (e *Element) Property(name string) (interface{}, error) {
	result, err := e.rodElem.Property(name)
	if err != nil {
		return nil, err
	}
	return result.Val(), nil
}

// TagName returns the tag name.
func (e *Element) TagName() (string, error) {
	result, err := e.rodElem.Eval(`() => this.tagName`)
	if err != nil {
		return "", err
	}
	tag := strings.ToLower(result.Value.Str())
	// Handle rod's "<nil>" string for undefined values (per CLAUDE.md)
	if tag == "<nil>" || tag == "" {
		return "", nil
	}
	return tag, nil
}

// IsVisible returns true if the element is visible.
func (e *Element) IsVisible() bool {
	visible, err := e.rodElem.Visible()
	if err != nil {
		return false
	}
	return visible
}

// IsInteractable checks if element can be interacted with.
func (e *Element) IsInteractable() bool {
	_, err := e.rodElem.Interactable()
	return err == nil
}

// WaitVisible waits for the element to be visible with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (e *Element) WaitVisible() error {
	return e.rodElem.Timeout(e.page.config.ElementTimeout).WaitVisible()
}

// WaitEnabled waits for the element to be enabled with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (e *Element) WaitEnabled() error {
	return e.rodElem.Timeout(e.page.config.ElementTimeout).WaitEnabled()
}

// WaitInteractable waits for the element to be interactable with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (e *Element) WaitInteractable() error {
	_, err := e.rodElem.Timeout(e.page.config.ElementTimeout).WaitInteractable()
	return err
}

// ScrollIntoView scrolls the element into view.
func (e *Element) ScrollIntoView() error {
	return e.rodElem.ScrollIntoView()
}

// GetSelector generates a unique CSS selector for the element.
// M1 PERFORMANCE: Selector is cached after first generation.
func (e *Element) GetSelector() (string, error) {
	// Return cached selector if available
	if e.selectorCached {
		return e.cachedSelector, nil
	}

	result, err := e.rodElem.Eval(`() => {
		const el = this;
		if (el.id) return '#' + el.id;

		const parts = [];
		let current = el;
		while (current && current.nodeType === Node.ELEMENT_NODE) {
			let selector = current.tagName.toLowerCase();
			if (current.id) {
				parts.unshift('#' + current.id);
				break;
			}
			if (current.className) {
				const classes = current.className.split(/\s+/).filter(c => c && !c.includes(':'));
				if (classes.length) {
					selector += '.' + classes.slice(0, 2).join('.');
				}
			}
			let sibling = current;
			let nth = 1;
			while (sibling = sibling.previousElementSibling) {
				if (sibling.tagName === current.tagName) nth++;
			}
			if (nth > 1) selector += ':nth-of-type(' + nth + ')';
			parts.unshift(selector);
			current = current.parentElement;
		}
		return parts.join(' > ');
	}`)
	if err != nil {
		return "", err
	}
	sel := result.Value.Str()
	// Handle rod's "<nil>" string for undefined values (per CLAUDE.md)
	if sel == "<nil>" {
		return "", nil
	}

	// Cache the result
	e.cachedSelector = sel
	e.selectorCached = true

	return sel, nil
}

// GetXPath returns the absolute XPath of the element.
// CRITICAL FIX: Returns absolute XPath starting from /html for reliable identification.
// M1 PERFORMANCE: XPath is cached after first generation.
func (e *Element) GetXPath() (string, error) {
	// Return cached XPath if available
	if e.xpathCached {
		return e.cachedXPath, nil
	}

	result, err := e.rodElem.Eval(`() => {
		const el = this;
		const parts = [];
		let current = el;
		while (current && current.nodeType === Node.ELEMENT_NODE) {
			let idx = 1;
			let sibling = current.previousElementSibling;
			while (sibling) {
				if (sibling.tagName === current.tagName) idx++;
				sibling = sibling.previousElementSibling;
			}
			parts.unshift(current.tagName.toLowerCase() + '[' + idx + ']');
			current = current.parentElement;
		}
		// Return absolute XPath starting with /
		return '/' + parts.join('/');
	}`)
	if err != nil {
		return "", err
	}
	xpath := result.Value.Str()
	// Handle rod's "<nil>" string for undefined values (per CLAUDE.md)
	if xpath == "<nil>" {
		return "", nil
	}

	// Cache the result
	e.cachedXPath = xpath
	e.xpathCached = true

	return xpath, nil
}

// ClearCache clears the cached XPath and selector.
func (e *Element) ClearCache() {
	e.cachedXPath = ""
	e.cachedSelector = ""
	e.xpathCached = false
	e.selectorCached = false
}

// Matches checks if element matches a CSS selector.
func (e *Element) Matches(selector string) bool {
	result, err := e.rodElem.Eval(`(selector) => this.matches(selector)`, selector)
	if err != nil {
		return false
	}
	return result.Value.Bool()
}

// Eval evaluates JavaScript on the element without returning the result.
func (e *Element) Eval(script string) error {
	_, err := e.rodElem.Eval(script)
	return err
}

// EvalWithResult evaluates JavaScript on the element and returns the result.
func (e *Element) EvalWithResult(script string) (interface{}, error) {
	result, err := e.rodElem.Eval(script)
	if err != nil {
		return nil, err
	}
	return result.Value.Val(), nil
}

// Page returns the parent page.
func (e *Element) Page() *Page {
	return e.page
}

// RodElement returns the underlying rod.Element (for advanced usage).
func (e *Element) RodElement() *rod.Element {
	return e.rodElem
}

// BoundingBox returns the element's bounding box.
func (e *Element) BoundingBox() (*Box, error) {
	shape, err := e.rodElem.Shape()
	if err != nil {
		return nil, err
	}
	box := shape.Box()
	return &Box{
		X:      box.X,
		Y:      box.Y,
		Width:  box.Width,
		Height: box.Height,
	}, nil
}

// Box represents a bounding box.
type Box struct {
	X      float64
	Y      float64
	Width  float64
	Height float64
}

// Parent returns the parent element.
func (e *Element) Parent() (*Element, error) {
	rodElem, err := e.rodElem.Parent()
	if err != nil {
		return nil, err
	}
	return &Element{rodElem: rodElem, page: e.page}, nil
}

// Children returns child elements with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (e *Element) Children() ([]*Element, error) {
	// Use rod's Elements method to get children via CSS selector with timeout
	rodChildren, err := e.rodElem.Timeout(e.page.config.ElementTimeout).Elements(":scope > *")
	if err != nil {
		return nil, err
	}

	children := make([]*Element, 0, len(rodChildren))
	for _, rodChild := range rodChildren {
		children = append(children, &Element{rodElem: rodChild, page: e.page})
	}

	return children, nil
}

// HasClass checks if element has a CSS class.
func (e *Element) HasClass(className string) bool {
	result, err := e.rodElem.Eval(`(cls) => this.classList.contains(cls)`, className)
	if err != nil {
		return false
	}
	return result.Value.Bool()
}

// GetClasses returns all CSS classes.
func (e *Element) GetClasses() ([]string, error) {
	result, err := e.rodElem.Eval(`() => Array.from(this.classList)`)
	if err != nil {
		return nil, err
	}

	arr := result.Value.Arr()
	classes := make([]string, len(arr))
	for i, v := range arr {
		classes[i] = v.Str()
	}
	return classes, nil
}

// GetAllAttributes returns all attributes as a sorted string.
// which is used in CandidateElement.getUniqueString() for ClickOnce detection.
// Returns empty string if element has no attributes or on error.
func (e *Element) GetAllAttributes() string {
	result, err := e.rodElem.Eval(`() => {
		const el = this;
		const attrs = [];
		for (let i = 0; i < el.attributes.length; i++) {
			const attr = el.attributes[i];
			// Include all attributes (id, class, value, name, etc.)
			attrs.push(attr.name + '=' + attr.value);
		}
		// Sort for consistent ordering
		attrs.sort();
		return attrs.join(' ');
	}`)
	if err != nil {
		return ""
	}
	attrStr := result.Value.Str()
	// Handle rod's "<nil>" string for undefined values (per CLAUDE.md)
	if attrStr == "<nil>" {
		return ""
	}
	return attrStr
}
