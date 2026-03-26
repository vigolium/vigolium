package condition

import (
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// regexCache caches compiled regex patterns for performance.
// Using sync.Map for thread-safe access without explicit locking.
var regexCache sync.Map

// getCachedRegex returns a cached compiled regex, or compiles and caches it.
// Returns nil if the pattern is invalid.
func getCachedRegex(pattern string) *regexp.Regexp {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	regexCache.Store(pattern, re)
	return re
}

// Condition checks a browser page state.
type Condition struct {
	Type   config.ConditionType
	Value  string
	Negate bool

	// For composite conditions
	operator string       // "and", "or"
	children []*Condition // Sub-conditions

	// For count limit condition - CRITICAL FIX: Use int32 for atomic operations
	MaxCount     int            // Maximum allowed occurrences
	currentCount int32          // Current count - atomic for thread safety
	countTracker map[string]int // Shared count tracker (for external management)
	countMu      sync.Mutex     // Mutex for countTracker access

	// For nested condition in CountCondition
	// Count only increments when NestedCondition is nil or returns true
	NestedCondition *Condition

	// For preconditions - conditions that must pass before this one is evaluated
	Preconditions []*Condition
}

// New creates a new condition.
func New(condType config.ConditionType, value string) *Condition {
	return &Condition{
		Type:   condType,
		Value:  value,
		Negate: false,
	}
}

// NewFromConfig creates a condition from config.
func NewFromConfig(cfg config.ConditionConfig) *Condition {
	cond := &Condition{
		Type:     cfg.Type,
		Value:    cfg.Value,
		Negate:   cfg.Negate,
		MaxCount: cfg.MaxCount,
	}

	// Convert preconditions
	if len(cfg.Preconditions) > 0 {
		cond.Preconditions = make([]*Condition, len(cfg.Preconditions))
		for i, pre := range cfg.Preconditions {
			cond.Preconditions[i] = NewFromConfig(pre)
		}
	}

	return cond
}

// Not returns a negated copy of the condition.
func (c *Condition) Not() *Condition {
	return &Condition{
		Type:     c.Type,
		Value:    c.Value,
		Negate:   !c.Negate,
		operator: c.operator,
		children: c.children,
	}
}

// And creates a new condition that requires all conditions to be true.
func And(conditions ...*Condition) *Condition {
	return &Condition{
		operator: "and",
		children: conditions,
	}
}

// Or creates a new condition that requires at least one condition to be true.
func Or(conditions ...*Condition) *Condition {
	return &Condition{
		operator: "or",
		children: conditions,
	}
}

// Check evaluates the condition against the current page state.
func (c *Condition) Check(page *browser.Page) bool {
	// Check preconditions first - if any precondition fails, skip this condition (return true to allow crawl)
	for _, pre := range c.Preconditions {
		if !pre.Check(page) {
			// Precondition not met, skip evaluating this condition
			return true
		}
	}

	result := c.evaluate(page)
	if c.Negate {
		return !result
	}
	return result
}

func (c *Condition) evaluate(page *browser.Page) bool {
	// Handle composite conditions
	if c.operator != "" {
		return c.evaluateComposite(page)
	}

	switch c.Type {
	case config.CondURLContains:
		return c.checkURLContains(page)
	case config.CondURLMatches:
		return c.checkURLMatches(page)
	case config.CondElementExists:
		return c.checkElementExists(page)
	case config.CondElementVisible:
		return c.checkElementVisible(page)
	case config.CondJavaScript:
		return c.checkJavaScript(page)
	// MEDIUM PRIORITY: Additional condition types
	case config.CondXPathExists:
		return c.checkXPathExists(page)
	case config.CondDOMRegex:
		return c.checkDOMRegex(page)
	case config.CondCountLimit:
		return c.checkCountLimit(page)
	default:
		return false
	}
}

func (c *Condition) evaluateComposite(page *browser.Page) bool {
	if len(c.children) == 0 {
		return true
	}

	switch c.operator {
	case "and":
		for _, child := range c.children {
			if !child.Check(page) {
				return false
			}
		}
		return true
	case "or":
		for _, child := range c.children {
			if child.Check(page) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// checkURLContains checks if the URL contains the given substring.
// CRITICAL FIX: Made case-insensitive.
func (c *Condition) checkURLContains(page *browser.Page) bool {
	url, err := page.URL()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(url), strings.ToLower(c.Value))
}

// checkURLMatches checks if the URL matches the given regex pattern.
// HIGH PRIORITY: Uses cached compiled regex for performance.
func (c *Condition) checkURLMatches(page *browser.Page) bool {
	url, err := page.URL()
	if err != nil {
		return false
	}
	re := getCachedRegex(c.Value)
	if re == nil {
		return false
	}
	return re.MatchString(url)
}

func (c *Condition) checkElementExists(page *browser.Page) bool {
	return page.HasElement(c.Value)
}

func (c *Condition) checkElementVisible(page *browser.Page) bool {
	// First check existence with non-blocking HasElement
	if !page.HasElement(c.Value) {
		return false
	}
	// Element exists, now get it to check visibility
	elem, err := page.Element(c.Value)
	if err != nil || elem == nil {
		return false
	}
	return elem.IsVisible()
}

func (c *Condition) checkJavaScript(page *browser.Page) bool {
	return EvalCondition(page, c.Value)
}

// checkXPathExists checks if any element matches the XPath expression.
// MEDIUM PRIORITY: XPath condition support
func (c *Condition) checkXPathExists(page *browser.Page) bool {
	return page.HasElementX(c.Value)
}

// checkDOMRegex checks if the DOM content matches a regex pattern.
// Pattern.compile(regex, Pattern.CASE_INSENSITIVE).
// Go equivalent: prepend (?i) for case-insensitive matching.
func (c *Condition) checkDOMRegex(page *browser.Page) bool {
	html, err := page.HTML()
	if err != nil {
		return false
	}
	pattern := "(?i)" + c.Value
	re := getCachedRegex(pattern)
	if re == nil {
		return false
	}
	return re.MatchString(html)
}

// checkCountLimit checks if the occurrence count is within limit.
// CRITICAL FIX: :
// 1. Only increment count when NestedCondition is nil or evaluates to true
// 2. Use atomic operations for thread safety
// 3. Return true if count <= maxCount (allow crawl), false otherwise
func (c *Condition) checkCountLimit(page *browser.Page) bool {
	if c.NestedCondition != nil && !c.NestedCondition.Check(page) {
		// Nested condition not met, don't count, allow crawl
		return true
	}

	// Use countTracker if available (for URL-based counting), otherwise use internal count
	if c.countTracker != nil {
		url, err := page.URL()
		if err != nil {
			return true // Allow on error
		}

		c.countMu.Lock()
		count := c.countTracker[url]
		c.countTracker[url] = count + 1
		c.countMu.Unlock()

		return count <= c.MaxCount
	}

	// CRITICAL FIX: Use atomic increment for thread safety
	count := atomic.AddInt32(&c.currentCount, 1)
	return int(count) <= c.MaxCount
}

// SetCountTracker sets a shared count tracker for the condition.
// This allows multiple conditions to share state counts.
func (c *Condition) SetCountTracker(tracker map[string]int) {
	c.countTracker = tracker
}

// ResetCount resets the internal counter.
func (c *Condition) ResetCount() {
	atomic.StoreInt32(&c.currentCount, 0)
}

// URLContains creates a condition that checks if URL contains a substring.
func URLContains(substring string) *Condition {
	return New(config.CondURLContains, substring)
}

// URLMatches creates a condition that checks if URL matches a regex pattern.
func URLMatches(pattern string) *Condition {
	return New(config.CondURLMatches, pattern)
}

// ElementExists creates a condition that checks if an element exists.
func ElementExists(selector string) *Condition {
	return New(config.CondElementExists, selector)
}

// ElementVisible creates a condition that checks if an element is visible.
func ElementVisible(selector string) *Condition {
	return New(config.CondElementVisible, selector)
}

// JavaScript creates a condition that evaluates a JS expression.
func JavaScript(expression string) *Condition {
	return New(config.CondJavaScript, expression)
}

// XPathExists creates a condition that checks if an XPath matches any element.
func XPathExists(xpath string) *Condition {
	return New(config.CondXPathExists, xpath)
}

// DOMRegex creates a condition that checks if DOM content matches a regex.
func DOMRegex(pattern string) *Condition {
	return New(config.CondDOMRegex, pattern)
}

// CountLimit creates a condition that limits occurrences.
func CountLimit(key string, maxCount int) *Condition {
	return &Condition{
		Type:     config.CondCountLimit,
		Value:    key,
		MaxCount: maxCount,
	}
}

// WithPrecondition adds a precondition to the condition.
func (c *Condition) WithPrecondition(pre *Condition) *Condition {
	c.Preconditions = append(c.Preconditions, pre)
	return c
}
