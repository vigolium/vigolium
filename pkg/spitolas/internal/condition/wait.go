package condition

import (
	"regexp"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// WaitResult represents the result of a wait condition.
type WaitResult int

const (
	WaitSuccess     WaitResult = 1  // Condition was satisfied
	WaitTimeout     WaitResult = 0  // Condition timed out
	WaitURLMismatch WaitResult = -1 // URL pattern didn't match
)

// WaitCondition waits for a specific element on matching URLs.
type WaitCondition struct {
	URLPattern string        // Regex pattern to match URL
	Selector   string        // CSS selector to wait for
	Visible    bool          // Wait for visibility (not just existence)
	Timeout    time.Duration // Max wait time
	Polling    time.Duration // Poll interval
}

// NewWaitCondition creates a new wait condition.
func NewWaitCondition(selector string, timeout time.Duration) *WaitCondition {
	return &WaitCondition{
		URLPattern: "",
		Selector:   selector,
		Visible:    false,
		Timeout:    timeout,
		Polling:    100 * time.Millisecond,
	}
}

// NewWaitConditionFromConfig creates a wait condition from config.
func NewWaitConditionFromConfig(cfg config.WaitConditionConfig) *WaitCondition {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &WaitCondition{
		URLPattern: cfg.URLPattern,
		Selector:   cfg.Selector,
		Visible:    cfg.Visible,
		Timeout:    timeout,
		Polling:    100 * time.Millisecond,
	}
}

// ForURL sets the URL pattern to match.
func (w *WaitCondition) ForURL(pattern string) *WaitCondition {
	w.URLPattern = pattern
	return w
}

// WithVisibility sets whether to wait for element visibility.
func (w *WaitCondition) WithVisibility(visible bool) *WaitCondition {
	w.Visible = visible
	return w
}

// WithPolling sets the polling interval.
func (w *WaitCondition) WithPolling(d time.Duration) *WaitCondition {
	w.Polling = d
	return w
}

// Wait waits for the condition to be satisfied.
// Returns:
//   - WaitSuccess (1): condition was satisfied
//   - WaitTimeout (0): condition timed out
//   - WaitURLMismatch (-1): URL pattern didn't match
func (w *WaitCondition) Wait(page *browser.Page) WaitResult {
	// Check URL pattern if specified
	if w.URLPattern != "" {
		url, err := page.URL()
		if err != nil {
			return WaitURLMismatch
		}

		matched, err := regexp.MatchString(w.URLPattern, url)
		if err != nil || !matched {
			return WaitURLMismatch
		}
	}

	// Wait for element
	deadline := time.Now().Add(w.Timeout)
	for time.Now().Before(deadline) {
		// Use HasElement for non-blocking existence check
		if page.HasElement(w.Selector) {
			if w.Visible {
				// Need to get element to check visibility
				elem, err := page.Element(w.Selector)
				if err == nil && elem != nil && elem.IsVisible() {
					return WaitSuccess
				}
			} else {
				return WaitSuccess
			}
		}

		time.Sleep(w.Polling)
	}

	return WaitTimeout
}

// WaitAll waits for all conditions to be satisfied.
// Returns on first failure or when all succeed.
func WaitAll(page *browser.Page, conditions ...*WaitCondition) WaitResult {
	for _, c := range conditions {
		result := c.Wait(page)
		if result != WaitSuccess {
			return result
		}
	}
	return WaitSuccess
}

// WaitAny waits for any condition to be satisfied.
// Returns on first success or when all fail.
func WaitAny(page *browser.Page, conditions ...*WaitCondition) WaitResult {
	if len(conditions) == 0 {
		return WaitSuccess
	}

	// For WaitAny, we need to poll all conditions until one succeeds
	// Find the maximum timeout
	maxTimeout := time.Duration(0)
	for _, c := range conditions {
		if c.Timeout > maxTimeout {
			maxTimeout = c.Timeout
		}
	}

	deadline := time.Now().Add(maxTimeout)
	polling := 100 * time.Millisecond

	for time.Now().Before(deadline) {
		for _, c := range conditions {
			// Check URL pattern if specified
			if c.URLPattern != "" {
				url, err := page.URL()
				if err != nil {
					continue
				}
				matched, err := regexp.MatchString(c.URLPattern, url)
				if err != nil || !matched {
					continue
				}
			}

			// Check element using HasElement for non-blocking check
			if page.HasElement(c.Selector) {
				if c.Visible {
					// Need to get element to check visibility
					elem, err := page.Element(c.Selector)
					if err == nil && elem != nil && elem.IsVisible() {
						return WaitSuccess
					}
				} else {
					return WaitSuccess
				}
			}
		}

		time.Sleep(polling)
	}

	return WaitTimeout
}

// WaitForElement is a helper to wait for an element to exist.
func WaitForElement(page *browser.Page, selector string, timeout time.Duration) bool {
	return NewWaitCondition(selector, timeout).Wait(page) == WaitSuccess
}

// WaitForVisible is a helper to wait for an element to be visible.
func WaitForVisible(page *browser.Page, selector string, timeout time.Duration) bool {
	cond := NewWaitCondition(selector, timeout)
	cond.Visible = true
	return cond.Wait(page) == WaitSuccess
}
