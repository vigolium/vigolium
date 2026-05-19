package browser

import (
	"fmt"

	"github.com/go-rod/rod/lib/proto"
)

// GetEventListeners uses CDP to get event listeners for an element.
// Note: This requires Chrome DevTools and getEventListeners is only available
// in the console context, not in regular page evaluation.
func (p *Page) GetEventListeners(selector string) (map[string]interface{}, error) {
	// getEventListeners is only available in DevTools console
	// We need to use Runtime.evaluate with includeCommandLineAPI: true
	script := fmt.Sprintf(`
		(function() {
			const el = document.querySelector(%q);
			if (!el) return null;
			if (typeof getEventListeners !== 'function') return null;
			return getEventListeners(el);
		})()
	`, selector)

	result, err := proto.RuntimeEvaluate{
		Expression:            script,
		IncludeCommandLineAPI: true,
		ReturnByValue:         true,
	}.Call(p.rodPage)

	if err != nil {
		return nil, err
	}

	if result.ExceptionDetails != nil {
		return nil, fmt.Errorf("CDP exception: %s", result.ExceptionDetails.Text)
	}

	val := result.Result.Value.Val()
	if val == nil {
		return nil, nil
	}

	if m, ok := val.(map[string]interface{}); ok {
		return m, nil
	}

	return nil, nil
}

// GetAllEventListeners gets event listeners for all elements matching xpath list.
func (p *Page) GetAllEventListeners(xpaths []string) ([]ElementListeners, error) {
	// Build the xpaths array for JavaScript
	xpathsJS := "["
	for i, xpath := range xpaths {
		if i > 0 {
			xpathsJS += ","
		}
		xpathsJS += fmt.Sprintf("%q", xpath)
	}
	xpathsJS += "]"

	script := fmt.Sprintf(`
		(function() {
			const xpaths = %s;
			const results = [];

			for (const xpath of xpaths) {
				try {
					const result = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
					const el = result.singleNodeValue;

					if (!el) continue;

					if (typeof getEventListeners === 'function') {
						const listeners = getEventListeners(el);
						if (listeners && listeners.click && listeners.click.length > 0) {
							results.push({
								xpath: xpath,
								hasClick: true,
								listenerCount: listeners.click.length
							});
						}
					}
				} catch (e) {
					// Skip errors
				}
			}

			return results;
		})()
	`, xpathsJS)

	result, err := proto.RuntimeEvaluate{
		Expression:            script,
		IncludeCommandLineAPI: true,
		ReturnByValue:         true,
	}.Call(p.rodPage)

	if err != nil {
		return nil, err
	}

	if result.ExceptionDetails != nil {
		return nil, fmt.Errorf("CDP exception: %s", result.ExceptionDetails.Text)
	}

	val := result.Result.Value.Val()
	if val == nil {
		return nil, nil
	}

	// Parse results
	listeners := make([]ElementListeners, 0)

	if arr, ok := val.([]interface{}); ok {
		for _, item := range arr {
			if m, ok := item.(map[string]interface{}); ok {
				el := ElementListeners{
					XPath:    getString(m, "xpath"),
					HasClick: getBool(m, "hasClick"),
				}
				if count, ok := m["listenerCount"].(float64); ok {
					el.ListenerCount = int(count)
				}
				listeners = append(listeners, el)
			}
		}
	}

	return listeners, nil
}

// ElementListeners represents event listeners for an element.
type ElementListeners struct {
	XPath         string
	HasClick      bool
	ListenerCount int
}

// DOMSnapshot captures a DOM snapshot.
func (p *Page) DOMSnapshot() (*DOMSnapshotResult, error) {
	result, err := p.rodPage.CaptureDOMSnapshot()
	if err != nil {
		return nil, err
	}

	return &DOMSnapshotResult{
		Documents: len(result.Documents),
		NodeCount: len(result.Strings),
		RawResult: result,
	}, nil
}

// DOMSnapshotResult holds DOM snapshot data.
type DOMSnapshotResult struct {
	Documents int
	NodeCount int
	RawResult *proto.DOMSnapshotCaptureSnapshotResult
}

// EnableNetwork enables network domain for interception.
func (p *Page) EnableNetwork() error {
	return proto.NetworkEnable{}.Call(p.rodPage)
}

// SetRequestInterception enables request interception.
func (p *Page) SetRequestInterception(patterns []string) error {
	urlPatterns := make([]*proto.FetchRequestPattern, len(patterns))
	for i, pattern := range patterns {
		urlPatterns[i] = &proto.FetchRequestPattern{
			URLPattern: pattern,
		}
	}

	return proto.FetchEnable{
		Patterns: urlPatterns,
	}.Call(p.rodPage)
}

// GetLayoutMetrics returns page layout metrics.
func (p *Page) GetLayoutMetrics() (*LayoutMetrics, error) {
	result, err := proto.PageGetLayoutMetrics{}.Call(p.rodPage)
	if err != nil {
		return nil, err
	}

	return &LayoutMetrics{
		ContentWidth:   result.CSSContentSize.Width,
		ContentHeight:  result.CSSContentSize.Height,
		ViewportX:      result.CSSVisualViewport.PageX,
		ViewportY:      result.CSSVisualViewport.PageY,
		ViewportWidth:  result.CSSVisualViewport.ClientWidth,
		ViewportHeight: result.CSSVisualViewport.ClientHeight,
	}, nil
}

// LayoutMetrics represents page layout metrics.
type LayoutMetrics struct {
	ContentWidth   float64
	ContentHeight  float64
	ViewportX      float64
	ViewportY      float64
	ViewportWidth  float64
	ViewportHeight float64
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

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
