package condition

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// HIGH PRIORITY FIX: Escape string for safe embedding in JavaScript single-quoted strings.
// Prevents JS injection and syntax errors from special characters.
func escapeJSString(s string) string {
	// Escape backslashes first, then single quotes, then newlines/tabs
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// EvalCondition evaluates a JavaScript expression and returns whether it's truthy.
// The expression is wrapped in try-catch for safety.
func EvalCondition(page *browser.Page, expression string) bool {
	// Wrap expression in try-catch and return boolean
	script := `
		(function() {
			try {
				var result = ` + expression + `;
				return !!result;
			} catch (e) {
				return false;
			}
		})()
	`

	result, err := page.Eval(script)
	if err != nil {
		return false
	}

	// Handle nil result
	if result == nil {
		return false
	}

	// Handle various return types from rod
	switch v := result.(type) {
	case bool:
		return v
	case string:
		// Handle rod's "<nil>" string gotcha and string "true"/"false"
		return v == "true"
	case float64:
		// JavaScript might return 1 or 0
		return v != 0
	case int:
		return v != 0
	default:
		return false
	}
}

// EvalConditionWithError evaluates a JavaScript expression and returns the result with error info.
func EvalConditionWithError(page *browser.Page, expression string) (bool, error) {
	script := `
		(function() {
			try {
				var result = ` + expression + `;
				return { success: true, value: !!result };
			} catch (e) {
				return { success: false, error: e.message };
			}
		})()
	`

	result, err := page.Eval(script)
	if err != nil {
		return false, err
	}

	if result == nil {
		return false, nil
	}

	// Try to extract value from result map
	if m, ok := result.(map[string]interface{}); ok {
		if success, ok := m["success"].(bool); ok && success {
			if val, ok := m["value"].(bool); ok {
				return val, nil
			}
		}
	}

	return false, nil
}

// Common JavaScript condition expressions

// JSDocumentReady checks if document.readyState is "complete".
const JSDocumentReady = `document.readyState === 'complete'`

// JSNoLoading checks if there are no loading indicators visible.
const JSNoLoading = `!document.querySelector('.loading, .spinner, [class*="loading"], [class*="spinner"]')`

// JSNoAjaxPending checks if there are no pending XHR/fetch requests (requires instrumentation).
const JSNoAjaxPending = `typeof window.__pendingRequests === 'undefined' || window.__pendingRequests === 0`

// JSAngularReady checks if AngularJS has finished bootstrapping.
const JSAngularReady = `
	(function() {
		if (typeof angular === 'undefined') return true;
		var injector = angular.element(document.body).injector();
		if (!injector) return true;
		var $http = injector.get('$http');
		return $http.pendingRequests.length === 0;
	})()
`

// JSReactReady checks if React has finished rendering (basic heuristic).
const JSReactReady = `
	(function() {
		var reactRoot = document.querySelector('[data-reactroot], #root, #app');
		if (!reactRoot) return true;
		return reactRoot.childNodes.length > 0;
	})()
`

// JSVueReady checks if Vue has finished mounting.
const JSVueReady = `
	(function() {
		var vueRoot = document.querySelector('[data-v-app], #app');
		if (!vueRoot) return true;
		return vueRoot.__vue__ !== undefined || vueRoot.__vue_app__ !== undefined;
	})()
`

// JSjQueryReady checks if jQuery AJAX requests are complete.
const JSjQueryReady = `
	(function() {
		if (typeof jQuery === 'undefined' && typeof $ === 'undefined') return true;
		var jq = jQuery || $;
		return jq.active === 0;
	})()
`

// JSElementInViewport creates a JS expression to check if element is in viewport.
// HIGH PRIORITY FIX: Uses escapeJSString to prevent JS injection.
func JSElementInViewport(selector string) string {
	return `
		(function() {
			var el = document.querySelector('` + escapeJSString(selector) + `');
			if (!el) return false;
			var rect = el.getBoundingClientRect();
			return (
				rect.top >= 0 &&
				rect.left >= 0 &&
				rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
				rect.right <= (window.innerWidth || document.documentElement.clientWidth)
			);
		})()
	`
}

// JSElementHasText creates a JS expression to check if element contains text.
// HIGH PRIORITY FIX: Uses escapeJSString to prevent JS injection.
func JSElementHasText(selector, text string) string {
	return `
		(function() {
			var el = document.querySelector('` + escapeJSString(selector) + `');
			if (!el) return false;
			return el.textContent.includes('` + escapeJSString(text) + `');
		})()
	`
}

// JSFormValid creates a JS expression to check if a form is valid.
// HIGH PRIORITY FIX: Uses escapeJSString to prevent JS injection.
func JSFormValid(selector string) string {
	return `
		(function() {
			var form = document.querySelector('` + escapeJSString(selector) + `');
			if (!form) return false;
			return form.checkValidity();
		})()
	`
}
