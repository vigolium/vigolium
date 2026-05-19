package form

import (
	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// Detector provides form and input detection utilities.
type Detector struct{}

// NewDetector creates a new form detector.
func NewDetector() *Detector {
	return &Detector{}
}

// HasForms returns true if the page has any forms.
func (d *Detector) HasForms(page *browser.Page) bool {
	result, err := page.Eval(`(() => document.querySelectorAll('form').length > 0)()`)
	if err != nil {
		return false
	}
	if b, ok := result.(bool); ok {
		return b
	}
	return false
}

// HasInputs returns true if the page has any form inputs.
func (d *Detector) HasInputs(page *browser.Page) bool {
	result, err := page.Eval(`(() => document.querySelectorAll('input, textarea, select').length > 0)()`)
	if err != nil {
		return false
	}
	if b, ok := result.(bool); ok {
		return b
	}
	return false
}

// CountForms returns the number of forms on the page.
func (d *Detector) CountForms(page *browser.Page) int {
	result, err := page.Eval(`(() => document.querySelectorAll('form').length)()`)
	if err != nil {
		return 0
	}
	if n, ok := result.(float64); ok {
		return int(n)
	}
	return 0
}

// CountInputs returns the number of form inputs on the page.
func (d *Detector) CountInputs(page *browser.Page) int {
	result, err := page.Eval(`(() => document.querySelectorAll('input, textarea, select').length)()`)
	if err != nil {
		return 0
	}
	if n, ok := result.(float64); ok {
		return int(n)
	}
	return 0
}

// GetLoginForm tries to detect a login form on the page.
// Returns nil if no login form is found.
func (d *Detector) GetLoginForm(page *browser.Page) *Form {
	// JavaScript returns XPath for all elements
	script := `(() => {
		// Helper to get XPath for element
		function getXPath(el) {
			if (!el || el.nodeType !== Node.ELEMENT_NODE) return '';

			const parts = [];
			while (el && el.nodeType === Node.ELEMENT_NODE) {
				let idx = 1;
				let sibling = el.previousSibling;
				while (sibling) {
					if (sibling.nodeType === Node.ELEMENT_NODE &&
						sibling.tagName === el.tagName) {
						idx++;
					}
					sibling = sibling.previousSibling;
				}
				parts.unshift('/' + el.tagName.toUpperCase() + '[' + idx + ']');
				el = el.parentElement;
			}
			return parts.join('');
		}

		// Look for forms with password fields
		for (const form of document.querySelectorAll('form')) {
			const passwordInput = form.querySelector('input[type="password"]');
			if (!passwordInput) continue;

			// Found a form with password - likely a login form
			const usernameInput = form.querySelector(
				'input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[name*="login"]'
			);

			return {
				formXPath: getXPath(form),
				usernameXPath: usernameInput ? getXPath(usernameInput) : null,
				usernameName: usernameInput ? (usernameInput.name || '') : '',
				usernameID: usernameInput ? (usernameInput.id || '') : '',
				passwordXPath: getXPath(passwordInput),
				passwordName: passwordInput.name || '',
				passwordID: passwordInput.id || ''
			};
		}
		return null;
	})()`

	result, err := page.Eval(script)
	if err != nil || result == nil {
		return nil
	}

	data, ok := result.(map[string]interface{})
	if !ok {
		return nil
	}

	formXPath := getString(data, "formXPath")
	if formXPath == "" {
		return nil
	}

	form := NewForm(formXPath)

	if usernameXPath := getString(data, "usernameXPath"); usernameXPath != "" {
		input := NewDetectedInputWithType(action.InputTypeText, action.NewIdentification(action.HowXPath, usernameXPath))
		input.Name = getString(data, "usernameName")
		input.ID = getString(data, "usernameID")
		input.XPath = usernameXPath
		form.AddInput(input)
	}

	if passwordXPath := getString(data, "passwordXPath"); passwordXPath != "" {
		input := NewDetectedInputWithType(action.InputTypePassword, action.NewIdentification(action.HowXPath, passwordXPath))
		input.Name = getString(data, "passwordName")
		input.ID = getString(data, "passwordID")
		input.XPath = passwordXPath
		form.AddInput(input)
	}

	return form
}

// GetSearchForm tries to detect a search form on the page.
func (d *Detector) GetSearchForm(page *browser.Page) *Form {
	script := `(() => {
		// Helper to get XPath for element
		function getXPath(el) {
			if (!el || el.nodeType !== Node.ELEMENT_NODE) return '';

			const parts = [];
			while (el && el.nodeType === Node.ELEMENT_NODE) {
				let idx = 1;
				let sibling = el.previousSibling;
				while (sibling) {
					if (sibling.nodeType === Node.ELEMENT_NODE &&
						sibling.tagName === el.tagName) {
						idx++;
					}
					sibling = sibling.previousSibling;
				}
				parts.unshift('/' + el.tagName.toUpperCase() + '[' + idx + ']');
				el = el.parentElement;
			}
			return parts.join('');
		}

		// Look for search inputs
		const searchInput = document.querySelector(
			'input[type="search"], input[name*="search"], input[name*="query"], input[name="q"], input[placeholder*="search" i]'
		);
		if (!searchInput) return null;

		// Find containing form
		const form = searchInput.closest('form');

		return {
			formXPath: form ? getXPath(form) : '/HTML[1]/BODY[1]',
			searchXPath: getXPath(searchInput),
			searchName: searchInput.name || '',
			searchID: searchInput.id || ''
		};
	})()`

	result, err := page.Eval(script)
	if err != nil || result == nil {
		return nil
	}

	data, ok := result.(map[string]interface{})
	if !ok {
		return nil
	}

	searchXPath := getString(data, "searchXPath")
	if searchXPath == "" {
		return nil
	}

	formXPath := getString(data, "formXPath")
	if formXPath == "" {
		formXPath = "/HTML[1]/BODY[1]"
	}

	form := NewForm(formXPath)
	input := NewDetectedInputWithType(action.InputTypeText, action.NewIdentification(action.HowXPath, searchXPath))
	input.Name = getString(data, "searchName")
	input.ID = getString(data, "searchID")
	input.XPath = searchXPath
	form.AddInput(input)

	return form
}

// GetSelectOptions returns the available options for a select element.
// Parameter xpath must be an XPath expression.
func (d *Detector) GetSelectOptions(page *browser.Page, xpath string) ([]string, error) {
	script := `(xpath) => {
		const result = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
		const select = result.singleNodeValue;
		if (!select || select.tagName !== 'SELECT') return [];
		const options = [];
		for (const opt of select.options) {
			options.push(opt.value || opt.textContent);
		}
		return options;
	}`

	result, err := page.EvalWithArgs(script, xpath)
	if err != nil {
		return nil, err
	}

	if arr, ok := result.([]interface{}); ok {
		options := make([]string, len(arr))
		for i, v := range arr {
			if s, ok := v.(string); ok {
				options[i] = s
			}
		}
		return options, nil
	}

	return nil, nil
}

// GetRadioOptions returns the available options for a radio button group.
func (d *Detector) GetRadioOptions(page *browser.Page, name string) ([]string, error) {
	script := `(name) => {
		const radios = document.querySelectorAll('input[type="radio"][name="' + name + '"]');
		const values = [];
		for (const radio of radios) {
			values.push(radio.value);
		}
		return values;
	}`

	result, err := page.EvalWithArgs(script, name)
	if err != nil {
		return nil, err
	}

	if arr, ok := result.([]interface{}); ok {
		options := make([]string, len(arr))
		for i, v := range arr {
			if s, ok := v.(string); ok {
				options[i] = s
			}
		}
		return options, nil
	}

	return nil, nil
}
