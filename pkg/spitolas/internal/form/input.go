package form

import (
	"fmt"

	"go.uber.org/zap"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
)

// FillText fills a text-like input element.
// CRAWLJAX PARITY: Java handleText() skips empty/null values.
func FillText(elem *browser.Element, value string) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// CRAWLJAX PARITY: Java (FormHandler.java:161-168):
	// if (null == text || text.length() == 0) return;
	if value == "" {
		return nil
	}

	// Check if input already has the correct value - skip if so to avoid double fill
	currentValue, err := GetInputValue(elem)
	if err == nil && currentValue == value {
		return nil // Already has correct value, no need to fill again
	}

	// Set value directly via JavaScript - most reliable and atomic method
	script := fmt.Sprintf(`() => {
		this.value = %q;
		this.dispatchEvent(new Event('input', { bubbles: true }));
		this.dispatchEvent(new Event('change', { bubbles: true }));
	}`, value)

	if err := elem.Eval(script); err != nil {
		return fmt.Errorf("failed to set input value: %w", err)
	}

	return nil
}

// FillHidden fills a hidden input element via JavaScript.
// CRAWLJAX PARITY: Java uses element.setAttribute("value", value) which sets the HTML attribute.
// Go sets BOTH the HTML attribute and DOM property to match Java and ensure form submission works.
func FillHidden(elem *browser.Element, value string) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// CRAWLJAX PARITY: Set both setAttribute (HTML attribute) and .value (DOM property)
	// Java: element.setAttribute("value", value)
	script := fmt.Sprintf(`() => {
		this.setAttribute('value', %q);
		this.value = %q;
		this.dispatchEvent(new Event('change', { bubbles: true }));
	}`, value, value)

	if err := elem.Eval(script); err != nil {
		return fmt.Errorf("failed to set hidden value: %w", err)
	}

	return nil
}

// FillCheckbox sets a checkbox to checked or unchecked state.
// Crawljax parity: checks isSelected() before clicking, verifies after.
// If verification fails, logs warning but continues (doesn't block form submission).
func FillCheckbox(elem *browser.Element, checked bool) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// Get current checked state (Crawljax: webElement.isSelected())
	currentChecked, err := elem.Property("checked")
	if err != nil {
		return fmt.Errorf("failed to get checkbox state: %w", err)
	}

	isChecked := false
	if b, ok := currentChecked.(bool); ok {
		isChecked = b
	}

	// Click to toggle if needed (Crawljax: only clicks when state differs)
	if isChecked != checked {
		if err := elem.Click(); err != nil {
			return fmt.Errorf("failed to click checkbox: %w", err)
		}

		// Verify the state actually changed - warn if not, but don't block
		afterChecked, err := elem.Property("checked")
		if err != nil {
			zap.L().Warn("Failed to verify checkbox state after click",
				zap.Error(err))
			return nil // Continue anyway
		}

		finalState := false
		if b, ok := afterChecked.(bool); ok {
			finalState = b
		}

		if finalState != checked {
			zap.L().Warn("Checkbox state did not change as expected",
				zap.Bool("expected", checked),
				zap.Bool("actual", finalState))
			// Don't return error - continue with form submission
		}
	}

	return nil
}

// FillRadio clicks a radio button if value indicates it should be checked.
// CRAWLJAX PARITY: handleRadioSwitches() - identifies radio individually, clicks if checked.
// Value: "1"/"true"/"checked" = click to select, "0"/"false" = do nothing
func FillRadio(elem *browser.Element, value string) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// Crawljax: value "1" means checked, "0" means unchecked
	shouldCheck := value == "1" || value == "true" || value == "checked"

	if !shouldCheck {
		// Crawljax: does nothing if not checked - radio stays as-is
		return nil
	}

	// Get current state (Crawljax: webElement.isSelected())
	currentChecked, _ := elem.Property("checked")
	isChecked := false
	if b, ok := currentChecked.(bool); ok {
		isChecked = b
	}

	// Only click if not already checked
	if !isChecked {
		if err := elem.Click(); err != nil {
			return fmt.Errorf("failed to click radio: %w", err)
		}

		// Verify - warn only, don't block (matches checkbox behavior)
		afterChecked, _ := elem.Property("checked")
		if s, ok := afterChecked.(bool); !ok || !s {
			zap.L().Warn("Radio was clicked but not selected")
		}
	}

	return nil
}

// FillSelect selects an option in a select element.
// Uses a multi-step matching strategy: exact value > exact text > partial match.
// Verifies the option was actually selected after setting.
// If verification fails, logs warning but continues (doesn't block form submission).
func FillSelect(elem *browser.Element, value string) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// Multi-step matching with progressive strategy + verification:
	// 1. Exact value match
	// 2. Exact text content match (case-sensitive)
	// 3. Case-insensitive text match
	// 4. Partial/contains match (case-insensitive)
	// After each match, verify the value was actually set
	script := fmt.Sprintf(`() => {
		const targetValue = %q;
		const targetLower = targetValue.toLowerCase();

		// Helper to set value and verify
		const setAndVerify = (opt, matchType) => {
			const expectedValue = opt.value;
			this.value = expectedValue;
			this.dispatchEvent(new Event('change', { bubbles: true }));
			// Verify the value was actually set
			const actualValue = this.value;
			if (actualValue !== expectedValue) {
				return { found: true, match: matchType, selected: expectedValue, verified: false, actual: actualValue };
			}
			return { found: true, match: matchType, selected: expectedValue, verified: true };
		};

		// Step 1: Exact value match
		for (const opt of this.options) {
			if (opt.value === targetValue) {
				return setAndVerify(opt, 'exact_value');
			}
		}

		// Step 2: Exact text content match
		for (const opt of this.options) {
			if (opt.textContent.trim() === targetValue) {
				return setAndVerify(opt, 'exact_text');
			}
		}

		// Step 3: Case-insensitive text match
		for (const opt of this.options) {
			if (opt.textContent.trim().toLowerCase() === targetLower) {
				return setAndVerify(opt, 'case_insensitive');
			}
		}

		// Step 4: Partial/contains match (case-insensitive)
		for (const opt of this.options) {
			const optText = opt.textContent.trim().toLowerCase();
			const optValue = opt.value.toLowerCase();
			if (optText.includes(targetLower) || optValue.includes(targetLower) ||
				targetLower.includes(optText) || targetLower.includes(optValue)) {
				return setAndVerify(opt, 'partial');
			}
		}

		// Collect available options for error reporting
		const available = Array.from(this.options).map(o => o.value || o.textContent.trim());
		return { found: false, available: available.slice(0, 10) };
	}`, value)

	result, err := elem.EvalWithResult(script)
	if err != nil {
		return fmt.Errorf("failed to select option: %w", err)
	}

	if resultMap, ok := result.(map[string]interface{}); ok {
		if found, ok := resultMap["found"].(bool); ok && found {
			// Check if value was verified - warn if not, but continue
			if verified, ok := resultMap["verified"].(bool); ok && !verified {
				actual, _ := resultMap["actual"].(string)
				selected, _ := resultMap["selected"].(string)
				zap.L().Warn("Select option was set but verification failed",
					zap.String("target", value),
					zap.String("expected", selected),
					zap.String("actual", actual))
				// Don't return error - continue with form submission
			}
			return nil
		}
		// Option not found - log warning and continue
		if available, ok := resultMap["available"].([]interface{}); ok && len(available) > 0 {
			zap.L().Warn("Select option not found",
				zap.String("target", value),
				zap.Any("available", available))
		}
		return nil // Continue anyway - don't block form submission
	}

	zap.L().Warn("Select option not found",
		zap.String("target", value))
	return nil
}

// FillSelectMultiple selects multiple options in a multi-select element.
// Uses same matching strategy as FillSelect: exact value > exact text > case-insensitive > partial.
// Verifies that all options were actually selected.
func FillSelectMultiple(elem *browser.Element, values []string) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// Convert values to JS array literal
	jsValues := "["
	for i, v := range values {
		if i > 0 {
			jsValues += ","
		}
		jsValues += fmt.Sprintf("%q", v)
	}
	jsValues += "]"

	// Set via JavaScript with multi-step matching + verification
	script := fmt.Sprintf(`() => {
		const targetValues = %s;
		const targetLowers = targetValues.map(v => v.toLowerCase());
		let matched = 0;
		const selectedValues = [];

		// Clear all existing selections first
		for (const opt of this.options) {
			opt.selected = false;
		}

		// Track which targets have been matched to avoid double-matching
		const matchedTargets = new Set();

		for (const opt of this.options) {
			const optValue = opt.value;
			const optText = opt.textContent.trim();
			const optValueLower = optValue.toLowerCase();
			const optTextLower = optText.toLowerCase();

			// Check each target value (only exact matches for multi-select)
			for (let i = 0; i < targetValues.length; i++) {
				if (matchedTargets.has(i)) continue;

				const target = targetValues[i];
				const targetLower = targetLowers[i];

				// Prioritize exact matches for multi-select to avoid partial matches
				if (optValue === target || optText === target ||
					optValueLower === targetLower || optTextLower === targetLower) {
					opt.selected = true;
					matchedTargets.add(i);
					matched++;
					selectedValues.push(optValue);
					break;
				}
			}
		}

		this.dispatchEvent(new Event('change', { bubbles: true }));

		// Verify selections
		let verified = 0;
		for (const opt of this.selectedOptions) {
			if (selectedValues.includes(opt.value)) {
				verified++;
			}
		}

		return {
			matched: matched,
			total: targetValues.length,
			verified: verified,
			selectedCount: this.selectedOptions.length
		};
	}`, jsValues)

	result, err := elem.EvalWithResult(script)
	if err != nil {
		return fmt.Errorf("failed to select multiple options: %w", err)
	}

	if resultMap, ok := result.(map[string]interface{}); ok {
		matched := 0
		total := len(values)
		verified := 0
		if m, ok := resultMap["matched"].(float64); ok {
			matched = int(m)
		}
		if v, ok := resultMap["verified"].(float64); ok {
			verified = int(v)
		}
		if matched < total {
			zap.L().Warn("Multi-select: only matched some options",
				zap.Int("matched", matched),
				zap.Int("total", total))
			// Don't return error - continue with form submission
		}
		if verified < matched {
			zap.L().Warn("Multi-select: verification failed",
				zap.Int("set", matched),
				zap.Int("verified", verified))
			// Don't return error - continue with form submission
		}
	}

	return nil
}

// FillDate fills a date input.
func FillDate(elem *browser.Element, value string) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// Date inputs are tricky - set via JavaScript
	// Use () => this syntax for rod's Element.Eval
	script := fmt.Sprintf(`() => {
		this.value = %q;
		this.dispatchEvent(new Event('input', { bubbles: true }));
		this.dispatchEvent(new Event('change', { bubbles: true }));
	}`, value)

	if err := elem.Eval(script); err != nil {
		return fmt.Errorf("failed to set date: %w", err)
	}

	return nil
}

// FillFile triggers file input (note: actual file selection requires file chooser handling).
func FillFile(elem *browser.Element, filePaths []string) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// File inputs require special handling via CDP
	return elem.SetFiles(filePaths)
}

// FillFileViaDialog handles file upload by intercepting the file chooser dialog.
// Use this when clicking a trigger element (button/link) that opens a file dialog.
// GO EXTENSION: Works with hidden file inputs and custom upload components.
//
// Usage: For buttons/links that trigger hidden file inputs:
//
//	err := FillFileViaDialog(page, triggerButton, []string{"/path/to/file.png"})
func FillFileViaDialog(page *browser.Page, triggerElem *browser.Element, filePaths []string) error {
	if page == nil {
		return fmt.Errorf("page is nil")
	}
	if triggerElem == nil {
		return fmt.Errorf("trigger element is nil")
	}
	if len(filePaths) == 0 {
		return fmt.Errorf("no file paths provided")
	}

	// Setup file dialog interception BEFORE clicking
	handleFile, err := page.HandleFileDialog()
	if err != nil {
		return fmt.Errorf("failed to setup file dialog handler: %w", err)
	}

	// Click the trigger element (async - don't wait for dialog)
	go func() {
		_ = triggerElem.Click()
	}()

	// Provide files to the intercepted dialog
	if err := handleFile(filePaths); err != nil {
		return fmt.Errorf("failed to set files in dialog: %w", err)
	}

	return nil
}

// ClearInput clears an input element.
func ClearInput(elem *browser.Element) error {
	if elem == nil {
		return fmt.Errorf("element is nil")
	}

	// Try SelectAllText + Delete
	if err := elem.SelectAllText(); err == nil {
		// Send backspace/delete to clear
		if err := elem.Input(""); err == nil {
			return nil
		}
	}

	// Fallback: clear via JavaScript
	// Use () => this syntax for rod's Element.Eval
	script := `() => {
		if (this.type === 'checkbox' || this.type === 'radio') {
			this.checked = false;
		} else if (this.tagName === 'SELECT') {
			this.selectedIndex = -1;
		} else {
			this.value = '';
		}
		this.dispatchEvent(new Event('input', { bubbles: true }));
		this.dispatchEvent(new Event('change', { bubbles: true }));
	}`

	return elem.Eval(script)
}

// GetInputValue gets the current value of an input element.
func GetInputValue(elem *browser.Element) (string, error) {
	if elem == nil {
		return "", fmt.Errorf("element is nil")
	}

	val, err := elem.Property("value")
	if err != nil {
		return "", err
	}

	if s, ok := val.(string); ok {
		return s, nil
	}

	return fmt.Sprintf("%v", val), nil
}

// IsChecked returns whether a checkbox/radio is checked.
func IsChecked(elem *browser.Element) (bool, error) {
	if elem == nil {
		return false, fmt.Errorf("element is nil")
	}

	val, err := elem.Property("checked")
	if err != nil {
		return false, err
	}

	if b, ok := val.(bool); ok {
		return b, nil
	}

	return false, nil
}

// GetSelectedOptions returns the selected options in a select element.
func GetSelectedOptions(elem *browser.Element) ([]string, error) {
	if elem == nil {
		return nil, fmt.Errorf("element is nil")
	}

	// Use () => this syntax for rod's Element.Eval
	result, err := elem.EvalWithResult(`() => {
		const selected = [];
		for (const opt of this.selectedOptions) {
			selected.push(opt.value);
		}
		return selected;
	}`)

	if err != nil {
		return nil, err
	}

	if arr, ok := result.([]interface{}); ok {
		values := make([]string, len(arr))
		for i, v := range arr {
			values[i] = fmt.Sprintf("%v", v)
		}
		return values, nil
	}

	return nil, fmt.Errorf("unexpected result type")
}

// GetSelectAllOptions returns all non-disabled option values from a select element.
// Matches Crawljax behavior: used for random option selection when no value is specified.
func GetSelectAllOptions(elem *browser.Element) ([]string, error) {
	if elem == nil {
		return nil, fmt.Errorf("element is nil")
	}

	// Use () => this syntax for rod's Element.Eval
	// Get all non-disabled options with non-empty values
	result, err := elem.EvalWithResult(`() => {
		const options = [];
		for (const opt of this.options) {
			// Skip disabled options and empty values (like placeholder options)
			if (!opt.disabled && opt.value !== '') {
				options.push(opt.value);
			}
		}
		return options;
	}`)

	if err != nil {
		return nil, err
	}

	if arr, ok := result.([]interface{}); ok {
		values := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok && s != "" {
				values = append(values, s)
			}
		}
		return values, nil
	}

	return nil, fmt.Errorf("unexpected result type")
}
