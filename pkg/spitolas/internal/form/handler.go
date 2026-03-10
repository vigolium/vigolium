package form

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"

	"github.com/lucasjones/reggen"
)

// Crawljax parity constants
const (
	// RandomStringLength matches Crawljax FormHandler.RANDOM_STRING_LENGTH
	RandomStringLength = 8
	// ProbabilityCheck matches Crawljax RandomInputValueGenerator.PROBABILITY_CHECK
	ProbabilityCheck = 0.5
	// MaxRandomInt matches Crawljax RandomInputValueGenerator.MAX_INT
	MaxRandomInt = 12345
	// randomChars matches Crawljax - letters only (a-zA-Z), NO numbers
	randomChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// Handler handles form detection and filling.
// CRAWLJAX PARITY: Uses action.FormInput for Crawljax parity,
// DetectedInput for Go extension (detection metadata).
type Handler struct {
	config       *config.Config
	inputConfigs map[string]*action.FormInput // CRAWLJAX PARITY: key = "id:value" or "name:value" or "xpath:value"
	rng          *rand.Rand
}

// identificationKey creates a map key from identification how and value.
// CRAWLJAX PARITY: Matches Java FormInputValueHelper.formInputs map keying
func identificationKey(how, value string) string {
	return how + ":" + value
}

// parseHow converts a string to action.How.
// CRAWLJAX PARITY: Matches Java Identification.How enum
func parseHow(how string) action.How {
	switch how {
	case "id":
		return action.HowID
	case "name":
		return action.HowName
	case "xpath":
		return action.HowXPath
	default:
		return action.HowID
	}
}

// NewHandler creates a new form handler.
func NewHandler(cfg *config.Config) *Handler {
	h := &Handler{
		config:       cfg,
		inputConfigs: make(map[string]*action.FormInput),
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	// CRAWLJAX PARITY: Load input configurations using Identification key
	// Matches Java FormInputValueHelper constructor which stores by Identification
	for _, inputCfg := range cfg.FormInputs {
		identification := action.NewIdentification(parseHow(inputCfg.How), inputCfg.Value)
		input := action.NewFormInput(action.GetTypeFromStr(inputCfg.Type), identification)
		// Convert values to InputValue
		for _, v := range inputCfg.Values {
			input.InputValues = append(input.InputValues, action.InputValue{Value: v, Checked: v == "1"})
		}
		key := identificationKey(inputCfg.How, inputCfg.Value)
		h.inputConfigs[key] = input
		zap.L().Debug("Loaded form input config",
			zap.String("key", key),
			zap.String("how", inputCfg.How),
			zap.String("value", inputCfg.Value),
			zap.Int("valuesCount", len(inputCfg.Values)))
	}

	return h
}

// DetectForms finds all forms on the page.
// CRAWLJAX PARITY: Uses XPath (skeleton) instead of CSS selectors.
// Returns Form with DetectedInput (Go extension for detection metadata).
func (h *Handler) DetectForms(page *browser.Page) ([]*Form, error) {
	script := `(() => {
		const forms = [];
		for (const form of document.querySelectorAll('form')) {
			const formData = {
				xpath: getSkeletonXPath(form),
				action: form.action,
				method: form.method,
				inputs: []
			};

			// Find all inputs in this form
			const inputs = form.querySelectorAll('input, textarea, select');
			for (const input of inputs) {
				const inputData = {
					type: input.type || input.tagName.toLowerCase(),
					xpath: getSkeletonXPath(input),
					name: input.name || '',
					id: input.id || '',
					required: input.required,
					disabled: input.disabled,
					readOnly: input.readOnly,
					multiple: input.multiple,
					pattern: input.pattern || '',
					minlength: input.minLength || 0,
					maxlength: input.maxLength || 0,
					min: input.min || '',
					max: input.max || '',
					step: input.step || '',
					placeholder: input.placeholder || '',
					label: getLabel(input),
					accept: input.accept || ''
				};
				formData.inputs.push(inputData);
			}
			forms.push(formData);
		}
		return forms;

		function getLabel(input) {
			if (input.id) {
				const label = document.querySelector('label[for="' + CSS.escape(input.id) + '"]');
				if (label) return label.textContent.trim();
			}
			const parent = input.closest('label');
			if (parent) {
				const clone = parent.cloneNode(true);
				clone.querySelectorAll('input,select,textarea').forEach(i => i.remove());
				return clone.textContent.trim();
			}
			const ariaLabel = input.getAttribute('aria-label');
			if (ariaLabel) return ariaLabel;
			return '';
		}

		// CRAWLJAX PARITY: getSkeletonXpath() from XPathHelper.java
		// Generates position-based XPath like /HTML[1]/BODY[1]/DIV[3]/INPUT[2]
		function getSkeletonXPath(el) {
			const parts = [];
			let current = el;
			while (current && current.nodeType === Node.ELEMENT_NODE) {
				const tagName = current.tagName.toUpperCase();
				// Count same-tag siblings before this element
				let index = 1;
				let sibling = current.previousElementSibling;
				while (sibling) {
					if (sibling.tagName === current.tagName) index++;
					sibling = sibling.previousElementSibling;
				}
				parts.unshift(tagName + '[' + index + ']');
				current = current.parentElement;
			}
			return '/' + parts.join('/');
		}
	})()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, fmt.Errorf("failed to detect forms: %w", err)
	}

	forms := make([]*Form, 0)

	if arr, ok := result.([]interface{}); ok {
		for _, formData := range arr {
			if formMap, ok := formData.(map[string]interface{}); ok {
				form := h.parseFormData(formMap)
				forms = append(forms, form)
			}
		}
	}

	return forms, nil
}

// parseFormData parses form data from JavaScript detection.
// CRAWLJAX PARITY: Uses XPath instead of CSS selector.
func (h *Handler) parseFormData(data map[string]interface{}) *Form {
	// Use XPath for form identification
	xpath := getString(data, "xpath")
	form := NewForm(xpath)
	form.Action = getString(data, "action")
	form.Method = getString(data, "method")

	if inputs, ok := data["inputs"].([]interface{}); ok {
		for _, inputData := range inputs {
			if inputMap, ok := inputData.(map[string]interface{}); ok {
				input := h.parseInputData(inputMap)
				form.AddInput(input)
			}
		}
	}

	return form
}

// parseInputData parses input data from JavaScript detection.
// CRAWLJAX PARITY: Creates Identification with priority ID → Name → XPath.
// Java: FormInputValueHelper.getIdentification() lines 255-272
// Returns DetectedInput which wraps action.FormInput with detection metadata.
func (h *Handler) parseInputData(data map[string]interface{}) *DetectedInput {
	typeStr := getString(data, "type")
	inputType := action.GetTypeFromStr(typeStr)
	xpath := getString(data, "xpath") // Skeleton XPath from JS
	name := getString(data, "name")
	id := getString(data, "id")

	// CRAWLJAX PARITY: Create Identification with priority ID → Name → XPath
	// Java: FormInputValueHelper.getIdentification() lines 255-272
	var identification *action.Identification
	var configuredInput *action.FormInput

	if id != "" {
		identification = action.NewIdentification(action.HowID, id)
		key := identificationKey("id", id)
		configuredInput = h.inputConfigs[key]
	} else if name != "" {
		identification = action.NewIdentification(action.HowName, name)
		key := identificationKey("name", name)
		configuredInput = h.inputConfigs[key]
	} else if xpath != "" {
		identification = action.NewIdentification(action.HowXPath, xpath)
		key := identificationKey("xpath", xpath)
		configuredInput = h.inputConfigs[key]
	}

	// Create FormInput (Crawljax parity)
	formInput := action.NewFormInput(inputType, identification)

	// Copy configured values if found
	if configuredInput != nil {
		formInput.InputValues = configuredInput.InputValues
		zap.L().Debug("Found configured values for input",
			zap.String("how", string(identification.How)),
			zap.String("value", identification.Value),
			zap.Int("valuesCount", len(configuredInput.InputValues)))
	}

	// Create DetectedInput with metadata (Go extension)
	detected := NewDetectedInput(formInput)
	detected.Name = name
	detected.ID = id
	detected.XPath = xpath
	detected.Required = getBool(data, "required")
	detected.Disabled = getBool(data, "disabled")
	detected.ReadOnly = getBool(data, "readOnly")
	detected.Multiple = getBool(data, "multiple")
	detected.Pattern = getString(data, "pattern")
	detected.MinLength = getInt(data, "minlength")
	detected.MaxLength = getInt(data, "maxlength")
	detected.Min = getString(data, "min")
	detected.Max = getString(data, "max")
	detected.Step = getString(data, "step")
	detected.Placeholder = getString(data, "placeholder")
	detected.Label = getString(data, "label")
	detected.Accept = getString(data, "accept")
	detected.Hidden = getBool(data, "hidden")
	detected.TriggerXPath = getString(data, "triggerXPath")

	return detected
}

// DetectInputs finds all form inputs on the page (not limited to forms).
// CRAWLJAX PARITY: Uses XPath (skeleton) instead of CSS selectors.
// Returns DetectedInput slice (Go extension for detection metadata).
func (h *Handler) DetectInputs(page *browser.Page) ([]*DetectedInput, error) {
	script := `(() => {
		const inputs = [];
		for (const input of document.querySelectorAll('input, textarea, select')) {
			const hidden = isHidden(input);
			const inputData = {
				type: input.type || input.tagName.toLowerCase(),
				xpath: getSkeletonXPath(input),
				name: input.name || '',
				id: input.id || '',
				required: input.required,
				disabled: input.disabled,
				readOnly: input.readOnly,
				multiple: input.multiple,
				pattern: input.pattern || '',
				minlength: input.minLength || 0,
				maxlength: input.maxLength || 0,
				min: input.min || '',
				max: input.max || '',
				step: input.step || '',
				placeholder: input.placeholder || '',
				label: getLabel(input),
				accept: input.accept || '',
				hidden: hidden,
				triggerXPath: hidden && input.type === 'file' ? findTriggerXPath(input) : ''
			};
			inputs.push(inputData);
		}
		return inputs;

		// Check if element is visually hidden
		function isHidden(el) {
			if (el.hidden || el.type === 'hidden') return true;
			const style = getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden') return true;
			if (style.opacity === '0') return true;
			const rect = el.getBoundingClientRect();
			if (rect.width === 0 || rect.height === 0) return true;
			if (parseFloat(style.width) === 0 || parseFloat(style.height) === 0) return true;
			return false;
		}

		// Find trigger element for hidden file input
		function findTriggerXPath(fileInput) {
			// 1. Check for label with for attribute
			if (fileInput.id) {
				const label = document.querySelector('label[for="' + CSS.escape(fileInput.id) + '"]');
				if (label && !isHidden(label)) return getSkeletonXPath(label);
			}

			// 2. Check parent label
			const parentLabel = fileInput.closest('label');
			if (parentLabel && !isHidden(parentLabel)) return getSkeletonXPath(parentLabel);

			// 3. Check sibling button/link
			const parent = fileInput.parentElement;
			if (parent) {
				const trigger = parent.querySelector('button, a, [role="button"], .btn, .upload-btn');
				if (trigger && !isHidden(trigger)) return getSkeletonXPath(trigger);
			}

			// 4. Check for element that triggers via onclick
			const allElements = document.querySelectorAll('button, a, [role="button"], label, div, span');
			for (const el of allElements) {
				if (isHidden(el)) continue;
				const onclick = el.getAttribute('onclick') || '';
				if (onclick.includes(fileInput.id) || onclick.includes('.click()')) {
					return getSkeletonXPath(el);
				}
			}

			return '';
		}

		function getLabel(input) {
			if (input.id) {
				const label = document.querySelector('label[for="' + CSS.escape(input.id) + '"]');
				if (label) return label.textContent.trim();
			}
			const parent = input.closest('label');
			if (parent) {
				const clone = parent.cloneNode(true);
				clone.querySelectorAll('input,select,textarea').forEach(i => i.remove());
				return clone.textContent.trim();
			}
			const ariaLabel = input.getAttribute('aria-label');
			if (ariaLabel) return ariaLabel;
			return '';
		}

		// CRAWLJAX PARITY: getSkeletonXpath() from XPathHelper.java
		// Generates position-based XPath like /HTML[1]/BODY[1]/DIV[3]/INPUT[2]
		function getSkeletonXPath(el) {
			const parts = [];
			let current = el;
			while (current && current.nodeType === Node.ELEMENT_NODE) {
				const tagName = current.tagName.toUpperCase();
				// Count same-tag siblings before this element
				let index = 1;
				let sibling = current.previousElementSibling;
				while (sibling) {
					if (sibling.tagName === current.tagName) index++;
					sibling = sibling.previousElementSibling;
				}
				parts.unshift(tagName + '[' + index + ']');
				current = current.parentElement;
			}
			return '/' + parts.join('/');
		}
	})()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, fmt.Errorf("failed to detect inputs: %w", err)
	}

	inputs := make([]*DetectedInput, 0)

	if arr, ok := result.([]interface{}); ok {
		for _, inputData := range arr {
			if inputMap, ok := inputData.(map[string]interface{}); ok {
				input := h.parseInputData(inputMap)
				inputs = append(inputs, input)
			}
		}
	}

	return inputs, nil
}

// FillResult contains the result of filling a form input.
type FillResult struct {
	Input   *DetectedInput
	Success bool
	Error   error
}

// FillInputsResult contains the result of filling multiple inputs.
type FillInputsResult struct {
	Results   []*FillResult
	Succeeded int
	Failed    int
}

// HasErrors returns true if any input failed to fill.
func (r *FillInputsResult) HasErrors() bool {
	return r.Failed > 0
}

// Errors returns all errors that occurred during filling.
func (r *FillInputsResult) Errors() []error {
	errors := make([]error, 0, r.Failed)
	for _, result := range r.Results {
		if result.Error != nil {
			errors = append(errors, result.Error)
		}
	}
	return errors
}

// FillInputs fills the given inputs with configured or random values.
// Returns detailed results including any errors that occurred.
// CRAWLJAX PARITY: Uses Identification for element lookup.
func (h *Handler) FillInputs(page *browser.Page, inputs []*DetectedInput) *FillInputsResult {
	zap.L().Debug("Filling form inputs",
		zap.Int("input_count", len(inputs)),
		zap.String("mode", string(h.config.FormFillMode)))

	result := &FillInputsResult{
		Results: make([]*FillResult, 0, len(inputs)),
	}

	for _, input := range inputs {
		fillResult := &FillResult{
			Input: input,
		}

		if !input.CanInteract() {
			fillResult.Success = true // Skip non-interactable inputs (not an error)
			result.Results = append(result.Results, fillResult)
			continue
		}

		// Get identification value for logging
		idValue := ""
		if input.FormInput != nil && input.Identification != nil {
			idValue = input.Identification.Value
		}

		if err := h.FillInput(page, input); err != nil {
			fillResult.Success = false
			fillResult.Error = fmt.Errorf("failed to fill input %s: %w", idValue, err)
			result.Failed++
			zap.L().Debug("Input fill failed",
				zap.String("identification", idValue),
				zap.String("type", string(input.Type)),
				zap.Error(err))
		} else {
			fillResult.Success = true
			result.Succeeded++
		}

		result.Results = append(result.Results, fillResult)
	}

	zap.L().Debug("Form inputs filled",
		zap.Int("succeeded", result.Succeeded),
		zap.Int("failed", result.Failed))

	return result
}

// getElementByIdentification finds element using XPath based on Identification.
// CRAWLJAX PARITY: Matches Java FormInputValueHelper.getBelongingNode() exactly (line 218-249).
// - HowXPath: Use xpath value directly
// - HowID/HowName: Build XPath "//TAG[@name='X' or @id='X']" where TAG is INPUT/SELECT/TEXTAREA
func (h *Handler) getElementByIdentification(page *browser.Page, input *DetectedInput) (*browser.Element, error) {
	if input.FormInput == nil || input.Identification == nil {
		// Fallback to XPath field if set
		if input.XPath != "" {
			return page.ElementX(input.XPath)
		}
		return nil, fmt.Errorf("no identification for form input")
	}

	id := input.Identification

	switch id.How {
	case action.HowXPath:
		// CRAWLJAX PARITY: Use XPath directly
		return page.ElementX(id.Value)

	case action.HowID, action.HowName:
		// CRAWLJAX PARITY: Build XPath with tag name (line 233-240)
		// Java: "//" + element + "[@name='" + value + "' or @id='" + value + "']"
		// GO FIX: Escape single quotes in XPath to handle values like "father's day"
		tagName := h.getTagNameForType(input.Type)
		escapedValue := escapeXPathString(id.Value)
		xpath := fmt.Sprintf("//%s[@name=%s or @id=%s]", tagName, escapedValue, escapedValue)
		return page.ElementX(xpath)

	default:
		return nil, fmt.Errorf("unsupported identification how: %s", id.How)
	}
}

// getTagNameForType returns HTML tag name for form input type.
// CRAWLJAX PARITY: Matches Java FormInputValueHelper.getBelongingNode() (line 233-237)
func (h *Handler) getTagNameForType(inputType action.InputType) string {
	switch inputType {
	case action.InputTypeSelect:
		return "SELECT"
	case action.InputTypeTextarea:
		return "TEXTAREA"
	default:
		return "INPUT"
	}
}

// HandleFormElements fills form inputs and returns the handled inputs list.
// CRAWLJAX PARITY: Matches Java FormHandler.handleFormElements() exactly.
// Java behavior (line 316-343):
//   - Returns List<FormInput> of handled inputs
//   - For each input, creates NEW FormInput with XPath identification from actual DOM node
//   - If error occurs, adds the failing input at end of list
//   - This allows backtracking to use actual XPath instead of id/name
func (h *Handler) HandleFormElements(page *browser.Page, formInputs []*DetectedInput) []*action.FormInput {
	handled := make([]*action.FormInput, 0, len(formInputs))
	var failing *action.FormInput

	for _, input := range formInputs {
		if input.FormInput == nil {
			continue
		}
		failing = input.FormInput // Track current input in case of failure

		idValue := ""
		if input.Identification != nil {
			idValue = input.Identification.Value
		}
		zap.L().Debug("Filling in", zap.String("identification", idValue))

		if !input.CanInteract() {
			handled = append(handled, input.FormInput)
			failing = nil
			continue
		}

		// CRAWLJAX PARITY: Get element using XPath lookup via Identification
		elem, err := h.getElementByIdentification(page, input)
		if err != nil {
			zap.L().Debug("Could not find element for form input",
				zap.String("identification", idValue),
				zap.Error(err))
			continue // Skip but don't break
		}

		// Fill the input
		if fillErr := h.fillElement(elem, input); fillErr != nil {
			if h.config.Verbose {
				zap.L().Error("Could not handle form element",
					zap.String("identification", idValue),
					zap.Error(fillErr))
			} else {
				zap.L().Debug("Could not handle form element",
					zap.String("identification", idValue),
					zap.Error(fillErr))
			}
			continue
		}

		// CRAWLJAX PARITY: Create NEW FormInput with skeleton XPath identification
		// Java line 327-331: Creates new FormInput with actual XPath from DOM
		actualXPath := h.getElementXPath(page, elem)
		if actualXPath != "" {
			xpathId := action.NewIdentification(action.HowXPath, actualXPath)
			handledInput := action.NewFormInput(input.Type, xpathId)
			handledInput.InputValues = input.InputValues
			handled = append(handled, handledInput)
		} else {
			handled = append(handled, input.FormInput)
		}

		failing = nil
	}

	// CRAWLJAX PARITY: Add failing input at end if any (Java line 341)
	// Java: handled.add(Objects.requireNonNullElseGet(failing, () -> new FormInput(null, null)));
	if failing != nil {
		handled = append(handled, failing)
	}

	return handled
}

// GetFormInputs returns all form inputs detected on current DOM.
// CRAWLJAX PARITY: Matches Java FormHandler.getFormInputs() exactly.
// Java behavior (line 224-240):
//   - Gets DOM from browser
//   - Finds all INPUT, TEXTAREA, SELECT elements
//   - For each, calls formInputValueHelper.getFormInputWithIndexValue()
//   - Returns list of FormInput with values from config
func (h *Handler) GetFormInputs(page *browser.Page) []*action.FormInput {
	inputs, err := h.DetectInputs(page)
	if err != nil {
		zap.L().Error("Failed to detect form inputs", zap.Error(err))
		return make([]*action.FormInput, 0)
	}

	// Convert DetectedInput to action.FormInput
	return ToFormInputs(inputs)
}

// getElementXPath gets the XPath of an element.
// CRAWLJAX PARITY: Matches Java XPathHelper.getSkeletonXpath()
func (h *Handler) getElementXPath(_ *browser.Page, elem *browser.Element) string {
	// CRITICAL: Must use regular function (not arrow function) so that `this` is bound correctly
	// when rod wraps the script with .apply(this, arguments).
	// Arrow functions don't have their own `this` binding - they inherit from enclosing scope.
	script := `function() {
		const parts = [];
		let current = this;
		while (current && current.nodeType === Node.ELEMENT_NODE) {
			let index = 1;
			let sibling = current.previousElementSibling;
			while (sibling) {
				if (sibling.tagName === current.tagName) index++;
				sibling = sibling.previousElementSibling;
			}
			const tagName = current.tagName.toLowerCase();
			parts.unshift(tagName + '[' + index + ']');
			current = current.parentElement;
		}
		return '/' + parts.join('/');
	}`

	result, err := elem.EvalWithResult(script)
	if err != nil {
		return ""
	}

	if s, ok := result.(string); ok {
		return s
	}
	return ""
}

// fillElement fills an element with the appropriate value based on input type.
// Internal method used by HandleFormElements.
func (h *Handler) fillElement(elem *browser.Element, input *DetectedInput) error {
	value := h.getValueForInput(input)

	if input.FormInput == nil {
		return fmt.Errorf("no form input")
	}

	switch input.Type {
	case action.InputTypeText, action.InputTypeTextarea, action.InputTypePassword,
		action.InputTypeEmail, action.InputTypeNumber, action.InputTypeInput:
		return FillText(elem, value)

	case action.InputTypeHidden:
		return FillHidden(elem, value)

	case action.InputTypeCheckbox:
		checked := value == "true" || value == "1" || value == "checked"
		return FillCheckbox(elem, checked)

	case action.InputTypeRadio:
		return FillRadio(elem, value)

	case action.InputTypeSelect:
		if input.Multiple && len(input.GetValues()) > 1 {
			return FillSelectMultiple(elem, input.GetValues())
		}
		// Crawljax parity: if no value specified, select random option from dropdown
		if value == "" {
			options, err := GetSelectAllOptions(elem)
			if err == nil && len(options) > 0 {
				value = options[h.rng.Intn(len(options))]
			}
		}
		if value == "" {
			return nil // No options available
		}
		return FillSelect(elem, value)

	case action.InputTypeFile:
		// GO EXTENSION: File upload support with smart file type selection
		// Use configured path if provided, otherwise select based on accept attribute
		if value != "" {
			return FillFile(elem, []string{value})
		}
		filePath, err := GetFilePathForAccept(input.Accept)
		if err != nil {
			return fmt.Errorf("failed to get upload file for accept=%q: %w", input.Accept, err)
		}
		return FillFile(elem, []string{filePath})

	default:
		return FillText(elem, value)
	}
}

// FillInput fills a single input based on its type.
// CRAWLJAX PARITY: Uses XPath-based element lookup via Identification.
func (h *Handler) FillInput(page *browser.Page, input *DetectedInput) error {
	if !input.CanInteract() {
		idValue := ""
		if input.FormInput != nil && input.Identification != nil {
			idValue = input.Identification.Value
		}
		zap.L().Debug("Input not interactable, skipping",
			zap.String("identification", idValue),
			zap.Bool("disabled", input.Disabled),
			zap.Bool("readonly", input.ReadOnly))
		return nil
	}

	// CRAWLJAX PARITY: Get element using XPath lookup via Identification
	elem, err := h.getElementByIdentification(page, input)
	if err != nil {
		idValue := ""
		if input.FormInput != nil && input.Identification != nil {
			idValue = input.Identification.Value
		}
		return fmt.Errorf("element not found (identification: %s): %w", idValue, err)
	}

	value := h.getValueForInput(input)
	idValue := ""
	if input.FormInput != nil && input.Identification != nil {
		idValue = input.Identification.Value
	}
	zap.L().Debug("Filling input",
		zap.String("identification", idValue),
		zap.String("type", string(input.Type)),
		zap.String("value", value),
		zap.Bool("hasConfiguredValues", input.HasValues()))

	if input.FormInput == nil {
		return fmt.Errorf("no form input")
	}

	switch input.Type {
	case action.InputTypeText, action.InputTypeTextarea, action.InputTypePassword,
		action.InputTypeEmail, action.InputTypeNumber, action.InputTypeInput:
		return FillText(elem, value)

	case action.InputTypeHidden:
		return FillHidden(elem, value)

	case action.InputTypeCheckbox:
		checked := value == "true" || value == "1" || value == "checked"
		return FillCheckbox(elem, checked)

	case action.InputTypeRadio:
		return FillRadio(elem, value)

	case action.InputTypeSelect:
		if input.Multiple && len(input.GetValues()) > 1 {
			return FillSelectMultiple(elem, input.GetValues())
		}
		// Crawljax parity: if no value specified, select random option from dropdown
		if value == "" {
			options, err := GetSelectAllOptions(elem)
			if err == nil && len(options) > 0 {
				value = options[h.rng.Intn(len(options))]
			}
		}
		if value == "" {
			return nil // No options available, skip
		}
		return FillSelect(elem, value)

	case action.InputTypeFile:
		// GO EXTENSION: File upload support with smart file type selection
		// Determine file path: configured value or smart selection based on accept
		filePath := value
		if filePath == "" {
			var err error
			filePath, err = GetFilePathForAccept(input.Accept)
			if err != nil {
				return fmt.Errorf("failed to get upload file for accept=%q: %w", input.Accept, err)
			}
		}

		// If hidden input with trigger, use dialog interception
		if input.Hidden && input.TriggerXPath != "" {
			triggerElem, err := page.ElementX(input.TriggerXPath)
			if err != nil {
				return fmt.Errorf("failed to find trigger element: %w", err)
			}
			return FillFileViaDialog(page, triggerElem, []string{filePath})
		}

		// Direct file input - use SetFiles
		return FillFile(elem, []string{filePath})

	default:
		// Try as text input
		return FillText(elem, value)
	}
}

// getValueForInput returns the appropriate value for an input.
// Priority: 1) Configured value, 2) Constraint-aware, 3) Smart detection, 4) Random/Default
func (h *Handler) getValueForInput(input *DetectedInput) string {
	// 1. Use configured value if available (highest priority)
	if input.HasValues() {
		return input.NextValue()
	}

	// 2. Constraint-aware generation from HTML5 validation attributes
	if val := h.generateConstrainedValue(input); val != "" {
		return val
	}

	// 3. Try intelligent name-based detection (BEYOND Crawljax)
	// Skip for SELECT - smart values are text, but SELECT needs option values
	// Skip for FILE - file handling uses default file path, not smart values
	// Random option selection is handled in FillInput instead
	if input.FormInput != nil && input.Type != action.InputTypeSelect && input.Type != action.InputTypeFile {
		if smartValue := h.getSmartValue(input); smartValue != "" {
			return smartValue
		}
	}

	// 4. Generate random value if enabled
	if h.config.FormFillMode == config.FormFillRandom {
		return h.generateRandomValue(input)
	}

	// 5. Return default value based on type
	return h.getDefaultValue(input)
}

// generateRandomValue generates a random value for the input type.
// Matches Crawljax RandomInputValueGenerator behavior where applicable.
func (h *Handler) generateRandomValue(input *DetectedInput) string {
	if input.FormInput == nil {
		return h.randomString(RandomStringLength)
	}

	switch input.Type {
	case action.InputTypeText, action.InputTypeTextarea:
		// Crawljax: 8-char random string
		return h.randomString(RandomStringLength)

	case action.InputTypePassword:
		// Go extension: random password with complexity
		return h.randomString(12) + "A1!"

	case action.InputTypeEmail:
		// Go extension: random email
		return h.randomString(RandomStringLength) + "@example.com"

	case action.InputTypeNumber:
		// Crawljax: random int 0 to MaxRandomInt-1
		return fmt.Sprintf("%d", h.rng.Intn(MaxRandomInt))

	case action.InputTypeCheckbox:
		// Crawljax: 50% probability, values "1"/"0"
		if h.rng.Float64() > ProbabilityCheck {
			return "1"
		}
		return "0"

	case action.InputTypeRadio:
		// Crawljax: 50% probability, values "1"/"0"
		if h.rng.Float64() > ProbabilityCheck {
			return "1"
		}
		return "0"

	case action.InputTypeSelect:
		// Crawljax: random option selected in FillInput, return empty here
		return ""

	case action.InputTypeFile:
		// GO EXTENSION: File inputs don't use random values - use default file
		return ""

	default:
		// Crawljax: 8-char random string for unknown types
		return h.randomString(RandomStringLength)
	}
}

func (h *Handler) randomString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = randomChars[h.rng.Intn(len(randomChars))]
	}
	return string(result)
}

// generateConstrainedValue generates value respecting HTML5 validation constraints.
func (h *Handler) generateConstrainedValue(input *DetectedInput) string {
	// Pattern regex has highest priority
	if input.Pattern != "" {
		if val := h.generateFromPattern(input.Pattern, input.MinLength, input.MaxLength); val != "" {
			return val
		}
	}

	// Number/Range with min/max/step
	if input.FormInput != nil && input.Type == action.InputTypeNumber &&
		(input.Min != "" || input.Max != "") {
		return h.generateNumberInRange(input.Min, input.Max, input.Step)
	}

	// String length constraints (only for text-like inputs without pattern)
	if input.FormInput != nil && input.IsTextLike() && (input.MinLength > 0 || input.MaxLength > 0) {
		return h.generateStringWithLength(input.MinLength, input.MaxLength)
	}

	return ""
}

// generateFromPattern generates string matching regex pattern using reggen.
func (h *Handler) generateFromPattern(pattern string, minLen, maxLen int) string {
	gen, err := reggen.NewGenerator(pattern)
	if err != nil {
		return ""
	}

	for i := 0; i < 10; i++ {
		val := gen.Generate(h.rng.Intn(20) + 1)
		if (minLen <= 0 || len(val) >= minLen) && (maxLen <= 0 || len(val) <= maxLen) {
			return val
		}
	}
	return gen.Generate(h.rng.Intn(20))
}

// generateNumberInRange generates number within [min, max] respecting step.
func (h *Handler) generateNumberInRange(min, max, step string) string {
	minVal := parseFloatOrDefault(min, 0)
	maxVal := parseFloatOrDefault(max, float64(MaxRandomInt))
	stepVal := parseFloatOrDefault(step, 1)

	if maxVal <= minVal {
		return formatNumber(minVal, stepVal)
	}

	steps := int((maxVal - minVal) / stepVal)
	if steps <= 0 {
		steps = 1
	}
	randomSteps := h.rng.Intn(steps + 1)
	value := minVal + float64(randomSteps)*stepVal

	return formatNumber(value, stepVal)
}

// generateStringWithLength generates string with length in [minLen, maxLen].
func (h *Handler) generateStringWithLength(minLen, maxLen int) string {
	if minLen <= 0 {
		minLen = 1
	}
	if maxLen <= 0 || maxLen < minLen {
		maxLen = minLen + RandomStringLength
	}

	length := minLen
	if maxLen > minLen {
		length = minLen + h.rng.Intn(maxLen-minLen+1)
	}
	return h.randomString(length)
}

// Helper functions for constraint-aware generation

// escapeXPathString escapes quotes in XPath string values.
// GO IMPROVEMENT over Crawljax: Uses double quotes when possible for cleaner XPath.
// - No quotes: 'value'
// - Single quotes only: "value" (simpler than concat)
// - Double quotes only: 'value'
// - Both: concat('before', "'", 'after')
func escapeXPathString(s string) string {
	hasSingle := strings.Contains(s, "'")
	hasDouble := strings.Contains(s, "\"")

	switch {
	case !hasSingle:
		return "'" + s + "'"
	case !hasDouble:
		return "\"" + s + "\""
	default:
		// Both quotes - use concat()
		parts := strings.Split(s, "'")
		var b strings.Builder
		b.WriteString("concat(")
		for i, part := range parts {
			if i > 0 {
				b.WriteString(", \"'\", ")
			}
			b.WriteString("'")
			b.WriteString(part)
			b.WriteString("'")
		}
		b.WriteString(")")
		return b.String()
	}
}

func parseFloatOrDefault(s string, def float64) float64 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return v
}

func formatNumber(v, step float64) string {
	if step == float64(int(step)) && step >= 1 {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%g", v)
}

// containsAny checks if any of the patterns are contained in target strings.
func containsAny(targets []string, patterns ...string) bool {
	for _, target := range targets {
		for _, pattern := range patterns {
			if strings.Contains(target, pattern) {
				return true
			}
		}
	}
	return false
}

// Fixed credentials for consistent register/login flow during crawling
const (
	FixedEmail    = "johnted132123@gmail.com"
	FixedUsername = "johnted132123"
	FixedPassword = "Server2018!!"
)

// getSmartValue generates intelligent values based on input name/id/placeholder/label.
// This goes BEYOND Crawljax by detecting field purpose from naming conventions.
// Note: email, username, password use FIXED values for consistent register/login during crawl.
func (h *Handler) getSmartValue(input *DetectedInput) string {
	name := strings.ToLower(input.Name)
	id := strings.ToLower(input.ID)
	placeholder := strings.ToLower(input.Placeholder)
	label := strings.ToLower(input.Label)
	targets := []string{name, id, placeholder, label}

	// Email patterns - FIXED for consistent login
	if containsAny(targets, "email", "mail", "e-mail", "correo") {
		return FixedEmail
	}

	// Password patterns - FIXED for consistent login
	if containsAny(targets, "password", "passwd", "pwd", "pass", "secret") {
		return FixedPassword
	}

	// Username patterns - FIXED for consistent login
	if containsAny(targets, "username", "user_name", "login", "userid", "user_id") {
		return FixedUsername
	}

	// Phone patterns
	if containsAny(targets, "phone", "tel", "mobile", "cell", "fax", "telefono") {
		return "+15551234567"
	}

	// Name patterns - check specific patterns first
	if containsAny(targets, "firstname", "first_name", "fname", "given_name", "givenname") {
		return "Crawl"
	}
	if containsAny(targets, "lastname", "last_name", "lname", "surname", "family_name", "familyname") {
		return "Tester"
	}
	if containsAny(targets, "fullname", "full_name") {
		return "Crawl Tester"
	}
	// Generic "name" - avoid matching "username"
	if (name == "name" || id == "name") && !containsAny(targets, "user") {
		return "Crawl Tester"
	}

	// Address patterns - FIXED for consistent crawl
	if containsAny(targets, "address", "street", "addr", "direccion") {
		return "123 Test Street"
	}
	if containsAny(targets, "city", "ciudad") {
		return "New York"
	}
	if containsAny(targets, "zip", "postal", "postcode", "zipcode") {
		return "10001"
	}
	if containsAny(targets, "country", "pais") {
		return "United States"
	}
	if containsAny(targets, "state", "province", "region", "estado") {
		return "New York"
	}

	// Date patterns - FIXED for consistent crawl
	if containsAny(targets, "date", "dob", "birthday", "birth", "fecha") {
		return "1990-01-15"
	}

	// Age patterns
	if containsAny(targets, "age", "edad") {
		return "30"
	}

	// URL patterns
	if containsAny(targets, "url", "website", "site", "link", "homepage", "web") {
		return "https://example.com/test"
	}

	// Company patterns
	if containsAny(targets, "company", "org", "organization", "empresa", "business") {
		return "Test Company Inc"
	}

	// Credit card patterns (fake data for testing)
	if containsAny(targets, "card", "credit", "ccn", "cardnumber", "card_number") {
		return "4111111111111111" // Test Visa
	}
	if containsAny(targets, "cvv", "cvc", "security_code", "securitycode") {
		return "123"
	}
	if containsAny(targets, "expiry", "exp", "expiration") {
		return "12/25"
	}

	// Message/comment patterns
	if containsAny(targets, "message", "comment", "note", "description", "bio", "about", "text", "content", "body") {
		return "Test message for form submission"
	}

	// Search patterns
	if containsAny(targets, "search", "query", "keyword") || name == "q" || id == "q" {
		return "a"
	}

	// Title patterns
	if containsAny(targets, "title", "subject", "titulo", "asunto") {
		return "Test Title"
	}

	// Fallback - no match found
	return "a"
}

// getDefaultValue returns a default value for the input type.
func (h *Handler) getDefaultValue(input *DetectedInput) string {
	if input.FormInput == nil {
		return "a"
	}

	switch input.Type {
	case action.InputTypeText, action.InputTypeTextarea:
		return "a"

	case action.InputTypePassword:
		return "Password123!"

	case action.InputTypeEmail:
		return "test@example.com"

	case action.InputTypeNumber:
		return "42"

	case action.InputTypeCheckbox:
		return "true"

	case action.InputTypeSelect:
		// Return empty to trigger random option selection in FillInput
		return ""

	case action.InputTypeFile:
		// GO EXTENSION: Return empty - file handling uses generated default
		return ""

	default:
		return "a"
	}
}

// ResetInputs clears all inputs.
// CRAWLJAX PARITY: Uses XPath-based element lookup via Identification.
func (h *Handler) ResetInputs(page *browser.Page, inputs []*DetectedInput) error {
	for _, input := range inputs {
		elem, err := h.getElementByIdentification(page, input)
		if err != nil {
			continue
		}

		if err := ClearInput(elem); err != nil {
			continue
		}
	}

	return nil
}

// FillForm fills all inputs in a form.
func (h *Handler) FillForm(page *browser.Page, form *Form) *FillInputsResult {
	return h.FillInputs(page, form.Inputs)
}

// SubmitForm fills and submits a form.
// Returns the fill result and any submission error.
func (h *Handler) SubmitForm(page *browser.Page, form *Form) (*FillInputsResult, error) {
	// Fill the form first
	fillResult := h.FillForm(page, form)

	// Find submit button using XPath
	submitXPath := form.XPath + "//input[@type='submit'] | " +
		form.XPath + "//button[@type='submit'] | " +
		form.XPath + "//button[not(@type)]"

	elem, err := page.ElementX(submitXPath)
	if err == nil && elem != nil {
		return fillResult, elem.Click()
	}

	// Fallback: submit via JavaScript using XPath
	script := fmt.Sprintf(`
		(() => {
			const result = document.evaluate(%q, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
			if (result.singleNodeValue) {
				result.singleNodeValue.submit();
				return true;
			}
			return false;
		})()
	`, form.XPath)
	_, err = page.Eval(script)
	return fillResult, err
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

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

// CRAWLJAX PARITY: Pairwise form handling

// getIdentificationKey returns a unique key for the input based on Identification.
func getIdentificationKey(input *DetectedInput) string {
	if input.FormInput != nil && input.Identification != nil {
		return input.Identification.String()
	}
	if input.XPath != "" {
		return "xpath:" + input.XPath
	}
	return ""
}

// FillInputsPairwise tries filling inputs in pairs when full fill fails.
// This matches Java Crawljax's handleInputs_pairwise() fallback mechanism.
// IMPORTANT: Caller should already have attempted FillInputs and it failed.
// This function assumes inputs need pairwise testing, not a full retry.
// Returns (success, workedInputs) - the inputs that were successfully filled.
// CRAWLJAX PARITY: Uses Identification-based keys instead of CSS selectors.
func (h *Handler) FillInputsPairwise(page *browser.Page, inputs []*DetectedInput) (bool, []*DetectedInput) {
	// Reset all inputs before pairwise testing
	// (caller already tried FillInputs which failed)
	_ = h.ResetInputs(page, inputs)

	// Track which inputs work (can be filled without error)
	workingInputs := make(map[string]bool)
	testedPairs := make(map[string]bool)

	// Try pairs of inputs to find which ones work together
	for i := range len(inputs) {
		for j := i + 1; j < len(inputs); j++ {
			input1 := inputs[i]
			input2 := inputs[j]

			// Create unique pair key using Identification
			key1 := getIdentificationKey(input1)
			key2 := getIdentificationKey(input2)
			pairKey := fmt.Sprintf("%s:%s", key1, key2)
			if testedPairs[pairKey] {
				continue
			}
			testedPairs[pairKey] = true

			// Reset before trying this pair
			_ = h.ResetInputs(page, []*DetectedInput{input1, input2})

			// Try filling this pair
			pair := []*DetectedInput{input1, input2}
			pairResult := h.FillInputs(page, pair)

			if pairResult.Failed == 0 {
				// Mark both inputs as working
				workingInputs[key1] = true
				workingInputs[key2] = true
			}
		}
	}

	// Collect working inputs
	worked := make([]*DetectedInput, 0)
	for _, input := range inputs {
		key := getIdentificationKey(input)
		if workingInputs[key] {
			worked = append(worked, input)
		}
	}

	// If we found working inputs, reset all and fill them once
	if len(worked) > 0 {
		_ = h.ResetInputs(page, inputs)
		finalResult := h.FillInputs(page, worked)
		return finalResult.Failed == 0, worked
	}

	return false, nil
}

// FillFormPairwise fills a form using pairwise strategy if normal fill fails.
func (h *Handler) FillFormPairwise(page *browser.Page, form *Form) (bool, []*DetectedInput) {
	return h.FillInputsPairwise(page, form.Inputs)
}
