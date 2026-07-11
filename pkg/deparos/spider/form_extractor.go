package spider

import (
	"context"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/spider/formparser"
)

// FormExtractor extracts actionable form requests from HTML responses.
type FormExtractor struct {
	urlResolver *URLResolver
}

// NewFormExtractor creates a new form extractor.
func NewFormExtractor(urlResolver *URLResolver) *FormExtractor {
	return &FormExtractor{urlResolver: urlResolver}
}

// ExtractForms parses forms from HTML and returns actionable requests.
// For forms with radio buttons or checkboxes, multiple requests are generated
// with different option combinations.
func (e *FormExtractor) ExtractForms(
	ctx context.Context,
	baseURL *url.URL,
	response *HTTPResponse,
) ([]*FormRequest, error) {
	// Ensure HTML is parsed
	if err := response.ParseHTML(); err != nil {
		//nolint:nilerr // intentional: unparseable HTML skipped silently
		return nil, nil
	}

	if response.HTML == nil {
		return nil, nil
	}

	// Create mock http.Request for formparser
	req := &http.Request{URL: baseURL}

	// Extract forms using formparser
	forms := formparser.ExtractFormsInfo(
		req,
		response.HTML,
		func() bool { return ctx.Err() != nil },
	)

	if len(forms) == 0 {
		return nil, nil
	}

	// Convert FormInfo to FormRequests
	return e.convertToRequests(baseURL, forms), nil
}

// convertToRequests converts FormInfo slice to actionable FormRequests.
// Handles multiple submit buttons and radio/checkbox option variations.
func (e *FormExtractor) convertToRequests(
	sourceURL *url.URL,
	forms []*formparser.FormInfo,
) []*FormRequest {
	var requests []*FormRequest

	for _, form := range forms {
		// Resolve action URL against source URL
		actionURL := e.resolveActionURL(sourceURL, form)
		if actionURL == nil {
			continue
		}

		// Find submit buttons
		submitButtons := e.findSubmitButtons(form)

		// Group radio buttons, select options, and collect checkboxes
		radioGroups := e.groupRadioButtons(form)
		selectGroups := e.groupSelectOptions(form)
		checkboxInputs := e.findCheckboxInputs(form)

		// Generate all option combinations (cartesian product of radio + select options)
		combinations := e.generateOptionCombinations(radioGroups, selectGroups, checkboxInputs)

		// Generate requests for each combination
		if len(combinations) == 0 {
			// No radio/checkbox, generate single request per submit button
			if len(submitButtons) == 0 {
				req := e.buildRequest(sourceURL, actionURL, form, nil, nil)
				if req != nil {
					requests = append(requests, req)
				}
			} else {
				for _, submit := range submitButtons {
					req := e.buildRequest(sourceURL, actionURL, form, submit, nil)
					if req != nil {
						requests = append(requests, req)
					}
				}
			}
		} else {
			// Generate request for each combination
			for i := range combinations {
				combo := &combinations[i]
				if len(submitButtons) == 0 {
					req := e.buildRequest(sourceURL, actionURL, form, nil, combo)
					if req != nil {
						requests = append(requests, req)
					}
				} else {
					for _, submit := range submitButtons {
						req := e.buildRequest(sourceURL, actionURL, form, submit, combo)
						if req != nil {
							requests = append(requests, req)
						}
					}
				}
			}
		}
	}

	return requests
}

// resolveActionURL resolves the form action URL against source URL.
func (e *FormExtractor) resolveActionURL(sourceURL *url.URL, form *formparser.FormInfo) *url.URL {
	if form.ActionURL == "" {
		// No action attribute, use current URL
		return sourceURL
	}

	resolved, err := e.urlResolver.Resolve(sourceURL, form.ActionURL)
	if err != nil {
		return sourceURL
	}
	return resolved
}

// findSubmitButtons returns all submit button inputs from the form.
func (e *FormExtractor) findSubmitButtons(form *formparser.FormInfo) []*formparser.FormInputInfo {
	var submits []*formparser.FormInputInfo
	for _, input := range form.Inputs {
		if input.Type == formparser.InputTypeSubmit || input.Type == formparser.InputTypeImage {
			submits = append(submits, input)
		}
	}
	return submits
}

// radioGroup represents a group of radio buttons with the same name.
type radioGroup struct {
	name   string
	values []string
}

// selectGroup represents a select element with its options.
type selectGroup struct {
	name   string
	values []string
}

// groupRadioButtons groups radio inputs by name.
func (e *FormExtractor) groupRadioButtons(form *formparser.FormInfo) []radioGroup {
	groups := make(map[string][]string)
	order := []string{} // Preserve order

	for _, input := range form.Inputs {
		if input.Type == formparser.InputTypeRadio {
			if _, exists := groups[input.Name]; !exists {
				order = append(order, input.Name)
			}
			groups[input.Name] = append(groups[input.Name], input.Value)
		}
	}

	result := make([]radioGroup, 0, len(order))
	for _, name := range order {
		result = append(result, radioGroup{
			name:   name,
			values: groups[name],
		})
	}
	return result
}

// findCheckboxInputs returns all checkbox inputs.
func (e *FormExtractor) findCheckboxInputs(form *formparser.FormInfo) []*formparser.FormInputInfo {
	var checkboxes []*formparser.FormInputInfo
	for _, input := range form.Inputs {
		if input.Type == formparser.InputTypeCheckbox {
			checkboxes = append(checkboxes, input)
		}
	}
	return checkboxes
}

// groupSelectOptions groups select inputs by name (both single-select and multi-select).
func (e *FormExtractor) groupSelectOptions(form *formparser.FormInfo) []selectGroup {
	groups := make(map[string][]string)
	order := []string{}

	for _, input := range form.Inputs {
		if input.Type == formparser.InputTypeSelect ||
			input.Type == formparser.InputTypeSelectMultiple {
			if _, exists := groups[input.Name]; !exists {
				order = append(order, input.Name)
			}
			groups[input.Name] = append(groups[input.Name], input.Value)
		}
	}

	result := make([]selectGroup, 0, len(order))
	for _, name := range order {
		result = append(result, selectGroup{
			name:   name,
			values: groups[name],
		})
	}
	return result
}

// optionCombination represents a specific selection of radio, checkbox, and select values.
type optionCombination struct {
	radioSelections    map[string]string // name -> selected value
	checkboxSelections map[string]bool   // name -> checked
	selectSelections   map[string]string // name -> selected option value
}

// maxFormOptionCombinations bounds the number of radio/select value combinations
// materialized per form. The full Cartesian product is EXPONENTIAL in the number
// of radio+select GROUPS (e.g. 6 selects × 10 options = 10^6 variants, each an
// allocated struct + FormRequest), so a crafted page could OOM the crawler. The
// cap truncates that product while staying high enough to preserve a single large
// group's LINEAR expansion (e.g. a 250-option country dropdown → one request per
// option), which is legitimate coverage, not a blowup.
const maxFormOptionCombinations = 256

// cloneOptionCombination copies an optionCombination's selection maps. The maps
// hold primitive values, so a shallow clone is a full copy.
func cloneOptionCombination(src optionCombination) optionCombination {
	return optionCombination{
		radioSelections:    maps.Clone(src.radioSelections),
		checkboxSelections: maps.Clone(src.checkboxSelections),
		selectSelections:   maps.Clone(src.selectSelections),
	}
}

// generateOptionCombinations generates combinations of radio, select, and checkbox options.
// Radio buttons: Creates cartesian product - one variant per option in each group.
// Select: Creates cartesian product - one variant per option (like radio).
// Checkboxes: All checkboxes are always checked (no variants).
//
// The product is bounded to maxFormOptionCombinations: expansion stops once the
// cap is hit so allocation stays O(cap) per group rather than exponential in the
// number of groups. Truncation is acceptable because the downstream per-structure
// submission cap keeps only a few variants regardless.
func (e *FormExtractor) generateOptionCombinations(
	radioGroups []radioGroup,
	selectGroups []selectGroup,
	checkboxes []*formparser.FormInputInfo,
) []optionCombination {
	if len(radioGroups) == 0 && len(selectGroups) == 0 && len(checkboxes) == 0 {
		return nil
	}

	// Start with empty combination
	combinations := []optionCombination{{
		radioSelections:    make(map[string]string),
		checkboxSelections: make(map[string]bool),
		selectSelections:   make(map[string]string),
	}}

	// expand multiplies the running combinations by one group's values, applying
	// assign() to set that group's selection, and stops at the cap.
	expand := func(name string, values []string, assign func(c *optionCombination, name, value string)) {
		if len(values) == 0 {
			return // an empty group must not wipe the running combinations
		}
		newCombos := make([]optionCombination, 0, min(len(combinations)*len(values), maxFormOptionCombinations))
		for _, combo := range combinations {
			for _, value := range values {
				if len(newCombos) >= maxFormOptionCombinations {
					combinations = newCombos
					return
				}
				newCombo := cloneOptionCombination(combo)
				assign(&newCombo, name, value)
				newCombos = append(newCombos, newCombo)
			}
		}
		combinations = newCombos
	}

	// Expand for each radio group (bounded cartesian product)
	for _, group := range radioGroups {
		expand(group.name, group.values, func(c *optionCombination, name, value string) {
			c.radioSelections[name] = value
		})
	}

	// Expand for each select group (bounded cartesian product, like radio)
	for _, group := range selectGroups {
		expand(group.name, group.values, func(c *optionCombination, name, value string) {
			c.selectSelections[name] = value
		})
	}

	// Checkboxes: Always check ALL checkboxes (no variants)
	for _, cb := range checkboxes {
		for i := range combinations {
			combinations[i].checkboxSelections[cb.Name] = true
		}
	}

	return combinations
}

// buildRequest creates a FormRequest from FormInfo.
func (e *FormExtractor) buildRequest(
	sourceURL *url.URL,
	actionURL *url.URL,
	form *formparser.FormInfo,
	submitButton *formparser.FormInputInfo,
	optionCombo *optionCombination,
) *FormRequest {
	method := strings.ToUpper(form.Method)
	if method == "" {
		method = "GET"
	}

	// Collect input values
	inputs := e.collectInputs(form, submitButton, optionCombo)

	var body, contentType string
	finalURL := *actionURL // Copy to avoid mutation

	if method == "GET" {
		// Encode inputs into query string, merging with existing action URL params.
		// Form params override action URL params with the same name.
		queryParams := e.encodeFormURLEncoded(inputs)
		if queryParams != "" {
			if finalURL.RawQuery != "" {
				existingParams, _ := url.ParseQuery(finalURL.RawQuery)
				newParams, _ := url.ParseQuery(queryParams)
				for key, values := range newParams {
					existingParams[key] = values // Replace, not append
				}
				finalURL.RawQuery = existingParams.Encode()
			} else {
				finalURL.RawQuery = queryParams
			}
		}
	} else {
		// POST - determine encoding
		if e.hasFileInput(form) && strings.Contains(strings.ToLower(form.Enctype), "multipart") {
			body, contentType = e.encodeMultipart(inputs)
		} else {
			body = e.encodeFormURLEncoded(inputs)
			contentType = "application/x-www-form-urlencoded"
		}
	}

	return &FormRequest{
		SourceURL:   sourceURL,
		URL:         &finalURL,
		Method:      method,
		ContentType: contentType,
		Body:        body,
		Inputs:      inputs,
		SourceForm:  form,
	}
}

// collectInputs gathers all input values for submission.
func (e *FormExtractor) collectInputs(
	form *formparser.FormInfo,
	submitButton *formparser.FormInputInfo,
	optionCombo *optionCombination,
) []*FormInputValue {
	var inputs []*FormInputValue
	seenRadio := make(map[string]bool)
	seenSelect := make(map[string]bool)
	seenOther := make(map[string]bool) // Dedup for text, hidden, textarea, etc.

	for _, input := range form.Inputs {
		switch input.Type {
		case formparser.InputTypeSubmit, formparser.InputTypeImage:
			// Only include the clicked submit button
			continue

		case formparser.InputTypeRadio:
			// Only include the selected radio option
			if seenRadio[input.Name] {
				continue
			}
			seenRadio[input.Name] = true

			if optionCombo != nil {
				if selectedValue, ok := optionCombo.radioSelections[input.Name]; ok {
					inputs = append(inputs, &FormInputValue{
						Name:  input.Name,
						Value: selectedValue,
						Type:  input.Type,
					})
				}
			} else {
				// No combo specified, use first value
				inputs = append(inputs, &FormInputValue{
					Name:  input.Name,
					Value: input.Value,
					Type:  input.Type,
				})
			}

		case formparser.InputTypeCheckbox:
			// Include if checked in combination
			if optionCombo != nil {
				if checked, ok := optionCombo.checkboxSelections[input.Name]; ok && checked {
					inputs = append(inputs, &FormInputValue{
						Name:  input.Name,
						Value: input.Value,
						Type:  input.Type,
					})
				}
			}
			// If no combo, skip checkbox (unchecked by default)

		case formparser.InputTypeButton, formparser.InputTypeNone:
			// Skip non-submitting buttons
			continue

		case formparser.InputTypeSelect, formparser.InputTypeSelectMultiple:
			// Both single-select and multi-select: use value from optionCombo or first option.
			// Each option generates a separate request variant (cartesian product).
			if seenSelect[input.Name] {
				continue
			}
			seenSelect[input.Name] = true

			if optionCombo != nil {
				if selectedValue, ok := optionCombo.selectSelections[input.Name]; ok {
					inputs = append(inputs, &FormInputValue{
						Name:  input.Name,
						Value: selectedValue,
						Type:  input.Type,
					})
					continue
				}
			}
			// No combo specified, use first value
			inputs = append(inputs, &FormInputValue{
				Name:  input.Name,
				Value: input.Value,
				Type:  input.Type,
			})

		default:
			// Include text, password, hidden, textarea, etc.
			// Deduplicate by name - first value wins
			if seenOther[input.Name] {
				continue
			}
			seenOther[input.Name] = true
			inputs = append(inputs, &FormInputValue{
				Name:  input.Name,
				Value: input.Value,
				Type:  input.Type,
			})
		}
	}

	// Add submit button if present and has name
	if submitButton != nil && submitButton.Name != "" {
		inputs = append(inputs, &FormInputValue{
			Name:  submitButton.Name,
			Value: submitButton.Value,
			Type:  submitButton.Type,
		})
	}

	return inputs
}

// hasFileInput checks if the form has any file input fields.
func (e *FormExtractor) hasFileInput(form *formparser.FormInfo) bool {
	for _, input := range form.Inputs {
		if input.Type == formparser.InputTypeFile {
			return true
		}
	}
	return false
}

// encodeFormURLEncoded encodes inputs as application/x-www-form-urlencoded.
func (e *FormExtractor) encodeFormURLEncoded(inputs []*FormInputValue) string {
	values := url.Values{}
	for _, input := range inputs {
		values.Add(input.Name, input.Value)
	}
	return values.Encode()
}

// encodeMultipart encodes inputs as multipart/form-data.
// Returns body and Content-Type header with boundary.
func (e *FormExtractor) encodeMultipart(inputs []*FormInputValue) (string, string) {
	var body strings.Builder
	writer := multipart.NewWriter(&body)

	for _, input := range inputs {
		if input.Type == formparser.InputTypeFile {
			// Create file field with placeholder
			part, err := writer.CreateFormFile(input.Name, "file.txt")
			if err == nil {
				_, _ = part.Write([]byte("")) // Empty file content placeholder
			}
		} else {
			_ = writer.WriteField(input.Name, input.Value)
		}
	}

	_ = writer.Close()
	return body.String(), writer.FormDataContentType()
}
