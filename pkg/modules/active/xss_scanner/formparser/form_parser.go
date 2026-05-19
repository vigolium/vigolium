package formparser

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/active/xss_scanner/htmlparser"
)

// Using byte for direct mapping if persistedForm values are important.
// Otherwise, string constants might be more Go-idiomatic if direct mapping isn't critical.
type InputType byte

const (
	InputTypeNone           InputType = 0xFF
	InputTypeText           InputType = 0
	InputTypePassword       InputType = 1
	InputTypeCheckbox       InputType = 2
	InputTypeRadio          InputType = 3
	InputTypeSubmit         InputType = 4
	InputTypeFile           InputType = 5
	InputTypeHidden         InputType = 6
	InputTypeImage          InputType = 7
	InputTypeButton         InputType = 8
	InputTypeNumber         InputType = 9
	InputTypeSelect         InputType = 10
	InputTypeTextarea       InputType = 11
	InputTypeSelectMultiple InputType = 12
)

// FormInputInfo represents a single input field within an HTML form.
type FormInputInfo struct {
	Type         InputType // Changed from string to InputType
	Name         string
	Value        string
	InputElement *htmlparser.HTMLElement // Pointer to the original HTMLElement
}

// FormInfo represents a parsed HTML form.
type FormInfo struct {
	ActionURL   string                  // Absolute URL for the form action
	Method      string                  // GET or POST, defaults to GET
	Enctype     string                  // e.g., application/x-www-form-urlencoded, multipart/form-data
	FormElement *htmlparser.HTMLElement // Pointer to the original <form> HTMLElement
	Inputs      []*FormInputInfo
}

// mapHtmlInputTypeToInputType maps HTML input type string to our InputType enum,
// It considers both the 'type' attribute and the tag name (for buttons).
func mapHtmlInputTypeToInputType(htmlTypeAttribute, tagName string) InputType {
	lowerTagName := strings.ToLower(tagName)
	lowerHtmlType := strings.ToLower(htmlTypeAttribute)

	switch lowerTagName {
	case "input":
		switch lowerHtmlType {
		case "text":
			return InputTypeText
		case "password":
			return InputTypePassword
		case "checkbox":
			return InputTypeCheckbox
		case "radio":
			return InputTypeRadio
		case "submit":
			return InputTypeSubmit
		case "file":
			return InputTypeFile
		case "hidden":
			return InputTypeHidden
		case "image":
			return InputTypeImage
		case "button": // <input type="button">
			return InputTypeButton
		case "number":
			return InputTypeNumber
		case "reset":
			return InputTypeNone // Explicitly None for reset inputs
		default:
			// Fallback for <input> with unrecognized or missing type attribute.
			// Since "button" is handled above and "reset" is None, others default to TEXT.
			return InputTypeText
		}
	case "button":
		// For <button> tags, if type is "submit" or missing/empty, it's a submit button.
		// If type is "button", it's a generic button.
		// If type is "reset", it's a reset button.
		switch lowerHtmlType {
		case "submit", "": // Empty or "submit" type for <button>
			return InputTypeSubmit
		case "reset":
			return InputTypeNone
		case "button":
			return InputTypeButton
		default:
			// According to HTML spec, if type attribute for <button> is missing or invalid, it defaults to "submit".
			// We handle known types; others could be considered submit or a generic button.
			// This implies other types for <button> (like an invalid one) are not treated as form submission inputs.			// For strictness, if it's not explicitly submit, reset, or button, treat as non-submitting (None).
			return InputTypeNone
		}
	case "select":
		// "multiple" attribute presence determines SELECT_MULTIPLE vs SELECT.
		// This is handled during <option> processing, not here directly.
		// For a general select tag, we can default to SELECT.
		return InputTypeSelect
	case "textarea":
		return InputTypeTextarea
	}

	return InputTypeNone // Default for unhandled tags
}

// resolveBaseURL attempts to find a <base href="..."> tag and resolve it against the request URL.
// ... existing code ...

// resolveBaseURL attempts to find a <base href="..."> tag and resolve it against the request URL.
func resolveBaseURL(req *http.Request, htmlElements []*htmlparser.HTMLElement) *url.URL {
	if req == nil || req.URL == nil {
		return nil
	}
	originalBaseURL := req.URL
	for _, element := range htmlElements {
		if element.TagInfo != nil && element.Type == htmlparser.OpenTag &&
			strings.EqualFold(element.TagInfo.Name, "base") {
			for _, attr := range element.TagInfo.Attributes {
				if strings.EqualFold(attr.Name, "href") {
					baseHref := strings.TrimSpace(attr.Value)
					if baseHref != "" {
						parsedBaseHref, err := originalBaseURL.Parse(baseHref)
						if err == nil {
							return parsedBaseHref
						}
						return originalBaseURL
					}
				}
			}
			break
		}
	}
	return originalBaseURL
}

// ExtractFormsInfo parses HTML elements to find forms and their input fields,
func ExtractFormsInfo(
	req *http.Request,
	htmlElements []*htmlparser.HTMLElement,
	originalBody []byte, // Added to get raw HTML for tags inside textarea
	stopSupplier func() bool,
) []*FormInfo {
	var forms []*FormInfo

	// This resolves the base URL considering <base href> tag.
	// The original req.URL is the initial base.
	var effectiveBaseURL *url.URL
	if req != nil && req.URL != nil {
		effectiveBaseURL = resolveBaseURL(
			req,
			htmlElements,
		) // resolveBaseURL returns req.URL if <base> not found or invalid
	} else if len(htmlElements) > 0 {
		// If req or req.URL is nil, but we have HTML elements, try to find a base URL anyway.
		// This might be less common but covers edge cases.
		effectiveBaseURL = resolveBaseURL(&http.Request{URL: &url.URL{}}, htmlElements)
	}

	numElements := len(htmlElements)
	mainLoopIndex := 0

Label225:
	for mainLoopIndex < numElements {
		if stopSupplier != nil && stopSupplier() {
			return nil // Return null if stopSupplier signals to stop
		}
		if mainLoopIndex >= numElements { // Equivalent to !var5.hasNext()
			break Label225
		}

		// Find the next <form> tag
		var currentFormElement *htmlparser.HTMLElement
		var isFormSelfClosing = false
		formElementSearchIndex := mainLoopIndex

		for formElementSearchIndex < numElements {
			elementToTest := htmlElements[formElementSearchIndex]
			if elementToTest.TagInfo != nil && strings.EqualFold(elementToTest.TagInfo.Name, "form") {
				currentFormElement = elementToTest
				if elementToTest.Type == htmlparser.SelfClosingTagOrPI {
					isFormSelfClosing = true
				}
				break // Found a form tag
			}
			formElementSearchIndex++
		}

		if currentFormElement == nil {
			break Label225 // No more forms found
		}
		mainLoopIndex = formElementSearchIndex // Advance mainLoopIndex to the found form

		// Process the found form
		var actionURL *url.URL
		actionStr := ""
		if currentFormElement.TagInfo != nil {
			for _, attr := range currentFormElement.TagInfo.Attributes {
				if strings.EqualFold(attr.Name, "action") {
					actionStr = attr.Value
					break
				}
			}
		}

		if effectiveBaseURL != nil {
			if actionStr == "" {
				actionURL = effectiveBaseURL // No action attribute, use base URL
			} else {
				parsedAction, err := effectiveBaseURL.Parse(actionStr)
				if err == nil {
					actionURL = parsedAction
				} else {
					actionURL = effectiveBaseURL // Fallback to base if parsing action fails
				}
			}
		} else if actionStr != "" {
			// No effective base URL, try to parse actionStr as an absolute URL
			parsedAction, err := url.Parse(actionStr)
			if err == nil && parsedAction.IsAbs() {
				actionURL = parsedAction
			}
			// If not absolute or parse error, actionURL remains nil
		}

		formInfo := &FormInfo{
			FormElement: currentFormElement,
			Inputs:      make([]*FormInputInfo, 0),
			Enctype:     "application/x-www-form-urlencoded", // Default enctype
		}
		if actionURL != nil {
			formInfo.ActionURL = actionURL.String()
		}

		// Determine form method and enctype from attributes
		formInfo.Method = "GET" // Default method
		if currentFormElement.TagInfo != nil {
			enctypeFound := false
			for _, attr := range currentFormElement.TagInfo.Attributes {
				if strings.EqualFold(attr.Name, "method") {
					formInfo.Method = strings.ToUpper(attr.Value)
				} else if strings.EqualFold(attr.Name, "enctype") {
					formInfo.Enctype = attr.Value
					enctypeFound = true
				}
			}
			// Default enctype (application/x-www-form-urlencoded) already set above
			_ = enctypeFound
		}

		forms = append(forms, formInfo)                  // Add the form early, its inputs will be populated
		currentFormInputs := &forms[len(forms)-1].Inputs // Get a pointer to the current form's inputs slice

		if isFormSelfClosing {
			mainLoopIndex++
			continue Label225
		}

		// Inner loop to process elements inside the form
		formContentLoopIndex := mainLoopIndex + 1
		for formContentLoopIndex < numElements {
			if stopSupplier != nil && stopSupplier() {
				return nil
			}

			currentElement := htmlElements[formContentLoopIndex]

			// Check for closing </form> tag
			if currentElement.Type == htmlparser.CloseTag && currentElement.TagInfo != nil && strings.EqualFold(currentElement.TagInfo.Name, "form") {
				mainLoopIndex = formContentLoopIndex + 1 // Move past </form>
				continue Label225                        // Continue to find the next form
			}

			// Process input, button, select, textarea tags
			if currentElement.Type == htmlparser.OpenTag || currentElement.Type == htmlparser.SelfClosingTagOrPI {
				if currentElement.TagInfo != nil {
					tagNameLower := strings.ToLower(currentElement.TagInfo.Name)
					inputName := ""
					inputValue := ""
					inputTypeAttr := ""

					for _, attr := range currentElement.TagInfo.Attributes {
						attrNameLower := strings.ToLower(attr.Name)
						switch attrNameLower {
						case "name":
							inputName = attr.Value
						case "value":
							inputValue = attr.Value
						case "type":
							inputTypeAttr = attr.Value
						}
					}

					if tagNameLower == "input" {
						inputType := mapHtmlInputTypeToInputType(inputTypeAttr, tagNameLower)
						if inputType != InputTypeNone && inputType != InputTypeButton {
							*currentFormInputs = append(*currentFormInputs, &FormInputInfo{
								Type:         inputType,
								Name:         inputName,
								Value:        inputValue,
								InputElement: currentElement,
							})
						}
					} else if tagNameLower == "button" {
						inputType := mapHtmlInputTypeToInputType(inputTypeAttr, tagNameLower)
						if inputType == InputTypeSubmit {
							*currentFormInputs = append(*currentFormInputs, &FormInputInfo{
								Type:         InputTypeSubmit,
								Name:         inputName,
								Value:        inputValue,
								InputElement: currentElement,
							})
						}
					} else if tagNameLower == "select" {
						isMultiple := false
						for _, attr := range currentElement.TagInfo.Attributes {
							if strings.EqualFold(attr.Name, "multiple") {
								isMultiple = true
								break
							}
						}

						// Inner loop for options, start from element after <select>
						optionLoopIndex := formContentLoopIndex + 1
						for optionLoopIndex < numElements {
							optionElement := htmlElements[optionLoopIndex]
							if optionElement.Type == htmlparser.CloseTag && optionElement.TagInfo != nil && strings.EqualFold(optionElement.TagInfo.Name, "select") {
								// Continue from after </select> in outer loop
								break
							}
							// If form closes before select closes
							if optionElement.Type == htmlparser.CloseTag && optionElement.TagInfo != nil && strings.EqualFold(optionElement.TagInfo.Name, "form") {
								// Outer loop will handle </form>
								break
							}

							if (optionElement.Type == htmlparser.OpenTag || optionElement.Type == htmlparser.SelfClosingTagOrPI) &&
								optionElement.TagInfo != nil && strings.EqualFold(optionElement.TagInfo.Name, "option") {
								optionValue := ""
								valueAttrFound := false
								for _, attr := range optionElement.TagInfo.Attributes {
									if strings.EqualFold(attr.Name, "value") {
										optionValue = attr.Value
										valueAttrFound = true
										break
									}
								}

								if !valueAttrFound {
									if optionLoopIndex+1 < numElements && htmlElements[optionLoopIndex+1].Type == htmlparser.TextNode {
										optionValue = strings.TrimSpace(htmlElements[optionLoopIndex+1].Content) // Trimmed here
										// We will advance optionLoopIndex by one more at the end of this iteration for the text node
									}
								}

								selectType := InputTypeSelect
								if isMultiple {
									selectType = InputTypeSelectMultiple
								}
								*currentFormInputs = append(*currentFormInputs, &FormInputInfo{
									Type:         selectType,
									Name:         inputName, // Name from <select>
									Value:        optionValue,
									InputElement: optionElement, // The <option> element
								})
								if !valueAttrFound && optionLoopIndex+1 < numElements && htmlElements[optionLoopIndex+1].Type == htmlparser.TextNode {
									optionLoopIndex++ // Consume the text node that provided the value
								}
							}
							optionLoopIndex++
						}
						formContentLoopIndex = optionLoopIndex - 1

					} else if tagNameLower == "textarea" && currentElement.Type != htmlparser.SelfClosingTagOrPI {
						var contentBuilder strings.Builder
						textareaContentLoopIndex := formContentLoopIndex + 1
						for textareaContentLoopIndex < numElements {
							contentElement := htmlElements[textareaContentLoopIndex]

							// Check for closing </textarea>
							if contentElement.Type == htmlparser.CloseTag && contentElement.TagInfo != nil && strings.EqualFold(contentElement.TagInfo.Name, "textarea") {
								formContentLoopIndex = textareaContentLoopIndex
								break
							}
							// Check for closing </form> tag
							if contentElement.Type == htmlparser.CloseTag && contentElement.TagInfo != nil && strings.EqualFold(contentElement.TagInfo.Name, "form") {
								formContentLoopIndex = textareaContentLoopIndex - 1
								break
							}

							if contentElement.TagInfo == nil { // Text node
								// Our parser's TextNode.Content is already the equivalent of cT().
								// The .trim() in java was on individual text node string before appending.
								// If parser already provides trimmed-like content for TextNode, this is fine.
								// Based on html_parser.go, HTMLElement.Content for TextNode is not explicitly trimmed by the parser itself.
								contentBuilder.WriteString(strings.TrimSpace(contentElement.Content))
							} else {
								// Handle elements inside textarea by appending their raw HTML string (cW() equivalent)
								if contentElement.StartOffset < contentElement.EndOffset && contentElement.EndOffset <= len(originalBody) {
									rawTagBytes := originalBody[contentElement.StartOffset:contentElement.EndOffset]
									contentBuilder.Write(rawTagBytes)
								}
							}
							textareaContentLoopIndex++
						}
						*currentFormInputs = append(*currentFormInputs, &FormInputInfo{
							Type:         InputTypeTextarea,
							Name:         inputName,
							Value:        contentBuilder.String(),
							InputElement: currentElement,
						})
						if textareaContentLoopIndex >= numElements {
							formContentLoopIndex = textareaContentLoopIndex - 1
						}
						// If loop broke due to </textarea> or </form>, formContentLoopIndex is already set.
					}
				}
			}
			formContentLoopIndex++
		}
		mainLoopIndex = formContentLoopIndex
	}

	return forms
}
