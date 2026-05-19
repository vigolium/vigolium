package formparser

import (
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type InputType byte

const (
	InputTypeNone           InputType = 0xFF // ad7.NONE(-1)
	InputTypeText           InputType = 0    // ad7.TEXT(0)
	InputTypePassword       InputType = 1    // ad7.PASSWORD(1)
	InputTypeCheckbox       InputType = 2    // ad7.CHECKBOX(2)
	InputTypeRadio          InputType = 3    // ad7.RADIO(3)
	InputTypeSubmit         InputType = 4    // ad7.SUBMIT(4)
	InputTypeFile           InputType = 5    // ad7.FILE(5)
	InputTypeHidden         InputType = 6    // ad7.HIDDEN(6)
	InputTypeImage          InputType = 7    // ad7.IMAGE(7)
	InputTypeButton         InputType = 8    // ad7.BUTTON(8)
	InputTypeNumber         InputType = 9    // ad7.NUMBER(9)
	InputTypeSelect         InputType = 10   // ad7.SELECT(10)
	InputTypeTextarea       InputType = 11   // ad7.TEXTAREA(11)
	InputTypeSelectMultiple InputType = 12   // ad7.SELECT_MULTIPLE(12)
)

// FormInputInfo represents a single input field within an HTML form.
type FormInputInfo struct {
	Type         InputType
	Name         string
	Value        string
	InputElement *html.Node // Pointer to the original html.Node
}

// FormInfo represents a parsed HTML form.
type FormInfo struct {
	ActionURL   string
	Method      string
	Enctype     string
	FormElement *html.Node // Pointer to the original <form> html.Node
	Inputs      []*FormInputInfo
}

// mapHtmlInputTypeToInputType maps HTML input type string to InputType enum.
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
		case "button":
			return InputTypeButton
		case "number":
			return InputTypeNumber
		case "reset":
			return InputTypeNone
		default:
			return InputTypeText
		}
	case "button":
		switch lowerHtmlType {
		case "submit", "":
			return InputTypeSubmit
		case "reset":
			return InputTypeNone
		case "button":
			return InputTypeButton
		default:
			return InputTypeNone
		}
	case "select":
		return InputTypeSelect
	case "textarea":
		return InputTypeTextarea
	}

	return InputTypeNone
}

// resolveBaseURL attempts to find a <base href="..."> tag and resolve it against the request URL.
func resolveBaseURL(req *http.Request, doc *html.Node) *url.URL {
	if req == nil || req.URL == nil {
		return nil
	}
	originalBaseURL := req.URL

	// Find <base> element
	baseNode := findFirstElement(doc, "base")
	if baseNode != nil {
		baseHref := strings.TrimSpace(getAttr(baseNode, "href"))
		if baseHref != "" {
			parsedBaseHref, err := originalBaseURL.Parse(baseHref)
			if err == nil {
				return parsedBaseHref
			}
		}
	}

	return originalBaseURL
}

// ExtractFormsInfo parses HTML to find forms and their input fields.
func ExtractFormsInfo(
	req *http.Request,
	doc *html.Node,
	stopSupplier func() bool,
) []*FormInfo {
	if doc == nil {
		return nil
	}

	// Resolve base URL considering <base href> tag
	var effectiveBaseURL *url.URL
	if req != nil && req.URL != nil {
		effectiveBaseURL = resolveBaseURL(req, doc)
	}

	// Find all form elements
	formNodes := findAllElements(doc, "form")
	if len(formNodes) == 0 {
		return nil
	}

	var forms []*FormInfo

	for _, formNode := range formNodes {
		if stopSupplier != nil && stopSupplier() {
			return nil
		}

		form := processFormNode(formNode, effectiveBaseURL)
		if form != nil {
			forms = append(forms, form)
		}
	}

	return forms
}

// processFormNode extracts form information from a <form> node.
func processFormNode(formNode *html.Node, effectiveBaseURL *url.URL) *FormInfo {
	// Get action URL
	actionStr := getAttr(formNode, "action")
	var actionURL *url.URL

	if effectiveBaseURL != nil {
		if actionStr == "" {
			actionURL = effectiveBaseURL
		} else {
			parsedAction, err := effectiveBaseURL.Parse(actionStr)
			if err == nil {
				actionURL = parsedAction
			} else {
				actionURL = effectiveBaseURL
			}
		}
	} else if actionStr != "" {
		parsedAction, err := url.Parse(actionStr)
		if err == nil && parsedAction.IsAbs() {
			actionURL = parsedAction
		}
	}

	formInfo := &FormInfo{
		FormElement: formNode,
		Inputs:      make([]*FormInputInfo, 0),
		Enctype:     "application/x-www-form-urlencoded",
		Method:      "GET",
	}

	if actionURL != nil {
		formInfo.ActionURL = actionURL.String()
	}

	// Get method and enctype
	method := getAttr(formNode, "method")
	if method != "" {
		formInfo.Method = strings.ToUpper(method)
	}

	enctype := getAttr(formNode, "enctype")
	if enctype != "" {
		formInfo.Enctype = enctype
	}

	// Extract inputs from form
	extractFormInputs(formNode, formInfo)

	return formInfo
}

// extractFormInputs extracts all input elements from a form node.
func extractFormInputs(formNode *html.Node, formInfo *FormInfo) {
	// Process direct children and descendants
	var processNode func(n *html.Node)
	processNode = func(n *html.Node) {
		if n.Type != html.ElementNode {
			// Continue to children for non-elements
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				processNode(c)
			}
			return
		}

		tagName := strings.ToLower(n.Data)

		switch tagName {
		case "input":
			processInputElement(n, formInfo)

		case "button":
			processButtonElement(n, formInfo)

		case "select":
			processSelectElement(n, formInfo)

		case "textarea":
			processTextareaElement(n, formInfo)

		case "form":
			// Don't recurse into nested forms
			if n != formNode {
				return
			}
		}

		// Continue to children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			processNode(c)
		}
	}

	// Start processing from form's children
	for c := formNode.FirstChild; c != nil; c = c.NextSibling {
		processNode(c)
	}
}

// processInputElement handles <input> elements.
func processInputElement(n *html.Node, formInfo *FormInfo) {
	inputName := getAttr(n, "name")
	inputValue := getAttr(n, "value")
	inputTypeAttr := getAttr(n, "type")

	inputType := mapHtmlInputTypeToInputType(inputTypeAttr, "input")

	// Skip button-type inputs and reset
	if inputType == InputTypeNone || inputType == InputTypeButton {
		return
	}

	formInfo.Inputs = append(formInfo.Inputs, &FormInputInfo{
		Type:         inputType,
		Name:         inputName,
		Value:        inputValue,
		InputElement: n,
	})
}

// processButtonElement handles <button> elements.
func processButtonElement(n *html.Node, formInfo *FormInfo) {
	inputTypeAttr := getAttr(n, "type")
	inputType := mapHtmlInputTypeToInputType(inputTypeAttr, "button")

	// Only add submit buttons
	if inputType != InputTypeSubmit {
		return
	}

	formInfo.Inputs = append(formInfo.Inputs, &FormInputInfo{
		Type:         InputTypeSubmit,
		Name:         getAttr(n, "name"),
		Value:        getAttr(n, "value"),
		InputElement: n,
	})
}

// processSelectElement handles <select> elements and their options.
func processSelectElement(n *html.Node, formInfo *FormInfo) {
	selectName := getAttr(n, "name")
	isMultiple := hasAttr(n, "multiple")

	selectType := InputTypeSelect
	if isMultiple {
		selectType = InputTypeSelectMultiple
	}

	// Find all option elements
	options := findAllElements(n, "option")

	for _, optNode := range options {
		optionValue := getAttr(optNode, "value")

		// If no value attribute, use text content
		if !hasAttr(optNode, "value") {
			optionValue = strings.TrimSpace(getTextContent(optNode))
		}

		formInfo.Inputs = append(formInfo.Inputs, &FormInputInfo{
			Type:         selectType,
			Name:         selectName,
			Value:        optionValue,
			InputElement: optNode,
		})
	}
}

// processTextareaElement handles <textarea> elements.
func processTextareaElement(n *html.Node, formInfo *FormInfo) {
	inputName := getAttr(n, "name")

	// Get textarea content - use renderChildren to get inner HTML
	// or getTextContent for just text
	var contentBuilder strings.Builder

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			contentBuilder.WriteString(strings.TrimSpace(c.Data))
		} else {
			// Render non-text nodes (preserves HTML inside textarea)
			contentBuilder.WriteString(renderNode(c))
		}
	}

	formInfo.Inputs = append(formInfo.Inputs, &FormInputInfo{
		Type:         InputTypeTextarea,
		Name:         inputName,
		Value:        contentBuilder.String(),
		InputElement: n,
	})
}
